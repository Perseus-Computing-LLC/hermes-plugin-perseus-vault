"""Background-thread MCP client for the Perseus Vault server.

The MemoryProvider interface is synchronous, but the `mcp` Python client is
async. This module runs a dedicated asyncio event loop in a daemon thread,
holds a persistent streamable-HTTP MCP session to the Vault, and exposes a
blocking `call_tool()` wrapper. The session reconnects once transparently on
transport errors.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class VaultMCPClient:
    """Synchronous facade over a persistent async MCP session."""

    def __init__(self, url: str, token: str, *, connect_timeout: float = 15.0,
                 call_timeout: float = 30.0) -> None:
        self._url = url
        self._token = token
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._start_error: Optional[BaseException] = None

        # Async-side state (only touched on the loop thread)
        self._exit_stack = None
        self._session = None
        self._lock: Optional[asyncio.Lock] = None

    # ------------------------------------------------------------------
    # Lifecycle (sync side)
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background loop thread and pre-connect the session."""
        if self._thread and self._thread.is_alive():
            return
        self._ready.clear()
        self._start_error = None
        self._thread = threading.Thread(
            target=self._thread_main, name="perseus-vault-mcp", daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout=self._connect_timeout + 5):
            raise TimeoutError("Perseus Vault MCP connect timed out")
        if self._start_error is not None:
            raise RuntimeError(f"Perseus Vault MCP connect failed: {self._start_error}")

    def stop(self) -> None:
        if not self._loop:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(self._aclose(), self._loop)
            fut.result(timeout=10)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=10)
        self._loop = None
        self._thread = None

    # ------------------------------------------------------------------
    # Tool calls (sync side)
    # ------------------------------------------------------------------

    def call_tool(self, name: str, arguments: Dict[str, Any],
                  timeout: Optional[float] = None) -> Dict[str, Any]:
        """Call a Vault MCP tool; returns {"ok": bool, "text": str, "data": Any}."""
        if not self._loop:
            return {"ok": False, "text": "client not started", "data": None}
        timeout = timeout or self._call_timeout
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._acall_with_retry(name, arguments, timeout), self._loop,
            )
            return fut.result(timeout=timeout + 10)
        except Exception as e:
            logger.debug("perseus-vault call_tool %s failed: %s", name, e)
            return {"ok": False, "text": f"{type(e).__name__}: {e}", "data": None}

    # ------------------------------------------------------------------
    # Async internals (loop thread only)
    # ------------------------------------------------------------------

    def _thread_main(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._lock = asyncio.Lock()
            self._loop.run_until_complete(self._aconnect())
            self._ready.set()
            self._loop.run_forever()
        except BaseException as e:  # noqa: BLE001 — propagate to start()
            self._start_error = e
            self._ready.set()
        finally:
            try:
                if self._loop and not self._loop.is_closed():
                    self._loop.close()
            except Exception:
                pass

    async def _aconnect(self) -> None:
        from contextlib import AsyncExitStack

        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        await self._aclose()
        self._exit_stack = AsyncExitStack()
        headers = {"Authorization": f"Bearer {self._token}"}
        read, write, _ = await self._exit_stack.enter_async_context(
            streamablehttp_client(self._url, headers=headers)
        )
        self._session = await self._exit_stack.enter_async_context(
            ClientSession(read, write)
        )
        await asyncio.wait_for(self._session.initialize(), timeout=self._connect_timeout)

    async def _aclose(self) -> None:
        self._session = None
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception:
                pass
            self._exit_stack = None

    async def _acall_with_retry(self, name: str, arguments: Dict[str, Any],
                                timeout: float) -> Dict[str, Any]:
        async with self._lock:
            try:
                return await self._acall(name, arguments, timeout)
            except Exception as first:
                logger.debug("perseus-vault %s failed (%s); reconnecting", name, first)
                try:
                    await asyncio.wait_for(self._aconnect(), timeout=self._connect_timeout)
                    return await self._acall(name, arguments, timeout)
                except Exception as second:
                    return {"ok": False,
                            "text": f"{type(second).__name__}: {second}",
                            "data": None}

    async def _acall(self, name: str, arguments: Dict[str, Any],
                     timeout: float) -> Dict[str, Any]:
        if self._session is None:
            await asyncio.wait_for(self._aconnect(), timeout=self._connect_timeout)
        result = await asyncio.wait_for(
            self._session.call_tool(name, arguments), timeout=timeout,
        )
        text = ""
        if getattr(result, "content", None):
            parts = [getattr(c, "text", "") for c in result.content]
            text = "\n".join(p for p in parts if p)
        data = getattr(result, "structuredContent", None)
        if not text and data is not None:
            text = json.dumps(data)
        is_error = bool(getattr(result, "isError", False))
        return {"ok": not is_error, "text": text, "data": data}
