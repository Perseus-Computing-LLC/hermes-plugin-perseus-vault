"""Authorized Action Receipt enforcement hooks for Hermes tools.

The hook records only SHA-256 digests and trusted identifiers in Perseus Vault.
Raw tool arguments/results remain process-local and are never sent as evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

if __package__:
    from .client import VaultMCPClient
    from .constraints import ResourceConstraints, compare, constraints_from_tool, durable_projection
else:  # Standalone checkout/import used by plugin discovery and test runners.
    from client import VaultMCPClient
    from constraints import ResourceConstraints, compare, constraints_from_tool, durable_projection

logger = logging.getLogger(__name__)

_DEFAULT_URL = "https://vault.perseus.observer/message"
_TERMINAL_READ_ONLY = re.compile(
    r"^\s*(?:git\s+(?:status|rev-parse)\b|"
    r"(?:pwd|whoami|id|uname|df|du|ps)\b)", re.I,
)
# A read-only-looking prefix does not make the rest of a shell program safe.
# Compound operators, command substitution, redirects, and newlines force the
# command through authority enforcement instead of the read-only fast path.
_SHELL_COMPOUND = re.compile(r"(?:&&|\|\||[;&|`<>]|\$\(|[\r\n])")
_TERMINAL_RULES = (
    (re.compile(r"\bgit\s+push\b", re.I), "git_push"),
    (re.compile(r"\b(?:gh\s+pr\s+merge|pulls?/\d+/merge)\b", re.I), "pull_request_merge"),
    (re.compile(r"\b(?:kubectl\s+(?:apply|delete|rollout)|terraform\s+apply|"
                r"(?:docker\s+)?compose\s+(?:up|down)|deploy)\b", re.I), "deployment"),
    (re.compile(r"\b(?:bw|bws|op)\s+(?:get|read|secret)|\bsecrets?\s+(?:get|read)\b", re.I),
     "secret_access"),
    (re.compile(r"\b(?:rm|rmdir|shred|mkfs|dd|git\s+reset\s+--hard|git\s+clean)\b", re.I),
     "destructive_command"),
)
_TOOL_CAPABILITIES = {
    "write_file": "filesystem_write",
    "patch": "filesystem_write",
    "memory": "memory_write",
    "skill_manage": "skill_write",
    "cronjob": "scheduler_write",
    "send_message": "external_message_send",
    "image_generate": "paid_resource_allocation",
    "execute_code": "code_execution",
    "browser_click": "browser_interaction",
    "browser_type": "browser_interaction",
    "browser_press": "browser_interaction",
}
_READ_ONLY_TOOLS = {
    "read_file", "search_files", "web_search", "web_extract", "browser_snapshot",
    "browser_vision", "browser_get_images", "browser_console", "vision_analyze",
    "session_search", "skill_view", "skills_list", "todo", "perseus_recall",
}


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_tool_payload(response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not response.get("ok"):
        return None
    candidates = [response.get("data"), response.get("text")]
    for candidate in candidates:
        value = candidate
        for _ in range(3):
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except Exception:
                    break
            if isinstance(value, dict) and isinstance(value.get("result"), str):
                value = value["result"]
                continue
            break
        if isinstance(value, dict):
            return value
    return None


def _git_scope(cwd: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"], cwd=str(cwd), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=True,
        )
        remote = result.stdout.strip()
        match = re.search(r"github\.com(?::|/)([^/]+/[^/]+?)(?:\.git)?$", remote)
        if match:
            return "github:" + match.group(1).removesuffix(".git")
    except Exception:
        pass
    return ""


def _classify(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    overrides = os.getenv("PERSEUS_VAULT_AUTHORITY_TOOL_CAPABILITIES_JSON", "").strip()
    if overrides:
        try:
            mapped = json.loads(overrides)
            if tool_name in mapped:
                return str(mapped[tool_name]) if mapped[tool_name] else None
        except Exception:
            logger.warning("perseus-vault: invalid authority tool capability JSON")
    if tool_name == "terminal":
        command = str(args.get("command") or "")
        if not _SHELL_COMPOUND.search(command) and _TERMINAL_READ_ONLY.search(command):
            return None
        for pattern, capability in _TERMINAL_RULES:
            if pattern.search(command):
                return capability
        return "shell_command"
    if tool_name in _TOOL_CAPABILITIES:
        return _TOOL_CAPABILITIES[tool_name]
    if tool_name in _READ_ONLY_TOOLS or tool_name.startswith(("perseus_", "mcp__perseus_vault__")):
        return None
    # Unknown tools are safe in compatibility/shadow mode, but enforcement is
    # deliberately fail-closed because the plugin cannot prove they are reads.
    return "unknown_tool_side_effect"


def _result_failed(result: Any) -> bool:
    """Conservatively recognize structured tool failures without false positives."""
    value = result
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return False
    if not isinstance(value, dict):
        return False
    if value.get("success") is False:
        return True
    exit_code = value.get("exit_code")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        return True
    error = value.get("error")
    return bool(error) if isinstance(error, (str, list, dict)) else error is not None


class AuthorityEnforcer:
    """Process-local bridge from Hermes lifecycle hooks to Vault AAR tools."""

    def __init__(self) -> None:
        self._client: Optional[VaultMCPClient] = None
        self._lock = threading.RLock()

    @property
    def mode(self) -> str:
        mode = os.getenv("PERSEUS_VAULT_AUTHORITY_MODE", "off").strip().lower()
        return mode if mode in {"off", "shadow", "enforce"} else "off"

    def _identity(self) -> Tuple[str, str, str, str]:
        agent_id = os.getenv("PERSEUS_VAULT_AGENT_ID", "").strip()
        workspace = os.getenv("PERSEUS_VAULT_WORKSPACE", "").strip()
        cwd = Path.cwd()
        scope = os.getenv("PERSEUS_VAULT_AUTHORITY_SCOPE", "").strip() or _git_scope(cwd)
        if not scope and workspace:
            scope = f"hermes:workspace:{workspace}"
        external_ref = os.getenv("PERSEUS_VAULT_AUTHORITY_EXTERNAL_REF", "").strip() or scope
        return agent_id, workspace, scope, external_ref

    def _ensure_client(self) -> VaultMCPClient:
        with self._lock:
            if self._client is not None:
                return self._client
            token = os.getenv("PERSEUS_VAULT_MCP_TOKEN", "").strip()
            url = os.getenv("PERSEUS_VAULT_URL", "").strip() or _DEFAULT_URL
            if not token:
                raise RuntimeError("PERSEUS_VAULT_MCP_TOKEN is missing")
            client = VaultMCPClient(url, token)
            client.start()
            self._client = client
            return client

    @staticmethod
    def _correlation(kwargs: Dict[str, Any]) -> str:
        return str(kwargs.get("tool_call_id") or kwargs.get("task_id") or
                   kwargs.get("session_id") or threading.get_ident())

    def _call(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        response = self._ensure_client().call_tool(name, args, timeout=20)
        payload = _parse_tool_payload(response)
        if payload is None:
            raise RuntimeError(response.get("text") or f"Vault {name} failed")
        return payload

    def execution_middleware(
        self, tool_name: str, args: Dict[str, Any], next_call: Any, **kwargs: Any
    ) -> Any:
        """Authorize, execute once, and finalize a side effect atomically.

        This middleware catches every authority/lifecycle failure and returns a
        blocking tool result instead of raising. Hermes middleware is generally
        fail-open on callback exceptions, so this local catch is a security
        invariant, not merely error handling.
        """
        mode = self.mode
        # Classification is pure and total under normal operation. Read-only/off
        # pass-through must happen outside the security catch so a tool exception
        # propagates exactly once instead of being mistaken for preflight failure.
        try:
            capability = _classify(tool_name, args if isinstance(args, dict) else {})
        except BaseException as exc:
            logger.warning("perseus-vault authority classification failed: %s", exc)
            if mode == "shadow":
                return next_call(args)
            return json.dumps({"error": f"Vault authority blocked tool execution: {exc}"})
        if mode == "off" or capability is None:
            return next_call(args)

        # Hermes execution middleware is fail-open when a callback raises before
        # next_call(). Keep the remaining enforcement prelude inside this boundary.
        try:
            correlation = self._correlation(kwargs)
            agent_id, workspace, scope, external_ref = self._identity()
            if not all((agent_id, scope, external_ref)):
                raise RuntimeError("Vault authority identity/scope is not configured")
            resource_constraints = constraints_from_tool(tool_name, args, capability, scope)
            resource_constraints.validate_for(capability)
        except BaseException as exc:
            logger.warning("perseus-vault authority preflight failed: %s", exc)
            if mode == "shadow":
                return next_call(args)
            return json.dumps({"error": f"Vault authority blocked tool execution: {exc}"})

        action: Optional[Dict[str, Any]] = None
        lease_id = ""
        execution_started = False
        execution_finished = False
        execution_result: Any = None
        holder_id = f"hermes:{agent_id}:{correlation}"
        try:
            intent_args: Dict[str, Any] = {
                "agent_id": agent_id, "workspace_hash": workspace,
                "scope_anchor": scope, "external_ref": external_ref,
                "capability": capability,
                "action_key": f"hermes:{capability}:{correlation}",
                "intent_hash": _canonical_digest({"tool": tool_name, "args": args}),
                "resource_constraints": resource_constraints.canonical(),
                "resource_constraints_json": json.dumps(resource_constraints.canonical(), sort_keys=True, separators=(",", ":")),
                "resource_constraints_hash": resource_constraints.digest(),
            }
            context_projection = kwargs.get("context_projection")
            if context_projection is not None:
                if not isinstance(context_projection, dict):
                    raise RuntimeError("context projection is not an object")
                if context_projection.get("decision") not in {"allow", "constrain", "interrupt", "recover", "abstain"}:
                    raise RuntimeError("context projection has an invalid decision")
                context_digest = _canonical_digest(context_projection)
                if context_projection.get("decision") in {"interrupt", "abstain"}:
                    raise RuntimeError("context decision does not authorize action")
            else:
                context_digest = None
            if context_digest:
                intent_args["context_selection_digest"] = context_digest
            action = self._call("perseus_vault_action_intent", intent_args)
            action_id = str(action.get("id") or "")
            if not action_id:
                raise RuntimeError("Vault returned no action id")
            action_constraints = ResourceConstraints.from_mapping(action.get("resource_constraints"))
            allowed, reason = compare(resource_constraints, action_constraints)
            if not allowed:
                raise RuntimeError(reason)

            if capability == "payment" and not action.get("approval_required"):
                raise RuntimeError("payment capability requires an approval-bound authority manifest")
            if action.get("approval_required"):
                from tools.approval import request_tool_approval
                decision = request_tool_approval(
                    tool_name,
                    f"Perseus Vault manifest requires approval for {capability}",
                    rule_key=f"perseus-vault:{action_id}",
                )
                granted = bool(decision.get("approved"))
                principal = os.getenv("PERSEUS_VAULT_APPROVER_PRINCIPAL", "").strip()
                if not principal:
                    raise RuntimeError("PERSEUS_VAULT_APPROVER_PRINCIPAL is missing")
                approval = self._call("perseus_vault_action_approve", {
                    "action_id": action_id, "approver_principal": principal,
                    "decision": "granted" if granted else "denied",
                })
                if not granted:
                    return json.dumps({
                        "error": decision.get("message") or "Vault action approval denied",
                        "action_id": action_id,
                        "approval_ref": approval.get("approval_ref", ""),
                    })
                if approval.get("status") != "approval_granted" or not approval.get("approval_ref"):
                    raise RuntimeError("Vault did not record a granted approval reference")
                approved_constraints = ResourceConstraints.from_mapping(approval.get("resource_constraints"))
                allowed, reason = compare(resource_constraints, approved_constraints)
                if not allowed:
                    raise RuntimeError(reason)

            lease_args = {
                "action_id": action_id, "holder_id": holder_id, "ttl_seconds": 900,
            }
            if context_digest:
                lease_args["context_selection_digest"] = context_digest
            lease = self._call("perseus_vault_action_lease_acquire", lease_args)
            lease_id = str(lease.get("id") or "")
            if not lease_id:
                raise RuntimeError("Vault returned no execution lease")

            try:
                execution_started = True
                result = next_call(args)
                execution_result = result
                execution_finished = True
            except BaseException as exc:
                try:
                    self._call("perseus_vault_action_complete", {
                        "action_id": action_id, "actor_agent_id": agent_id,
                        "outcome": "failed",
                        "outcome_hash": _canonical_digest({"exception_type": type(exc).__name__}),
                    })
                except Exception as lifecycle_exc:
                    logger.error("perseus-vault failed to record tool exception: %s", lifecycle_exc)
                raise

            failed = _result_failed(result)
            completion_args = {
                "action_id": action_id, "actor_agent_id": agent_id,
                "outcome": "failed" if failed else "executed",
                "outcome_hash": _canonical_digest({"result": result}),
                "resource_constraints_hash": resource_constraints.digest(),
                "resource_constraints": durable_projection(resource_constraints),
            }
            if context_digest:
                completion_args["context_selection_digest"] = context_digest
            receipt = self._call("perseus_vault_action_complete", completion_args)
            logger.debug("perseus-vault action receipt finalized: %s", receipt.get("id", action_id))
            return result
        except BaseException as exc:
            logger.warning("perseus-vault authority middleware %s %s: %s",
                           "observed failure after" if execution_started else "blocked before",
                           capability, exc)
            # Once the real tool starts, its exception is the authoritative tool
            # outcome. Lifecycle recording must never replace or swallow it.
            if execution_started and not execution_finished:
                raise
            if mode == "shadow":
                # Shadow observes but never changes whether or what the tool executes.
                if execution_finished:
                    return execution_result
                if not execution_started:
                    return next_call(args)
            return json.dumps({"error": f"Vault authority blocked {capability}: {exc}"})
        finally:
            if lease_id:
                try:
                    self._call("perseus_vault_action_lease_release", {
                        "lease_id": lease_id, "holder_id": holder_id,
                    })
                except Exception as exc:
                    logger.warning("perseus-vault lease release failed: %s", exc)


_ENFORCER = AuthorityEnforcer()


def activate_runtime_hooks() -> None:
    """Attach hooks from the active memory-provider import path.

    Memory providers use Hermes's exclusive-provider loader rather than the
    general plugin loader, so they do not receive a PluginContext. Registering
    against the host hook registry here keeps one standalone install while
    remaining idempotent across provider discovery/status probes.
    """
    if _ENFORCER.mode == "off":
        return
    try:
        from hermes_cli.plugins import get_plugin_manager
        manager = get_plugin_manager()
        callbacks = manager._middleware.setdefault("tool_execution", [])
        callback = _ENFORCER.execution_middleware
        identity = (getattr(callback, "__self__", None), getattr(callback, "__func__", callback))
        if not any(
            (getattr(existing, "__self__", None), getattr(existing, "__func__", existing)) == identity
            for existing in callbacks
        ):
            callbacks.append(callback)
    except Exception as exc:
        if _ENFORCER.mode == "enforce":
            raise RuntimeError(f"unable to activate Vault authority hooks: {exc}") from exc
        logger.warning("perseus-vault authority hooks unavailable: %s", exc)


def register_authority_hooks(ctx: Any) -> None:
    """Register AAR middleware when loaded through a general plugin context."""
    if not hasattr(ctx, "register_middleware"):
        return
    ctx.register_middleware("tool_execution", _ENFORCER.execution_middleware)
