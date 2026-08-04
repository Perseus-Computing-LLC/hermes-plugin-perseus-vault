"""Perseus Vault memory plugin — MemoryProvider interface.

Cross-session memory backed by a remote Perseus Vault MCP server:
FTS5 + dense semantic recall, correction tracking, decision journaling, and
bi-temporal fact history. One Vault can be shared by many Hermes instances
(Cloud, Desktop, cron workers) so context follows the user between machines.

Config (env vars take precedence, then config.yaml under memory.perseus-vault:):
  PERSEUS_VAULT_MCP_TOKEN  — bearer token for the Vault MCP endpoint (required)
  PERSEUS_VAULT_URL        — MCP endpoint (default: https://vault.perseus.observer/message)
  PERSEUS_VAULT_WORKSPACE  — workspace scope hash (optional; blank = global)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from agent.memory_provider import MemoryProvider

if __package__:
    from .client import VaultMCPClient
    from .authority import activate_runtime_hooks
else:  # Standalone checkout/import used by plugin discovery and test runners.
    from client import VaultMCPClient
    from authority import activate_runtime_hooks


EVIDENCE_CONTROL_SCHEMA = "perseus-evidence-control/v1"
EVIDENCE_DECISIONS = {"allow", "constrain", "interrupt", "recover", "abstain"}
_SHA256_HEX = set("0123456789abcdef")


def _evidence_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def build_context_decision_projection(
    selected_sources: List[Dict[str, Any]],
    *,
    decision: str,
    reason_codes: List[str],
    stage_refs: List[str],
    contract_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the hash-only context projection used by downstream receipts."""
    sources = [dict(source) for source in selected_sources]
    selection_digest = _evidence_digest(sources)
    contract = dict(contract_fields or {})
    contract.update({
        "schema_version": EVIDENCE_CONTROL_SCHEMA,
        "source_refs": sources,
        "selection_digest": selection_digest,
        "decision": decision,
        "reason_codes": list(reason_codes),
        "stage_refs": list(stage_refs),
        "sensitive_payload": "not_captured",
    })
    return {
        "schema_version": EVIDENCE_CONTROL_SCHEMA,
        "source_refs": sources,
        "selection_digest": selection_digest,
        "contract_digest": _evidence_digest(contract),
        "decision": decision,
        "reason_codes": list(reason_codes),
        "stage_refs": list(stage_refs),
        "sensitive_payload": "not_captured",
    }


def derive_context_decision(
    source_refs: List[Dict[str, Any]],
    *,
    workspace_scope: str = "",
    require_provenance: bool = True,
) -> Tuple[str, List[str]]:
    """Classify selected evidence without treating empty/ambiguous recall as allow."""
    if not source_refs:
        return "abstain", ["missing_evidence"]
    if any(source.get("timeout") is True for source in source_refs):
        return "abstain", ["context_timeout"]
    if any(source.get("evidence_sufficient") is False for source in source_refs):
        return "abstain", ["insufficient_evidence"]
    if require_provenance:
        required = {"id", "content_hash", "valid_from", "valid_to", "recorded_at", "scope", "trust_class"}
        if any(not required.issubset(source) for source in source_refs):
            return "abstain", ["missing_provenance"]
    status = {source.get("evidence_status") for source in source_refs}
    if status & {"stale", "superseded", "contradictory", "conflicting"}:
        value = "contradictory_evidence" if status & {"contradictory", "conflicting"} else "stale_evidence"
        return "recover", [value, "refresh_or_resolve_evidence"]
    if workspace_scope and any(source.get("scope") != workspace_scope for source in source_refs):
        return "constrain", ["scope_mismatch", "revalidate_before_action"]
    if any(source.get("trust_class") in {"untrusted", "unknown", "quarantined"} for source in source_refs):
        return "constrain", ["untrusted_evidence", "isolate_non_authoritative_context"]
    return "allow", ["evidence_in_scope"]


def validate_context_decision_projection(projection: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if projection.get("schema_version") != EVIDENCE_CONTROL_SCHEMA:
        errors.append("schema_version")
    if projection.get("decision") not in EVIDENCE_DECISIONS:
        errors.append("decision")
    if projection.get("sensitive_payload") != "not_captured":
        errors.append("sensitive_payload")
    sources = projection.get("source_refs")
    if not isinstance(sources, list):
        errors.append("source_refs")
        sources = []
    for index, source in enumerate(sources):
        for field in ("id", "content_hash", "valid_from", "valid_to", "recorded_at", "scope", "trust_class"):
            if field not in source:
                errors.append(f"source_refs[{index}].{field}")
        digest = source.get("content_hash")
        if not isinstance(digest, str) or len(digest) != 64 or set(digest.lower()) - _SHA256_HEX:
            errors.append(f"source_refs[{index}].content_hash")
        if isinstance(source.get("valid_from"), (int, float)) and isinstance(source.get("valid_to"), (int, float)) and source["valid_to"] < source["valid_from"]:
            errors.append(f"source_refs[{index}].valid_interval")
        if any(key in source for key in ("content", "body", "body_json", "prompt", "context", "arguments", "secret", "token")):
            errors.append(f"source_refs[{index}].raw_payload")
    if projection.get("selection_digest") != _evidence_digest(sources):
        errors.append("selection_digest")
    contract = {
        "schema_version": EVIDENCE_CONTROL_SCHEMA,
        "source_refs": sources,
        "selection_digest": projection.get("selection_digest"),
        "decision": projection.get("decision"),
        "reason_codes": projection.get("reason_codes"),
        "stage_refs": projection.get("stage_refs"),
        "sensitive_payload": "not_captured",
    }
    if projection.get("contract_digest") != _evidence_digest(contract):
        errors.append("contract_digest")
    if projection.get("decision") == "allow" and not sources:
        errors.append("allow_requires_source_refs")
    if not isinstance(projection.get("reason_codes"), list) or not projection["reason_codes"]:
        errors.append("reason_codes")
    if not isinstance(projection.get("stage_refs"), list):
        errors.append("stage_refs")
    forbidden = {"prompt", "context", "content", "body", "body_json", "arguments", "tool_arguments", "response", "secret", "token"}
    for key in projection:
        if str(key).lower() in forbidden or str(key).lower().startswith("raw_"):
            errors.append(f"forbidden_field:{key}")
    return not errors, sorted(set(errors))

logger = logging.getLogger(__name__)

_DEFAULT_URL = "https://vault.perseus.observer/message"
_PREFETCH_LIMIT = 6
_PREVIEW_CAP = 400
_SESSION_CAPTURE_MAX_CHARS = 8000
_TURN_BUFFER_CAP = 40

# Per-Vault-call timeout used on the *synchronous* prefetch (cache-miss) path.
# _build_recall_block makes two sequential recall calls (recall_when + recall),
# and the client serializes them on a single asyncio lock, so the wall-clock
# cost is roughly 2x this value. The host (MemoryManager._prefetch_provider)
# runs prefetch() inside a thread it join()s with an ~8s budget, so the sum
# MUST stay comfortably under that or the whole block is dropped as "timed
# out" and startup memory silently fails to surface (issue #753). 3s x 2 = 6s
# worst case leaves headroom. The background warm path (queue_prefetch) can
# afford to be more patient.
_SYNC_CALL_TIMEOUT = 3.0
_WARM_CALL_TIMEOUT = 15.0

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

REMEMBER_SCHEMA = {
    "name": "perseus_remember",
    "description": (
        "Persist a durable fact, decision, correction, or lesson to the shared "
        "Perseus Vault (long-term memory visible to all connected agents). "
        "Idempotent by (category, key). Never store secret values."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "content": {"type": "string", "description": "The fact to remember."},
            "category": {
                "type": "string",
                "description": "Category, e.g. 'decision', 'convention', 'insight' (default: 'general').",
            },
            "key": {
                "type": "string",
                "description": "Stable key within the category (default: derived from content).",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional tags for cross-referencing.",
            },
        },
        "required": ["content"],
    },
}

RECALL_SCHEMA = {
    "name": "perseus_recall",
    "description": (
        "Search the shared Perseus Vault for previously stored facts, decisions, "
        "corrections, and ops notes. Use before asking the user to repeat context."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to search for."},
            "limit": {"type": "integer", "description": "Max results (default: 6, max: 20)."},
            "category": {"type": "string", "description": "Optional category filter."},
        },
        "required": ["query"],
    },
}

FORGET_SCHEMA = {
    "name": "perseus_forget",
    "description": "Archive (soft-delete) a Vault entity by category + key.",
    "parameters": {
        "type": "object",
        "properties": {
            "category": {"type": "string", "description": "Entity category."},
            "key": {"type": "string", "description": "Entity key."},
        },
        "required": ["category", "key"],
    },
}


class PerseusVaultProvider(MemoryProvider):
    """MemoryProvider backed by a remote Perseus Vault MCP server."""

    def __init__(self) -> None:
        self._client: Optional[VaultMCPClient] = None
        self._session_id: str = ""
        self._agent_context: str = "primary"
        self._workspace_hash: str = ""
        self._prefetched: str = ""
        self._prefetch_generation: int = 0
        self._prefetch_lock = threading.Lock()
        self._turn_buffer: List[Dict[str, str]] = []
        self._enabled = False

    # ------------------------------------------------------------------
    # Config resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _config_section() -> Dict[str, Any]:
        try:
            from hermes_cli.config import cfg_get, load_config
            config = load_config()
            section = cfg_get(config, "memory", "perseus-vault")
            return section if isinstance(section, dict) else {}
        except Exception:
            return {}

    @classmethod
    def _resolve(cls, env_var: str, key: str, default: str = "") -> str:
        val = os.environ.get(env_var, "").strip()
        if val:
            return val
        section = cls._config_section()
        val = str(section.get(key, "") or "").strip()
        return val or default

    @classmethod
    def _token(cls) -> str:
        return cls._resolve("PERSEUS_VAULT_MCP_TOKEN", "token")

    @classmethod
    def _url(cls) -> str:
        return cls._resolve("PERSEUS_VAULT_URL", "url", _DEFAULT_URL)

    # ------------------------------------------------------------------
    # Core lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "perseus-vault"

    def is_available(self) -> bool:
        if not self._token():
            return False
        try:
            import mcp  # noqa: F401
        except ImportError:
            return False
        return True

    def initialize(self, session_id: str, **kwargs) -> None:
        self._session_id = session_id
        self._agent_context = kwargs.get("agent_context", "primary")
        # AAR hooks must be installed before this session can execute tools.
        # In enforce mode activation errors are fatal rather than fail-open.
        activate_runtime_hooks()
        self._workspace_hash = self._resolve(
            "PERSEUS_VAULT_WORKSPACE", "workspace_hash")
        try:
            self._client = VaultMCPClient(self._url(), self._token())
            self._client.start()
            self._enabled = True
        except Exception as e:
            logger.warning("perseus-vault: connect failed, provider disabled: %s", e)
            self._client = None
            self._enabled = False

    def shutdown(self) -> None:
        if self._client:
            try:
                self._client.stop()
            except Exception:
                pass
            self._client = None
        self._enabled = False

    # ------------------------------------------------------------------
    # Prompt + prefetch
    # ------------------------------------------------------------------

    def system_prompt_block(self) -> str:
        if not self._enabled:
            return ""
        return (
            "## Long-term memory: Perseus Vault\n"
            "A shared Perseus Vault is connected as the external memory provider. "
            "Relevant Vault memories are prefetched and injected before turns when available. "
            "Use `perseus_recall` to search it before asking the user to repeat context, and "
            "`perseus_remember` to persist durable facts, decisions, and corrections. "
            "Never store secret values in the Vault."
        )

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        if not self._enabled or not self._client or not query.strip():
            return

        def _work() -> None:
            with self._prefetch_lock:
                generation = self._prefetch_generation
            block = self._build_recall_block(query, call_timeout=_WARM_CALL_TIMEOUT)
            self.store_prefetched(block, generation=generation)

        threading.Thread(target=_work, daemon=True,
                         name="perseus-vault-prefetch").start()

    def prefetch_generation(self) -> int:
        """Return the generation of the currently valid warmed context."""
        with self._prefetch_lock:
            return self._prefetch_generation

    def invalidate_prefetch(self) -> None:
        """Discard warmed context and advance its invalidation generation."""
        with self._prefetch_lock:
            self._prefetch_generation += 1
            self._prefetched = ""

    def store_prefetched(self, block: str, *, generation: int) -> None:
        """Publish a warm result only if no invalidation happened meanwhile."""
        with self._prefetch_lock:
            if generation == self._prefetch_generation:
                self._prefetched = block

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        # Fast path: consume a block warmed by a prior queue_prefetch().
        with self._prefetch_lock:
            block = self._prefetched
            self._prefetched = ""
        if block:
            return block

        # Cache-miss path (issue #753): on a FRESH session, queue_prefetch()
        # has never run, so there is nothing warmed for turn 1 — the exact
        # moment "startup memory surfacing" is expected. The same miss happens
        # when the background warm from the previous turn hasn't landed yet.
        # The host runs this call inside a timed worker thread, so a bounded
        # synchronous recall here is safe and is what makes startup memory
        # actually appear instead of silently returning "". Timeouts are kept
        # tight (_SYNC_CALL_TIMEOUT) so the two serialized Vault calls fit
        # inside the host's prefetch budget.
        if not self._enabled or not self._client or not query.strip():
            return ""
        try:
            return self._build_recall_block(query, call_timeout=_SYNC_CALL_TIMEOUT)
        except Exception as e:  # never let a recall hiccup break the turn
            logger.debug("perseus-vault: synchronous prefetch failed: %s", e)
            return ""

    def _build_recall_block(self, query: str, *,
                            call_timeout: float = _WARM_CALL_TIMEOUT) -> str:
        items: List[Dict[str, Any]] = []
        seen: set = set()

        ws_args = ({"workspace_hash": self._workspace_hash}
                   if self._workspace_hash else {})

        # 1) Triggered memories (recall_when) — declared 'recall in this situation'
        res = self._client.call_tool(
            "perseus_vault_recall_when",
            {"context": query, "limit": 4, **ws_args}, timeout=call_timeout)
        for it in self._extract_items(res):
            if it.get("id") not in seen:
                seen.add(it.get("id"))
                items.append(it)

        # 2) Keyword recall
        res = self._client.call_tool(
            "perseus_vault_recall",
            {"query": query, "limit": _PREFETCH_LIMIT,
             "preview_cap": _PREVIEW_CAP, **ws_args}, timeout=call_timeout)
        for it in self._extract_items(res):
            if it.get("id") not in seen:
                seen.add(it.get("id"))
                items.append(it)

        if not items:
            return ""

        lines = ["## Recalled from Perseus Vault (shared memory)"]
        for it in items[: _PREFETCH_LIMIT + 2]:
            text = self._item_text(it)
            if not text:
                continue
            cat = it.get("category", "")
            key = it.get("key", "")
            lines.append(f"- [{cat}/{key}] {text}")
        if len(lines) == 1:
            return ""
        return "\n".join(lines)

    def context_decision_projection(
        self,
        selected_sources: List[Dict[str, Any]],
        *,
        decision: Optional[str] = None,
        reason_codes: Optional[List[str]] = None,
        stage_refs: Optional[List[str]] = None,
        require_provenance: bool = True,
    ) -> Dict[str, Any]:
        """Expose the machine-readable selection projection without changing rendering."""
        derived_decision, derived_reasons = derive_context_decision(
            selected_sources,
            workspace_scope=self._workspace_hash,
            require_provenance=require_provenance,
        )
        projection = build_context_decision_projection(
            selected_sources,
            decision=decision or derived_decision,
            reason_codes=reason_codes or derived_reasons,
            stage_refs=stage_refs or [],
        )
        valid, errors = validate_context_decision_projection(projection)
        if not valid:
            raise ValueError("invalid context decision projection: " + ", ".join(errors))
        return projection

    @staticmethod
    def _extract_items(res: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not res.get("ok"):
            return []
        payload = res.get("data")
        if not isinstance(payload, dict):
            try:
                payload = json.loads(res.get("text", "") or "{}")
            except Exception:
                return []
        # MCP tools wrap the JSON payload in a "result" string
        inner = payload.get("result")
        if isinstance(inner, str):
            try:
                payload = json.loads(inner)
            except Exception:
                pass
        items = payload.get("items")
        return items if isinstance(items, list) else []

    @staticmethod
    def _item_text(item: Dict[str, Any]) -> str:
        for field in ("summary", "lesson", "details"):
            val = item.get(field)
            if isinstance(val, str) and val.strip():
                return val.strip()
        body = item.get("body_json")
        if isinstance(body, str) and body.strip():
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    for field in ("summary", "lesson", "details", "content"):
                        val = parsed.get(field)
                        if isinstance(val, str) and val.strip():
                            return val.strip()
            except Exception:
                return body.strip()[:_PREVIEW_CAP]
        return ""

    # ------------------------------------------------------------------
    # Turn persistence
    # ------------------------------------------------------------------

    def sync_turn(self, user_content: str, assistant_content: str, *,
                  session_id: str = "", messages=None) -> None:
        if not self._enabled:
            return
        self._turn_buffer.append({
            "user": (user_content or "")[:2000],
            "assistant": (assistant_content or "")[:2000],
        })
        if len(self._turn_buffer) > _TURN_BUFFER_CAP:
            self._turn_buffer = self._turn_buffer[-_TURN_BUFFER_CAP:]

    def on_session_end(self, messages: List[Dict[str, Any]]) -> None:
        """Distill the session into durable Vault entities (buffer layer)."""
        if not self._enabled or not self._client:
            return
        if self._agent_context != "primary":
            return  # cron/subagent sessions would pollute shared memory
        source = messages if messages else [
            {"role": "user", "content": t["user"]} for t in self._turn_buffer
        ]
        text_parts = []
        total = 0
        for msg in source:
            role = msg.get("role", "")
            if role not in ("user", "assistant"):
                continue
            content = msg.get("content") or ""
            if not isinstance(content, str) or not content.strip():
                continue
            chunk = f"{role.upper()}: {content.strip()}"
            if total + len(chunk) > _SESSION_CAPTURE_MAX_CHARS:
                break
            text_parts.append(chunk)
            total += len(chunk)
        if not text_parts:
            return
        transcript = (
            "Session transcript to distill into durable memories "
            "(facts, decisions, corrections, lessons only; skip chit-chat; "
            "never include secret values):\n\n" + "\n\n".join(text_parts)
        )
        self._client.call_tool(
            "perseus_vault_capture",
            {"text": transcript, "max_entities": 5},
            timeout=60,
        )
        self._turn_buffer.clear()

    # ------------------------------------------------------------------
    # Built-in memory mirroring
    # ------------------------------------------------------------------

    def on_memory_write(self, action: str, target: str, content: str,
                        metadata: Optional[Dict[str, Any]] = None) -> None:
        if not self._enabled or not self._client or not content:
            return
        digest = hashlib.sha1(content.encode()).hexdigest()[:8]
        category = "hermes-memory"
        key = f"builtin-{target}-{digest}"
        if action in ("add", "replace"):
            self._client.call_tool("perseus_vault_remember", {
                "category": category,
                "key": key,
                "body_json": json.dumps({
                    "summary": content[:600],
                    "source": "hermes-builtin-memory",
                    "target": target,
                }),
                "type": "insight",
                "tags": ["hermes", "builtin-memory", target],
            }, timeout=15)
        elif action == "remove":
            self._client.call_tool("perseus_vault_forget", {
                "category": category, "key": key,
                "reason": "removed from built-in memory",
            }, timeout=15)
            self.invalidate_prefetch()

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        # NOTE: MemoryManager.add_provider() snapshots these schemas into its
        # routing table BEFORE initialize() runs, so they must be returned
        # unconditionally. handle_tool_call() stays guarded by _enabled.
        return [REMEMBER_SCHEMA, RECALL_SCHEMA, FORGET_SCHEMA]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any],
                         **kwargs) -> str:
        if not self._enabled or not self._client:
            return json.dumps({"success": False, "error": "perseus-vault not connected"})

        ws_args = ({"workspace_hash": self._workspace_hash}
                   if self._workspace_hash else {})

        if tool_name == "perseus_remember":
            content = (args.get("content") or "").strip()
            if not content:
                return json.dumps({"success": False, "error": "content required"})
            category = (args.get("category") or "general").strip()
            key = (args.get("key") or "").strip() or (
                "fact-" + hashlib.sha1(content.encode()).hexdigest()[:8])
            res = self._client.call_tool("perseus_vault_remember", {
                "category": category,
                "key": key,
                "body_json": json.dumps({"summary": content}),
                "type": "insight",
                "tags": args.get("tags") or [],
                **ws_args,
            }, timeout=20)
            return json.dumps({
                "success": res.get("ok", False),
                "category": category,
                "key": key,
                "result": res.get("text", "")[:800],
            })

        if tool_name == "perseus_recall":
            query = (args.get("query") or "").strip()
            if not query:
                return json.dumps({"success": False, "error": "query required"})
            call_args: Dict[str, Any] = {
                "query": query,
                "limit": min(int(args.get("limit") or 6), 20),
                "preview_cap": _PREVIEW_CAP,
                **ws_args,
            }
            if args.get("category"):
                call_args["category"] = args["category"]
            res = self._client.call_tool("perseus_vault_recall", call_args, timeout=20)
            items = self._extract_items(res)
            return json.dumps({
                "success": res.get("ok", False),
                "count": len(items),
                "items": [{
                    "category": it.get("category", ""),
                    "key": it.get("key", ""),
                    "text": self._item_text(it),
                } for it in items],
            })

        if tool_name == "perseus_forget":
            category = (args.get("category") or "").strip()
            key = (args.get("key") or "").strip()
            if not category or not key:
                return json.dumps({"success": False, "error": "category and key required"})
            res = self._client.call_tool("perseus_vault_forget", {
                "category": category, "key": key, **ws_args,
            }, timeout=15)
            self.invalidate_prefetch()
            return json.dumps({"success": res.get("ok", False),
                               "result": res.get("text", "")[:400]})

        return json.dumps({"success": False, "error": f"unknown tool {tool_name}"})

    # ------------------------------------------------------------------
    # Setup wizard integration
    # ------------------------------------------------------------------

    def get_config_schema(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "token",
                "description": "Perseus Vault MCP bearer token",
                "secret": True,
                "required": True,
                "env_var": "PERSEUS_VAULT_MCP_TOKEN",
                "url": "https://vault.perseus.observer",
            },
            {
                "key": "url",
                "description": "Vault MCP endpoint URL",
                "required": False,
                "default": _DEFAULT_URL,
                "env_var": "PERSEUS_VAULT_URL",
            },
            {
                "key": "workspace_hash",
                "description": "Workspace scope hash (blank = global/unscoped)",
                "required": False,
                "default": "",
                "env_var": "PERSEUS_VAULT_WORKSPACE",
            },
        ]

    def save_config(self, values: Dict[str, Any], hermes_home: str) -> None:
        """Persist non-secret fields into config.yaml under memory.perseus-vault."""
        try:
            from hermes_cli.config import load_config, save_config as _save
            config = load_config()
            memory = config.setdefault("memory", {})
            memory["perseus-vault"] = {k: v for k, v in values.items() if k != "token"}
            _save(config)
        except Exception as e:
            logger.warning("perseus-vault: save_config failed: %s", e)

    def get_status_config(self, provider_config: Dict[str, Any]) -> Dict[str, Any]:
        """Redacted view for `hermes memory status`."""
        return {
            "url": self._url(),
            "workspace_hash": self._resolve(
                "PERSEUS_VAULT_WORKSPACE", "workspace_hash") or "(global)",
            "token": "set (env)" if self._token() else "MISSING",
        }


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    # Exclusive memory-provider discovery supplies a collector whose hook methods
    # are no-ops. Register directly with the host middleware registry here, before
    # provider initialization (whose exceptions Hermes intentionally swallows).
    activate_runtime_hooks()
    ctx.register_memory_provider(PerseusVaultProvider())
