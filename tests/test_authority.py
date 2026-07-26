from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = "perseus_vault_test_plugin"
package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_PLUGIN_ROOT)]
sys.modules.setdefault(_PACKAGE, package)
spec = importlib.util.spec_from_file_location(
    f"{_PACKAGE}.authority", _PLUGIN_ROOT / "authority.py"
)
assert spec and spec.loader
authority = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = authority
spec.loader.exec_module(authority)


class FakeVault:
    def __init__(self, *, approval_required=False, deny=False):
        self.approval_required = approval_required
        self.deny = deny
        self.calls = []

    def call_tool(self, name, args, timeout=None):
        self.calls.append((name, args))
        if self.deny and name.endswith("action_intent"):
            return {"ok": False, "text": "capability is not permitted", "data": None}
        if name.endswith("action_intent"):
            payload = {"id": "act-test", "approval_required": self.approval_required,
                       "status": "approval_requested" if self.approval_required else "intent"}
        elif name.endswith("action_approve"):
            payload = {"id": "act-test", "status": "approval_granted", "approval_ref": "apr-test"}
        elif name.endswith("action_lease_acquire"):
            payload = {"id": "lease-test"}
        elif name.endswith("action_complete"):
            payload = {"id": "act-test", "status": "action_executed"}
        elif name.endswith("action_lease_release"):
            payload = {"released": True}
        else:
            payload = {}
        return {"ok": True, "text": json.dumps(payload), "data": payload}


class AuthorityE2ETest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {
            "HERMES_HOME": self.tmp.name,
            "PERSEUS_VAULT_AUTHORITY_MODE": "enforce",
            "PERSEUS_VAULT_AGENT_ID": "agent-test",
            "PERSEUS_VAULT_WORKSPACE": "ws-test",
            "PERSEUS_VAULT_AUTHORITY_SCOPE": "github:Perseus-Computing-LLC/test",
            "PERSEUS_VAULT_AUTHORITY_EXTERNAL_REF": "github:Perseus-Computing-LLC/test",
            "PERSEUS_VAULT_APPROVER_PRINCIPAL": "user:test",
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def enforcer(self, vault):
        value = authority.AuthorityEnforcer()
        value._client = vault
        return value

    def test_execution_middleware_enforces_full_hash_only_lifecycle(self):
        vault = FakeVault()
        gate = self.enforcer(vault)
        raw_secret = "do-not-store-this-secret"
        executed = []
        result = gate.execution_middleware(
            "terminal", {"command": f"git push origin main # {raw_secret}"},
            lambda args: executed.append(args) or json.dumps({"success": True}),
            tool_call_id="tc-1",
        )
        self.assertEqual(json.loads(result), {"success": True})
        self.assertEqual(len(executed), 1)
        names = [name for name, _ in vault.calls]
        self.assertEqual(names, [
            "perseus_vault_action_intent", "perseus_vault_action_lease_acquire",
            "perseus_vault_action_complete", "perseus_vault_action_lease_release",
        ])
        durable = json.dumps(vault.calls)
        self.assertNotIn(raw_secret, durable)
        intent = vault.calls[0][1]
        self.assertEqual(len(intent["intent_hash"]), 64)
        self.assertNotIn("command", intent)

    def test_unknown_revoked_or_mismatched_authority_blocks(self):
        gate = self.enforcer(FakeVault(deny=True))
        result = gate.execution_middleware(
            "write_file", {"path": "x", "content": "y"},
            lambda args: self.fail("side effect executed despite denied authority"),
            tool_call_id="tc-deny",
        )
        payload = json.loads(result)
        self.assertIn("blocked", payload["error"].lower())

    def test_enforcement_transport_failure_never_executes(self):
        class BrokenVault:
            def call_tool(self, name, args, timeout=None):
                return {"ok": False, "text": "transport unavailable", "data": None}

        gate = self.enforcer(BrokenVault())
        result = gate.execution_middleware(
            "write_file", {"path": "x", "content": "y"},
            lambda args: self.fail("side effect executed while Vault was unavailable"),
            tool_call_id="tc-transport",
        )
        self.assertIn("transport unavailable", json.loads(result)["error"])

    def test_approval_is_vault_event_and_receipt_before_execution(self):
        vault = FakeVault(approval_required=True)
        gate = self.enforcer(vault)
        tools_pkg = types.ModuleType("tools")
        approval_mod = types.ModuleType("tools.approval")
        setattr(approval_mod, "request_tool_approval", lambda *a, **k: {"approved": True})
        setattr(tools_pkg, "approval", approval_mod)
        executed = []
        with patch.dict(sys.modules, {"tools": tools_pkg, "tools.approval": approval_mod}):
            result = gate.execution_middleware(
                "terminal", {"command": "git push origin main"},
                lambda args: executed.append(args) or json.dumps({"success": True}),
                tool_call_id="tc-approval",
            )
        self.assertEqual(json.loads(result), {"success": True})
        self.assertEqual(len(executed), 1)
        names = [name for name, _ in vault.calls]
        self.assertEqual(names[:3], [
            "perseus_vault_action_intent", "perseus_vault_action_approve",
            "perseus_vault_action_lease_acquire",
        ])
        approval = vault.calls[1][1]
        self.assertEqual(approval["decision"], "granted")
        self.assertIn("perseus_vault_action_complete", names)

    def test_approval_denial_records_vault_event_and_never_executes(self):
        vault = FakeVault(approval_required=True)
        gate = self.enforcer(vault)
        tools_pkg = types.ModuleType("tools")
        approval_mod = types.ModuleType("tools.approval")
        setattr(approval_mod, "request_tool_approval", lambda *a, **k: {
            "approved": False, "message": "denied by user",
        })
        setattr(tools_pkg, "approval", approval_mod)
        with patch.dict(sys.modules, {"tools": tools_pkg, "tools.approval": approval_mod}):
            result = gate.execution_middleware(
                "terminal", {"command": "git push origin main"},
                lambda args: self.fail("side effect executed after approval denial"),
                tool_call_id="tc-denied",
            )
        payload = json.loads(result)
        self.assertIn("denied", payload["error"])
        names = [name for name, _ in vault.calls]
        self.assertEqual(names, ["perseus_vault_action_intent", "perseus_vault_action_approve"])
        self.assertEqual(vault.calls[1][1]["decision"], "denied")

    def test_off_mode_is_backward_compatible(self):
        os.environ["PERSEUS_VAULT_AUTHORITY_MODE"] = "off"
        vault = FakeVault()
        gate = self.enforcer(vault)
        calls = []
        result = gate.execution_middleware(
            "write_file", {"path": "x"},
            lambda args: calls.append(args) or "ok", tool_call_id="tc-off",
        )
        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 1)
        self.assertEqual(vault.calls, [])

    def test_temporary_hermes_home_does_not_receive_payload_evidence(self):
        vault = FakeVault()
        gate = self.enforcer(vault)
        sentinel = "payload-must-not-land-on-disk"
        gate.execution_middleware(
            "patch", {"new_string": sentinel}, lambda args: "ok", tool_call_id="tc-home"
        )
        files = [p for p in Path(self.tmp.name).rglob("*") if p.is_file()]
        self.assertEqual(files, [])
        self.assertNotIn(sentinel, json.dumps(vault.calls))


if __name__ == "__main__":
    unittest.main()
