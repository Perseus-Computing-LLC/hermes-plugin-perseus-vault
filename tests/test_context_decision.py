from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = "perseus_vault_context_test"

agent = types.ModuleType("agent")
agent.__path__ = []
agent_memory = types.ModuleType("agent.memory_provider")
agent_memory.MemoryProvider = type("MemoryProvider", (), {})
sys.modules["agent"] = agent
sys.modules["agent.memory_provider"] = agent_memory

package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_ROOT)]
sys.modules.setdefault(_PACKAGE, package)
spec = importlib.util.spec_from_file_location(_PACKAGE, _ROOT / "__init__.py", submodule_search_locations=[str(_ROOT)])
assert spec and spec.loader
plugin = importlib.util.module_from_spec(spec)
sys.modules[_PACKAGE] = plugin
spec.loader.exec_module(plugin)


def source(source_id="source-1", text="fixture"):
    return {
        "id": source_id,
        "content_hash": hashlib.sha256(text.encode()).hexdigest(),
        "valid_from": 0,
        "valid_to": None,
        "recorded_at": 0,
        "scope": "workspace:test",
        "trust_class": "verified",
    }


class ContextDecisionTests(unittest.TestCase):
    def test_projection_is_deterministic_and_hash_only(self):
        projection = plugin.build_context_decision_projection(
            [source()], decision="allow", reason_codes=["evidence_in_scope"], stage_refs=["selection-1"]
        )
        self.assertEqual(plugin.validate_context_decision_projection(projection), (True, []))
        self.assertEqual(projection["sensitive_payload"], "not_captured")
        self.assertNotIn("prompt", json.dumps(projection))
        self.assertNotIn("body", json.dumps(projection))

    def test_missing_provenance_abstains_instead_of_allowing(self):
        missing = source()
        missing.pop("trust_class")
        decision, reasons = plugin.derive_context_decision(
            [missing], workspace_scope="workspace:test", require_provenance=True
        )
        self.assertEqual(decision, "abstain")
        self.assertIn("missing_provenance", reasons)

    def test_stale_conflict_scope_timeout_and_ood_are_explicit(self):
        cases = [
            ({"evidence_status": "stale"}, "recover", "stale_evidence"),
            ({"evidence_status": "contradictory"}, "recover", "contradictory_evidence"),
            ({"scope": "workspace:other"}, "constrain", "scope_mismatch"),
            ({"timeout": True}, "abstain", "context_timeout"),
            ({"evidence_sufficient": False}, "abstain", "insufficient_evidence"),
        ]
        for overrides, expected_decision, reason in cases:
            with self.subTest(overrides=overrides):
                item = source()
                item.update(overrides)
                decision, reasons = plugin.derive_context_decision(
                    [item], workspace_scope="workspace:test", require_provenance=False
                )
                self.assertEqual(decision, expected_decision)
                self.assertIn(reason, reasons)

    def test_projection_rejects_tamper_and_raw_fields(self):
        projection = plugin.build_context_decision_projection(
            [source()], decision="constrain", reason_codes=["scope_mismatch"], stage_refs=[]
        )
        projection["decision"] = "allow"
        valid, errors = plugin.validate_context_decision_projection(projection)
        self.assertFalse(valid)
        self.assertIn("contract_digest", errors)

        projection = plugin.build_context_decision_projection(
            [source()], decision="abstain", reason_codes=["missing_evidence"], stage_refs=[]
        )
        projection["context"] = "raw context"
        valid, errors = plugin.validate_context_decision_projection(projection)
        self.assertFalse(valid)
        self.assertIn("forbidden_field:context", errors)


if __name__ == "__main__":
    unittest.main()


__all__ = ["ContextDecisionTests"]


# The test intentionally imports the standalone plugin layout rather than the
# Hermes installation so it remains hermetic and never needs a Vault token.
