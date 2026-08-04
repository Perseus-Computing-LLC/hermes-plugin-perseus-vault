from __future__ import annotations

import hashlib
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = "perseus_vault_prefetch_test"

agent = types.ModuleType("agent")
agent.__path__ = []
agent_memory = types.ModuleType("agent.memory_provider")
agent_memory.MemoryProvider = type("MemoryProvider", (), {})
sys.modules["agent"] = agent
sys.modules["agent.memory_provider"] = agent_memory

package = types.ModuleType(_PACKAGE)
package.__path__ = [str(_ROOT)]
sys.modules.setdefault(_PACKAGE, package)
spec = __import__("importlib.util").util.spec_from_file_location(
    _PACKAGE, _ROOT / "__init__.py", submodule_search_locations=[str(_ROOT)]
)
assert spec and spec.loader
plugin = __import__("importlib.util").util.module_from_spec(spec)
sys.modules[_PACKAGE] = plugin
spec.loader.exec_module(plugin)


class PrefetchLifecycleTests(unittest.TestCase):
    def provider(self):
        provider = plugin.PerseusVaultProvider()
        provider._enabled = True
        provider._client = Mock()
        return provider

    @staticmethod
    def store(provider, block, *, session_id="", query="next query"):
        provider.store_prefetched(
            block,
            generation=provider.prefetch_generation(),
            session_id=session_id,
            query_digest=plugin._evidence_digest(query),
            source_revision=provider._source_revision,
        )

    def test_forget_invalidates_warmed_context_before_consumption(self):
        provider = self.provider()
        self.store(provider, "secret remembered text")

        provider.invalidate_prefetch()

        self.assertEqual(provider.prefetch("next query"), "")

    def test_stale_warm_completion_cannot_restore_invalidated_context(self):
        provider = self.provider()
        generation = provider.prefetch_generation()
        provider.invalidate_prefetch()

        provider.store_prefetched("stale context", generation=generation)

        self.assertEqual(provider.prefetch("next query"), "")

    def test_legacy_string_prefetch_remains_compatible(self):
        provider = self.provider()
        provider.store_prefetched(
            "legacy context",
            generation=provider.prefetch_generation(),
        )

        self.assertEqual(provider.prefetch("any query"), "legacy context")

    def test_current_generation_result_from_before_source_mutation_is_rejected(self):
        provider = self.provider()
        source = ("source-1", "decision", "old", "digest")
        with provider._prefetch_lock:
            revision = provider._source_revision
            epochs = (provider._source_epochs.get(
                provider._source_epoch_key(source), 0
            ),)

        provider._invalidate_source_key("decision", "old")
        provider.store_prefetched(
            plugin._RecallResult(
                "stale source context",
                (source,),
                revision,
                epochs,
            ),
            generation=provider.prefetch_generation(),
            query_digest=plugin._evidence_digest("next query"),
        )

        self.assertEqual(provider.prefetch("next query"), "")

    def test_forget_uses_the_same_invalidation_path(self):
        provider = self.provider()
        self.store(provider, "remembered context")
        provider._client.call_tool.return_value = {"ok": True, "text": "forgot"}

        result = provider.handle_tool_call(
            "perseus_forget", {"category": "decision", "key": "old"}
        )

        self.assertEqual(provider.prefetch("next query"), "")
        self.assertIn('"success": true', result)

    def test_forget_invalidates_before_backend_failure(self):
        provider = self.provider()
        self.store(provider, "remembered context")
        generation = provider.prefetch_generation()

        def fail_after_observing_invalidation(*args, **kwargs):
            self.assertEqual(provider.prefetch_generation(), generation + 1)
            raise RuntimeError("backend unavailable")

        provider._client.call_tool.side_effect = fail_after_observing_invalidation

        with self.assertRaises(RuntimeError):
            provider.handle_tool_call(
                "perseus_forget", {"category": "decision", "key": "old"}
            )

        self.assertEqual(provider.prefetch("next query"), "")

    def test_invalid_forget_does_not_invalidate(self):
        provider = self.provider()
        self.store(provider, "remembered context")
        generation = provider.prefetch_generation()

        result = provider.handle_tool_call("perseus_forget", {"category": "decision"})

        self.assertIn('"success": false', result)
        self.assertEqual(provider.prefetch_generation(), generation)
        self.assertEqual(provider.prefetch("next query"), "remembered context")

    def test_forget_invalidates_when_backend_is_disconnected(self):
        provider = self.provider()
        self.store(provider, "remembered context")
        provider._enabled = False
        provider._client = None

        result = provider.handle_tool_call(
            "perseus_forget", {"category": "decision", "key": "old"}
        )

        self.assertIn('"success": false', result)
        self.assertEqual(provider.prefetch("next query"), "")

    def test_disconnected_forget_clears_matching_source_cache(self):
        provider = self.provider()
        source = ("", "decision", "old", "digest")
        provider.store_prefetched(
            plugin._RecallResult("forgotten source", (source,)),
            generation=provider.prefetch_generation(),
            source_revision=provider._source_revision,
            query_digest=plugin._evidence_digest("next query"),
        )
        provider._enabled = False
        provider._client = None

        provider.handle_tool_call(
            "perseus_forget", {"category": "decision", "key": "old"}
        )

        self.assertEqual(provider.prefetch("next query"), "")

    def test_cached_entry_validation_happens_under_prefetch_lock(self):
        provider = self.provider()
        self.store(provider, "fresh context")

        class TrackingLock:
            def __init__(self):
                self._lock = threading.Lock()

            def __enter__(self):
                self._lock.acquire()
                return self

            def __exit__(self, exc_type, exc, tb):
                self._lock.release()

            def locked(self):
                return self._lock.locked()

        lock = TrackingLock()
        provider._prefetch_lock = lock
        observed = []

        def match_under_lock(*args, **kwargs):
            observed.append(lock.locked())
            return True

        provider._prefetch_entry_matches = match_under_lock

        self.assertEqual(provider.prefetch("next query"), "fresh context")
        self.assertEqual(observed, [True])


    def test_sync_prefetch_discards_result_if_invalidated_while_recalling(self):
        provider = self.provider()
        provider._session_id = "session-1"
        provider._principal = "principal-1"
        provider._workspace_hash = "workspace-1"

        def recall_then_invalidate(*args, **kwargs):
            provider.invalidate_prefetch()
            return plugin._RecallResult("stale synchronous context")

        provider._build_recall_block = Mock(side_effect=recall_then_invalidate)

        self.assertEqual(provider.prefetch("next query"), "")

    def test_sync_prefetch_discards_result_if_session_changes_while_recalling(self):
        provider = self.provider()
        provider._session_id = "session-1"

        def recall_then_switch(*args, **kwargs):
            provider.on_session_switch("session-2")
            return plugin._RecallResult("stale session context")

        provider._build_recall_block = Mock(side_effect=recall_then_switch)

        self.assertEqual(provider.prefetch("next query"), "")

    def test_initialize_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "old initialized context")
        generation = provider.prefetch_generation()

        with patch.object(plugin, "VaultMCPClient") as client_class, \
             patch.object(plugin, "activate_runtime_hooks"):
            client_class.return_value.start.return_value = None
            provider.initialize("new-session")

        self.assertEqual(provider.prefetch_generation(), generation + 1)
        self.assertEqual(provider._session_id, "new-session")

    def test_initialize_rebinds_identity_atomically_before_hooks_run(self):
        provider = self.provider()
        provider._session_id = "old-session"
        provider._principal = "old-principal"
        provider._workspace_hash = "old-workspace"
        observed = {}

        def observe_initialized_state():
            observed.update(
                session=provider._session_id,
                principal=provider._principal,
                workspace=provider._workspace_hash,
                generation=provider.prefetch_generation(),
            )

        with patch.object(plugin, "VaultMCPClient") as client_class, \
             patch.object(
                 plugin,
                 "activate_runtime_hooks",
                 side_effect=observe_initialized_state,
             ), \
             patch.object(
                 provider,
                 "_resolve",
                 return_value="new-workspace",
             ):
            client_class.return_value.start.return_value = None
            provider.initialize(
                "new-session",
                user_id="new-principal",
            )

        self.assertEqual(
            observed,
            {
                "session": "new-session",
                "principal": "new-principal",
                "workspace": "new-workspace",
                "generation": 1,
            },
        )

    def test_shutdown_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "old shutdown context")
        generation = provider.prefetch_generation()

        provider.shutdown()

        self.assertEqual(provider.prefetch_generation(), generation + 1)
        self.assertEqual(provider.prefetch("next query"), "")

    def test_session_switch_invalidates_warmed_context_and_updates_identity(self):
        provider = self.provider()
        provider._session_id = "old-session"
        self.store(provider, "old session context", session_id="old-session")

        provider.on_session_switch("new-session", reset=True)

        self.assertEqual(provider._session_id, "new-session")
        self.assertEqual(provider.prefetch("next query"), "")

    def test_reset_session_switch_clears_old_turn_buffer(self):
        provider = self.provider()
        provider._enabled = True
        provider._turn_buffer = [{"user": "old-user", "assistant": "old-answer"}]
        provider._client.call_tool.return_value = {"ok": True, "text": "captured"}

        provider.on_session_switch("new-session", reset=True)
        provider.on_session_end([])

        provider._client.call_tool.assert_not_called()
        self.assertEqual(provider._turn_buffer, [])

    def test_rewound_session_switch_clears_old_turn_buffer(self):
        provider = self.provider()
        provider._enabled = True
        provider._turn_buffer = [{"user": "old-user", "assistant": "old-answer"}]

        provider.on_session_switch("same-session", rewound=True)

        self.assertEqual(provider._turn_buffer, [])

    def test_builtin_memory_removal_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "mirrored context")

        provider.on_memory_write("remove", "MEMORY.md", "old content")

        self.assertEqual(provider.prefetch("next query"), "")

    def test_builtin_memory_replace_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "old replaced context")

        provider.on_memory_write("replace", "MEMORY.md", "new content")

        self.assertEqual(provider.prefetch("next query"), "")

    def test_source_epoch_key_is_stable_for_category_and_key(self):
        provider = self.provider()
        provider._source_epochs[("category-key", "hermes-memory", "builtin-MEMORY.md")] = 4
        provider._source_epochs[("identity", "", "digest")] = 9

        self.assertEqual(
            provider._source_epoch_key(
                ("source-1", "hermes-memory", "builtin-MEMORY.md", "digest")
            ),
            ("category-key", "hermes-memory", "builtin-MEMORY.md"),
        )
        self.assertEqual(
            provider._source_epoch_key(("source-1", "", "", "digest")),
            ("identity", "source-1", "digest"),
        )

    def test_source_key_invalidation_discards_warm_source_before_consume(self):
        provider = self.provider()
        source = ("", "hermes-memory", "builtin-MEMORY.md", "old-digest")
        provider.store_prefetched(
            plugin._RecallResult("old source context", (source,)),
            generation=provider.prefetch_generation(),
            source_revision=provider._source_revision,
            query_digest=plugin._evidence_digest("next query"),
        )

        provider._invalidate_source_key("hermes-memory", "builtin-MEMORY.md")

        self.assertEqual(provider.prefetch("next query"), "")

    def test_builtin_replace_invalidates_previous_digest_key(self):
        provider = self.provider()
        old_key = "builtin-MEMORY.md-old"
        provider._builtin_source_keys["MEMORY.md"] = {old_key}
        source = ("", "hermes-memory", old_key, "old-digest")
        provider.store_prefetched(
            plugin._RecallResult(
                "old built-in context",
                (source,),
                provider._source_revision,
                (0,),
            ),
            generation=provider.prefetch_generation(),
            query_digest=plugin._evidence_digest("next query"),
        )

        provider.on_memory_write("replace", "MEMORY.md", "new content")

        self.assertEqual(provider.prefetch("next query"), "")

    def test_builtin_memory_replace_invalidates_matching_warm_source(self):
        provider = self.provider()
        source = ("", "hermes-memory", "builtin-MEMORY.md", "old-digest")
        provider.store_prefetched(
            plugin._RecallResult("old source context", (source,)),
            generation=provider.prefetch_generation(),
            source_revision=provider._source_revision,
            query_digest=plugin._evidence_digest("next query"),
        )

        provider._invalidate_source_ref(source)

        self.assertEqual(provider.prefetch("next query"), "")

    def test_empty_builtin_removal_uses_old_text_and_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "removed context")
        provider._builtin_source_keys.setdefault("MEMORY.md", set()).add(
            "builtin-MEMORY.md-abc12345"
        )

        provider.on_memory_write(
            "remove",
            "MEMORY.md",
            "",
            {"old_text": "old content"},
        )

        self.assertEqual(
            provider._client.call_tool.call_args_list,
            [
                call("perseus_vault_forget", {
                    "category": "hermes-memory",
                    "key": "builtin-MEMORY.md-abc12345",
                    "reason": "removed from built-in memory",
                }, timeout=15),
            ],
        )
        provider._client.call_tool.reset_mock()
        self.assertEqual(provider.prefetch("next query"), "")

    def test_removal_without_old_text_still_invalidates_warmed_context(self):
        provider = self.provider()
        self.store(provider, "removed context")

        provider.on_memory_write("remove", "MEMORY.md", "")

        provider._client.call_tool.reset_mock()
        self.assertEqual(provider.prefetch("next query"), "")
        self.assertFalse(
            any(
                call_args.args
                and call_args.args[0] == "perseus_vault_forget"
                for call_args in provider._client.call_tool.call_args_list
            )
        )

    def test_removal_invalidates_when_provider_is_disconnected(self):
        provider = self.provider()
        self.store(provider, "removed context")
        provider._enabled = False
        provider._client = None

        provider.on_memory_write("remove", "MEMORY.md", "")

        self.assertEqual(provider.prefetch("next query"), "")

    def test_queued_prefetch_captures_generation_before_worker_starts(self):
        provider = self.provider()
        provider._build_recall_block = Mock(
            side_effect=[plugin._RecallResult("stale context"), plugin._RecallResult("")]
        )

        with patch.object(plugin.threading, "Thread") as thread_class:
            provider.queue_prefetch("query")
            worker = thread_class.call_args.kwargs["target"]
            provider.invalidate_prefetch()
            worker()

        self.assertIsNone(provider._prefetched)
        self.assertEqual(provider.prefetch("query"), "")

    def test_queued_prefetch_captures_source_revision_before_worker_starts(self):
        provider = self.provider()
        provider._build_recall_block = Mock(
            side_effect=[
                plugin._RecallResult("stale context"),
                plugin._RecallResult(""),
            ]
        )

        with patch.object(plugin.threading, "Thread") as thread_class:
            provider.queue_prefetch("query")
            worker = thread_class.call_args.kwargs["target"]
            provider._invalidate_source_key("decision", "old")
            worker()

        self.assertIsNone(provider._prefetched)
        self.assertEqual(provider.prefetch("query"), "")

    def test_legacy_string_store_still_consumed_without_metadata(self):
        provider = self.provider()

        provider.store_prefetched("legacy block", generation=provider.prefetch_generation())

        self.assertEqual(provider.prefetch("any query"), "legacy block")

    def test_warmed_context_is_returned_for_matching_query_and_session(self):
        provider = self.provider()
        provider._session_id = "session-1"
        self.store(
            provider,
            "fresh context",
            session_id="session-1",
        )

        self.assertEqual(
            provider.prefetch("next query", session_id="session-1"),
            "fresh context",
        )

    def test_warmed_context_is_not_returned_after_workspace_changes(self):
        provider = self.provider()
        self.store(provider, "old workspace context")
        provider._workspace_hash = "workspace:new"

        with patch.object(
            provider,
            "_build_recall_block",
            return_value=plugin._RecallResult(""),
        ):
            self.assertEqual(provider.prefetch("next query"), "")

    def test_warmed_context_is_not_returned_after_principal_changes(self):
        provider = self.provider()
        provider._principal = "principal-old"
        self.store(provider, "old principal context")
        provider._principal = "principal-new"

        with patch.object(
            provider,
            "_build_recall_block",
            return_value=plugin._RecallResult(""),
        ):
            self.assertEqual(provider.prefetch("next query"), "")

    def test_warmed_context_is_not_returned_for_a_different_session(self):
        provider = self.provider()
        self.store(provider, "old session context", session_id="old-session")

        with patch.object(provider, "_build_recall_block", return_value=plugin._RecallResult("")):
            self.assertEqual(
                provider.prefetch("next query", session_id="new-session"),
                "",
            )

    def test_warmed_context_is_not_returned_for_a_different_query(self):
        provider = self.provider()
        self.store(provider, "old query context", query="old query")

        with patch.object(provider, "_build_recall_block", return_value=plugin._RecallResult("")):
            self.assertEqual(provider.prefetch("new query"), "")

    def test_lifecycle_capabilities_report_supported_and_unsupported_operations(self):
        capabilities = self.provider().lifecycle_capabilities()

        self.assertEqual(capabilities["schema_version"], "perseus-memory-lifecycle/v1")
        self.assertTrue(capabilities["addressed_forget"])
        self.assertTrue(capabilities["prefetch_invalidation"])
        self.assertFalse(capabilities["semantic_rejection"])
        self.assertFalse(capabilities["supersession"])
        self.assertFalse(capabilities["derived_artifact_invalidation"])
        self.assertEqual(
            capabilities["unsupported_behavior"],
            "explicit_false_capability",
        )

    def test_source_identity_is_digest_only(self):
        item = {
            "id": "source-1",
            "category": "decision",
            "key": "k",
            "summary": "private context",
        }

        result = plugin.PerseusVaultProvider._source_ref(item, "private context")

        self.assertEqual(result[:3], ("source-1", "decision", "k"))
        self.assertNotIn("private context", result)
        self.assertEqual(len(result[3]), 64)

if __name__ == "__main__":
    unittest.main()
