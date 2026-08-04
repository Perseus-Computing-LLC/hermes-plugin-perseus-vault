from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock

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

    def test_forget_invalidates_warmed_context_before_consumption(self):
        provider = self.provider()
        provider._prefetched = "secret remembered text"

        provider.invalidate_prefetch()

        self.assertEqual(provider.prefetch("next query"), "")

    def test_stale_warm_completion_cannot_restore_invalidated_context(self):
        provider = self.provider()
        generation = provider.prefetch_generation()
        provider.invalidate_prefetch()

        provider.store_prefetched("stale context", generation=generation)

        self.assertEqual(provider.prefetch("next query"), "")

    def test_forget_uses_the_same_invalidation_path(self):
        provider = self.provider()
        provider._prefetched = "remembered context"
        provider._client.call_tool.return_value = {"ok": True, "text": "forgot"}

        result = provider.handle_tool_call(
            "perseus_forget", {"category": "decision", "key": "old"}
        )

        self.assertEqual(provider._prefetched, "")
        self.assertIn('"success": true', result)

    def test_builtin_memory_removal_invalidates_warmed_context(self):
        provider = self.provider()
        provider._prefetched = "mirrored context"

        provider.on_memory_write("remove", "MEMORY.md", "old content")

        self.assertEqual(provider._prefetched, "")


if __name__ == "__main__":
    unittest.main()
