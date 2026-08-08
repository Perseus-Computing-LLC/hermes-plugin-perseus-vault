from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = "perseus_vault_config_test"

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


class ConfigResolutionTests(unittest.TestCase):
    @staticmethod
    def config_module(config):
        module = types.ModuleType("hermes_cli.config")

        def cfg_get(value, *path):
            for key in path:
                value = value.get(key, {}) if isinstance(value, dict) else {}
            return value

        module.cfg_get = cfg_get
        module.load_config = lambda: config
        return module

    def test_active_mcp_server_url_is_fallback_for_provider(self):
        config = {
            "memory": {"provider": "perseus-vault"},
            "mcp_servers": {
                "perseus-vault": {
                    "url": "http://10.168.168.29:8768/message",
                }
            },
        }
        hermes_cli = types.ModuleType("hermes_cli")
        config_module = self.config_module(config)
        with patch.dict(
            sys.modules,
            {"hermes_cli": hermes_cli, "hermes_cli.config": config_module},
        ), patch.dict(
            os.environ,
            {"PERSEUS_VAULT_MCP_TOKEN": "test-token"},
            clear=True,
        ):
            self.assertEqual(
                plugin.PerseusVaultProvider._url(),
                "http://10.168.168.29:8768/message",
            )

    def test_memory_provider_url_beats_active_mcp_server_url(self):
        config = {
            "memory": {
                "perseus-vault": {"url": "https://configured.example/message"}
            },
            "mcp_servers": {
                "perseus-vault": {"url": "http://10.168.168.29:8768/message"}
            },
        }
        hermes_cli = types.ModuleType("hermes_cli")
        config_module = self.config_module(config)
        with patch.dict(
            sys.modules,
            {"hermes_cli": hermes_cli, "hermes_cli.config": config_module},
        ), patch.dict(
            os.environ,
            {"PERSEUS_VAULT_MCP_TOKEN": "test-token"},
            clear=True,
        ):
            self.assertEqual(
                plugin.PerseusVaultProvider._url(),
                "https://configured.example/message",
            )

    def test_environment_url_beats_both_config_sources(self):
        config = {
            "memory": {
                "perseus-vault": {"url": "https://configured.example/message"}
            },
            "mcp_servers": {
                "perseus-vault": {"url": "http://10.168.168.29:8768/message"}
            },
        }
        hermes_cli = types.ModuleType("hermes_cli")
        config_module = self.config_module(config)
        with patch.dict(
            sys.modules,
            {"hermes_cli": hermes_cli, "hermes_cli.config": config_module},
        ), patch.dict(
            os.environ,
            {
                "PERSEUS_VAULT_MCP_TOKEN": "test-token",
                "PERSEUS_VAULT_URL": "https://env.example/message",
            },
            clear=True,
        ):
            self.assertEqual(
                plugin.PerseusVaultProvider._url(),
                "https://env.example/message",
            )


if __name__ == "__main__":
    unittest.main()
