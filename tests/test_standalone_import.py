from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


class StandaloneImportTests(unittest.TestCase):
    def test_plugin_entrypoint_imports_as_standalone_module(self):
        root = Path(__file__).resolve().parents[1]
        code = """
import sys, types
sys.path.insert(0, sys.argv[1])
agent = types.ModuleType('agent')
agent.__path__ = []
mem = types.ModuleType('agent.memory_provider')
mem.MemoryProvider = type('MemoryProvider', (), {})
sys.modules['agent'] = agent
sys.modules['agent.memory_provider'] = mem
import __init__
assert __init__.EVIDENCE_CONTROL_SCHEMA == 'perseus-evidence-control/v1'
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
