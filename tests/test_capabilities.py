import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import arch as archmod
from rdis.capabilities import capabilities


class Capabilities(unittest.TestCase):
    def test_every_capstone_cpu_listed_actually_builds(self):
        for row in capabilities()["architectures"]:
            if row["engine"] == "Capstone":
                self.assertEqual(archmod.make(row["name"]).name.startswith(row["name"][:3]), True, row["name"])

    def test_verified_claims_point_at_files_that_exist(self):
        for row in capabilities()["architectures"]:
            if row["verified"]:
                self.assertTrue(os.path.exists(os.path.join(ROOT, row["verified"])), row)

    def test_sleigh_cpus_are_never_reported_as_verified_decompilers(self):
        for row in capabilities()["architectures"]:
            if row["engine"].startswith("SLEIGH"):
                self.assertIsInstance(row["decompile"], str)
                self.assertIn("experimental", row["decompile"])

    def test_cli_and_mcp_agree(self):
        out = subprocess.run([sys.executable, "-m", "rdis", "--capabilities"], capture_output=True, text=True,
                             cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
        self.assertEqual(json.loads(out.stdout), capabilities())
        from rdis.mcp_server import _handle
        r = _handle({"method": "tools/call", "params": {"name": "capabilities", "arguments": {}}})
        self.assertEqual(json.loads(r["content"][0]["text"]), capabilities())


if __name__ == "__main__":
    unittest.main()
