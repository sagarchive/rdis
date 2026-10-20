"""A short, deterministic slice of the fuzz campaign (tests/fuzz.py). The full campaign runs offline; this keeps
every fixed finding fixed on each build. Seeds and counts are fixed, so a failure replays exactly."""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    import pypcode
except ImportError:
    pypcode = None


class FuzzSmoke(unittest.TestCase):
    def campaign(self, targets, seeds=3, cases=40):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "fuzz.py"), "--seeds", str(seeds), "--cases",
                            str(cases), "--targets", targets], capture_output=True, text=True, timeout=900,
                           env={**os.environ, "PYTHONPATH": ROOT})
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-500:])
        for line in r.stdout.splitlines():
            if "ran" in line:
                self.assertIn("distinct failures 0", line)

    def test_parsers_survive_mutated_input(self):
        self.campaign("elf,zip,wasm,mcp")

    @unittest.skipIf(pypcode is None, "pypcode is not installed")
    def test_sleigh_decoding_and_ir_survive_random_machine_code(self):
        self.campaign("decode,ir", seeds=18, cases=15)


if __name__ == "__main__":
    unittest.main()
