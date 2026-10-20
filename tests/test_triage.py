import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import sleigh_fixtures as F
from rdis import triage as T


def elf(directory, name="x.elf", cpu="ppc", **kwargs):
    data, _, _ = F.elf(cpu, **kwargs)
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def kinds(report, severity=None):
    return {i["indicator"] for i in report["indicators"] if severity in (None, i["severity"])}


class Entropy(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(T.entropy(b""), 0.0)
        self.assertEqual(T.entropy(b"\0" * 1000), 0.0)
        self.assertAlmostEqual(T.entropy(bytes(range(256)) * 4), 8.0)
        self.assertAlmostEqual(T.entropy(b"ab" * 500), 1.0)


class Indicators(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.rng = random.Random(7)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ordinary_code_raises_nothing(self):
        code = bytes.fromhex("9421fff0" "7c0802a6" "38600001" "4e800020") * 200
        report = T.triage(elf(self.dir, code=code))
        self.assertEqual(report["indicators"], [])

    def test_random_bytes_in_an_executable_section_are_notable(self):
        report = T.triage(elf(self.dir, code=self.rng.randbytes(4096)))
        self.assertIn("high-entropy executable section", kinds(report, "notable"))

    def test_compressed_code_is_flagged_like_random_data(self):
        plain = b"".join(f"mov r{n % 31}, {n}\n".encode() for n in range(4000))
        report = T.triage(elf(self.dir, code=zlib.compress(plain, 9)))
        self.assertIn("high-entropy executable section", kinds(report, "notable"))

    def test_high_entropy_data_in_a_non_executable_section_is_informational_only(self):
        report = T.triage(elf(self.dir, code=self.rng.randbytes(4096), sh_flags=2, ph_flags=4))
        self.assertEqual(kinds(report, "notable"), set())
        self.assertIn("high-entropy section", kinds(report, "informational"))

    def test_packer_section_names(self):
        report = T.triage(elf(self.dir, code=bytes(600), section="UPX0"))
        row = next(i for i in report["indicators"] if i["indicator"] == "packer section name")
        self.assertEqual(row["consistent_with"], ["UPX"])

    def test_entry_point_outside_every_executable_section(self):
        report = T.triage(elf(self.dir, code=bytes(600), entry=0x7000000))
        self.assertIn("entry point outside executable sections", kinds(report))

    def test_writable_executable_segment(self):
        report = T.triage(elf(self.dir, code=bytes(600), sh_flags=7, ph_flags=7))
        self.assertIn("writable and executable segment", kinds(report))

    def test_runtime_markers_report_their_evidence(self):
        code = b"\0" * 64 + b"Go build ID: abc" + b"\0" * 64 + b"runtime.main" + b"\0" * 64
        report = T.triage(elf(self.dir, code=code))
        go = next(r for r in report["runtimes"] if r["runtime"] == "Go")
        self.assertEqual(go["evidence"], ["Go build ID", "runtime.main"])

    def test_no_output_ever_claims_a_verdict(self):
        report = T.triage(elf(self.dir, code=self.rng.randbytes(4096), section="UPX0", sh_flags=7, ph_flags=7))
        findings = json.dumps({k: v for k, v in report.items() if k != "note"}).lower()
        for word in ("malicious", "malware", "verdict", "virus", "trojan", "suspicious"):
            self.assertNotIn(word, findings)
        self.assertIn("not verdicts", report["note"])
        for indicator in report["indicators"]:
            self.assertTrue(indicator["evidence"] and indicator["consistent_with"])

    def test_large_sections_are_sampled_not_read_whole(self):
        report = T.triage(elf(self.dir, code=bytes(4 * T.SAMPLE)))
        self.assertTrue(report["sections"][0]["sampled"])


class RealBinaries(unittest.TestCase):
    @unittest.skipUnless(os.path.exists("/bin/ls"), "needs /bin/ls")
    def test_a_system_binary_has_no_notable_indicator(self):
        self.assertEqual(kinds(T.triage("/bin/ls"), "notable"), set())

    def test_files_that_are_not_binaries_are_a_value_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "script.sh")
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\necho hi\n")
            with self.assertRaises(ValueError):
                T.triage(path)


class Interfaces(unittest.TestCase):
    def test_cli_and_mcp(self):
        with tempfile.TemporaryDirectory() as d:
            path = elf(d, code=random.Random(3).randbytes(4096))
            env = {**os.environ, "PYTHONPATH": ROOT}
            cli = subprocess.run([sys.executable, "-m", "rdis", path, "--triage", "--json"], capture_output=True,
                                 text=True, env=env, cwd=ROOT)
            self.assertEqual(cli.returncode, 0, cli.stderr)
            self.assertIn("high-entropy executable section", {i["indicator"] for i in json.loads(cli.stdout)["indicators"]})
            text = subprocess.run([sys.executable, "-m", "rdis", path, "--triage"], capture_output=True, text=True,
                                  env=env, cwd=ROOT).stdout
            self.assertIn("[notable] high-entropy executable section", text)
            from rdis.mcp_server import _handle
            r = _handle({"method": "tools/call", "params": {"name": "triage", "arguments": {"path": path}}})
            self.assertFalse(r.get("isError"), r)
            self.assertEqual(json.loads(r["content"][0]["text"])["format"], "elf")


if __name__ == "__main__":
    unittest.main()
