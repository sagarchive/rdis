import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scorecard


class Scoring(unittest.TestCase):
    def test_score_counts_hits_misses_and_extras(self):
        row = scorecard.score({1, 2, 3, 4}, {2, 3, 9})
        self.assertEqual((row["true_positives"], row["missed"], row["extra"]), (2, 2, 1))
        self.assertEqual(row["recall"], 0.5)
        self.assertEqual(row["precision_vs_truth_and_extras"], round(2 / 3, 4))

    def test_empty_inputs_do_not_divide_by_zero(self):
        row = scorecard.score(set(), set())
        self.assertIsNone(row["recall"])
        self.assertIsNone(row["precision_vs_truth_and_extras"])


class AdapterParsing(unittest.TestCase):
    def test_radare2_json_after_a_banner(self):
        out = 'WARN: something\n[{"offset": 4096, "name": "main", "size": 12}, {"offset": 4120, "name": "fcn.1", "size": 4}]\n'
        self.assertEqual(scorecard.radare2_parse(out), {4096, 4120})
        self.assertEqual(scorecard.radare2_parse("no json here"), set())

    def test_ghidra_export_ignores_external_functions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.json")
            with open(path, "w") as fh:
                json.dump([{"addr": 4096, "name": "main", "size": 8, "external": False},
                           {"addr": 8192, "name": "puts", "size": 1, "external": True}], fh)
            self.assertEqual(scorecard.ghidra_parse(path), {4096})

    def test_the_ghidra_script_matches_what_the_adapter_reads(self):
        path = os.path.join(scorecard.GHIDRA_SCRIPT_DIR, "ExportFunctions.java")
        with open(path) as fh:
            source = fh.read()
        self.assertIn("public class ExportFunctions extends GhidraScript", source)
        for key in ('\\"addr\\"', '\\"external\\"', "getScriptArgs()[0]"):
            self.assertIn(key, source)


class Availability(unittest.TestCase):
    def test_missing_tools_are_reported_not_estimated(self):
        with mock.patch.object(shutil, "which", return_value=None), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GHIDRA_INSTALL_DIR", None)
            with self.assertRaises(scorecard.ToolUnavailable) as r2:
                scorecard.radare2_command("x")
            self.assertIn("radare2", str(r2.exception))
            with self.assertRaises(scorecard.ToolUnavailable) as gh:
                scorecard.ghidra_command("x", "/tmp")
            self.assertIn("analyzeHeadless", str(gh.exception))

    def test_ghidra_without_java_is_unavailable_even_when_installed(self):
        def which(name):
            return "/opt/ghidra/support/analyzeHeadless" if name == "analyzeHeadless" else None
        with mock.patch.object(shutil, "which", side_effect=which):
            with self.assertRaises(scorecard.ToolUnavailable) as e:
                scorecard.ghidra_command("x", "/tmp")
        self.assertIn("Java", str(e.exception))

    def test_radare2_command_follows_the_documented_flags(self):
        with mock.patch.object(shutil, "which", return_value="/usr/bin/r2"):
            cmd = scorecard.radare2_command("/tmp/bin")
        self.assertEqual(cmd[0], "/usr/bin/r2")
        self.assertIn("aaa;aflj", cmd)
        self.assertEqual(cmd[-2:], ["--", "/tmp/bin"])


class EndToEnd(unittest.TestCase):
    def test_rdis_is_measured_and_absent_competitors_are_marked_not_available(self):
        args = mock.Mock(tools="rdis,radare2,ghidra", extra=[], timeout=60)
        with mock.patch.object(scorecard, "radare2_command", side_effect=scorecard.ToolUnavailable("no r2")), \
                mock.patch.object(scorecard, "ghidra_command", side_effect=scorecard.ToolUnavailable("no ghidra")):
            result = scorecard.run(args)
        if not result["corpus"]:
            self.skipTest("no C compiler available to build the corpus")
        rows = result["tasks"]["function_discovery"]
        for name, row in rows["rdis"].items():
            self.assertEqual(row["status"], "measured", row)
            self.assertTrue(row["adapter_verified"])
            self.assertGreaterEqual(row["recall"], 0.9, row)
            self.assertGreater(row["peak_rss_bytes"], 0)
        for tool in ("radare2", "ghidra"):
            self.assertTrue(all(r["status"] == "not_available" for r in rows[tool].values()))
            self.assertFalse(result["tools"][tool]["available"])
        self.assertEqual({c["name"] for c in result["corpus"]}, {"c-program-v1", "c-program-v2"})
        self.assertTrue(all(len(c["sha256"]) == 64 for c in result["corpus"]))
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()
