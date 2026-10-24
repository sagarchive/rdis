"""Cross-references from strings to the functions that use them."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis.mcp_server import _handle, _prog
from rdis.stringrefs import string_refs

SOURCE = r'''
#include <stdio.h>
__attribute__((noinline)) void uses_it(void) { puts("rdis-xref-literal-123"); }
__attribute__((noinline)) void also_uses(void) { puts("rdis-xref-literal-123"); puts("rdis-second-literal-456"); }
volatile const char *only_data = "rdis-only-in-data-789";
int main(void) { uses_it(); also_uses(); return only_data == 0; }
'''


def call(tool, **arguments):
    res = _handle({"method": "tools/call", "params": {"name": tool, "arguments": arguments}})
    assert not res.get("isError"), res
    return json.loads(res["content"][0]["text"])


@unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
class CStrings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rdis-xref-")
        src = os.path.join(cls.tmp, "x.c")
        with open(src, "w") as fh:
            fh.write(SOURCE)
        cls.binary = os.path.join(cls.tmp, "x")
        subprocess.run(["cc", "-O1", "-o", cls.binary, src], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rows(self):
        return {s["text"]: s for s in call("strings", path=self.binary, limit=20000)["strings"]}

    def test_a_literal_lists_every_function_that_uses_it(self):
        row = self.rows()["rdis-xref-literal-123"]
        self.assertEqual({r["name"].lstrip("_") for r in row["refs"]}, {"uses_it", "also_uses"})
        self.assertEqual(row["ref_count"], 2)
        for r in row["refs"]:
            self.assertTrue(r["function"].startswith("0x") and r["site"].startswith("0x"))

    def test_a_literal_used_once_lists_one_function(self):
        row = self.rows()["rdis-second-literal-456"]
        self.assertEqual([r["name"].lstrip("_") for r in row["refs"]], ["also_uses"])

    def test_a_string_no_code_loads_has_no_function(self):
        self.assertEqual(self.rows()["rdis-only-in-data-789"]["refs"], [])

    def test_sites_are_inside_the_named_function(self):
        p = _prog(self.binary)
        for addr, rows in string_refs(p).items():
            for r in rows:
                self.assertEqual(p.function_at(r["site"]).addr, r["function"])

    def test_cli_prints_the_referencing_functions(self):
        out = subprocess.run([sys.executable, "-m", "rdis", self.binary, "--strings"], cwd=ROOT, capture_output=True, text=True).stdout
        line = next(l for l in out.splitlines() if "rdis-xref-literal-123" in l)
        self.assertIn("<-", line)
        self.assertIn("uses_it", line)
        self.assertIn("also_uses", line)
        unused = next(l for l in out.splitlines() if "rdis-only-in-data-789" in l)
        self.assertNotIn("<-", unused)


if __name__ == "__main__":
    unittest.main()
