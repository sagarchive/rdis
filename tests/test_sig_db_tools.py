"""Tests for signature database tools: sig_db_build, sig_db_load, sig_db_match."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from rdis.mcp_server import _handle


class TestSigDbTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Check if cc and strip are available
        cls.cc_available = shutil.which("cc") is not None
        cls.strip_available = shutil.which("strip") is not None

    def _call(self, tool, **arguments):
        return _handle({"method": "tools/call", "params": {"name": tool, "arguments": arguments}})

    def _payload(self, result):
        """Extract the JSON payload from a tool call result."""
        self.assertFalse(result.get("isError"), f"Tool returned error: {result}")
        return json.loads(result["content"][0]["text"])

    @unittest.skipUnless(shutil.which("cc") and shutil.which("strip"), "cc or strip not available")
    def test_sig_db_build_load_match(self):
        """Build a sig db from a freshly compiled library, load it, and match against it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a small C file
            c_path = os.path.join(tmpdir, "test_lib.c")
            with open(c_path, "w") as f:
                f.write("""
int test_func1(int a, int b) {
    return a + b;
}

int test_func2(int x) {
    int result = 0;
    for (int i = 0; i < x; i++) {
        result += i * 2;
    }
    return result;
}

int test_func3(int n) {
    if (n <= 1) return n;
    return test_func3(n - 1) + test_func3(n - 2);
}
""")

            # Compile to a shared library with symbols
            lib_path = os.path.join(tmpdir, "libtest.dylib")
            result = subprocess.run(
                ["cc", "-shared", "-o", lib_path, c_path],
                capture_output=True,
                text=True
            )
            self.assertEqual(result.returncode, 0, f"Compilation failed: {result.stderr}")
            self.assertTrue(os.path.exists(lib_path), "Shared library not created")

            # Build signature database with extra_libs (from the library with symbols)
            db_path = os.path.join(tmpdir, "test_sig.db")
            result = self._call("sig_db_build", path=lib_path, output_db=db_path, extra_libs=[lib_path])
            payload = self._payload(result)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["output"], db_path)
            self.assertGreater(payload["num_signatures"], 0, "Expected at least one signature")
            self.assertGreater(payload["num_sources"], 0, "Expected at least one source")

            # Load the database and verify metadata
            result = self._call("sig_db_load", path=lib_path, db=db_path)
            payload = self._payload(result)
            self.assertEqual(payload["format"], 1)
            self.assertIn(payload["arch"], ("x86_64", "arm64"))
            self.assertGreater(payload["num_entries"], 0, "Expected num_entries > 0")
            self.assertEqual(payload["sources"][0]["name"], "libtest.dylib")

            # Create a stripped copy of the library for matching
            stripped_path = os.path.join(tmpdir, "libtest_stripped.dylib")
            shutil.copy(lib_path, stripped_path)
            result = subprocess.run(["strip", stripped_path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"Strip failed: {result.stderr}")

            # Match against the stripped library - should find at least one match
            result = self._call("sig_db_match", path=stripped_path, db=db_path)
            payload = self._payload(result)
            self.assertIsInstance(payload["matches"], list)
            self.assertIsInstance(payload["ambiguous"], list)
            self.assertGreater(len(payload["matches"]), 0, "Expected at least one match against the stripped library")


if __name__ == "__main__":
    unittest.main()