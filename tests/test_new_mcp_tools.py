"""Tests for the new MCP tools: xrefs_from, exports, globals."""
import json
import os
import shutil
import tempfile
import unittest

from rdis.mcp_server import _handle


class TestNewMcpTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temp copy of /bin/ls (never write beside /bin/ls)
        cls.tmpdir = tempfile.mkdtemp()
        cls.binary = os.path.join(cls.tmpdir, "ls")
        shutil.copy("/bin/ls", cls.binary)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _call(self, tool, **arguments):
        return _handle({"method": "tools/call", "params": {"name": tool, "arguments": arguments}})

    def _payload(self, result):
        """Extract the JSON payload from a tool call result."""
        self.assertFalse(result.get("isError"), f"Tool returned error: {result}")
        return json.loads(result["content"][0]["text"])

    def test_xrefs_from_returns_non_error(self):
        """xrefs_from returns a non-error result with documented shape."""
        # Use an instruction address known to have xrefs (from first function)
        # 0x1000009a8 is a call instruction in the first function of /bin/ls
        result = self._call("xrefs_from", path=self.binary, addr="0x1000009a8")
        payload = self._payload(result)

        # Check documented shape
        self.assertIn("xrefs", payload)
        self.assertIsInstance(payload["xrefs"], list)
        # Each xref should have from, to, type
        for xref in payload["xrefs"]:
            self.assertIn("from", xref)
            self.assertIn("to", xref)
            self.assertIn("type", xref)
            self.assertTrue(xref["from"].startswith("0x"))
            self.assertTrue(xref["to"].startswith("0x"))
            self.assertIn(xref["type"], ("call", "tail", "jmp", "data"))

    def test_xrefs_from_has_meaningful_value(self):
        """xrefs_from returns at least one meaningful value on /bin/ls."""
        # Use an instruction address known to have outgoing xrefs
        # 0x1000009a8 is a call instruction in the first function of /bin/ls
        result = self._call("xrefs_from", path=self.binary, addr="0x1000009a8")
        payload = self._payload(result)

        # Should have at least one xref
        self.assertGreater(len(payload["xrefs"]), 0, "Expected at least one outgoing xref")
        
        # Verify the xref structure
        for xref in payload["xrefs"]:
            self.assertTrue(xref["from"].startswith("0x"))
            self.assertTrue(xref["to"].startswith("0x"))
            self.assertIn(xref["type"], ("call", "tail", "jmp", "data"))
            
            # The 'from' address should match our query address
            self.assertEqual(xref["from"], "0x1000009a8")

    def test_exports_returns_non_error(self):
        """exports returns a non-error result with documented shape."""
        result = self._call("exports", path=self.binary)
        payload = self._payload(result)

        # Check documented shape
        self.assertIn("exports", payload)
        self.assertIsInstance(payload["exports"], list)
        for exp in payload["exports"]:
            self.assertIn("addr", exp)
            self.assertIn("name", exp)
            self.assertTrue(exp["addr"].startswith("0x"))
            self.assertIsInstance(exp["name"], str)

    def test_globals_returns_non_error(self):
        """globals returns a non-error result with documented shape."""
        result = self._call("globals", path=self.binary)
        payload = self._payload(result)

        # Check documented shape
        self.assertIn("globals", payload)
        self.assertIsInstance(payload["globals"], list)
        for g in payload["globals"]:
            self.assertIn("addr", g)
            self.assertIn("name", g)
            self.assertTrue(g["addr"].startswith("0x"))
            self.assertIsInstance(g["name"], str)


if __name__ == "__main__":
    unittest.main()