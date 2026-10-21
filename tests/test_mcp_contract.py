import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import mcp_server
from rdis.mcp_server import TOOLS, WRITES, _handle

SUBJECT = "/bin/ls"


def rpc(*messages):
    """Send JSON-RPC lines to a real server process and return the parsed replies."""
    lines = "".join(json.dumps(m) + "\n" for m in messages)
    out = subprocess.run([sys.executable, "-m", "rdis.mcp_server"], input=lines, capture_output=True, text=True,
                         cwd=ROOT, timeout=120)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def call(tool, /, **arguments):
    return _handle({"method": "tools/call", "params": {"name": tool, "arguments": arguments}})


def payload(result):
    return json.loads(result["content"][0]["text"])


class SchemaContract(unittest.TestCase):
    def test_every_tool_is_described_typed_and_annotated(self):
        tools = _handle({"method": "tools/list"})["tools"]
        self.assertEqual({t["name"] for t in tools}, set(TOOLS))
        for t in tools:
            with self.subTest(tool=t["name"]):
                self.assertTrue(t["description"].strip())
                schema = t["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                if t["name"] != "capabilities":                # the one tool that needs no file
                    self.assertIn("path", schema["required"])
                self.assertTrue(set(schema["required"]) <= set(schema["properties"]))
                self.assertEqual(t["annotations"]["readOnlyHint"], t["name"] not in WRITES)
                self.assertIs(t["annotations"]["openWorldHint"], False)

    def test_write_tools_are_exactly_the_ones_that_persist_state(self):
        for name in WRITES:
            self.assertIn(name, TOOLS)
        for name in ("rename", "comment", "rename_many", "define_function", "undefine_function", "set_type"):
            self.assertIn(name, WRITES)
        for name in ("decompile", "disassemble", "diff", "signatures", "emulate", "unresolved", "search"):
            self.assertNotIn(name, WRITES)


class DocumentationMatchesCode(unittest.TestCase):
    def test_readme_tool_table_lists_exactly_the_registered_tools(self):
        import re
        with open(os.path.join(ROOT, "README.md")) as fh:
            readme = fh.read()
        section = readme[readme.index("## MCP server"):]
        section = section[:section.index("\n## ", 5)] if "\n## " in section[5:] else section
        table = [row for row in section.splitlines() if row.startswith("| ") and "`" in row and not row.startswith("| Group")]
        documented = {name for row in table for name in re.findall(r"`([a-z_]+)`", row.split("|")[2])}
        self.assertEqual(documented, set(TOOLS))
        self.assertIn(f"{len(TOOLS)} tools", section)
        self.assertIn(f"MCP server ({len(TOOLS)} tools)", open(os.path.join(ROOT, "FEATURE_SUPPORT_MATRIX.md")).read())


class ProtocolErrors(unittest.TestCase):
    def test_bad_requests_get_standard_json_rpc_codes_and_the_server_keeps_running(self):
        replies = rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "nope"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "no_such_tool", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "decompile", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "list_functions", "arguments": {"path": SUBJECT, "limit": "ten"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "list_functions", "arguments": {"path": SUBJECT, "bogus": 1}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"arguments": {}}},
            {"jsonrpc": "2.0", "id": 7, "method": "ping"},
        )
        by_id = {r["id"]: r for r in replies}
        self.assertEqual(by_id[1]["error"]["code"], -32601)
        for i in (2, 3, 4, 5, 6):
            self.assertEqual(by_id[i]["error"]["code"], -32602, by_id[i])
        self.assertIn("missing required", by_id[3]["error"]["message"])
        self.assertIn("must be integer", by_id[4]["error"]["message"])
        self.assertIn("unknown argument", by_id[5]["error"]["message"])
        self.assertEqual(by_id[7]["result"], {})

    def test_boolean_is_not_accepted_as_an_integer(self):
        r = rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "list_functions", "arguments": {"path": SUBJECT, "limit": True}}})
        self.assertEqual(r[0]["error"]["code"], -32602)


class ToolFailures(unittest.TestCase):
    def assertStructured(self, result, code):
        self.assertTrue(result["isError"])
        text = result["content"][0]["text"]
        self.assertNotIn("Traceback", text)
        self.assertNotIn("File \"", text)
        self.assertEqual(json.loads(text)["error"]["code"], code, text)

    def test_missing_file_is_not_found_without_a_traceback(self):
        self.assertStructured(call("info", path="/no/such/binary"), "not_found")

    def test_unknown_function_is_not_found(self):
        self.assertStructured(call("decompile", path=SUBJECT, func="definitely_not_a_function_xyz"), "not_found")

    def test_bad_pattern_and_bad_regex_are_invalid_arguments(self):
        self.assertStructured(call("find_bytes", path=SUBJECT, pattern="zz"), "invalid_argument")
        self.assertStructured(call("find_insns", path=SUBJECT, regex="("), "invalid_argument")

    def test_oversized_results_are_refused_with_paging_advice(self):
        old = mcp_server.MAX_RESPONSE
        mcp_server.MAX_RESPONSE = 50
        try:
            result = call("list_functions", path=SUBJECT)
        finally:
            mcp_server.MAX_RESPONSE = old
        self.assertStructured(result, "response_too_large")
        self.assertIn("limit/offset", payload(result)["error"]["message"])


@unittest.skipUnless(os.path.exists(SUBJECT), "needs /bin/ls")
class Behaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = os.path.join(cls.tmp.name, "subject")
        shutil.copy(SUBJECT, cls.binary)
        cls.env = {k: os.environ.get(k) for k in ("RDIS_CACHE_DIR",)}
        os.environ["RDIS_CACHE_DIR"] = os.path.join(cls.tmp.name, "cache")
        mcp_server._CACHE.clear()

    @classmethod
    def tearDownClass(cls):
        for k, v in cls.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        mcp_server._CACHE.clear()
        cls.tmp.cleanup()

    def test_pages_are_disjoint_and_cover_the_whole_list(self):
        first = payload(call("list_functions", path=self.binary, limit=7, offset=0))
        self.assertTrue(first["truncated"])
        self.assertEqual(first["returned"], 7)
        seen, offset = [], 0
        while True:
            page = payload(call("list_functions", path=self.binary, limit=7, offset=offset))
            self.assertEqual(page["total"], first["total"])
            seen += page["functions"]
            offset += 7
            if not page["truncated"]:
                break
        full = payload(call("list_functions", path=self.binary, limit=5000))
        self.assertEqual(seen, full["functions"])
        self.assertFalse(full["truncated"])
        self.assertEqual(len({f["addr"] for f in seen}), len(seen))

    def test_page_size_is_capped_and_negative_values_are_clamped(self):
        page = payload(call("list_functions", path=self.binary, limit=10 ** 9, offset=-4))
        self.assertEqual((page["limit"], page["offset"]), (mcp_server.MAX_PAGE, 0))

    def test_strings_and_imports_are_paged(self):
        for tool, key in (("strings", "strings"), ("imports", "imports")):
            page = payload(call(tool, path=self.binary, limit=3))
            self.assertLessEqual(page["returned"], 3)
            self.assertEqual(len(page[key]), page["returned"])
            self.assertIn("total", page)

    def test_read_only_tools_never_write_next_to_the_binary(self):
        before = sorted(os.listdir(self.tmp.name))
        funcs = payload(call("list_functions", path=self.binary, limit=3))["functions"]
        target = funcs[0]["addr"]
        for name, args in (("info", {}), ("disassemble", {"func": target}), ("decompile", {"func": target}),
                           ("cfg", {"func": target}), ("xrefs", {"addr": target}), ("callees", {"func": target}),
                           ("callers", {"func": target}), ("basic_blocks", {"func": target}),
                           ("unresolved", {}), ("search", {"query": "main"}), ("lookup", {"addr": target}),
                           ("stack_frame", {"func": target}), ("find_bytes", {"pattern": "?? ??", "limit": 2}),
                           ("find_insns", {"regex": "ret", "limit": 2}), ("jump_tables", {}),
                           ("read_bytes", {"addr": target, "size": 8}), ("hexdump", {"func": target})):
            result = call(name, path=self.binary, **args)
            self.assertFalse(result.get("isError"), (name, result))
        self.assertEqual(sorted(os.listdir(self.tmp.name)), before)
        self.assertFalse([f for f in os.listdir(self.tmp.name) if f.endswith(".rdb")])

    def test_write_tools_persist_and_are_visible_to_later_reads(self):
        funcs = payload(call("list_functions", path=self.binary, limit=2))["functions"]
        addr = funcs[1]["addr"]
        self.assertTrue(payload(call("rename", path=self.binary, addr=addr, name="contract_renamed"))["ok"])
        self.assertTrue(any(f["name"] == "contract_renamed" for f in
                            payload(call("list_functions", path=self.binary, limit=5000))["functions"]))
        self.assertTrue(os.path.exists(self.binary + ".rdb"))


if __name__ == "__main__":
    unittest.main()
