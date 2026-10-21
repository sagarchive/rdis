import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples", "plugins")


def rdis(*args, plugins=None, cwd=None, stdin=None):
    env = {k: v for k, v in os.environ.items() if k != "RDIS_PLUGINS"}
    env["PYTHONPATH"] = ROOT
    if plugins:
        env["RDIS_PLUGINS"] = plugins
    return subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True, env=env, cwd=cwd or ROOT,
                          input=stdin, timeout=120)


def write(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(body))
    return path


try:
    import pypcode
except ImportError:
    pypcode = None


class ExamplePlugins(unittest.TestCase):
    def test_loader_and_tool_examples_work(self):
        status = rdis("rdis", "--list-plugins", plugins=EXAMPLES).stdout
        for name in ("count_calls.py", "ppc_alias.py", "tiny_loader.py"):
            self.assertRegex(status, rf"ok .*{name}")
        with tempfile.TemporaryDirectory() as d:
            tiny = os.path.join(d, "s.tiny")
            with open(tiny, "wb") as fh:
                fh.write(b"TINY\x01\x31\xc0\xc3")
            listing = rdis("rdis", tiny, plugins=EXAMPLES)
            self.assertEqual(listing.returncode, 0, listing.stderr)
            self.assertIn("entry", listing.stdout)
            blob = os.path.join(d, "f.bin")
            with open(blob, "wb") as fh:
                fh.write(bytes.fromhex("e801000000" "c3" "c3"))
            out = rdis("rdis", blob, "--loader", "raw", "--arch", "x86_64", "--base", "0x1000", "--tool", "count_calls",
                       plugins=EXAMPLES)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(json.loads(out.stdout)["call_edges"], 1)

    def test_architecture_example_is_registered_and_listed(self):
        self.assertIn("ppc32be", rdis("rdis", "--list-archs", plugins=EXAMPLES).stdout)

    @unittest.skipIf(pypcode is None, "the example aliases a SLEIGH CPU, which needs pypcode")
    def test_architecture_example_loads_a_binary(self):
        with tempfile.TemporaryDirectory() as d:
            blob = os.path.join(d, "f.bin")
            with open(blob, "wb") as fh:
                fh.write(bytes.fromhex("9421fff0" "4e800020"))
            out = rdis("rdis", blob, "--loader", "raw", "--arch", "ppc32be", "--base", "0x1000", "--tool", "count_calls",
                       plugins=EXAMPLES)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(json.loads(out.stdout)["functions"], 1)


class Isolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        write(d, "01_good.py", '''
            from rdis import plugins
            RDIS_API = 1
            plugins.register_tool("t1", lambda program, **k: {"ok": True}, "good")
        ''')
        write(d, "02_half.py", '''
            from rdis import plugins
            RDIS_API = 1
            plugins.register_tool("half", lambda program, **k: 1)
            raise RuntimeError("fails after registering")
        ''')
        write(d, "03_old_api.py", "RDIS_API = 2\n")
        write(d, "04_no_api.py", "x = 1\n")
        write(d, "05_exits.py", "import sys\nsys.exit(3)\n")
        write(d, "06_dup.py", '''
            from rdis import plugins
            RDIS_API = 1
            plugins.register_tool("dup_only", lambda program, **k: 1)
            plugins.register_tool("t1", lambda program, **k: 2)
        ''')
        write(d, "07_bad_probe.py", '''
            from rdis import plugins
            RDIS_API = 1
            def probe(path, opts):
                raise KeyError("probe bug")
            plugins.register_loader("bad", probe, lambda path, **k: None)
        ''')
        write(d, "08_shadow.py", '''
            from rdis import plugins
            RDIS_API = 1
            plugins.register_loader("raw", lambda path, opts: True, lambda path, **k: None)
        ''')

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_failure_is_reported_with_its_reason_and_rolled_back(self):
        out = rdis("rdis", "--list-plugins", plugins=self.tmp.name).stdout
        self.assertRegex(out, r"ok\s+.*01_good\.py: registers tool t1")
        self.assertRegex(out, r"REJECTED .*02_half\.py: RuntimeError: fails after registering")
        self.assertRegex(out, r"REJECTED .*03_old_api\.py: ValueError: declares RDIS_API = 2")
        self.assertRegex(out, r"REJECTED .*04_no_api\.py: ValueError: declares RDIS_API = None")
        self.assertRegex(out, r"REJECTED .*05_exits\.py: SystemExit")
        self.assertRegex(out, r"REJECTED .*06_dup\.py: ValueError: tool 't1' is already registered by .*01_good\.py")
        self.assertRegex(out, r"REJECTED .*08_shadow\.py: ValueError: loader 'raw' is already registered by builtin")

    def test_core_analysis_still_works_with_broken_plugins_loaded(self):
        blob = os.path.join(self.tmp.name, "sample.bin")
        with open(blob, "wb") as fh:
            fh.write(bytes.fromhex("31c0c3"))
        out = rdis("rdis", blob, "--loader", "raw", "--arch", "x86_64", "--base", "0x1000", plugins=self.tmp.name)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("start", out.stdout)

    def test_rolled_back_names_are_gone_and_the_survivor_works(self):
        blob = os.path.join(self.tmp.name, "sample.bin")
        with open(blob, "wb") as fh:
            fh.write(bytes.fromhex("31c0c3"))
        base = ("rdis", blob, "--loader", "raw", "--arch", "x86_64", "--base", "0x1000")
        self.assertEqual(json.loads(rdis(*base, "--tool", "t1", plugins=self.tmp.name).stdout), {"ok": True})
        for gone in ("half", "dup_only"):
            r = rdis(*base, "--tool", gone, plugins=self.tmp.name)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("no plugin tool", r.stderr)

    def test_a_loader_whose_probe_raises_does_not_break_opening_other_files(self):
        blob = os.path.join(self.tmp.name, "plain.bin")
        with open(blob, "wb") as fh:
            fh.write(b"\x7fELF" + bytes(60))
        out = rdis("rdis", blob, plugins=self.tmp.name)
        self.assertNotIn("Traceback", out.stderr)

    def test_unknown_loader_name_is_a_clear_error(self):
        r = rdis("rdis", "/bin/ls", "--loader", "nonesuch")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown loader 'nonesuch'", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


class TrustBoundary(unittest.TestCase):
    def test_nothing_in_the_current_directory_is_executed(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "plugins"))
            marker = os.path.join(d, "pwned")
            write(os.path.join(d, "plugins"), "evil.py", f"open({marker!r}, 'w').close()\nRDIS_API = 1\n")
            out = rdis("rdis", "--list-plugins", cwd=d)
            self.assertIn("no plugins loaded", out.stdout)
            self.assertFalse(os.path.exists(marker))
            blob = os.path.join(d, "b.bin")
            with open(blob, "wb") as fh:
                fh.write(b"\xc3")
            rdis("rdis", blob, "--loader", "raw", "--arch", "x86_64", cwd=d)
            self.assertFalse(os.path.exists(marker))


class McpPluginTools(unittest.TestCase):
    def test_plugin_tools_are_listed_validated_and_never_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            blob = os.path.join(d, "f.bin")
            with open(blob, "wb") as fh:
                fh.write(bytes.fromhex("31c0c3"))
            lines = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                     {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "plugin_count_calls", "arguments": {
                         "path": blob, "arch": "x86_64", "loader": "raw", "base": 4096, "args": {"top": 1}}}},
                     {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "plugin_count_calls", "arguments": {
                         "path": blob, "args": "not an object"}}}]
            out = rdis("rdis.mcp_server", plugins=EXAMPLES, stdin="".join(json.dumps(m) + "\n" for m in lines))
        replies = {r["id"]: r for r in map(json.loads, out.stdout.splitlines())}
        tool = next(t for t in replies[1]["result"]["tools"] if t["name"] == "plugin_count_calls")
        self.assertIs(tool["annotations"]["readOnlyHint"], False)
        self.assertEqual(json.loads(replies[2]["result"]["content"][0]["text"])["functions"], 1)
        self.assertEqual(replies[3]["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
