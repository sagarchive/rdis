"""Go binaries: build info, gopclntab function recovery and its use in discovery.

Real Go programs are built into a temp dir and checked against `go tool nm` for the same binary.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import gobin
from rdis.loader import open_image
from rdis.mcp_server import _handle, _prog

DEP_MOD = "module example.com/dep\n\ngo 1.22\n"
DEP_GO = 'package dep\n\n//go:noinline\nfunc Greet(n string) string { return "hello " + n }\n'
HELLO_MOD = ("module example.com/hello\n\ngo 1.22\n\nrequire example.com/dep v0.0.0\n\n"
             "replace example.com/dep => ../dep\n")
HELLO_GO = '''package main

import (
	"fmt"
	"os"

	"example.com/dep"
)

type T struct{ n int }

//go:noinline
func (t *T) Add(x int) int { return t.n + x }

//go:noinline
func (t T) Val() int { return t.n }

//go:noinline
func Map[K comparable, V any](m map[K]V) int { return len(m) }

var banner = "static data string in a global var"
var long = "L0NG-" + "0123456789abcdefghijklmnopqrstuvwxyz-0123456789abcdefghijklmnopqrstuvwxyz-0123456789abcdefghijklmnopqrstuvwxyz-END"

//go:noinline
func greet(a, b string) string { return a + b }

func main() {
	t := &T{1}
	fmt.Println(dep.Greet("rdis"), t.Add(2), t.Val(), Map(map[string]int{"a": 1}), os.Args)
	fmt.Println("rdis-go-string-alpha", greet("second literal, with punctuation!", "ok"))
	fmt.Println("unicode: h\u00e9llo w\u00f6rld \u2713", banner, long, "https://api.example.com/v1/upload")
}
'''
SKIP_NAMES = {"runtime.text", "_go:buildid", "go:buildid", "runtime.etext"}


def nm_functions(path):
    """{address: [names]} of the text symbols `go tool nm` reports."""
    out = subprocess.run(["go", "tool", "nm", "-n", path], capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[1] in ("T", "t") and parts[2] not in SKIP_NAMES:
            table.setdefault(int(parts[0], 16), []).append(parts[2])
    return table


def recovered(path):
    table = {}
    for f in gobin.read_pclntab(path):
        table.setdefault(f["entry_addr"], []).append(f["name"])
    return table


def nm_spellings(name):
    """nm decorates assembly symbols: an .abi0 suffix and, on macOS, one extra leading underscore."""
    base = name[:-5] if name.endswith(".abi0") else name
    return {name, base, base[1:]}


@unittest.skipUnless(shutil.which("go"), "needs the go toolchain")
class GoBinaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rdis-go-")
        os.makedirs(os.path.join(cls.tmp, "bin"))
        env = dict(os.environ, GOCACHE=os.path.join(cls.tmp, "cache"), GOPATH=os.path.join(cls.tmp, "path"),
                   GOTOOLCHAIN="local", GOFLAGS="-mod=mod", GOPROXY="off")
        for sub, files in (("dep", {"go.mod": DEP_MOD, "dep.go": DEP_GO}),
                           ("hello", {"go.mod": HELLO_MOD, "main.go": HELLO_GO})):
            os.makedirs(os.path.join(cls.tmp, sub))
            for name, text in files.items():
                with open(os.path.join(cls.tmp, sub, name), "w") as fh:
                    fh.write(text)
        src = os.path.join(cls.tmp, "hello")

        def build(out, goarch=None, *flags):
            e = dict(env, **({"GOARCH": goarch} if goarch else {}))
            dest = os.path.join(cls.tmp, "bin", out)
            r = subprocess.run(["go", "build", *flags, "-o", dest, "."], cwd=src, env=e, capture_output=True, text=True)
            return dest if r.returncode == 0 else None

        cls.native_arch = subprocess.run(["go", "env", "GOARCH"], capture_output=True, text=True, env=env).stdout.strip()
        cls.other_arch = "amd64" if cls.native_arch == "arm64" else "arm64"
        cls.go_version = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, env=env).stdout.strip()
        cls.normal = build("hello")
        cls.stripped = build("hello_stripped", None, "-ldflags=-s -w")
        cls.other = build("hello_other", cls.other_arch)
        if not cls.normal or not cls.stripped:
            raise unittest.SkipTest("go build failed in this environment")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_build_info_version_module_and_replaced_dependency(self):
        bi = gobin.read_build_info(self.normal)
        self.assertEqual(bi["go_version"], self.go_version)
        self.assertEqual(bi["path"], "example.com/hello")
        self.assertEqual(bi["main_module"]["path"], "example.com/hello")
        dep = next(d for d in bi["deps"] if d["path"] == "example.com/dep")
        self.assertEqual(dep["version"], "v0.0.0")
        self.assertEqual(dep["replace"]["path"], "../dep")

    def test_build_info_survives_stripping(self):
        bi = gobin.read_build_info(self.stripped)
        self.assertEqual((bi["go_version"], bi["path"]), (self.go_version, "example.com/hello"))

    def _assert_matches_nm(self, path, reference):
        truth, got = nm_functions(reference), recovered(path)
        self.assertGreater(len(truth), 1000)
        self.assertEqual([a for a in truth if a not in got], [], "functions nm knows that gopclntab missed")
        for addr, names in truth.items():
            allowed = set().union(*(nm_spellings(n) for n in names))
            self.assertTrue(set(got[addr]) <= allowed, f"{hex(addr)} nm={names} gopclntab={got[addr]}")
        self.assertLessEqual(len(set(got) - set(truth)), 2, "only the build-id stub may be extra")

    def test_functions_match_go_tool_nm(self):
        self._assert_matches_nm(self.normal, self.normal)

    def test_stripped_build_recovers_the_same_functions(self):
        self._assert_matches_nm(self.stripped, self.normal)

    def test_other_architecture_matches_go_tool_nm(self):
        if not self.other:
            self.skipTest("cross build not available")
        self._assert_matches_nm(self.other, self.other)

    def test_methods_and_generics_and_packages(self):
        names = {n for ns in recovered(self.normal).values() for n in ns}
        self.assertIn("main.main", names)
        self.assertIn("main.(*T).Add", names)
        self.assertIn("main.T.Val", names)
        self.assertTrue(any(n.startswith("main.Map[") for n in names), "generic instantiation")
        pkgs = {p["package"]: p["function_count"] for p in gobin.packages(gobin.read_pclntab(self.normal))}
        for want in ("main", "runtime", "fmt", "example.com/dep"):
            self.assertIn(want, pkgs)
        self.assertGreater(pkgs["runtime"], 500)

    def test_discovery_uses_the_function_table_on_a_stripped_build(self):
        p = _prog(self.stripped)
        table = gobin.function_table(p.image)
        self.assertGreater(len(table), 1000)
        self.assertEqual(set(table) - set(p.functions), set(), "every Go function is discovered")
        self.assertLessEqual(len(set(p.functions) - set(table)), 2)
        self.assertEqual(p.names[next(a for a, n in table.items() if n == "main.main")], "main.main")

    def test_stripped_main_main_is_listed_and_decompiles(self):
        res = _handle({"method": "tools/call", "params": {"name": "list_functions",
                                                        "arguments": {"path": self.stripped, "limit": 5000}}})
        funcs = json.loads(res["content"][0]["text"])["functions"]
        main = next(f for f in funcs if f["name"].lstrip("_") == "main.main")
        res = _handle({"method": "tools/call", "params": {"name": "decompile",
                                                        "arguments": {"path": self.stripped, "func": main["addr"]}}})
        self.assertFalse(res.get("isError"))
        self.assertIn("main_main", json.loads(res["content"][0]["text"])["c"])

    def test_go_info_tool(self):
        res = _handle({"method": "tools/call", "params": {"name": "go_info", "arguments": {"path": self.stripped, "limit": 5}}})
        self.assertFalse(res.get("isError"))
        info = json.loads(res["content"][0]["text"])
        self.assertEqual(info["go_version"], self.go_version)
        self.assertEqual(info["main_module"]["path"], "example.com/hello")
        self.assertIn("example.com/dep", info["dependencies"])
        self.assertGreater(info["function_count"], 1000)
        self.assertEqual(len(info["functions"]), 5)
        tool = next(t for t in _handle({"method": "tools/list"})["tools"] if t["name"] == "go_info")
        self.assertTrue(tool["annotations"]["readOnlyHint"])

    def test_cli_summary_and_json(self):
        run = lambda *a: subprocess.run([sys.executable, "-m", "rdis", self.stripped, *a], cwd=ROOT, capture_output=True, text=True)
        text = run("--go")
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn(f"Go version: {self.go_version}", text.stdout)
        self.assertIn("example.com/dep v0.0.0", text.stdout)
        self.assertNotIn("{'package'", text.stdout)
        doc = json.loads(run("--go", "--json").stdout)
        self.assertEqual(doc["main_module"], "example.com/hello")
        self.assertGreater(doc["function_count"], 1000)

    def test_triage_reports_go_details(self):
        from rdis.triage import triage
        go = next(r for r in triage(self.stripped)["runtimes"] if r["runtime"] == "Go")
        self.assertEqual(go["go_version"], self.go_version)
        self.assertEqual(go["main_module"], "example.com/hello")
        self.assertIn("example.com/dep", go["dependencies"])

    PLANTED = ["rdis-go-string-alpha", "second literal, with punctuation!", "unicode: h\u00e9llo w\u00f6rld \u2713",
               "static data string in a global var", "https://api.example.com/v1/upload",
               "L0NG-0123456789abcdefghijklmnopqrstuvwxyz-0123456789abcdefghijklmnopqrstuvwxyz-0123456789abcdefghijklmnopqrstuvwxyz-END"]

    def _assert_strings_split(self, path):
        strings = _prog(path).strings()
        values = set(strings.values())
        self.assertEqual([s for s in self.PLANTED if s not in values], [], "planted Go strings recovered one by one")
        self.assertLess(max(map(len, values)), 2000, "no concatenated blob is left in the output")
        for s in self.PLANTED:
            addr = next(a for a, v in strings.items() if v == s)
            self.assertEqual(_prog(path).image.read(addr, len(s.encode())), s.encode(), "address points at the string")

    def test_go_strings_are_split_on_a_stripped_build(self):
        self._assert_strings_split(self.stripped)

    def test_go_strings_are_split_on_the_other_architecture(self):
        if not self.other:
            self.skipTest("cross build not available")
        self._assert_strings_split(self.other)

    def test_strings_tool_and_cli_show_the_split_strings(self):
        res = _handle({"method": "tools/call", "params": {"name": "strings", "arguments": {"path": self.stripped, "limit": 20000}}})
        texts = {s["text"] for s in json.loads(res["content"][0]["text"])["strings"]}
        self.assertIn("rdis-go-string-alpha", texts)
        out = subprocess.run([sys.executable, "-m", "rdis", self.stripped, "--strings", "--json"], cwd=ROOT,
                             capture_output=True, text=True)
        self.assertIn("rdis-go-string-alpha", json.loads(out.stdout).values())

    def test_go_strings_name_the_function_that_loads_them(self):
        from rdis.stringrefs import string_refs
        for path in [self.stripped] + ([self.other] if self.other else []):
            p = _prog(path)
            strings, refs = p.strings(), string_refs(_prog(path))
            for text in self.PLANTED:
                addr = next(a for a, v in strings.items() if v == text)
                self.assertIn("main.main", {r["name"] for r in refs.get(addr, ())}, f"{text[:24]} in {os.path.basename(path)}")

    def test_corrupt_function_table_yields_nothing_and_does_not_raise(self):
        bad = os.path.join(self.tmp, "bin", "corrupt")
        shutil.copy(self.normal, bad)
        section = next(s for s in open_image(bad).sections if (s.name or "").lower() in ("__gopclntab", ".gopclntab"))
        with open(bad, "r+b") as fh:
            fh.seek(section.offset)
            fh.write(b"\x00\x00\x00\x00")
        self.assertEqual(gobin.read_pclntab(bad), [])
        self.assertEqual(gobin.function_table(open_image(bad)), {})


class NotGo(unittest.TestCase):
    def test_a_non_go_binary_returns_empty_results(self):
        self.assertIsNone(gobin.read_build_info("/bin/ls"))
        self.assertEqual(gobin.read_pclntab("/bin/ls"), [])
        self.assertEqual(gobin.function_table(open_image("/bin/ls")), {})
        self.assertEqual(gobin.packages([]), [])


if __name__ == "__main__":
    unittest.main()
