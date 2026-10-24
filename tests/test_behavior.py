"""Capability summary: planted capabilities are found with their evidence, clean programs report nothing."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import behavior
from rdis.mcp_server import _handle, _prog

BAD_C = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ptrace.h>
__attribute__((noinline)) void escalate(void) {
    system("osascript -e 'do shell script \"id\" with administrator privileges'");
}
__attribute__((noinline)) void phone_home(const char *host) {
    struct addrinfo *res = 0;
    if (getaddrinfo(host, "80", 0, &res) == 0) {
        int s = socket(res->ai_family, SOCK_STREAM, 0);
        connect(s, res->ai_addr, res->ai_addrlen);
        const char *req = "POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=x\r\n\r\n";
        send(s, req, strlen(req), 0);
    }
}
__attribute__((noinline)) void hide(void) { ptrace(31, 0, 0, 0); }
int main(int argc, char **argv) { if (argc > 3) { escalate(); phone_home(argv[1]); hide(); } return 0; }
'''
CLEAN_C = '#include <stdio.h>\nint main(void){ puts("hello"); return 0; }\n'


def ids(doc):
    return {b["id"] for b in doc["behaviors"]}


def tool(path):
    res = _handle({"method": "tools/call", "params": {"name": "behavior", "arguments": {"path": path}}})
    assert not res.get("isError"), res
    return json.loads(res["content"][0]["text"])


@unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
class CPrograms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rdis-behavior-")
        for name, text in (("bad", BAD_C), ("clean", CLEAN_C)):
            src = os.path.join(cls.tmp, name + ".c")
            with open(src, "w") as fh:
                fh.write(text)
            subprocess.run(["cc", "-O1", "-o", os.path.join(cls.tmp, name), src], check=True, capture_output=True)
        cls.bad, cls.clean = os.path.join(cls.tmp, "bad"), os.path.join(cls.tmp, "clean")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_planted_capabilities_are_found(self):
        found = ids(tool(self.bad))
        self.assertTrue({"admin-rights", "spawn-process", "network-sockets", "upload", "anti-debug", "scripting"} <= found, found)

    def test_a_program_that_only_prints_reports_nothing(self):
        self.assertEqual(tool(self.clean)["behaviors"], [])

    def test_each_behavior_links_to_the_functions_that_use_the_evidence(self):
        doc = tool(self.bad)
        by_id = {b["id"]: b for b in doc["behaviors"]}
        spawn = [e for e in by_id["spawn-process"]["evidence"] if e["kind"] == "import"]
        self.assertTrue(any(e["value"] == "system" and any(f.lstrip("_") == "escalate" for f in e["functions"]) for e in spawn), spawn)
        admin = [e for e in by_id["admin-rights"]["evidence"] if e["kind"] == "string"]
        self.assertTrue(any("administrator privileges" in e["value"] and any(f.lstrip("_") == "escalate" for f in e["functions"])
                            for e in admin), admin)
        sock = [e for e in by_id["network-sockets"]["evidence"] if e["kind"] == "import"]
        self.assertTrue(any(any(f.lstrip("_") == "phone_home" for f in e["functions"]) for e in sock), sock)
        for b in doc["behaviors"]:
            self.assertIn(b["confidence"], ("medium", "high"))
            self.assertTrue(b["evidence"])
            for e in b["evidence"]:
                self.assertTrue(e["address"] is None or e["address"].startswith("0x"))

    def test_cli_text_and_json_agree_with_the_tool(self):
        out = subprocess.run([sys.executable, "-m", "rdis", self.bad, "--behavior"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("requests administrator rights", out.stdout)
        self.assertIn("<- ", out.stdout)
        doc = json.loads(subprocess.run([sys.executable, "-m", "rdis", self.bad, "--behavior", "--json"], cwd=ROOT,
                                        capture_output=True, text=True).stdout)
        self.assertEqual(ids(doc), ids(tool(self.bad)))

    def test_the_tool_is_read_only(self):
        spec = next(t for t in _handle({"method": "tools/list"})["tools"] if t["name"] == "behavior")
        self.assertTrue(spec["annotations"]["readOnlyHint"])


GO_ACTIVE = '''package main

import (
	"net/http"
	"os"
	"os/exec"
)

//go:noinline
func run() error { return exec.Command("/bin/echo", os.Args[0]).Run() }

//go:noinline
func fetch() { http.Get("https://updates.vendor.net/check") }

func main() { run(); fetch() }
'''
GO_QUIET = 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("quiet") }\n'


@unittest.skipUnless(shutil.which("go"), "needs the go toolchain")
class GoPrograms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rdis-behavior-go-")
        env = dict(os.environ, GOCACHE=os.path.join(cls.tmp, "cache"), GOPATH=os.path.join(cls.tmp, "path"),
                   GOTOOLCHAIN="local", GOFLAGS="-mod=mod", GOPROXY="off")
        cls.paths = {}
        for name, source in (("active", GO_ACTIVE), ("quiet", GO_QUIET)):
            d = os.path.join(cls.tmp, name)
            os.makedirs(d)
            with open(os.path.join(d, "go.mod"), "w") as fh:
                fh.write(f"module example.com/{name}\n\ngo 1.22\n")
            with open(os.path.join(d, "main.go"), "w") as fh:
                fh.write(source)
            out = os.path.join(cls.tmp, name + "_bin")
            r = subprocess.run(["go", "build", "-ldflags=-s -w", "-o", out, "."], cwd=d, env=env, capture_output=True)
            if r.returncode:
                raise unittest.SkipTest("go build failed here")
            cls.paths[name] = out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_stripped_go_binary_shows_process_and_http_use(self):
        doc = tool(self.paths["active"])
        self.assertTrue({"spawn-process", "http-client"} <= ids(doc), ids(doc))
        spawn = next(b for b in doc["behaviors"] if b["id"] == "spawn-process")
        self.assertTrue(any(e["kind"] == "function" and e["value"].lstrip("_").startswith("os/exec.") for e in spawn["evidence"]))
        self.assertEqual(doc["modules"], ["example.com/active"])

    def test_a_quiet_go_program_reports_nothing_despite_libc_imports(self):
        self.assertEqual(tool(self.paths["quiet"])["behaviors"], [])


class ModuleRules(unittest.TestCase):
    """Go dependency lists name what a binary embeds (the WireGuard, gVisor, zeroconf case)."""

    def run_with(self, deps):
        info = {"path": "example.com/app", "deps": [{"path": d, "version": "v1.0.0"} for d in deps]}
        prog = mock.Mock()
        prog.image.imports, prog.image.path = {}, "x"
        prog.xrefs, prog.functions, prog.names = {}, {}, {}
        prog.strings.return_value = {}
        prog._go_functions.return_value = {1: "main.main"}
        with mock.patch("rdis.gobin.read_build_info", return_value=info):
            return behavior.analyze(prog)

    def test_known_modules_become_capabilities(self):
        doc = self.run_with(["golang.zx2c4.com/wireguard", "gvisor.dev/gvisor", "github.com/grandcat/zeroconf", "github.com/mattn/go-sqlite3"])
        self.assertEqual(ids(doc), {"vpn-tunnel", "userspace-network", "service-discovery", "database"})
        vpn = next(b for b in doc["behaviors"] if b["id"] == "vpn-tunnel")
        self.assertEqual(vpn["evidence"][0]["value"], "golang.zx2c4.com/wireguard@v1.0.0")
        self.assertEqual(vpn["confidence"], "high")

    def test_unrelated_modules_add_nothing(self):
        self.assertEqual(self.run_with(["github.com/spf13/cobra", "golang.org/x/text"])["behaviors"], [])


if __name__ == "__main__":
    unittest.main()
