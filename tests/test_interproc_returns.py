"""Tests for interprocedural return-type inference over the call graph.

Compiles C source with ``cc`` into a temp dir (skipped if no cc) and decompiles
through ``rdis.mcp_server._handle`` tool ``decompile``, verifying that a
function's return type can be inferred from the return type of a callee that
lives in the same binary.

Rule: a call (tail or non-tail) to an in-binary function g propagates g's
inferred return type to the caller f exactly like the existing libc-table case:
the call must be the last write to the return register before the ret (a later
write to rax/x0/xmm0/v0 invalidates it).
"""
import unittest
import tempfile
import subprocess
import os
import sys
import json
import re
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rdis.mcp_server import _handle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _cc_available():
    """True when the system C compiler is on PATH."""
    return shutil.which("cc") is not None


def _compile(c_src, arch="arm64"):
    """Compile *c_src* with cc to a temp binary; return (tmpdir, bin_path)."""
    tmp = tempfile.mkdtemp()
    c_file = os.path.join(tmp, "test.c")
    bin_file = os.path.join(tmp, "test")
    with open(c_file, "w") as f:
        f.write(c_src)
    subprocess.run(
        ["cc", "-O2", "-fno-vectorize", "-fno-slp-vectorize", "-arch", arch,
         c_file, "-o", bin_file],
        check=True, capture_output=True,
    )
    return tmp, bin_file


def _decompile(path, func_name, arch="arm64"):
    """Decompile *func_name* from *path* via the MCP _handle interface."""
    resp = _handle({
        "method": "tools/call",
        "params": {
            "name": "decompile",
            "arguments": {"path": path, "func": func_name, "arch": arch},
        },
    })
    if resp.get("isError"):
        return ""
    text = resp["content"][0]["text"]
    return json.loads(text).get("c", "")


def _return_type(code, func_name):
    """Extract the return type from the function-signature line in *code*.

    Looks for the line ``<type> _func_name(...) {`` and returns ``<type>``.
    Returns ``None`` if the function signature cannot be found.
    """
    for line in code.split("\n"):
        # Match a definition line: <type> _?func_name(args) {
        if re.search(r'(?<!\w)_?' + re.escape(func_name) + r'\s*\([^)]*\)\s*\{', line):
            m = re.match(r'\s*([\w\s\*]+?)\s+(_?)' + re.escape(func_name) + r'\s*\(', line)
            if m:
                return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@unittest.skipUnless(_cc_available(), "cc not available")
class TestInterprocReturns(unittest.TestCase):
    """Each test compiles C, decompiles via _handle, checks return types."""

    def setUp(self):
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _dec(self, c_src, func_name):
        """Compile and decompile *func_name*; return the C text."""
        tmp, bin_path = _compile(c_src)
        self._dirs.append(tmp)
        return _decompile(bin_path, func_name)

    # -- Case 1 -------------------------------------------------------------
    def test_helper_wrapper(self):
        """int helper(int x){return x*3+1;} int wrapper(int x){return helper(x);}
        -> wrapper returns non-void (inferred from helper's return type)."""
        c_src = """
__attribute__((noinline)) static int helper(int x) { return x * 3 + 1; }
int wrapper(int x) { return helper(x); }
int main(void) { return 0; }
"""
        c = self._dec(c_src, "wrapper")
        rt = _return_type(c, "wrapper")
        self.assertIsNotNone(rt, f"Could not find 'wrapper' signature:\n{c}")
        self.assertNotEqual(rt, "void", f"wrapper should be non-void:\n{c}")

    # -- Case 2 -------------------------------------------------------------
    def test_call_chain(self):
        """Chain a->b->c where c returns a value and a, b only return the
        callee result -> all three are non-void."""
        c_src = """
__attribute__((noinline)) static int c_func(int x) { return x + 42; }
__attribute__((noinline)) int b_func(int x) { return c_func(x); }
__attribute__((noinline)) int a_func(int x) { return b_func(x); }
int main(void) { return 0; }
"""
        for name in ("a_func", "b_func", "c_func"):
            c = self._dec(c_src, name)
            rt = _return_type(c, name)
            self.assertIsNotNone(rt, f"Could not find '{name}' signature:\n{c}")
            self.assertNotEqual(rt, "void", f"{name} should be non-void:\n{c}")

    # -- Case 3 -------------------------------------------------------------
    def test_mutual_recursion(self):
        """Mutual recursion p<->q with base cases: both are non-void."""
        c_src = """
__attribute__((noinline)) int q(int n);
__attribute__((noinline)) int p(int n);
__attribute__((noinline)) int p(int n) { return n ? q(n - 1) : 0; }
__attribute__((noinline)) int q(int n) { return n ? p(n - 1) : 1; }
int main(void) { return 0; }
"""
        for name in ("p", "q"):
            c = self._dec(c_src, name)
            rt = _return_type(c, name)
            self.assertIsNotNone(rt, f"Could not find '{name}' signature:\n{c}")
            self.assertNotEqual(rt, "void", f"{name} should be non-void:\n{c}")

    # -- Case 4 -------------------------------------------------------------
    def test_void_caller_stays_void(self):
        """void v(int x){ volatile int s; s=x; } void u(int x){ v(x); }
        -> u stays void (in-binary void callee does not propagate)."""
        c_src = """
__attribute__((noinline)) static void v(int x) { volatile int s; s = x; }
__attribute__((noinline)) void u(int x) { v(x); }
int main(void) { return 0; }
"""
        c = self._dec(c_src, "u")
        rt = _return_type(c, "u")
        self.assertIsNotNone(rt, f"Could not find 'u' signature:\n{c}")
        self.assertEqual(rt, "void", f"u should be void:\n{c}")

    # -- Case 5 -------------------------------------------------------------
    def test_own_return_value_not_overridden(self):
        """int keep(int x){ helper(x); return 0; } keeps its own value return,
        not helper's type (helper is called but its result is not returned)."""
        c_src = """
__attribute__((noinline)) static int helper(int x) { return x * 3 + 1; }
__attribute__((noinline)) int keep(int x) { helper(x); return 0; }
int main(void) { return 0; }
"""
        c = self._dec(c_src, "keep")
        rt = _return_type(c, "keep")
        self.assertIsNotNone(rt, f"Could not find 'keep' signature:\n{c}")
        self.assertNotEqual(rt, "void", f"keep should be non-void (return 0):\n{c}")

    # -- Case 6 -------------------------------------------------------------
    def test_void_helper_caller_stays_void(self):
        """A function calling an in-binary void helper and returning nothing
        stays void."""
        c_src = """
__attribute__((noinline)) static void vhelp(int x) { (void)x; }
__attribute__((noinline)) void caller(int x) { vhelp(x); }
int main(void) { return 0; }
"""
        c = self._dec(c_src, "caller")
        rt = _return_type(c, "caller")
        self.assertIsNotNone(rt, f"Could not find 'caller' signature:\n{c}")
        self.assertEqual(rt, "void", f"caller should be void:\n{c}")


if __name__ == "__main__":
    unittest.main()