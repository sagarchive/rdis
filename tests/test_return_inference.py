"""Tests for return-type inference in the lifter.

Covers the case where a function calls a known libc function (e.g. strlen)
and returns its result directly -- the decompiler must not print void.
Also covers the case where a genuinely void function calls printf and
ignores the result -- it must stay void.
"""
import unittest
import tempfile
import subprocess
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler


def compile_and_decompile(c_src, arch="arm64", opt="-O2"):
    """Compile C source, decompile, return the C text."""
    with tempfile.TemporaryDirectory() as tmp:
        c_file = os.path.join(tmp, "test.c")
        bin_file = os.path.join(tmp, "test")
        with open(c_file, "w") as f:
            f.write(c_src)
        # Compile C to binary
        subprocess.run(["clang", opt, "-fno-vectorize", "-fno-slp-vectorize", "-arch", arch, c_file, "-o", bin_file],
                       check=True, capture_output=True)
        # Decompile
        prog = Program(open_image(bin_file, arch)).analyze()
        # Find the function (first non-main function)
        for addr, func in prog.functions.items():
            shown = prog.display(addr)
            if shown not in ("main", "_main"):
                return Decompiler(prog, func).c()
    return ""


class TestReturnInference(unittest.TestCase):
    def test_strlen_call_returns_value(self):
        """A function that calls strlen and returns its result must not be void."""
        c_src = """
#include <string.h>
int strlen_ret(const char *s) {
    return strlen(s);
}
int main(void) { return 0; }
"""
        c = compile_and_decompile(c_src, arch="arm64", opt="-O2")
        # Should return int64_t/uint64_t, not void
        self.assertIn("int64_t", c)
        self.assertNotIn("void dec_", c)
        self.assertIn("return", c)

    def test_printf_caller_ignores_result_stays_void(self):
        """A void function that calls printf and ignores the result must stay void."""
        c_src = """
#include <stdio.h>
void prints_hello(void) {
    printf("hello\\n");
}
int main(void) { return 0; }
"""
        c = compile_and_decompile(c_src, arch="arm64", opt="-O2")
        # Should be void since printf's return value is ignored
        # Note: compiler may optimize printf("hello\\n") to puts("hello")
        self.assertIn("void _prints_hello", c)
        self.assertIn("return;", c)
        # Should not return a value
        self.assertNotIn("return ", c.replace("return;", ""))  # no "return <expr>"

    def test_unknown_import_call_stays_void(self):
        """A function that calls an unknown external function and returns its result must stay void."""
        c_src = """
// unknown_external is not a known libc function
extern int completely_unknown_func_12345(const char *);
int unknown_ret(const char *s) {
    return completely_unknown_func_12345(s);
}
int main(void) { return 0; }
"""
        # Use -undefined dynamic_lookup to allow undefined symbols on macOS
        with tempfile.TemporaryDirectory() as tmp:
            c_file = os.path.join(tmp, "test.c")
            bin_file = os.path.join(tmp, "test")
            with open(c_file, "w") as f:
                f.write(c_src)
            # Compile C to binary with undefined dynamic lookup
            subprocess.run(["clang", "-O2", "-fno-vectorize", "-fno-slp-vectorize", "-arch", "arm64",
                            "-undefined", "dynamic_lookup", c_file, "-o", bin_file],
                           check=True, capture_output=True)
            # Decompile
            prog = Program(open_image(bin_file, "arm64")).analyze()
            for addr, func in prog.functions.items():
                shown = prog.display(addr)
                if shown not in ("main", "_main"):
                    c = Decompiler(prog, func).c()
                    break
        # Should be void since we don't know the return type of the unknown import
        # The decompiler should not infer a return type for unknown imports
        self.assertIn("void", c)  # function return type is void
        self.assertIn("return;", c)
        # Should not return a value
        self.assertNotIn("return ", c.replace("return;", ""))

    # D3 tests: compiled C tests covering real-world scenarios
    def test_strlen_return_nonvoid(self):
        """int f(const char*s){return strlen(s);} returns non-void."""
        c_src = """
#include <string.h>
int strlen_wrapper(const char *s) {
    return strlen(s);
}
int main(void) { return 0; }
"""
        c = compile_and_decompile(c_src, arch="arm64", opt="-O2")
        # Should return int64_t (size_t), not void
        self.assertIn("int64_t", c)
        self.assertNotIn("void ", c.split("{")[0])  # return type not void

    def test_strerror_result_not_returned_stays_void(self):
        """void g(int n){ char*e=strerror(n); fputs(e,stderr); } stays void."""
        c_src = """
#include <string.h>
#include <stdio.h>
void strerror_logger(int n) {
    char *e = strerror(n);
    fputs(e, stderr);
}
int main(void) { return 0; }
"""
        c = compile_and_decompile(c_src, arch="arm64", opt="-O2")
        # Should be void since strerror's result is not returned
        self.assertIn("void ", c.split("{")[0])  # return type is void
        self.assertIn("return;", c)

    def test_strerror_then_return_zero_keeps_int64(self):
        """int h(int n){ char*e=strerror(n); log(e); return 0; } keeps int64_t (not char *)."""
        c_src = """
#include <string.h>
#include <stdio.h>
// log is an unknown function that takes a string
extern void log(const char *);
int strerror_then_zero(int n) {
    char *e = strerror(n);
    log(e);
    return 0;
}
int main(void) { return 0; }
"""
        # Use -undefined dynamic_lookup to allow undefined symbols on macOS
        with tempfile.TemporaryDirectory() as tmp:
            c_file = os.path.join(tmp, "test.c")
            bin_file = os.path.join(tmp, "test")
            with open(c_file, "w") as f:
                f.write(c_src)
            subprocess.run(["clang", "-O2", "-fno-vectorize", "-fno-slp-vectorize", "-arch", "arm64",
                            "-undefined", "dynamic_lookup", c_file, "-o", bin_file],
                           check=True, capture_output=True)
            prog = Program(open_image(bin_file, "arm64")).analyze()
            for addr, func in prog.functions.items():
                shown = prog.display(addr)
                if shown not in ("main", "_main"):
                    c = Decompiler(prog, func).c()
                    break
        # Should return int64_t (the explicit return 0), not char* from strerror
        self.assertIn("int64_t", c.split("{")[0])  # return type is int64_t
        self.assertIn("return 0", c)

    def test_usleep_result_ignored_stays_void(self):
        """void k(int n){ usleep(n*3+1); } stays void."""
        c_src = """
#include <unistd.h>
void usleep_wrapper(int n) {
    usleep(n * 3 + 1);
}
int main(void) { return 0; }
"""
        c = compile_and_decompile(c_src, arch="arm64", opt="-O2")
        # Should be void since usleep's result is ignored
        self.assertIn("void ", c.split("{")[0])  # return type is void
        self.assertIn("return;", c)


if __name__ == "__main__":
    unittest.main()