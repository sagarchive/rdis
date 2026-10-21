"""Function ends: a call that never returns, a trap, and a declared function start all end a function.

The hand-encoded cases are independent of any compiler. Each failed before the fix (a missed `exit` made
the decoder run into the next function). The compiled case uses the symbol table of the unstripped build as the
oracle; tests/boundary_check.py measures the same property on real system binaries."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdis.analysis import Program
from rdis.arch import make
from rdis.loader import Image, Section, open_image

BASE = 0x1000


def rel(here, target):
    return ((target - (here + 5)) & 0xFFFFFFFF).to_bytes(4, "little")


def image(code, symbols=None, arch="x86_64"):
    blob = bytes(code)
    return Image("<boundary-fixture>", "raw", make(arch), BASE, BASE, [Section(".text", BASE, len(blob), 0, True)],
                 dict(symbols or {}), {}, lambda va, n: blob[va - BASE:va - BASE + n] if BASE <= va < BASE + len(blob) else b"",
                 lambda va: None)


def analyze(code, symbols=None, arch="x86_64"):
    return Program(image(code, symbols, arch)).analyze(objc=False, swift=False, prologues=False)


def edges(func):
    return {(b.addr, s) for b in func.blocks.values() for s in b.succs}


def padded(parts, size):
    out = bytearray()
    for at, blob in sorted(parts.items()):
        out += b"\xcc" * (at - BASE - len(out)) + blob
    return out.ljust(size, b"\xcc")


class StopsInX86(unittest.TestCase):
    def test_call_to_exit_ends_the_function_before_the_next_one(self):
        code = padded({0x1000: bytes.fromhex("85ff" "7401" "c3") + b"\xe8" + rel(0x1005, 0x1020),
                       0x100A: bytes.fromhex("55" "4889e5" "31c0" "5d" "c3"), 0x1020: b"\xc3"}, 0x30)
        p = analyze(code, {0x1000: "a", 0x1020: "exit"})
        a = p.functions[0x1000]
        self.assertEqual(a.end, 0x100A)
        self.assertNotIn(0x100A, a.blocks)
        self.assertEqual(a.stops, frozenset({0x1005}))

    def test_a_conditional_exit_keeps_the_code_after_the_branch_without_a_false_edge(self):
        code = padded({0x1000: bytes.fromhex("85ff" "7505") + b"\xe8" + rel(0x1004, 0x1020) + bytes.fromhex("b801000000" "c3"),
                       0x1020: b"\xc3"}, 0x30)
        p = analyze(code, {0x1000: "a", 0x1020: "exit"})
        a = p.functions[0x1000]
        self.assertEqual(sorted(a.blocks), [0x1000, 0x1004, 0x1009])
        self.assertEqual(edges(a), {(0x1000, 0x1009), (0x1000, 0x1004)})

    def test_ud2_ends_its_block_with_no_fall_through(self):
        p = analyze(padded({0x1000: bytes.fromhex("85ff" "7502" "0f0b" "b801000000" "c3")}, 0x20))
        a = p.functions[0x1000]
        self.assertEqual(edges(a), {(0x1000, 0x1006), (0x1000, 0x1004)})
        self.assertIn(0x1004, a.blocks)
        self.assertEqual(a.blocks[0x1004].succs, [])

    def test_a_function_that_only_ever_calls_exit_is_learned_as_non_returning(self):
        code = padded({0x1000: bytes.fromhex("85ff" "7401" "c3") + b"\xe8" + rel(0x1005, 0x1020),
                       0x100A: bytes.fromhex("55" "4889e5" "5d" "c3"),
                       0x1020: b"\xe8" + rel(0x1020, 0x1040), 0x1040: b"\xc3"}, 0x50)
        p = analyze(code, {0x1000: "f", 0x1040: "exit"})
        self.assertIn(0x1020, p.noreturn_addrs)
        self.assertEqual(p.functions[0x1000].end, 0x100A)

    def test_a_function_that_can_return_is_not_marked_non_returning(self):
        code = padded({0x1000: b"\xe8" + rel(0x1000, 0x1020) + b"\xc3", 0x1020: bytes.fromhex("85ff" "7401" "c3") + b"\xe8" + rel(0x1025, 0x1040),
                       0x1040: b"\xc3"}, 0x50)
        p = analyze(code, {0x1000: "f", 0x1040: "exit"})
        self.assertNotIn(0x1020, p.noreturn_addrs)

    def test_falling_into_a_declared_function_start_ends_the_function(self):
        p = analyze(padded({0x1000: b"\x90\x90\x90", 0x1003: b"\xc3"}, 0x10), {0x1000: "a", 0x1003: "b"})
        a = p.functions[0x1000]
        self.assertEqual((a.end, len(a.blocks), a.blocks[0x1000].succs), (0x1003, 1, []))

    def test_mapping_symbols_and_local_labels_are_not_function_starts(self):
        p = analyze(padded({0x1000: b"\x90\x90\x90\xc3"}, 0x10), {0x1000: "a", 0x1002: "$t", 0x1001: ".Lx"})
        self.assertEqual(p.functions[0x1000].end, 0x1004)


class StopsInArm64(unittest.TestCase):
    def test_brk_after_a_branch_has_no_fall_through(self):
        words = [0x34000040, 0xD4200020, 0xD65F03C0]        # cbz w0, +8 ; brk #1 ; ret
        code = b"".join(w.to_bytes(4, "little") for w in words)
        p = analyze(code, arch="arm64")
        a = p.functions[0x1000]
        self.assertEqual(a.blocks[0x1004].succs, [])
        self.assertEqual(edges(a), {(0x1000, 0x1008), (0x1000, 0x1004)})


try:
    import diff_corpus
except ImportError:
    diff_corpus = None

NORETURN_C = """#include <stdlib.h>
__attribute__((noinline)) int fa(int x){ if (x > 3) exit(2); return x + 1; }
__attribute__((noinline)) int fb(int y){ if (y < 0) abort(); return y * 3 + 7; }
__attribute__((noinline)) int fc(int z){ return z ^ 0x55; }
int main(int c, char **v){ return fa(c) + fb(c) + fc(c); }
"""


class CompiledOracle(unittest.TestCase):
    def test_no_function_runs_over_the_next_declared_start(self):
        import shutil, subprocess
        cc = shutil.which("cc")
        if not cc or not shutil.which("strip"):
            self.skipTest("needs a C compiler and strip")
        with tempfile.TemporaryDirectory() as d:
            src, full, stripped = (os.path.join(d, n) for n in ("t.c", "t", "t.stripped"))
            with open(src, "w") as fh:
                fh.write(NORETURN_C)
            flags = ["-O1", "-fno-inline", "-fno-stack-protector"] + ([] if sys.platform == "darwin" else ["-no-pie"])
            subprocess.run([cc, *flags, src, "-o", full], check=True, capture_output=True)
            subprocess.run(["cp", full, stripped], check=True)
            subprocess.run(["strip"] + ([] if sys.platform == "darwin" else ["--strip-all"]) + [stripped], check=True)
            truth = Program(open_image(full)).analyze()
            starts = sorted(a for a, n in truth.names.items() if a in truth.functions and (n or "").lstrip("_") in ("fa", "fb", "fc", "main"))
            self.assertEqual(len(starts), 4)
            for path in (full, stripped):
                with self.subTest(binary=os.path.basename(path)):
                    p = Program(open_image(path)).analyze()
                    for here, nxt in zip(starts, starts[1:]):
                        self.assertIn(here, p.functions, hex(here))
                        self.assertLessEqual(p.functions[here].end, nxt, f"{here:#x} runs past {nxt:#x}")


if __name__ == "__main__":
    unittest.main()
