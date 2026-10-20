"""The P-code emulator against native execution: compile C, run the binary on this machine, run the same
machine code through rdis.emulate, and require every result to agree. The native CPU is the oracle."""
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import maturity_cases as M
from rdis.analysis import Program
from rdis.emulate import EmulationError, emulate
from rdis.loader import open_image

try:
    import pypcode
except ImportError:
    pypcode = None

ARRAYS = {"S": [1, 3, 5, 7, 9, 11, 13], "M": [1, 2, 3, 4, 5, 6], "L": [5, -2, 9, -7, 3],
          "V": [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5,
                0, 2, 8, 8, 4, 1, 9, 7],
          "W": [2, 7, 1, 8, 2, 8, 1, 8, 2, 8, 4, 5, 9, 0, 4, 5, 2, 3, 5, 3, 6, 0, 2, 8, 7, 4, 7, 1, 3, 5, 2, 6,
                6, 2, 4, 9, 7, 7, 5, 7],
          "T": list(b"the quick brown fox jumps over the lazy dog, then the dog sleeps".ljust(64, b"\0"))}
WIDE = {"L"}
BYTES = {"T"}
TIERS = {"opt": (M.OPT_SRC, M.OPT_SUPPORT, M.OPT_CASES),
         "simd": (M.SIMD_SRC, M.SIMD_SUPPORT, [c for c in M.SIMD_CASES if c[0] in ("vsum", "vdot", "vmax", "vcount")])}
BASE_ADDR = 0x40000000
HOST = "arm64" if platform.machine() in ("arm64", "aarch64") else "x86_64"


def _buffer(name):
    if name in BYTES:
        return bytes(ARRAYS[name])
    fmt = "<q" if name in WIDE else "<i"
    return b"".join(struct.pack(fmt, v) for v in ARRAYS[name])


def _cases(tier):
    return [(fn, rtype, args) for fn, rtype, argsets in TIERS[tier][2] for args in argsets]


def _harness(tier):
    src, support, _ = TIERS[tier]
    lines = [src, "#include <stdio.h>", support, "int main(void) {"]
    for fn, rtype, args in _cases(tier):
        cast = "(unsigned)" if rtype == "unsigned" else ""
        lines.append(f'    printf("%lld\\n", (long long){cast}{fn}({", ".join(args)}));')
    lines.append("    return 0;\n}")
    return "\n".join(lines)


def _compiler(arch):
    if platform.system() == "Darwin":
        return ["clang", "-arch", arch]
    return [shutil.which("cc") or "cc"] if arch == platform.machine().replace("aarch64", "arm64") else None


def _runner(arch):
    if platform.system() == "Darwin" and arch == "x86_64" and platform.machine() == "arm64":
        ok = subprocess.run(["arch", "-x86_64", "/usr/bin/true"], capture_output=True).returncode == 0
        return ["arch", "-x86_64"] if ok else None
    return []


def _arg_value(token, buffers, allocate):
    if token in ARRAYS:
        return allocate(_buffer(token))
    if token.startswith('"'):
        return allocate(token.strip('"').encode() + b"\0")
    if len(token) == 3 and token[0] == token[2] == "'":
        return ord(token[1])
    return int(token, 0)


def _decode(value, rtype):
    bits = 64 if rtype == "long" else 32
    value &= (1 << bits) - 1
    if rtype == "unsigned":
        return value
    return value - (1 << bits) if value >> (bits - 1) else value


@unittest.skipIf(pypcode is None, "pypcode is not installed")
class NativeOracleTests(unittest.TestCase):
    def check(self, arch, opt, tier="opt", vectorize=False):
        cc, run = _compiler(arch), _runner(arch)
        if not cc or run is None or not shutil.which(cc[0]):
            self.skipTest(f"cannot build and run {arch} here")
        with tempfile.TemporaryDirectory() as d:
            src, binary = os.path.join(d, "t.c"), os.path.join(d, "t")
            with open(src, "w") as fh:
                fh.write(_harness(tier))
            novec = [] if vectorize else ["-fno-vectorize", "-fno-slp-vectorize"]
            built = subprocess.run([*cc, opt, *novec, "-w", src, "-o", binary], capture_output=True, text=True)
            if built.returncode:
                self.skipTest(f"cannot compile: {built.stderr[:200]}")
            native = subprocess.run([*run, binary], capture_output=True, text=True, timeout=30).stdout.split()
            prog = Program(open_image(binary, arch=arch)).analyze(objc=False, swift=False)
            cases = _cases(tier)
            self.assertEqual(len(native), len(cases))
            agree = unsupported = 0
            reasons = set()
            mismatches = []
            for (fn, rtype, args), expected in zip(cases, native):
                entry = next((prog.resolve(n) for n in ("_" + fn, fn) if _resolves(prog, n)), None)
                self.assertIsNotNone(entry, fn)
                memory, cursor = [], [BASE_ADDR]

                def allocate(data):
                    addr = cursor[0]
                    memory.append((addr, data))
                    cursor[0] += (len(data) + 0xFFF) & ~0xFFF
                    return addr

                try:
                    got = emulate(prog, entry, [_arg_value(t, ARRAYS, allocate) for t in args], memory).value
                except EmulationError as e:
                    unsupported += 1
                    reasons.add(str(e).split(" at ")[0][:60])
                    continue
                if _decode(got, rtype) == int(expected):
                    agree += 1
                else:
                    mismatches.append((fn, args, int(expected), _decode(got, rtype)))
            metric = {"arch": arch, "opt": opt, "tier": tier, "cases": len(cases), "agree": agree,
                      "unsupported": unsupported, "reasons": sorted(reasons), "mismatches": len(mismatches)}
            print("EMULATOR_METRIC " + json.dumps(metric, sort_keys=True))
            self.assertEqual(mismatches, [], "a wrong answer is never acceptable; an explicit error is")
            self.assertGreaterEqual(agree, len(cases) * 0.6, metric)

    def test_host_architecture_o2(self):
        self.check(HOST, "-O2")

    def test_host_architecture_o3(self):
        self.check(HOST, "-O3")

    def test_vectorized_code_agrees_or_fails_explicitly(self):
        self.check(HOST, "-O3", tier="simd", vectorize=True)

    def test_x86_64_under_translation_when_available(self):
        if platform.machine() in ("x86_64", "AMD64"):
            self.skipTest("covered by the host-architecture tests")
        self.check("x86_64", "-O2")


def _resolves(prog, name):
    try:
        prog.resolve(name)
        return True
    except KeyError:
        return False


@unittest.skipIf(pypcode is None, "pypcode is not installed")
class ScratchSpaceRegressionTests(unittest.TestCase):
    def test_tzcnt_loop_uses_scratch_offsets_far_above_a_small_array(self):
        """tzcnt expands to a P-code loop whose scratch varnodes sit near 0x34ab00; a fixed-size scratch
        array once misplaced those writes silently and returned 249 for every input."""
        from rdis.arch import make
        from rdis.loader import Image, Section
        code = bytes.fromhex("b820000000" "f30fbcc7" "c3")
        image = Image("<tzcnt>", "raw", make("x86_64"), 0x1000, 0x1000, [Section(".text", 0x1000, len(code), 0, True)],
                      {}, {}, lambda va, n: code[va - 0x1000:va - 0x1000 + n] if 0x1000 <= va < 0x1000 + len(code) else b"",
                      lambda va: None)
        prog = Program(image).analyze(objc=False, swift=False, prologues=False)
        for arg, expected in ((8, 3), (1, 0), (0, 32), (0x80000000, 31), (0xFFFFFFFF, 0), (96, 5)):
            self.assertEqual(emulate(prog, 0x1000, [arg]).value, expected, arg)


@unittest.skipIf(pypcode is None, "pypcode is not installed")
class ExplicitFailureTests(unittest.TestCase):
    def test_budget_and_unmapped_memory_are_errors_not_guesses(self):
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ppc.elf")
            data, _, entry = F.elf("ppc")
            with open(path, "wb") as fh:
                fh.write(data)
            prog = Program(open_image(path)).analyze(prologues=False)
            self.assertEqual(emulate(prog, 0x10030, [41]).value, 42)
            with self.assertRaises(EmulationError):
                emulate(prog, entry, [1], max_steps=3)
            with self.assertRaises(EmulationError):
                emulate(prog, 0x90000000, [1])

    def test_mcp_tool_returns_values_and_structured_errors(self):
        import sleigh_fixtures as F
        from rdis import mcp_server
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ppc.elf")
            data, _, entry = F.elf("ppc")
            with open(path, "wb") as fh:
                fh.write(data)

            def call(**args):
                r = mcp_server._handle({"method": "tools/call", "params": {"name": "emulate", "arguments": {
                    "path": path, "func": hex(entry), **args}}})
                self.assertFalse(r.get("isError"), r)
                return json.loads(r["content"][0]["text"])

            ok = call(args=[41])
            self.assertEqual((ok["ok"], ok["value"]), (True, 1))
            starved = call(args=[41], max_steps=3)
            self.assertFalse(starved["ok"])
            self.assertIn("budget", starved["error"])
            self.assertEqual(call(args=[1], max_steps=10 ** 12)["budget"], mcp_server.MAX_EMULATION_STEPS)

    def test_powerpc_frame_link_register_and_branch(self):
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ppc.elf")
            data, _, entry = F.elf("ppc")
            with open(path, "wb") as fh:
                fh.write(data)
            prog = Program(open_image(path)).analyze(prologues=False)
            for arg, expected in ((41, 1), (0, 1), (0xFFFFFFFF, 0), (7, 1)):
                self.assertEqual(emulate(prog, entry, [arg]).value, expected, arg)


if __name__ == "__main__":
    unittest.main()
