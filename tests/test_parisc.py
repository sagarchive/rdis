"""PA-RISC through SLEIGH: known encodings from the architecture manual and the declared ABI registers."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import sleigh

NOP = bytes.fromhex("08000240")           # or %r0,%r0,%r0
RETURN = bytes.fromhex("e840c000")        # bv %r0(%rp)


class PariscSpec(unittest.TestCase):
    def test_the_spec_names_registers_that_exist_in_the_language(self):
        import pypcode
        lang, bits, args, ret, sp, fp, fargs, fret, delay = sleigh._SPECS["parisc"]
        regs = set(pypcode.Context(lang).registers.keys())
        self.assertEqual(bits, 32)
        self.assertEqual(args, ["r26", "r25", "r24", "r23"], "PA-RISC passes four arguments in r26..r23")
        for name in (*args, ret, sp, fp):
            self.assertIn(name, regs)
        self.assertEqual((ret, fp), ("r28", "r3"))
        self.assertTrue(delay, "PA-RISC branches have a delay slot")

    def test_it_is_listed_with_the_other_cpus(self):
        out = subprocess.run([sys.executable, "-m", "rdis", "--list-archs"], cwd=ROOT, capture_output=True, text=True).stdout
        self.assertIn("parisc", out)

    def test_known_encodings_disassemble_as_nop_and_return(self):
        with tempfile.TemporaryDirectory() as d:
            blob = os.path.join(d, "pa.bin")
            with open(blob, "wb") as fh:
                fh.write(NOP + RETURN + NOP)
            out = subprocess.run([sys.executable, "-m", "rdis", blob, "--loader", "raw", "--arch", "parisc", "--base", "0x1000",
                                  "-f", "0x1000"], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            rows = [line.split() for line in out.stdout.splitlines() if line.strip().startswith("0x")]
            self.assertEqual([(r[0], r[1]) for r in rows[:3]], [("0x00001000", "nop"), ("0x00001004", "bv"), ("0x00001008", "nop")])
            self.assertIn("(rp)", out.stdout)


if __name__ == "__main__":
    unittest.main()
