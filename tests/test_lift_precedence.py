"""Operator precedence in lifted C: a shifted operand must be parenthesized.

In C `>>` binds tighter than `^`, so `a ^ b >> 2` is `a ^ (b >> 2)`, not `(a ^ b) >> 2`.
The lifter therefore parenthesizes a compound operand before shifting it (TBZ/TBNZ and
the other bit-field forms). The fixture is hand-encoded arm64, not produced by RDIS.
"""
import unittest

from rdis.analysis import Program
from rdis.arch import make
from rdis.lift import Lifter
from rdis.loader import Image, Section

BASE = 0x1000
# eor w8, w8, w9 ; tbz w8, #2, +8 ; ret
CODE = bytes.fromhex("0801094a48001036c0035fd6")


class LiftPrecedenceTests(unittest.TestCase):
    def test_tbz_of_xor_shifts_the_whole_xor(self):
        def read(va, n):
            off = va - BASE
            return CODE[off:off + n] if 0 <= off < len(CODE) else b""

        image = Image("<tbz-precedence>", "raw", make("arm64"), BASE, BASE,
                      [Section(".text", BASE, len(CODE), 0, True)], {}, {}, read,
                      lambda va: va - BASE if BASE <= va < BASE + len(CODE) else None)
        program = Program(image).analyze(objc=False, swift=False, prologues=False)
        lifter = Lifter(program)
        tbz = list(make("arm64").decode_run(CODE, BASE))[1]
        self.assertEqual(tbz.mnemonic, "tbz")

        lifter._last_regs = {"x8": "local_4 ^ local_0", "x9": "local_0"}
        cond = lifter._cond_from(tbz, None)
        self.assertIn("((local_4 ^ local_0) >> 2)", cond)
        self.assertNotIn("local_4 ^ local_0 >> 2", cond)
