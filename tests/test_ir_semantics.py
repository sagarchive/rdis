"""Boundary-value tests for IR constant folding and byte-accurate structure views."""
import shutil
import subprocess
import unittest

from rdis.ir import StructDB, mk


class ConstantFoldingTests(unittest.TestCase):
    def test_logical_shift_count_is_not_masked_to_six_bits(self):
        # In a 32-bit P-code value, shift amounts 32 and 64 do not wrap to 0.
        cases = [
            ("INT_LEFT", 1, 32, 0),
            ("INT_LEFT", 1, 64, 0),
            ("INT_RIGHT", 0x80000000, 32, 0),
        ]
        for op, value, shift, expected in cases:
            with self.subTest(op=op, shift=shift):
                expr = mk(op, ("c", value, 4), ("c", shift, 4), 4)
                self.assertEqual(expr, ("c", expected, 4))

    def test_arithmetic_right_shift_fills_sign_for_large_shift(self):
        expr = mk("INT_SRIGHT", ("c", 0x80000000, 4), ("c", 32, 4), 4)
        self.assertEqual(expr, ("c", 0xffffffff, 4))
        positive = mk("INT_SRIGHT", ("c", 0x7fffffff, 4), ("c", 64, 4), 4)
        self.assertEqual(positive, ("c", 0, 4))

    def test_signed_division_truncates_toward_zero(self):
        expr = mk("INT_SDIV", ("c", 0xfffffff9, 4), ("c", 3, 4), 4)
        self.assertEqual(expr, ("c", 0xfffffffe, 4))
        remainder = mk("INT_SREM", ("c", 0xfffffff9, 4), ("c", 3, 4), 4)
        self.assertEqual(remainder, ("c", 0xffffffff, 4))

    def test_division_by_zero_is_not_constant_folded(self):
        expr = mk("INT_SDIV", ("c", 7, 4), ("c", 0, 4), 4)
        self.assertEqual(expr[0], "op")
        self.assertEqual(expr[1], "/")
        remainder = mk("INT_SREM", ("c", 7, 4), ("c", 0, 4), 4)
        self.assertEqual(remainder[0], "op")
        self.assertEqual(remainder[1], "%")


class StructLayoutTests(unittest.TestCase):
    def test_packed_offsets_and_observed_field_types_are_preserved(self):
        db = StructDB(word_size=8)
        key = (0x1000, 0)
        db.access(key, 1, 4)
        db.access_type(key, 1, "float")
        db.access(key, 8, 8)
        db.access_type(key, 8, "pointer")
        name = db.name(key)
        decl = "\n".join(db.decl(name))
        self.assertIn("#pragma pack(push, 1)", decl)
        self.assertIn("uint8_t _pad_0[1]", decl)
        self.assertIn("float f_1", decl)
        self.assertIn("void * f_8", decl)
        self.assertEqual(db.field(name, 1, 4), "f_1")
        self.assertEqual(db.field(name, 8, 8), "f_8")

    def test_overlapping_views_are_not_silently_discarded(self):
        db = StructDB(word_size=8)
        key = (0x2000, 1)
        db.access(key, 0, 8)
        db.access(key, 4, 4)
        name = db.name(key)
        decl = "\n".join(db.decl(name))
        self.assertIn("union", decl)
        self.assertIn("_overlay_0", decl)
        self.assertIn("view_4_4", decl)
        self.assertEqual(db.field(name, 0, 8), "_overlay_0.f_0")
        self.assertEqual(db.field(name, 4, 4), "_overlay_0.view_4_4.f_4")

    def test_repeated_equal_width_accesses_are_reported_as_array_hypotheses(self):
        db = StructDB(word_size=8)
        key = (0x6000, 0)
        for offset in (0, 4, 8):
            db.access(key, offset, 4)
        candidates = db.array_candidates(key)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["offset"], 0)
        self.assertEqual(candidates[0]["element_size"], 4)
        self.assertEqual(candidates[0]["stride"], 4)
        self.assertEqual(candidates[0]["count"], 3)
        self.assertEqual(candidates[0]["confidence"], "candidate")
        # Do not automatically turn an ambiguous pattern into an array declaration.
        self.assertNotIn("[3]", "\n".join(db.decl(db.name(key))))

    def test_two_same_width_fields_are_not_enough_to_claim_an_array(self):
        db = StructDB(word_size=8)
        key = (0x7000, 0)
        db.access(key, 0, 4)
        db.access(key, 4, 4)
        self.assertEqual(db.array_candidates(key), [])

    def test_conflicting_field_types_do_not_claim_a_specific_type(self):
        db = StructDB(word_size=8)
        key = (0x3000, 0)
        db.access(key, 0, 4)
        db.access(key, 8, 4)
        db.access_type(key, 0, "float")
        db.access_type(key, 0, "signed")
        name = db.name(key)
        decl = "\n".join(db.decl(name))
        self.assertNotIn("float f_0", decl)
        self.assertIn("uint32_t f_0", decl)

    @unittest.skipUnless(shutil.which("cc") or shutil.which("clang"), "C compiler unavailable")
    def test_emitted_structs_compile_with_expected_byte_offsets(self):
        compiler = shutil.which("cc") or shutil.which("clang")
        db = StructDB(word_size=8)
        key = (0x4000, 0)
        db.access(key, 1, 4)
        db.access_type(key, 1, "float")
        db.access(key, 8, 8)
        db.access_type(key, 8, "pointer")
        name = db.name(key)
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n"
            + "\n".join(db.decl(name))
            + f"\n_Static_assert(sizeof(struct {name}) == 16, \"size\");"
            + f"\n_Static_assert(offsetof(struct {name}, f_1) == 1, \"packed float offset\");"
            + f"\n_Static_assert(offsetof(struct {name}, f_8) == 8, \"pointer offset\");"
        )
        result = subprocess.run([compiler, "-x", "c", "-std=gnu11", "-fsyntax-only", "-"],
                                input=source, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("cc") or shutil.which("clang"), "C compiler unavailable")
    def test_overlapping_struct_views_compile_and_preserve_offsets(self):
        compiler = shutil.which("cc") or shutil.which("clang")
        db = StructDB(word_size=8)
        key = (0x5000, 0)
        db.access(key, 0, 8)
        db.access(key, 4, 4)
        name = db.name(key)
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n"
            + "\n".join(db.decl(name))
            + f"\n_Static_assert(sizeof(struct {name}) == 8, \"union layout size\");"
            + f"\n_Static_assert(offsetof(struct {name}, _overlay_0.view_4_4.f_4) == 4, \"overlap view offset\");"
        )
        result = subprocess.run([compiler, "-x", "c", "-std=gnu11", "-fsyntax-only", "-"],
                                input=source, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
