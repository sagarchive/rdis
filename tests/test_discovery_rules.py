import unittest

from rdis.analysis import Program

RET, JMP8 = b"\xc3", b"\xeb\x05"


class X86PaddingGuard(unittest.TestCase):
    def test_multibyte_nops_after_a_return_are_padding(self):
        for pad in (b"\x0f\x1f\x00", b"\x0f\x1f\x84\x00\x00\x00\x00\x00", b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
                    b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00", b"\x90\x0f\x1f\x40\x00", b"\xcc\xcc"):
            self.assertTrue(Program._x86_after_terminator(b"\x5d" + RET + pad), pad.hex())

    def test_indirect_jump_and_padded_noreturn_call_end_a_function(self):
        self.assertTrue(Program._x86_after_terminator(b"\x5d\xff\xe0\x90"))
        self.assertTrue(Program._x86_after_terminator(b"\xe8\x10\x20\x00\x00\x0f\x1f\x00"))
        self.assertTrue(Program._x86_after_terminator(b"\x0f\x0b"))

    def test_mid_function_bytes_are_not_a_boundary(self):
        self.assertFalse(Program._x86_after_terminator(b"\x48\x89\xe5\x31\xc0"))
        self.assertFalse(Program._x86_after_terminator(b"\xe8\x10\x20\x00\x00"))   # a call with no padding after it


class Arm64PairPush(unittest.TestCase):
    RET_ = (0xD65F03C0).to_bytes(4, "little")

    def words(self, *ws):
        return b"".join(w.to_bytes(4, "little") for w in ws)

    def test_callee_saved_pair_push_then_frame_save_opens_a_function(self):
        code = self.RET_ + self.words(0xA9BD57F6, 0xA9014FF4, 0xA9027BFD, 0x910083FD)
        self.assertTrue(Program._arm64_pair_push_then_fp_lr_save(code, 4))

    def test_no_frame_save_or_no_terminator_before_is_rejected(self):
        self.assertFalse(Program._arm64_pair_push_then_fp_lr_save(self.RET_ + self.words(0xA9BD57F6, 0xD503201F, 0xD503201F), 4))
        self.assertFalse(Program._arm64_pair_push_then_fp_lr_save(self.words(0x91000400, 0xA9BD57F6, 0xA9027BFD), 4))


if __name__ == "__main__":
    unittest.main()
