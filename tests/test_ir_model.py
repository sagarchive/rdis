import unittest
from types import SimpleNamespace

from rdis.ir import IRLifter
from rdis.ir_model import IRFunction, IRBlock, IRInstruction, build_function_ir
from rdis.ir_front import PcodeFront


class IRModelTests(unittest.TestCase):
    def test_signed_comparison_has_boolean_result_and_source_width(self):
        op = IRInstruction.from_frontend(
            0x1000, 0, "INT_SLESS", ("tmp", (0x1000, 0), 1),
            [("reg", "r1", 4), ("reg", "r2", 4)],
        )
        self.assertEqual(op.result_type.kind, "bool")
        self.assertEqual(op.result_type.bits, 1)
        self.assertEqual(op.validate(), ())
        self.assertEqual(op.effects, ())

    def test_float_nan_is_a_boolean_predicate_not_a_float_result(self):
        op = IRInstruction.from_frontend(
            0x1002, 0, "FLOAT_NAN", ("tmp", "isnan", 1), [("reg", "f0", 8)]
        )
        self.assertEqual(op.result_type.kind, "bool")
        self.assertEqual(op.result_type.bits, 1)
        self.assertEqual(op.validate(), ())

    def test_multi_instruction_imark_marks_non_transfer_origins_ambiguous(self):
        class Space:
            def __init__(self, name):
                self.name = name
        class Varnode:
            def __init__(self, offset, size, space):
                self.offset, self.size, self.space = offset, size, Space(space)
        class OpCode:
            def __init__(self, name):
                self.name = name
        class Op:
            def __init__(self, name, inputs=(), output=None):
                self.opcode, self.inputs, self.output = OpCode(name), list(inputs), output
            def __str__(self):
                return self.opcode.name
        class Context:
            def translate(self, code, addr, max_instructions=1):
                return SimpleNamespace(ops=[
                    Op("IMARK", [Varnode(0x5000, 4, "ram"), Varnode(0x5004, 4, "ram")]),
                    Op("INT_ADD", [Varnode(1, 4, "const"), Varnode(2, 4, "const")],
                       Varnode(0, 4, "unique")),
                    Op("CBRANCH", [Varnode(0x5010, 8, "ram"), Varnode(1, 1, "const")]),
                ])
            def getRegisterName(self, space, offset, size):
                return f"r{offset}"

        front = object.__new__(PcodeFront)
        front.arch = SimpleNamespace(delay_slot=True)
        front._context = lambda thumb: Context()
        ops, covered, addresses = front.translate_with_provenance(b"\\0" * 16, 0x5000)
        self.assertEqual(covered, [0x5000, 0x5004])
        self.assertEqual(addresses, [None, 0x5000])
        self.assertEqual(len(ops), 2)

    def test_bitwise_shift_result_is_not_mislabeled_unsigned(self):
        op = IRInstruction.from_frontend(
            0x1004, 0, "INT_LEFT", ("tmp", (0x1004, 0), 4),
            [("reg", "r1", 4), ("const", 2, 4)],
        )
        self.assertEqual(op.result_type.kind, "int")
        self.assertEqual(op.result_type.signedness, "signless")

    def test_load_store_and_call_expose_side_effects(self):
        load = IRInstruction.from_frontend(0x1010, 0, "LOAD", ("tmp", 1, 4), [("reg", "r1", 8)])
        store = IRInstruction.from_frontend(0x1014, 0, "STORE", None,
                                            [("reg", "r1", 8), ("reg", "r2", 4)])
        call = IRInstruction.from_frontend(0x1018, 0, "CALLIND", None, [("reg", "r3", 8)])
        self.assertIn("memory_read", load.effects)
        self.assertIn("memory_write", store.effects)
        self.assertIn("call", call.effects)
        self.assertEqual(store.validate(), ())

    def test_known_opcode_arity_errors_are_reported(self):
        op = IRInstruction.from_frontend(0x1020, 0, "INT_ADD", ("reg", "r1", 4), [("reg", "r2", 4)])
        self.assertIn("expects 2..2 inputs", op.validate()[0])

    def test_pointer_arithmetic_and_less_common_pcode_ops_are_typed_and_validated(self):
        ptr = IRInstruction.from_frontend(
            0x1024, 0, "PTRADD", ("reg", "r1", 8),
            [("reg", "r2", 8), ("reg", "r3", 8), ("const", 4, 8)],
        )
        self.assertEqual(ptr.result_type.kind, "pointer")
        self.assertEqual(ptr.validate(), ())
        trunc = IRInstruction.from_frontend(
            0x1028, 0, "FLOAT_TRUNC", ("tmp", (0x1028, 0), 4), [("reg", "f1", 8)]
        )
        self.assertEqual(trunc.result_type.kind, "float")
        self.assertEqual(trunc.validate(), ())
        insert = IRInstruction.from_frontend(
            0x102c, 0, "INSERT", ("reg", "r1", 8),
            [("reg", "r2", 8), ("reg", "r3", 4), ("const", 8, 4), ("const", 8, 4)],
        )
        self.assertEqual(insert.validate(), ())

    def test_unknown_opcodes_and_negative_provenance_are_not_silently_valid(self):
        unknown = IRInstruction.from_frontend(0x1034, 0, "VENDOR_MAGIC_OP", None, [])
        self.assertIn("unsupported opcode: VENDOR_MAGIC_OP", unknown.validate())
        bad = IRInstruction.from_frontend(-1, -1, "VENDOR_MAGIC_OP", None, [])
        self.assertIn("source address cannot be negative", bad.validate())
        self.assertIn("operation sequence cannot be negative", bad.validate())

    def test_function_json_is_deterministic_and_has_schema_version(self):
        op = IRInstruction.from_frontend(0x1030, 0, "COPY", ("reg", "r1", 4), [("const", 7, 4)])
        func = IRFunction("riscv32", 0x1030, (IRBlock(0x1030, (op,), ()),))
        self.assertEqual(func.validate(), ())
        self.assertEqual(func.to_json(), func.to_json())
        self.assertEqual(func.to_dict()["schema_version"], 2)
        self.assertEqual(func.to_dict()["blocks"][0]["instructions"][0]["source_address"], 0x1030)

    def test_duplicate_blocks_and_missing_entry_are_rejected(self):
        func = IRFunction("x86_64", 0x9999, (IRBlock(0x1000, ()), IRBlock(0x1000, ())))
        issues = func.validate()
        self.assertIn("duplicate basic-block address", issues)
        self.assertIn("entry address does not identify a basic block", issues)

    def test_builder_preserves_source_address_and_does_not_duplicate_covered_delay_slot(self):
        class Front:
            def __init__(self):
                self.calls = []
            def translate(self, code, addr, thumb=False):
                self.calls.append(addr)
                if addr == 0x2000:
                    return [("CBRANCH", None, [("ram", 0x2010, 8), ("tmp", "cond", 1)])], [0x2000, 0x2004]
                return [("COPY", ("reg", "r1", 4), [("const", 1, 4)])], [addr]

        i0 = SimpleNamespace(address=0x2000)
        delay = SimpleNamespace(address=0x2004)
        block = SimpleNamespace(addr=0x2000, insns=[i0], delay=delay, succs=[0x2010])
        target_block = SimpleNamespace(addr=0x2010, insns=[], succs=[])
        func = SimpleNamespace(addr=0x2000, blocks={0x2000: block, 0x2010: target_block})
        prog = SimpleNamespace(
            arch=SimpleNamespace(name="mips64"),
            image=SimpleNamespace(read=lambda addr, size: b"\0" * size),
            _insns={},
        )
        front = Front()
        lowered = build_function_ir(prog, func, front)
        self.assertEqual(front.calls, [0x2000])
        self.assertEqual(len(lowered.blocks[0].instructions), 1)
        self.assertEqual(lowered.blocks[0].instructions[0].source_address, 0x2000)
        self.assertEqual(lowered.validate(), ())

        lifter = object.__new__(IRLifter)
        lifter.prog, lifter.func, lifter.front = prog, func, front
        exposed = lifter.canonical_ir()
        self.assertEqual(exposed.to_json(), lowered.to_json())

    def test_builder_serializes_ambiguous_bundle_provenance_instead_of_guessing(self):
        class Front:
            def translate(self, code, addr, thumb=False):
                ops, covered, _ = self.translate_with_provenance(code, addr, thumb)
                return ops, covered
            def translate_with_provenance(self, code, addr, thumb=False):
                if addr == 0x4800:
                    return [("COPY", ("reg", "r1", 4), [("const", 1, 4)])], [0x4800, 0x4804], [None]
                return [], [addr], []

        branch = SimpleNamespace(address=0x4800)
        delay = SimpleNamespace(address=0x4804)
        block = SimpleNamespace(addr=0x4800, insns=[branch], delay=delay,
                                shown=[branch, delay], succs=[0x4810])
        target = SimpleNamespace(addr=0x4810, insns=[], delay=None, shown=[], succs=[])
        func = SimpleNamespace(addr=0x4800, blocks={0x4800: block, 0x4810: target})
        prog = SimpleNamespace(
            arch=SimpleNamespace(name="mips64"),
            image=SimpleNamespace(read=lambda addr, size: b"\\0" * size),
            _insns={},
        )
        lowered = build_function_ir(prog, func, Front())
        op = lowered.blocks[0].instructions[0]
        self.assertEqual(op.source_address, 0x4800)
        self.assertFalse(op.source_address_exact)
        self.assertEqual(op.source_candidates, (0x4800, 0x4804))
        self.assertEqual(op.validate(), ())
        serialized = lowered.to_dict()["blocks"][0]["instructions"][0]
        self.assertFalse(serialized["source_address_exact"])
        self.assertEqual(serialized["source_candidates"], [0x4800, 0x4804])

    def test_builder_preserves_per_operation_source_for_translated_delay_slot(self):
        class Front:
            def translate(self, code, addr, thumb=False):
                ops, covered, _ = self.translate_with_provenance(code, addr, thumb)
                return ops, covered

            def translate_with_provenance(self, code, addr, thumb=False):
                if addr == 0x4000:
                    return [
                        ("CBRANCH", None, [("ram", 0x4010, 8), ("const", 1, 1)]),
                        ("COPY", ("reg", "r1", 4), [("const", 7, 4)]),
                    ], [0x4000, 0x4004], [0x4000, 0x4004]
                return [], [addr], []

        branch = SimpleNamespace(address=0x4000)
        delay = SimpleNamespace(address=0x4004)
        block = SimpleNamespace(addr=0x4000, insns=[branch], delay=delay,
                                shown=[branch, delay], succs=[0x4010])
        target = SimpleNamespace(addr=0x4010, insns=[], delay=None, shown=[], succs=[])
        func = SimpleNamespace(addr=0x4000, blocks={0x4000: block, 0x4010: target})
        prog = SimpleNamespace(
            arch=SimpleNamespace(name="mips64"),
            image=SimpleNamespace(read=lambda addr, size: b"\\0" * size),
            _insns={},
        )

        lowered = build_function_ir(prog, func, Front())
        ops = lowered.blocks[0].instructions
        self.assertEqual([op.source_address for op in ops], [0x4000, 0x4004])
        self.assertEqual([op.sequence for op in ops], [0, 0])
        self.assertEqual(lowered.validate(), ())

    def test_builder_keeps_delay_slot_when_frontend_does_not_cover_it(self):
        class Front:
            def __init__(self):
                self.calls = []
            def translate(self, code, addr, thumb=False):
                self.calls.append(addr)
                if addr == 0x3000:
                    return [("BRANCH", None, [("ram", 0x3010, 8)])], [0x3000]
                return [("COPY", ("reg", "r1", 4), [("const", 7, 4)])], [addr]

        branch = SimpleNamespace(address=0x3000)
        delay = SimpleNamespace(address=0x3004)
        block = SimpleNamespace(addr=0x3000, insns=[branch], delay=delay, succs=[0x3010])
        target = SimpleNamespace(addr=0x3010, insns=[], delay=None, succs=[])
        func = SimpleNamespace(addr=0x3000, blocks={0x3000: block, 0x3010: target})
        prog = SimpleNamespace(
            arch=SimpleNamespace(name="mips64"),
            image=SimpleNamespace(read=lambda addr, size: b"\\0" * size),
            _insns={},
        )
        front = Front()
        lowered = build_function_ir(prog, func, front)
        self.assertEqual(front.calls, [0x3000, 0x3004])
        self.assertEqual([op.source_address for op in lowered.blocks[0].instructions], [0x3000, 0x3004])
        self.assertEqual(lowered.validate(), ())


if __name__ == "__main__":
    unittest.main()
