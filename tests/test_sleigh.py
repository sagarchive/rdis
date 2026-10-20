"""CPUs decoded through Ghidra's SLEIGH specs (rdis/sleigh.py). Needs the optional `pypcode` package;
the whole file skips without it. Fixtures are hand-assembled programs (tests/sleigh_fixtures.py)."""
import os, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pypcode
except ImportError:
    pypcode = None

from rdis.analysis import Program
from rdis.decompile import Decompiler
from rdis.loader import open_image


@unittest.skipIf(pypcode is None, "pypcode is not installed (pip install 'rdis[ir]')")
class SleighCpuTests(unittest.TestCase):
    def test_abi_tables_match_their_specs(self):
        """A typo'd register in an ABI table would silently disable parameter recovery for a CPU."""
        from rdis import sleigh
        for name, (lang, bits, args, ret, sp, fp, fargs, fret, _) in sleigh._SPECS.items():
            regs = {r.lower() for r in pypcode.Context(lang).registers}
            for r in [*args, ret, sp, fp, *fargs, fret]:
                self.assertTrue(r is None or r.lower() in regs, f"{name}: {r!r} is not a register of {lang}")
            self.assertEqual(sleigh.make(name).bits, bits)

    def test_every_bundled_language_resolves(self):
        from rdis import sleigh
        ids = sleigh.languages()
        self.assertGreaterEqual(len(ids), 190)
        self.assertEqual(sleigh.make("sleigh:" + ids[0]).name, "sleigh:" + ids[0])
        with self.assertRaises(ValueError):                   # from_id returns None for a typo
            sleigh.make("sleigh:NoSuch:LE:32:default")

    def test_fixture_programs_on_eleven_cpus(self):
        """`f: call g; test; branch over one insn; ret` + `g: ret`: two functions, the call edge and a
        3-block diamond on every CPU (PowerPC, 68k, AVR, MSP430, SPARC and SH-4 with delay slots, Z80,
        6502, Xtensa, eBPF, LoongArch)."""
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            for name, mk in F.FIXTURES.items():
                with self.subTest(cpu=name):
                    code, base, f, g, nblocks = mk()
                    path = os.path.join(d, name + ".bin")
                    Path(path).write_bytes(code)
                    p = Program(open_image(path, loader="raw", arch=name, base=base)).analyze(prologues=False)
                    self.assertEqual(sorted(p.functions), [f, g])
                    fn = p.functions[f]
                    self.assertEqual(fn.calls, {g})
                    self.assertEqual(len(fn.blocks), nblocks)
                    entry = fn.blocks[f]
                    self.assertEqual(len(entry.succs), 2)
                    self.assertTrue(all(s in fn.blocks for s in entry.succs))
                    join = fn.blocks[max(fn.blocks)]          # the last block is the join: it returns
                    self.assertEqual(join.succs, [])
                    self.assertIn("ret", {p.arch.kind(i) for i in join.shown})

    def test_real_elf_containers_and_decompile(self):
        """The same programs inside real ELF files: LIEF finds the CPU and entry, the P-code IR
        decompiles, and the decompiled entry calls the callee."""
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            for name in F.ELF_MACHINE:
                with self.subTest(cpu=name):
                    _, _, f, g, _ = F.FIXTURES[name]()
                    data, _, entry = F.elf(name)
                    path = os.path.join(d, name + ".elf")
                    Path(path).write_bytes(data)
                    im = open_image(path)
                    self.assertEqual((im.arch.name, im.entry), (name, entry))
                    p = Program(im).analyze(prologues=False)
                    self.assertEqual(sorted(p.functions), [f, g])
                    self.assertIn(f"sub_{g:x}", Decompiler(p, p.functions[f]).c())

    def test_powerpc_condition_register_folds(self):
        """`cmpwi r3,0; beq` must decompile to `x != 0`, not a packed CR0 word, and the callee to r3 + 1."""
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ppc.elf")
            data, _, entry = F.elf("ppc")
            Path(path).write_bytes(data)
            p = Program(open_image(path)).analyze(prologues=False)
            main = Decompiler(p, p.functions[entry]).c()
            self.assertIn("if (u1 != 0)", main)
            self.assertIn("r3_1 = 1", main)
            self.assertNotIn("<<", main)
            self.assertIn("return r3 + 1;", Decompiler(p, p.functions[0x10030]).c())

    def test_sparc_register_window_spill_is_pinned_off(self):
        """The spec pins DECOMPILE_MODE=1 for decompilers; without honouring it `save` expands to
        a 16-register spill guarded by an undefined flag."""
        import sleigh_fixtures as F
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sparc.elf")
            data, _, entry = F.elf("sparc")
            Path(path).write_bytes(data)
            p = Program(open_image(path)).analyze(prologues=False)
            c = Decompiler(p, p.functions[entry]).c()
            self.assertNotIn("decompile_mode", c)
            self.assertNotIn("cwp", c)

    def test_delay_slot_is_per_instruction(self):
        """SuperH `bt` has no delay slot, so the instruction after it must stay in the fall-through block."""
        import sleigh_fixtures as F
        code, base, f, g, _ = F.FIXTURES["sh4"]()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sh4.bin")
            Path(path).write_bytes(code)
            p = Program(open_image(path, loader="raw", arch="sh4", base=base)).analyze(prologues=False)
            mov = base + 0x08                                # `mov #1,r0`, right after `bt`
            self.assertIn(mov, p.functions[f].blocks)


if __name__ == "__main__":
    unittest.main()
