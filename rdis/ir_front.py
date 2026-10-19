"""IR frontends: one machine instruction -> a list of P-code-shaped ops.

An op is `(opcode, out, ins)`; varnodes are `("reg", name, size)`, `("const", value, size)`,
`("tmp", key, size)` or `("ram", addr, size)`. Opcode names follow Ghidra P-code (INT_ADD, LOAD,
CBRANCH, CALL, RETURN, ...), so both frontends feed the same lifter:

* PcodeFront — SLEIGH/P-code semantics through `pypcode` for the architecture IDs explicitly mapped by `_lang`; this is not a bridge for every Ghidra language.
* NativeFront — a dependency-free MIPS/RISC-V instruction subset used when a P-code frontend is unavailable.

For delay-slot ISAs a branch's translation includes its delay slot (executed after the condition
is computed, before control transfers), and `covered` lists every instruction address consumed.
"""
import re

from .arch import CALL, RET, JMP, CJMP, IJMP, mem_operand

try:
    import pypcode
except ImportError:      # optional: NativeFront covers MIPS / RISC-V without it
    pypcode = None


def _lang(arch, thumb):
    n = arch.name
    if n == "x86_64":
        return "x86:LE:64:default"
    if n == "x86":
        return "x86:LE:32:default"
    if n == "arm64":
        return "AARCH64:LE:64:v8A"
    if n == "arm":
        return "ARM:LE:32:v8"
    if n.startswith("mips"):
        return f"MIPS:{'LE' if n.endswith('el') else 'BE'}:{arch.bits}:default"
    if n.startswith("riscv"):
        return f"RISCV:LE:{arch.bits}:default"
    return None


class PcodeFront:
    name = "pcode"

    def __init__(self, arch):
        self.arch, self._ctx = arch, {}

    @staticmethod
    def available(arch):
        return pypcode is not None and _lang(arch, False) is not None

    def _context(self, thumb):
        if thumb not in self._ctx:
            c = pypcode.Context(_lang(self.arch, thumb))
            if thumb:
                c.setVariableDefault("TMode", 1)
            self._ctx[thumb] = c
        return self._ctx[thumb]

    def _vn(self, ctx, v):
        sp = v.space.name
        if sp == "register":
            return ("reg", ctx.getRegisterName(v.space, v.offset, v.size) or f"reg_{v.offset:x}", v.size)
        if sp == "const":
            return ("const", v.offset, v.size)
        if sp == "unique":
            return ("tmp", v.offset, v.size)
        return ("ram", v.offset, v.size)

    def translate(self, code, addr, thumb=False):
        ops, covered, _ = self.translate_with_provenance(code, addr, thumb)
        return ops, covered

    def translate_with_provenance(self, code, addr, thumb=False):
        """Translate to P-code while reporting only source addresses the frontend can prove.

        A multi-address IMARK represents a delayed-control-flow bundle. pypcode exposes the source
        instruction addresses in that marker, but does not expose an origin address on each PcodeOp.
        Operations within such a bundle are marked ambiguous unless they are the control transfer.
        """
        ctx = self._context(thumb)
        try:
            tr = ctx.translate(code, addr, max_instructions=1)
        except Exception:
            return None, [], []
        ops, covered, op_addresses = [], [], []
        current_sources = ()
        for op in tr.ops:
            name = op.opcode.name
            if name == "IMARK":
                # Each IMARK input encodes one source instruction as ram[address:length].
                # Varnode.offset is the address; Varnode.size is the instruction length.
                current_sources = tuple(dict.fromkeys(int(v.offset) for v in op.inputs))
                for source in current_sources:
                    if source not in covered:
                        covered.append(source)
                continue
            ins = [self._vn(ctx, v) for v in op.inputs]
            if name in ("LOAD", "STORE"):
                ins = ins[1:]                      # drop the address-space id
            elif name == "CALLOTHER":
                m = re.match(r"(?:.*? = )?(\w+)\(", str(op))
                ins = [("const", m.group(1) if m else "intrinsic", 0)] + ins[1:]
            out = self._vn(ctx, op.output) if op.output is not None else None
            ops.append((name, out, ins))
            if len(current_sources) == 1:
                op_addresses.append(current_sources[0])
            elif len(current_sources) > 1 and name in {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN"}:
                op_addresses.append(current_sources[0])
            else:
                op_addresses.append(None)
        if not covered and ops:
            covered.append(int(addr))
        return ops, covered, op_addresses


# ---- NativeFront: our own semantics for MIPS / RISC-V -------------------------------------------
_BIN = {"add": "INT_ADD", "addu": "INT_ADD", "addi": "INT_ADD", "addiu": "INT_ADD", "dadd": "INT_ADD",
        "daddu": "INT_ADD", "daddiu": "INT_ADD", "addw": "INT_ADD", "addiw": "INT_ADD",
        "sub": "INT_SUB", "subu": "INT_SUB", "dsubu": "INT_SUB", "subw": "INT_SUB",
        "and": "INT_AND", "andi": "INT_AND", "or": "INT_OR", "ori": "INT_OR", "xor": "INT_XOR",
        "xori": "INT_XOR", "sll": "INT_LEFT", "slli": "INT_LEFT", "sllv": "INT_LEFT", "sllw": "INT_LEFT",
        "slliw": "INT_LEFT", "dsll": "INT_LEFT", "srl": "INT_RIGHT", "srli": "INT_RIGHT",
        "srlv": "INT_RIGHT", "srlw": "INT_RIGHT", "srliw": "INT_RIGHT", "dsrl": "INT_RIGHT",
        "sra": "INT_SRIGHT", "srai": "INT_SRIGHT", "srav": "INT_SRIGHT", "sraw": "INT_SRIGHT",
        "sraiw": "INT_SRIGHT", "dsra": "INT_SRIGHT", "mul": "INT_MULT", "mulw": "INT_MULT",
        "div": "INT_SDIV", "divw": "INT_SDIV", "divu": "INT_DIV", "divuw": "INT_DIV",
        "rem": "INT_SREM", "remw": "INT_SREM", "remu": "INT_REM", "remuw": "INT_REM",
        "slt": "INT_SLESS", "slti": "INT_SLESS", "sltu": "INT_LESS", "sltiu": "INT_LESS"}
_LOAD = {"lb": (1, True), "lbu": (1, False), "lh": (2, True), "lhu": (2, False), "lw": (4, True),
         "lwu": (4, False), "ld": (8, True)}
_STORE = {"sb": 1, "sh": 2, "sw": 4, "sd": 8}
# branch mnemonic -> (P-code compare, swap operands, compare against zero)
_CMP = {"beq": ("INT_EQUAL", 0), "bne": ("INT_NOTEQUAL", 0), "blt": ("INT_SLESS", 0),
        "bge": ("INT_SLESSEQUAL", 1), "bltu": ("INT_LESS", 0), "bgeu": ("INT_LESSEQUAL", 1),
        "bgt": ("INT_SLESS", 1), "ble": ("INT_SLESSEQUAL", 0), "bgtu": ("INT_LESS", 1),
        "bleu": ("INT_LESSEQUAL", 0)}
_CMPZ = {"beqz": "beq", "bnez": "bne", "bltz": "blt", "bgez": "bge", "bgtz": "bgt", "blez": "ble"}


class NativeFront:
    name = "native"

    def __init__(self, arch):
        self.arch, self.w = arch, arch.bits // 8

    @staticmethod
    def available(arch):
        return arch.name.startswith(("mips", "riscv"))

    def _ops_of(self, i, n):
        """Ops for one non-branch instruction; `n` makes tmp keys unique per instruction."""
        w, ops = self.w, []
        m = i.mnemonic.removeprefix("c.")
        o = i.operands
        R = lambda k: ("const", 0, w) if i.reg_name(o[k].reg) == "zero" else ("reg", i.reg_name(o[k].reg), w)
        imm = lambda k: ("const", o[k].imm & ((1 << (8 * w)) - 1), w)
        src = lambda k: R(k) if o[k].type == 1 else imm(k)
        if m in ("ecall", "syscall"):
            return [("CALLOTHER", None, [("const", "syscall", 0)])]
        if m == "nop" or not o:
            return ops
        dst = ("reg", i.reg_name(o[0].reg), w) if o[0].type == 1 else None
        if dst and dst[1] == "zero":
            return ops
        if m in ("move", "mv") or (m == "li" and len(o) == 2):
            return [("COPY", dst, [src(1)])]
        if m == "not":
            return [("INT_NEGATE", dst, [R(1)])]
        if m in ("neg", "negu"):
            return [("INT_2COMP", dst, [R(1)])]
        if m in ("seqz", "snez", "sltz", "sgtz"):
            t = ("tmp", (n, 0), 1)
            cmp = {"seqz": ("INT_EQUAL", R(1), ("const", 0, w)), "snez": ("INT_NOTEQUAL", R(1), ("const", 0, w)),
                   "sltz": ("INT_SLESS", R(1), ("const", 0, w)), "sgtz": ("INT_SLESS", ("const", 0, w), R(1))}[m]
            return [(cmp[0], t, [cmp[1], cmp[2]]), ("INT_ZEXT", dst, [t])]
        if m == "lui":
            sh = 16 if self.arch.name.startswith("mips") else 12
            v = (o[1].imm << sh) & 0xffffffff
            if v & 0x80000000:
                v |= ((1 << (8 * w)) - 1) ^ 0xffffffff     # sign-extend to the register width
            return [("COPY", dst, [("const", v, w)])]
        if m == "auipc":
            return [("COPY", dst, [("const", (i.address + (o[1].imm << 12)) & ((1 << (8 * w)) - 1), w)])]
        if m == "nor":
            t = ("tmp", (n, 0), w)
            return [("INT_OR", t, [R(1), src(2)]), ("INT_NEGATE", dst, [t])]
        if m in _BIN and len(o) == 3:
            op = _BIN[m]
            if op in ("INT_SLESS", "INT_LESS"):
                t = ("tmp", (n, 0), 1)
                return [(op, t, [R(1), src(2)]), ("INT_ZEXT", dst, [t])]
            if m.endswith("w") and w == 8:   # RV64 *W ops: 32-bit result, sign-extended
                a, b, t = ("tmp", (n, 1), 4), ("tmp", (n, 2), 4), ("tmp", (n, 0), 4)
                return [("SUBPIECE", a, [R(1), ("const", 0, 4)]),
                        ("SUBPIECE", b, [src(2), ("const", 0, 4)]),
                        (op, t, [a, b]), ("INT_SEXT", dst, [t])]
            return [(op, dst, [R(1), src(2)])]
        mem = mem_operand(i)
        if m.removesuffix("sp") in _LOAD and mem:
            size, signed = _LOAD[m.removesuffix("sp")]
            addr, val = ("tmp", (n, 0), w), ("tmp", (n, 1), size)
            base = mem[0]
            b = ("const", 0, w) if not base or i.reg_name(base) == "zero" else ("reg", i.reg_name(base), w)
            ops = [("INT_ADD", addr, [b, ("const", mem[1] & ((1 << (8 * w)) - 1), w)]),
                   ("LOAD", val if size < w else dst, [addr])]
            if size < w:
                ops.append(("INT_SEXT" if signed else "INT_ZEXT", dst, [val]))
            return ops
        if m.removesuffix("sp") in _STORE and mem:
            size = _STORE[m.removesuffix("sp")]
            addr = ("tmp", (n, 0), w)
            base = mem[0]
            b = ("const", 0, w) if not base or i.reg_name(base) == "zero" else ("reg", i.reg_name(base), w)
            v = R(0)
            ops = [("INT_ADD", addr, [b, ("const", mem[1] & ((1 << (8 * w)) - 1), w)])]
            if size < w:
                t = ("tmp", (n, 1), size)
                ops.append(("SUBPIECE", t, [v, ("const", 0, 4)]))
                v = t
            return ops + [("STORE", None, [addr, v])]
        if m in ("mfhi", "mflo"):
            return [("COPY", dst, [("reg", m[2:], w)])]
        if m in ("mult", "multu", "div", "divu") and len(o) == 2:
            mul = m.startswith("mult")
            return [("INT_MULT" if mul else ("INT_SDIV" if m == "div" else "INT_DIV"), ("reg", "lo", w), [R(0), R(1)]),
                    (("INT_MULT" if mul else ("INT_SREM" if m == "div" else "INT_REM")), ("reg", "hi", w), [R(0), R(1)])]
        return [("ASM", None, [f"{i.mnemonic} {i.op_str}".strip()])]

    def translate(self, code, addr, thumb=False):
        ops, covered, _ = self.translate_with_provenance(code, addr, thumb)
        return ops, covered

    def translate_with_provenance(self, code, addr, thumb=False):
        """Native translation with exact origins for bundled delay-slot operations."""
        insns = list(self.arch.md.disasm(code, addr, 2 if self.arch.delay_slot else 1))
        if not insns:
            return None, [], []
        i = insns[0]
        k = self.arch.kind(i)
        if k == "other":
            ops = self._ops_of(i, 0)
            return ops, [i.address], [i.address] * len(ops)
        w = self.w
        ops, covered, op_addresses = [], [i.address], []
        m = i.mnemonic.removeprefix("c.")
        o = i.operands
        reg = lambda k_: ("const", 0, w) if i.reg_name(o[k_].reg) == "zero" else ("reg", i.reg_name(o[k_].reg), w)
        t = self.arch.target(i)
        cond = None
        if k == CJMP:
            base = _CMPZ.get(m, m)
            op, swap = _CMP.get(base, ("INT_NOTEQUAL", 0))
            regs = [reg(n) for n in range(len(o)) if o[n].type == 1]
            a, b = (regs + [("const", 0, w)] * 2)[:2] if m not in _CMPZ else (regs[0], ("const", 0, w))
            if swap:
                a, b = b, a
            cond = ("tmp", ("c", 0), 1)
            ops.append((op, cond, [a, b]))       # condition is read before the delay slot runs
            op_addresses.append(i.address)
        elif k == CALL and m in ("jalr",) or (k == CALL and t is None):
            tgt = ("tmp", ("c", 1), w)
            r = next((reg(n) for n in range(len(o)) if o[n].type == 1 and i.reg_name(o[n].reg) != "ra"), None)
            ops.append(("COPY", tgt, [r or ("const", 0, w)]))
            op_addresses.append(i.address)
        elif k == IJMP:
            tgt = ("tmp", ("c", 1), w)
            ops.append(("COPY", tgt, [reg(len(o) - 1) if o else ("const", 0, w)]))
            op_addresses.append(i.address)
        if self.arch.delay_slot and len(insns) > 1:
            delay_ops = self._ops_of(insns[1], 1)
            ops += delay_ops
            op_addresses += [insns[1].address] * len(delay_ops)
            covered.append(insns[1].address)
        if k == CJMP:
            ops.append(("CBRANCH", None, [("ram", t, w), cond]))
            op_addresses.append(i.address)
        elif k == JMP:
            ops.append(("BRANCH", None, [("ram", t, w)]))
            op_addresses.append(i.address)
        elif k == CALL:
            ops.append(("CALL", None, [("ram", t, w)]) if t is not None else ("CALLIND", None, [tgt]))
            op_addresses.append(i.address)
        elif k == RET:
            ops.append(("RETURN", None, [("reg", "ra", w)]))
            op_addresses.append(i.address)
        elif k == IJMP:
            ops.append(("BRANCHIND", None, [tgt]))
            op_addresses.append(i.address)
        return ops, covered, op_addresses


def frontend(arch):
    """Best available frontend for `arch`: Ghidra P-code when installed, else our own (MIPS/RISC-V).
    RDIS_IR_FRONT=native forces ours (used to cross-check the two)."""
    import os
    if os.environ.get("RDIS_IR_FRONT") != "native" and PcodeFront.available(arch):
        return PcodeFront(arch)
    if NativeFront.available(arch):
        return NativeFront(arch)
    return None
