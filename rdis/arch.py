"""CPU backends: decoding plus the few branch facts analysis needs."""
import capstone as cs
from capstone import arm64 as a64, x86

CALL, RET, JMP, CJMP, IJMP, OTHER = "call", "ret", "jmp", "cjmp", "ijmp", "other"


class Arch:
    def __init__(self, name, cs_arch, cs_mode, bits, args, ret, sp, fp, nop, fargs=(), fret=None):
        self.name, self.bits, self.args, self.ret, self.sp, self.fp, self.nop = name, bits, args, ret, sp, fp, nop
        self.fargs, self.fret = list(fargs), fret  # floating-point/vector argument & return registers
        self.md = cs.Cs(cs_arch, cs_mode)
        self.md.detail = True

    def decode(self, code, addr, thumb=False):
        md = self.thumb_md if thumb and getattr(self, "thumb_md", None) else self.md
        return next(md.disasm(code, addr), None)

    def is_blx(self, i):
        """ARM: does this call/branch toggle instruction set (Thumb<->ARM)? `blx <label>` and `bx`."""
        return self.name == "arm" and i.mnemonic.split(".")[0] in ("blx", "bx")

    def kind(self, i):
        # cache per instruction: kind() is called many times for the same decoded insn, and each
        # capstone group lookup rebuilds the group list, so this dominated analysis time.
        cached = getattr(i, "_rdis_kind", None)
        if cached is not None:
            return cached
        g = set(i.groups)  # read the group list once
        # Check CALL before JUMP: Capstone puts arm64 `bl` in both groups.
        if cs.CS_GRP_CALL in g:
            k = CALL
        elif cs.CS_GRP_RET in g:
            k = RET
        elif cs.CS_GRP_JUMP in g:
            k = IJMP if self.target(i) is None else (JMP if i.mnemonic in ("jmp", "b") else CJMP)
        else:
            k = OTHER
        try:
            i._rdis_kind = k
        except Exception:
            pass
        return k

    def data_refs(self, i, regs):
        """Absolute addresses `i` references as data. `regs` carries arm64 adrp pages within a block."""
        if self.name.startswith("x86"):
            out = []
            for op in i.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    out.append(i.address + i.size + op.mem.disp)
                elif op.type == x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp > 0:
                    out.append(op.mem.disp)  # 32-bit absolute [disp]
                elif op.type == x86.X86_OP_IMM and self.bits == 32 and op.imm > 0x10000:
                    out.append(op.imm)
            return out
        if self.name != "arm64" or not i.operands:
            return []
        ops, m = i.operands, i.mnemonic
        if m in ("adrp", "adr") and len(ops) == 2:
            regs[ops[0].reg] = ops[1].imm
            return [ops[1].imm] if m == "adr" else []
        if m == "add" and len(ops) == 3 and ops[1].type == a64.ARM64_OP_REG and ops[2].type == a64.ARM64_OP_IMM \
                and ops[1].reg in regs:
            regs[ops[0].reg] = v = regs[ops[1].reg] + ops[2].imm
            return [v]
        for op in ops:
            if op.type == a64.ARM64_OP_MEM and op.mem.base in regs:
                v = regs[op.mem.base] + op.mem.disp
                if m.startswith("ld") and ops[0].type == a64.ARM64_OP_REG:
                    regs.pop(ops[0].reg, None)
                    regs[("slot", ops[0].reg)] = v  # lets a later `br/blr reg` resolve to this pointer
                return [v]
            if op.type == a64.ARM64_OP_IMM and m.startswith("ldr") and len(ops) == 2:
                return [op.imm]  # literal-pool load
        if ops[0].type == a64.ARM64_OP_REG:
            regs.pop(ops[0].reg, None)  # any other write clobbers a tracked page
        return []

    @staticmethod
    def target(i):
        """Immediate branch/call target, or None for register-indirect."""
        if i.operands and i.operands[-1].type == cs.CS_OP_IMM:
            return i.operands[-1].imm
        return None


def make(name):
    if name in ("x86_64", "x64", "amd64"):
        return Arch("x86_64", cs.CS_ARCH_X86, cs.CS_MODE_64, 64,
                    ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], "rax", "rsp", "rbp", b"\x90",
                    [f"xmm{n}" for n in range(8)], "xmm0")
    if name in ("x86", "i386"):
        return Arch("x86", cs.CS_ARCH_X86, cs.CS_MODE_32, 32, [], "eax", "esp", "ebp", b"\x90")
    if name in ("arm64", "aarch64", "arm64e"):
        return Arch("arm64", cs.CS_ARCH_ARM64, cs.CS_MODE_ARM, 64,
                    [f"x{n}" for n in range(8)], "x0", "sp", "x29", b"\x1f\x20\x03\xd5",
                    [f"v{n}" for n in range(8)], "v0")
    if name in ("arm", "armv7"):
        a = Arch("arm", cs.CS_ARCH_ARM, cs.CS_MODE_ARM, 32,
                 ["r0", "r1", "r2", "r3"], "r0", "sp", "r11", b"\x00\xf0\x20\xe3")
        a.thumb_md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
        a.thumb_md.detail = True
        return a
    raise ValueError(f"unsupported architecture: {name}")
