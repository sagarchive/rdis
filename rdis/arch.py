"""CPU backends: decoding plus the few branch facts analysis needs."""
import capstone as cs
from capstone import arm, arm64 as a64, x86

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

    def decode_run(self, code, addr, thumb=False):
        md = self.thumb_md if thumb and getattr(self, "thumb_md", None) else self.md
        return md.disasm(code, addr)

    def is_blx(self, i):
        """ARM: does this call/branch toggle instruction set (Thumb<->ARM)? `blx <label>` and `bx`."""
        return self.name == "arm" and i.mnemonic.split(".")[0] in ("blx", "bx")

    delay_slot = False  # MIPS: the instruction after a branch executes before the branch takes

    def kind(self, i):
        # cache per instruction: kind() is called many times for the same decoded insn, and each
        # capstone group lookup rebuilds the group list, so this dominated analysis time.
        cached = getattr(i, "_rdis_kind", None)
        if cached is not None:
            return cached
        g = set(i.groups)  # read the group list once
        if self.name.startswith(("mips", "riscv")):
            k = self._risc_kind(i, g)
        elif self.name == "arm" and (pc := self._arm_pc_write(i)):
            k = pc
        # Check CALL before JUMP: Capstone puts arm64 `bl` in both groups.
        elif cs.CS_GRP_CALL in g:
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
        if self.name.startswith(("mips", "riscv")):
            return self._risc_refs(i, regs)
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

    def _arm_pc_write(self, i):
        """ARM/Thumb returns and computed jumps that Capstone files under no group: `pop {.., pc}`,
        `ldm sp!, {.., pc}`, `ldr pc, [sp], #4`, `mov pc, lr` — plus `bx lr`, which it calls a jump.
        Without this every function fell through its return into the next one. A conditional
        return (`popeq {pc}`) stays OTHER so the walk continues into the not-taken path.
        ponytail: conditional returns lose their exit edge; model as CJMP-to-exit if graphs need it."""
        m, ops = i.mnemonic, i.op_str
        if m.startswith(("pop", "ldm")) and ops.rstrip("}").endswith("pc"):
            k = RET
        elif m.startswith("bx") and not m.startswith("bxj"):
            k = RET if ops == "lr" else IJMP
        elif m.startswith(("mov", "ldr")) and ops.startswith("pc,"):
            k = RET if ops in ("pc, lr", "pc, [sp], #4") else IJMP
        else:
            return None
        cc = getattr(i, "cc", arm.ARM_CC_AL)
        return k if cc in (arm.ARM_CC_AL, getattr(arm, "ARM_CC_INVALID", -1)) else OTHER

    def _risc_refs(self, i, regs):
        """Address materialization on MIPS (`lui hi; addiu/ori lo` or `lw rd, lo(rt)`) and
        RISC-V (`auipc hi; addi lo` or `ld rd, lo(rt)`): track the high part per register within a
        block, like arm64 adrp pages."""
        ops, m = i.operands, i.mnemonic.removeprefix("c.")
        if not ops or ops[0].type != cs.CS_OP_REG:
            return []
        mask = (1 << self.bits) - 1
        rd = ops[0].reg
        if m in ("jalr", "jr"):                     # `auipc ra, hi; jalr ra, ra, lo` -> call target
            base = ops[1] if len(ops) >= 2 and ops[1].type == cs.CS_OP_REG else ops[0]
            imm = ops[-1].imm if ops[-1].type == cs.CS_OP_IMM else 0
            if base.reg in regs:
                return [(regs[base.reg] + imm) & mask]
            return []
        if m == "lui" and len(ops) == 2 and ops[1].type == cs.CS_OP_IMM:
            regs[rd] = (ops[1].imm << (16 if self.name.startswith("mips") else 12)) & mask
            return []
        if m == "auipc" and len(ops) == 2:
            regs[rd] = (i.address + (ops[1].imm << 12)) & mask
            return []
        if m in ("addiu", "addi", "daddiu", "ori") and len(ops) == 3 and ops[1].type == cs.CS_OP_REG \
                and ops[1].reg in regs and ops[2].type == cs.CS_OP_IMM:
            v = (regs[ops[1].reg] | ops[2].imm) if m == "ori" else (regs[ops[1].reg] + ops[2].imm) & mask
            regs[rd] = v
            return [v]
        mem = mem_operand(i)
        if mem is not None and mem[0] in regs:
            v = (regs[mem[0]] + mem[1]) & mask
            if m.startswith("l"):
                regs.pop(rd, None)
                regs[("slot", rd)] = v
            return [v]
        if mem is None:
            regs.pop(rd, None)   # any other write clobbers a tracked high part
        return []

    def _risc_kind(self, i, g):
        """MIPS / RISC-V: Capstone's groups are unreliable here (RISC-V files `ret` and `j` under
        "call", MIPS files `jr $ra` as a plain jump), so classify by mnemonic and link register."""
        m = i.mnemonic.removeprefix("c.")
        ops = i.operands
        if self.name.startswith("mips"):
            if (m in ("jr", "jr.hb") and i.op_str == "$ra") or m in ("break", "sdbbp"):
                return RET
            if m in ("jal", "bal", "jalr", "jalr.hb", "jalx", "bgezal", "bltzal", "jialc", "balc"):
                return CALL
            if m in ("j", "b", "bc"):
                return JMP
            if m in ("jr", "jr.hb", "jic"):
                return IJMP
            return CJMP if cs.CS_GRP_JUMP in g else OTHER
        rd = i.reg_name(ops[0].reg) if ops and ops[0].type == cs.CS_OP_REG else None
        if m in ("ebreak", "unimp"):                # trap: nothing falls through it
            return RET
        if m == "ret" or (m in ("jr", "jalr") and i.op_str in ("ra", "ra, 0", "zero, ra, 0", "zero, 0(ra)")):
            return RET
        if m == "j" or (m == "jal" and rd == "zero"):
            return JMP
        if m == "jal" or (m == "jalr" and rd != "zero"):
            return CALL
        if m in ("jr", "jalr"):
            return IJMP
        if m.startswith("b") and not m.startswith(("bclr", "bset", "binv", "bext", "brev")) \
                and ops and ops[-1].type == cs.CS_OP_IMM:   # (Zbs bit ops also start with b)
            return CJMP
        return OTHER

    def target(self, i):
        """Immediate branch/call target, or None for register-indirect."""
        if i.operands and i.operands[-1].type == cs.CS_OP_IMM:
            t = i.operands[-1].imm
            if self.name.startswith("riscv") and i.mnemonic.removeprefix("c.") in ("jalr", "jr"):
                return None                               # `jalr rd, rs, imm`: relative to rs, not pc
            if self.name.startswith("riscv") and self.kind(i) != OTHER:
                t = (i.address + t) & ((1 << self.bits) - 1)   # Capstone 5 RISC-V: PC-relative
            return t
        return None


def mem_operand(i):
    """(base_reg, disp) of a load/store's memory operand, or None. Capstone gives RISC-V
    compressed forms (`c.sdsp a7, 0x48(sp)`, `c.ld a0, 8(a5)`) as reg, imm, reg instead of a mem."""
    ops = i.operands
    for o in ops:
        if o.type == 3:
            return o.mem.base, o.mem.disp
    if len(ops) == 3 and ops[0].type == 1 and ops[1].type == 2 and ops[2].type == 1 \
            and i.mnemonic.startswith("c.") and i.mnemonic[2:3] in ("l", "s", "f"):
        return ops[2].reg, ops[1].imm
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
    if name in ("mips", "mipsel", "mips64", "mips64el"):
        bits = 64 if "64" in name else 32
        mode = (cs.CS_MODE_MIPS64 if bits == 64 else cs.CS_MODE_MIPS32) | \
            (cs.CS_MODE_LITTLE_ENDIAN if name.endswith("el") else cs.CS_MODE_BIG_ENDIAN)
        args = [f"a{n}" for n in range(8 if bits == 64 else 4)]   # n64 vs o32
        a = Arch(name, cs.CS_ARCH_MIPS, mode, bits, args, "v0", "sp", "fp", b"\0\0\0\0")
        a.delay_slot = True
        return a
    if name in ("riscv64", "riscv32", "riscv"):
        bits = 32 if name == "riscv32" else 64
        mode = (cs.CS_MODE_RISCV32 if bits == 32 else cs.CS_MODE_RISCV64) | cs.CS_MODE_RISCVC
        return Arch(f"riscv{bits}", cs.CS_ARCH_RISCV, mode, bits, [f"a{n}" for n in range(8)],
                    "a0", "sp", "s0", b"\x13\x00\x00\x00", [f"fa{n}" for n in range(8)], "fa0")
    raise ValueError(f"unsupported architecture: {name}")
