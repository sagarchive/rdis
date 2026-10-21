"""CPU backend for any processor Ghidra describes in SLEIGH, through `pypcode`.

Capstone covers six ISAs. pypcode bundles Ghidra's own processor specs (51 architectures, 194
language variants), so a `SleighArch` decodes with the spec's disassembler and classifies control flow
from the P-code that spec emits (RETURN / CALL / BRANCH / CBRANCH / ...), not from per-ISA mnemonic
tables. That gives function discovery, CFGs and the P-code IR for a CPU without writing a decoder.

    rdis fw.bin --loader raw --arch ppc --base 0x10000     # a short name below
    rdis fw.bin --loader raw --arch "sleigh:PowerPC:BE:32:VLE-32addr"   # any pypcode language id

Short names carry a calling convention (arguments / return / stack registers) so the decompiler can
name parameters; `sleigh:<id>` works for every language but has no ABI, so parameters are not
recovered. Control flow and delay slots come from the spec; data cross-references do not (yet).
"""
import re
import threading

from .arch import Arch, CALL, RET, JMP, CJMP, IJMP, OTHER

try:
    import pypcode
except ImportError:                       # optional dependency, like the IR front end
    pypcode = None

_CTX, _LOCK = {}, threading.RLock()       # a Context is not thread-safe; decode under one lock
_NON_ADDRESS = ("const", "unique", "register")
_PAD = 16

# SLEIGH's translate() segfaults on a delay-slot instruction with no bytes after it, and on a
# control transfer sitting in another one's delay slot (pypcode 4.0.1; found by tests/fuzz.py). Real
# code never has either, but a crafted file can. These are the mnemonics that transfer control and the
# no-op swapped into such a slot in the buffer handed to SLEIGH.
_DELAY = {
    "sparc": (re.compile(r"^(b|fb|cb)[a-z]*(,a)?$|^(call|jmpl|ret|retl|rett|return|done|retry|t[a-z]{1,4})$"),
              {"BE": bytes.fromhex("01000000"), "LE": bytes.fromhex("00000001")}),
    "superh": (re.compile(r"^(bra|bsr|braf|bsrf|jmp|jsr|rts|rte|bt|bf|bt/s|bf/s|trapa)$"),
               {"BE": bytes.fromhex("0009"), "LE": bytes.fromhex("0900")}),
    "pa-risc": (re.compile(r"^(b|be|bl|ble|bv|bve|bb|bvb|cmpb|addb|movb|blr|bve)[a-z,.]*$"),
                {"BE": bytes.fromhex("08000240"), "LE": bytes.fromhex("40020008")}),
    "mips": (re.compile(r"^(j|jal|jr|jalr|jalx|b|bal|b[a-z0-9]+)$"),
             {"BE": bytes.fromhex("00000000"), "LE": bytes.fromhex("00000000")}),
}


def _delay_rule(lang):
    if not lang:
        return None
    processor, endian, _, variant = (lang.split(":") + ["", "", "", ""])[:4]
    key = "superh" if processor.lower().startswith("superh") else processor.lower()
    rule = _DELAY.get(key)
    if rule is None or (key == "mips" and variant not in ("default", "R6")):
        return None
    return rule[0], rule[1][endian]


def _translates(ctx, raw, address, nop):
    try:
        ctx.translate(raw + nop * (_PAD // len(nop)), address)
        return True
    except Exception:
        return False


def _sanitize(ctx, rule, insns, code):
    """Buffer for translate(): each delay slot that is a control transfer or cannot be translated alone is
    replaced by a no-op, and padding follows so a final slot has bytes. The caller's own bytes and
    mnemonics are never altered."""
    transfer, nop = rule
    buf = bytearray(code)
    base = insns[0].addr.offset
    for before, slot in zip(insns, insns[1:]):
        if not transfer.match(before.mnem.lower()):
            continue
        at = slot.addr.offset - base
        if transfer.match(slot.mnem.lower()) or not _translates(ctx, bytes(buf[at:at + slot.length]),
                                                                slot.addr.offset, nop):
            buf[at:at + slot.length] = nop[:slot.length].ljust(slot.length, nop[-1:])
    return bytes(buf) + nop * (_PAD // len(nop))


def safe_translate(ctx, lang, code, addr, insns=None, **kwargs):
    """ctx.translate() that cannot abort the process on delay-slot languages (pypcode 4.0.1 segfaults on a
    missing, control-transfer or untranslatable delay slot; tests/fuzz.py found all three). Languages
    without delay slots go straight through."""
    rule = _delay_rule(lang)
    if rule is None:
        return ctx.translate(code, addr, **kwargs)
    if insns is None:
        insns = list(ctx.disassemble(code, addr, max_instructions=3).instructions)
    if not insns:
        return ctx.translate(code, addr, **kwargs)
    span = sum(i.length for i in insns)
    return ctx.translate(_sanitize(ctx, rule, insns, code[:span]), addr, **kwargs)


def _regs(prefix, lo, hi):
    return [f"{prefix}{n}" for n in range(lo, hi + 1)]


# short name -> language id, address bits, argument regs, return reg, sp, fp, fp args, fp return, delay slot
# (register names are checked against the spec by tests/test_rdis.py::test_sleigh_specs)
_SPECS = {
    "ppc":      ("PowerPC:BE:32:default", 32, _regs("r", 3, 10), "r3", "r1", "r31", _regs("f", 1, 8), "f1", False),
    "ppcle":    ("PowerPC:LE:32:default", 32, _regs("r", 3, 10), "r3", "r1", "r31", _regs("f", 1, 8), "f1", False),
    "ppc64":    ("PowerPC:BE:64:default", 64, _regs("r", 3, 10), "r3", "r1", "r31", _regs("f", 1, 8), "f1", False),
    "ppc64le":  ("PowerPC:LE:64:default", 64, _regs("r", 3, 10), "r3", "r1", "r31", _regs("f", 1, 8), "f1", False),
    "sparc":    ("sparc:BE:32:default", 32, _regs("o", 0, 5), "o0", "sp", "fp", [], None, True),
    "sparc64":  ("sparc:BE:64:default", 64, _regs("o", 0, 5), "o0", "sp", "fp", [], None, True),
    "m68k":     ("68000:BE:32:default", 32, [], "D0", "SP", "A6", [], None, False),
    "avr8":     ("avr8:LE:16:default", 16, ["R24", "R22", "R20", "R18"], "R24", "SP", "Y", [], None, False),
    "xtensa":   ("Xtensa:LE:32:default", 32, _regs("a", 2, 7), "a2", "a1", "a15", [], None, False),
    "xtensabe": ("Xtensa:BE:32:default", 32, _regs("a", 2, 7), "a2", "a1", "a15", [], None, False),
    "msp430":   ("TI_MSP430:LE:16:default", 16, _regs("R", 12, 15), "R12", "SP", "R4", [], None, False),
    "sh4":      ("SuperH4:BE:32:default", 32, _regs("r", 4, 7), "r0", "r15", "r14", [], None, True),
    "sh4le":    ("SuperH4:LE:32:default", 32, _regs("r", 4, 7), "r0", "r15", "r14", [], None, True),
    "loongarch64": ("Loongarch:LE:64:lp64d", 64, _regs("a", 0, 7), "a0", "sp", "fp", _regs("fa", 0, 7), "fa0", False),
    "ebpf":     ("eBPF:LE:64:default", 64, _regs("R", 1, 5), "R0", "R10", "R10", [], None, False),
    "ebpfbe":   ("eBPF:BE:64:default", 64, _regs("R", 1, 5), "R0", "R10", "R10", [], None, False),
    "tricore":  ("tricore:LE:32:default", 32, _regs("d", 4, 7), "d2", "a10", "a14", [], None, False),
    "z80":      ("z80:LE:16:default", 16, [], "A", "SP", "IY", [], None, False),
    "6502":     ("6502:LE:16:default", 16, [], "A", "SP", "X", [], None, False),
}


class Insn:
    """One decoded instruction, shaped like the Capstone object the rest of rdis reads."""
    __slots__ = ("address", "size", "bytes", "mnemonic", "op_str", "_rdis_kind", "_target", "_slot")
    operands = ()          # no per-operand model: flow facts come from P-code
    groups = ()
    id = 0

    def __init__(self, address, size, raw, mnemonic, op_str, kind, target, slot=False):
        self.address, self.size, self.bytes = address, size, raw
        self.mnemonic, self.op_str = mnemonic, op_str
        self._rdis_kind, self._target, self._slot = kind, target, slot

    def reg_name(self, _reg):
        return ""


def _tracked(lang):
    """Registers the processor spec pins to a constant for decompilation: {lowercase name: value}.
    SPARC pins DECOMPILE_MODE=1, which switches off the register-window spill code in `save`."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(pypcode.ArchLanguage.from_id(lang).pspec_path).getroot()
        return {s.get("name").lower(): int(s.get("val"), 0)
                for t in root.iter("tracked_set") for s in t.iter("set")}
    except Exception:
        return {}


def _classify(control, nxt):
    """(kind, target) of one instruction from its control P-code ops [(opcode, space, offset)].

    Op order and shape follow Ghidra's convention: RETURN ends the function; CALL/CALLIND call;
    BRANCH is a direct jump, CBRANCH a conditional one, BRANCHIND an indirect one. A branch whose
    target is in `const` space stays inside the instruction (e.g. a predicated move), so it is not
    program control flow. A CBRANCH that only skips to the next instruction guards a RETURN or CALL
    (`beqlr`, a conditional call): the walk must continue past it, so it is not a terminator.
    """
    call = ret = indirect = False
    call_t = jump_t = cond_t = None
    guarded = False
    for op, space, off in control:
        real = space not in _NON_ADDRESS
        if op == "CALL":
            call, call_t = True, (off if real else None)
        elif op == "CALLIND":
            call = True
        elif op == "RETURN":
            ret = True
        elif op == "BRANCHIND":
            indirect = True
        elif op == "BRANCH" and real:
            jump_t = off
        elif op == "CBRANCH" and real:
            if off == nxt:
                guarded = True
            else:
                cond_t = off
    if call:
        return CALL, call_t
    if ret:
        return (OTHER, None) if guarded else (RET, None)     # conditional return: falls through
    if indirect:
        return IJMP, None
    if cond_t is not None:
        return CJMP, cond_t
    if jump_t is not None:
        return JMP, jump_t
    return OTHER, None


class SleighArch(Arch):
    """Arch backed by a SLEIGH language. Subclasses Arch only so `isinstance` checks keep working."""

    def __init__(self, name, lang, bits, args, ret, sp, fp, fargs=(), fret=None, delay_slot=False):
        if pypcode is None:
            raise ValueError(f"architecture {name!r} needs pypcode (pip install pypcode)")
        self.name, self.lang, self.bits = name, lang, bits
        self.args, self.ret, self.sp, self.fp, self.nop = list(args), ret, sp, fp, b""
        self.fargs, self.fret, self.delay_slot = list(fargs), fret, delay_slot
        self.md = None
        self._context()                                   # fail now on a bad language id, not mid-analysis
        self.tracked = _tracked(lang)

    def _context(self):
        with _LOCK:
            c = _CTX.get(self.lang)
            if c is None:
                try:
                    c = _CTX[self.lang] = pypcode.Context(self.lang)
                except Exception as e:
                    raise ValueError(f"unknown SLEIGH language {self.lang!r}") from e
            return c

    def decode_run(self, code, addr, thumb=False):
        """Instructions decoded back to back from `code` at `addr`, stopping at the first bad byte."""
        if not code:
            return []
        with _LOCK:
            ctx = self._context()
            try:
                insns = list(ctx.disassemble(code, addr).instructions)
                if not insns:
                    return []
                span = sum(i.length for i in insns)
                ops = safe_translate(ctx, self.lang, code[:span], addr, insns=insns).ops
            except Exception:
                return []
            control, key, slotted = {}, None, set()
            for op in ops:
                name = op.opcode.name
                if name == "IMARK":
                    if int(op.inputs[0].offset) >= addr + span:
                        break                              # padding, not input
                    key = int(op.inputs[0].offset)        # a delay-slot bundle starts with the branch
                    control.setdefault(key, [])
                    if len(op.inputs) > 1:                # ...and names the slot instruction(s) too
                        slotted.add(key)
                elif key is not None and name in ("CALL", "CALLIND", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"):
                    v = op.inputs[0]
                    control[key].append((name, v.space.name, int(v.offset)))
        out, base = [], insns[0].addr.offset
        for i in insns:
            a, n = int(i.addr.offset), i.length
            kind, target = _classify(control.get(a, ()), a + n)
            out.append(Insn(a, n, bytes(code[a - base:a - base + n]), i.mnem.lower(),
                            i.body, kind, target, a in slotted and kind in (JMP, CJMP, IJMP, RET)))
        return out

    def decode(self, code, addr, thumb=False):
        return next(iter(self.decode_run(code, addr)), None)

    def kind(self, i):
        return i._rdis_kind

    def slot(self, i, k):
        return i._slot                                    # from the spec: SH `bt` has none, `bt/s` has one

    def target(self, i):
        return i._target

    def data_refs(self, i, regs):
        return []                                          # no operand model: data xrefs are not recovered

    def is_blx(self, i):
        return False


def make(name):
    """SleighArch for a short name or `sleigh:<language id>`; None if `name` is neither."""
    if name in _SPECS:
        lang, bits, args, ret, sp, fp, fargs, fret, delay = _SPECS[name]
        return SleighArch(name, lang, bits, args, ret, sp, fp, fargs, fret, delay)
    if name.startswith("sleigh:"):
        lang = name[len("sleigh:"):]
        if pypcode is None:
            return None
        lg = pypcode.ArchLanguage.from_id(lang)          # None for an unknown id
        if lg is None:
            raise ValueError(f"unknown SLEIGH language {lang!r} (rdis --list-archs shows the valid ids)")
        return SleighArch(name, lang, int(lg.size), [], "", "", "", [], None, False)
    return None


def languages():
    """Every language id pypcode bundles (for `--arch sleigh:<id>` and docs)."""
    if pypcode is None:
        return []
    return sorted(l.id for a in pypcode.Arch.enumerate() for l in a.languages)
