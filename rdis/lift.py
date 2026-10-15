"""Per-block micro-lifter: symbolic execution over registers and stack -> C-like statements.

This is intentionally a pattern lifter, not a full SSA/type-recovery pipeline. It tracks a value
per register and per stack slot as a C expression string, folds moves and arithmetic, recognizes
calls and their arguments from the ABI, and renders comparisons as conditions. Anything it does not
model is emitted verbatim as `/* mnemonic op */` so no information is silently lost.
"""
import re
from collections import Counter

import capstone as cs
from capstone import x86, arm64 as a64

from .arch import CALL, RET, CJMP, JMP, IJMP
from . import lift_simd, neon, typelib


def cstr_lit(s, limit=60):
    """Render `s` as a valid C string literal: escape \\ and " and control chars, then truncate."""
    out = []
    for ch in s[:limit]:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("\\x%02x" % (ord(ch) & 0xFF))
    return '"' + "".join(out) + ('"' if len(s) <= limit else '..."')


# condition-code -> C operator, per the flags a preceding compare set (signed view by default)
_X86_CC = {"e": "==", "ne": "!=", "g": ">", "ge": ">=", "l": "<", "le": "<=",
           "a": ">", "ae": ">=", "b": "<", "be": "<=", "s": "< 0", "ns": ">= 0",
           "z": "==", "nz": "!="}
_ARM_CC = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<=",
           "hi": ">", "hs": ">=", "lo": "<", "ls": "<=", "mi": "< 0", "pl": ">= 0"}
# condition codes whose comparison is unsigned (ja/jb..., b.hi/b.lo...): operands need a uint cast
_UNSIGNED_CC = {"a", "ae", "b", "be", "hi", "hs", "lo", "ls"}

# flag-setting arithmetic -> the compare it is equivalent to for the following branch
def cname(name):
    """A C identifier for a symbol: `-[Cls sel:with:]` -> `Cls_sel_with_`, `f$x:y:` -> `f$x_y_`."""
    if not name or re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return name
    n = re.sub(r"^[-+]\[(\S+) (.*)\]$", r"\1_\2", name or "")
    n = re.sub(r"[^\w$]", "_", n)
    return n if re.match(r"[A-Za-z_$]", n) else "_" + n


_FLAG_ARITH = {"subs": "cmp", "adds": "cmn", "ands": "tst", "bics": "tst"}

# x86 sub-register -> 64-bit canonical name (built once, not per call). Every 8/16/32-bit view
# folds to its parent so a value written via `al` and read via `rax` is the same variable.
_X86_CANON = {}
for _r in ("a", "b", "c", "d"):
    _X86_CANON.update({f"e{_r}x": f"r{_r}x", f"{_r}x": f"r{_r}x", f"{_r}l": f"r{_r}x", f"{_r}h": f"r{_r}x"})
for _r in ("si", "di", "bp", "sp"):
    _X86_CANON.update({f"e{_r}": f"r{_r}", _r: f"r{_r}", f"{_r}l": f"r{_r}"})
for _n in range(8, 16):
    _X86_CANON.update({f"r{_n}d": f"r{_n}", f"r{_n}w": f"r{_n}", f"r{_n}b": f"r{_n}"})
for _n in range(32):
    _X86_CANON.update({f"ymm{_n}": f"xmm{_n}", f"zmm{_n}": f"xmm{_n}"})
_ARM_FP = re.compile(r"[bhsdqv](\d{1,2})")  # every view of SIMD/FP register N (b/h/s/d/q/v) is vN


class Lifter:
    def __init__(self, prog):
        self.prog, self.arch = prog, prog.arch
        self.x86 = self.arch.name.startswith("x86")
        self._locals = {}   # stack offset -> C name
        self._argcount = 0
        self._fargcount, self._ffloat = 0, set()  # FP/vector args, and which of them are float
        self._ret_fp = False
        self._ptrvars = {}  # register -> pointer type, for single-definition copies of pointer args
        self._entry = {}    # incoming variable names for the block being lifted
        self._temps, self._tmpn, self._out = set(), 0, []
        self._last_regs = {}
        self._rettype = "int64_t"
        self._argtypes = {}     # arg register -> C type (filled by type inference)
        self._localtype = {}    # stack offset -> C type
        self._localname = {}    # stack offset -> C name
        self._objc_self = None  # name of this function (set for ObjC methods: arg0=id, arg1=SEL)

    _WIDTH_T = {1: "char", 2: "short", 4: "int", 8: "int64_t"}

    def _argtype(self, reg):
        return self._argtypes.get(reg, "int64_t")

    # -- public ------------------------------------------------------------
    MATERIALIZE = 56  # expr longer than this gets pinned to a named temp instead of re-inlined

    def signature(self, func, name):
        self._func, self._block_cmp = func, {}
        self._pages = self._hoisted_pages(func)
        self._scan_args(func)
        self._objc_self = name if name.startswith(("-[", "+[")) else None
        self._infer_types(func)
        self._temps, self._tmpn = set(), 0  # reset per function
        params = [f"{self._argtype(a)} {a}" for a in self._args()]
        params += [f"{'float' if r in self._ffloat else 'double'} {r}" for r in self._fargs()]
        return f"{self._rettype} {name}({', '.join(params) or 'void'})"

    def _fargs(self):
        return self.arch.fargs[:self._fargcount]

    def locals_block(self):
        out = []
        for n in sorted(self._temps):
            t = "v128" if n in getattr(self, "_vecnames", ()) else getattr(self, "_temptype", {}).get(n, "int64_t")
            out.append(f"{t} {n};")
        for off, name in sorted(self._localname.items()):
            t = self._localtype.get(off, "int64_t")
            out.append(f"{t}{'' if t.endswith('*') else ' '}{name};")
        return out

    def _writeback(self, i):
        return bool(getattr(i, "writeback", False))

    @staticmethod
    def _is_struct(fields):
        """Struct, not array: mixed field widths, a gap, or a pointer back to itself. Same-width
        elements packed back to back (s[0], s[1], ...) read as an array."""
        if len(fields) < 2:
            return False
        widths = {w for w, _, _, _ in fields.values()}
        if len(widths) > 1 or any(f[3] for f in fields.values()):
            return True
        w = widths.pop()
        offs = sorted(fields)
        if w == 1:   # a byte run (s[0], s[1], ...) is a char buffer unless it has holes
            return any(b - a != 1 for a, b in zip(offs, offs[1:]))
        return True

    def _struct(self, func, arg, fields):
        """Declare `struct s_<func>_<arg>` from the field accesses: typed by width, signedness and
        FP use; a pointer-sized field loaded back into the same argument (p = p->next) points to
        the struct itself."""
        name = f"s_{func.addr:x}_{self._canon(arg)}"
        out = {}
        for disp, (w, sgn, fp, selfp) in sorted(fields.items()):
            if selfp:
                t = f"struct {name} *"
            elif fp and w in (4, 8):
                t = "float" if w == 4 else "double"
            else:
                t = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(w, "int64_t")
                t = t if sgn else "u" + t
            out[disp] = (t, w)
        self._structs[name] = out
        return name

    def preamble(self, counts):
        """Vector type/helper definitions, then the structs recovered for pointer arguments."""
        out = neon.decls(self, counts)
        for name, flds in sorted(getattr(self, "_structs", {}).items()):
            lines, pos = [f"struct {name} {{   /* recovered from field accesses */"], 0
            for disp, (t, w) in sorted(flds.items()):
                if disp < pos:
                    continue                    # overlapping access: keep the first field
                if disp > pos:
                    lines.append(f"    uint8_t _pad_{pos:x}[{disp - pos}];")
                lines.append(f"    {t}{'' if t.endswith('*') else ' '}field_{disp:x};   /* +{disp:#x} */")
                pos = disp + w
            out += lines + ["};", ""]
        return out

    # -- type / variable inference ----------------------------------------
    def _infer_types(self, func):
        """Classify argument/local/return types from how values are accessed (lightweight)."""
        self._localtype, self._localname = {}, {}
        self._structs = {}
        args = {self._canon(a): a for a in self._args()}
        argptr, argwidth, localwidth, localptr = {}, {}, {}, set()
        derived = {}  # register -> argument it was computed from (p + i*4, p + 16, ...)
        argfp = {}    # pointer arg -> "float"/"double" when its elements go through FP registers
        fields, arrayish = {}, set()   # struct recovery: arg -> {disp: (width, signed, fp, selfptr)}
        proto_ptr = {}                 # arg -> pointer type from a system prototype it is passed to
        copies, defcount = {}, Counter()  # register copies of args (mov x8, x0) and write counts
        slot_root = {}  # stack slot displacement -> argument spilled there (-O0 code)
        reg_t = x86.X86_OP_REG if self.x86 else a64.ARM64_OP_REG
        mem_t = x86.X86_OP_MEM if self.x86 else a64.ARM64_OP_MEM
        # return register's last writer, tracked in program order; a value-producing write that
        # reaches a `ret` means the function returns something, a leftover call result means void.
        retsrc, ret_is_value = None, False
        fsrc, fret_value, fret_single = None, False, False   # same tracking for the FP return reg
        rread = fread = False    # was the return register read after its last write?
        tail_ptr = None          # pointer type returned through a tail call to a known API
        fret = self.arch.fret
        ipos = rpos = fpos = 0   # program-order position of the last write to each return reg
        int_votes = fp_votes = 0  # per `ret`: which return register was written most recently
        unw_in = getattr(self, "_unw_in", {})
        for b in func.blocks.values():
            still_arg = set(unw_in.get(b.addr, args))       # registers that may still hold the argument
            for i in b.insns:
                ipos += 1
                k = self.arch.kind(i)
                if k == RET:
                    ret_is_value |= retsrc == "value"
                    fret_value |= fsrc == "value"
                    if retsrc == "value" and fsrc == "value" and rread != fread:
                        # both written: the result is the one not read again before returning
                        if rread:
                            fp_votes += 1
                        else:
                            int_votes += 1
                    elif retsrc == "value" and (fsrc != "value" or rpos >= fpos):
                        int_votes += 1
                    elif fsrc == "value":
                        fp_votes += 1
                tgt = self.prog.call_target(i, {}) if k == JMP else None
                tail = tgt is not None and (tgt in self.prog.functions or tgt in self.prog.image.imports)
                if k == CALL or tail:
                    ct = tgt if tail else self.prog.call_target(i, {})
                    pr = typelib.proto(self.prog.display(ct)) if ct is not None and ct not in self.prog.functions else None
                    # `b _strdup`: we return what it returns. Only pointer/float results count:
                    # void functions routinely tail-call printf/puts and drop the int.
                    if tail and pr and (pr[0].endswith("*") or pr[0] in ("double", "float")):
                        if pr[0] in ("double", "float"):
                            fret_value, fp_votes, fret_single = True, fp_votes + 1, pr[0] == "float"
                        else:
                            ret_is_value, int_votes = True, int_votes + 1
                            if pr[0].endswith("*"):
                                tail_ptr = pr[0]
                    for n_, pt in enumerate(pr[1] if pr else ()):
                        r_ = self._canon(self.arch.args[n_]) if n_ < len(self.arch.args) else None
                        if pt.endswith("*") and r_ in args and r_ in still_arg:
                            proto_ptr.setdefault(r_, pt)
                    retsrc = fsrc = "call"   # a (tail) call clobbers/produces the return regs
                else:
                    rd, wr = self._rw(i)
                    rread |= self._canon(self.arch.ret) in rd and retsrc == "value"
                    fread |= bool(fret) and self._canon(fret) in rd and fsrc == "value"
                    if self._canon(self.arch.ret) in wr:
                        retsrc, rpos, rread = "value", ipos, False
                    if fret and self._canon(fret) in wr:
                        fpos, fread = ipos, False
                        # only a scalar write is a float result; a vector op leaves a temp in v0
                        fsrc = "value" if self._scalar_fp(i) else "vector"
                        fret_single = self._single(i, self._canon(fret))
                w = self._acc_width(i)
                # lea computes an address; multi-byte NOPs and prefetches name memory they never access
                if not i.mnemonic.startswith(("lea", "nop", "prefetch", "prfm", "prfum", "endbr")):
                    fpdata = self._fp_access(i)
                    for op in i.operands:
                        if op.type != mem_t:
                            continue
                        base = self._canon(i.reg_name(op.mem.base)) if op.mem.base else None
                        root = base if base in args and base in still_arg else derived.get(base)
                        disp = op.mem.disp
                        if root in args:                 # *(arg + k) or *(arg-derived): a pointer
                            argptr[root] = True
                            argwidth[root] = min(argwidth.get(root, 8), w)
                            if fpdata and w in (4, 8):   # element loaded into an FP register
                                argfp[root] = "float" if w == 4 else "double"
                            if base != root or op.mem.index or self._writeback(i):
                                arrayish.add(root)       # indexed / pointer-bumped: an array
                            else:
                                f = fields.setdefault(root, {})
                                dst0 = i.operands[0]
                                selfp = (w == 8 and dst0.type == reg_t and not fpdata and
                                         self._canon(i.reg_name(dst0.reg)) == root)
                                sgn = not i.mnemonic.startswith(("ldrb", "ldrh", "strb", "strh", "movzx",
                                                                 "ldurb", "ldurh", "sturb", "sturh"))
                                prev = f.get(disp)
                                f[disp] = (max(w, prev[0]) if prev else w, sgn and (prev[1] if prev else True),
                                           fpdata or bool(prev and prev[2]), selfp or bool(prev and prev[3]))
                        elif base in (self.arch.sp, self.arch.fp, "rbp", "rsp", "sp", "x29"):
                            localwidth[disp] = max(localwidth.get(disp, 0), w)
                still_arg -= self._rw(i)[1]
                self._track_derived(i, args, derived, reg_t, mem_t)
                self._track_spill(i, args, derived, slot_root, reg_t, mem_t)
                for r in self._rw(i)[1]:
                    defcount[r] += 1
                ops_ = i.operands
                if i.mnemonic == "mov" and len(ops_) == 2 and ops_[0].type == reg_t and ops_[1].type == reg_t:
                    src = self._canon(i.reg_name(ops_[1].reg))
                    root = src if src in args else copies.get(src)
                    if root:
                        copies[self._canon(i.reg_name(ops_[0].reg))] = root
                # lea/add of (sp+disp) into a register: the local's address is taken
                if i.mnemonic in ("lea", "add") and i.operands and i.operands[0].type == reg_t:
                    for op in i.operands[1:]:
                        if op.type == mem_t and op.mem.base and \
                                self._canon(i.reg_name(op.mem.base)) in (self.arch.sp, self.arch.fp):
                            localptr.add(op.mem.disp)
        # arguments
        for c, reg in args.items():
            if self._objc_self and reg == self.arch.args[0]:
                self._argtypes[reg] = "id"
            elif self._objc_self and reg == self.arch.args[1]:
                self._argtypes[reg] = "SEL"
            elif c in proto_ptr and (not argptr.get(c) or argwidth.get(c, 8) == 1):
                self._argtypes[reg] = proto_ptr[c]     # typed by the API it is passed to
            elif argptr.get(c) and c not in arrayish and self._is_struct(fields.get(c, {})):
                self._argtypes[reg] = f"struct {self._struct(func, c, fields[c])} *"
            elif argptr.get(c):
                pointee = argfp.get(c) or self._WIDTH_T.get(argwidth.get(c, 8), "void")
                self._argtypes[reg] = f"{pointee} *"
            else:
                self._argtypes[reg] = "int64_t"
        # a register holding a copy of a pointer argument, defined exactly once, shares its type
        self._ptrvars = {dst: self._argtypes[args[root]] for dst, root in copies.items()
                         if defcount[dst] == 1 and dst not in args and self._argtypes.get(args[root], "").endswith("*")}
        # a RET at the very end with no prior terminator also observes the last writer
        ret_is_value |= retsrc == "value"
        fret_value |= fsrc == "value"
        if not int_votes and not fp_votes:      # function falls off the end without a `ret` insn
            int_votes, fp_votes = int(retsrc == "value"), int(fsrc == "value")
        # strongest evidence: how callers use the result right after the call
        use = self._caller_use(func.addr)
        if use == "fp" and fsrc in ("value", "vector"):
            fret_value, fp_votes, int_votes = True, 1, 0
        elif use == "int" and ret_is_value:
            fp_votes = 0
        elif use == "none":
            # every caller ignores both return registers (checked across the CFG): no result
            ret_is_value = fret_value = False
            int_votes = fp_votes = 0
        # when both registers hold values, the one written last before the returns is the result
        self._ret_fp = fret_value and (not ret_is_value or fp_votes > int_votes)
        ret_is_value = ret_is_value and not self._ret_fp
        self._rettype = (tail_ptr or "int64_t") if ret_is_value else (("float" if fret_single else "double")
                                                                      if self._ret_fp else "void")
        self._ret_void = not (ret_is_value or self._ret_fp)
        # stack locals: name + type by width / address-taken
        for disp, w in localwidth.items():
            self._localname[disp] = f"local_{abs(disp):x}"
            self._localtype[disp] = self._WIDTH_T.get(w, "int64_t")
        for disp, root in slot_root.items():  # a spill slot of a pointer argument is that pointer
            t = self._argtypes.get(args.get(root, ""), "")
            if t.endswith("*") and disp in self._localname:
                self._localtype[disp] = t
        for disp in localptr:
            self._localname.setdefault(disp, f"local_{abs(disp):x}")
            self._localtype[disp] = self._localtype.get(disp, "int64_t")

    _DERIVE = ("mov", "add", "sub", "lea", "adds", "subs", "orr")

    def _track_derived(self, i, args, derived, reg_t, mem_t):
        """Pointer arithmetic: a register computed from an argument (or from something derived
        from one) by mov/add/sub/lea carries that argument as its root; other writes clear it."""
        ops = i.operands
        if not ops or ops[0].type != reg_t:
            return
        if not self.x86 and i.mnemonic.startswith(("st", "cmp", "cmn", "tst", "cb", "tb")):
            return  # operand 0 is read, not written (str Rt, [mem]; cmp; cbz) -- keep its root
        dst = self._canon(i.reg_name(ops[0].reg))
        root = None
        if i.mnemonic in self._DERIVE:
            # For arithmetic address formation, only the first source operand is the base.
            # Treating *any* argument used by an ADD as the root incorrectly marks integer
            # indices as pointers, e.g. AArch64 jump-table address + switch-key*entry-size.
            # ORR with the zero register is the common register-copy alias and uses its other input.
            candidates = ops[1:2]
            if i.mnemonic == "orr" and len(ops) > 2:
                first = ops[1]
                first_name = self._canon(i.reg_name(first.reg)) if first.type == reg_t else None
                if first_name in ("xzr", "wzr", "zero", "0"):
                    candidates = ops[2:3]
            elif i.mnemonic.startswith("add") and len(ops) > 2:
                first = ops[1]
                first_name = self._canon(i.reg_name(first.reg)) if first.type == reg_t else None
                if first_name in ("xzr", "wzr", "zero", "0"):
                    candidates = ops[2:3]
            for op in candidates:
                r = None
                if op.type == reg_t:
                    r = self._canon(i.reg_name(op.reg))
                elif op.type == mem_t and i.mnemonic == "lea" and op.mem.base:
                    r = self._canon(i.reg_name(op.mem.base))
                if r in args:
                    root = r
                elif r in derived:
                    root = derived[r]
                if root:
                    break
        if root and dst not in args:
            derived[dst] = root
        else:
            derived.pop(dst, None)

    _STORE = ("str", "stur", "mov", "movq")
    _LOAD = ("ldr", "ldur", "mov", "movq")

    def _track_spill(self, i, args, derived, slot_root, reg_t, mem_t):
        """-O0 code spills arguments to the stack and reloads them before each use. Follow the
        pointer through the slot so `ldr x8, [sp, #0x18]` after `str x0, [sp, #0x18]` is x0."""
        ops = i.operands
        if len(ops) != 2:
            return
        frame = (self.arch.sp, self.arch.fp, "rbp", "rsp", "sp", "x29")
        m = i.mnemonic
        if self.x86:
            store = m in self._STORE and ops[0].type == mem_t and ops[1].type == reg_t
            load = m in self._LOAD and ops[0].type == reg_t and ops[1].type == mem_t
            mem, reg = (ops[0], ops[1]) if store else (ops[1], ops[0])
        else:
            store = m in ("str", "stur") and ops[0].type == reg_t and ops[1].type == mem_t
            load = m in ("ldr", "ldur") and ops[0].type == reg_t and ops[1].type == mem_t
            reg, mem = ops[0], ops[1]
        if not (store or load) or not mem.mem.base or mem.mem.index:
            return
        if self._canon(i.reg_name(mem.mem.base)) not in frame:
            return
        r = self._canon(i.reg_name(reg.reg))
        if store:
            root = r if r in args else derived.get(r)
            if root:
                slot_root[mem.mem.disp] = root
            else:
                slot_root.pop(mem.mem.disp, None)
        elif mem.mem.disp in slot_root and r not in args:
            derived[r] = slot_root[mem.mem.disp]

    def _acc_width(self, i):
        """Byte width of a memory access, from the mnemonic (arm) or operand size (x86)."""
        m = i.mnemonic
        if self.x86:
            for op in i.operands:
                if op.type == x86.X86_OP_MEM and op.size:
                    return op.size
            return 8
        if m.startswith(("ldrb", "strb", "sturb", "ldrsb")):
            return 1
        if m.startswith(("ldrh", "strh", "sturh", "ldrsh")):
            return 2
        if m.startswith("ldrsw"):
            return 4
        if m.startswith(("ldr", "str", "ldur", "stur", "ldp", "stp")) and i.operands and \
                i.operands[0].type == a64.ARM64_OP_REG:
            nm = i.reg_name(i.operands[0].reg) or "x"
            return {"w": 4, "s": 4, "b": 1, "h": 2, "q": 16}.get(nm[0], 8)  # x/d -> 8
        return 8

    live_out = None      # {block addr: registers live after it}, set by the Decompiler (liveness)
    entry_names = None   # {block: {reg: variable}} incoming SSA-web variable names
    def_names = None     # {block: {reg: variable}} variables this block's live-out values go to

    def _ent(self, r):
        """Variable holding register `r` on entry to the block being lifted."""
        return self._entry.get(r, r)

    def _changed(self, r, regs):
        """Was register `r` given a new value inside the current block?"""
        return r in regs and regs[r] != self._entry.get(r, r)

    def block(self, b):
        self._entry = dict(self.entry_names.get(b.addr, {})) if self.entry_names else {}
        regs, out = dict(self._entry), []
        if getattr(self, "_pages", None) and b.addr in self._pages:
            regs["__page__"] = dict(self._pages[b.addr])   # adrp pages hoisted out of this block
        inh = self._inherited_cmp(b)
        if inh is not None:
            regs["__cmp__"] = inh        # flags set in the predecessor (csel / b.cc reuse them)
        self._out = out
        term = b.insns[-1]
        tk = self.arch.kind(term)
        # the last instruction is control flow (ret/branch); the structurer owns it, so skip it
        insns = b.insns[:-1] if tk in (RET, CJMP, JMP, IJMP) else b.insns
        if b.delay is not None:   # MIPS delay slot: runs before the branch transfers control
            insns = insns + [b.delay]
        for i in insns:
            try:
                s = self._step(i, regs)
            except Exception:
                # best-effort lifter: an operand form it doesn't model yet (e.g. some arm32 shift
                # encodings) degrades to the raw instruction instead of aborting the decompilation.
                s = f"__asm(\"{i.mnemonic} {i.op_str}\");"
            if s:
                out.append(s)
        self._last_regs = regs
        if tk == CJMP:
            regs["__cond__"] = self._cond_from(term, regs.get("__cmp__"))
        self.__dict__.setdefault("_block_cmp", {})[b.addr] = regs.get("__cmp__")
        if self.live_out is not None and tk != RET and not self._tail_target(b):
            self._materialize(b, regs, out)
        self._last_regs = regs
        return out

    def _inherited_cmp(self, b):
        """The flag-setter a block reuses from its single predecessor, if still valid here: its
        operands must not read a variable the predecessor reassigned on its way out (that value
        would be the *new* one, e.g. `subs x9, x9, #1` then `x9_1 = x9_1 - 1`)."""
        func = getattr(self, "_func", None)
        if func is None:
            return None
        preds = [a for a, q in func.blocks.items() if b.addr in q.succs]
        bc = self.__dict__.get("_block_cmp", {})
        if not preds or any(q not in bc for q in preds):
            return None                      # a predecessor not lifted yet (loop back edge)
        if any(bc[q] is None for q in preds) or any(bc[q] != bc[preds[0]] for q in preds[1:]):
            return None                      # the paths disagree on (or lack) the flags
        cmp = bc[preds[0]]
        text = " ".join(a for a in cmp[1] if isinstance(a, str))
        for q in preds:
            wrote = self.__dict__.get("_block_wrote", {}).get(q, set())
            if any(re.search(rf"(?<![\w.]){re.escape(w)}\b", text) for w in wrote):
                return None
        return cmp

    def _materialize(self, b, regs, out):
        """Store values live out of `b` into their SSA-web variables (values crossing block edges).

        Every expression is in terms of the block's incoming variables, so this is a parallel
        assignment: stores are ordered so no variable is overwritten before an expression that
        reads its old value; only a true cycle needs temps."""
        live = self.live_out.get(b.addr, ())
        dnames = self.def_names.get(b.addr, {}) if self.def_names else {}
        dst = {r: dnames.get(r, self._ent(r)) for r in live}
        pending = [(r, regs[r]) for r in sorted(live) if r in regs and isinstance(regs[r], str)
                   and regs[r] != dst[r]]
        if not pending:
            return
        written = {dst[r] for r, _ in pending}
        ident = re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, written)) + r")\b")
        # the branch condition was rendered against incoming values. Where it tests a value we are
        # about to store, name the variable instead; if it still needs an *old* value of a
        # variable being overwritten, evaluate the test into a temp before the stores.
        cond0 = regs.get("__cond__")
        if cond0 is not None:
            cond = cond0
            for r, e in sorted(pending, key=lambda p: -len(p[1])):
                if not self._atomic(e) and e in cond:
                    cond = cond.replace(e, f"\0{dst[r]}\0")
            if ident.search(re.sub(r"\0\w+\0", "", cond)):
                regs["__cond__"] = self._pin(cond0)
            else:
                cond = re.sub(r"\0(\w+)\0", r"\1", cond)
                # `(r8) != 0` -> `r8 != 0`: drop parens left around a lone substituted variable
                regs["__cond__"] = re.sub(r"\((\w+)\)(?=\s|\)|$)", r"\1", cond)
        expr = dict(pending)
        # r must be evaluated before s overwrites a variable that r's expression reads
        reads = {r: {s for s, _ in pending if s != r and
                     re.search(rf"(?<![\w.]){re.escape(dst[s])}\b", expr[r])} for r, _ in pending}
        order, done = [], set()
        while len(order) < len(pending):
            ready = [r for r, _ in pending if r not in done and
                     not any(r in reads[o] for o in expr if o not in done and o != r)]
            if not ready:  # cycle: stage the remaining values through temps, then store them
                rest = [r for r, _ in pending if r not in done]
                staged = {r: self._pin(expr[r]) for r in rest}
                order += [(r, staged[r]) for r in rest]
                break
            for r in ready:
                order.append((r, expr[r]))
                done.add(r)
        hint = getattr(self.prog, "_vec_hint", {}).get(getattr(self, "_func", None) and self._func.addr, ())
        kinds = self.__dict__.setdefault("_assignkinds", {})
        self.__dict__.setdefault("_block_wrote", {})[b.addr] = {dst[r] for r, _ in order}
        for r, val in order:
            vec = neon.is_vec(self, val)
            if not vec and dst[r] in hint:          # scalar write into a vector web: lane 0, rest 0
                t = getattr(self, "_lastview", {}).get(r, "f64x2")
                self.__dict__.setdefault("_vtypes", set()).add(t)
                val, vec = f"(v128)({t}){{{val}}}", True
            out.append(f"{dst[r]} = {val};")
            kinds.setdefault(dst[r], set()).add("v" if vec else "s")
            if vec:
                self.__dict__.setdefault("_vecnames", set()).add(dst[r])   # declared v128, not double
            regs[r] = dst[r]

    def _tail_target(self, b):
        """Address a block tail-calls (jmp/b to another function or import), else None."""
        term = b.insns[-1]
        if self.arch.kind(term) not in (JMP, IJMP):
            return None
        t = self.prog.call_target(term, {})
        if t is not None and (t in self.prog.image.imports or (t in self.prog.functions and t not in b.succs)):
            return t
        return None

    def _pin_name(self):
        self._tmpn += 1
        self._last_pin = f"t{self._tmpn}"  # t*: never a register name
        self._temps.add(self._last_pin)
        return self._last_pin

    def _pin(self, expr):
        """Emit `name = expr;` and return the name, so a long value is computed once, not re-inlined."""
        name = self._pin_name()
        self._out.append(f"{name} = {expr};")
        if neon.is_vec(self, expr):
            self.__dict__.setdefault("_vecnames", set()).add(name)
        else:
            t = self._scalar_type(expr)
            if t:
                self.__dict__.setdefault("_temptype", {})[name] = t
        return name

    _FLT = re.compile(r"\(\(f32x4\)|\b\d+\.\d*(?:e[-+]?\d+)?f\b|\(float\)")
    _DBL = re.compile(r"\(\(f64x2\)|(?<![\w.])\d+\.\d+(?:e[-+]?\d+)?(?![\w])|\(double\)")
    _TEMP = re.compile(r"\bt\d+\b")

    def _scalar_type(self, expr):
        """float/double for a pinned value computed in floating point (a lane of an f32x4, a float
        literal, or another float temp), else None (int64_t). An int64_t temp would truncate it."""
        known = getattr(self, "_temptype", {})
        refs = {known[n] for n in self._TEMP.findall(expr) if n in known}
        if self._FLT.search(expr) or "float" in refs:
            return "float"
        if self._DBL.search(expr) or "double" in refs:
            return "double"
        return None

    def condition(self, b):
        """C boolean for block `b`'s terminator, from the regs the just-run block() pass left."""
        if "__cond__" in self._last_regs:
            return self._last_regs["__cond__"]
        return self._cond_from(b.insns[-1], self._last_regs.get("__cmp__"))

    def ret(self, b):
        t = self._tail_target(b)
        if t is not None:  # tail call: `jmp f` is `return f(...)`
            regs = self._last_regs
            name = self.prog.display(t) or f"sub_{t:x}"
            call = self._objc_message(name, regs) or f"{cname(name)}({', '.join(self._call_args(t, regs))})"
            return f"{call};\nreturn;" if getattr(self, "_ret_void", False) else f"return {call};"
        if getattr(self, "_ret_void", False):
            return "return;"
        reg = self._canon(self.arch.fret) if self._ret_fp else self.arch.ret
        rv = self._last_regs.get(reg) or self._ent(reg)
        if self._ret_fp and neon.is_vec(self, rv):    # float result left in a vector register: lane 0
            t = "f32x4" if self._rettype == "float" else "f64x2"
            self.__dict__.setdefault("_vtypes", set()).add(t)
            rv = f"(({t}){rv if self._atomic(rv) else '(' + rv + ')'})[0]"
        return f"return {rv};"

    def indirect(self, b):
        # reached only when no jump table was recovered: a register-indirect branch — i.e. a
        # computed goto or (at a function tail) a tail-call through a function pointer / vtable slot.
        term = b.insns[-1]
        if term.operands and term.operands[-1].type == (x86.X86_OP_MEM if self.x86 else a64.ARM64_OP_MEM):
            tgt = self._op(term.operands[-1], term, self._last_regs)   # jmp [rdi + 0x20]: a slot
        else:
            tgt = self._last_regs.get(self._target_reg(term), self._target_reg(term))
        args = ", ".join(self._last_regs.get(a, a) for a in self._args())   # a tail call forwards them
        call = f"((code){tgt if self._atomic(tgt) else '(' + tgt + ')'})({args})"
        if getattr(self, "_ret_void", False):
            return f"{call};   /* indirect tail-call / computed jump */\nreturn;"
        return f"return {call};   /* indirect tail-call / computed jump */"

    # -- argument discovery ------------------------------------------------
    def _scan_args(self, func):
        """Arguments = ABI argument registers read before being written (integer and FP)."""
        argidx = {self._canon(a): i for i, a in enumerate(self.arch.args)}
        fidx = {self._canon(a): i for i, a in enumerate(self.arch.fargs)}
        argset, fset = set(argidx), set(fidx)
        used, fused = set(), set()
        single = set()  # FP args seen through a single-precision view (s0, or *ss/*ps ops)
        # A read is an argument only if some path from the entry reaches it with the register still
        # unwritten: forward "maybe unwritten" dataflow over the CFG, not address order (a loop's
        # back half often sits at a lower address than the block that defines its registers).
        allregs = argset | fset
        B = func.blocks
        rw = {a: [self._rw_args(i) for i in b.insns] for a, b in B.items()}  # one regs_access per insn
        kill = {a: set().union(*(w for _, w in rw[a])) & allregs for a in B}
        preds = {a: [] for a in B}
        for a, b in B.items():
            for t in b.succs:
                if t in preds:
                    preds[t].append(a)
        unw_in = {a: set() for a in B}
        unw_in[func.addr] = set(allregs)
        changed = True
        while changed:
            changed = False
            for a in sorted(B):
                inn = set(allregs) if a == func.addr else set()
                for q in preds[a]:
                    inn |= unw_in[q] - kill[q]
                if inn != unw_in[a]:
                    unw_in[a], changed = inn, True
        self._unw_in = unw_in              # reused by type inference: is a register still the arg?
        for a, b in B.items():
            unwritten = set(unw_in[a])
            for i, (rd, wr) in zip(b.insns, rw[a]):
                for c in rd & argset & unwritten:
                    used.add(argidx[c])
                for c in rd & fset & unwritten:
                    fused.add(fidx[c])
                    if self._single(i, c):
                        single.add(c)
                unwritten -= wr
        self._argcount = (max(used) + 1) if used else 0
        self._fargcount = (max(fused) + 1) if fused else 0
        self._ffloat = {self.arch.fargs[n] for n in range(self._fargcount) if self.arch.fargs[n] in single}

    _READS_DST = ("st", "fcmp", "fccmp", "cmp", "tst", "ccmp", "mla", "mls", "fmla", "fmls", "bsl",
                  "bit", "bif", "ins", "sli", "sri", "xtn2", "uaddw", "saddw")

    def _hoisted_pages(self, func):
        """{block: {reg id: page}}: `adrp` pages known on entry to each block. Forward dataflow -- a
        page holds at a block when every path into it carries the same adrp value for that
        register (compilers hoist adrp out of loops, so the load is blocks away from it)."""
        if self.x86:
            return {}
        B = func.blocks
        gen = {}
        for a, b in B.items():
            cur = {}
            for i in b.insns:
                ops = i.operands
                written = {o.reg for o in ops[:1] if o.type == a64.ARM64_OP_REG}
                for r in list(cur):
                    if r in written:
                        del cur[r]
                if i.mnemonic == "adrp" and len(ops) == 2:
                    cur[ops[0].reg] = ops[1].imm
                elif written:
                    cur = {r: v for r, v in cur.items() if r not in written}
            kills = {o.reg for i in b.insns for o in i.operands[:1] if o.type == a64.ARM64_OP_REG}
            gen[a] = (cur, kills)
        preds = {a: [] for a in B}
        for a, b in B.items():
            for t in b.succs:
                if t in preds:
                    preds[t].append(a)
        TOP = None
        inn = {a: ({} if a == func.addr else TOP) for a in B}
        def out(a):
            if inn[a] is TOP:
                return TOP
            cur, kills = gen[a]
            o = {r: v for r, v in inn[a].items() if r not in kills}
            o.update(cur)
            return o
        changed = True
        while changed:
            changed = False
            for a in sorted(B):
                if a == func.addr:
                    continue
                outs = [out(q) for q in preds[a]]
                outs = [o for o in outs if o is not TOP]
                if not outs:
                    continue
                new = {r: v for r, v in outs[0].items() if all(o.get(r) == v for o in outs[1:])}
                if new != inn[a]:
                    inn[a], changed = new, True
        return {a: v for a, v in inn.items() if v}

    def _rw_args(self, i):
        """regs read/written, for argument detection. Capstone also lists a NEON destination as read
        (movi, lane inserts, ...), which would make it look like an incoming FP argument: drop it
        unless the instruction genuinely reads its destination (stores, compares, accumulates)."""
        rd, wr = self._rw(i)
        k = self.arch.kind(i)
        if k in (CALL, JMP):                     # an API call reads its prototype's arguments
            t = self.prog.call_target(i, {})
            pr = typelib.proto(self.prog.display(t)) if t is not None and t not in self.prog.functions else None
            if pr:
                rd = rd | {self._canon(a) for a in self.arch.args[:len(pr[1])]}
            if k == CALL:
                return rd, wr
        if self.x86 or not i.operands or i.operands[0].type != a64.ARM64_OP_REG or \
                i.mnemonic.startswith(self._READS_DST) or "[" in i.op_str.split(",")[0]:
            return rd, wr
        d = self._canon(i.reg_name(i.operands[0].reg))
        if d.startswith("v") and d in wr:
            srcs = {self._canon(i.reg_name(o.reg)) for o in i.operands[1:] if o.type == a64.ARM64_OP_REG}
            if d not in srcs:
                rd = rd - {d}
        return rd, wr

    def _single(self, i, canon_reg):
        """Is FP register `canon_reg` used at single precision by `i`?"""
        n = canon_reg.lstrip("dxmv")
        if self.x86:
            return i.mnemonic.endswith(("ss", "ps")) and f"xmm{n}" in i.op_str
        return re.search(rf"\bs{n}\b", i.op_str) is not None

    def _caller_use(self, faddr):
        """'int' / 'fp' / 'none' / None: which return register callers read after calling faddr.

        Scans the few instructions after each call site, until the register is overwritten,
        another call happens or the block ends. Memoized per program."""
        cache = self.prog._ret_use_cache
        if faddr in cache:
            return cache[faddr]
        ret, fret = self._canon(self.arch.ret), self._canon(self.arch.fret) if self.arch.fret else None
        votes = {"int": 0, "fp": 0, "none": 0}
        for src, kind in self.prog.xrefs_to(faddr):
            if kind != "call":
                continue
            caller = self.prog.function_at(src)
            blk = next((b for b in caller.blocks.values() if b.addr <= src < b.end), None) if caller else None
            if blk is None:
                continue
            votes[self._first_use(caller, blk, src, ret, fret) or "none"] += 1
        real = {k: v for k, v in votes.items() if k != "none" and v}
        best = max(real, key=real.get) if real else ("none" if votes["none"] else None)
        cache[faddr] = best
        return best

    def _first_use(self, caller, blk, src, ret, fret, budget=40):
        """Breadth-first over the caller's CFG from just after the call: is the return value
        first read as an integer ('int') or float ('fp') before being overwritten?"""
        queue, seen_blocks, n = [(blk, src, frozenset())], set(), 0
        while queue and n < budget:
            b, after, dead = queue.pop(0)
            for i in b.insns:
                if i.address <= after:
                    continue
                n += 1
                k = self.arch.kind(i)
                if k == CALL:
                    break  # the next call clobbers both registers
                rd, wr = self._rw(i)
                if fret and fret in rd and fret not in dead:
                    return "fp"
                if ret in rd and ret not in dead:
                    return "int"
                dead = dead | wr
                if k == RET:
                    break
            else:
                for s in b.succs:
                    if s not in seen_blocks and s in caller.blocks:
                        seen_blocks.add(s)
                        queue.append((caller.blocks[s], -1, dead))
        return None

    def _fp_access(self, i):
        """Is a memory access by `i` moving data through a scalar FP register (movss, ldr s0, ...)?"""
        if self.x86:
            return i.mnemonic.lstrip("v").startswith(("movss", "movsd", "adds", "subs", "muls", "divs",
                                                      "ucomis", "comis", "maxs", "mins", "cvtss", "cvtsd"))
        first = i.op_str.split(",")[0].strip()
        return bool(re.fullmatch(r"[sd]\d{1,2}", first))

    def _scalar_fp(self, i):
        """Does `i` write its first operand as a scalar float/double (not a vector lane set)?"""
        m, first = i.mnemonic, i.op_str.split(",")[0].strip()
        if self.x86:
            ops = i.operands
            zero = m in ("xorps", "xorpd", "pxor", "vxorps", "vxorpd", "vpxor") and len(ops) >= 2 and \
                len({o.reg for o in ops if o.type == x86.X86_OP_REG}) == 1   # xorps x, x = 0.0
            return zero or m.endswith(("sd", "ss")) or m.startswith(("cvt", "vcvt", "sqrts", "vsqrts")) \
                or m in ("movq", "movd", "vmovq", "vmovd")
        return bool(re.fullmatch(r"[hsd]\d{1,2}", first))

    _ZERO_IDIOMS = ("xor", "sub", "xorps", "xorpd", "pxor", "vxorps", "vxorpd", "vpxor", "eor", "sbb")

    def _rw(self, i):
        """Canonical (reads, writes) register-name sets for one instruction; regs_access once."""
        if i.mnemonic in ("cmp", "cmn", "tst", "test"):  # capstone misfiles these as writes
            return {self._canon(t) for t in self._mentioned(i)}, set()
        if i.mnemonic in self._ZERO_IDIOMS and len(i.operands) >= 2 and \
                len({o.reg for o in i.operands if o.type == 1}) == 1 and all(o.type == 1 for o in i.operands):
            # xor r, r / xorps x, x: defines r (zero), does not read it -> not an argument use
            return set(), {self._canon(i.reg_name(i.operands[0].reg))}
        try:
            ra = i.regs_access()
        except Exception:
            return {self._canon(t) for t in self._mentioned(i)}, set()
        return ({self._canon(i.reg_name(r)) for r in ra[0]},
                {self._canon(i.reg_name(r)) for r in ra[1]})

    def _args(self):
        return self.arch.args[:self._argcount]

    # -- one instruction ---------------------------------------------------
    def _step(self, i, regs):
        """Lift one instruction. arm64 pre/post-indexed addressing also advances its base
        register (`ldrb w8, [x0], #1` loads then x0 += 1) -- loops that walk pointers rely on it."""
        self._cur_insn = i
        if self.x86 or not getattr(i, "writeback", False):
            return self._step1(i, regs)
        mem = next((o for o in i.operands if o.type == a64.ARM64_OP_MEM), None)
        if mem is None or not mem.mem.base:
            return self._step1(i, regs)
        base = self._canon(i.reg_name(mem.mem.base))
        if getattr(i, "post_index", False):
            inc = next((o.imm for o in i.operands if o.type == a64.ARM64_OP_IMM), 0)
        else:
            inc = mem.mem.disp
        old = regs.get(base, self._ent(base))
        res = self._step1(i, regs)               # the access itself uses the old base (+disp)
        if base not in ("sp", "x29") and inc:
            regs[base] = self._bin(self._byte_ptr(old), "+" if inc > 0 else "-",
                                   hex(abs(inc)) if abs(inc) > 9 else str(abs(inc)))   # bytes, not elements
        return res

    def _step1(self, i, regs):
        m = i.mnemonic
        k = self.arch.kind(i)
        if m in ("cmp", "test", "cmn", "tst", "cbz", "cbnz"):
            regs["__cmp__"] = (m, [self._op(o, i, regs) for o in i.operands])
        elif m in _FLAG_ARITH and len(i.operands) == 3:
            # subs/adds/ands set flags from their *sources* (and also write a result, lifted below)
            regs["__cmp__"] = (_FLAG_ARITH[m], [self._op(o, i, regs) for o in i.operands[1:]])
        if not self.x86 and m in ("ldr", "ldur") and i.operands and i.operands[0].type == a64.ARM64_OP_REG \
                and (i.reg_name(i.operands[0].reg) or "")[:1] in "qdsh":
            c = self._fp_const(i, regs)
            if c is not None:                       # FP / vector constant from read-only data
                return self._assign(i.operands[0], c, i, regs)
        # resolve address-forming instructions (adrp/adr/add-of-page, PC-rel lea, literal ldr) to
        # the string or symbol they point at, so call arguments read as "..." instead of raw math.
        if m in ("adrp", "adr", "add", "lea", "ldr", "mov") and i.operands and \
                i.operands[0].type == (x86.X86_OP_REG if self.x86 else a64.ARM64_OP_REG) and \
                not any(o.type == (x86.X86_OP_MEM if self.x86 else a64.ARM64_OP_MEM) and o.mem.index
                        for o in i.operands):   # an indexed load is a table access, not a literal
            for r in self.arch.data_refs(i, regs.setdefault("__page__", {})):
                lit = self.prog.strings().get(r)
                cf = self.prog.objc.cfstrings.get(r) if self.prog.objc else None
                sym = cname(self.prog.display(r) or "") or None
                if cf is not None:                 # NSString literal
                    regs[self._canon(i.reg_name(i.operands[0].reg))] = "@" + cstr_lit(cf)
                    return None
                if lit is not None or sym:
                    if lit is not None:
                        val = cstr_lit(lit)      # pointer to a string literal
                    elif m in ("ldr", "mov") or r in self.prog.functions or r in self.prog.image.imports:
                        val = sym                # loaded value / code or import address
                    else:
                        val = f"&{sym}"          # computed address of a data symbol
                    regs[self._canon(i.reg_name(i.operands[0].reg))] = val
                    return None  # the resolved address IS the value; don't also arithmetic it
        if m in ("adrp", "adr"):
            return None  # page-base half of an address pair; the paired add/ldr carries the value
        if m in ("cset", "csetm", "csinc", "csinv", "csneg", "csel"):
            return self._csel(i, regs)
        if self.x86 and m.startswith("set") and len(m) > 3:  # setcc dst
            cond = self._cc_expr_x86(regs.get("__cmp__"), m[3:])
            return self._assign(i.operands[0], f"({cond}) ? 1 : 0", i, regs)
        if self.x86 and m.startswith("cmov"):  # cmovcc dst, src: dst = cond ? src : dst
            cond = self._cc_expr_x86(regs.get("__cmp__"), m[4:])
            return self._assign(i.operands[0],
                                f"({cond}) ? {self._op(i.operands[-1], i, regs)} : {self._op(i.operands[0], i, regs)}",
                                i, regs)
        if self._is_frame_noise(i):
            return None
        if k == CALL:
            return self._call(i, regs)
        if m in ("ret", "retab", "retaa"):
            return None
        r = lift_simd.lift(self, i, regs)  # SIMD / FP / extended integer forms
        if r is not lift_simd.NA:
            return r
        if m == "movk" and len(i.operands) == 2:
            return self._movk(i, regs)
        if m in ("mov", "movz", "mov.w", "movaps", "movups", "movq", "movl", "lea", "ldr", "str",
                 "stur", "ldur", "movzx", "movsx", "movsxd", "movk",
                 "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "strb", "strh", "sturb", "sturh"):
            return self._move(i, regs)
        if m in ("inc", "dec", "neg", "not", "mvn", "negs"):
            return self._unary(i, regs)
        if m in ("add", "sub", "and", "or", "orr", "xor", "eor", "mul", "imul", "mneg",
                 "umull", "smull", "umulh", "smulh", "sdiv", "udiv", "orn", "eon",
                 "lsl", "lsr", "asr", "ror", "shl", "shr", "sar", "sal", "madd", "ands", "bic",
                 "subs", "adds", "bics"):
            return self._arith(i, regs)
        if m in ("stp", "ldp"):
            return self._pair(i, regs)
        if m in ("push", "pop", "cmp", "test", "nop", "endbr64", "hint", "cmn", "tst"):
            return None
        # unmodeled: keep as a comment so nothing is lost
        return f"/* {m} {i.op_str} */"

    def _call(self, i, regs):
        regs2 = {}
        target = self.prog.call_target(i, regs2) or self.prog.call_target(i, regs)
        if target is not None:
            name = self.prog.display(target) or f"sub_{target:x}"
            fname = cname(name)
        else:                                    # through a register/memory value: cast and call
            v = self._op(i.operands[-1], i, regs)
            name = fname = f"((code){v if self._atomic(v) else '(' + v + ')'})"
        call = self._objc_message(name, regs) or f"{fname}({', '.join(self._call_args(target, regs))})"
        # the callee may write memory: values loaded earlier must be captured before it runs
        arg_regs = set(self.arch.args) | {self._canon(r) for r in self.arch.fargs}
        self._flush(regs, lambda v: bool(self._READS_MEM.search(v)) or bool(re.search(r"(?<![\w.])local_\w+", v)),
                    skip=arg_regs)  # argument registers are consumed by the call itself
        for a in self.arch.args:                 # arguments are clobbered by the call
            regs.pop(a, None)
        for r in self.arch.fargs:
            regs.pop(self._canon(r), None)
        if self._callee_void(target, name):      # no result: a statement, not `t = f()`
            self._out.append(f"{call};")
            return None
        # a call has a side effect and must appear exactly once: pin its result to a temp
        # so later uses reference the temp rather than re-emitting (and re-"calling") it.
        self._out.append(f"{self._pin_name()} = {call};")
        pr = typelib.proto(name) if target is None or target not in self.prog.functions else None
        if pr and pr[0] not in ("void", "int32_t", "int64_t", "uint32_t", "uint64_t", "uint8_t"):
            self.__dict__.setdefault("_temptype", {})[self._last_pin] = pr[0]   # char *, void *, double
        regs[self.arch.ret] = self._last_pin
        if self.arch.fret:
            regs[self._canon(self.arch.fret)] = self._last_pin  # FP result, if the callee returns one
            regs["__fret_pin__"] = self._last_pin
        return None

    _VOID = {"exit", "_exit", "abort", "free", "__stack_chk_fail", "longjmp", "siglongjmp", "_longjmp",
             "pthread_exit", "err", "errx", "verr", "verrx", "warn", "warnx", "vwarn", "vwarnx", "perror",
             "__assert_rtn", "objc_release", "objc_storeStrong", "objc_autoreleasePoolPop",
             "objc_end_catch", "objc_exception_throw", "_Unwind_Resume", "swift_release",
             "swift_bridgeObjectRelease", "CFRelease", "dispatch_release", "os_release",
             "dispatch_async", "dispatch_sync", "dispatch_once", "free_sized", "bzero", "qsort",
             "__cxa_throw", "__cxa_end_catch", "_os_log_impl", "os_unfair_lock_lock",
             "os_unfair_lock_unlock", "objc_destroyWeak", "objc_copyWeak", "objc_moveWeak"}
    _VOID_N = {v.lstrip("_") for v in _VOID}

    def _callee_void(self, target, name):
        """Does the callee return nothing? Known libc/runtime functions, or our own analysis."""
        if (name or "").lstrip("_").split("$")[0] in self._VOID_N:
            return True
        f = self.prog.functions.get(target) if target is not None else None
        if f is None:
            return False
        if f is getattr(self, "_func", None):
            return bool(getattr(self, "_ret_void", False))   # recursion: our own signature says
        cache = self.prog.__dict__.setdefault("_void_cache", {})
        if target not in cache:
            cache[target] = False                # provisional: recursion
            try:
                sub = Lifter(self.prog)
                sub.signature(f, "f")
                cache[target] = sub._ret_void
            except Exception:
                pass
        return cache[target]

    def _call_args(self, target, regs):
        """Argument expressions for a call. Known callees use their scanned arity; for imports the
        arity is the highest argument register actually set before the call (printf(fmt, x))."""
        argc, fargc = self._callee_argc(target)
        pr = typelib.proto(self.prog.display(target)) if target is not None else None
        if pr is not None and target not in self.prog.functions:      # a system prototype wins
            n = len(pr[1])
            if pr[2]:                                # variadic: the extra registers the caller set
                ints = [k for k, a in enumerate(self.arch.args) if self._changed(a, regs)]
                n = max([n] + [k + 1 for k in ints])
            return [regs.get(a, a) for a in self.arch.args[:n]]
        if target not in self.prog.functions:
            ints = [n for n, a in enumerate(self.arch.args) if self._changed(a, regs)]
            argc = max(ints) + 1 if ints else min(self._argcount, 4)
            # an FP register still holding the previous call's result is not a new argument
            pin = regs.get("__fret_pin__")
            fl = [n for n, r in enumerate(self.arch.fargs)
                  if self._changed(self._canon(r), regs) and regs[self._canon(r)] != pin]
            fargc = max(fl) + 1 if fl else 0
        fregs = [self._canon(r) for r in self.arch.fargs[:fargc]]
        return [regs.get(a, a) for a in self.arch.args[:argc]] + [regs.get(r, r) for r in fregs]

    def _objc_message(self, name, regs):
        """`[receiver sel:arg ...]` for objc_msgSend and the objc_msgSend$sel stubs."""
        n = name.lstrip("_")
        a = self.arch.args
        if n.startswith("objc_msgSend$"):
            sel, first = n[len("objc_msgSend$"):], 2  # stub loads the selector itself
        elif n in ("objc_msgSend", "objc_msgSendSuper2", "objc_msgSend_stret"):
            s = regs.get(a[1], "")
            if not s.startswith("selRef_"):
                return None
            sel, first = s[len("selRef_"):], 2
        else:
            return None
        recv = regs.get(a[0], a[0])
        cls = re.match(r"^&?(_?OBJC_CLASS_\$_|classRef_)", recv)
        recv = re.sub(r"^&?(_?OBJC_CLASS_\$_|classRef_)", "", recv)  # a class receiver is its name
        typed = self._argtypes.get(recv) == "id" or recv.startswith(('@"', "[")) or cls
        if not typed:                     # valid Objective-C needs an object-typed receiver
            recv = f"(id){self._paren(recv)}"
        parts = sel.split(":")
        if len(parts) == 1:
            return f"[{recv} {sel}]"
        vals = [regs.get(a[first + k], a[first + k]) if first + k < len(a) else "?" for k in range(len(parts) - 1)]
        return f"[{recv} " + " ".join(f"{p}:{v}" for p, v in zip(parts, vals)) + "]"

    def _callee_argc(self, target):
        """(integer args, FP args) a callee takes; memoized for the whole program."""
        f = self.prog.functions.get(target) if target is not None else None
        if f is None:
            return 4, 0  # unknown/import: show up to 4 args, trimmed where obviously unused
        cache = self.prog._argc_cache
        if target not in cache:
            saved = (self._argcount, self._fargcount, self._ffloat, self._locals)
            self._scan_args(f)
            cache[target] = (self._argcount, self._fargcount)
            self._argcount, self._fargcount, self._ffloat, self._locals = saved
        return cache[target]

    def _move(self, i, regs):
        ops = i.operands
        if len(ops) < 2:
            return None
        dst, src = ops[0], ops[-1]
        m = i.mnemonic
        if not self.x86:
            # arm64 loads/stores name the register first, then the memory operand; a trailing
            # immediate is the pre/post-index increment (handled in _step), not a value source.
            mem = next((o for o in ops if o.type == a64.ARM64_OP_MEM), None)
            if mem is not None:
                if m.startswith(("str", "stur", "stlr", "stlur", "stnp")):
                    dst, src = mem, ops[0]
                else:
                    dst, src = ops[0], mem
        if m == "lea":  # address-of, not a load: drop the deref
            val = self._addr(src, i, regs)
        else:
            val = self._op(src, i, regs)
        cast = None
        if m in ("movzx", "movsx", "movsxd") and src.size:        # x86 widening loads/moves
            cast = f"({'u' if m == 'movzx' else ''}int{8 * src.size}_t)"
        elif m in self._ARM_LOAD_CAST:
            cast = self._ARM_LOAD_CAST[m]
        if cast:
            val = f"{cast}{val}" if self._atomic(val) else f"{cast}({val})"
            if self._reg_width(dst, i) == 8 and dst.type == (x86.X86_OP_REG if self.x86 else a64.ARM64_OP_REG):
                val = f"(int64_t){val}"   # widened into a 64-bit register: later math is 64-bit
        return self._assign(dst, val, i, regs)

    _ARM_LOAD_CAST = {"ldrb": "(uint8_t)", "ldurb": "(uint8_t)", "ldrh": "(uint16_t)", "ldurh": "(uint16_t)",
                      "ldrsb": "(int8_t)", "ldursb": "(int8_t)", "ldrsh": "(int16_t)", "ldursh": "(int16_t)",
                      "ldrsw": "(int32_t)", "ldursw": "(int32_t)"}

    def _addr(self, op, i, regs):
        """Value of an address computation (lea, ld1/st1 pointers): the address, never a load."""
        inner = self._mem(op, i, regs)
        typed = re.fullmatch(r"\*\([\w ]+ \*\)(.*)", inner)
        if typed:                        # *(T *)(addr) -> addr   (lea computes the address)
            a = typed.group(1)
            return a[1:-1] if a.startswith("(") and a.endswith(")") and self._atomic(a) else a
        if inner.startswith("*") and self._atomic(inner[1:]):
            return inner[1:]             # *p -> p
        if inner.startswith("local_") or inner.endswith("]") or "->" in inner:
            return f"&{inner}"           # address of a local, an array element or a struct field
        return inner                     # a symbol or string literal is already an address

    def _arith(self, i, regs):
        ops = i.operands
        m = i.mnemonic.rstrip(".w")
        opsym = {"add": "+", "sub": "-", "and": "&", "or": "|", "orr": "|", "xor": "^", "eor": "^",
                 "mul": "*", "imul": "*", "madd": "*", "mneg": "*", "umull": "*", "smull": "*",
                 "umulh": "*", "smulh": "*", "sdiv": "/", "udiv": "/", "shl": "<<", "sal": "<<",
                 "lsl": "<<", "shr": ">>", "lsr": ">>", "sar": ">>", "asr": ">>", "ror": "ror",
                 "ands": "&", "bic": "& ~", "bics": "& ~", "subs": "-", "adds": "+",
                 "orn": "| ~", "eon": "^ ~"}[m]
        if self.x86:
            dst = ops[0]
            a, b = self._op(dst, i, regs), self._op(ops[-1], i, regs)
            if m == "xor" and a == b:
                regs["__cmp__"] = ("test", ["0", "0"])
                return self._assign(dst, "0", i, regs)
            if m in ("shr", "sar", "shl", "sal"):
                a = self._shift_operand(a, m in ("shr",), self._reg_width(dst, i))
            if m in ("add", "sub"):
                a = self._byte_ptr(a)
            else:                                   # bit ops / shifts on a pointer: as an integer
                a, b = self._int_operand(a), self._int_operand(b)
            val = self._wrap32(self._bin(a, opsym, b), m, dst, i)
            # x86 arithmetic sets the flags from its operation: sub/and behave like cmp/test,
            # everything else compares the result with zero (je/jne/js after add, shr, or ...).
            regs["__cmp__"] = ("cmp", [self._op(dst, i, regs), b]) if m == "sub" \
                else ("test", [self._op(dst, i, regs), b]) if m == "and" else ("test", [val, val])
            return self._assign(dst, val, i, regs)
        dst = ops[0]
        a = self._op(ops[1], i, regs)
        b = self._op(ops[2], i, regs) if len(ops) > 2 else a
        if m in ("umulh", "smulh"):                          # high 64 bits of the 128-bit product
            t, c = ("unsigned __int128", "(uint64_t)") if m == "umulh" else ("__int128", "(int64_t)")
            return self._assign(dst, f"(int64_t)((({t}){c}{self._paren(a)} * {c}{self._paren(b)}) >> 64)", i, regs)
        if m in ("umull", "smull", "umaddl", "smaddl", "umsubl", "smsubl"):   # 32x32 -> 64 widening
            c, w = ("(uint32_t)", "(uint64_t)") if m[0] == "u" else ("(int32_t)", "(int64_t)")
            prod = f"{w}{c}{self._paren(a)} * {w}{c}{self._paren(b)}"
            if len(ops) > 3:
                prod = self._bin(self._op(ops[3], i, regs), "-" if "sub" in m else "+", f"({prod})")
            return self._assign(dst, prod, i, regs)
        if m in ("add", "sub") and a == "sp" and len(ops) > 2 and ops[2].type == a64.ARM64_OP_IMM:
            off = ops[2].imm if m == "add" else -ops[2].imm   # add x0, sp, #0x10: &local buffer
            return self._assign(dst, f"&{self._local(off)}", i, regs)
        if m in ("add", "sub", "adds", "subs"):
            a = self._byte_ptr(a)                             # pointer + bytes, not + elements
        else:
            a, b = self._int_operand(a), self._int_operand(b)
        if m in ("lsr", "asr", "lsl"):
            a = self._shift_operand(a, m == "lsr", self._reg_width(dst, i))
        if m in ("madd", "msub") and len(ops) > 3:            # c +/- a*b
            v = self._bin(self._op(ops[3], i, regs), "+" if m == "madd" else "-", f"({self._bin(a, '*', b)})")
            return self._assign(dst, self._wrap32(v, m, dst, i), i, regs)
        if m == "mneg":                                       # -(a*b)
            return self._assign(dst, self._wrap32(f"-({self._bin(a, '*', b)})", m, dst, i), i, regs)
        if m == "ror":
            bits = self._reg_width(dst, i) * 8
            ua = f"({self._utype(bits)}){a}" if self._atomic(a) else f"({self._utype(bits)})({a})"
            return self._assign(dst, f"__builtin_rotateright{bits}({ua}, {b})", i, regs)
        if opsym.endswith(" ~"):                             # bic/orn/eon: a OP ~b
            inv = f"~{b}" if self._atomic(b) else f"~({b})"
            return self._assign(dst, self._bin(a, opsym[0], inv), i, regs)
        return self._assign(dst, self._wrap32(self._bin(a, opsym, b), m, dst, i), i, regs)

    _WRAPS = {"add", "sub", "adds", "subs", "mul", "imul", "madd", "msub", "mneg", "lsl", "shl", "sal",
              "neg", "negs", "inc", "dec"}

    def _wrap32(self, val, m, dst, i):
        """A 32-bit destination (w0, eax) wraps at 32 bits; 64-bit C arithmetic on the int64_t
        variables would not. Only for operations whose result can leave the 32-bit range."""
        if m not in self._WRAPS or self._reg_width(dst, i) != 4:
            return val
        return f"(int32_t)({self._strip32(val)})"

    @staticmethod
    def _strip32(val):
        """Inside a 32-bit wrap of + - * <<, an operand's own (int32_t)( ) wrap is redundant: the
        low 32 bits are the same either way (arithmetic mod 2^32). Only top-level + - * terms."""
        if ">>" in val or "/" in val or "%" in val or "?" in val:
            return val
        out, k = [], 0
        while True:
            j = val.find("(int32_t)(", k)
            if j < 0:
                out.append(val[k:])
                break
            depth, e = 0, j + 9
            for e in range(j + 9, len(val)):
                depth += {"(": 1, ")": -1}.get(val[e], 0)
                if depth == 0:
                    break
            before = val[:j].rstrip()
            top = val[:j].count("(") - val[:j].count(")") == 0
            if top and (not before or before[-1] in "+-*"):
                out.append(val[k:j] + "(" + val[j + 10:e] + ")")
            else:
                out.append(val[k:e + 1])
            k = e + 1
        return "".join(out)

    def _byte_ptr(self, v):
        """A typed pointer in integer arithmetic: C would scale by the element size, the machine
        adds bytes. Cast through char * (no-op for char * and plain integers)."""
        t = self._ptr_type(v)
        if t and t not in ("char *", "void *"):
            return f"(char *){v}" if self._atomic(v) else f"(char *)({v})"
        if re.fullmatch(r"&[\w$.]+", v or ""):
            return f"(char *){v}"              # &sym + n is bytes past the symbol
        return v

    _PTRISH = re.compile(r'^(\(char \*\)|"|&|@")')

    def _int_operand(self, v):
        """Bit operations and shifts need an integer: a pointer-typed value (a string literal,
        &sym, a typed pointer arg) is cast to int64_t first -- tagged/PAC pointer arithmetic."""
        if self._PTRISH.match(v or "") or self._ptr_type(v) or "(char *)" in (v or ""):
            return f"(int64_t){self._paren(v)}"   # anywhere inside: a ternary of pointers too
        return v

    def _neg(self, v):
        """-v, parenthesized when needed: `-` before `-1` or `-x` would be C's `--` operator."""
        return f"-{v}" if self._atomic(v) and not str(v).startswith(("-", "+")) else f"-({v})"

    def _paren(self, v):
        return v if self._atomic(v) else f"({v})"

    @staticmethod
    def _utype(bits):
        return {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}.get(bits, "uint64_t")

    def _reg_width(self, op, i):
        """Byte width of a register operand (4 for w0/eax, 8 for x0/rax, else 8)."""
        if self.x86:
            return op.size or 8
        return 4 if (i.reg_name(op.reg) or "x")[0] == "w" else 8

    def _shift_operand(self, a, logical, width):
        """Cast a shift's left operand so C does the right shift: unsigned for lsr/shr (zero-fill),
        signed for asr/sar; sized so a 32-bit shift does not sign-extend from 64 bits."""
        bits = width * 8
        if logical:
            cast = f"(uint{bits}_t)"
        elif width == 4:
            cast = "(int32_t)"      # int64_t default is already a signed arithmetic shift
        else:
            return a
        return f"{cast}{a}" if self._atomic(a) else f"{cast}({a})"

    def _unary(self, i, regs):
        ops = i.mnemonic, i.operands
        m, operands = ops
        dst = operands[0]
        src = self._op(operands[-1], i, regs)
        neg = self._neg(src)
        inv = f"~{src}" if self._atomic(src) else f"~({src})"
        expr = {"inc": self._bin(src, "+", "1"), "dec": self._bin(src, "-", "1"), "neg": neg,
                "negs": neg, "not": inv, "mvn": inv}[m]
        if self.x86 and m in ("inc", "dec", "neg"):  # flags from the result (not for x86 `not`)
            # the optional third element is the carry flag, where the instruction defines one
            regs["__cmp__"] = ("test", [expr, expr], self._bin(src, "!=", "0")) if m == "neg" \
                else ("test", [expr, expr])
        return self._assign(dst, expr, i, regs)

    _NUM = re.compile(r"-?(0x[0-9a-fA-F]+|\d+)")
    _FOLD = {"+": lambda x, y: x + y, "-": lambda x, y: x - y, "*": lambda x, y: x * y,
             "&": lambda x, y: x & y, "|": lambda x, y: x | y, "^": lambda x, y: x ^ y,
             "<<": lambda x, y: x << y if 0 <= y < 64 else None, ">>": lambda x, y: x >> y if 0 <= y < 64 else None}

    @classmethod
    def _num(cls, s):
        """Integer value of a literal like 12, -3 or 0x1f; None for anything else."""
        if not cls._NUM.fullmatch(s):
            return None
        try:
            return int(s, 0)
        except ValueError:  # e.g. "08"
            return None

    @staticmethod
    def _atomic(s):
        """True if `s` needs no parentheses as an operand: no top-level binary op or ternary."""
        depth, quote = 0, False
        for n, ch in enumerate(s):
            if quote:
                if ch == '"' and s[n - 1] != "\\":
                    quote = False
            elif ch == '"':
                quote = True
            elif ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif depth == 0 and (ch == "?" or ch == " "):  # binary operators are space-separated
                return False
        return True

    @classmethod
    def _bin(cls, a, op, b):
        """`a op b` with constant folding and identities; parenthesizes compound operands."""
        x, y = cls._num(a), cls._num(b)
        if x is not None and y is not None and op in cls._FOLD:
            v = cls._FOLD[op](x, y)
            if v is not None and abs(v) < (1 << 64):
                return (hex(v) if v > 9 else str(v)) if v >= 0 else (f"-{hex(-v)}" if -v > 9 else str(v))
        if y == 0 and op in ("+", "-", "|", "^", "<<", ">>"):
            return a
        if x == 0 and op in ("+", "|", "^"):
            return b
        if (x == 0 or y == 0) and op in ("*", "&"):
            return "0"
        if y == 1 and op in ("*", "/"):
            return a
        if x == 1 and op == "*":
            return b

        p = cls._PREC.get(op, 0)
        pa, pb = cls._top_prec(a), cls._top_prec(b)
        left = a if pa >= p else f"({a})"
        # right side: equal precedence only stays bare for associative ops (a + b + c)
        right = b if pb > p or (pb == p and op in cls._ASSOC and cls._top_op(b) == op) else f"({b})"
        return f"{left} {op} {right}"

    # C operator precedence (higher binds tighter); ternary is lowest, atomic operands are 99
    _PREC = {"||": 4, "&&": 5, "|": 6, "^": 7, "&": 8, "==": 9, "!=": 9, "<": 10, "<=": 10, ">": 10,
             ">=": 10, "<<": 11, ">>": 11, "+": 12, "-": 12, "*": 13, "/": 13, "%": 13}
    _ASSOC = {"+", "*", "&", "|", "^", "&&", "||"}

    @classmethod
    def _top_op(cls, s):
        """Lowest-precedence operator at nesting depth 0 ('?' for a ternary), or None if atomic."""
        depth, quote, best, n = 0, False, None, 0
        while n < len(s):
            ch = s[n]
            if quote:
                quote = not (ch == '"' and s[n - 1] != "\\")
            elif ch == '"':
                quote = True
            elif ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif depth == 0 and ch == "?":
                return "?"
            elif depth == 0 and ch == " ":
                end = s.find(" ", n + 1)
                tok = s[n + 1:end] if end > 0 else ""
                if tok in cls._PREC and (best is None or cls._PREC[tok] <= cls._PREC[best]):
                    best = tok
            n += 1
        return best

    @classmethod
    def _top_prec(cls, s):
        op = cls._top_op(s)
        return 99 if op is None else 3 if op == "?" else cls._PREC[op]

    def _csel(self, i, regs):
        """cset/csinc/csinv/csneg/csel -> ternary from the block's pending condition."""
        ops, m = i.operands, i.mnemonic
        cc = i.cc if hasattr(i, "cc") else None
        cond = self._cc_expr(regs.get("__cmp__"), self._cc_name(i))
        tp = lambda s: f"({s})" if "?" in s else s  # a nested ternary needs its own parentheses
        if m in ("cset", "csetm"):
            val = f"({cond}) ? {'-1' if m == 'csetm' else '1'} : 0"
        elif m == "csel":
            val = f"({cond}) ? {tp(self._op(ops[1], i, regs))} : {tp(self._op(ops[2], i, regs))}"
        else:
            t = self._op(ops[1], i, regs)
            f = self._op(ops[2], i, regs) if len(ops) > 2 else t
            tweak = {"csinc": tp(self._bin(f, "+", "1")), "csinv": f"~{tp(f)}", "csneg": self._neg(tp(f))}[m]
            val = f"({cond}) ? {tp(t)} : {tweak}"
        return self._assign(ops[0], val, i, regs)

    _CALLEE_SAVED = {f"x{n}" for n in range(19, 31)} | {f"v{n}" for n in range(8, 16)} | {"fp", "lr"}

    def _pair(self, i, regs):
        """ldp/stp: two loads/stores at [mem] and [mem + width]. Callee-saved spills to the stack
        are frame bookkeeping and are dropped; everything else is real data movement."""
        ops = i.operands
        if len(ops) < 3 or ops[2].type != a64.ARM64_OP_MEM:
            return None
        r0, r1 = (self._canon(i.reg_name(o.reg)) for o in ops[:2])
        base = self._canon(i.reg_name(ops[2].mem.base)) if ops[2].mem.base else None
        if base in ("sp", "x29") and {r0, r1} <= self._CALLEE_SAVED:
            return None
        width = 4 if i.reg_name(ops[0].reg)[0] in "ws" else 16 if i.reg_name(ops[0].reg)[0] == "q" else 8
        first = self._op(ops[2], i, regs)
        second = self._mem_offset(ops[2], i, regs, width)
        if i.mnemonic == "ldp" or i.mnemonic == "ldpsw":
            self._assign(ops[0], first, i, regs)
            self._assign(ops[1], second, i, regs)
            return None
        v0, v1 = self._op(ops[0], i, regs), self._op(ops[1], i, regs)
        self._out.append(f"{first} = {v0};")   # two stores, two statements
        return f"{second} = {v1};"

    def _mem_offset(self, op, i, regs, delta):
        """The memory operand `op` displaced by `delta` bytes, rendered like _mem."""
        m = op.mem
        base = self._canon(i.reg_name(m.base)) if m.base else None
        disp = m.disp + delta
        if base in ("sp", "x29"):
            return self._local(disp)
        member = self._member(base, disp, regs) if base else None
        if member:
            return member
        return self._deref(self._elem_type(i),
                           self._address(self._byte_base(base, regs) if base else None, None, 1, disp))

    # -- operands ----------------------------------------------------------
    def _movk(self, i, regs):
        """movk: replace one 16-bit lane, keep the others (mov+movk builds 32/64-bit constants)."""
        dst, src = i.operands
        name = self._canon(i.reg_name(dst.reg))
        sh = src.shift.value if src.shift.type else 0
        imm, mask = src.imm << sh, 0xffff << sh
        old = regs.get(name, name)
        try:
            v = int(old, 0)
        except (TypeError, ValueError):
            v = None
        if v is not None:
            full = (1 << (8 * self._reg_width(dst, i))) - 1
            k = ((v & full) & ~mask) | imm
            return self._assign(dst, hex(k) if k > 9 else str(k), i, regs)
        return self._assign(dst, f"({self._paren(old)} & {hex(~mask & ((1 << 64) - 1))}) | {hex(imm)}", i, regs)

    _RODATA = ("const", "literal", "rodata", "cstring", "text", "rdata")

    def _ro_bytes(self, a, n):
        """`n` bytes at `a` when it is in read-only data (a compiler constant pool), else None."""
        sec = self.prog.image.section_at(a)
        if sec is None or (sec.code and "literal" not in sec.name.lower()) or \
                not any(k in sec.name.lower() for k in self._RODATA):
            return None
        raw = self.prog.image.read(a, n)
        return raw if len(raw) == n else None

    def _fp_const(self, i, regs):
        """`ldr d0, =1.5` / `ldr q7, [x8, :lo12:cst]`: the constant itself, when the address is a
        fixed location in read-only data. None for anything else (writable data, runtime pointers)."""
        refs = self.arch.data_refs(i, dict(regs.get("__page__", {})))
        if not refs:
            return None
        a = refs[0]
        sec = self.prog.image.section_at(a)
        if sec is None or sec.code and "literal" not in sec.name.lower() or \
                not any(k in sec.name.lower() for k in self._RODATA):
            return None
        import struct, math
        kind = (i.reg_name(i.operands[0].reg) or "")[0]
        raw = self.prog.image.read(a, {"q": 16, "d": 8, "s": 4, "h": 2}[kind])
        if kind == "q" and len(raw) == 16:
            self.__dict__.setdefault("_vtypes", set()).add("v128")
            return "(v128){" + ", ".join(hex(b) for b in raw) + "}"
        if kind in "ds" and len(raw) == (8 if kind == "d" else 4):
            v = struct.unpack("<d" if kind == "d" else "<f", raw)[0]
            if math.isfinite(v):
                return repr(v) if kind == "d" else f"{v!r}f"
        return None

    def _assign(self, dst, val, i, regs):
        reg_t = x86.X86_OP_REG if self.x86 else a64.ARM64_OP_REG
        mem_t = x86.X86_OP_MEM if self.x86 else a64.ARM64_OP_MEM
        if dst.type == reg_t:
            name = self._canon(i.reg_name(dst.reg))
            raw = i.reg_name(dst.reg) or ""
            if self.x86 and raw.startswith("xmm"):     # x86 scalar FP write: its lane-0 type
                mm = i.mnemonic.lstrip("v")
                if mm.endswith(("ss", "sd")) or mm.startswith("cvt"):
                    self.__dict__.setdefault("_lastview", {})[name] = \
                        "f32x4" if mm.endswith("ss") or mm.endswith("2ss") else "f64x2"
            if not self.x86 and raw[:1] in "bhsd" and raw[1:].isdigit():   # scalar view of a v reg
                bits = {"b": 8, "h": 16, "s": 32, "d": 64}[raw[0]]
                gpr_src = i.mnemonic == "fmov" and len(i.operands) > 1 and \
                    (i.reg_name(i.operands[1].reg) or "")[:1] in "wx"    # fmov d0, x8: integer bits
                fp = bits >= 32 and not gpr_src and \
                    (i.mnemonic.startswith("f") or i.mnemonic in ("scvtf", "ucvtf", "ldr", "ldur"))
                self.__dict__.setdefault("_lastview", {})[name] = f"{'f' if fp else 'u'}{bits}x{128 // bits}"
            # track the value symbolically; emit nothing unless the expression is big enough
            # to be worth pinning (keeps chained temporaries from nesting without bound).
            regs[name] = self._pin(val) if len(val) > self.MATERIALIZE else val
            return None
        if dst.type == mem_t:
            loc = self._mem(dst, i, regs)
            self._flush_for_store(loc, regs)
            return f"{loc} = {val};"   # store: a real side effect
        return f"{val};"

    _READS_MEM = re.compile(r"\*\(|->|\[")

    def _flush(self, regs, pred, skip=()):
        """Pin every pending value for which pred(expr) holds: it must be read *now*, before a
        store or call changes the memory it reads (loads are not re-evaluated later)."""
        for r, v in list(regs.items()):
            if not r.startswith("__") and r not in skip and isinstance(v, str) and pred(v):
                regs[r] = self._pin(v)
        cmp = regs.get("__cmp__")
        if cmp:
            regs["__cmp__"] = (cmp[0], [self._pin(a) if pred(a) else a for a in cmp[1]], *cmp[2:])

    def _flush_for_store(self, loc, regs):
        if re.fullmatch(r"local_\w+", loc):           # a stack slot: only reads of that slot
            pat = re.compile(rf"(?<![\w.]){re.escape(loc)}\b")
            self._flush(regs, lambda v: bool(pat.search(v)))
        else:                                         # unknown memory may alias any load
            self._flush(regs, lambda v: bool(self._READS_MEM.search(v)))

    def _op(self, op, i, regs):
        if self.x86:
            if op.type == x86.X86_OP_REG:
                r = self._canon(i.reg_name(op.reg))
                v = regs.get(r, r)
                m = i.mnemonic.lstrip("v")
                if r.startswith("xmm") and neon.is_vec(self, v) and \
                        (m.endswith(("ss", "sd")) or m.startswith(("ucomis", "comis", "cvtts", "cvts"))):
                    t = "f32x4" if m.endswith("ss") or "ss2" in m else "f64x2"   # scalar op: lane 0
                    self.__dict__.setdefault("_vtypes", set()).add(t)
                    v = f"(({t}){v if self._atomic(v) else '(' + v + ')'})[0]"
                return v
            if op.type == x86.X86_OP_IMM:
                return self._imm(op.imm, i)
            if op.type == x86.X86_OP_MEM:
                return self._mem(op, i, regs)
        else:
            if op.type == a64.ARM64_OP_REG:
                raw = i.reg_name(op.reg) or ""
                r = self._canon(raw)
                v = "0" if r in ("wzr", "xzr") else regs.get(r, r)
                if r in ("lr", "x30") and v == r:
                    v = "(int64_t)__builtin_return_address(0)"   # the link register on entry
                elif r in ("fp", "x29") and v == r:
                    v = "(int64_t)__builtin_frame_address(0)"    # the frame pointer
                elif r == "sp" and v == r and i.mnemonic not in ("add", "sub"):
                    v = f"&{self._local(0)}"                    # mov x1, sp: the stack buffer
                if raw[:1] in "bhsd" and raw[1:].isdigit() and neon.is_vec(self, v):
                    # a scalar view (s0, d1) of a register that holds a vector: its lane 0
                    bits = {"b": 8, "h": 16, "s": 32, "d": 64}[raw[0]]
                    k = "f" if bits >= 32 and i.mnemonic.startswith(("f", "scvtf", "ucvtf")) \
                        and i.mnemonic != "fmov" else "u"      # fmov x8, d0 moves bits, not a value
                    t = f"{k}{bits}x{128 // bits}"
                    self.__dict__.setdefault("_vtypes", set()).add(t)
                    v = f"(({t}){v if self._atomic(v) else '(' + v + ')'})[0]"
                return self._shifted(self._extended(v, getattr(op, "ext", 0)), op.shift.type, op.shift.value,
                                     4 if (i.reg_name(op.reg) or "x")[0] == "w" else 8)
            if op.type == a64.ARM64_OP_IMM:
                v = self._imm(op.imm, i)
                return self._shifted(v, op.shift.type, op.shift.value)  # e.g. mov x0, #1, lsl #16
            if op.type == a64.ARM64_OP_FP:
                return repr(op.fp)
            if op.type == a64.ARM64_OP_MEM:
                return self._mem(op, i, regs)
        return "?"

    _EXT = {1: "(uint8_t)", 2: "(uint16_t)", 3: "(uint32_t)", 5: "(int8_t)", 6: "(int16_t)", 7: "(int32_t)"}

    def _extended(self, v, ext):
        """arm64 operand extend (uxtw, sxtb, ...) as a C cast."""
        cast = self._EXT.get(ext)
        return f"{cast}{v}" if cast and " " not in v else (f"{cast}({v})" if cast else v)

    def _shifted(self, v, kind, amount, width=8):
        """arm64 shifted operand (x8, lsl #2) as a C shift, at the register's width: `w9, lsr #1`
        is a 32-bit logical shift, `w9, asr #3` a 32-bit arithmetic one."""
        if not kind or not amount:
            return v
        bits = width * 8
        if kind == 5:  # ROR
            return f"__builtin_rotateright{bits}(({self._utype(bits)}){self._paren(v)}, {amount})"
        if kind == 3:  # LSR
            v = f"({self._utype(bits)}){self._paren(v)}"
        elif kind == 4 and width == 4:  # ASR on a w register
            v = f"(int32_t){self._paren(v)}"
        return self._bin(v, {1: "<<", 3: ">>", 4: ">>", 2: "<<"}.get(kind, "<<"), str(amount))

    def _imm(self, v, i):
        for r in self.arch.data_refs(i, {}):
            s = self.prog.strings().get(r)
            if s is not None and r == v:
                return cstr_lit(s, 40)
        name = self.prog.display(v)
        return cname(name) if name else (hex(v) if abs(v) > 9 else str(v))

    def _mem(self, op, i, regs):
        m = op.mem
        disp = m.disp
        # A plain (non-indexed) reference to a fixed address resolves to its symbol or string. An
        # indexed access is an array/table and is handled below, not as a single symbol.
        if not m.index:
            for r in self.arch.data_refs(i, dict(regs) if not self.x86 else {}):
                s = self.prog.strings().get(r)
                if s is not None:
                    return cstr_lit(s, 40)
                n = self.prog.display(r)
                if n:
                    return cname(n)
        base = self._canon(i.reg_name(m.base)) if m.base else None
        # index register with its scale: x86 [b + i*s + d]; arm64 [b, i, lsl #n] / [b, w, sxtw #n]
        idx, scale = None, 1
        if m.index:
            ireg = self._canon(i.reg_name(m.index))
            idx = regs.get(ireg, ireg)
            if self.x86:
                scale = m.scale or 1
            else:
                idx = self._extended(idx, op.ext)
                if op.shift.type == 1 and op.shift.value:
                    scale = 1 << op.shift.value
        T = self._elem_type(i)
        if base in ("rip", "pc") and idx is None:  # PC-relative data with no symbol: absolute address
            return f"*({T} *){i.address + i.size + disp if base == 'rip' else i.address + disp:#x}"
        if base in ("rbp", "rsp", "sp", "x29", "fp") and idx is None:
            return self._local(disp)
        if base is None and idx is None:
            return f"*({T} *){disp:#x}"
        if idx is not None:                             # possible lookup table: base[idx] in rodata
            tbl = self._lookup_table(base, disp, scale, regs, i, idx)
            if tbl:
                return tbl
        member = self._member(base, disp, regs, idx, scale) if base else None
        if member:
            return member
        return self._deref(T, self._address(self._byte_base(base, regs) if base else None, idx, scale, disp))

    def _const_addr(self, base, regs, i):
        """Numeric address a base register holds, if it is a constant in a data section."""
        if base is None:
            return None
        v = regs.get(base, base)
        if v != base and re.fullmatch(r"&?\w+", v):          # a resolved symbol: &tbl or tbl
            try:
                return self.prog.resolve(v.lstrip("&"))
            except (KeyError, ValueError):
                pass
        for r in self.arch.data_refs(i, dict(regs) if not self.x86 else {}):
            return r                                         # adrp/adr page tracked by data_refs
        return None

    def _lookup_table(self, base, disp, scale, regs, i, idx):
        """`base[idx]` into a lookup table recovered by analysis: inline it as a static C array."""
        info = getattr(self.prog, "value_tables", {}).get(i.address)
        if info is None:
            return None
        tbl, elem, count, signed = info
        ctype = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(elem, "int32_t")
        if not signed:
            ctype = "u" + ctype
        name = self.prog.lookup_table(tbl, elem, count, ctype)
        return f"{name}[{idx}]" if name else None

    _ELEM = {1: "uint8_t", 2: "uint16_t", 4: "int32_t", 8: "int64_t", 16: "__int128"}

    def _elem_type(self, i):
        """C type of the value a memory access moves: by width, float/double through FP regs."""
        w = self._acc_width(i)
        if self._fp_access(i) and w in (4, 8):
            return "float" if w == 4 else "double"
        return self._ELEM.get(w, "int64_t")

    @classmethod
    def _cast_u(cls, v):
        """Unsigned view of a value, for carry/unsigned comparisons."""
        return f"(uint64_t){v}" if cls._atomic(v) else f"(uint64_t)({v})"

    @staticmethod
    def _deref(T, addr):
        """`*(T *)(addr)`: an explicit, typed load/store, as decompilers print it."""
        return f"*({T} *){addr}" if Lifter._atomic(addr) else f"*({T} *)({addr})"

    def _byte_base(self, base, regs):
        """A typed pointer used in byte arithmetic must be cast, or C would scale the offset."""
        v = regs.get(base, base)
        t = self._ptr_type(v)
        if t and t != "char *":
            return f"(char *){v}" if self._atomic(v) else f"(char *)({v})"
        return v

    def _ptr_type(self, v):
        """Pointer type of a variable expression (typed arg, typed copy, or pointer-typed local)."""
        if not re.fullmatch(r"\w+", v or ""):
            return None
        t = self._argtypes.get(v) or self._ptrvars.get(v) or getattr(self, "_temptype", {}).get(v)
        if not t:
            for off, name in self._localname.items():
                if name == v:
                    t = self._localtype.get(off)
                    break
        return t if t and t.endswith("*") else None

    def _address(self, base, idx, scale, disp):
        """C expression for base + idx*scale + disp (any part optional)."""
        terms = []
        if base and base.startswith("&") and (idx is not None or disp):
            base = f"(char *){base}"       # &sym + 8: bytes, not sizeof(sym) units
        if base:
            terms.append(base)
        if idx is not None:
            terms.append(idx if scale == 1 else self._bin(idx, "*", str(scale)))
        e = terms[0] if terms else "0"
        for t in terms[1:]:
            e = self._bin(e, "+", t)
        if disp:
            e = self._bin(e, "+" if disp > 0 else "-", hex(abs(disp))) if terms else hex(disp)
        return e

    def _member(self, base_reg, disp, regs, idx=None, scale=1):
        """Struct/array access when the base is a pointer-typed arg still holding its value:
        `p->field_<off>`, `s[i]` for char* buffers, `p[i]` when the index scale matches the
        element size. None if not applicable."""
        var = regs.get(base_reg, base_reg)
        if var != self._ent(base_reg) or not re.fullmatch(r"\w+", var):
            return None  # base was recomputed in this block: not the typed variable any more
        t = self._argtypes.get(var) or self._ptrvars.get(var)
        if not t or not t.endswith("*"):
            return None
        base_reg = var
        width = {"char *": 1, "short *": 2, "int *": 4, "int64_t *": 8}.get(t)
        if idx is not None:
            if width and scale == width and disp % width == 0:
                i = idx if not disp else self._bin(idx, "+", str(disp // width))
                return f"{base_reg}[{i}]"
            return None
        acc = self._acc_width(self._cur_insn) if getattr(self, "_cur_insn", None) is not None else None
        if t.startswith("struct "):
            fld = getattr(self, "_structs", {}).get(t[7:].rstrip(" *"), {}).get(disp)
            if fld and (acc is None or acc == fld[1]):
                return f"{base_reg}->field_{disp:x}"
            return None                         # a narrower/wider view of a field: explicit deref
        if width and acc == width and disp % width == 0:
            return f"{base_reg}[{disp // width}]" if disp else f"*{base_reg}"
        return None

    def _local(self, disp):
        if disp in self._localname:          # name chosen by type inference
            return self._localname[disp]
        name = self._localname[disp] = f"local_{abs(disp):x}" if disp else "local_0"
        self._localtype.setdefault(disp, "int64_t")
        return name

    @staticmethod
    def _disp(d):
        return "" if not d else (f" + {d:#x}" if d > 0 else f" - {-d:#x}")

    def _canon(self, name):
        """Fold sub-registers to their full name: eax/al -> rax, w0 -> x0, s0/b0/h0 -> d0."""
        if not name:
            return name
        if not self.x86:
            if name[0] == "w" and name[1:].isdigit():
                return "x" + name[1:]
            m = _ARM_FP.fullmatch(name)
            return f"v{m.group(1)}" if m else name
        return _X86_CANON.get(name, name)

    def _cc_expr_x86(self, cmp, suffix):
        if not cmp:
            return "cond"
        return self._flag_cond(cmp[0], cmp[1], _X86_CC.get(suffix, "!="), suffix in _UNSIGNED_CC)

    @classmethod
    def _flag_cond(cls, name, args, op, unsigned=False):
        """C condition for a branch/select using operator `op` after flag-setter `name(args)`.
        Built through _bin so ternary or compound operands get correct parentheses. `unsigned`
        casts the operands (ja/jb..., b.hi/b.lo...) so e.g. `(unsigned)k > 5` catches negatives."""
        lhs = args[0] if args else "?"
        rhs = args[1] if len(args) > 1 else "0"
        sign = op.endswith(" 0")                  # "< 0" / ">= 0": sign test of a result
        rel = op[:-2] if sign else op
        if name in ("test", "tst"):
            e = lhs if len(args) >= 2 and args[0] == args[1] else cls._bin(lhs, "&", rhs)
            return cls._bin(e, rel, "0")              # test x,x compares x itself with zero
        if name == "bt":                              # CF = bit; jb/setb when set
            bit = cls._bin(cls._bin(lhs, ">>", rhs), "&", "1")
            return cls._bin(bit, "!=" if rel in ("<", "!=") else "==", "0")
        if name == "cmn":                             # compares lhs with -rhs
            rhs = rhs[1:] if rhs.startswith("-") else (f"-{rhs}" if cls._atomic(rhs) else f"-({rhs})")
        if sign:                                      # sign test of lhs - rhs
            return cls._bin(lhs if rhs in ("0", "#0") else cls._bin(lhs, "-", rhs), rel, "0")
        if unsigned and rel not in ("==", "!="):      # unsigned comparison: cast both operands
            lhs, rhs = cls._cast_u(lhs), cls._cast_u(rhs)
        return cls._bin(lhs, rel, rhs)

    def _is_frame_noise(self, i):
        """Standard prologue/epilogue bookkeeping that adds nothing to the reconstruction."""
        m, s = i.mnemonic, i.op_str
        if m in ("push", "pop", "leave", "nop", "endbr64", "pacibsp", "autibsp", "retab", "hint"):
            return True
        if m == "mov" and s in ("rbp, rsp", "x29, sp"):
            return True
        if m in ("add", "sub") and ("rsp," in s or "sp," in s and "x29" not in s):
            return True
        if m == "stp" and "[sp" in s and "x29" in s:
            return True
        return False

    def _cc_name(self, i):
        """Condition suffix of a csel-family op (its last mnemonic token or .cc)."""
        for suf in _ARM_CC:
            if i.op_str.rstrip().endswith(suf):
                return suf
        return "ne"

    def _cc_expr(self, cmp, suffix):
        if not cmp:
            return "cond"
        name, args = cmp[0], cmp[1]
        if name in ("cbz", "cbnz"):
            return f"{args[0] if args else '?'} {'==' if name == 'cbz' else '!='} 0"
        return self._flag_cond(name, args, _ARM_CC.get(suffix, "!="), suffix in _UNSIGNED_CC)

    # -- condition rendering ----------------------------------------------
    def _cond_from(self, i, cmp):
        m = i.mnemonic
        if not self.x86 and m in ("cbz", "cbnz", "tbz", "tbnz"):
            # compare-and-branch tests its own operand (the terminator is not stepped, so read it
            # against the block's final register state rather than an earlier compare)
            v = self._op(i.operands[0], i, self._last_regs)
            if m in ("tbz", "tbnz") and len(i.operands) > 1:
                v = f"(({self._int_operand(v)} >> {i.operands[1].imm}) & 1)"   # a bit of a pointer too
            return f"{v} == 0" if m in ("cbz", "tbz") else f"{v} != 0"
        suffix = m[1:] if self.x86 and m.startswith("j") else \
            (m.split(".")[-1] if "." in m else m[1:] if m.startswith("b") else "")
        if cmp is None:
            return "/* cond */ 1"
        return self._flag_cond(cmp[0], cmp[1], (_X86_CC if self.x86 else _ARM_CC).get(suffix, "!="),
                               suffix in _UNSIGNED_CC)

    # -- register read/write facts for arg scan ----------------------------
    def _reads(self, i, name):
        c = self._canon(name)
        if i.mnemonic in ("cmp", "cmn", "tst", "test"):  # capstone misfiles these as writes
            return c in {self._canon(t) for t in self._mentioned(i)}
        try:
            regs_read = i.regs_access()[0]
        except Exception:
            return c in {self._canon(t) for t in self._mentioned(i)}
        return any(self._canon(i.reg_name(r)) == c for r in regs_read)

    def _writes(self, i, name):
        if i.mnemonic in ("cmp", "cmn", "tst", "test"):
            return False  # capstone lists the compared reg as "written"; it only sets flags
        try:
            regs_written = i.regs_access()[1]
        except Exception:
            return False
        return any(self._canon(i.reg_name(r)) == self._canon(name) for r in regs_written)

    def _mentioned(self, i):
        return [tok.strip(",[]!") for tok in i.op_str.replace(",", " ").split() if tok[:1].isalpha()]

    def _target_reg(self, i):
        return self._canon(i.reg_name(i.operands[-1].reg)) if i.operands else "?"
