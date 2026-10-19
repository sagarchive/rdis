"""IR lifter: P-code-shaped ops (ir_front) -> symbolic expressions -> C statements.

Drop-in for lift.Lifter behind the Decompiler: same signature/block/condition/ret/indirect
interface, so the existing structurer (loops, if/else, switch, gotos) is reused unchanged. What the
IR adds over the per-ISA pattern lifter:

* Architecture-independent handling of the operations emitted by the configured P-code frontend (or native MIPS/RISC-V frontend), so a branch
  condition is represented as the expression the frontend emits; supported languages and instruction coverage remain frontend-dependent.
* Stack frame recovery: the stack pointer is tracked as `entry_sp + k` across blocks, sp-relative
  accesses become named locals, callee-saved spills/restores disappear.
* Struct recovery: per-parameter field accesses become a `struct` with typed fields, merged across
  calls that pass the pointer on (`p->f_8` in both caller and callee, one declaration).

Expressions are tuples:
  ("c", value, size)  ("v", name, size)  ("sp", offset)  ("ld", addr, size)
  ("op", cop, a, b, size)  ("u", cop, a, size)  ("cast", ctype, a, size)  ("call", text, size)
"""
import re

from .arch import CALL, RET, JMP, CJMP, IJMP
from . import ir_front
from .lift import cstr_lit

_BINOP = {"INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*", "INT_DIV": "/", "INT_SDIV": "/",
          "INT_REM": "%", "INT_SREM": "%", "INT_AND": "&", "INT_OR": "|", "INT_XOR": "^",
          "INT_LEFT": "<<", "INT_RIGHT": ">>", "INT_SRIGHT": ">>", "INT_EQUAL": "==",
          "INT_NOTEQUAL": "!=", "INT_LESS": "<", "INT_SLESS": "<", "INT_LESSEQUAL": "<=",
          "INT_SLESSEQUAL": "<=", "BOOL_AND": "&&", "BOOL_OR": "||", "BOOL_XOR": "!=",
          "FLOAT_ADD": "+", "FLOAT_SUB": "-", "FLOAT_MULT": "*", "FLOAT_DIV": "/",
          "FLOAT_EQUAL": "==", "FLOAT_NOTEQUAL": "!=", "FLOAT_LESS": "<", "FLOAT_LESSEQUAL": "<="}
_UNSIGNED = {"INT_DIV", "INT_REM", "INT_RIGHT", "INT_LESS", "INT_LESSEQUAL"}
_CMP = {"==", "!=", "<", "<=", ">", ">="}
_NEG = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<="}
_PREC = {"*": 10, "/": 10, "%": 10, "+": 9, "-": 9, "<<": 8, ">>": 8, "<": 7, "<=": 7, ">": 7,
         ">=": 7, "==": 6, "!=": 6, "&": 5, "^": 4, "|": 3, "&&": 2, "||": 1}
_INT = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t", 16: "__int128"}
_SINT = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t", 16: "__int128"}
_UINT = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t", 16: "unsigned __int128"}

# registers that are machinery, not program variables
_MACHINE = {"sp", "pc", "ra", "gp", "zero", "lr", "rsp", "rip", "esp", "eip", "x30", "isamodeswitch",
            "tmode", "isetstate", "contextreg", "xzr", "wzr"}
_CALLEE_SAVED = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "fp",
                 "ra", "gp", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "lr"}
_CALLER_SAVED = re.compile(r"(a|t|v|ft|fa)\d+|at|hi|lo|r[0-3]|r12")


def _mask(v, size):
    return v & ((1 << (8 * size)) - 1) if size else v


def _signed(v, size):
    v = _mask(v, size)
    return v - (1 << (8 * size)) if size and v >> (8 * size - 1) else v


def _size(e):
    t = e[0]
    if t in ("c", "v", "ld"):
        return e[2]
    if t == "sp":
        return 8
    if t in ("op",):
        return e[4]
    if t in ("u", "cast"):
        return e[3]
    if t == "call":
        return e[2]
    if t == "tern":
        return e[4]
    return 8


def _is_cmp(e):
    return (e[0] == "op" and e[1] in _CMP) or (e[0] == "u" and e[1] == "!")


def _refs(e, name):
    """Does expression `e` read variable `name`?"""
    if e[0] == "v":
        return e[1] == name
    return any(isinstance(x, tuple) and _refs(x, name) for x in e[1:])


def _has_load(e):
    if e[0] in ("ld", "call"):
        return True
    return any(isinstance(x, tuple) and _has_load(x) for x in e[1:])


def mk(op, a, b, size):
    """Build a binary expression, simplifying as we go (constant folding and the identities that
    compilers' lowering leaves behind: x+0, x^x, (a-b)==0, sp arithmetic ...)."""
    c = _BINOP[op] if op in _BINOP else op
    if a[0] == "c" and b[0] == "c" and op.startswith("INT") and a[2] > 0 and b[2] > 0:
        ux, uy = _mask(a[1], a[2]), _mask(b[1], b[2])
        sx, sy = _signed(ux, a[2]), _signed(uy, b[2])
        shift = uy
        width = 8 * a[2]
        def trunc_div(x, y):
            if y == 0:
                return None
            q = abs(x) // abs(y)
            return -q if (x < 0) != (y < 0) else q
        try:
            v = {
                "INT_ADD": ux + uy, "INT_SUB": ux - uy, "INT_MULT": ux * uy,
                "INT_AND": ux & uy, "INT_OR": ux | uy, "INT_XOR": ux ^ uy,
                # P-code shifts use the full unsigned shift amount. Masking it by 63 is
                # incorrect for 32-bit operands shifted by 32 or 64.
                "INT_LEFT": 0 if shift >= width else ux << shift,
                "INT_RIGHT": 0 if shift >= width else ux >> shift,
                "INT_SRIGHT": (-1 if sx < 0 else 0) if shift >= width else sx >> shift,
                "INT_EQUAL": int(ux == uy), "INT_NOTEQUAL": int(ux != uy),
                "INT_LESS": int(ux < uy), "INT_SLESS": int(sx < sy),
                "INT_LESSEQUAL": int(ux <= uy), "INT_SLESSEQUAL": int(sx <= sy),
                "INT_DIV": (ux // uy) if uy else None,
                "INT_REM": (ux % uy) if uy else None,
                "INT_SDIV": trunc_div(sx, sy),
                "INT_SREM": (sx - trunc_div(sx, sy) * sy) if sy else None,
            }.get(op)
        except (ArithmeticError, OverflowError, ValueError):
            v = None
        if v is not None:
            return ("c", _mask(v, size), size)
    if a[0] == "sp" and b[0] == "c" and op in ("INT_ADD", "INT_SUB"):
        d = _signed(b[1], b[2])
        return ("sp", a[1] + (d if op == "INT_ADD" else -d))
    if a[0] == "sp" and op == "INT_AND":           # stack realignment: keep the frame base
        return a
    if b[0] == "c":
        bv = _signed(b[1], b[2])
        if bv == 0 and op in ("INT_ADD", "INT_SUB", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT"):
            return a
        if bv == 1 and op in ("INT_MULT", "INT_DIV", "INT_SDIV"):
            return a
        if bv == 0 and op in ("INT_MULT", "INT_AND"):
            return ("c", 0, size)
        if _mask(b[1], size) == _mask(-1, size) and op == "INT_AND" and _size(a) <= size:
            return a
        if op in ("INT_ADD", "INT_SUB") and a[0] == "op" and a[1] in ("+", "-") and a[3][0] == "c":
            k = _signed(a[3][1], a[3][2]) * (1 if a[1] == "+" else -1) + (bv if op == "INT_ADD" else -bv)
            return mk("INT_ADD", a[2], ("c", _mask(k, size), size), size)
        if op in ("INT_EQUAL", "INT_NOTEQUAL") and bv == 0:
            if a[0] == "op" and a[1] == "-":              # (x - y) == 0  ->  x == y
                return ("op", "==" if op == "INT_EQUAL" else "!=", a[2], a[3], 1)
            if _is_cmp(a):
                return a if op == "INT_NOTEQUAL" else negate(a)
        if op == "INT_ADD" and bv < 0:
            return ("op", "-", a, ("c", -bv, size), size)
    if a[0] == "c" and op in ("INT_ADD", "INT_OR", "INT_XOR", "INT_AND", "INT_MULT", "INT_EQUAL", "INT_NOTEQUAL"):
        return mk(op, b, a, size)                    # constants on the right
    if a == b and op in ("INT_XOR", "INT_SUB"):
        return ("c", 0, size)
    if a == b and op in ("INT_EQUAL",):
        return ("c", 1, 1)
    if op in _UNSIGNED and op not in ("INT_RIGHT",) or (op == "INT_RIGHT" and _size(a) < 8):
        a = ("c", a[1], a[2], "u") if a[0] == "c" else mkcast(_UINT.get(_size(a), "uint64_t"), a, _size(a))
        b = ("c", b[1], b[2], "u") if b[0] == "c" else mkcast(_UINT.get(_size(b), "uint64_t"), b, _size(b))
    if op in ("BOOL_AND", "BOOL_OR") and a[0] == "c":
        return b if (a[1] != 0) == (op == "BOOL_AND") else a
    return ("op", c, a, b, 1 if c in _CMP or c in ("&&", "||") else size)


def mkcast(ctype, a, size):
    """(T)a, collapsing cast chains: narrowing a widened value narrows the original directly."""
    if a[0] == "c":
        return ("c", _mask(a[1], size), size)
    while a[0] == "cast" and size <= a[3] and _size(a[2]) >= size:   # (T8)(T32)x keeps the trunc
        a = a[2]
    if a[0] == "cast" and a[1] == ctype:
        return a
    if _size(a) == size and (a[0] != "cast" or a[1] == ctype):
        return a if ctype.startswith("int") or a[0] == "c" else ("cast", ctype, a, size)
    return ("cast", ctype, a, size)


_MIRROR = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def negate(e):
    if e[0] == "op" and e[1] in _NEG:
        return ("op", _NEG[e[1]], e[2], e[3], 1)
    if e[0] == "u" and e[1] == "!":
        return e[2]
    if e[0] == "op" and e[1] in ("&&", "||"):
        return ("op", "||" if e[1] == "&&" else "&&", negate(e[2]), negate(e[3]), 1)
    if e[0] == "c":
        return ("c", int(not e[1]), 1)
    return ("u", "!", e, 1)


_LIBC_ARGC = {"puts": 1, "strlen": 1, "malloc": 1, "free": 1, "exit": 1, "_exit": 1, "abort": 0,
              "memcpy": 3, "memmove": 3, "memset": 3, "memcmp": 3, "strcmp": 2, "strncmp": 3,
              "strcpy": 2, "strncpy": 3, "strcat": 2, "strchr": 2, "strrchr": 2, "strstr": 2,
              "strdup": 1, "atoi": 1, "atol": 1, "strtol": 3, "strtoul": 3, "getenv": 1, "calloc": 2,
              "realloc": 2, "perror": 1, "close": 1, "read": 3, "write": 3, "open": 3, "fopen": 2,
              "fclose": 1, "fread": 4, "fwrite": 4, "fgets": 3, "fputs": 2, "putchar": 1, "getchar": 0,
              "stack_chk_fail": 0, "cxa_finalize": 1, "cxa_atexit": 3, "time": 1, "sleep": 1,
              "usleep": 1, "rand": 0, "srand": 1, "pthread_mutex_lock": 1, "pthread_mutex_unlock": 1}


def _global_pointer(prog):
    """The ABI global pointer (gp) value, so `gp - 0x7b0` folds to an address: from the
    `__global_pointer$` / `_gp` symbol, else what the entry stub loads into gp, else MIPS .got+0x7ff0."""
    if "_ir_gp" in prog.__dict__:
        return prog._ir_gp
    gp = next((a for a, n in prog.image.symbols.items() if n in ("__global_pointer$", "_gp")), None)
    if gp is None and prog.image.entry in prog.functions:
        front, vals = ir_front.frontend(prog.arch), {}
        a, hops = prog.image.entry, 0
        for _ in range(24):                       # `auipc gp, hi; addi gp, gp, lo` / `lui gp; addiu gp`
            i = prog.insn(a)
            if i is None or front is None:
                break
            for op, o, ins in front.translate(prog.image.read(a, 16), a)[0] or []:
                if o is None or o[0] not in ("reg", "tmp"):
                    continue
                v = [x[1] if x[0] == "const" else vals.get(x[:2]) for x in ins]
                r = None
                if op == "COPY" and v and v[0] is not None:
                    r = v[0]
                elif op in _BINOP and len(v) == 2 and None not in v:   # fold with the IR simplifier
                    e = mk(op, ("c", v[0], ins[0][2]), ("c", v[1], ins[1][2]), o[2])
                    r = e[1] if e[0] == "c" else None
                if r is not None:
                    vals[o[:2]] = r
                else:
                    vals.pop(o[:2], None)
            gp = vals.get(("reg", "gp"))
            if gp is not None:
                break
            t = prog.call_target(i, {}) if prog.arch.kind(i) == CALL else None
            if t is not None and hops == 0 and t in prog.functions:
                a, hops = t, 1                  # the entry's first call is load_gp on RISC-V
                continue
            if prog.arch.kind(i) in (CALL, RET, JMP):
                break
            a += i.size
    if gp is None and prog.arch.name.startswith("mips"):
        got = next((s for s in prog.image.sections if s.name == ".got"), None)
        gp = got.va + 0x7ff0 if got else None
    prog._ir_gp = gp
    return gp


class IRLifter:
    TEMP = "u"   # temp-variable prefix (MIPS/RISC-V own the t0..t9 register names)

    def __init__(self, prog):
        self.prog, self.arch = prog, prog.arch
        self.front = ir_front.frontend(self.arch)
        self.w = self.arch.bits // 8
        self._pcode = {}            # (addr, thumb) -> (ops, covered)
        self.live_out = self.entry_names = self.def_names = None
        self._temps, self._ptrvars, self._locals = set(), {}, {}
        self._expr_types = {}
        self._last_regs, self._bstate = {}, {}
        self._ret_void, self._ret_fp = False, False
        self._tn = 0
        self._collect, self.params, self.func, self._sp, self._saves = None, [], None, {}, set()
        self._cur, self._cur_sp, self._slots, self._out, self._env_end = None, 0, {}, [], {}
        self._gp_now, self._consts, self._defs = None, {}, None
        self.gp = _global_pointer(prog) if self.front else None
        self.structs = getattr(prog, "_ir_structs", None)
        if self.structs is None:
            self.structs = prog._ir_structs = StructDB(self.w)

    @staticmethod
    def supports(arch):
        return ir_front.frontend(arch) is not None

    def canonical_ir(self, func=None):
        """Return validated, provenance-preserving IR for a function without changing C output.

        This exposes the new IR contract to test harnesses and analysis tools while keeping the
        legacy structurer/decompiler as the default until the new pipeline passes semantic gates.
        """
        from .ir_model import build_function_ir
        target = func or self.func
        if target is None:
            raise ValueError("canonical_ir requires a function")
        return build_function_ir(self.prog, target, self.front)

    # -- per-instruction ops ------------------------------------------------
    def _thumb(self, i):
        return self.arch.name == "arm" and self.prog._insns.get((i.address, True)) is i

    def ops(self, i):
        key = (i.address, self._thumb(i))
        if key not in self._pcode:
            code = self.prog.image.read(i.address, 16)
            ops, cov = self.front.translate(code, i.address, key[1])
            self._pcode[key] = (ops if ops is not None else [("ASM", None, [f"{i.mnemonic} {i.op_str}"])], cov)
        return self._pcode[key]

    def _canon(self, r):
        return r.lower().lstrip("$")

    def _rw(self, i):
        rd, wr = set(), set()
        for op, out, ins in self.ops(i)[0]:
            for v in ins:
                if v[0] == "reg":
                    r = self._canon(v[1])
                    if r not in wr:
                        rd.add(r)
            if out is not None and out[0] == "reg":
                wr.add(self._canon(out[1]))
        return rd - _MACHINE, wr - _MACHINE

    def _insns(self, b):
        """Instructions to lift, skipping ones a previous translation already covered (delay slots
        of calls inside the block)."""
        skip = set()
        for i in b.insns:
            if i.address in skip:
                continue
            ops, cov = self.ops(i)
            skip.update(c for c in cov if c != i.address)
            yield i

    # -- liveness (delay-slot aware, op-level) -----------------------------
    def liveness(self, func, returns):
        from .decompile import _UNTRACKED
        arch, B = self.arch, func.blocks
        allargs = {self._canon(r) for r in arch.args} | {self._canon(r) for r in arch.fargs}
        rets = {self._canon(arch.ret)} | ({self._canon(arch.fret)} if arch.fret else set())
        use, defs = {}, {}
        for a, b in B.items():
            u, d = set(), set()
            for i in self._insns(b):
                rd, wr = self._rw(i)
                if arch.kind(i) == CALL:
                    argc, fargc = self._callee_argc(self.prog.call_target(i, {}))
                    rd = rd | ({self._canon(r) for r in arch.args[:max(argc, 0)]} - wr)
                    wr = wr | allargs | rets
                u |= (rd - _UNTRACKED) - d
                d |= wr - _UNTRACKED
            if not b.insns or arch.kind(b.insns[-1]) == RET or not [s for s in b.succs if s in B]:
                u |= returns - d
            use[a], defs[a] = u, d
        live_in = {a: set() for a in B}
        live_out = {a: set() for a in B}
        changed = True
        while changed:
            changed = False
            for a in sorted(B, reverse=True):
                out = set().union(*(live_in[s] for s in B[a].succs if s in B))
                inn = use[a] | (out - defs[a])
                if out != live_out[a] or inn != live_in[a]:
                    live_out[a], live_in[a] = out, inn
                    changed = True
        return live_in, live_out, defs

    # -- calls ------------------------------------------------------------
    def _callee_argc(self, t):
        """(int args, float args) of the function at `t`: argument registers live at its entry."""
        if t is None:
            return -1, 0            # indirect: decided at the call site from the registers set
        cache = self.prog._argc_cache
        key = ("ir", t)
        if key in cache:
            return cache[key]
        cache[key] = (len(self.arch.args) if t in self.prog.image.imports or t not in self.prog.functions
                      else 0, 0)            # provisional (recursion), refined below
        f = self.prog.functions.get(t)
        if f is not None and f.addr in f.blocks and (self._variadic(f) or self._tail_stub(f)):
            cache[key] = (-1, 0)    # printf-like: the caller's set registers say how many
            return cache[key]
        if f is not None and f.addr in f.blocks:
            try:
                live_in, _, _ = IRLifter(self.prog).liveness(f, set())
                live = live_in.get(f.addr, set())
                n = 0
                for k, r in enumerate(self.arch.args):
                    if self._canon(r) in live:
                        n = k + 1
                cache[key] = (n, 0)
            except Exception:
                pass
        else:
            name = (self.prog.display(t) or "").lstrip("_").split("@")[0]
            cache[key] = (_LIBC_ARGC.get(name, -1), 0)   # -1: decide at the call site
        return cache[key]

    def _set_args(self, env):
        n = 0
        for k, r in enumerate(self.arch.args):
            if self._canon(r) in env:
                n = k + 1
        return n

    def _tail_stub(self, f):
        """A small function that ends in an indirect jump out (PLT/GOT trampoline, MIPS `jr $t9`)."""
        return len(f.blocks) <= 3 and any(b.insns and self.arch.kind(b.insns[-1]) == IJMP and
                                          not [s for s in b.succs if s in f.blocks] for b in f.blocks.values())

    def _variadic(self, f):
        """A variadic prologue spills the last argument register into the va save area."""
        last = self._canon(self.arch.args[-1])
        from .arch import mem_operand
        for i in f.blocks[f.addr].insns:
            mem, ops = mem_operand(i), i.operands
            if mem and i.mnemonic.removeprefix("c.").startswith("s") and ops[0].type == 1 \
                    and self._canon(i.reg_name(ops[0].reg)) == last and self._canon(i.reg_name(mem[0])) == "sp":
                return True
        return False

    # -- function-level setup ---------------------------------------------
    def signature(self, func, name):
        from .decompile import webs
        self.func = func
        self._expr_types = {}
        self._sp = self._sp_deltas(func)
        self._saves = set()
        rt = self._returns(func)
        returns = set() if rt is None else {self._canon(self.arch.ret)}
        self._ret_void = rt is None
        live_in, self.live_out, defs = self.liveness(func, returns)
        self.entry_names, self.def_names = webs(func, live_in, self.live_out, defs)
        live = live_in.get(func.addr, set())
        argc = 0
        for k, r in enumerate(self.arch.args):
            if self._canon(r) in live:
                argc = k + 1
        self.params = [self._canon(r) for r in self.arch.args[:argc]]
        self._entry_vals = set(self.entry_names.get(func.addr, {}).values()) | {"ra"}
        # pass 1: lift every block silently to collect field accesses and callee links
        self._collect = {"acc": [], "links": [], "types": []}
        self._defs = {}
        for a in sorted(func.blocks):
            try:
                self.block(func.blocks[a])
            except Exception:
                pass
        for r, off, size in self._collect["acc"]:
            if r in self.params:
                self.structs.access((func.addr, self.params.index(r)), off, size)
        for r, off, ctype in self._collect["types"]:
            if r in self.params:
                self.structs.access_type((func.addr, self.params.index(r)), off, ctype)
        for r, callee, k in self._collect["links"]:
            if r in self.params:
                self._scan_callee(callee)
                self.structs.link((func.addr, self.params.index(r)), (callee, k))
        self._consts = {d: es[0] for d, es in self._defs.items()
                        if len(es) == 1 and es[0][0] == "c" and d not in self.params}
        self._defs = None
        self._collect = None
        self._temps, self._locals, self._bstate, self._tn = set(), {}, {}, 0
        self._ptrvars = {}
        ptypes = []
        for k, r in enumerate(self.params):
            st = self.structs.name((func.addr, k))
            t = f"struct {st} *" if st else _SINT[self.w]
            if st:
                self._ptrvars[r] = t
                self._sig_structs = getattr(self, "_sig_structs", set()) | {st}
            ptypes.append(f"{t}{'' if t.endswith('*') else ' '}{r}")
        ret_t = "void" if rt is None else _SINT[self.w]
        return f"{ret_t} {name}({', '.join(ptypes) or 'void'})"

    def _scan_callee(self, t):
        """Collect a callee's own parameter field accesses once (depth 1), so struct layouts merge
        across a call that passes the pointer on."""
        done = self.prog.__dict__.setdefault("_ir_scanned", set())
        if t in done or t not in self.prog.functions:
            return
        done.add(t)
        try:
            sub = IRLifter(self.prog)
            sub.signature(self.prog.functions[t], "f")
        except Exception:
            pass

    def _sp_deltas(self, func):
        """Stack-pointer offset from its entry value at each block start (forward propagation)."""
        out, work = {func.addr: 0}, [func.addr]
        while work:
            a = work.pop()
            b = func.blocks.get(a)
            if b is None:
                continue
            sp = ("sp", out[a])
            env = {}
            for i in self._insns(b):
                for op, o, ins in self.ops(i)[0]:
                    if o is None:
                        continue
                    vals = [env.get(v, sp if v[0] == "reg" and self._canon(v[1]) == "sp" else v) for v in ins]
                    if op == "COPY":
                        val = vals[0]
                    elif op in ("INT_ADD", "INT_SUB", "INT_AND") and vals[0][0] == "sp" and vals[1][0] == "const":
                        val = mk(op, vals[0], ("c", vals[1][1], vals[1][2]), self.w)
                    else:
                        val = None
                    if o[0] == "reg" and self._canon(o[1]) == "sp":
                        if val is not None and val[0] == "sp":
                            sp = val
                    elif val is not None:
                        env[o] = val
            for s in b.succs:
                if s not in out:
                    out[s] = sp[1]
                    work.append(s)
        return out

    def _returns(self, func):
        """None for void, else the return register's width. Searching backwards from each return
        over all predecessors: non-void when some path's last write of the return register is an
        ordinary instruction, or a call to a non-void callee / import."""
        ret = self._canon(self.arch.ret)
        cache = self.prog._ret_use_cache
        key = ("ir", func.addr)
        if key in cache:
            return cache[key]
        cache[key] = None                       # provisional: recursion through a cycle is void
        preds = {a: [] for a in func.blocks}
        for b in func.blocks.values():
            for s in b.succs:
                if s in preds:
                    preds[s].append(b.addr)
        work = [b.addr for b in func.blocks.values() if b.insns and self.arch.kind(b.insns[-1]) == RET]
        seen = set(work)
        while work:
            b = func.blocks[work.pop()]
            verdict = None
            for i in reversed(list(self._insns(b))):
                if self.arch.kind(i) == CALL:
                    t = self.prog.call_target(i, {})
                    f = self.prog.functions.get(t)
                    if f is not None and f is not func:
                        verdict = IRLifter(self.prog)._returns(f) is not None
                    else:
                        verdict = t in self.prog.image.imports
                    break
                if ret in self._rw(i)[1]:
                    verdict = True
                    break
            if verdict:
                cache[key] = self.w
                return self.w
            if verdict is None:                 # no write here: keep looking upstream
                for p in preds[b.addr]:
                    if p not in seen:
                        seen.add(p)
                        work.append(p)
        return None

    # -- block lifting ----------------------------------------------------
    def _new_temp(self, size):
        self._tn += 1
        n = f"{self.TEMP}{self._tn}"
        self._temps.add(n)
        self._ptrvars.setdefault(n, _SINT.get(size, "int64_t"))
        return n

    def _leaf(self, r, size):
        if r == "zero":
            return ("c", 0, size)
        if r == "gp" and self.gp is not None:
            return ("c", self.gp, self.w)
        name0 = (self.entry_names or {}).get(self._cur, {}).get(r, r)
        if name0 in self._consts:
            return self._consts[name0]
        if r == "t9" and self.arch.name.startswith("mips") and self.func is not None \
                and (self.entry_names or {}).get(self._cur, {}).get("t9", "t9") == "t9":
            return ("c", self.func.addr, self.w)   # o32/n64 PIC: $t9 holds the callee's own address
        if r == "sp":
            return ("sp", self._cur_sp)
        name = (self.entry_names or {}).get(self._cur, {}).get(r, r)
        return ("v", name, size)

    def _read(self, v, env, tmp):
        kind = v[0]
        if kind == "const":
            return ("c", _mask(v[1], v[2]) if isinstance(v[1], int) else 0, v[2])
        if kind == "tmp":
            return tmp.get(v[1], ("c", 0, v[2]))
        if kind == "ram":
            return ("ld", ("c", v[1], self.w), v[2])
        r = self._canon(v[1])
        e = env.get(r)
        if e is None:                                   # GPRs are full width: a narrower read truncates
            e = self._leaf(r, self.w if v[2] <= self.w and not r.startswith("f") else v[2])
        if _size(e) > v[2] and e[0] != "sp":            # sub-register read (eax of rax, addiw's a0:4)
            e = mkcast(_SINT.get(v[2], "int64_t"), e, v[2])
        return e

    def _write(self, v, val, env, tmp):
        if v[0] == "tmp":
            tmp[v[1]] = val
        elif v[0] == "reg":
            r = self._canon(v[1])
            if r == "sp" and val[0] == "sp":
                self._cur_sp = val[1]
            elif r != "zero":
                env[r] = val
                if r == "gp" and val[0] == "c":
                    self._gp_now = val[1]
        elif v[0] == "ram":
            self._store(("c", v[1], self.w), val, v[2])

    def _flush_loads(self, env, tmp):
        """Before a store or call: pin pending values that read memory into temps (ordering)."""
        for d in (env, tmp):
            for k, e in list(d.items()):
                if _has_load(e) and e[0] != "v":
                    n = self._new_temp(_size(e))
                    self._out.append(f"{n} = {self.render(e)};")
                    d[k] = ("v", n, _size(e))

    def _store(self, addr, val, size, type_hint=None):
        if addr[0] == "sp" and val[0] == "c" and val[1] in (self.gp, self._gp_now):
            return                                   # MIPS .cprestore of gp
        if addr[0] == "sp":
            if val[0] == "v" and val[1] in _CALLEE_SAVED and val[1] in self._entry_vals:   # spill
                self._saves.add(addr[1])     # prologue spill of a callee-saved register: noise
                self._slots[addr[1]] = val
                return
            self._slots[addr[1]] = val
        self._note_access(addr, size, type_hint)
        self._out.append(f"{self._lvalue(addr, size)} = {self.render(val)};")

    def _note_access(self, addr, size, type_hint=None):
        if self._collect is None:
            return
        base, off = self._base_off(addr)
        if base is not None:
            self._collect["acc"].append((base, off, size))
            if type_hint:
                self._collect["types"].append((base, off, type_hint))

    def _note_expr_type(self, expr, type_hint):
        """Record type constraints on recovered fields when an expression reveals its use."""
        if self._collect is None or not type_hint:
            return
        seen = set()
        def visit(node):
            if not isinstance(node, tuple) or not node or id(node) in seen:
                return
            seen.add(id(node))
            if node[0] == "ld" and len(node) >= 3:
                base, off = self._base_off(node[1])
                if base is not None:
                    self._collect["types"].append((base, off, type_hint))
            for item in node[1:]:
                if isinstance(item, tuple):
                    visit(item)
        visit(expr)

    @staticmethod
    def _base_off(addr):
        if addr[0] == "v":
            return addr[1], 0
        if addr[0] == "op" and addr[1] in ("+", "-") and addr[2][0] == "v" and addr[3][0] == "c":
            k = _signed(addr[3][1], addr[3][2])
            return addr[2][1], (k if addr[1] == "+" else -k)
        return None, 0

    def _got(self, a):
        secs = self.prog.__dict__.setdefault("_ir_got", [s for s in self.prog.image.sections
                                                          if s.name in (".got", ".got.plt", "__got")])
        if not any(s.va <= a < s.va + s.size for s in secs):
            return None
        im = self.prog.image
        v = im.fixups.get(a) or int.from_bytes(im.read(a, self.w), "little")
        return v or None

    def _local(self, off, size):
        name = f"var_{-off:x}" if off < 0 else f"arg_{off:x}"
        self._locals[name] = max(self._locals.get(name, 0), size)
        return name

    def _lvalue(self, addr, size):
        if addr[0] == "sp":
            return self._local(addr[1], size)
        base, off = self._base_off(addr)
        if base is not None and base in self.params and self.func is not None:
            st = self.structs.name((self.func.addr, self.params.index(base)))
            if st:
                return f"{base}->{self.structs.field(st, off, size)}"
        if addr[0] == "c":
            n = self.prog.display(addr[1])
            if n:
                return n
            return f"*({_INT.get(size, 'int64_t')} *){addr[1]:#x}"
        return f"*({_INT.get(size, 'int64_t')} *)({self.render(addr)})"

    def block(self, b):
        self._cur = b.addr
        self._cur_sp = getattr(self, "_sp", {}).get(b.addr, 0)
        self._slots = {}
        env, tmp, out = {}, {}, []
        self._out = out
        state = {"cond": None, "ret": None, "tail": None, "ijmp": None}
        for i in self._insns(b):
            self._lift_insn(i, env, tmp, state)
        self._env_end = env
        self._last_regs = {k: self.render(v) for k, v in env.items()}
        if state["tail"] is None and state["ret"] is None:
            done = self._materialize(b, env)
            for k in ("cond", "ijmp"):
                if state[k] is not None and done:
                    state[k] = _replace(state[k], done)
        state["env"] = env
        self._bstate[b.addr] = state
        return out

    def _lift_insn(self, i, env, tmp, state):
        ops = self.ops(i)[0]
        if any(op in ("CBRANCH", "BRANCH") and ins and ins[0][0] == "const" for op, _, ins in ops):
            return self._lift_forked(i, ops, env, tmp, state)
        for op, o, ins in ops:
            self._op(i, op, o, ins, env, tmp, state)

    def _lift_forked(self, i, ops, env, tmp, state):
        """P-code that branches inside one instruction (MIPS movn/movz/teq, RISC-V div/rem guards,
        ARM conditional execution): run every path, then merge — registers become `c ? a : b`,
        side effects run under `if (c)`. Path count is bounded (budget)."""
        TRUE, base_out, paths, emitted = ("c", 1, 1), self._out, [], []

        def run(k, cond, env2, tmp2, out2, budget):
            while k < len(ops):
                op, o, ins = ops[k]
                if op in ("CBRANCH", "BRANCH") and ins and ins[0][0] == "const":
                    rel = _signed(ins[0][1], ins[0][2] or 8)
                    if op == "BRANCH" or rel <= 0:
                        k = k + rel if rel > 0 else len(ops)     # never loop inside an instruction
                        continue
                    self._out = out2
                    c = self._read(ins[1], env2, tmp2)
                    emitted.append((cond, list(out2)))
                    out2.clear()
                    if budget > 0:
                        run(k + rel, mk("BOOL_AND", cond, c, 1), dict(env2), dict(tmp2), [], budget - 1)
                    cond = mk("BOOL_AND", cond, negate(c), 1)
                    k += 1
                    continue
                self._out = out2
                self._op(i, op, o, ins, env2, tmp2, state)
                k += 1
            emitted.append((cond, out2))
            paths.append((cond, env2))

        run(0, TRUE, dict(env), dict(tmp), [], 4)
        self._out = base_out
        for cond, lines in emitted:
            if not lines:
                continue
            if cond[0] == "c" and cond[1]:
                base_out.extend(lines)
            elif not (cond[0] == "c"):
                base_out.append(f"if ({self.render(cond)}) {{ {' '.join(lines)} }}")
        keys = set().union(*(pe.keys() for _, pe in paths)) if paths else set()
        for k in keys:
            vals = [pe.get(k) or env.get(k) or self._leaf(k, self.w) for _, pe in paths]
            if all(v == vals[0] for v in vals):
                env[k] = vals[0]
                continue
            v = vals[-1]
            for (cond, _), pv in zip(reversed(paths[:-1]), reversed(vals[:-1])):
                v = ("tern", cond, pv, v, _size(pv))
            env[k] = v

    def _op(self, i, op, o, ins, env, tmp, state):
        if op == "IMARK":
            return
        if op == "COPY":
            self._write(o, self._read(ins[0], env, tmp), env, tmp)
        elif op == "LOAD":
            addr = self._read(ins[0], env, tmp)
            if addr[0] == "sp" and addr[1] in self._slots:
                val = self._slots[addr[1]]
            elif addr[0] == "sp" and addr[1] in self._saves:
                return                        # restore of a spilled callee-saved register
            elif addr[0] == "c" and o[2] == self.w and self._got(addr[1]) is not None:
                val = ("c", self._got(addr[1]), self.w)   # GOT slot: a constant pointer
            else:
                # If the value came from a field and is now used as an address, that field is pointer-like.
                self._note_expr_type(addr, "pointer")
                self._note_access(addr, o[2])
                val = ("ld", addr, o[2]) if addr[0] != "sp" else ("v", self._local(addr[1], o[2]), o[2])
            self._write(o, val, env, tmp)
        elif op == "STORE":
            addr = self._read(ins[0], env, tmp)
            val = self._read(ins[1], env, tmp)
            self._flush_loads(env, tmp)
            self._store(addr, val, ins[1][2], self._expr_types.get(val))
        elif op in _BINOP:
            a, b2 = self._read(ins[0], env, tmp), self._read(ins[1], env, tmp)
            hint = ("float" if o[2] == 4 else "double") if op.startswith("FLOAT_") else (
                "signed" if op in {"INT_SDIV", "INT_SREM", "INT_SRIGHT", "INT_SLESS", "INT_SLESSEQUAL"} else
                "unsigned" if op in {"INT_DIV", "INT_REM", "INT_RIGHT", "INT_LESS", "INT_LESSEQUAL"} else None)
            if hint:
                self._note_expr_type(a, hint)
                self._note_expr_type(b2, hint)
            value = mk(op, a, b2, o[2])
            if hint in {"float", "double"}:
                self._expr_types[value] = hint
            self._write(o, value, env, tmp)
        elif op in ("INT_ZEXT", "INT_SEXT"):
            a = self._read(ins[0], env, tmp)
            self._note_expr_type(a, "signed" if op == "INT_SEXT" else "unsigned")
            if a[0] == "c":
                v = _signed(a[1], a[2]) if op == "INT_SEXT" else a[1]
                val = ("c", _mask(v, o[2]), o[2])
            elif _is_cmp(a) or a[0] == "sp":
                val = a
            else:
                val = mkcast((_SINT if op == "INT_SEXT" else _UINT).get(o[2], "int64_t"), a, o[2])
            self._write(o, val, env, tmp)
        elif op == "SUBPIECE":
            a, k = self._read(ins[0], env, tmp), ins[1][1]
            if k:
                a = mk("INT_RIGHT", a, ("c", 8 * k, 4), _size(a))
            if a[0] == "c":
                val = ("c", _mask(a[1], o[2]), o[2])
            elif _size(a) == o[2] or _is_cmp(a):
                val = a
            else:
                val = mkcast(_SINT.get(o[2], "int64_t"), a, o[2])
            self._write(o, val, env, tmp)
        elif op == "PIECE":
            hi, lo = self._read(ins[0], env, tmp), self._read(ins[1], env, tmp)
            self._write(o, mk("INT_OR", mk("INT_LEFT", hi, ("c", 8 * ins[1][2], 4), o[2]), lo, o[2]), env, tmp)
        elif op in ("INT_2COMP", "INT_NEGATE", "BOOL_NEGATE", "FLOAT_NEG"):
            a = self._read(ins[0], env, tmp)
            if op == "BOOL_NEGATE":
                val = negate(a)
            elif a[0] == "c":
                val = ("c", _mask(-a[1] if op == "INT_2COMP" else ~a[1], o[2]), o[2])
            else:
                val = ("u", "~" if op == "INT_NEGATE" else "-", a, o[2])
            self._write(o, val, env, tmp)
        elif op in ("INT_CARRY", "INT_SCARRY", "INT_SBORROW", "POPCOUNT", "LZCOUNT", "FLOAT_NAN",
                    "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT", "FLOAT2FLOAT", "TRUNC", "FLOAT_CEIL",
                    "FLOAT_FLOOR", "FLOAT_ROUND"):
            args = ", ".join(self.render(self._read(v, env, tmp)) for v in ins)
            fn = {"INT2FLOAT": "(double)", "FLOAT2FLOAT": "(double)", "TRUNC": f"({_SINT.get(o[2], 'int64_t')})"}.get(op)
            text = f"{fn}({args})" if fn else f"__{op.lower()}({args})"
            self._write(o, ("call", text, o[2]), env, tmp)
        elif op == "CALLOTHER" and ins and ins[0][1] in ("ecall", "syscall", "svc", "swi"):
            self._syscall(env, tmp)
        elif op == "CALLOTHER":
            name = str(ins[0][1]) if ins and ins[0][0] == "const" else "intrinsic"
            if name in ("setISAMode", "intrinsic") and o is None:
                return
            args = ", ".join(self.render(self._read(v, env, tmp)) for v in ins[1:])
            if o is not None:
                self._write(o, ("call", f"__{name}({args})", o[2]), env, tmp)
            else:
                self._out.append(f"__{name}({args});")
        elif op in ("CALL", "CALLIND"):
            self._call(i, ins[0], env, tmp, op == "CALLIND")
        elif op == "CBRANCH":
            if ins[0][0] == "const":           # P-code-internal branch (skips within an insn)
                self._out.append(f'__asm("{i.mnemonic} {i.op_str}");')
                return
            state["cond"] = self._read(ins[1], env, tmp)
        elif op == "BRANCH":
            t = ins[0][1] if ins[0][0] == "ram" else None
            if t is not None and t != self.func.addr and (t in self.prog.functions or t in self.prog.image.imports) \
                    and t not in self.func.blocks:
                state["tail"] = self._call(i, ("ram", t, self.w), env, tmp, False, tail=True)
        elif op == "BRANCHIND":
            state["ijmp"] = self._read(ins[0], env, tmp)
        elif op == "RETURN":
            state["ret"] = True
        elif op == "ASM":
            self._out.append(f'__asm("{ins[0]}");')
            for r in self._rw(i)[1]:
                env[r] = ("call", f'__asm_{r}', self.w)
        # unknown opcodes: no effect modeled

    _SYSNR = {"riscv": "a7", "mips": "v0", "arm64": "x8", "arm": "r7", "x86_64": "rax"}

    def _syscall(self, env, tmp):
        self._flush_loads(env, tmp)
        nr = self._SYSNR.get(next((k for k in self._SYSNR if self.arch.name.startswith(k)), ""), "")
        args = [self._read(("reg", nr, self.w), env, tmp)] if nr else []
        args += [self._read(("reg", r, self.w), env, tmp) for r in self.arch.args[:4]]
        n = self._new_temp(self.w)
        self._out.append(f"{n} = syscall({', '.join(self.render(a) for a in args)});")
        ret = "a0" if self.arch.name.startswith("riscv") else self._canon(self.arch.ret)
        env[ret] = ("v", n, self.w)

    def _call(self, i, tv, env, tmp, indirect, tail=False):
        self._flush_loads(env, tmp)
        if indirect:
            tgt = _unmode(self._read(tv, env, tmp))
            t = tgt[1] if tgt[0] == "c" else None
            fname = f"(*(code *){self.render(tgt, 11)})" if t is None else None
        else:
            t = tv[1]
            fname = None
        if t is not None:
            fname = self.prog.display(t) or f"sub_{t:x}"
        argc, _ = self._callee_argc(t)
        if argc < 0:   # unknown callee: up to the highest argument register this block set
            argc = self._set_args(env)
        args = []
        for r in self.arch.args[:argc]:
            e = self._read(("reg", r, self.w), env, tmp)
            args.append(e)
            if self._collect is not None and e[0] == "v" and t is not None:
                self._collect["links"].append((e[1], t, len(args) - 1))
        text = f"{fname}({', '.join(self.render(a) for a in args)})"
        for r in list(env):
            if _CALLER_SAVED.fullmatch(r):
                del env[r]
        if tail:
            return text
        n = self._new_temp(self.w)
        self._out.append(f"{n} = {text};")
        env[self._canon(self.arch.ret)] = ("v", n, self.w)
        return text

    def _materialize(self, b, env):
        """Assign live-out registers changed by this block, ordered so no assignment overwrites a
        variable another pending assignment still reads (parallel-copy sequentialization)."""
        if self.live_out is None or self.def_names is None:
            return {}
        done = {}
        live = self.live_out.get(b.addr, set())
        names = self.def_names.get(b.addr, {})
        pend = {}
        for r, e in env.items():
            if r not in live:
                continue
            dst = names.get(r, r)
            if e == ("v", dst, _size(e)) or (e[0] == "v" and e[1] == dst):
                continue
            pend[dst] = e
        if any(e[0] == "sp" for e in pend.values()):
            pend = {k: v for k, v in pend.items() if v[0] != "sp"}
        while pend:
            ready = [d for d in pend if not any(_refs(e, d) for k, e in pend.items() if k != d)]
            if not ready:                       # a cycle: break it through a temp
                d = next(iter(pend))
                n = self._new_temp(self.w)
                self._out.append(f"{n} = {d};")
                pend = {k: _subst(e, d, ("v", n, self.w)) for k, e in pend.items()}
                continue
            for d in ready:
                e = pend.pop(d)
                if self._defs is not None:          # pass 1: count definitions per web
                    self._defs.setdefault(d, []).append(e)
                if d in self._consts:
                    continue                        # constant web: every use reads the constant
                self._out.append(f"{d} = {self.render(e)};")
                if e[0] not in ("v", "c"):
                    done[e] = ("v", d, _size(e))
                    pend = {k: _replace(x, {e: done[e]}) for k, x in pend.items()}
        return done

    def condition(self, b):
        st = self._bstate.get(b.addr)
        if st is None:
            saved = self._out if hasattr(self, "_out") else None
            self.block(b)
            st = self._bstate[b.addr]
            self._out = saved
        c = st["cond"]
        return self.render(c) if c is not None else "/* cond */ 1"

    def ret(self, b):
        st = self._bstate.get(b.addr) or {}
        if st.get("tail"):
            return f"return {st['tail']};" if not self._ret_void else f"{st['tail']};\nreturn;"
        if self._ret_void:
            return "return;"
        env = getattr(self, "_env_end", {}) if self._cur == b.addr else {}
        r = self._canon(self.arch.ret)
        e = env.get(r)
        if e is None:
            n = (self.def_names or {}).get(b.addr, {}).get(r) or (self.entry_names or {}).get(b.addr, {}).get(r, r)
            e = self._consts.get(n, ("v", n, self.w))
        return f"return {self.render(e)};"

    def indirect(self, b):
        st = self._bstate.get(b.addr) or {}
        t = st.get("ijmp")
        if t is None:
            return "/* indirect jump */"
        t = _unmode(t)
        if [s for s in b.succs if s in self.func.blocks]:
            return f"goto *({self.render(t)});"       # computed goto inside the function
        env = st.get("env", {})
        args = []
        n = self._callee_argc(t[1])[0] if t[0] == "c" else -1
        n = self._set_args(env) if n < 0 else n
        for k, r in enumerate(self.arch.args):
            r = self._canon(r)
            if k >= n:
                break
            args.append(self.render(env[r]) if r in env else
                        (self.entry_names or {}).get(b.addr, {}).get(r, r))
        if t[0] == "c":
            name = self.prog.display(t[1]) or f"sub_{t[1]:x}"
            call = f"{name}({', '.join(args)})"
        else:
            call = f"(*(code *){self.render(t, 11)})({', '.join(args)})"
        return f"return {call};   /* tail call */" if not self._ret_void else f"{call};   /* tail call */\nreturn;"

    def _tail_target(self, b):
        st = self._bstate.get(b.addr) or {}
        return st.get("tail")

    def locals_block(self):
        return [f"{_SINT.get(s, 'int64_t')} {n};" for n, s in sorted(self._locals.items())]

    def register_decls(self, sig, counts):
        params = set(re.findall(r"\b(\w+)(?=[,)])", sig.split("(", 1)[1]))
        regs = {self._canon(r) for r in self.arch.args} | {self._canon(self.arch.ret)}
        pat = re.compile(r"([avtsx]\d{1,2}|r\d{1,2}|at|hi|lo|fp|s\d{1,2}|f[sat]?\d{1,2}|[re]?[abcd]x|[re]?[sd]i|r\d+[dwb]?)(_\d+)?")
        out = []
        for n in sorted(counts):
            if n in params or n in self._temps or n in self._locals or not pat.fullmatch(n):
                continue
            if n.split("_")[0] in regs or pat.fullmatch(n):
                t = "double" if re.match(r"f[sat]?\d", n) else self._ptrvars.get(n, _SINT[self.w])
                out.append(f"{t}{'' if t.endswith('*') else ' '}{n};")
        for n in sorted(self._temps):
            if counts.get(n):
                t = self._ptrvars.get(n, _SINT[self.w])
                out.append(f"{t}{'' if t.endswith('*') else ' '}{n};")
        return out

    def preamble(self, counts):
        """Struct declarations for the recovered types this function's text uses."""
        out, counts = [], dict(counts)
        for st in getattr(self, "_sig_structs", ()):
            counts[st] = counts.get(st, 0) + 1     # used by the signature even if not the body
        for st in self.structs.used(counts):
            out += self.structs.decl(st) + [""]
        return out

    # -- rendering ----------------------------------------------------------
    def render(self, e, prec=0):
        t = e[0]
        if t == "c":
            return hex(_mask(e[1], e[2])) if len(e) > 3 else self._const(e[1], e[2])
        if t == "v":
            return e[1]
        if t == "sp":
            return f"&{self._local(e[1], self.w)}"
        if t == "ld":
            return self._lvalue(e[1], e[2])
        if t == "call":
            return e[1]
        if t == "tern":
            s = f"{self.render(e[1], 1)} ? {self.render(e[2], 1)} : {self.render(e[3], 1)}"
            return f"({s})" if prec > 0 else s
        if t == "cast":
            inner = e[2]
            if inner[0] == "c":
                return self._const(_mask(inner[1], e[3]), e[3])
            return f"({e[1]}){self.render(inner, 11)}"
        if t == "u":
            s = f"{e[1]}{self.render(e[2], 11)}"
            return s
        if t == "op":
            c, p = e[1], _PREC.get(e[1], 0)
            a, b = e[2], e[3]
            if a[0] == "c" and b[0] != "c" and c in _MIRROR:
                a, b, c = b, a, _MIRROR[c]
            if c in ("&&", "||"):
                s = f"{self.render(a, p)} {c} {self.render(b, p + 1)}"
            else:
                rb = self.render(b, p + 1)
                s = f"{self.render(a, p)} {c} {rb}"
            return f"({s})" if p < prec else s
        return "?"

    def _const(self, v, size):
        if size >= 4 and v > 0x1000:
            strs = self.prog.strings()
            if v in strs:
                return cstr_lit(strs[v])
            n = self.prog.display(v)
            if n:
                return n if v in self.prog.functions else f"&{n}"
        s = _signed(v, size)
        if -0x10000 < s < 0:
            return str(s)
        return str(v) if v < 10 else hex(v)


def _unmode(t):
    """Drop the ISA-mode bit mask (`& -2`, MIPS16/Thumb interworking) from a jump target."""
    if t[0] == "op" and t[1] == "&" and t[3][0] == "c" and _signed(t[3][1], t[3][2]) in (-2, -4):
        return t[2]
    return t


def _replace(e, mapping):
    """Replace whole subexpressions found in `mapping` (expr -> variable)."""
    if e in mapping:
        return mapping[e]
    if e[0] in ("c", "v", "sp", "call"):
        return e
    return tuple(_replace(x, mapping) if isinstance(x, tuple) else x for x in e)


def _subst(e, name, rep):
    if e[0] == "v":
        return rep if e[1] == name else e
    return tuple(_subst(x, name, rep) if isinstance(x, tuple) else x for x in e)


class StructDB:
    """Recovered layouts keyed by (function, parameter index), merged through call links.

    Access widths and type evidence are retained separately. Overlapping accesses are emitted as
    explicit unions/views, and packed layout preserves observed byte offsets instead of letting the
    host compiler silently insert alignment padding.
    """

    def __init__(self, word_size=8):
        self.parent, self.fields, self.order = {}, {}, {}
        self.access_sizes, self.field_types = {}, {}
        self.word_size = int(word_size or 8)

    def _find(self, key):
        self.parent.setdefault(key, key)
        while self.parent[key] != key:
            self.parent[key] = self.parent[self.parent[key]]
            key = self.parent[key]
        return key

    def access(self, key, off, size):
        if off < 0 or off > 0x10000 or size <= 0 or size > 0x10000:
            return
        root = self._find(key)
        fields = self.fields.setdefault(root, {})
        fields[off] = max(fields.get(off, 0), size)
        self.access_sizes.setdefault(root, {}).setdefault(off, set()).add(size)

    def access_type(self, key, off, kind):
        """Record an observed use type; conflicting observations remain ambiguous."""
        if off < 0 or off > 0x10000 or kind not in {"signed", "unsigned", "float", "double", "pointer"}:
            return
        root = self._find(key)
        self.field_types.setdefault(root, {}).setdefault(off, set()).add(kind)

    def link(self, a, b):
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        self.parent[rb] = ra
        fields = self.fields.setdefault(ra, {})
        for off, size in self.fields.pop(rb, {}).items():
            fields[off] = max(fields.get(off, 0), size)
        sizes = self.access_sizes.setdefault(ra, {})
        for off, values in self.access_sizes.pop(rb, {}).items():
            sizes.setdefault(off, set()).update(values)
        types = self.field_types.setdefault(ra, {})
        for off, values in self.field_types.pop(rb, {}).items():
            types.setdefault(off, set()).update(values)

    def name(self, key):
        root = self._find(key)
        fields = self.fields.get(root, {})
        if len(fields) < 2 and not any(off > 0 for off in fields):
            return None
        func_addr, param_index = root
        return f"s_{func_addr:x}_{param_index}"

    def _intervals(self, root):
        sizes = self.access_sizes.get(root, {})
        items = [(off, size) for off, ss in sizes.items() for size in ss]
        if not items:
            items = [(off, size) for off, size in self.fields.get(root, {}).items()]
        return sorted(set(items))

    def array_candidates(self, key):
        """Report possible repeated-index layouts without silently declaring a C array.

        Three or more same-width accesses at a stable stride are evidence worth presenting to a
        type solver or analyst, but adjacent struct fields can look identical. Callers must treat
        each result as a hypothesis and must not rewrite the declaration automatically.
        """
        root = self._find(key)
        observations = self.access_sizes.get(root, {})
        candidates = []
        widths = sorted({size for sizes in observations.values() for size in sizes})
        for size in widths:
            offsets = sorted(off for off, sizes in observations.items() if size in sizes)
            for i in range(len(offsets) - 2):
                stride = offsets[i + 1] - offsets[i]
                if stride <= 0:
                    continue
                # Start only at the beginning of a run; do not emit every suffix as a duplicate.
                if i > 0 and offsets[i] - offsets[i - 1] == stride:
                    continue
                run = [offsets[i], offsets[i + 1]]
                j = i + 2
                while j < len(offsets) and offsets[j] - offsets[j - 1] == stride:
                    run.append(offsets[j])
                    j += 1
                if len(run) >= 3:
                    candidates.append({
                        "offset": run[0],
                        "element_size": size,
                        "stride": stride,
                        "count": len(run),
                        "observed_offsets": tuple(run),
                        "confidence": "candidate",
                    })
        return sorted(candidates, key=lambda item: (item["offset"], item["element_size"], item["stride"]))

    def _groups(self, root):
        groups = []
        for item in self._intervals(root):
            off, size = item
            end = off + size
            if groups and off < max(a + n for a, n in groups[-1]):
                groups[-1].append(item)
            else:
                groups.append([item])
        return groups

    def _ctype(self, root, off, size):
        evidence = self.field_types.get(root, {}).get(off, set())
        if evidence == {"float"} and size == 4:
            return "float"
        if evidence == {"double"} and size == 8:
            return "double"
        if evidence == {"pointer"}:
            # Only use a C pointer when it has the recovered target width. For cross-width output,
            # preserve the observed storage width rather than emitting a host-width pointer.
            if size == self.word_size:
                return "void *"
            return _UINT.get(size, "uint8_t")
        if evidence == {"signed"}:
            return _SINT.get(size, "uint8_t")
        if evidence == {"unsigned"}:
            return _UINT.get(size, "uint8_t")
        # Mixed/unknown evidence is intentionally signless in the C declaration.
        return _UINT.get(size, "uint8_t")

    @staticmethod
    def _member_name(group, off, size):
        same_offset = [item for item in group if item[0] == off]
        return f"f_{off:x}_as_{size}" if len(same_offset) > 1 else f"f_{off:x}"

    def field(self, st, off, size):
        root = next((key for key in self.fields if self.name(key) == st), None)
        if root is None:
            return f"f_{off:x}"
        for group in self._groups(root):
            if (off, size) not in group:
                continue
            if len(group) == 1:
                return f"f_{off:x}"
            start = min(a for a, _ in group)
            if off == start:
                return f"_overlay_{start:x}." + self._member_name(group, off, size)
            return f"_overlay_{start:x}.view_{off:x}_{size}.f_{off:x}"
        return f"f_{off:x}"

    def used(self, counts):
        names = set()
        for root in list(self.fields):
            name = self.name(root)
            if name and counts.get(name):
                names.add(name)
        return sorted(names)

    def decl(self, st):
        root = next(key for key in self.fields if self.name(key) == st)
        out = ["#pragma pack(push, 1)", f"struct {st} {{   /* inferred from field accesses */"]
        pos = 0
        for group in self._groups(root):
            start = min(off for off, _ in group)
            end = max(off + size for off, size in group)
            if start > pos:
                out.append(f"    uint8_t _pad_{pos:x}[{start - pos}];")
            if len(group) == 1:
                off, size = group[0]
                out.append(f"    {self._ctype(root, off, size)} f_{off:x};   /* +{off:#x} */")
            else:
                out.append(f"    union {{   /* overlapping access views: {start:#x}..{end:#x} */")
                out.append(f"        uint8_t _bytes[{end - start}];")
                for off, size in group:
                    ctype = self._ctype(root, off, size)
                    name = self._member_name(group, off, size)
                    if off == start:
                        out.append(f"        {ctype} {name};   /* +{off:#x}, {size} bytes */")
                    else:
                        pad = off - start
                        out.append("        struct {")
                        if pad:
                            out.append(f"            uint8_t _pad[{pad}];")
                        out.append(f"            {ctype} f_{off:x};")
                        out.append(f"        }} view_{off:x}_{size};")
                # Field expressions emitted by field() address this named union member.
                out.append(f"    }} _overlay_{start:x};")
            if end > pos:
                pos = end
        return out + ["};", "#pragma pack(pop)"]
