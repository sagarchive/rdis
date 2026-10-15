"""Approximate C pseudo-code: structure the CFG, then lift each block to C-like statements.

Two stages, like any decompiler:
  1. structuring -- turn the basic-block graph into nested if/while/do-while/sequence via
     dominators + loop detection (a pragmatic structural match, not full Zhang/Sharir).
  2. lifting -- symbolic execution of each block over registers and stack slots, emitting
     assignments, calls and returns as C. Unknown instructions degrade to an `__asm("...")` line.

The output is a readable reconstruction, not compilable source -- same caveat Hopper states.
"""
import re
from collections import Counter

from .arch import CALL, RET, JMP, CJMP, IJMP
from . import lift


EXIT = -1  # virtual exit node for post-dominators


# ---- graph helpers (iterative: functions with thousands of blocks must not recurse) ---------
def _rpo(succ, entry):
    """Reverse post-order of nodes reachable from `entry`."""
    seen, out, stack = {entry}, [], [(entry, iter(succ(entry)))]
    while stack:
        node, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            out.append(node)
        elif nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(succ(nxt))))
    return out[::-1]


def _idoms(succ, pred, entry):
    """Immediate dominators (Cooper-Harvey-Kennedy) for nodes reachable from `entry`."""
    order = _rpo(succ, entry)
    rank = {a: i for i, a in enumerate(order)}
    idom = {entry: entry}

    def meet(a, b):
        while a != b:
            while rank[a] > rank[b]:
                a = idom[a]
            while rank[b] > rank[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for a in order[1:]:
            new = None
            for p in pred(a):
                if p in idom and p in rank:
                    new = p if new is None else meet(p, new)
            if new is not None and idom.get(a) != new:
                idom[a] = new
                changed = True
    return idom


def _dominates(idom, a, b):
    while True:
        if b == a:
            return True
        nb = idom.get(b)
        if nb is None or nb == b:
            return False
        b = nb


# ---- structuring ---------------------------------------------------------
class Structurer:
    """CFG -> nested statements.

    if/else joins come from immediate post-dominators (computed against a virtual exit), loops
    from natural-loop back edges. Inside a loop, edges to the header become `continue` and edges
    to the loop's follow block become `break`. One-sided branches whose arm cannot reach the other
    path become guard clauses. Anything left irreducible is a `goto` to a printed label.

    Node shapes: ("block", a) ("ret", a) ("switch", a) ("goto", a) ("break",) ("continue",)
                 ("if", a, then, els, negate) ("loop", h, form, body, follow)
    """

    def __init__(self, prog, func):
        self.prog, self.func, self.blocks, self.arch = prog, func, func.blocks, prog.arch
        B = self.blocks
        self.succ = {a: [s for s in dict.fromkeys(b.succs) if s in B] for a, b in B.items()}
        self.pred = {a: [] for a in B}
        for a, ss in self.succ.items():
            for s in ss:
                self.pred[s].append(a)
        self.idom = _idoms(lambda a: self.succ[a], lambda a: self.pred[a], func.addr)
        # post-dominators on the reversed graph, rooted at a virtual exit joined to every exit block
        exits = [a for a in B if not self.succ[a] or self.arch.kind(B[a].insns[-1]) in (RET, IJMP)]
        rsucc = lambda a: exits if a == EXIT else self.pred[a]
        rpred = lambda a: (self.succ[a] + ([EXIT] if a in exits else [])) if a != EXIT else []
        self.ipdom = _idoms(rsucc, rpred, EXIT)
        self.loops = self._natural_loops()
        self.placed, self.active, self.labels = set(), [], set()
        self._reach = {}

    def _natural_loops(self):
        loops = {}
        for n in self.blocks:
            if n not in self.idom:
                continue  # unreachable from entry
            for h in self.succ[n]:
                if _dominates(self.idom, h, n):  # back edge n -> h
                    body, stack = {h}, [n]
                    while stack:
                        x = stack.pop()
                        if x not in body:
                            body.add(x)
                            stack += self.pred[x]
                    loops.setdefault(h, set()).update(body)
        return loops

    def reach(self, a):
        if a not in self._reach:
            seen, st = set(), [a]
            while st:
                y = st.pop()
                if y not in seen:
                    seen.add(y)
                    st += self.succ[y]
            self._reach[a] = seen
        return self._reach[a]

    def run(self):
        return self._seq(self.func.addr, None, first=True)

    # a region runs from `a` until `end` (its natural continuation, emitted by the caller)
    def _seq(self, a, end, first=False):
        out = []
        while a is not None:
            if not first:
                if a == end:
                    break
                loop = self.active[-1] if self.active else None
                if loop and a == loop["header"]:
                    out.append(("continue",))
                    break
                if loop and a == loop["follow"]:
                    out.append(("break",))
                    break
                if a in self.placed:
                    chain = self._dup_tail(a)
                    if chain:  # small shared exit: duplicate it rather than goto (tail duplication)
                        out += [("block", c) for c in chain] + [("ret", chain[-1])]
                        return out
                    self.labels.add(a)
                    out.append(("goto", a))
                    break
            first = False
            if a in self.loops and all(l["header"] != a for l in self.active):
                node, a = self._loop(a)
                out.append(node)
                continue
            self.placed.add(a)
            out.append(("block", a))
            kind = self.arch.kind(self.blocks[a].insns[-1])
            ss = self.succ[a]
            # IJMP must be checked before `not ss`: a register tail-call (`br x2`, JNIEnv/vtable
            # dispatch, PLT tail) has no successors, and would otherwise be swallowed as a bare
            # `return;`, silently dropping the call that IS the function body.
            if kind == IJMP:
                out.append(("switch", a))
                jt = getattr(self.prog, "jump_tables", {}).get(self.blocks[a].insns[-1].address)
                if jt:  # emit each case body as a labeled region after the switch
                    for t in dict.fromkeys(jt["cases"].values()):
                        self.labels.add(t)   # every case target is a goto label, placed or not
                        if t not in self.placed and t in self.blocks:
                            out += self._seq(t, end, first=True)
                return out
            if kind == RET or not ss:
                out.append(("ret", a))
                return out
            if kind == CJMP and len(ss) == 2:
                node, a = self._if(a, end)
                out.append(node)
                if _leaves(node[2]) and _leaves(node[3]):
                    return out  # both arms return/break/continue/goto: nothing after is reachable
                continue
            a = ss[0]
        return out

    def _dup_tail(self, a, max_insns=8, max_blocks=3):
        """Blocks from `a` that fall straight into a return, if small enough to duplicate."""
        chain, n = [], 0
        while len(chain) < max_blocks:
            if a in self.loops or a in chain:
                return None
            b = self.blocks[a]
            n += len(b.insns)
            if n > max_insns:
                return None
            chain.append(a)
            k = self.arch.kind(b.insns[-1])
            if k == RET or not self.succ[a]:
                return chain
            if k in (CJMP, IJMP) or len(self.succ[a]) != 1:
                return None
            a = self.succ[a][0]
        return None

    def _if(self, a, end):
        blk = self.blocks[a]
        taken = self.arch.target(blk.insns[-1])
        t = taken if taken in self.blocks else None
        f = blk.end if blk.end in self.blocks else next((s for s in self.succ[a] if s != t), None)
        join = self.ipdom.get(a)
        loop = self.active[-1] if self.active else None
        if join == EXIT or (loop and join not in loop["body"] and join != loop["follow"]):
            join = None
        if join is None and t is not None and f is not None:
            # guard clause: an arm that cannot reach the other path is self-contained
            if f not in self.reach(t):
                return ("if", a, self._seq(t, None), [], False), f
            if t not in self.reach(f):
                return ("if", a, self._seq(f, None), [], True), t
        stop = join if join is not None else end
        then = self._seq(t, stop) if t is not None and t != stop else []
        els = self._seq(f, stop) if f is not None and f != stop else []
        if not then and els:                       # if (!cond) { fallthrough }
            return ("if", a, els, [], True), join
        return ("if", a, then, els, False), join

    def _loop(self, h):
        body = self.loops[h]
        exits = [s for b in sorted(body) for s in self.succ[b] if s not in body]
        follow = self.ipdom.get(h) if self.ipdom.get(h) in exits else (min(exits) if exits else None)
        L = {"header": h, "body": body, "follow": follow}
        self.active.append(L)
        hb = self.blocks[h]
        form = None
        if self.arch.kind(hb.insns[-1]) == CJMP and follow is not None and follow in self.succ[h] \
                and len(self.succ[h]) == 2:
            enter = next(s for s in self.succ[h] if s != follow)
            exit_on_taken = self.arch.target(hb.insns[-1]) == follow
            self.placed.add(h)
            body_nodes = self._seq(enter, h) if enter != h else []
            form = ("test", exit_on_taken)        # header block is the loop test
        else:
            body_nodes = self._seq(h, h, first=True)  # header is the first statement of the body
        self.active.pop()
        return ("loop", h, form, body_nodes, follow), follow


# ---- emission ------------------------------------------------------------
_INV = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def negate(cond):
    """Logical negation of a rendered condition, inverting a top-level comparison when possible."""
    op = lift.Lifter._top_op(cond)
    if op in _INV:
        lhs, sep, rhs = _split_top(cond, op)
        if sep:
            return f"{lhs} {_INV[op]} {rhs}"
    if cond.startswith("!(") and cond.endswith(")") and lift.Lifter._atomic(cond[1:]):
        return cond[2:-1]
    return f"!{cond}" if lift.Lifter._atomic(cond) else f"!({cond})"


def _split_top(s, op):
    """Split `s` at the first depth-0 occurrence of ` op `."""
    depth, quote, tok = 0, False, f" {op} "
    for n, ch in enumerate(s):
        if quote:
            quote = not (ch == '"' and s[n - 1] != "\\")
        elif ch == '"':
            quote = True
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and s.startswith(tok, n):
            return s[:n], op, s[n + len(tok):]
    return s, None, ""


TERMINAL = ("ret", "goto", "break", "continue", "switch")
_CALL = re.compile(r"(?<![\w*])[A-Za-z_$][\w$]*\s*\(|\[[^\]]* [^\]]*:")  # a call or ObjC message


def _leaves(nodes):
    """Does this statement list always transfer control away (never falls through)?"""
    if not nodes:
        return False
    last = nodes[-1]
    if last[0] in TERMINAL:
        return True
    return last[0] == "if" and bool(last[3]) and _leaves(last[2]) and _leaves(last[3])

# registers that never carry program values across blocks (flags, stack/frame/link, zero, pc)
_UNTRACKED = {"nzcv", "rflags", "flags", "rip", "pc", "sp", "rsp", "rbp", "x29", "fp", "x30", "lr",
              "xzr", "wzr", "ptr", "qword", "dword", "word", "byte", "fpcr", "fpsr", "mxcsr"}


def liveness(lifter, func, returns):
    """Registers live out of each block (backward dataflow over canonical register names).

    Calls use the callee's argument registers and define/clobber the argument and return
    registers. A returning block reads the return register(s). This is what lets values that
    flow across blocks (loop counters, results set before a shared epilogue) become real
    assignments instead of vanishing with the per-block symbolic state."""
    arch, canon = lifter.arch, lifter._canon
    allargs = {canon(r) for r in arch.args} | {canon(r) for r in arch.fargs}
    rets = {canon(arch.ret)} | ({canon(arch.fret)} if arch.fret else set())
    use, defs, B = {}, {}, func.blocks
    for a, b in B.items():
        u, d = set(), set()
        for i in b.insns:
            k = arch.kind(i)
            if k == CALL:
                argc, fargc = lifter._callee_argc(lifter.prog.call_target(i, {}))
                rd = {canon(r) for r in arch.args[:argc]} | {canon(r) for r in arch.fargs[:fargc]}
                wr = allargs | rets
            else:
                rd, wr = lifter._rw(i)
            u |= (rd - _UNTRACKED) - d
            d |= wr - _UNTRACKED
        if arch.kind(b.insns[-1]) == RET or not [s for s in b.succs if s in B]:
            u |= returns - d   # the return value is read on the way out
        use[a], defs[a] = u, d
    live_in = {a: set() for a in B}
    live_out = {a: set() for a in B}
    changed = True
    while changed:
        changed = False
        for a in sorted(B, reverse=True):  # roughly reverse program order converges fast
            out = set().union(*(live_in[s] for s in B[a].succs if s in B)) if B[a].succs else set()
            inn = use[a] | (out - defs[a])
            if out != live_out[a] or inn != live_in[a]:
                live_out[a], live_in[a] = out, inn
                changed = True
    return live_in, live_out, defs


def webs(func, live_in, live_out, defs):
    """SSA-style live-range splitting: one variable per def-use web of each register.

    Reaching definitions are computed per block (a block that writes r is one definition of r;
    the function entry defines every register). Definitions reaching the same live-in point are
    unioned into a web, and each web is a separate variable -- so a register the compiler reuses
    for unrelated values (a pointer argument, then a loop index, then the return value) becomes
    distinct variables with their own types instead of one variable that is all three.

    Returns (entry_names, def_names): {block: {reg: var}} for values coming into and stored out of
    each block. Webs containing the entry definition keep the plain register name."""
    B = func.blocks
    regs = set().union(*live_in.values(), *defs.values()) if B else set()
    preds = {a: [] for a in B}
    for a, b in B.items():
        for s in b.succs:
            if s in B:
                preds[s].append(a)
    ENTRY = "entry"
    rd_out = {a: {} for a in B}
    rd_in = {a: {} for a in B}
    order = sorted(B)
    changed = True
    while changed:
        changed = False
        for a in order:
            inn = {r: {ENTRY} for r in regs} if a == func.addr else {}
            for p in preds[a]:
                for r, sites in rd_out[p].items():
                    inn.setdefault(r, set()).update(sites)
            out = {r: s for r, s in inn.items() if r not in defs[a]}
            for r in defs[a]:
                out[r] = {a}
            if inn != rd_in[a] or out != rd_out[a]:
                rd_in[a], rd_out[a] = inn, out
                changed = True
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in B:
        for r in live_in[a]:
            sites = [(s, r) for s in rd_in[a].get(r, ())]
            for s in sites[1:]:
                parent[find(s)] = find(sites[0])
    relevant = {}  # web root -> (reg, first definition address) for webs that need a name
    for a in B:
        for r in live_in[a]:
            for s in rd_in[a].get(r, ()):
                relevant.setdefault(find((s, r)), (r, -1 if s == ENTRY else s))
        for r in live_out[a] & defs[a]:
            root = find((a, r))
            prev = relevant.get(root)
            relevant[root] = (r, min(prev[1], a) if prev else a)
    # name webs per register: the entry web (parameters, incoming values) keeps the plain name,
    # the others follow in address order as r_1, r_2, ...
    by_reg = {}
    for root, (r, first) in relevant.items():
        by_reg.setdefault(r, []).append((first, root))
    names = {}
    for r, lst in by_reg.items():
        entry_root = find((ENTRY, r))
        lst.sort(key=lambda x: (x[1] != entry_root, x[0]))
        for k, (_, root) in enumerate(lst):
            names[root] = r if k == 0 else f"{r}_{k}"
    entry_names, def_names = {}, {}
    for a in B:
        e = {}
        for r in live_in[a]:
            sites = rd_in[a].get(r)
            if sites:
                e[r] = names.get(find((next(iter(sites)), r)), r)
        entry_names[a] = e
        def_names[a] = {r: names.get(find((a, r)), r) for r in live_out[a] & defs[a]}
    return entry_names, def_names


class Decompiler:
    # ISAs the pattern lifter models; the rest (MIPS, RISC-V, ...) decompile through the IR.
    # RDIS_IR=1 routes every ISA through the IR (needs pypcode beyond MIPS/RISC-V).
    LEGACY = ("x86", "x86_64", "arm64", "arm")

    def __init__(self, prog, func, engine=None):
        import os
        from . import ir
        self.prog, self.func = prog, func
        engine = engine or ("ir" if os.environ.get("RDIS_IR") == "1" or prog.arch.name not in self.LEGACY
                            else "legacy")
        self.engine = engine if engine == "legacy" or ir.IRLifter.supports(prog.arch) else "legacy"
        self.lifter = ir.IRLifter(prog) if self.engine == "ir" else lift.Lifter(prog)

    _IDENT = re.compile(r"(?<![\w.])[A-Za-z_]\w*")  # not the x in 0x10

    def c(self):
        name = self.prog.display(self.func.addr) or f"sub_{self.func.addr:x}"
        if self.func.addr not in self.func.blocks:   # undecodable/empty (e.g. wrong-mode stub)
            return f"/* {name}: no decodable instructions at this address */\nvoid {name}(void) {{}}\n"
        st = Structurer(self.prog, self.func)
        tree = st.run()
        self.labels = st.labels
        name = self.prog.display(self.func.addr) or f"sub_{self.func.addr:x}"
        ident = lift.cname(name)
        sig = self.lifter.signature(self.func, ident)  # first: scans args, resets temp state
        L = self.lifter
        returns = set() if L._ret_void else {L._canon(L.arch.fret if L._ret_fp else L.arch.ret)}
        live_in, L.live_out, defs = (L.liveness(self.func, returns) if hasattr(L, "liveness")
                                     else liveness(L, self.func, returns))
        L.entry_names, L.def_names = webs(self.func, live_in, L.live_out, defs)
        body = self._tidy(self._emit(tree, 1))         # then: allocates temps/locals
        mixed = {n for n, k in getattr(L, "_assignkinds", {}).items() if len(k) > 1}
        hint = self.prog.__dict__.setdefault("_vec_hint", {})
        if mixed - set(hint.get(self.func.addr, ())):
            # a register web is written both as a vector and through a scalar view: decompile once
            # more, now writing its scalar values as vectors (lane 0, upper lanes zero, as on arm64)
            hint[self.func.addr] = set(hint.get(self.func.addr, ())) | mixed
            return Decompiler(self.prog, self.func, self.engine).c()
        # count every identifier once; a temp used only by its own definition drops the "vN = "
        counts = Counter(self._IDENT.findall("\n".join(body)))
        dead = {t for t in self.lifter._temps if counts.get(t, 0) == 1}
        tp = re.escape(getattr(L, "TEMP", "t"))
        if dead:
            # an unused temp: drop it if its value is pure, keep the expression if it calls
            def keep(ln):
                m = re.fullmatch(rf"\s*({tp}\d+) = (.*);", ln)
                return not (m and m.group(1) in dead and not _CALL.search(m.group(2)))
            body = [re.sub(rf"^(\s*)({tp}\d+) = ", lambda m: m.group(1) if m.group(2) in dead else m.group(0), ln)
                    for ln in body if keep(ln)]
            counts = Counter(self._IDENT.findall("\n".join(body)))
        decls = [d for d in self.lifter.locals_block() if counts.get(d.split()[-1].rstrip(";").lstrip("*"), 0)]
        decls = (L.register_decls(sig, counts) if hasattr(L, "register_decls")
                 else self._register_decls(sig, counts)) + decls
        seen, uniq = set(), []
        for d in decls:                      # a name declared twice (register + local) is an error
            n = re.sub(r"\[.*$", "", d.rstrip(";")).split()[-1].lstrip("*")
            if n not in seen:
                seen.add(n)
                uniq.append(d)
        decls = uniq
        tables = self._table_decls(counts)   # static const arrays for recovered lookup tables
        nat = getattr(self.prog, "jni_natives", {}).get(self.func.addr)
        if nat:   # registered via RegisterNatives: show the Java-side method it implements
            tables = tables + [f"/* JNI native {nat[0]}{nat[1]}  (env, thiz, ...) */"]
        if hasattr(L, "preamble"):
            tables = L.preamble(counts) + tables     # recovered struct declarations
        if self.engine == "legacy" and self.prog.arch.name not in self.LEGACY:
            tables = tables + [f"/* {self.prog.arch.name}: control flow recovered; instruction "
                               "semantics shown as asm (install pypcode for the IR lifter) */"]
        if ident != name:
            tables = tables + [f"/* {name} */"]
        lines = tables + [sig + " {"] + ["    " + d for d in decls] + ([""] if decls else []) + body + ["}"]
        from . import jni
        return jni.name_calls("\n".join(lines))   # (*env)->Fn(…) for JNIEnv dispatch calls

    def _table_decls(self, counts):
        """`static const T table_X[] = { ... };` for each recovered lookup table used in the body."""
        out = []
        for info in getattr(self.prog, "tables", {}).values():
            if not counts.get(info["name"]):
                continue
            vals = ", ".join(hex(v) if v >= 0 else str(v) for v in info["values"])
            out.append(f"static const {info['ctype']} {info['name']}[] = {{{vals}}};")
        return out + ([""] if out else [])

    _REGVAR = re.compile(r"(x\d{1,2}|v\d{1,2}|r[a-ds]x|r[sd]i|r\d{1,2}|xmm\d{1,2})(_\d+)?")

    def _register_decls(self, sig, counts):
        """Declare every register used as a variable, so the output is self-contained C."""
        params = set(re.findall(r"\b(\w+)(?=[,)])", sig.split("(", 1)[1]))
        L, out = self.lifter, []
        for name in sorted((n for n in counts if self._REGVAR.fullmatch(n) and n not in params),
                           key=lambda n: (n[0], [int(x) for x in re.findall(r"\d+", n)])):
            if name in getattr(L, "_vecnames", ()):
                t = "v128"                      # holds a vector (see neon.py)
            elif name.startswith(("v", "xmm")):
                t = "double"
            else:
                t = L._ptrvars.get(name, "int64_t")
            out.append(f"{t}{'' if t.endswith('*') else ' '}{name};")
        return out

    def _label(self, a, pad, out):
        placed = self.__dict__.setdefault("_placed_labels", set())
        if a in self.labels and a not in placed:
            placed.add(a)
            out.append(f"{pad[:-4] if len(pad) >= 4 else ''}loc_{a:x}:")

    def _emit(self, nodes, depth):
        pad = "    " * depth
        out = []
        for node in nodes:
            tag = node[0]
            if tag == "block":
                self._label(node[1], pad, out)
                out += [pad + s for s in self.lifter.block(self.func.blocks[node[1]])]
            elif tag == "ret":
                out += [pad + ln for ln in self.lifter.ret(self.func.blocks[node[1]]).split("\n")]
            elif tag == "if":
                _, a, then, els, neg = node
                cond = self.lifter.condition(self.func.blocks[a])
                cond = negate(cond) if neg else cond
                k = {"0": "0", "1": "1", "!0": "1", "!1": "0", "!(0)": "1", "!(1)": "0"}.get(cond.strip())
                if k:                               # folded to a constant: keep only the live arm
                    out += self._emit(then if k == "1" else els, depth)
                    continue
                t_out, e_out = self._emit(then, depth + 1), self._emit(els, depth + 1)
                if not t_out and e_out:           # nothing to do when true: flip it
                    cond, t_out, e_out = negate(cond), e_out, []
                if not t_out and not e_out:
                    continue                       # both arms empty: the test has no effect
                out.append(f"{pad}if ({cond}) {{")
                out += t_out
                if e_out:
                    if len(e_out) >= 1 and e_out[0].lstrip().startswith("if (") and _single_stmt(e_out):
                        out.append(f"{pad}}} else {e_out[0].lstrip()}")   # else-if chain
                        out += [ln[4:] for ln in e_out[1:]]
                        continue
                    out.append(pad + "} else {")
                    out += e_out
                out.append(pad + "}")
            elif tag == "loop":
                out += self._emit_loop(node, depth)
            elif tag == "switch":
                out += self._emit_switch(node[1], depth)
            elif tag == "goto":
                out.append(f"{pad}goto loc_{node[1]:x};")
            elif tag in ("break", "continue"):
                out.append(f"{pad}{tag};")
        return out

    def _emit_switch(self, addr, depth):
        """A computed goto: if analysis recovered its jump table, emit a readable `switch` whose
        cases jump to the recovered targets; otherwise fall back to the raw indirect jump."""
        pad = "    " * depth
        block = self.func.blocks[addr]
        self.lifter.block(block)                        # lift so the index register resolves
        jt = getattr(self.prog, "jump_tables", {}).get(block.insns[-1].address)
        if not jt:
            return [pad + self.lifter.indirect(block)]
        idx = self.lifter._last_regs.get(jt["index"], jt["index"] or "?")
        out = [f"{pad}switch ({idx}) {{"]
        bytarget = {}
        for v, t in jt["cases"].items():
            bytarget.setdefault(t, []).append(v)
        for t, vals in bytarget.items():
            self.labels.add(t)
            out += [f"{pad}case {v}:" for v in sorted(vals)]
            out.append(f"{pad}    goto loc_{t:x};")
        out.append(pad + "}")
        return out

    def _emit_loop(self, node, depth):
        _, h, form, body, follow = node
        pad, out = "    " * depth, []
        self._label(h, pad, out)
        if form:  # header is the test: lift it now so its compare drives the loop condition
            _, exit_on_taken = form
            hdr = self.lifter.block(self.func.blocks[h])
            cond = self.lifter.condition(self.func.blocks[h])
            stay = negate(cond) if exit_on_taken else cond
            inner = self._strip_latch(self._emit(body, depth + 1), pad + "    ")
            if not hdr:
                out.append(f"{pad}while ({stay}) {{")
                out += inner
            else:  # header does work every iteration: while (1) { work; if (exit) break; ... }
                out.append(f"{pad}while (1) {{")
                out += [pad + "    " + s for s in hdr]
                out.append(f"{pad}    if ({negate(stay)}) break;")
                out += inner
            out.append(pad + "}")
            return self._drop_trailing_continue(out, pad)
        inner = self._strip_latch(self._emit(body, depth + 1), pad + "    ")
        # while (1) { S; if (c) break; }  ->  do { S } while (!c);
        if inner and re.fullmatch(r"\s*if \((.*)\) \{", inner[-3] if len(inner) >= 3 else "") \
                and inner[-2].strip() == "break;" and inner[-1].strip() == "}":
            c = re.fullmatch(r"\s*if \((.*)\) \{", inner[-3]).group(1)
            out.append(f"{pad}do {{")
            out += inner[:-3]
            out.append(f"{pad}}} while ({negate(c)});")
            return out
        out.append(f"{pad}while (1) {{")
        out += inner
        out.append(pad + "}")
        return self._drop_trailing_continue(out, pad)

    @staticmethod
    def _drop_trailing_continue(out, pad):
        if len(out) >= 2 and out[-2].strip() == "continue;" and out[-1] == pad + "}":
            del out[-2]
        return out

    @staticmethod
    def _strip_latch(inner, ipad):
        """At the end of a loop body, `if (c) { continue; } [else { S }]` is `if (!c) { S }`:
        continuing is what falling off the end of the body already does."""
        for j in range(len(inner) - 1, -1, -1):
            if inner[j].startswith(ipad + "if (") and inner[j].endswith(") {") and \
                    not inner[j].startswith(ipad + " ") and j + 2 < len(inner) and \
                    inner[j + 1] == ipad + "    continue;":
                tail = inner[j + 2:]
                c = inner[j][len(ipad) + 4:-3]
                if tail == [ipad + "}"]:
                    return inner[:j]
                if tail and tail[0] == ipad + "} else {" and tail[-1] == ipad + "}":
                    return inner[:j] + [f"{ipad}if ({negate(c)}) {{"] + tail[1:]
                return inner
            if inner[j].startswith(ipad) and not inner[j].startswith(ipad + " ") and \
                    not inner[j].startswith(ipad + "}"):
                return inner  # last top-level statement is something else
        return inner

    @staticmethod
    def _tidy(lines):
        """Peephole cleanups on the emitted lines:
          * `goto L;` immediately followed by its own label `L:` is dropped;
          * `tN = E;` directly followed by `r = tN;` (tN used nowhere else) becomes `r = E;`."""
        text = "\n".join(lines)
        uses = Counter(re.findall(r"\bt\d+\b", text))
        out, n = [], 0
        while n < len(lines):
            ln = lines[n]
            m = re.fullmatch(r"\s*goto (loc_[0-9a-f]+);", ln)
            if m and n + 1 < len(lines) and lines[n + 1].strip() == f"{m.group(1)}:":
                n += 1
                continue
            r = re.fullmatch(r"(\s*)(\w+) = (.*);", ln)
            if r and n + 1 < len(lines) and lines[n + 1] == f"{r.group(1)}return {r.group(2)};":
                out.append(f"{r.group(1)}return {r.group(3)};")   # x0 = E; return x0;  ->  return E;
                n += 2
                continue
            t = re.fullmatch(r"(\s*)(t\d+) = (.*);", ln)
            if t and n + 1 < len(lines) and uses[t.group(2)] == 2:
                nxt = re.fullmatch(r"(\s*)(\w+) = " + t.group(2) + ";", lines[n + 1])
                if nxt and nxt.group(1) == t.group(1):
                    out.append(f"{t.group(1)}{nxt.group(2)} = {t.group(3)};")
                    n += 2
                    continue
            out.append(ln)
            n += 1
        return out


def _single_stmt(lines):
    """Is `lines` exactly one if/else statement (so it can chain as `else if`)?"""
    depth = 0
    for n, ln in enumerate(lines):
        depth += ln.count("{") - ln.count("}")
        if depth == 0 and n != len(lines) - 1:
            return False
    return True
