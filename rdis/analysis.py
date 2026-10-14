"""Whole-program analysis: functions, basic blocks, cross-references, strings."""
from collections import Counter, defaultdict

import capstone as cs
from dataclasses import dataclass, field
import re
import threading

from .arch import CALL, RET, JMP, CJMP, IJMP
from .demangle import demangle_all
from .objc import ObjC
from .swift import Swift

MAX_INSNS = 50_000  # ponytail: per-function cap guards against runaway descent into data


@dataclass
class Block:
    addr: int
    insns: list
    succs: list = field(default_factory=list)

    @property
    def end(self):
        last = self.insns[-1]
        return last.address + last.size


@dataclass
class Function:
    addr: int
    blocks: dict  # addr -> Block, in address order
    calls: set    # callee code addresses

    @property
    def end(self):
        return max(b.end for b in self.blocks.values())


class Program:
    def __init__(self, image):
        self.image, self.arch = image, image.arch
        # imports (stub/GOT slot names) win over auto-generated sub_ symbols at the same address
        self.names = dict(image.symbols)
        for a, n in image.imports.items():
            if self.names.get(a, "sub_").startswith("sub_"):
                self.names[a] = n
        self.functions = {}
        self.xrefs = defaultdict(set)  # target -> {(from_addr, kind)}
        self._insns = {}
        self._strings = None
        self.pretty, self.objc, self.swift = {}, None, None
        # decompile caches, shared by reference across session overlays (filled from the image,
        # which is immutable) and created here so copy.copy() shares them rather than forking them.
        self._argc_cache, self._ret_use_cache, self.tables = {}, {}, {}
        self.value_tables, self.jump_tables = {}, {}
        self._tmode = {}  # ARM: aligned addr -> is-Thumb, filled as branches/calls are discovered
        self.lock = threading.RLock()  # guards lazy cache fills when overlays share this analysis
        self.user_names = {}   # addr -> user-chosen name (overrides everything)
        self.comments = {}     # addr -> user comment
        self.bookmarks = set()
        self.user_types = {}   # addr -> 'data' | 'ascii' | 'code'
        self.user_procs, self.removed_procs = set(), set()

    def overlay(self):
        """A per-session view: shares the heavy immutable analysis (image, decoded instructions,
        xrefs, strings, metadata, decompile caches) by reference, but gets its own small edit state
        (names, comments, bookmarks, types, user procedures) and its own function/name maps, so one
        visitor's renames and procedure edits never affect another's."""
        import copy
        o = copy.copy(self)                 # shallow: every attribute shared by reference
        o.functions = dict(self.functions)  # own map (shares Block objects, read-only during lift)
        o.names = dict(self.names)
        o.user_names, o.comments, o.user_types = {}, {}, {}
        o.bookmarks, o.user_procs, o.removed_procs = set(), set(), set()
        o._fidx_key = None                  # its own function_at index (functions map differs)
        o._shared = self                    # the analysis whose lock serializes cache fills
        return o

    @property
    def _analysis_lock(self):
        return getattr(self, "_shared", self).lock

    # -- decoding -----------------------------------------------------------
    def _is_thumb(self, a):
        """ARM instruction-set mode at aligned address `a`: discovered mode wins, else the loader's."""
        return self._tmode[a] if a in self._tmode else (a in self.image.thumb)

    def insn(self, a, thumb=None):
        if thumb is None:
            thumb = self._is_thumb(a)
        key = (a, thumb)
        if key not in self._insns:
            self._insns[key] = self.arch.decode(self.image.read(a, 16), a, thumb)
        return self._insns[key]

    def call_target(self, i, regs=None):
        """Code address or import slot a call/jump goes to, if statically known."""
        t = self.arch.target(i)
        if t is not None:
            return t
        regs = regs if regs is not None else {}
        if i.operands and i.operands[0].type == 1 and ("slot", i.operands[0].reg) in regs:  # 1 = OP_REG
            return regs[("slot", i.operands[0].reg)]  # arm64 `ldr xN, [slot]; br/blr xN`
        refs = self.arch.data_refs(i, regs)
        return refs[0] if refs else None

    def _target_mode(self, i, t, cur):
        """Instruction-set mode (Thumb?) of a branch/call target. A known mode (loader flag or an
        earlier discovery) wins; else `blx`/`bx` toggles ARM<->Thumb; else the target inherits `cur`."""
        if t is None or self.arch.name != "arm":
            return cur
        if t in self.image.thumb or t in self._tmode:
            return self._is_thumb(t)
        return (not cur) if self.arch.is_blx(i) else cur

    # -- analysis -----------------------------------------------------------
    def analyze(self, objc=True, swift=True, prologues=True):
        """Full analysis. Flags mirror a loader dialog: skip ObjC/Swift parsing or the gap scan."""
        self._name_plt_stubs()
        self.objc = ObjC(self.image) if objc else ObjC.empty(self.image)
        self.swift = Swift(self.image) if swift else Swift.empty(self.image)
        for a, n in self.objc.names().items():
            self.auto_name(a, n)
        seeds = [a for a in self.image.symbols if self.image.is_code(a)]
        seeds += [m.imp for c in self.objc.classes for m in c.methods]
        if self.image.is_code(self.image.entry):
            seeds.append(self.image.entry)
            self.auto_name(self.image.entry, "entry")
        self._discover(seeds)
        if prologues:
            self._discover(list(self._prologue_scan()))
        self._recover_tables()
        self.pretty = demangle_all(self.names.values())
        # NOTE: the sidecar .rdb is NOT auto-loaded here. A shared analysis must stay free of any
        # one user's edits; callers that own a single workspace (the CLI, a single-user server)
        # load it explicitly onto their own view.
        return self

    # -- user edits: procedures, data types, bookmarks ----------------------
    def create_function(self, a):
        """Mark `a` as a procedure start (Hopper's P) and analyze it."""
        a = int(a)
        self.user_procs.add(a)
        self.removed_procs.discard(a)
        self.functions.pop(a, None)
        self._discover([a])
        self.names.setdefault(a, f"sub_{a:x}")
        return self.functions.get(a)

    def remove_function(self, a):
        """Drop the procedure starting at `a` (Hopper's U)."""
        a = int(a)
        self.removed_procs.add(a)
        self.user_procs.discard(a)
        return self.functions.pop(a, None) is not None

    def set_type(self, a, kind):
        """Record a user data type at `a`: 'data', 'ascii', 'code' or None to clear."""
        if kind:
            self.user_types[int(a)] = kind
        else:
            self.user_types.pop(int(a), None)

    def bookmark(self, a, on=True):
        (self.bookmarks.add if on else self.bookmarks.discard)(int(a))

    def lookup_table(self, addr, elem_size, count, ctype):
        """Recover a constant lookup table from the image; cache and name it. Returns the C name,
        or None if the data cannot be read. Shared across a decompile via `self.tables`."""
        if not hasattr(self, "tables"):
            self.tables = {}
        key = (addr, elem_size)
        if key not in self.tables:
            signed = not ctype.startswith("u")
            vals = []
            for n in range(count):
                raw = self.image.read(addr + n * elem_size, elem_size)
                if len(raw) < elem_size:
                    return None
                vals.append(int.from_bytes(raw, "little", signed=signed))
            self.tables[key] = {"name": f"table_{addr:x}", "ctype": ctype, "values": vals}
        return self.tables[key]["name"]

    def display(self, a):
        """Best human name for address `a`: a user rename, else demangled symbol, else None."""
        if a in self.user_names:
            return self.user_names[a]
        n = self.names.get(a)
        return self.pretty.get(n, n) if n else None

    # -- analysis database (renames + comments, persisted as JSON) ----------
    def rename(self, addr, name):
        self.user_names[int(addr)] = name

    def comment(self, addr, text):
        if text:
            self.comments[int(addr)] = text
        else:
            self.comments.pop(int(addr), None)

    def save(self, path):
        import json
        data = {"path": self.image.path, "format": self.image.format, "arch": self.arch.name,
                "names": {str(k): v for k, v in self.user_names.items()},
                "comments": {str(k): v for k, v in self.comments.items()},
                "bookmarks": sorted(self.bookmarks),
                "types": {str(k): v for k, v in self.user_types.items()},
                "procs": sorted(self.user_procs), "removed": sorted(self.removed_procs)}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    def load(self, path):
        import json, os
        if not os.path.exists(path):
            return self
        try:
            data = json.load(open(path))
        except (OSError, ValueError):
            return self  # a corrupt sidecar must never block opening the binary
        self.user_names.update({int(k): v for k, v in data.get("names", {}).items()})
        self.comments.update({int(k): v for k, v in data.get("comments", {}).items()})
        self.bookmarks.update(int(a) for a in data.get("bookmarks", []))
        self.user_types.update({int(k): v for k, v in data.get("types", {}).items()})
        for a in data.get("procs", []):
            if int(a) not in self.functions:
                self.create_function(a)
        for a in data.get("removed", []):
            self.remove_function(a)
        return self

    def rdb_path(self):
        """Sidecar DB: <binary>.rdb next to the binary, or ./.rdis_db/ when that dir is read-only."""
        import hashlib, os
        d = os.path.dirname(os.path.abspath(self.image.path))
        if os.access(d, os.W_OK):
            return self.image.path + ".rdb"
        store = os.environ.get("RDIS_DB_DIR", os.path.join(os.getcwd(), ".rdis_db"))
        os.makedirs(store, exist_ok=True)
        tag = hashlib.sha1(os.path.abspath(self.image.path).encode()).hexdigest()[:12]
        return os.path.join(store, f"{os.path.basename(self.image.path)}.{tag}.rdb")

    def auto_name(self, a, name):
        """Name `a` unless it already has a real (non-generated) name."""
        if self.names.get(a, "sub_").startswith("sub_"):
            self.names[a] = name

    def _discover(self, work):
        while work:
            a = work.pop()
            if a in self.functions or a in self.removed_procs or not self.image.is_code(a) \
                    or a in self.image.imports:
                continue
            f = self.functions[a] = self._build(a)
            self.names.setdefault(a, f"sub_{a:x}")
            work.extend(f.calls)

    def _build(self, start, seeds=()):
        insns, calls, seen = {}, set(), set()
        thumb = self._is_thumb(start)
        self._tmode.setdefault(start, thumb)
        work = [(start, thumb), *((s, thumb) for s in seeds)]
        known = self.image.symbols
        while work and len(insns) < MAX_INSNS:
            (a, tm), regs = work.pop(), {}
            while a not in seen and self.image.is_code(a):
                seen.add(a)
                i = self.insn(a, tm)
                if i is None:
                    break
                insns[a] = i
                k = self.arch.kind(i)
                if k in (CALL, JMP, CJMP, IJMP):
                    t = self.call_target(i, regs)
                    tt = self._target_mode(i, t, tm)  # instruction-set mode at the target
                else:
                    t = None
                    for r in self.arch.data_refs(i, regs):
                        self.xrefs[r].add((a, "data"))
                if k == CALL:
                    if t is not None:
                        self.xrefs[t].add((a, "call"))
                        if self.image.is_code(t):
                            self._tmode.setdefault(t, tt)
                            calls.add(t)
                elif k in (JMP, CJMP) and t is not None:
                    tail = t != start and (t in known or t in self.image.imports or not self.image.is_code(t))
                    self.xrefs[t].add((a, "tail" if tail else "jmp"))
                    if tail:
                        self._tmode.setdefault(t, tt)
                        calls.add(t)
                        if k == JMP:
                            break
                    else:
                        work.append((t, tt))  # intra-function branch: same mode unless toggled
                        if k == JMP:
                            break
                elif k == IJMP:
                    if t is not None and t in self.image.imports and len(insns) <= 4:
                        self.auto_name(start, f"j_{self.image.imports[t]}")  # import thunk
                    self.xrefs[t].add((a, "jmp")) if t is not None else None
                    break
                elif k == RET:
                    break
                a += i.size
        return Function(start, self._split(start, insns), calls)

    def _recover_tables(self):
        """Recover lookup/jump tables so optimized switches decompile and computed gotos resolve.

        self.value_tables[load_addr] = (table_addr, elem_size, count, signed) -- an indexed load of
            constant read-only data bounded by a preceding compare (an optimized `switch` returning
            a value, a character-class table, etc.).
        self.jump_tables[ijmp_addr]  = {"base", "cases": {case_value: target}} -- a computed goto
            through a table of int32 offsets relative to the table base.
        Jump-table case bodies are added to the owning function (rebuilt with them as extra seeds).
        """
        self.value_tables, self.jump_tables = {}, {}
        for fa in list(self.functions):
            func = self.functions[fa]
            jt_targets = self._scan_tables(func)
            if jt_targets:  # rebuild the function so the case bodies become blocks, then re-link
                self.functions[fa] = func = self._build(fa, jt_targets)
                self._scan_tables(func)  # re-scan the enlarged function for the switch index
                for b in func.blocks.values():
                    jt = self.jump_tables.get(b.insns[-1].address)
                    if jt:
                        b.succs = sorted(set(b.succs) | {t for t in jt["cases"].values() if t in func.blocks})

    _IMM = cs.CS_OP_IMM
    _REG = cs.CS_OP_REG
    _MEM = cs.CS_OP_MEM

    def _scan_tables(self, func):
        """Scan a function's instructions in address order, carrying the last compare bound and the
        set of registers holding constant addresses, so a table load sees a bound set a block
        earlier. State is reset at a join (a block with >1 predecessor) and after calls."""
        preds = Counter(s for b in func.blocks.values() for s in b.succs)
        bound, base, jt_targets = None, {}, []
        for addr in sorted(func.blocks):
            b = func.blocks[addr]
            if preds[addr] > 1:                     # a merge point invalidates carried state
                bound, base = None, {}
            for i in b.insns:
                k = self.arch.kind(i)
                if k == CALL:
                    base = {}
                if i.mnemonic in ("cmp", "subs", "sub") and len(i.operands) >= 2 \
                        and i.operands[-1].type == self._IMM:
                    bound = (i.operands[0], i.operands[-1].imm)
                for r in self.arch.data_refs(i, base):
                    if i.operands and i.operands[0].type == self._REG:
                        base[self._canon_reg(i.reg_name(i.operands[0].reg))] = r
                if k == IJMP:
                    self._jump_table(b, i, base, bound, jt_targets)
                else:
                    self._value_table(i, base, bound)
        return jt_targets

    def _canon_reg(self, name):
        if name and name[0] == "w" and name[1:].isdigit():
            return "x" + name[1:]
        return {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esi": "rsi", "edi": "rdi",
                "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11"}.get(name, name)

    @property
    def x86_like(self):
        return self.arch.name.startswith("x86")

    def _value_table(self, i, base, bound):
        """An indexed load `Rt = *(const_base + idx*scale)` of read-only data, idx bounded -> table."""
        mem = next((o for o in i.operands if o.type == self._MEM), None)
        if mem is None or not i.mnemonic.startswith(("ldr", "mov", "ldur")) or not mem.mem.index or mem.mem.disp:
            return
        breg = self._canon_reg(i.reg_name(mem.mem.base)) if mem.mem.base else None
        tbl = base.get(breg)
        sec = self.image.section_at(tbl) if tbl is not None else None
        if sec is None or sec.code or bound is None or not (0 <= bound[1] <= 8192):
            return
        scale = mem.mem.scale if self.x86_like else (1 << mem.shift.value if mem.shift.type == 1 else 1)
        if scale in (1, 2, 4, 8):
            signed = "ldrs" in i.mnemonic or (self.x86_like and i.mnemonic.startswith("movs"))
            self.value_tables[i.address] = (tbl, scale, bound[1] + 1, signed)

    def _jump_table(self, b, i, base, bound, jt_targets):
        """Computed goto through int32 offsets relative to the table base (the common clang/gcc
        form). Reads the offsets, records the switch, and queues the case bodies for discovery."""
        # a jump table may sit inside the code section (embedded after the branch); the strong
        # guard is that every recovered offset lands on code, checked below.
        cand = [a for a in base.values() if self.image.section_at(a)]
        if not cand or bound is None or not (0 < bound[1] + 1 <= 8192):
            return
        tbl, cases = cand[-1], {}
        for v in range(bound[1] + 1):
            raw = self.image.read(tbl + v * 4, 4)
            if len(raw) < 4:
                return
            t = tbl + int.from_bytes(raw, "little", signed=True)
            if not self.image.is_code(t):
                return
            cases[v] = t
        # the switch value is what indexes the table: find the load from `tbl` in this block and
        # take its index register; fall back to the compared register.
        index = self._canon_reg(i.reg_name(bound[0].reg)) if bound[0].type == self._REG else None
        for j in b.insns:
            mem = next((o for o in j.operands if o.type == self._MEM), None)
            if mem is not None and mem.mem.index:        # the table-indexing load gives the real key
                index = self._canon_reg(j.reg_name(mem.mem.index))
                break
        self.jump_tables[i.address] = {"base": tbl, "cases": cases, "index": index}
        jt_targets.extend(cases.values())

    def _split(self, start, insns):
        leaders = {start}
        for a, i in insns.items():
            k = self.arch.kind(i)
            t = self.arch.target(i)
            if k in (JMP, CJMP) and t in insns:
                leaders.add(t)
            if k in (JMP, CJMP, RET, IJMP) and a + i.size in insns:
                leaders.add(a + i.size)
        blocks, cur = {}, None
        for a in sorted(insns):
            if a in leaders or cur is None or insns[a].address != cur.end:
                cur = blocks[a] = Block(a, [])
            cur.insns.append(insns[a])
            if self.arch.kind(insns[a]) in (JMP, CJMP, RET, IJMP):
                cur = None
        for b in blocks.values():
            last = b.insns[-1]
            k, t = self.arch.kind(last), self.arch.target(last)
            if k in (JMP, CJMP) and t in blocks:
                b.succs.append(t)
            if k not in (JMP, RET, IJMP) and b.end in blocks:
                b.succs.append(b.end)
        return blocks

    def _name_plt_stubs(self):
        """ELF PLT entries are 16 bytes that jump through a GOT slot we already have a name for."""
        for s in self.image.sections:
            if not (s.code and "plt" in s.name):
                continue
            a, regs = s.va, {}
            while a < s.va + s.size:
                i = self.insn(a)
                if i is None:
                    a += 4
                    continue
                for r in self.arch.data_refs(i, regs):
                    if r in self.image.imports:
                        stub = s.va + (a - s.va) // 16 * 16
                        self.names.setdefault(stub, self.image.imports[r])
                        self.image.imports.setdefault(stub, self.image.imports[r])
                a += i.size

    def _prologue_scan(self):
        """Find functions with no symbol and no direct caller by their prologue, in uncovered code."""
        covered = set()
        for f in self.functions.values():
            for b in f.blocks.values():
                covered.update(range(b.addr, b.end))
        x86 = self.arch.name.startswith("x86")
        for s in self.image.sections:
            if not s.code or "plt" in s.name or "stub" in s.name:
                continue
            data = self.image.read(s.va, s.size)
            if x86:
                pats = rb"\x55\x48\x89\xe5|\xf3\x0f\x1e\xfa\x55" if self.arch.bits == 64 else rb"\x55\x89\xe5"
                cands = (m.start() for m in re.finditer(pats, data))
            else:
                cands = range(0, len(data) - 3, 4)
            for off in cands:
                a = s.va + off
                if a in covered:
                    continue
                if not x86:
                    i = self.insn(a)
                    if not i or not (i.mnemonic == "pacibsp" or
                                     (i.mnemonic == "stp" and i.op_str.startswith("x29, x30, [sp, #-"))):
                        continue
                    prev = self.insn(a - 4) if off else None
                    if prev and prev.mnemonic == "pacibsp":
                        continue
                yield a

    # -- queries ------------------------------------------------------------
    def function_at(self, a):
        """Function containing address `a` (start or interior)."""
        if a in self.functions:
            return self.functions[a]
        import bisect
        key = (len(self.functions), id(self.functions))
        if getattr(self, "_fidx_key", None) != key:  # rebuild when functions change
            self._fidx = sorted(self.functions)
            self._fidx_key = key
        i = bisect.bisect_right(self._fidx, a) - 1
        # nearest preceding start first (the common case), then any function owning a block there
        for start in ([self._fidx[i]] if i >= 0 else []):
            f = self.functions.get(start)
            if f and any(b.addr <= a < b.end for b in f.blocks.values()):
                return f
        for f in self.functions.values():
            if any(b.addr <= a < b.end for b in f.blocks.values()):
                return f
        return None

    def resolve(self, what):
        """Name, sub_xxx, or 0xaddr -> address."""
        if isinstance(what, int):
            return what
        w = what.strip()
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", w) and (w.startswith("0x") or not w.isalpha()):
            return int(w, 16)
        for a, n in self.user_names.items():
            if n == w:
                return a
        for a, n in self.names.items():
            if n == w or n.lstrip("_") == w.lstrip("_"):
                return a
        raise KeyError(f"no such symbol: {what}")

    def strings(self, minlen=4):
        """{va: text} for C strings (and UTF-16LE on PE) in data sections."""
        if self._strings is None:
            out = {}
            for s in self.image.sections:
                if s.code or s.name in (".bss", "__bss", "__common"):
                    continue
                data = self.image.read(s.va, s.size)
                for m in re.finditer(rb"[\x20-\x7e\t\r\n]{%d,}\x00" % minlen, data):
                    out[s.va + m.start()] = m.group()[:-1].decode()
                if self.image.format == "pe":
                    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}\x00\x00" % minlen, data):
                        out.setdefault(s.va + m.start(), m.group()[:-2].decode("utf-16le"))
            self._strings = out
        return self._strings

    def xrefs_to(self, a):
        return sorted(self.xrefs.get(a, ()))
