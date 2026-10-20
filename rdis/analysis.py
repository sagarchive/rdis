"""Whole-program analysis: functions, basic blocks, cross-references, strings."""
from collections import Counter, defaultdict
from collections.abc import MutableSet
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import warnings

import capstone as cs

from .arch import CALL, RET, JMP, CJMP, IJMP
from .demangle import demangle_all
from .objc import ObjC
from .swift import Swift

MAX_INSNS = 50_000  # Safety cap against runaway descent into data.


def _canonical_binary_path(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))


def _binary_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as binary:
        for chunk in iter(lambda: binary.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()



@dataclass
class Block:
    addr: int
    insns: list
    succs: list = field(default_factory=list)
    delay: object = None  # MIPS: the branch-delay-slot instruction after the terminator

    @property
    def end(self):
        last = self.delay or self.insns[-1]
        return last.address + last.size

    @property
    def shown(self):
        """Instructions in address order, delay slot included (for listings and graphs)."""
        return self.insns + [self.delay] if self.delay else self.insns


@dataclass
class Function:
    addr: int
    blocks: dict  # addr -> Block, in address order
    calls: set    # callee code addresses

    @property
    def end(self):
        return max(b.end for b in self.blocks.values())


class _CowXrefSet(MutableSet):
    """Set-like view that copies one shared xref set only when someone mutates it."""

    def __init__(self, owner, key):
        self._owner, self._key = owner, key

    def _view(self):
        if dict.__contains__(self._owner, self._key):
            return dict.__getitem__(self._owner, self._key)
        return self._owner.base.get(self._key, ())

    def __contains__(self, value):
        return value in self._view()

    def __iter__(self):
        return iter(self._view())

    def __len__(self):
        return len(self._view())

    def add(self, value):
        self._owner[self._key].add(value)

    def discard(self, value):
        if value in self._view():
            self._owner[self._key].discard(value)

    def clear(self):
        self._owner[self._key].clear()

    def __repr__(self):
        return repr(set(self._view()))


class _LayerXrefs(dict):
    """Copy-on-write xrefs for per-session analysis overlays without mutable base aliases."""

    def __init__(self, base):
        super().__init__()
        self.base = base

    def __missing__(self, k):
        v = self[k] = set(self.base.get(k, ()))
        return v

    def get(self, k, default=None):
        if dict.__contains__(self, k):
            return dict.__getitem__(self, k)
        if k in self.base:
            return _CowXrefSet(self, k)
        return default

    def items(self):
        own = dict(dict.items(self))
        return list(own.items()) + [
            (k, _CowXrefSet(self, k)) for k in self.base if k not in own
        ]

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
        self.jni_natives = {}  # fn addr -> (java name, signature, thumb) from RegisterNatives tables

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
            # decode a short linear run, not one instruction: the per-call Capstone overhead dominated
            # analysis, and a decode at an address is the same however it is reached, so caching the
            # neighbours is always valid (the walker usually asks for exactly those next).
            for i in self.arch.decode_run(self.image.read(a, 96), a, thumb):
                self._insns.setdefault((i.address, thumb), i)
            self._insns.setdefault(key, None)
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
        seeds += self._jni_natives()
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

    def _jni_natives(self):
        """Name RegisterNatives targets from their JNINativeMethod tables; return them as seeds."""
        from . import jni
        self.jni_natives = {} if self.image.format != "elf" else jni.native_tables(self.image)
        for fn, (name, sig, thumb) in self.jni_natives.items():
            if thumb:
                self.image.thumb.add(fn)
            self.auto_name(fn, name)
        return list(self.jni_natives)

    # -- user edits: procedures, data types, bookmarks ----------------------
    def create_function(self, a):
        """Mark `a` as a procedure start (Hopper's P) and analyze it."""
        a = int(a)
        self._private_analysis()
        self.user_procs.add(a)
        self.removed_procs.discard(a)
        self.functions.pop(a, None)
        self._discover([a])
        self.names.setdefault(a, f"sub_{a:x}")
        return self.functions.get(a)

    def _private_analysis(self):
        """Before an overlay discovers code: give it its own xref layer and mode map, so the
        shared analysis (seen by every other visitor) is never written."""
        base = getattr(self, "_shared", None)
        if base is not None and self.xrefs is base.xrefs:
            self.xrefs = _LayerXrefs(base.xrefs)
            self._tmode = dict(self._tmode)

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
        """Atomically save annotations bound to the exact binary content and analysis identity."""
        identity_path = _canonical_binary_path(self.image.path)
        digest = _binary_sha256(self.image.path)
        data = {
            "rdb_version": 2,
            "path": identity_path,
            "format": self.image.format,
            "arch": self.arch.name,
            "binary_sha256": digest,
            "names": {str(k): v for k, v in self.user_names.items()},
            "comments": {str(k): v for k, v in self.comments.items()},
            "bookmarks": sorted(self.bookmarks),
            "types": {str(k): v for k, v in self.user_types.items()},
            "procs": sorted(self.user_procs),
            "removed": sorted(self.removed_procs),
        }
        target = os.path.abspath(os.fspath(path))
        directory = os.path.dirname(target) or os.curdir
        os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".rdis-rdb-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return path

    def load(self, path, *, allow_legacy=False):
        """Load annotations only when their binary identity is verified.

        Version-1 sidecars have no content digest. They are preserved on disk but ignored by
        default because a same-path binary replacement cannot be detected retrospectively. A caller
        that has independently verified the original binary can explicitly opt into legacy import.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError, TypeError):
            return self
        if not isinstance(data, dict):
            return self

        def reject(reason):
            warnings.warn(f"Ignoring RDIS sidecar {os.fspath(path)!r}: {reason}",
                          RuntimeWarning, stacklevel=2)
            return self

        saved_path = data.get("path")
        try:
            saved_path = _canonical_binary_path(saved_path) if isinstance(saved_path, str) else None
            current_path = _canonical_binary_path(self.image.path)
        except (OSError, TypeError, ValueError):
            return reject("binary path identity is invalid")
        if saved_path != current_path:
            return reject("sidecar belongs to a different binary path")
        if data.get("format") != self.image.format:
            return reject("binary format does not match")
        if data.get("arch") != self.arch.name:
            return reject("architecture does not match")

        version = data.get("rdb_version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version not in (1, 2):
            return reject("unsupported sidecar schema version")
        if version == 1:
            if not allow_legacy:
                return reject("legacy sidecar has no binary content digest; pass allow_legacy=True only after verifying the original binary")
            warnings.warn(f"Importing unverified legacy RDIS sidecar {os.fspath(path)!r}; binary content identity cannot be proven",
                          RuntimeWarning, stacklevel=2)
        else:
            saved_digest = data.get("binary_sha256")
            if not isinstance(saved_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", saved_digest):
                return reject("binary content digest is malformed")
            try:
                current_digest = _binary_sha256(self.image.path)
            except OSError:
                return reject("source binary cannot be fingerprinted")
            if not hmac.compare_digest(saved_digest, current_digest):
                return reject("binary content digest does not match")

        def strmap(key):
            out = {}
            values = data.get(key)
            for k, v in values.items() if isinstance(values, dict) else ():
                try:
                    if isinstance(v, str):
                        out[int(k)] = v
                except (TypeError, ValueError):
                    pass
            return out

        def addrs(key):
            values = data.get(key)
            return [a for a in values if isinstance(a, int) and not isinstance(a, bool)] if isinstance(values, list) else []

        self.user_names.update(strmap("names"))
        self.comments.update(strmap("comments"))
        self.bookmarks.update(addrs("bookmarks"))
        self.user_types.update({k: v for k, v in strmap("types").items() if v in ("data", "ascii", "code")})
        for a in addrs("procs")[:4096]:
            if a not in self.functions:
                self.create_function(a)
        for a in addrs("removed")[:4096]:
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
        delays = set()
        while work and len(insns) < MAX_INSNS:
            (a, tm), regs = work.pop(), {}
            while a not in seen and self.image.is_code(a):
                seen.add(a)
                i = self.insn(a, tm)
                if i is None:
                    break
                insns[a] = i
                k = self.arch.kind(i)
                step = i.size
                if self.arch.delay_slot and k in (JMP, CJMP, IJMP, RET):
                    d = self.insn(a + i.size)          # executes before the branch takes effect
                    if d is not None:
                        insns[d.address] = d
                        seen.add(d.address)
                        delays.add(d.address)
                        step += d.size                  # fall through past the slot
                        for r in self.arch.data_refs(d, dict(regs)):  # `addiu a0, %lo(s)` in a slot
                            self.xrefs[r].add((d.address, "data"))
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
                a += step
        return Function(start, self._split(start, insns, delays), calls)

    def _recover_tables(self):
        """Recover lookup/jump tables so optimized switches decompile and computed gotos resolve.

        self.value_tables[load_addr] = (table_addr, elem_size, count, signed) -- an indexed load of
            constant read-only data bounded by a preceding compare (an optimized `switch` returning
            a value, a character-class table, etc.).
        self.jump_tables[ijmp_addr]  = {"base", "cases": {case_value: target}} -- a computed goto
            through a table of int32 offsets relative to a code base (often an ADR target) recorded by the branch sequence.
        Jump-table case bodies are added to the owning function (rebuilt with them as extra seeds).
        """
        self.value_tables, self.jump_tables = {}, {}
        if not self.arch.name.startswith(("x86", "arm")):
            return   # Table-pattern matching currently covers x86/ARM operand shapes; other ISAs retain indirect-goto output.
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
        starts = sorted(self.functions)
        # the next function start *outside* this function's own blocks: optimized code shares and
        # overlaps tails, so a start nested inside our body is not where our cases end
        inside = lambda a: any(b.addr <= a < b.end for b in func.blocks.values())
        func_end = next((a for a in starts if a > func.addr and not inside(a)), None)
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
                    self._jump_table(func, func_end, b, i, base, bound, jt_targets)
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

    def _jump_table(self, func, func_end, b, i, base, bound, jt_targets):
        """Recover an int32-relative jump table only from the actual indexed load feeding
        this indirect branch. Arbitrary address constants in the block are not table candidates:
        interpreting them as table bases can turn adjacent function code into fake switch cases."""
        if bound is None or not (0 < bound[1] + 1 <= 8192):
            return
        # Relative offsets are not necessarily relative to the table itself. On AArch64, clang
        # commonly loads int32 offsets from [table + index*4] and adds them to a separate ADR base
        # before BR. Recover that target base from the ADD feeding the indirect branch.
        target_reg = (self._canon_reg(i.reg_name(i.operands[-1].reg))
                      if i.operands and i.operands[-1].type == self._REG else None)
        target_base = None
        if target_reg:
            for insn in reversed(b.insns):
                if insn.address >= i.address or not insn.operands or insn.operands[0].type != self._REG:
                    continue
                if self._canon_reg(insn.reg_name(insn.operands[0].reg)) != target_reg:
                    continue
                if not insn.mnemonic.startswith("add"):
                    continue
                for op in insn.operands[1:]:
                    if op.type == self._REG:
                        source_reg = self._canon_reg(insn.reg_name(op.reg))
                        if source_reg in base:
                            target_base = base[source_reg]
                            break
                if target_base is not None:
                    break
        if target_base is None:
            return
        candidates = []
        for insn in b.insns:
            for mem in (o for o in insn.operands if o.type == self._MEM and o.mem.index):
                breg = self._canon_reg(insn.reg_name(mem.mem.base)) if mem.mem.base else None
                table_addr = base.get(breg)
                if table_addr is None or self.image.section_at(table_addr) is None:
                    continue
                scale = mem.mem.scale if self.x86_like else (
                    1 << mem.shift.value if mem.shift.type == 1 else 1
                )
                if scale == 4:
                    index = self._canon_reg(insn.reg_name(mem.mem.index))
                    candidates.append((table_addr, index))
        for table_addr, index in candidates:
            cases = {}
            for value in range(bound[1] + 1):
                raw = self.image.read(table_addr + value * 4, 4)
                if len(raw) < 4:
                    break
                target = target_base + int.from_bytes(raw, "little", signed=True)
                # A recovered case must belong to this function's address range. Merely landing
                # in any executable section is insufficient: it can accidentally absorb the next
                # function and generate a plausible but semantically unrelated CFG.
                if (not self.image.is_code(target) or target < func.addr or
                        (func_end is not None and target >= func_end)):
                    break
                cases[value] = target
            if len(cases) != bound[1] + 1:
                continue
            self.jump_tables[i.address] = {"base": table_addr, "target_base": target_base, "cases": cases, "index": index}
            jt_targets.extend(cases.values())
            return

    def _split(self, start, insns, delays=()):
        leaders = {start}
        for a, i in insns.items():
            if a in delays:
                continue
            k = self.arch.kind(i)
            t = self.arch.target(i)
            if k in (JMP, CJMP) and t in insns:
                leaders.add(t)
            if k in (JMP, CJMP, RET, IJMP):
                nxt = a + i.size
                if nxt in delays:
                    nxt += insns[nxt].size
                if nxt in insns:
                    leaders.add(nxt)
        blocks, cur, last = {}, None, None
        for a in sorted(insns):
            if a in delays and last is not None and last.end == a and last.delay is None:
                last.delay = insns[a]               # belongs to the branch just before it
                continue
            if a in leaders or cur is None or insns[a].address != cur.end:
                cur = blocks[a] = Block(a, [])
            cur.insns.append(insns[a])
            last = cur
            if self.arch.kind(insns[a]) in (JMP, CJMP, RET, IJMP):
                cur = None
        for b in blocks.values():
            last = b.insns[-1]
            k, t = self.arch.kind(last), self.arch.target(last)
            if k in (JMP, CJMP) and t in blocks:
                b.succs.append(t)
            if k not in (JMP, RET, IJMP) and b.end in blocks and b.end not in b.succs:
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
        pat, align, after, thumb = self._prologue_pattern()
        if pat is None:
            return
        for s in self.image.sections:
            if not s.code or "plt" in s.name or "stub" in s.name:
                continue
            data = self.image.read(s.va, s.size)
            # Match encodings, not decoded text: decoding every word dominated analysis time.
            # Add the valid AArch64 allocation-first frame shape separately. Keep the existing
            # regex specific to frame-save-first prologues so an interior STP is not a new function.
            offsets = {m.start() for m in re.finditer(b"(?=(?:" + pat + b"))", data, re.S)}
            if self.arch.name == "arm64":
                offsets.update(
                    off for off in range(0, max(0, len(data) - 3), 4)
                    if self._arm64_stack_adjust_then_fp_lr_save(data, off)
                    or self._arm64_stack_adjust_with_stack_access(data, off)
                )
            for off in sorted(offsets):
                a = s.va + off
                if a % align or a in covered:
                    continue
                # x86 prologue byte signatures are common enough inside immediate/data bytes to
                # create false functions. Give their boundary predicate a wider context so it can
                # verify that the candidate follows a RET/JMP or conventional padding. Other ISAs
                # have fixed-width/local boundary rules and keep their original four-byte window.
                window = 16 if self.arch.name.startswith("x86") else 4
                prev = data[max(off - window, 0):off]
                if after is not None and off and not after(prev):
                    continue
                if thumb:
                    self._tmode.setdefault(a, True)
                yield a

    _PACIBSP = b"\x7f\x23\x03\xd5"

    @staticmethod
    def _arm64_terminator_before(data, offset):
        """Require a real code boundary (or section start) before a gap-scan candidate."""
        if offset <= 0:
            return True
        # Permit a short run of AArch64 NOP alignment after a terminating instruction.
        pos = offset - 4
        for _ in range(4):
            if pos < 0:
                return True
            word = int.from_bytes(data[pos:pos + 4], "little")
            if word == 0xD503201F:  # NOP padding
                pos -= 4
                continue
            if (word & 0xFFFFFC1F) == 0xD65F0000:  # RET Xn (including RET X30)
                return True
            if (word & 0xFC000000) == 0x14000000:  # unconditional B, not BL
                return True
            if (word & 0xFFFFFC1F) == 0xD61F0000:  # BR Xn tail branch
                return True
            return False
        return False

    @staticmethod
    def _arm64_stack_adjust_with_stack_access(data, offset):
        """Find leaf AArch64 frames that allocate SP and spill locals without saving FP/LR.

        Leaf functions often do not save x29/x30 at all. Their first instruction can be
        SUB SP,SP,#N followed by STR/LDR through SP; the old STP-based pattern misses these.
        Requiring both a terminating preceding instruction and a nearby SP-based memory access
        avoids treating arbitrary SUB instructions in a live basic block as function starts.
        """
        if offset < 0 or offset + 4 > len(data) or offset % 4:
            return False
        first = int.from_bytes(data[offset:offset + 4], "little")
        # SUB SP, SP, #imm12{, LSL #12}. Mask the immediate and shift bit, then require
        # a real nonzero allocation (zero imm12 with LSL #12 is also a valid 4 KiB frame).
        if (first & 0xFF0003FF) != 0xD10003FF:
            return False
        imm12 = (first >> 10) & 0xFFF
        shift12 = (first >> 22) & 1
        if imm12 == 0 and not shift12:
            return False
        if not Program._arm64_terminator_before(data, offset):
            return False

        stack_memory_ops = {
            0xB8000000, 0xB8400000, 0xB9000000, 0xB9400000,
            0xF8000000, 0xF8400000, 0xF9000000, 0xF9400000,
            0xA8800000, 0xA8C00000, 0xA9000000, 0xA9400000,
        }
        # Search the start of the prologue, not the entire function, for an SP-based access.
        for pos in range(offset + 4, min(len(data) - 3, offset + 24), 4):
            word = int.from_bytes(data[pos:pos + 4], "little")
            if (word & 0xFFC00000) in stack_memory_ops and ((word >> 5) & 0x1F) == 31:
                return True
            # A branch or return before any stack access means this is not a frame prologue.
            if ((word & 0xFFFFFC1F) == 0xD65F0000
                    or (word & 0xFC000000) in (0x14000000, 0x94000000)
                    or (word & 0xFFFFFC1F) in (0xD61F0000, 0xD63F0000)):
                return False
        return False

    @staticmethod
    def _arm64_stack_adjust_then_fp_lr_save(data, offset):
        """Recognize an AArch64 frame whose first instruction allocates the stack.

        Clang commonly emits SUB SP, SP, #frame_size before saving x29/x30 at a
        positive offset inside that frame. The older gap scan only recognized a paired
        frame save as the first instruction, so stripped Mach-O functions with larger
        stack frames could be missed despite having a conventional prologue.

        Require a non-zero immediate stack allocation followed within four instructions
        by an STP x29,x30 whose base is SP. The scan runs only on uncovered, aligned code.
        """
        if offset < 0 or offset + 4 > len(data):
            return False
        first = int.from_bytes(data[offset:offset + 4], "little")
        # SUB (immediate), 64-bit, flags not set, Rd=SP and Rn=SP. Mask out imm12
        # and its optional shift bit; reject SUB SP,SP,#0.
        if (first & 0xFF8003FF) != 0xD10003FF or ((first >> 10) & 0xFFF) == 0:
            return False

        stop = min(len(data) - 3, offset + 20)
        for pos in range(offset + 4, stop, 4):
            word = int.from_bytes(data[pos:pos + 4], "little")
            # STP x29,x30,[sp,#imm], including offset/pre-index/post-index address modes.
            # Rt=x29, Rn=sp, Rt2=x30; A8/A9 are 64-bit integer pair-store encodings.
            if (word >> 24) in (0xA8, 0xA9) and (word & 0x7FFF) == 0x7BFD:
                return True
        return False

    @staticmethod
    def _x86_after_terminator(prev):
        """Conservative x86 gap-scan guard to avoid nested prologue-like byte sequences."""
        if not prev:
            return True
        # Padding often lies between functions; inspect the bytes before that padding for the
        # terminal instruction. Keep the recognized set deliberately narrow and auditable.
        for pad_len in range(min(len(prev), 8) + 1):
            prefix = prev[:len(prev) - pad_len] if pad_len else prev
            padding = prev[len(prev) - pad_len:] if pad_len else b""
            if any(byte not in (0x90, 0xcc) for byte in padding):
                continue
            if not prefix:
                return True  # a section beginning/padding run
            if prefix[-1] in (0xc3, 0xcb):  # RET / RETF
                return True
            if len(prefix) >= 3 and prefix[-3] in (0xc2, 0xca):  # RET imm16 / RETF imm16
                return True
            if len(prefix) >= 2 and prefix[-2] == 0xeb:  # JMP rel8 ending exactly at the boundary
                return True
            if len(prefix) >= 5 and prefix[-5] == 0xe9:  # JMP rel32 ending exactly at the boundary
                return True
        return False

    def _prologue_pattern(self):
        """(byte regex, alignment, previous-bytes check, is_thumb) for function-entry encodings."""
        n, bits = self.arch.name, self.arch.bits
        if n.startswith("x86"):
            # This signature can also appear inside an instruction stream or embedded bytes.
            # Require a plausible boundary before accepting a byte-scan candidate: a RET,
            # relative JMP, or conventional NOP/INT3 padding after a terminating instruction.
            # Symbol/debug starts still seed analysis independently of this heuristic.
            return (rb"\x55\x48\x89\xe5|\xf3\x0f\x1e\xfa\x55" if bits == 64 else rb"\x55\x89\xe5"), 1, self._x86_after_terminator, False
        if n == "arm64":
            # pacibsp, or `stp x29, x30, [sp, #-N]` (pre-index or signed offset, negative imm7);
            # a stp right after a pacibsp belongs to that function, not a new one. Dart AOT keeps
            # its stack in x15, so its frames open with `stp x29, x30, [x15, #-N]!`.
            return (re.escape(self._PACIBSP) + rb"|\xfd[\x7b\xfb][\x20-\x3f\xa0-\xbf]\xa9"
                    rb"|\xfd[\x79\xf9][\xa0-\xbf]\xa9", 4,
                    lambda p: p != self._PACIBSP, False)
        if n == "arm":
            if self.image.thumb:   # Thumb code (Android armeabi-v7a): `push {..., lr}` after a
                # function end — pop {..,pc} / bx lr / nop / padding — since 2 bytes alone are weak
                end = lambda p: p[-1:] == b"\xbd" or p[-2:] in (b"\x70\x47", b"\x00\xbf", b"\x00\x00")
                return rb"[\x00-\xff]\xb5", 2, end, True
            return rb"[\x00-\xff][\x40-\x7f\xc0-\xff]\x2d\xe9", 4, None, False   # ARM `push {..., lr}`
        if n.startswith("mips"):
            le = n.endswith("el")   # `addiu $sp, $sp, -N`
            # `addiu $sp, $sp, -N` (0x27bd) or MIPS64 `daddiu $sp, $sp, -N` (0x67bd)
            return (rb"[\x00-\xff][\x80-\xff]\xbd[\x27\x67]" if le else rb"[\x27\x67]\xbd[\x80-\xff][\x00-\xff]"), 4, None, False
        if n.startswith("riscv"):
            # `addi sp, sp, -N` (32-bit) or c.addi16sp / c.addi sp, -N (RVC) after a return/padding
            end = lambda p: p[-2:] in (b"\x82\x80", b"\x01\x00", b"\x00\x00") or p == b"\x67\x80\x00\x00"
            return rb"\x13\x01[\x01\x11\x21\x31\x41\x51\x61\x71\x81\x91\xa1\xb1\xc1\xd1\xe1\xf1][\x80-\xff]" \
                   rb"|[\x01\x05\x09\x0d\x11\x15\x19\x1d\x21\x25\x29\x2d\x31\x35\x39\x3d" \
                   rb"\x41\x45\x49\x4d\x51\x55\x59\x5d\x61\x65\x69\x6d\x71\x75\x79\x7d][\x11\x71]", 2, end, False
        return None, 1, None, False

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
