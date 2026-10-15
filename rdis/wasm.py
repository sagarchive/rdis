"""WebAssembly module analysis: parse a .wasm binary and disassemble its functions.

Capstone has no WASM backend, so this is a self-contained decoder for the WebAssembly binary format
(https://webassembly.github.io/spec/core/binary/). It recovers the module's types, imports, exports,
globals, memory, data segments (strings), and every function body as a disassembled instruction
listing with resolved call/local/global targets. It plugs into the server through a `WasmProgram`
adapter that quacks like `analysis.Program` for the read routes (info/functions/strings/imports/
listing/search); pseudo-code and CFG are reported as not-yet-supported for the stack machine.
"""
import struct


_LEB_MAX = 10      # a 64-bit LEB128 is at most 10 bytes; longer runs are malformed (and would let a
                   # crafted module build a megabit integer one byte at a time: quadratic CPU)
_MAX_LOCALS = 50000  # per-function local count cap (engines enforce the same): a 30-byte module
                     # declaring 300M locals would otherwise allocate gigabytes


def _uleb(data, p):
    r = s = 0
    for _ in range(_LEB_MAX):
        if p >= len(data):
            raise ValueError("truncated unsigned LEB128")
        b = data[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            if s == 70 and b & 0x7E:
                raise ValueError("unsigned LEB128 exceeds 64 bits")
            return r, p
    raise ValueError("LEB128 too long")


def _sleb(data, p):
    r = s = 0
    for _ in range(_LEB_MAX):
        if p >= len(data):
            raise ValueError("truncated signed LEB128")
        b = data[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            if b & 0x40:
                r |= -(1 << s)
            return r, p
    raise ValueError("LEB128 too long")


def _name(data, p, end=None):
    n, p = _uleb(data, p)
    stop = p + n
    if stop > len(data) or (end is not None and stop > end):
        raise ValueError("truncated WebAssembly name")
    return data[p:stop].decode("utf-8", "replace"), stop


_VALTYPE = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x7B: "v128",
            0x70: "funcref", 0x6F: "externref"}
_SECTION = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
            6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data", 12: "datacount"}
_EXPORT_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}


class Func:
    def __init__(self, index, addr, name, sig, imported=False):
        self.index, self.addr, self.name, self.sig, self.imported = index, addr, name, sig, imported
        self.insns = []    # (offset, mnemonic, operands, call_target|None)
        self.locals = []
        self.end = addr


class WasmModule:
    def __init__(self, data):
        self.data = data
        self.types, self.imports, self.exports = [], [], []
        self.func_types = []        # type index per defined function
        self.globals, self.memories, self.tables = [], [], []
        self.data_segments, self.func_names = [], {}
        self.start = None
        if data[:4] != b"\0asm":
            raise ValueError("not a WebAssembly module")
        if len(data) < 8:
            raise ValueError("truncated WebAssembly header")
        self.version = struct.unpack_from("<I", data, 4)[0]
        self.errors = []
        self._parse_sections()
        self.funcs = self._build_funcs()

    # -- sections -----------------------------------------------------------
    def _parse_sections(self):
        data, p, n = self.data, 8, len(self.data)
        self.code_entries = []
        while p < n:
            sid = data[p]
            size, p = _uleb(data, p + 1)
            body_end = p + size
            if body_end > n:
                raise ValueError(f"WebAssembly section {sid} exceeds module bounds")
            try:
                self._section(sid, p, body_end)
            except (IndexError, struct.error, ValueError) as exc:
                # Keep the module inspectable but never silently hide that metadata was malformed.
                self.errors.append(f"section {sid}: {exc}")
            p = body_end

    def _section(self, sid, p, end):
        data = self.data
        if sid == 1:    # type: vec of func types
            count, p = _uleb(data, p)
            for _ in range(count):
                assert data[p] == 0x60
                p += 1
                np, p = _uleb(data, p)
                params = [_VALTYPE.get(data[p + i], "?") for i in range(np)]
                p += np
                nr, p = _uleb(data, p)
                results = [_VALTYPE.get(data[p + i], "?") for i in range(nr)]
                p += nr
                self.types.append((params, results))
        elif sid == 2:  # import
            count, p = _uleb(data, p)
            for _ in range(count):
                mod, p = _name(data, p, end)
                field, p = _name(data, p, end)
                if p >= end:
                    raise ValueError("truncated import descriptor")
                kind = data[p]
                p += 1
                if kind == 0:  # function type index
                    idx, p = _uleb(data, p)
                elif kind == 1:  # table type: reference type + limits
                    if p >= end:
                        raise ValueError("truncated table import")
                    p += 1
                    p = self._skip_limits(p, end)
                    idx = -1
                elif kind == 2:  # memory limits
                    p = self._skip_limits(p, end)
                    idx = -1
                elif kind == 3:  # global type + mutability
                    if p + 2 > end:
                        raise ValueError("truncated global import")
                    p += 2
                    idx = -1
                else:
                    raise ValueError(f"unknown import kind {kind}")
                if p > end:
                    raise ValueError("import descriptor exceeds section bounds")
                self.imports.append({"module": mod, "field": field, "kind": _EXPORT_KIND.get(kind, "?"),
                                     "type": idx})
        elif sid == 3:  # function: type index per defined func
            count, p = _uleb(data, p)
            for _ in range(count):
                t, p = _uleb(data, p)
                self.func_types.append(t)
        elif sid == 7:  # export
            count, p = _uleb(data, p)
            for _ in range(count):
                nm, p = _name(data, p)
                kind = data[p]
                idx, p = _uleb(data, p + 1)
                self.exports.append({"name": nm, "kind": _EXPORT_KIND.get(kind, "?"), "index": idx})
        elif sid == 8:  # start
            self.start, p = _uleb(data, p)
        elif sid == 10:  # code: function bodies
            count, p = _uleb(data, p)
            for _ in range(count):
                sz, p = _uleb(data, p)
                self.code_entries.append((p, p + sz))
                p += sz
        elif sid == 11:  # data segments (strings live here)
            count, p = _uleb(data, p)
            for _ in range(count):
                flags, p = _uleb(data, p)
                if flags == 0:       # active, memory 0, offset expr
                    p = self._skip_expr(p, end)
                elif flags == 1:  # passive data segment: no offset expression
                    pass
                elif flags == 2:
                    _, p = _uleb(data, p)
                    p = self._skip_expr(p, end)
                else:
                    raise ValueError(f"unsupported data segment flags {flags}")
                ln, p = _uleb(data, p)
                if p + ln > end:
                    raise ValueError("data segment exceeds section bounds")
                self.data_segments.append((p, data[p:p + ln]))
                p += ln
        elif sid == 0:  # custom: the "name" section maps indices to names
            nm, p = _name(data, p, end)
            if nm == "name":
                self._name_section(p, end)
        if p > end:
            raise ValueError(f"section {sid} exceeds its declared size")
        return p

    def _skip_limits(self, p, end):
        flags, p = _uleb(self.data, p)
        _, p = _uleb(self.data, p)  # minimum
        if flags & 1:
            _, p = _uleb(self.data, p)  # maximum
        if p > end:
            raise ValueError("limits exceed section bounds")
        return p

    def _skip_expr(self, p, end):
        while p < end and self.data[p] != 0x0B:  # end
            p += 1
        if p >= end:
            raise ValueError("unterminated constant expression")
        return p + 1

    def _name_section(self, p, end):
        data = self.data
        while p < end:
            sub, p = data[p], p + 1
            sz, p = _uleb(data, p)
            stop = p + sz
            if stop > end:
                raise ValueError("name subsection exceeds custom section bounds")
            if sub == 1:  # function names
                count, p = _uleb(data, p)
                for _ in range(count):
                    idx, p = _uleb(data, p)
                    nm, p = _name(data, p, stop)
                    self.func_names[idx] = nm
            p = stop

    # -- functions ----------------------------------------------------------
    def _build_funcs(self):
        funcs, idx = [], 0
        imported = [im for im in self.imports if im["kind"] == "func"]
        export_name = {e["index"]: e["name"] for e in self.exports if e["kind"] == "func"}
        for im in imported:   # imported functions have no body
            name = self.func_names.get(idx) or f"{im['module']}.{im['field']}"
            funcs.append(Func(idx, -1 - idx, name, self.types[im["type"]] if im["type"] < len(self.types) else None,
                              imported=True))
            idx += 1
        for n, (start, end) in enumerate(self.code_entries):
            ti = self.func_types[n] if n < len(self.func_types) else None
            sig = self.types[ti] if ti is not None and ti < len(self.types) else None
            name = self.func_names.get(idx) or export_name.get(idx) or f"func_{idx}"
            f = Func(idx, start, name, sig)
            try:
                self._disasm_body(f, start, min(end, len(self.data)))
            except Exception:
                f.end = max(f.end, end)  # a malformed body keeps what decoded; others still load
            funcs.append(f)
            idx += 1
        self.by_index = {f.index: f for f in funcs}
        return funcs

    def _disasm_body(self, f, p, end):
        data = self.data
        nloc, p = _uleb(data, p)        # locals: vec of (count, valtype)
        for _ in range(nloc):
            c, p = _uleb(data, p)
            t = _VALTYPE.get(data[p], "?")
            p += 1
            if len(f.locals) + c > _MAX_LOCALS:
                raise ValueError("too many locals")
            f.locals += [t] * c
        depth = 0
        while p < end:
            off = p
            op = data[p]
            p += 1
            mnem, operands, target, p, depth = decode(data, p, op, depth, self)
            f.insns.append((off, mnem, operands, target))
            if p > end:
                break
        f.end = end


# ---- opcode decoding ------------------------------------------------------
_SIMPLE = {
    0x00: "unreachable", 0x01: "nop", 0x0B: "end", 0x05: "else", 0x0F: "return",
    0x1A: "drop", 0x1B: "select",
    0x45: "i32.eqz", 0x46: "i32.eq", 0x47: "i32.ne", 0x48: "i32.lt_s", 0x49: "i32.lt_u",
    0x4A: "i32.gt_s", 0x4B: "i32.gt_u", 0x4C: "i32.le_s", 0x4D: "i32.le_u", 0x4E: "i32.ge_s",
    0x4F: "i32.ge_u", 0x50: "i64.eqz", 0x51: "i64.eq", 0x52: "i64.ne", 0x53: "i64.lt_s",
    0x6A: "i32.add", 0x6B: "i32.sub", 0x6C: "i32.mul", 0x6D: "i32.div_s", 0x6E: "i32.div_u",
    0x6F: "i32.rem_s", 0x70: "i32.rem_u", 0x71: "i32.and", 0x72: "i32.or", 0x73: "i32.xor",
    0x74: "i32.shl", 0x75: "i32.shr_s", 0x76: "i32.shr_u", 0x77: "i32.rotl", 0x78: "i32.rotr",
    0x7C: "i64.add", 0x7D: "i64.sub", 0x7E: "i64.mul", 0x7F: "i64.div_s",
    0x92: "f32.add", 0x93: "f32.sub", 0x94: "f32.mul", 0x95: "f32.div",
    0xA0: "f64.add", 0xA1: "f64.sub", 0xA2: "f64.mul", 0xA3: "f64.div",
    0x67: "i32.clz", 0x68: "i32.ctz", 0x69: "i32.popcnt", 0xA7: "i32.wrap_i64",
}
_LOCAL = {0x20: "local.get", 0x21: "local.set", 0x22: "local.tee", 0x23: "global.get", 0x24: "global.set"}
_MEM = {0x28: "i32.load", 0x29: "i64.load", 0x2A: "f32.load", 0x2B: "f64.load",
        0x2C: "i32.load8_s", 0x2D: "i32.load8_u", 0x2E: "i32.load16_s", 0x2F: "i32.load16_u",
        0x36: "i32.store", 0x37: "i64.store", 0x38: "f32.store", 0x39: "f64.store",
        0x3A: "i32.store8", 0x3B: "i32.store16"}
_BLOCKTYPE = {0x40: "void", 0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}


def decode(data, p, op, depth, mod):
    """Decode one instruction. Returns (mnemonic, operands_str, call_target_index|None, new_p, depth)."""
    target = None
    if op in _SIMPLE:
        return _SIMPLE[op], "", None, p, depth
    if op in (0x02, 0x03, 0x04):  # block / loop / if
        bt = data[p]
        p += 1
        return {0x02: "block", 0x03: "loop", 0x04: "if"}[op], _BLOCKTYPE.get(bt, f"type[{bt}]"), None, p, depth + 1
    if op == 0x0C or op == 0x0D:  # br / br_if
        n, p = _uleb(data, p)
        return ("br" if op == 0x0C else "br_if"), str(n), None, p, depth
    if op == 0x0E:  # br_table
        cnt, p = _uleb(data, p)
        labels = []
        for _ in range(cnt + 1):
            v, p = _uleb(data, p)
            labels.append(v)
        return "br_table", " ".join(map(str, labels)), None, p, depth
    if op == 0x10:  # call
        idx, p = _uleb(data, p)
        return "call", str(idx), idx, p, depth
    if op == 0x11:  # call_indirect
        t, p = _uleb(data, p)
        tbl, p = _uleb(data, p)
        return "call_indirect", f"type[{t}] table[{tbl}]", None, p, depth
    if op in _LOCAL:
        idx, p = _uleb(data, p)
        return _LOCAL[op], str(idx), None, p, depth
    if op in _MEM:
        align, p = _uleb(data, p)
        offs, p = _uleb(data, p)
        return _MEM[op], f"offset={offs} align={1 << align}", None, p, depth
    if op == 0x41:  # i32.const
        v, p = _sleb(data, p)
        return "i32.const", str(v), None, p, depth
    if op == 0x42:  # i64.const
        v, p = _sleb(data, p)
        return "i64.const", str(v), None, p, depth
    if op == 0x43:  # f32.const
        v = struct.unpack_from("<f", data, p)[0]
        return "f32.const", repr(v), None, p + 4, depth
    if op == 0x44:  # f64.const
        v = struct.unpack_from("<d", data, p)[0]
        return "f64.const", repr(v), None, p + 8, depth
    if op in (0x3F, 0x40):  # memory.size / memory.grow
        _, p = _uleb(data, p)
        return ("memory.size" if op == 0x3F else "memory.grow"), "", None, p, depth
    if op == 0xFC:  # multi-byte (saturating truncation, memory.copy/fill, etc.)
        sub, p = _uleb(data, p)
        return f"fc.{sub}", "", None, p, depth
    return f"byte 0x{op:02x}", "", None, p, depth


# ---- adapter: make a WasmModule serveable like analysis.Program ----------
import threading


class _Img:
    """Minimal image shim for the server's info/addrinfo/hex routes."""
    def __init__(self, path, data, mod):
        self.path, self._data, self.format = path, data, "wasm"
        self.arch = _Arch()
        self.entry = 0
        self.base = 0
        self.imports = {f.addr & 0xFFFFFFFF | (1 << 40): f"{f.name}" for f in mod.funcs if f.imported}
        # one "section" per module section would need offsets; expose the whole code area simply
        secs = []
        if mod.code_entries:
            lo = min(s for s, _ in mod.code_entries)
            hi = max(e for _, e in mod.code_entries)
            secs.append(_Sec("code", lo, hi - lo, True))
        for i, (p, d) in enumerate(mod.data_segments):
            secs.append(_Sec(f"data[{i}]", p, len(d), False))
        self.sections = secs

    def read(self, va, n):
        return self._data[va:va + n] if 0 <= va < len(self._data) else b""

    def section_at(self, va):
        return next((s for s in self.sections if s.va <= va < s.va + s.size), None)

    def file_offset(self, va):
        return va if 0 <= va < len(self._data) else None


class _Sec:
    def __init__(self, name, va, size, code):
        self.name, self.va, self.size, self.code, self.offset = name, va, size, code, va


class _Arch:
    name = "wasm"
    bits = 32


class WasmProgram:
    """Serve a WebAssembly module through the same read API as a native Program. Decompilation and
    CFG are not offered (the stack machine needs their own lifter); everything else works."""
    wasm = True

    def __init__(self, path, data):
        self.mod = WasmModule(data)
        self.image = _Img(path, data, self.mod)
        self.arch = _Arch()
        self.functions = {f.addr: f for f in self.mod.funcs if not f.imported}
        self.names = {f.addr: f.name for f in self.mod.funcs if not f.imported}
        self.names.update(self.image.imports)
        self.display_name = path.split("/")[-1]
        self.user_names, self.comments, self.user_types = {}, {}, {}
        self.bookmarks, self.user_procs, self.removed_procs = set(), set(), set()
        self.pretty = {}
        self.objc = type("O", (), {"classes": [], "protocols": [], "cfstrings": {}})()
        self.swift = type("S", (), {"types": []})()
        self.value_tables, self.jump_tables = {}, {}
        self.lock = threading.RLock()
        self._strings = None
        self.entry = self.mod.funcs[self.mod.start].addr if self.mod.start is not None \
            and self.mod.start < len(self.mod.funcs) else (min(self.functions) if self.functions else 0)

    # overlay: WASM analysis is read-only here, so a cheap edit view mirrors Program.overlay
    def overlay(self):
        import copy
        o = copy.copy(self)
        o.functions = dict(self.functions)
        o.names = dict(self.names)
        o.user_names, o.comments, o.user_types = {}, {}, {}
        o.bookmarks, o.user_procs, o.removed_procs = set(), set(), set()
        o._shared = self
        return o

    @property
    def _analysis_lock(self):
        return getattr(self, "_shared", self).lock

    def display(self, a):
        return self.user_names.get(a) or self.names.get(a)

    def resolve(self, what):
        if isinstance(what, int):
            return what
        w = what.strip()
        import re
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", w) and (w.startswith("0x") or not w.isalpha()):
            return int(w, 16)
        for a, n in {**self.names, **self.user_names}.items():
            if n == w:
                return a
        raise KeyError(f"no such symbol: {what}")

    def function_at(self, a):
        if a in self.functions:
            return self.functions[a]
        return next((f for f in self.functions.values() if f.addr <= a < f.end), None)

    def xrefs_to(self, a):
        f = self.function_at(a)
        idx = f.index if f else None
        out = []
        for g in self.functions.values():
            for off, mn, ops, tgt in g.insns:
                if tgt == idx:
                    out.append((off, "call"))
        return sorted(out)

    def strings(self, minlen=4):
        if self._strings is None:
            import re
            out = {}
            for base, blob in self.mod.data_segments:
                for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
                    out[base + m.start()] = m.group().decode()
            self._strings = out
        return self._strings

    def rename(self, a, name):
        self.user_names[int(a)] = name

    def comment(self, a, text):
        (self.comments.__setitem__ if text else lambda k, v: self.comments.pop(k, None))(int(a), text)

    def bookmark(self, a, on=True):
        (self.bookmarks.add if on else self.bookmarks.discard)(int(a))

    def set_type(self, a, kind):
        pass

    def rdb_path(self):
        return self.image.path + ".rdb"

    def save(self, path):
        pass

    def load(self, path):
        return self

    def insn(self, a):
        return None


def listing_rows(P, func):
    """Hopper-style rows for a WASM function (the server's `listing` route)."""
    rows = []
    sig = func.sig or ([], [])
    params = ", ".join(f"{t} arg{i}" for i, t in enumerate(sig[0]))
    ret = sig[1][0] if sig[1] else "void"
    rows.append({"kind": "banner", "addr": hex(func.addr), "text": f"{ret} {func.name}({params})"})
    if func.locals:
        rows.append({"kind": "vars", "items": [{"off": i, "name": f"local{len(sig[0]) + i}", "type": t}
                                               for i, t in enumerate(func.locals)]})
    rows.append({"kind": "label", "addr": hex(func.addr), "text": f"{func.name}:", "xrefs": []})
    indent = 0
    for off, mn, ops, tgt in func.insns:
        if mn in ("end", "else"):
            indent = max(0, indent - 1)
        row = {"kind": "insn", "addr": hex(off), "bytes": "", "mnem": ("  " * indent) + mn,
               "ops": ops, "comment": "", "user": P.comments.get(off, ""), "flow": "other"}
        if tgt is not None and tgt in P.mod.by_index:
            t = P.mod.by_index[tgt]
            row["target"] = {"addr": hex(t.addr), "name": t.name}
            row["comment"] = t.name
        rows.append(row)
        if mn in ("block", "loop", "if", "else"):
            indent += 1
    rows.append({"kind": "endp", "text": "end"})
    return rows
