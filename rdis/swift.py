"""Swift 5 type metadata: nominal types and their stored fields (__swift5_types, __swift5_fieldmd)."""
from dataclasses import dataclass, field

from .demangle import _pipe, _tool

KINDS = {16: "class", 17: "struct", 18: "enum"}


@dataclass
class SwiftType:
    kind: str
    name: str
    addr: int
    superclass: str = ""
    fields: list = field(default_factory=list)  # (name, type, is_var)
    conforms: list = field(default_factory=list)  # protocol names this type conforms to

    def declaration(self):
        bases = ([self.superclass] if self.superclass else []) + self.conforms
        head = f"{self.kind} {self.name}" + (f": {', '.join(bases)}" if bases else "")
        if self.kind == "enum":
            body = [f"    case {n}" + ((t if t.startswith("(") else f"({t})") if t else "") for n, t, _ in self.fields]
        else:
            body = [f"    {'var' if v else 'let'} {n}: {t}" for n, t, v in self.fields]
        return "\n".join([head + " {"] + body + ["}"])


class Swift:
    @classmethod
    def empty(cls, image):
        s = cls.__new__(cls)
        s.im, s.types = image, []
        return s

    def __init__(self, image):
        self.im, self.types = image, []
        secs = {s.name: s for s in image.sections}
        s = secs.get("__swift5_types")
        if image.format != "macho" or not s:
            return
        raw_types = []
        for o in range(0, s.size, 4):
            d = self._rel(s.va + o)
            if d & 1:  # indirect: points at a pointer to the descriptor
                d = self.im.ptr(d & ~1)
            t = self._descriptor(d & ~3)
            if t:
                raw_types.append(t)
        self._conformances(secs.get("__swift5_proto"), raw_types)
        self._demangle(raw_types)
        self.types = raw_types

    def _conformances(self, sec, types):
        """__swift5_proto: conformance descriptors. Attach protocol names to the conforming type.

        Layout (relative): protocolDescriptor@0, typeRef@4, witnessTable@8, flags@12. The typeRef's
        low 3 bits are a kind; kind 0 = direct nominal descriptor, which we match to a parsed type.
        """
        if not sec:
            return
        by_addr = {t.addr: t for t in types}
        for o in range(0, sec.size, 4):
            desc = self._rel(sec.va + o)
            proto = self._proto_name(desc)
            type_kind = int.from_bytes(self.im.read(desc + 12, 4), "little") & 0x7
            type_ref = self._rel(desc + 4)
            if type_kind == 0:  # direct reference to a nominal type descriptor
                t = by_addr.get(type_ref & ~3)
                if t and proto and proto not in t.conforms:
                    t.conforms.append(proto)

    def _proto_name(self, desc):
        """Best-effort protocol name from a conformance's protocol descriptor (rel, indirectable)."""
        p = self._rel(desc)
        if p & 1:  # indirect: a bind pointer to an external protocol
            slot = p & ~1
            sym = self.im.binds.get(slot, "")
            return sym.split("_$")[-1] or "" if sym else ""
        raw = self._cstr(self._rel(p + 8)) if 0 < p < self.im.base + (1 << 34) else b""
        return raw.decode("utf-8", "replace") if raw.isascii() else ""

    def _rel(self, va):
        return va + int.from_bytes(self.im.read(va, 4), "little", signed=True)

    def _cstr(self, va):
        return self.im.read(va, 256).split(b"\0", 1)[0]

    def _mangled(self, va):
        """Mangled type name; symbolic references (bytes 0x01-0x17 + rel32) resolve to the target's name."""
        raw, out, o = self.im.read(va, 256), b"", 0
        while o < len(raw) and raw[o]:
            if 1 <= raw[o] <= 0x17:
                target = va + o + 1 + int.from_bytes(raw[o + 1:o + 5], "little", signed=True)
                if raw[o] == 2:  # indirect
                    target = self.im.ptr(target)
                out += b"\x00SYM%x\x00" % target
                o += 5
            else:
                out += raw[o:o + 1]
                o += 1
        return out.decode("latin-1")

    def _descriptor(self, d):
        flags = int.from_bytes(self.im.read(d, 4), "little")
        kind = KINDS.get(flags & 0x1F)
        if not kind:
            return None
        t = SwiftType(kind, self._cstr(self._rel(d + 8)).decode(), d)
        fd = self._rel(d + 16)
        if fd == d + 16:  # rel32 of 0: no field descriptor
            return t
        if kind == "class" and int.from_bytes(self.im.read(fd + 4, 4), "little"):
            t.superclass = self._mangled(self._rel(fd + 4))
        size = int.from_bytes(self.im.read(fd + 10, 2), "little") or 12
        count = int.from_bytes(self.im.read(fd + 12, 4), "little")
        for n in range(min(count, 4096)):
            r = fd + 16 + n * size
            rflags = int.from_bytes(self.im.read(r, 4), "little")
            tn = self._mangled(self._rel(r + 4)) if int.from_bytes(self.im.read(r + 4, 4), "little") else ""
            t.fields.append((self._cstr(self._rel(r + 8)).decode(), tn, bool(rflags & 2)))
        return t

    def _demangle(self, types):
        by_addr = {t.addr: t.name for t in types}
        def sym(m):  # local symbolic references become the referenced type's name
            parts = m.split("\x00")
            return "".join(by_addr.get(int(p[3:], 16), "?") if p.startswith("SYM") else p for p in parts)
        mangled = {m for t in types for m in [t.superclass] + [f[1] for f in t.fields] if m and "\x00" not in m}
        tool = _tool("swift-demangle")
        pretty = _pipe(tool + ["--simplified"], [f"$s{m}D" for m in sorted(mangled)]) if tool and mangled else {}
        fix = lambda m: sym(m) if "\x00" in m else pretty.get(f"$s{m}D", m) if m else ""
        for t in types:
            t.superclass = fix(t.superclass)
            t.fields = [(n, fix(ty), v) for n, ty, v in t.fields]
