"""Objective-C runtime metadata from a Mach-O (64-bit): classes, categories, methods, selectors."""
from dataclasses import dataclass, field

RELATIVE = 0x80000000  # method_list_t uses 32-bit relative offsets (iOS 14+/macOS 11+)

_SIMPLE = {"c": "char", "i": "int", "s": "short", "l": "long", "q": "long long", "C": "unsigned char",
           "I": "unsigned int", "S": "unsigned short", "L": "unsigned long", "Q": "unsigned long long",
           "f": "float", "d": "double", "D": "long double", "B": "BOOL", "v": "void", "*": "char *",
           "#": "Class", ":": "SEL", "?": "void *"}


def decode_type(enc):
    """One Objective-C type encoding -> (C type, remaining encoding)."""
    while enc and enc[0] in "rnNoORVA":  # const/in/out/... qualifiers
        enc = enc[1:]
    if not enc:
        return "void", ""
    ch, rest = enc[0], enc[1:]
    if ch == "@":
        if rest.startswith("?"):
            return "id /* block */", rest[1:]
        if rest.startswith('"'):
            name, _, rest = rest[1:].partition('"')
            return (f"{name} *" if not name.startswith("<") else f"id{name}"), rest
        return "id", rest
    if ch == "^":
        t, rest = decode_type(rest)
        return f"{t} *", rest
    if ch in "{([":
        close = {"{": "}", "(": ")", "[": "]"}[ch]
        depth, j = 1, 0
        while j < len(rest) and depth:
            depth += {ch: 1, close: -1}.get(rest[j], 0)
            j += 1
        body, rest = rest[:j - 1], rest[j:]
        if ch == "[":
            n = "".join(x for x in body if x.isdigit())
            t, _ = decode_type(body[len(n):])
            return f"{t}[{n}]", rest
        return f"{'struct' if ch == '{' else 'union'} {body.split('=')[0] or '?'}", rest
    if ch == "b":
        n = ""
        while rest and rest[0].isdigit():
            n, rest = n + rest[0], rest[1:]
        return f"unsigned int :{n}", rest
    return _SIMPLE.get(ch, ch), rest


def method_signature(sel, types, is_class):
    """'- (NSString *)greet:(id)arg1 times:(int)arg2' from a selector and its encoding."""
    parts, enc = [], types
    while enc:
        t, enc = decode_type(enc)
        parts.append(t)
        while enc and (enc[0].isdigit() or enc[0] == "-"):
            enc = enc[1:]
    ret, args = (parts[0] if parts else "id"), parts[3:]  # skip self, _cmd
    pieces = sel.split(":")
    if len(pieces) == 1:
        body = sel
    else:
        body = " ".join(f"{p}:({args[n] if n < len(args) else 'id'})arg{n + 1}"
                        for n, p in enumerate(pieces[:-1]))
    return f"{'+' if is_class else '-'} ({ret}){body}"


def property_decl(name, attrs):
    """'@property (nonatomic, copy) NSString *name' from 'T@"NSString",C,N,V_name'."""
    words, ctype = [], "id"
    for a in attrs.split(","):
        k, v = a[:1], a[1:]
        if k == "T":
            ctype, _ = decode_type(v)
        else:
            w = {"C": "copy", "&": "strong", "W": "weak", "N": "nonatomic", "R": "readonly", "D": "dynamic"}.get(k)
            words.append(w or (f"getter={v}" if k == "G" else f"setter={v}" if k == "S" else None))
    words = [w for w in words if w]
    sep = "" if ctype.endswith("*") else " "
    return f"@property {'(' + ', '.join(words) + ') ' if words else ''}{ctype}{sep}{name}"


@dataclass
class Method:
    sel: str
    types: str
    imp: int
    is_class: bool


@dataclass
class Clazz:
    name: str
    addr: int
    superclass: str = ""
    category_of: str = ""  # set for categories: the class they extend
    methods: list = field(default_factory=list)
    ivars: list = field(default_factory=list)       # (name, type, offset)
    properties: list = field(default_factory=list)  # (name, attributes)
    is_protocol: bool = False
    adopts: list = field(default_factory=list)       # adopted protocol names

    def declaration(self):
        """Readable @interface/@protocol, like class-dump output."""
        adopt = f" <{', '.join(self.adopts)}>" if self.adopts else ""
        if self.is_protocol:
            head = f"@protocol {self.name}{adopt}"
        elif self.category_of:
            head = f"@interface {self.category_of} ({self.name}){adopt}"
        else:
            head = f"@interface {self.name}" + (f" : {self.superclass}" if self.superclass else "") + adopt
        lines = [head + (" {" if self.ivars else "")]
        for n, t, o in self.ivars:
            ct = decode_type(t)[0]
            lines.append(f"    {ct}{'' if ct.endswith('*') else ' '}{n}; // +{o:#x}")
        if self.ivars:
            lines.append("}")
        lines += [property_decl(n, a) + ";" for n, a in self.properties]
        for m in self.methods:
            opt = "@optional " if getattr(m, "optional", False) else ""
            tail = "" if self.is_protocol else f" // {m.imp:#x}"
            lines.append(f"{opt}{method_signature(m.sel, m.types, m.is_class)};{tail}")
        return "\n".join(lines + ["@" + ("end" if not self.is_protocol else "end")])


class ObjC:
    @classmethod
    def empty(cls, image):
        """No ObjC parsing (loader option off): same interface, nothing found."""
        o = cls.__new__(cls)
        o.im, o.classes, o.selrefs, o.classrefs, o.cfstrings, o.stubs = image, [], {}, {}, {}, {}
        o.protocols, o.sections = [], {}
        return o

    def __init__(self, image):
        self.im = image
        self.classes, self.selrefs, self.classrefs, self.cfstrings, self.stubs = [], {}, {}, {}, {}
        self.protocols = []
        self.sections = {s.name: s for s in image.sections}
        if image.format != "macho" or image.arch.bits != 64:
            return
        self._refs()
        for p in self._ptrs("__objc_protolist"):
            self.protocols.append(self._protocol(p))
        for p in self._ptrs("__objc_classlist"):
            self.classes.append(self._class(p))
        for p in self._ptrs("__objc_catlist"):
            self.classes.append(self._category(p))
        self._stubs()

    def _protocol(self, p):
        """protocol_t: isa, name, protocols, instMeths, classMeths, optInst, optClass, props."""
        c = Clazz(self.cstr(self.im.ptr(p + 8)), p)
        c.is_protocol = True
        meths = self._methods(self.im.ptr(p + 24), False) + self._methods(self.im.ptr(p + 32), True)
        opt = self._methods(self.im.ptr(p + 40), False) + self._methods(self.im.ptr(p + 48), True)
        for m in opt:
            m.optional = True
        c.methods = meths + opt
        c.properties = self._props(self.im.ptr(p + 56))
        c.adopts = self._proto_names(self.im.ptr(p + 16))
        return c

    def _proto_names(self, listptr):
        if not listptr:
            return []
        n = self.im.ptr(listptr)  # count is pointer-sized on 64-bit
        return [self.cstr(self.im.ptr(self.im.ptr(listptr + 8 + i * 8) + 8)) for i in range(min(n, 64))]

    # -- low level ----------------------------------------------------------
    def cstr(self, va, limit=1024):
        raw = self.im.read(va, limit) if va else b""
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")

    def u32(self, va):
        return int.from_bytes(self.im.read(va, 4), "little")

    def i32(self, va):
        return int.from_bytes(self.im.read(va, 4), "little", signed=True)

    def _ptrs(self, sect):
        s = self.sections.get(sect)
        return [self.im.ptr(s.va + o) for o in range(0, s.size, 8)] if s else []

    def _class_name_at(self, slot):
        """Name of the class a pointer slot refers to, local or imported via bind."""
        bound = self.im.binds.get(slot, "")
        if bound:
            return bound.replace("_OBJC_CLASS_$_", "").replace("_OBJC_METACLASS_$_", "")
        p = self.im.ptr(slot)
        return self._ro_name(p) if p else ""

    def _ro(self, cls):
        return self.im.ptr(cls + 32) & ~7  # class_t.data; low bits are Swift/RW flags

    def _ro_name(self, cls):
        ro = self._ro(cls)
        return self._nice(self.cstr(self.im.ptr(ro + 24))) if ro else ""

    @staticmethod
    def _nice(name):
        """Swift classes exposed to the ObjC runtime carry a mangled _TtC... name; simplify it."""
        if name.startswith("_TtC"):
            from .demangle import demangle_all
            return demangle_all([name]).get(name, name)
        return name

    # -- structures ---------------------------------------------------------
    def _methods(self, ml, is_class):
        if not ml:
            return []
        flags, count = self.u32(ml), self.u32(ml + 4)
        out = []
        if flags & RELATIVE:
            for n in range(count):
                e = ml + 8 + n * 12
                selref = e + self.i32(e)
                sel = self.cstr(self.im.ptr(selref))
                out.append(Method(sel, self.cstr(e + 4 + self.i32(e + 4)), e + 8 + self.i32(e + 8), is_class))
        else:
            size = (flags & 0xFFFC) or 24
            for n in range(count):
                e = ml + 8 + n * size
                out.append(Method(self.cstr(self.im.ptr(e)), self.cstr(self.im.ptr(e + 8)),
                                  self.im.ptr(e + 16), is_class))
        return out

    def _ivars(self, il):
        if not il:
            return []
        size, count = self.u32(il) or 32, self.u32(il + 4)
        out = []
        for n in range(count):
            e = il + 8 + n * size
            off_ptr = self.im.ptr(e)
            out.append((self.cstr(self.im.ptr(e + 8)), self.cstr(self.im.ptr(e + 16)),
                        self.u32(off_ptr) if off_ptr else 0))
        return out

    def _props(self, pl):
        if not pl:
            return []
        size, count = self.u32(pl) or 16, self.u32(pl + 4)
        return [(self.cstr(self.im.ptr(pl + 8 + n * size)), self.cstr(self.im.ptr(pl + 8 + n * size + 8)))
                for n in range(count)]

    def _class(self, cls):
        ro = self._ro(cls)
        c = Clazz(self._nice(self.cstr(self.im.ptr(ro + 24))), cls, superclass=self._class_name_at(cls + 8))
        c.methods = self._methods(self.im.ptr(ro + 32), False)
        meta = self.im.ptr(cls)
        if meta:
            c.methods += self._methods(self.im.ptr(self._ro(meta) + 32), True)
        c.ivars = self._ivars(self.im.ptr(ro + 48))
        c.properties = self._props(self.im.ptr(ro + 64))
        c.adopts = self._proto_names(self.im.ptr(ro + 40))  # baseProtocols
        return c

    def _category(self, cat):
        c = Clazz(self.cstr(self.im.ptr(cat)), cat, category_of=self._class_name_at(cat + 8))
        c.methods = self._methods(self.im.ptr(cat + 16), False) + self._methods(self.im.ptr(cat + 24), True)
        c.properties = self._props(self.im.ptr(cat + 40))
        return c

    def _refs(self):
        s = self.sections.get("__objc_selrefs")
        for o in range(0, s.size if s else 0, 8):
            self.selrefs[s.va + o] = self.cstr(self.im.ptr(s.va + o))
        for name in ("__objc_classrefs", "__objc_superrefs"):
            s = self.sections.get(name)
            for o in range(0, s.size if s else 0, 8):
                self.classrefs[s.va + o] = self._class_name_at(s.va + o)
        s = self.sections.get("__cfstring")
        for o in range(0, s.size if s else 0, 32):
            e = s.va + o
            data, length, flags = self.im.ptr(e + 16), self.im.ptr(e + 24), self.u32(e + 8)
            if flags & 0x10 == 0 or flags == 0x7c8:  # 0x7d0 = UTF-16 literal
                self.cfstrings[e] = self.cstr(data, max(length + 1, 1))
            else:
                self.cfstrings[e] = self.im.read(data, length * 2).decode("utf-16le", "replace")

    def _stubs(self):
        """arm64 `objc_msgSend$sel` stubs: adrp/ldr x1 <- selref ... br x16."""
        s = self.sections.get("__objc_stubs")
        if not s:
            return
        a, start, regs = s.va, s.va, {}
        while a < s.va + s.size:
            i = self.im.arch.decode(self.im.read(a, 4), a)
            if i is None or i.mnemonic == "brk":
                a += 4
                start = a
                continue
            for r in self.im.arch.data_refs(i, regs):
                if r in self.selrefs:
                    self.stubs[start] = self.selrefs[r]
            a += 4
            if i.mnemonic == "br":
                start, regs = a, {}

    # -- summary ------------------------------------------------------------
    def names(self):
        """Symbol names Hopper-style: -[Cls sel], selRef_x, classRef_X, cfstring_x, objc_msgSend$x."""
        out = {}
        for c in self.classes:
            owner = f"{c.category_of}({c.name})" if c.category_of else c.name
            for m in c.methods:
                out[m.imp] = f"{'+' if m.is_class else '-'}[{owner} {m.sel}]"
        out.update({a: f"selRef_{s}" for a, s in self.selrefs.items()})
        out.update({a: f"classRef_{n}" for a, n in self.classrefs.items() if n})
        out.update({a: f"objc_msgSend${s}" for a, s in self.stubs.items()})
        return out
