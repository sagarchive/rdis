"""Binary loading: Mach-O (thin/fat), ELF and PE through LIEF, plus plugin loaders."""
import bisect
from dataclasses import dataclass
import lief

from . import arch as archmod, plugins

lief.logging.disable()


@dataclass(frozen=True)
class Section:
    name: str
    va: int
    size: int
    offset: int
    code: bool


class Image:
    """Uniform view of a loaded binary. Formats differ only in how they fill these fields."""

    def __init__(self, path, fmt, arch, entry, base, sections, symbols, imports, data_reader, offset_of):
        self.path, self.format, self.arch, self.entry, self.base = path, fmt, arch, entry, base
        self.sections, self.symbols, self.imports = sections, symbols, imports
        self._read, self._offset_of = data_reader, offset_of
        self.thumb = set()  # ARM: aligned addresses that decode as Thumb (loader may fill)

    def read(self, va, n):
        try:
            return bytes(self._read(va, n))
        except Exception:
            return b""

    fixups, binds = {}, {}  # Mach-O chained-fixup rebases {slot: target} and binds {slot: symbol}

    def ptr(self, va):
        """Pointer stored at `va`, with chained-fixup encoding removed. Binds return 0 (see binds)."""
        if va in self.fixups:
            return self.fixups[va]
        if va in self.binds:
            return 0
        return int.from_bytes(self.read(va, self.arch.bits // 8), "little")

    def section_at(self, va):
        # Hot path: bisect to the last section that starts at/before va. Sections can overlap,
        # so also keep a prefix maximum of section ends. This lets us stop only when every earlier
        # section has ended, rather than relying on a fixed (and format-independent) scan distance.
        idx = getattr(self, "_sidx", None)
        if idx is None or idx[0] is not self.sections or idx[1] != len(self.sections):
            order = sorted(self.sections, key=lambda s: s.va)
            starts = [s.va for s in order]
            max_ends = []
            end = None
            for section in order:
                section_end = section.va + max(0, section.size)
                end = section_end if end is None else max(end, section_end)
                max_ends.append(end)
            idx = self._sidx = (self.sections, len(self.sections), starts, order, max_ends)
        starts, order, max_ends = idx[2], idx[3], idx[4]
        i = bisect.bisect_right(starts, va) - 1
        while i >= 0:
            section = order[i]
            if section.va <= va < section.va + section.size:
                return section
            # All sections through i end at or before va; no earlier interval can contain it.
            if max_ends[i] <= va:
                break
            i -= 1
        return None

    def is_code(self, va):
        s = self.section_at(va)
        return bool(s and s.code)

    def file_offset(self, va):
        s = self.section_at(va)
        return s.offset + (va - s.va) if s and s.offset else self._offset_of(va)

    def name_at(self, va):
        return self.symbols.get(va) or self.imports.get(va)


def _str(n):
    """LIEF hands back `bytes` for a name that is not valid UTF-8 (crafted/corrupt symbol tables);
    everything downstream (demangling, JSON, sorting) needs str."""
    return n.decode("utf-8", "replace") if isinstance(n, (bytes, bytearray)) else (n or "")


def _arch_name(b):
    if isinstance(b, lief.MachO.Binary):
        return {"X86_64": "x86_64", "X86": "x86", "ARM64": "arm64", "ARM": "arm"}[b.header.cpu_type.__name__]
    if isinstance(b, lief.ELF.Binary):
        m = b.header.machine_type.__name__
        wide = b.header.identity_class == lief.ELF.Header.CLASS.ELF64
        if m in ("MIPS", "MIPS_RS3_LE"):
            le = b.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
            return ("mips64" if wide else "mips") + ("el" if le else "")
        if m == "RISCV":
            return "riscv64" if wide else "riscv32"
        return {"X86_64": "x86_64", "I386": "x86", "AARCH64": "arm64", "ARM": "arm"}[m]
    return {"AMD64": "x86_64", "I386": "x86", "ARM64": "arm64", "ARMNT": "arm"}[b.header.machine.__name__]


def _macho_imports(b, ptr):
    """Stubs and GOT slots map to names via the indirect symbol table (reserved1 = start index)."""
    out, indirect = {}, list(b.dynamic_symbol_command.indirect_symbols)
    for s in b.sections:
        t = s.type.__name__
        if t == "SYMBOL_STUBS":
            step = s.reserved2
        elif t in ("NON_LAZY_SYMBOL_POINTERS", "LAZY_SYMBOL_POINTERS"):
            step = ptr
        else:
            continue
        for n in range(s.size // step if step else 0):
            idx = s.reserved1 + n
            if idx < len(indirect) and indirect[idx].name:
                out[s.virtual_address + n * step] = _str(indirect[idx].name)
    return out


def _elf_imports(b):
    out = {r.address: _str(r.symbol.name) for r in b.pltgot_relocations if r.has_symbol and r.symbol.name}
    # PLT stubs jump through those GOT slots; resolved later by analysis via `imports` slots.
    return out


def _pe_imports(b):
    return {b.imagebase + e.iat_address: f"{_str(imp.name)}!{_str(e.name) or f'#{e.ordinal}'}"
            for imp in b.imports for e in imp.entries}


def _sections(b):
    out = []
    for s in b.sections:
        if isinstance(b, lief.MachO.Binary):
            code = bool(s.flags_list and any("INSTRUCTIONS" in f.__name__ for f in s.flags_list))
            va = s.virtual_address
        elif isinstance(b, lief.ELF.Binary):
            code = s.has(lief.ELF.Section.FLAGS.EXECINSTR)
            va = s.virtual_address
        else:
            code = s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
            va = b.imagebase + s.virtual_address
        if s.size:
            out.append(Section(_str(s.name), va, s.size, s.offset, code))
    if isinstance(b, lief.ELF.Binary) and not any(s.code for s in out):
        # section headers stripped (common in obfuscated/packed libs): LIEF reports no code, so
        # fall back to the executable LOAD segments to recover a code range for analysis.
        X = lief.ELF.Segment.FLAGS.X
        for seg in b.segments:
            execu = (seg.flags & X) == X if hasattr(seg.flags, "__and__") else bool(int(seg.flags) & 1)
            if seg.type == lief.ELF.Segment.TYPE.LOAD and execu and seg.virtual_size:
                out.append(Section(".text", seg.virtual_address, seg.virtual_size,
                                   seg.file_offset, True))
    return out


def _pe_function_starts(b):
    """Function starts from the .pdata exception directory (every non-leaf x64/ARM64 function)."""
    d = b.data_directory(lief.PE.DataDirectory.TYPES.EXCEPTION_TABLE)
    if not d.rva or not d.size:
        return []
    raw = bytes(b.get_content_from_virtual_address(d.rva, d.size, lief.Binary.VA_TYPES.RVA))
    step = 8 if b.header.machine.__name__ == "ARM64" else 12
    starts = (int.from_bytes(raw[o:o + 4], "little") for o in range(0, len(raw) - step + 1, step))
    return [b.imagebase + s for s in starts if s]


def _arm_array_modes(b):
    """ARM ELF: the DT_INIT_ARRAY / DT_FINI_ARRAY / DT_PREINIT_ARRAY tables hold function pointers
    whose bit0 selects Thumb. LIEF lists those targets as functions but loses the mode; recover it
    so init/fini routines decode correctly instead of as garbage ARM. Returns the Thumb addresses."""
    thumb = set()
    try:
        tag = lief.ELF.DynamicEntry.TAG
        pairs = [(tag.INIT_ARRAY, tag.INIT_ARRAYSZ), (tag.FINI_ARRAY, tag.FINI_ARRAYSZ),
                 (tag.PREINIT_ARRAY, tag.PREINIT_ARRAYSZ)]
        have = {d.tag: d.value for d in b.dynamic_entries}
        ptr = b.header.identity_class == lief.ELF.Header.CLASS.ELF64 and 8 or 4
        for a_tag, sz_tag in pairs:
            if a_tag not in have or sz_tag not in have:
                continue
            raw = bytes(b.get_content_from_virtual_address(have[a_tag], have[sz_tag]))
            for o in range(0, len(raw) - ptr + 1, ptr):
                v = int.from_bytes(raw[o:o + ptr], "little")
                if v & 1:
                    thumb.add(v & ~1)
    except Exception:
        pass
    return thumb


def _symbols(b):
    base = b.imagebase if isinstance(b, (lief.MachO.Binary, lief.PE.Binary)) else 0
    out = {}
    for f in b.functions:  # symbols + LC_FUNCTION_STARTS / .eh_frame / PE exception table
        a = f.address + (base if 0 < f.address < base else 0)
        if f.name:
            out[a] = _str(f.name)
        else:
            out.setdefault(a, "")
    if isinstance(b, lief.PE.Binary):
        for a in _pe_function_starts(b):
            out.setdefault(a, "")
        for e in b.exported_functions:
            out[base + e.address] = _str(e.name)
        return out
    # LIEF's `functions` misses most LC_FUNCTION_STARTS entries (24 of /bin/ls's 50, 1 of a Bun
    # binary's 72,876), and that table survives `strip`: read it directly, offsets from __TEXT.
    if isinstance(b, lief.MachO.Binary) and b.has_function_starts:
        for off in b.function_starts.functions:
            out.setdefault(base + off, "")
    for s in b.symbols:
        if s.value and s.name:
            out[s.value] = out.get(s.value) or _str(s.name)
    return out


def _arm_thumb(b, raw):
    """ARM uses bit0 of a symbol/branch value as a mode flag (1 = Thumb), not part of the address.
    Return (clean_symbols, thumb_addrs): symbols re-keyed to real (even) addresses, and the set of
    aligned addresses that are Thumb — from odd symbol values and ELF `$t` mapping symbols. Mapping
    symbols ($a/$t/$d) and other `$`-prefixed markers are dropped from names (they aren't functions)."""
    thumb, clean = set(), {}
    for k, v in raw.items():
        if v.startswith("$"):
            if v[:2] == "$t":
                thumb.add(k & ~1)
            continue  # mapping/marker symbol: not a function name
        if k & 1:
            thumb.add(k & ~1)
        ka = k & ~1
        if not clean.get(ka):        # keep the first real name at the aligned address
            clean[ka] = v
    if b.entrypoint & 1:
        thumb.add(b.entrypoint & ~1)
    return clean, thumb


def open_image(path, arch=None, **opts):
    """Open `path`. `arch` picks a fat Mach-O slice; plugin loaders get `opts` (e.g. base=)."""
    custom = plugins.find_loader(path, opts)
    if custom:
        return custom(path, arch=arch, **opts)
    owner = None
    if lief.is_macho(path):  # lief.parse would silently pick the first fat slice
        owner = lief.MachO.parse(path)  # slices die with their FatBinary, so keep it on the Image
        slices = list(owner) if owner is not None else []
        if not slices:
            raise ValueError(f"malformed Mach-O (no parseable slice): {path}")
        b = next((s for s in slices if arch and _arch_name(s) == archmod.make(arch).name), slices[0])
    else:
        b = lief.parse(path)
    if b is None:
        raise ValueError(f"not a Mach-O/ELF/PE file: {path}")
    try:
        a = archmod.make(_arch_name(b))
    except KeyError as e:   # e.g. e_machine NONE in a truncated/crafted header
        raise ValueError(f"unsupported CPU architecture {e} in {path}") from None
    if isinstance(b, lief.MachO.Binary):
        fmt, imports = "macho", _macho_imports(b, a.bits // 8)
    elif isinstance(b, lief.ELF.Binary):
        fmt, imports = "elf", _elf_imports(b)
    else:
        fmt, imports = "pe", _pe_imports(b)
    def offset_of(va):
        try:
            off = b.virtual_address_to_offset(va - (b.imagebase if fmt == "pe" else 0))
        except Exception:
            return None
        return off if isinstance(off, int) else None   # LIEF returns a lief_errors value, not raise
    raw = _symbols(b)
    thumb = set()
    entry = b.entrypoint
    if a.name == "arm":
        raw, thumb = _arm_thumb(b, raw)
        thumb |= _arm_array_modes(b)   # init/fini-array targets carry their mode in the pointer's bit0
        entry &= ~1
    syms = {k: v or f"sub_{k:x}" for k, v in raw.items()}
    im = Image(path, fmt, a, entry, b.imagebase, _sections(b), syms, imports,
               b.get_content_from_virtual_address, offset_of)
    im.thumb = thumb  # aligned addresses that decode as Thumb (empty for non-ARM)
    im.lief, im._owner = b, owner
    if fmt == "macho":
        im.fixups = {r.address: r.target for r in b.relocations if type(r).__name__ == "RelocationFixup"}
        im.binds = {x.address: _str(x.symbol.name) for x in b.bindings if x.has_symbol}
    elif fmt == "elf":
        im.fixups = _elf_fixups(b)
    return im


def _elf_fixups(b):
    """PIC data pointers live in RELA relocations (the file word is 0): {slot: target} from
    *_RELATIVE (addend) and absolute relocs against locally-defined symbols. REL (arm32) keeps the
    value in the file already, so ptr() reading the bytes is correct there."""
    out = {}
    try:
        for r in b.relocations:
            if not r.is_rela:
                continue
            t = str(r.type)
            if t.endswith("_RELATIVE"):
                out[r.address] = r.addend
            elif (t.endswith("_ABS64") or t.endswith("_ABS32") or t.endswith("_64")) \
                    and r.has_symbol and r.symbol.value:
                out[r.address] = r.symbol.value + r.addend
    except Exception:
        pass
    return out
