"""Pure-Python Go binary understanding: build-info recovery and gopclntab function/package recovery.

No third-party dependencies. Reads Go binaries (Mach-O/ELF/PE) using only the standard library
and the rdis loader's Image abstraction. Reference implementations consulted on this machine under
$(go env GOROOT)/src: debug/buildinfo/buildinfo.go (build-info layout), debug/gosym/pclntab.go
and runtime/symtab.go (pclntab layout) — concepts only, not copied verbatim.

Public API:
    read_build_info(path, image=None) -> dict | None   # Go build info (version, module, deps, ...)
    read_pclntab(path, image=None)   -> list[dict]      # function list: {entry_addr, name}
    packages(funcs)                  -> list[dict]      # package list with per-package counts
    go_analyze(path, image=None)     -> dict            # {build_info, functions, packages} merged
"""
import os
import re
import struct

from .loader import open_image

# ---- magic constants (from internal/abi/symtab.go) ----
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"  # 14-byte sentinel, 16-byte aligned
_BUILDINFO_ALIGN = 16
_BUILDINFO_HEADER_SIZE = 32

_GO_PCLNTAB_MAGIC_LE = {
    0xFFFFFFFB: "go1.2",     # Go 1.2 through Go 1.15
    0xFFFFFFFA: "go1.16",   # Go 1.16 through Go 1.17
    0xFFFFFFF0: "go1.18",   # Go 1.18 and 1.19
    0xFFFFFFF1: "go1.20",  # Go 1.20+
}


# =====================================================================
# Build-info parsing
# =====================================================================

def _read_file(path):
    """Read entire file as bytes."""
    with open(path, "rb") as f:
        return f.read()


def _read_file_at_offset(path, offset, size):
    """Read `size` bytes from `path` at `offset`."""
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def _scan_buildinfo_magic(data, max_scan=None):
    """Find the 14-byte buildinfo magic on a 16-byte boundary.

    Returns the offset in the data, or None.
    """
    if max_scan is not None:
        data = data[:max_scan]
    pos = 0
    while True:
        idx = data.find(_GO_BUILDINFO_MAGIC, pos)
        if idx < 0:
            return None
        # Magic must be 16-byte aligned
        if idx % _BUILDINFO_ALIGN == 0 and idx + _BUILDINFO_HEADER_SIZE <= len(data):
            return idx
        pos = idx + 1


def _decode_varint(data, offset):
    """Decode a Go-style uvarint starting at offset. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7
        if shift >= 64:
            return 0, offset  # overflow guard
    return result, offset


def _read_inline_string(data, offset):
    """Read a Go 1.18+ inline varint-prefixed string starting at offset.
    Returns (string, next_offset).
    """
    length, offset = _decode_varint(data, offset)
    if offset + length > len(data):
        return "", len(data)
    s = data[offset:offset + length].decode("utf-8", errors="replace")
    return s, offset + length


def _parse_modinfo_text(modinfo_text):
    """Parse the Go modinfo text into a structured dict.

    The modinfo text has lines like:
        path\tgithub.com/example/mymodule
        mod\tgithub.com/example/mymodule\tv1.0.0\th1:xxx
        dep\tgithub.com/some/dep\tv1.2.3\th1:yyy
        =>\tgithub.com/replaced/dep\tv1.0.1\th1:zzz
        build	-G=2	-p=12

    Returns: {go_version, path, main_module, deps: [...], build_settings: {...}}
    """
    result = {
        "go_version": None,
        "path": None,
        "main_module": None,
        "deps": [],
        "build_settings": {},
    }

    last_dep = None
    for line in modinfo_text.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("path\t"):
            result["path"] = line[5:].strip()
        elif line.startswith("mod\t"):
            parts = line[4:].split("\t")
            if len(parts) >= 2:
                result["main_module"] = {
                    "path": parts[0],
                    "version": parts[1] if len(parts) > 1 else "",
                    "sum": parts[2] if len(parts) > 2 else "",
                    "replace": None,
                }
        elif line.startswith("dep\t"):
            parts = line[4:].split("\t")
            dep = {
                "path": parts[0],
                "version": parts[1] if len(parts) > 1 else "",
                "sum": parts[2] if len(parts) > 2 else "",
                "replace": None,
            }
            result["deps"].append(dep)
            last_dep = dep
        elif line.startswith("=>\t"):
            parts = line[3:].split("\t")
            replace = {
                "path": parts[0],
                "version": parts[1] if len(parts) > 1 else "",
                "sum": parts[2] if len(parts) > 2 else "",
                "replace": None,
            }
            if last_dep is not None:
                last_dep["replace"] = replace
            elif result["main_module"] is not None:
                result["main_module"]["replace"] = replace
        elif line.startswith("build\t"):
            kv = line[6:]
            if "=" in kv:
                key, value = kv.split("=", 1)
                result["build_settings"][key.strip()] = value.strip()

    return result


def _find_buildinfo_section(image):
    """Try to find the buildinfo section by name.

    Returns (file_offset, size) or (None, 0).
    """
    for s in image.sections:
        name = s.name.lower() if s.name else ""
        if name in ("__go_buildinfo", ".go_buildinfo"):
            if s.offset and s.size:
                return s.offset, s.size
    return None, 0


def read_build_info(path, image=None):
    """Read Go build info from a binary.

    Returns a dict with: go_version, path, main_module, deps, build_settings.
    Returns None if no build info is found or the file is not a Go binary.
    Never raises.
    """
    try:
        if image is None:
            try:
                image = open_image(path)
            except Exception:
                image = None

        # Try section-based location first (only when we have an image)
        sec_result = _find_buildinfo_section(image) if image is not None else (None, 0)
        data = None

        if sec_result[0] is not None:
            file_off, sec_size = sec_result
            data = _read_file_at_offset(path, file_off, sec_size)
            idx = _scan_buildinfo_magic(data)
            if idx is not None:
                data = data[idx:]
            else:
                data = None

        if data is None or len(data) < _BUILDINFO_HEADER_SIZE:
            # Fall back to scanning all sections for the magic
            for s in (image.sections if image is not None else []):
                if s.size == 0:
                    continue
                section_data = image.read(s.va, min(s.size, 2 * 1024 * 1024))
                if len(section_data) < _BUILDINFO_HEADER_SIZE:
                    continue
                idx = _scan_buildinfo_magic(section_data)
                if idx is not None:
                    remaining = s.size - idx
                    start_va = s.va + idx
                    data = image.read(start_va, min(remaining, 256 * 1024))
                    if len(data) >= _BUILDINFO_HEADER_SIZE:
                        break

        if not data or len(data) < _BUILDINFO_HEADER_SIZE:
            # Last resort: scan the whole file
            raw = _read_file(path)
            idx = _scan_buildinfo_magic(raw)
            if idx is None:
                return None
            data = raw[idx:]

        # Parse the 32-byte header
        # Header: magic[14], ptrSize(1), flags(1), then either pointers or inline strings
        flags = data[15]  # flagsOffset = 15
        flags_version_mask = 0x2
        flags_version_inl = 0x2

        go_version = None
        modinfo = None

        if flags & flags_version_mask == flags_version_inl:
            # Go 1.18+ inline varint layout
            vers, off = _read_inline_string(data, _BUILDINFO_HEADER_SIZE)
            go_version = vers
            modinfo, _ = _read_inline_string(data, off)
        else:
            # Old pointer layout (<1.18) - rarely needed, skip gracefully
            ptr_size = data[14]
            if ptr_size not in (4, 8):
                return None
            # Old format requires VA->file translation through image; skip
            go_version = None
            modinfo = None

        if not go_version:
            return None

        # Strip module framing: 16-byte sentinel before and after
        if modinfo and len(modinfo) >= 33 and modinfo[len(modinfo) - 17] == '\n':
            modinfo = modinfo[16: len(modinfo) - 16]

        if modinfo is None:
            return {
                "go_version": go_version,
                "path": None,
                "main_module": None,
                "deps": [],
                "build_settings": {},
            }

        info = _parse_modinfo_text(modinfo)
        info["go_version"] = go_version
        return info

    except Exception:
        return None


# =====================================================================
# gopclntab parsing
# =====================================================================

def _find_text_start(image):
    """Find the start of the text segment from the image."""
    for s in image.sections:
        if s.code:
            return s.va
    return 0


def _find_pclntab(image):
    """Find the gopclntab section or scan for the magic.

    Returns (data, blob_va) or (None, None).
    """
    for s in image.sections:
        name = s.name.lower() if s.name else ""
        if name in ("__gopclntab", ".gopclntab"):
            if s.size:
                data = image.read(s.va, min(s.size, 64 * 1024 * 1024))
                if len(data) >= 4:
                    return data, s.va
    # Scan code sections for the magic
    for s in image.sections:
        if s.size == 0:
            continue
        sample = image.read(s.va, min(s.size, 256 * 1024))
        if len(sample) < 4:
            continue
        for magic in _GO_PCLNTAB_MAGIC_LE:
            magic_bytes = struct.pack("<I", magic)
            idx = sample.find(magic_bytes)
            if idx >= 0 and idx % 8 == 0:
                remaining = s.size - idx
                blob_va = s.va + idx
                data = image.read(blob_va, min(remaining, 64 * 1024 * 1024))
                return data, blob_va
    return None, None


def _parse_pclntab(data, text_start_hint=0):
    """Parse a gopclntab blob. Returns list of (entry_pc, name) tuples or [].

    Version detection via the 4-byte magic at the start.
    text_start_hint is used when the header's text_start is 0 (common).
    """
    if len(data) < 16:
        return []

    le_magic = struct.unpack("<I", data[:4])[0]
    be_magic = struct.unpack(">I", data[:4])[0]

    is_le = True
    version = None
    for magic, ver in _GO_PCLNTAB_MAGIC_LE.items():
        if le_magic == magic:
            version = ver
            is_le = True
            break
        if be_magic == magic:
            version = ver
            is_le = False
            break

    if version is None:
        return []

    endian = "<" if is_le else ">"

    try:
        ptr_size = data[7]

        if version in ("go1.18", "go1.20"):
            def _uoff(word):
                o = 8 + word * ptr_size
                return struct.unpack(endian + "I", data[o:o + 4])[0]

            nfunc = _uoff(0)
            funcnametab_off = _uoff(3)
            functab_off = _uoff(7)

            ts_off = 8 + 2 * ptr_size
            ts_bytes = data[ts_off:ts_off + ptr_size]
            text_start = struct.unpack(endian + ("Q" if ptr_size == 8 else "I"), ts_bytes)[0]
            if text_start == 0:
                text_start = text_start_hint  # fallback to image's text section start

            fsz = 4
            functab_size = (nfunc * 2 + 1) * fsz
            ft_data = data[functab_off:functab_off + functab_size]
            if len(ft_data) < nfunc * 2 * fsz:
                return []

            fn_data = data[funcnametab_off:functab_off]
            fd_data = data[functab_off:]

            funcs = []
            for i in range(nfunc):
                off = i * 2 * fsz
                if off + 2 * fsz > len(ft_data):
                    break
                pc_offset = struct.unpack(endian + "I", ft_data[off:off + fsz])[0]
                fd_offset = struct.unpack(endian + "I", ft_data[off + fsz:off + 2 * fsz])[0]

                entry_pc = text_start + pc_offset
                if fd_offset + 8 > len(fd_data):
                    break
                name_off = struct.unpack(endian + "I", fd_data[fd_offset + 4:fd_offset + 8])[0]

                name_end = fn_data.find(b"\x00", name_off)
                if name_end < 0:
                    name_end = len(fn_data)
                name = fn_data[name_off:name_end].decode("utf-8", errors="replace")

                if entry_pc > 0 and name:
                    funcs.append((entry_pc, name))
            return funcs

        elif version == "go1.16":
            def _uoff16(word):
                o = 8 + word * ptr_size
                if o + ptr_size > len(data):
                    return 0
                if ptr_size == 4:
                    return struct.unpack(endian + "I", data[o:o + 4])[0]
                return struct.unpack(endian + "Q", data[o:o + 8])[0]

            nfunc = _uoff16(0)
            funcnametab_off = _uoff16(2)
            functab_off = _uoff16(6)

            fsz = ptr_size
            functab_size = (nfunc * 2 + 1) * fsz
            ft_data = data[functab_off:functab_off + functab_size]
            fn_data = data[funcnametab_off:functab_off]
            fd_data = data[functab_off:]

            funcs = []
            for i in range(nfunc):
                off = i * 2 * fsz
                if off + 2 * fsz > len(ft_data):
                    break
                entry_pc = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                         ft_data[off:off + ptr_size])[0]
                fd_offset = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                        ft_data[off + fsz:off + 2 * fsz])[0]

                if fd_offset + ptr_size > len(fd_data):
                    break
                name_off = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                        fd_data[fd_offset:fd_offset + ptr_size])[0]

                name_end = fn_data.find(b"\x00", name_off)
                if name_end < 0:
                    name_end = len(fn_data)
                name = fn_data[name_off:name_end].decode("utf-8", errors="replace")

                if entry_pc > 0 and name:
                    funcs.append((entry_pc, name))
            return funcs

        elif version == "go1.2":
            nfunc = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                  data[8:8 + ptr_size])[0]
            fsz = ptr_size
            ft_start = 8 + ptr_size

            functab_size = (nfunc * 2 + 1) * fsz
            ft_data = data[ft_start:ft_start + functab_size]
            fn_data = data  # funcnametab = entire blob

            funcs = []
            for i in range(nfunc):
                off = i * 2 * fsz
                if off + 2 * fsz > len(ft_data):
                    break
                entry_pc = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                         ft_data[off:off + ptr_size])[0]
                fd_offset = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                        ft_data[off + fsz:off + 2 * fsz])[0]

                if fd_offset + ptr_size > len(data):
                    break
                name_off = struct.unpack(endian + ("I" if ptr_size == 4 else "Q"),
                                        data[fd_offset:fd_offset + ptr_size])[0]

                name_end = fn_data.find(b"\x00", name_off)
                if name_end < 0:
                    name_end = len(fn_data)
                name = fn_data[name_off:name_end].decode("utf-8", errors="replace")

                if entry_pc > 0 and name:
                    funcs.append((entry_pc, name))
            return funcs

    except Exception:
        return []

    return []


def function_table(image):
    """{entry address: name} from the image's gopclntab section; {} for anything that is not Go."""
    try:
        if not any((s.name or "").lower() in ("__gopclntab", ".gopclntab") and s.size for s in image.sections):
            return {}
        return {f["entry_addr"]: f["name"] for f in read_pclntab(image.path, image)}
    except Exception:
        return {}


def read_pclntab(path, image=None):
    """Parse the gopclntab and return a list of {entry_addr, name} dicts.

    Never raises; returns [] if no pclntab is found or it's corrupt.
    """
    try:
        if image is None:
            try:
                image = open_image(path)
            except Exception:
                image = None

        if image is not None:
            data, blob_va = _find_pclntab(image)
            text_start_hint = _find_text_start(image)
        else:
            data, blob_va = None, 0
            text_start_hint = 0
        if data is None:
            raw = _read_file(path)
            for magic in _GO_PCLNTAB_MAGIC_LE:
                magic_bytes = struct.pack("<I", magic)
                idx = raw.find(magic_bytes)
                while idx >= 0:
                    if idx + 32 <= len(raw) and idx % 8 == 0:
                        data = raw[idx:]
                        break
                    idx = raw.find(magic_bytes, idx + 1)
                if data:
                    break

        if not data or len(data) < 16:
            return []

        funcs = _parse_pclntab(data, text_start_hint)
        return [{"entry_addr": pc, "name": name} for pc, name in funcs if pc > 0]

    except Exception:
        pass
    return []


# =====================================================================
# Package extraction
# =====================================================================

def _func_to_package(func_name):
    """Extract the package import path from a Go function name.

    Rules:
    - Strip generics: foo/bar/baz[T].Method -> foo/bar/baz
    - The package is the text before the first '.' after the last '/'
    - Handle method receivers: main.(*T).Method -> main, foo.(func()).Bar -> foo
    - Compiler-special functions (type:.eq.*, go:*, _debugCall*, assembly stubs)
      without a proper package path are attributed to 'runtime'.
    """
    name = func_name

    # Strip generics: foo/bar/baz[T].Method -> foo/bar/baz[T]
    if "[" in name:
        name = name[:name.index("[")]

    # Compiler-special functions with '.' embedded in the name
    # (type:.eq.X, go:buildid, go:textfipsstart, etc.) -> runtime
    if name.startswith("type:") or name.startswith("go:buildid") or name.startswith("go:text"):
        return "runtime"

    # Functions without '/' in name and no '.' are assembly stubs in runtime
    # (e.g., notok, gogo, setg_gcc, _rt0_arm64_darwin)
    if "/" not in name and "." not in name:
        return "runtime"

    # Functions like _debugCall32, _debugCall64, etc. - runtime stubs
    if name.startswith("_debugCall"):
        return "runtime"
    if name.startswith("_"):
        # Other _ prefixed stubs without '/' are runtime
        if "/" not in name:
            return "runtime"

    # Find the package path: text before first '.' after last '/'
    last_slash = name.rfind("/")
    search_start = last_slash if last_slash >= 0 else 0
    first_dot = name.find(".", search_start)
    if first_dot > 0:
        pkg = name[:first_dot]
    else:
        pkg = name

    # Handle method receivers: main.(*T) -> main, foo.(func()).Bar -> foo
    paren_idx = pkg.find(".(*")
    if paren_idx > 0:
        pkg = pkg[:paren_idx]
    else:
        paren_idx = pkg.find(".(")
        if paren_idx > 0:
            pkg = pkg[:paren_idx]

    return pkg


def packages(funcs):
    """Given a list of {entry_addr, name} dicts, compute per-package function counts.

    Returns a list of {package, function_count} sorted by count descending.
    """
    counts = {}
    for f in funcs:
        pkg = _func_to_package(f["name"])
        counts[pkg] = counts.get(pkg, 0) + 1
    result = [{"package": p, "function_count": c} for p, c in counts.items()]
    result.sort(key=lambda x: x["function_count"], reverse=True)
    return result


# =====================================================================
# Public API
# =====================================================================

def go_analyze(path, image=None):
    """Full Go analysis: build info + functions + packages.

    Returns: {build_info, functions, packages}
    build_info may be None; functions is a list; packages is a list.
    Never raises.
    """
    info = read_build_info(path, image)
    funcs = read_pclntab(path, image)
    pkgs = packages(funcs) if funcs else []
    return {
        "build_info": info,
        "functions": funcs,
        "packages": pkgs,
    }


def apply_go_names(prog, path):
    """Apply Go function names recovered from the gopclntab to a Program.

    For functions rdis discovered whose only name is auto-generated (`sub_*`) or
    the Darwin underscore-mangled Mach-O symbol-table form (`_main.main`),
    prefer the authoritative gopclntab name (`main.main`). Explicit user renames
    live in `prog.user_names` and take display priority, so they are never clobbered.

    No-op for non-Go binaries; never raises.
    """
    try:
        funcs = read_pclntab(path, prog.image)
        if not funcs:
            return

        go_names = {}
        for f in funcs:
            go_names[f["entry_addr"]] = f["name"]

        for addr, name in go_names.items():
            if addr not in prog.functions and addr not in prog.names:
                continue
            cur = prog.names.get(addr)
            # Override auto-generated names and Darwin underscore-mangled symbol
            # names with the authoritative gopclntab name.
            if cur is None or cur.startswith("sub_") or cur == "_" + name:
                prog.names[addr] = name
    except Exception:
        pass




# =====================================================================
# String splitting
# =====================================================================
# Go strings are (pointer, length) pairs into one concatenated blob with no terminators. The boundaries
# live in the code that loads a string (address of the blob plus an immediate length) and in static
# (pointer, length) pairs in data. A boundary is accepted only when the bytes are valid printable UTF-8.

_BLOB_SECTIONS = ("rodata", "rdata")
_MAX_STRING = 1 << 16
_X86_LEA = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
_X86_IMM = re.compile(rb"[\xb8-\xbf]|\x48\xc7[\xc0-\xc7]", re.S)


def _blob_ranges(image):
    return [(s.va, s.va + s.size) for s in image.sections
            if not s.code and s.size and any(k in (s.name or "").lower() for k in _BLOB_SECTIONS)]


def _plausible(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or sum(c.isprintable() or c in "\t\r\n" for c in text) < 0.95 * len(text):
        return None
    return text


def _arm64_candidates(code, va):
    """(address, length) from `adrp; add; ... mov xN+1, #len` in either order, 4-byte instructions."""
    n = len(code) // 4
    words = memoryview(code[:n * 4]).cast("I")
    for i in range(n):
        w = words[i]
        if w & 0x9F000000 != 0x90000000:
            continue
        rd = w & 31
        imm = ((w >> 5) & 0x7FFFF) << 2 | (w >> 29) & 3
        imm = imm - (1 << 21) if imm & 0x100000 else imm
        page = ((va + 4 * i) & ~0xFFF) + (imm << 12)
        for j in range(i + 1, min(i + 4, n)):
            x = words[j]
            if x & 0xFFC00000 == 0x91000000 and (x >> 5) & 31 == rd:
                addr, ptr = page + ((x >> 10) & 0xFFF), x & 31
                for k in range(max(0, i - 8), min(j + 8, n)):
                    y = words[k]
                    if y & 0x7F800000 == 0x52800000 and y & 31 == ptr + 1:
                        yield addr, (y >> 5) & 0xFFFF
                break


_GO_AMD64_ARGS = (0, 3, 1, 7, 6, 8, 9, 10, 11)   # rax rbx rcx rdi rsi r8..r11: a string takes two in a row
_X86_MOV_IMM = re.compile(rb"([\x40-\x4f]?)(?:([\xb8-\xbf])|\x48?\xc7([\xc0-\xc7]))(....)", re.S)


def _x86_candidates(code, va):
    """(address, length) from `lea ptr, [rip+d]` with `mov len, imm` in the paired Go argument register."""
    for m in _X86_LEA.finditer(code):
        end = m.end() + 4
        if end > len(code):
            continue
        reg = ((code[m.end() - 1] >> 3) & 7) | (8 if code[m.start()] & 4 else 0)
        if reg not in _GO_AMD64_ARGS[:8:2]:
            continue
        want = _GO_AMD64_ARGS[_GO_AMD64_ARGS.index(reg) + 1]
        addr = va + end + int.from_bytes(code[m.end():end], "little", signed=True)
        lo = max(0, m.start() - 48)
        for im in _X86_MOV_IMM.finditer(code[lo:end + 48]):
            rex, short, long_ = im.group(1), im.group(2), im.group(3)
            low = (short[0] - 0xB8) if short else (long_[0] - 0xC0)
            if low | (8 if rex and rex[0] & 1 else 0) == want:
                yield addr, int.from_bytes(im.group(4), "little")


def string_headers(image):
    """{address: {lengths}} for Go string values found in code and in static data."""
    ranges = _blob_ranges(image)
    if not ranges:
        return {}
    lo, hi = min(r[0] for r in ranges), max(r[1] for r in ranges)
    in_blob = lambda a: any(s <= a < e for s, e in ranges)
    found = {}

    def offer(addr, length):
        if lo <= addr < hi and 0 < length <= _MAX_STRING and in_blob(addr) and in_blob(addr + length - 1):
            found.setdefault(addr, set()).add(length)

    sweep = {"arm64": _arm64_candidates, "x86_64": _x86_candidates}.get(image.arch.name)
    for s in image.sections:
        if s.size == 0 or s.name in (".bss", "__bss", "__noptrbss"):
            continue
        data = image.read(s.va, s.size)
        if s.code and sweep:
            for addr, length in sweep(data, s.va):
                offer(addr, length)
        elif not s.code:
            ptr = image.arch.bits // 8
            if len(data) >= 2 * ptr:
                words = [int.from_bytes(data[o:o + ptr], "little") for o in range(0, len(data) - ptr + 1, ptr)]
                for i in range(len(words) - 1):
                    if lo <= words[i] < hi:
                        offer(words[i], words[i + 1])
    out = {}
    for addr, lengths in found.items():
        for length in lengths:
            if _plausible(image.read(addr, length)) is not None:
                out.setdefault(addr, set()).add(length)
    return out


def string_slots(image):
    """{address of a static (pointer, length) string header: address of the string it points at}."""
    try:
        headers, ranges = string_headers(image), _blob_ranges(image)
        slots, ptr = {}, image.arch.bits // 8
        for s in image.sections:
            if s.code or s.size == 0 or s.name in (".bss", "__bss", "__noptrbss"):
                continue
            data = image.read(s.va, s.size)
            for o in range(0, len(data) - 2 * ptr + 1, ptr):
                p = int.from_bytes(data[o:o + ptr], "little")
                if p in headers and int.from_bytes(data[o + ptr:o + 2 * ptr], "little") in headers[p]:
                    slots[s.va + o] = p
        return slots
    except Exception:
        return {}


def split_strings(image, base):
    """Replace the concatenated Go string blob entries in `base` ({va: text}) with the individual strings.

    Text between recovered strings is kept as it was, so nothing is lost; only boundaries are added."""
    try:
        headers = string_headers(image)
        if not headers:
            return base
        ranges = _blob_ranges(image)
        out = {a: t for a, t in base.items() if not any(s <= a < e for s, e in ranges)}
        covered = []
        for addr, lengths in headers.items():
            for length in lengths:
                out[addr] = _plausible(image.read(addr, length))
                covered.append((addr, addr + length))
        covered.sort()
        for a, t in base.items():
            if not any(s <= a < e for s, e in ranges):
                continue
            raw, pos = t.encode("utf-8", "replace"), 0
            for s, e in covered:
                if e <= a or s >= a + len(raw):
                    continue
                if s - a > pos:
                    gap = raw[pos:s - a].decode("utf-8", "replace")
                    if len(gap) >= 4:
                        out.setdefault(a + pos, gap)
                pos = max(pos, e - a)
            if pos < len(raw) and len(raw) - pos >= 4:
                out.setdefault(a + pos, raw[pos:].decode("utf-8", "replace"))
        return out
    except Exception:
        return base
