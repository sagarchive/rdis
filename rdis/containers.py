"""Package containers (APK/IPA/AAR/JAR/ZIP, DMG): what's inside, and extracting one member.

Shared by the loader dialogs (server) and the CLI (`rdis app.apk`, `rdis app.apk -l lib/...`).
`slices(path)` is the loader-choice list; every archive/DMG row carries an `entry` naming the
member. `_extract` pulls one member into a content-addressed cache file.
"""
import errno
import functools
import hashlib
import lzma
import os
import shutil
import struct
import tarfile
import threading
import zipfile
import zlib

import lief

_ABI_ARCH = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm",
             "x86_64": "x86_64", "x86": "x86", "riscv64": "riscv64",
             "mips": "mipsel", "mips64": "mips64el"}

DECOMP = "\x00decompress"   # sentinel `entry`: decompress the file itself, then analyze it

# magic -> True when the first bytes are a native executable / module we can analyze directly
_NATIVE_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                 b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\0asm")
_RAW = [{"arch": "x86_64", "label": "Raw binary (x86-64)", "loader": "raw"},
        {"arch": "arm64", "label": "Raw binary (AArch64)", "loader": "raw"},
        {"arch": "arm", "label": "Raw binary (ARM)", "loader": "raw"},
        {"arch": "x86", "label": "Raw binary (x86)", "loader": "raw"},
        {"arch": "riscv64", "label": "Raw binary (RISC-V 64)", "loader": "raw"},
        {"arch": "mipsel", "label": "Raw binary (MIPS32 LE)", "loader": "raw"},
        {"arch": "mips", "label": "Raw binary (MIPS32 BE)", "loader": "raw"}]


def _is_native(magic):
    return magic[:4] in _NATIVE_MAGIC or magic[:2] == b"MZ"


def _opener(head):
    """(name, open-fn) for a gzip/xz/bzip2 stream, or (None, None)."""
    import bz2, gzip, lzma
    if head[:2] == b"\x1f\x8b":
        return "gzip", gzip.open
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz", lzma.open
    if head[:3] == b"BZh":
        return "bzip2", bz2.open
    return None, None


def _file_digest(path):
    """SHA-256 the actual file bytes; metadata alone is not a safe cache identity."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_bounded(src, dst, limit, expected_size=None):
    """Stream at most limit bytes and reject oversized or truncated members."""
    total = 0
    while True:
        chunk = src.read(min(1 << 20, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"expanded data exceeds the {limit} byte limit")
        dst.write(chunk)
    if expected_size is not None and total != expected_size:
        raise ValueError(f"archive member size mismatch: expected {expected_size} bytes, got {total}")
    return total


def _peek_compressed(path):
    """gzip/xz/bzip2 single file: peek the decompressed header and offer to open it transparently."""
    with open(path, "rb") as fh:
        head = fh.read(6)
    kind, op = _opener(head)
    if op is None:
        return None
    try:
        with op(path, "rb") as r:
            magic = r.read(8)
    except Exception:
        return None
    if _is_native(magic):
        return [{"entry": DECOMP, "arch": None, "label": f"{kind}-compressed binary — decompress and analyze"}]
    return [{**s, "entry": DECOMP, "label": f"{kind} → " + s["label"]} for s in _RAW]


class StorageLimitError(ValueError):
    """The shared extraction/upload directory has reached its configured disk quota."""


_STORAGE_WRITE_LOCK = threading.Lock()


def _validate_total_limit(max_total_mb):
    if max_total_mb is not None and (
        not isinstance(max_total_mb, int) or isinstance(max_total_mb, bool) or max_total_mb < 1
    ):
        raise ValueError("max_total_mb must be a positive integer")


def _directory_size(path):
    total = 0
    if not os.path.isdir(path):
        return 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                if not os.path.islink(os.path.join(root, name)):
                    total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def _write_atomic(cache_dir, out, fill, max_total_bytes=None):
    """Atomically write a cache result and enforce an optional aggregate directory quota."""
    import tempfile
    os.makedirs(cache_dir, exist_ok=True)
    with _STORAGE_WRITE_LOCK:
        used = _directory_size(cache_dir) if max_total_bytes is not None else 0
        old_size = os.path.getsize(out) if os.path.isfile(out) else 0
        fd, tmp = tempfile.mkstemp(dir=cache_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                fill(f)
            if max_total_bytes is not None:
                projected = used - old_size + os.path.getsize(tmp)
                if projected > max_total_bytes:
                    raise StorageLimitError(
                        f"cache storage quota exceeded ({projected} > {max_total_bytes} bytes); "
                        "remove unused files from the upload/cache directory or raise the configured limit"
                    )
            os.replace(tmp, out)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

def _decompress(path, cache_dir, max_mb, max_total_mb=None):
    if not isinstance(max_mb, int) or isinstance(max_mb, bool) or max_mb < 1:
        raise ValueError("max_mb must be a positive integer")
    if max_total_mb is not None and (not isinstance(max_total_mb, int) or isinstance(max_total_mb, bool) or max_total_mb < 1):
        raise ValueError("max_total_mb must be a positive integer")
    with open(path, "rb") as fh:
        head = fh.read(6)
    _, op = _opener(head)
    if op is None:
        return None
    os.makedirs(cache_dir, exist_ok=True)
    # Include content and the configured cap: same-size/same-mtime rewrites must not reuse output,
    # and a result produced under a larger limit must not bypass a smaller limit.
    digest = _file_digest(path)
    tag = hashlib.sha256(f"{os.path.abspath(path)}|{digest}|{max_mb}|decomp".encode()).hexdigest()[:24]
    out = os.path.join(cache_dir, f"{tag}-{os.path.basename(path).rsplit('.', 1)[0][:48] or 'bin'}")
    if not os.path.exists(out):
        def fill(w):
            with op(path, "rb") as r:
                _copy_bounded(r, w, max_mb << 20)
        _write_atomic(cache_dir, out, fill, (max_total_mb << 20) if max_total_mb is not None else None)
    return out


_TAR_MAX_MEMBERS = 20000   # a few hundred KB of xz expands to millions of tar headers (each kept
_TAR_MAX_SCAN = 1 << 30    # as a TarInfo) or a member gigabytes long to inflate past: cap the walk


def _tar_members(t):
    """Members of an open tar, walked lazily and bounded (count and bytes inflated)."""
    for n in range(_TAR_MAX_MEMBERS):
        m = t.next()
        if m is None or m.offset_data > _TAR_MAX_SCAN:
            return
        yield m


def _tar_slices(path):
    """Native binaries inside a tar/tar.gz/tar.xz archive (firmware dumps, source bundles)."""
    import tarfile
    out = []
    with tarfile.open(path) as t:
        for m in _tar_members(t):
            if not m.isfile() or m.size < 4 or m.size > (512 << 20):
                continue
            try:
                magic = t.extractfile(m).read(8)
            except Exception:
                continue
            if _is_native(magic):
                out.append({"entry": m.name, "label": f"{m.name}  ({m.size:,} B)", "size": m.size})
    out.sort(key=lambda s: s["entry"])
    return out or [{"arch": None, "disabled": True, "label": "No native binaries found in this tar archive."}]


def _tar_extract(path, entry, cache_dir, max_mb, max_total_mb=None):
    import tarfile
    if not isinstance(max_mb, int) or isinstance(max_mb, bool) or max_mb < 1:
        raise ValueError("max_mb must be a positive integer")
    _validate_total_limit(max_total_mb)
    with tarfile.open(path) as t:
        m = next((m for m in _tar_members(t) if m.name == entry and m.isfile()), None)
        if m is None:
            raise KeyError(f"no such file in the tar archive: {entry}")
        limit = max_mb << 20
        if m.size > limit:
            raise ValueError(f"archive member larger than {max_mb} MB")
        os.makedirs(cache_dir, exist_ok=True)
        # The archive digest avoids stale extraction when a member is replaced with same-size data.
        tag = hashlib.sha256(
            f"{os.path.abspath(path)}|{_file_digest(path)}|{entry}|{m.offset_data}|{m.size}|{max_mb}".encode()
        ).hexdigest()[:24]
        safe = "".join(c for c in os.path.basename(entry) if c.isalnum() or c in "._-")[:64] or "bin"
        out = os.path.join(cache_dir, f"{tag}-{safe}")
        if not (os.path.exists(out) and os.path.getsize(out) == m.size):
            def fill(dst):
                src = t.extractfile(m)
                if src is None:
                    raise ValueError(f"could not read archive member: {entry}")
                with src:
                    _copy_bounded(src, dst, limit, expected_size=m.size)
            _write_atomic(cache_dir, out, fill, (max_total_mb << 20) if max_total_mb is not None else None)
    return out


_FORMAT_ERRORS = (zipfile.BadZipFile, tarfile.TarError, zlib.error, lzma.LZMAError, EOFError, UnicodeError,
                  struct.error, NotImplementedError)


def _malformed(fn):
    """Report a corrupt archive as ValueError. Real I/O failures (missing file, permissions) keep their type;
    gzip and bz2 signal corrupt data with an OSError that carries no errno."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except _FORMAT_ERRORS as e:
            raise ValueError(f"malformed archive: {e}") from e
        except OSError as e:
            if e.errno in (None, errno.EINVAL):
                raise ValueError(f"malformed archive: {e}") from e
            raise
    return wrapper


@_malformed
def slices(path):
    """Loader choices for a file. For a native binary: its slices. For an archive
    (APK/AAR/JAR/IPA/ZIP): the native libraries it contains, each openable on its own."""
    if lief.is_macho(path):
        fat = lief.MachO.parse(path)
        out = [{"arch": _arch_of(b), "label": f"Mach-O {_arch_of(b)}"} for b in fat]
        return out or [{"arch": None, "label": "Mach-O"}]
    if lief.is_elf(path):
        return [{"arch": None, "label": "ELF"}]
    if lief.is_pe(path):
        return [{"arch": None, "label": "PE"}]
    import zipfile
    if zipfile.is_zipfile(path):
        return _archive_slices(path)
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:4] == b"\0asm":
        return [{"arch": "wasm", "label": "WebAssembly module"}]
    if _is_dmg(path):
        return _dmg_slices(path)
    import tarfile
    try:
        if tarfile.is_tarfile(path):
            return _tar_slices(path)
    except (OSError, tarfile.TarError):
        pass
    comp = _peek_compressed(path)       # gzip / xz / bzip2 single file: decompress transparently
    if comp:
        return comp
    if head[:4] == b"\x28\xb5\x2f\xfd":  # zstd has no stdlib decoder
        return [{"arch": None, "disabled": True,
                 "label": "zstd-compressed — run `zstd -d` first, then open the decompressed binary"}]
    return list(_RAW)                   # unknown: open as a headerless blob at a chosen architecture


def _is_dmg(path):
    """Apple disk image: UDIF trailer 'koly' in the last 512 bytes."""
    try:
        with open(path, "rb") as f:
            f.seek(-512, 2)
            return b"koly" in f.read(512)
    except OSError:
        return False


def _dmg_slices(path):
    """Mach-O/ELF/PE binaries inside a DMG, via `hdiutil` (macOS). Mounts read-only, walks the
    volume, and lists native executables; each entry carries the in-DMG path as its `entry`."""
    if not shutil.which("hdiutil"):
        return [{"arch": None, "disabled": True,
                 "label": "DMG needs `hdiutil` (macOS) to inspect; not available on this host"}]
    out = _dmg_list(path)
    return out or [{"arch": None, "disabled": True, "label": "No native binaries found in the DMG"}]


def _archive_slices(path):
    """Native libraries inside an APK/IPA/AAR/ZIP, as loader choices. Each carries the `entry` to
    extract. A note row flags Dalvik `.dex` (Java bytecode: out of scope, needs a DEX tool)."""
    import zipfile
    out, has_dex = [], False
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            n = info.filename
            if n.endswith("/"):
                continue
            low = n.lower()
            if low.endswith(".dex"):
                has_dex = True
            elif low.endswith((".so", ".dylib")) or low.startswith("lib/"):
                # `lib/` = the Android native dir; a bare "/lib/" anywhere would also match
                # flutter_assets/lib/... (fonts, images) which are not native code.
                abi = next((a for a in _ABI_ARCH if f"/{a}/" in n or n.startswith(a + "/")), None)
                out.append({"entry": n, "arch": _ABI_ARCH.get(abi),
                            "label": f"{n}  ({info.file_size:,} B)", "size": info.file_size})
            elif low.endswith((".exe", ".dll")):
                out.append({"entry": n, "label": f"{n}  ({info.file_size:,} B)", "size": info.file_size})
    out.sort(key=lambda s: (s.get("arch") or "zzz", s["entry"]))
    if not out:
        note = "No native libraries found. "
        note += "This APK's code is Dalvik bytecode (classes.dex) — use a DEX decompiler (jadx)." \
            if has_dex else "Archive contains no Mach-O/ELF/PE files."
        return [{"arch": None, "label": note, "disabled": True}]
    if has_dex:
        out.append({"label": "(classes.dex — Java/Kotlin bytecode, not analyzable here)",
                    "disabled": True, "arch": None})
    return out


def _dmg_list(path, _extract_entry=None, cache_dir=".rdis_uploads", max_mb=128, max_total_mb=None):
    """Attach a DMG read-only, enumerate native binaries (or extract one). Returns slice list, or
    the extracted file path when `_extract_entry` is given."""
    _validate_total_limit(max_total_mb)
    import plistlib
    import subprocess
    try:
        out = subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-plist", path],
                             capture_output=True, timeout=120)
        if out.returncode != 0:
            return [] if _extract_entry is None else None
        info = plistlib.loads(out.stdout)
        mounts = [e["mount-point"] for e in info.get("system-entities", []) if e.get("mount-point")]
    except Exception:
        return [] if _extract_entry is None else None
    try:
        slices, dev = [], info["system-entities"][0]["dev-entry"]
        for mp in mounts:
            for root, _, files in os.walk(mp):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, mp)
                    if os.path.islink(full):   # an image is attacker-controlled: a symlink to
                        continue               # /some/host/file must not be read or copied out
                    try:
                        with open(full, "rb") as f:
                            magic = f.read(4)
                    except OSError:
                        continue
                    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                                 b"\x7fELF") or magic[:2] == b"MZ":
                        if _extract_entry == rel:
                            size = os.path.getsize(full)
                            limit = max_mb << 20
                            if size > limit:
                                raise ValueError(f"disk image member larger than {max_mb} MB")
                            # The image can be replaced while retaining its path; bind the extraction
                            # cache to the image bytes and member identity, and write atomically.
                            tag = hashlib.sha256(
                                f"{os.path.abspath(path)}|{_file_digest(path)}|{rel}|{size}|{max_mb}".encode()
                            ).hexdigest()[:24]
                            dst = os.path.join(cache_dir, tag + "-" + fn)
                            os.makedirs(cache_dir, exist_ok=True)
                            if not (os.path.exists(dst) and os.path.getsize(dst) == size):
                                def fill(out):
                                    with open(full, "rb") as src:
                                        _copy_bounded(src, out, limit, expected_size=size)
                                _write_atomic(cache_dir, dst, fill, (max_total_mb << 20) if max_total_mb is not None else None)
                            return dst
                        slices.append({"entry": rel, "arch": None,
                                       "label": f"{rel}  ({os.path.getsize(full):,} B)"})
        return slices if _extract_entry is None else None
    finally:
        for mp in mounts:
            subprocess.run(["hdiutil", "detach", "-quiet", mp], capture_output=True)


def _arch_of(b):
    from .loader import _arch_name
    try:
        return _arch_name(b)
    except KeyError:
        cpu = b.header.cpu_type
        return getattr(cpu, "__name__", f"cpu{int(cpu)}").lower()


@_malformed
def extract(path, entry, cache_dir=".rdis_uploads", max_mb=128, max_total_mb=None):
    """Extract one archive member to a content-addressed cache file; return its path. Guards against
    zip-slip and zip bombs (size cap). Handles both ZIP-family archives and DMG disk images."""
    if not isinstance(max_mb, int) or isinstance(max_mb, bool) or max_mb < 1:
        raise ValueError("max_mb must be a positive integer")
    _validate_total_limit(max_total_mb)
    import tarfile
    import zipfile
    if entry == DECOMP:
        out = _decompress(path, cache_dir, max_mb, max_total_mb=max_total_mb)
        if out is None:
            raise ValueError("could not decompress this file")
        return out
    # same detection order as slices(): a zip (APK) with "koly" in its trailing comment is a zip
    if not zipfile.is_zipfile(path):
        if _is_dmg(path):
            out = _dmg_list(path, _extract_entry=entry, cache_dir=cache_dir, max_mb=max_mb, max_total_mb=max_total_mb)
            if out is None:
                raise ValueError(f"could not extract {entry} from the disk image")
            return out
        try:
            if tarfile.is_tarfile(path):
                return _tar_extract(path, entry, cache_dir, max_mb, max_total_mb=max_total_mb)
        except tarfile.TarError:
            pass
    if not isinstance(max_mb, int) or isinstance(max_mb, bool) or max_mb < 1:
        raise ValueError("max_mb must be a positive integer")
    with zipfile.ZipFile(path) as z:
        info = z.getinfo(entry)
        limit = max_mb << 20
        if info.file_size > limit:
            raise ValueError(f"archive member larger than {max_mb} MB")
        os.makedirs(cache_dir, exist_ok=True)
        tag = hashlib.sha256(
            f"{os.path.abspath(path)}|{_file_digest(path)}|{entry}|{info.header_offset}|"
            f"{info.CRC}|{info.file_size}|{max_mb}".encode()
        ).hexdigest()[:24]
        safe = "".join(c for c in os.path.basename(entry) if c.isalnum() or c in "._-")[:64] or "lib"
        out = os.path.join(cache_dir, f"{tag}-{safe}")
        if not (os.path.exists(out) and os.path.getsize(out) == info.file_size):
            def fill(dst):
                with z.open(entry) as src:
                    _copy_bounded(src, dst, limit, expected_size=info.file_size)
            _write_atomic(cache_dir, out, fill, (max_total_mb << 20) if max_total_mb is not None else None)
    return out


@_malformed
def find_entry(path, want):
    """Resolve a user-typed `-l` selector to an archive entry: exact match, else a unique
    substring/suffix match (`-l libfoo.so` finds `lib/arm64-v8a/libfoo.so`)."""
    import zipfile
    cands = [s["entry"] for s in slices(path) if s.get("entry")]
    if want in cands:
        return want
    sub = [e for e in cands if want in e or e.endswith("/" + want)]
    if len(sub) == 1:
        return sub[0]
    if len(sub) > 1:
        raise KeyError(f"ambiguous -l {want!r}: {', '.join(sub)}")
    raise KeyError(f"no archive member matching {want!r} (members: {', '.join(cands[:20])}"
                   f"{'…' if len(cands) > 20 else ''})")
