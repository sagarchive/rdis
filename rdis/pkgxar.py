"""Flat installer packages (.pkg) and other xar archives: table of contents, components, scripts, payload files.

Pure Python. Everything read from the file is bounded: the table of contents, every decoded member and each
decompressed payload, so a crafted package cannot exhaust memory. Member names are only ever labels here;
nothing in this module writes to disk.
"""
import bz2
import gzip
import hashlib
import lzma
import re
import struct
import xml.etree.ElementTree as ET
import zlib

MAGIC = b"xar!"
MAX_TOC = 64 << 20
MAX_MEMBER = 256 << 20
SCRIPT_NAMES = ("preinstall", "postinstall", "preupgrade", "postupgrade", "preflight", "postflight")
NATIVE_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe")

# what an installer script does that deserves a second look (evidence, not a verdict)
SCRIPT_RULES = (
    ("downloads code", re.compile(r"\b(curl|wget)\b")),
    ("pipes to a shell", re.compile(r"\|\s*(ba|z)?sh\b")),
    ("decodes data", re.compile(r"\bbase64\b\s+(-d|--decode|-D)")),
    ("elevates privileges", re.compile(r"\bsudo\b|with administrator privileges")),
    ("runs AppleScript", re.compile(r"\bosascript\b")),
    ("loads a launch job", re.compile(r"\blaunchctl\b")),
    ("writes a launch item", re.compile(r"LaunchDaemons|LaunchAgents")),
    ("changes permissions", re.compile(r"\bchmod\b\s+(\+x|[0-7]{3,4}|u\+s|\+s)")),
    ("clears quarantine", re.compile(r"com\.apple\.quarantine")),
    ("changes Gatekeeper", re.compile(r"\bspctl\b")),
    ("removes files", re.compile(r"\brm\s+-[a-zA-Z]*r")),
    ("edits login items", re.compile(r"login\s*item|SMLoginItem|sfltool", re.I)),
    ("edits the hosts file", re.compile(r"/etc/hosts")),
    ("adds a user or group", re.compile(r"\b(dscl|sysadminctl|dseditgroup)\b")),
)


class PkgError(ValueError):
    pass


def is_xar(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == MAGIC
    except OSError:
        return False


def _bounded(decoder, data, limit):
    out = decoder.decompress(data, limit + 1)
    if len(out) > limit or getattr(decoder, "unconsumed_tail", b""):
        raise PkgError(f"decoded data larger than {limit >> 20} MB")
    return out


def _header(fh):
    raw = fh.read(28)
    if len(raw) < 28 or raw[:4] != MAGIC:
        raise PkgError("not a xar archive")
    _, hsize, _version, clen, ulen, _alg = struct.unpack(">4sHHQQI", raw)
    if hsize < 28 or clen > MAX_TOC or ulen > MAX_TOC:
        raise PkgError("xar header is out of range")
    return hsize, clen


def entries(path):
    """Every member of the archive: {path, type, id, offset, length, size, encoding}, offsets relative to the heap."""
    with open(path, "rb") as fh:
        hsize, clen = _header(fh)
        fh.seek(hsize)
        compressed = fh.read(clen)
    if len(compressed) != clen:
        raise PkgError("truncated table of contents")
    try:
        toc = _bounded(zlib.decompressobj(), compressed, MAX_TOC)
        root = ET.fromstring(toc)
    except (zlib.error, ET.ParseError) as e:
        raise PkgError(f"unreadable table of contents: {e}") from None
    out = []

    def walk(node, prefix):
        for f in node.findall("file"):
            name = (f.findtext("name") or "").replace("\\", "/")
            path_ = f"{prefix}/{name}" if prefix else name
            data = f.find("data")
            enc = data.find("encoding") if data is not None else None
            out.append({"path": path_, "type": f.findtext("type") or "file", "id": f.get("id"),
                        "offset": int(data.findtext("offset") or 0) if data is not None else 0,
                        "length": int(data.findtext("length") or 0) if data is not None else 0,
                        "size": int(data.findtext("size") or 0) if data is not None else 0,
                        "encoding": enc.get("style") if enc is not None else "application/octet-stream"})
            walk(f, path_)

    walk(root.find("toc") if root.find("toc") is not None else root, "")
    return out


def read_member(path, entry, limit=MAX_MEMBER):
    """The decoded bytes of one member."""
    with open(path, "rb") as fh:
        hsize, clen = _header(fh)
        fh.seek(0, 2)
        total = fh.tell()
        start = hsize + clen + entry["offset"]
        if entry["length"] > limit or start + entry["length"] > total:
            raise PkgError(f"member {entry['path']} is truncated or larger than {limit >> 20} MB")
        fh.seek(start)
        raw = fh.read(entry["length"])
    style = entry["encoding"]
    try:
        if "gzip" in style or "zlib" in style:
            return _bounded(zlib.decompressobj(), raw, limit)
        if "bzip2" in style:
            return _bounded(bz2.BZ2Decompressor(), raw, limit)
        if "lzma" in style or "xz" in style:
            return _bounded(lzma.LZMADecompressor(), raw, limit)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError) as e:
        raise PkgError(f"cannot decode {entry['path']}: {e}") from None
    return raw


def _decompress_payload(data, limit=MAX_MEMBER):
    """Payload and Scripts are cpio archives, compressed with gzip, bzip2, xz, or Apple's chunked xz (pbzx)."""
    try:
        if data[:4] == b"pbzx":
            out, pos = [], 12
            while pos + 16 <= len(data):
                _flags, length = struct.unpack(">QQ", data[pos:pos + 16])
                chunk = data[pos + 16:pos + 16 + length]
                pos += 16 + length
                out.append(_bounded(lzma.LZMADecompressor(), chunk, limit) if chunk[:6] == b"\xfd7zXZ\x00" else chunk)
                if sum(map(len, out)) > limit:
                    raise PkgError(f"payload larger than {limit >> 20} MB")
            return b"".join(out)
        if data[:2] == b"\x1f\x8b":
            return _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), data, limit)
        if data[:3] == b"BZh":
            return _bounded(bz2.BZ2Decompressor(), data, limit)
        if data[:6] == b"\xfd7zXZ\x00":
            return _bounded(lzma.LZMADecompressor(), data, limit)
    except (zlib.error, OSError, EOFError, lzma.LZMAError) as e:
        raise PkgError(f"cannot decode payload: {e}") from None
    return data


def cpio_members(data):
    """[(name, mode, bytes)] from an odc ("070707") or newc ("070701"/"070702") cpio archive."""
    out, pos = [], 0
    while pos + 6 <= len(data):
        magic = data[pos:pos + 6]
        if magic == b"070707":
            if pos + 76 > len(data):
                break
            f = data[pos:pos + 76]
            mode, namesize, size = int(f[18:24], 8), int(f[59:65], 8), int(f[65:76], 8)
            name_at = pos + 76
            data_at = name_at + namesize
        elif magic in (b"070701", b"070702"):
            if pos + 110 > len(data):
                break
            f = data[pos + 6:pos + 110]
            mode, size, namesize = int(f[8:16], 16), int(f[48:56], 16), int(f[88:96], 16)
            name_at = pos + 110
            data_at = (name_at + namesize + 3) & ~3
        else:
            raise PkgError("not a cpio archive")
        name = data[name_at:name_at + namesize - 1].decode("utf-8", "replace")
        if name == "TRAILER!!!":
            break
        if data_at + size > len(data):
            raise PkgError("truncated cpio member")
        out.append((name, mode, data[data_at:data_at + size]))
        pos = data_at + size if magic == b"070707" else (data_at + size + 3) & ~3
    return out


def _is_file(mode):
    return mode & 0o170000 == 0o100000


def _real(name):
    """macOS packs resource forks as AppleDouble `._name` siblings; they are metadata, not files."""
    return not name.rsplit("/", 1)[-1].startswith("._")


def _script_info(name, mode, body, max_bytes):
    text = body[:max_bytes].decode("utf-8", "replace")
    native = body[:4] in NATIVE_MAGIC
    first = text.split("\n", 1)[0]
    findings = []
    if not native:
        for lineno, line in enumerate(text.splitlines(), 1):
            for label, pattern in SCRIPT_RULES:
                if pattern.search(line):
                    findings.append({"rule": label, "line": lineno, "text": line.strip()[:200]})
    return {"name": name, "mode": oct(mode & 0o7777), "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "executable": bool(mode & 0o111), "native": native,
            "interpreter": first[2:].strip() if first.startswith("#!") else None,
            "text": None if native else text, "truncated": len(body) > max_bytes, "findings": findings}


def _package_info(raw):
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}
    info = {k: root.get(k) for k in ("identifier", "version", "install-location", "auth") if root.get(k)}
    info["scripts"] = {c.tag: c.get("file") for s in root.findall("scripts") for c in s}
    return info


def _components(items):
    """{component name: {member name: entry}}; a package with no component directories is one component."""
    roots = {e["path"].split("/")[0] for e in items if "/" in e["path"] and e["path"].split("/")[0].endswith((".pkg", ".mpkg"))}
    if not roots:
        return {"": {e["path"]: e for e in items if "/" not in e["path"]}}
    return {r: {e["path"][len(r) + 1:]: e for e in items if e["path"].startswith(r + "/")} for r in sorted(roots)}


def analyze(path, max_script_bytes=65536, list_files=True):
    """Components, install scripts (with what they do) and payload files of a flat package."""
    items = entries(path)
    out = {"format": "xar", "members": len(items), "components": [], "scripts": [], "files": [], "errors": []}
    names = {e["path"] for e in items}
    if "Distribution" in names:
        try:
            dist = ET.fromstring(read_member(path, next(e for e in items if e["path"] == "Distribution"), 4 << 20))
            out["distribution"] = {"title": dist.findtext("title"),
                                   "scripts": [e.get("script") or "" for e in dist.iter("installer-script")][:5],
                                   "has_javascript": dist.find("script") is not None}
        except (PkgError, ET.ParseError, StopIteration):
            out["errors"].append("Distribution unreadable")
    for comp, members in _components(items).items():
        info = {"name": comp, "files": 0}
        if "PackageInfo" in members:
            try:
                info.update(_package_info(read_member(path, members["PackageInfo"], 4 << 20)))
            except PkgError as e:
                out["errors"].append(f"{comp}/PackageInfo: {e}")
        if "Scripts" in members:
            try:
                for name, mode, body in cpio_members(_decompress_payload(read_member(path, members["Scripts"]))):
                    base = name[2:] if name.startswith("./") else name
                    if _is_file(mode) and base and _real(base):
                        s = _script_info(base, mode, body, max_script_bytes)
                        s["component"] = comp
                        s["stage"] = "pre" if base.startswith("pre") else "post" if base.startswith("post") else "other"
                        out["scripts"].append(s)
            except PkgError as e:
                out["errors"].append(f"{comp}/Scripts: {e}")
        if "Payload" in members and list_files:
            try:
                for name, mode, body in cpio_members(_decompress_payload(read_member(path, members["Payload"]))):
                    if _is_file(mode) and _real(name):
                        rel = name[2:] if name.startswith("./") else name
                        out["files"].append({"component": comp, "path": rel, "size": len(body), "mode": oct(mode & 0o7777),
                                             "native": body[:4] in NATIVE_MAGIC or body[:2] == b"MZ",
                                             "executable": bool(mode & 0o111)})
                        info["files"] += 1
            except PkgError as e:
                out["errors"].append(f"{comp}/Payload: {e}")
        out["components"].append(info)
    return out


def payload_file(path, component, rel):
    """Bytes of one payload file."""
    members = _components(entries(path))[component]
    for name, mode, body in cpio_members(_decompress_payload(read_member(path, members["Payload"]))):
        if (name[2:] if name.startswith("./") else name) == rel and _is_file(mode):
            return body
    raise KeyError(f"{rel} is not in the payload of {component or 'this package'}")
