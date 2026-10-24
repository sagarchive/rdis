"""Triage of a whole application bundle (.app, framework, any directory) or flat installer package (.pkg).

One row per native binary: format, entropy, runtime, code signature, entitlements. Plus the Info.plist facts a
reviewer wants first (permissions the app asks for) and, for packages, the install scripts. Evidence, not verdicts.
"""
import os
import plistlib
import re
import shutil
import subprocess
import tempfile

from . import pkgxar

MAX_FILES = 5000
MAX_BINARY = 512 << 20
NATIVE = pkgxar.NATIVE_MAGIC + (b"MZ",)
USAGE_KEYS = re.compile(r"^NS.*UsageDescription$|^NSAppleEventsUsageDescription$")
PLIST_FACTS = ("CFBundleIdentifier", "CFBundleName", "CFBundleShortVersionString", "CFBundleVersion",
               "CFBundleExecutable", "LSMinimumSystemVersion", "LSUIElement", "LSBackgroundOnly",
               "SMPrivilegedExecutables", "SMAuthorizedClients")


def is_bundle(path):
    return os.path.isdir(path) or pkgxar.is_xar(path)


def codesign_info(path):
    """Signature facts from the system `codesign` (macOS); {"available": False} elsewhere."""
    exe = shutil.which("codesign")
    if not exe:
        return {"available": False}
    try:
        r = subprocess.run([exe, "-dvv", "--entitlements", ":-", path], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return {"available": True, "signed": None, "error": str(e)}
    err = r.stderr.decode("utf-8", "replace")
    if "not signed at all" in err:
        return {"available": True, "signed": False}
    fields = {}
    authorities = []
    for line in err.splitlines():
        key, _, value = line.partition("=")
        if key == "Authority":
            authorities.append(value)
        elif value:
            fields.setdefault(key, value)
    flags = re.search(r"flags=(0x[0-9a-f]+)\(([^)]*)\)", err)
    entitlements = {}
    out = r.stdout
    if out:
        start = out.find(b"<?xml")
        try:
            entitlements = plistlib.loads(out[start:] if start >= 0 else out)
        except Exception:
            entitlements = {}
    return {"available": True, "signed": r.returncode == 0 or "Identifier" in fields,
            "adhoc": fields.get("Signature") == "adhoc", "identifier": fields.get("Identifier"),
            "team_id": None if fields.get("TeamIdentifier") in (None, "not set") else fields["TeamIdentifier"],
            "authorities": authorities, "hardened_runtime": bool(flags and "runtime" in flags.group(2)),
            "flags": flags.group(2) if flags else None, "entitlements": entitlements}


def _plist_facts(raw):
    try:
        data = plistlib.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    facts = {k: data[k] for k in PLIST_FACTS if k in data}
    facts["usage"] = {k: v for k, v in data.items() if USAGE_KEYS.match(k)}
    schemes = [s for t in data.get("CFBundleURLTypes", []) if isinstance(t, dict) for s in t.get("CFBundleURLSchemes", [])]
    if schemes:
        facts["url_schemes"] = schemes
    ats = data.get("NSAppTransportSecurity")
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads"):
        facts["allows_arbitrary_loads"] = True
    return facts


def _binary_row(path, label):
    from .triage import triage
    row = {"path": label, "bytes": os.path.getsize(path)}
    try:
        t = triage(path)
        sections = t.get("sections", [])
        row.update({"format": t["format"], "arch": t["arch"], "overall_entropy": t["overall_entropy"],
                    "max_section_entropy": max((s["entropy"] for s in sections), default=0),
                    "runtimes": [r["runtime"] + (f" {r['go_version']}" if r.get("go_version") else "")
                                 for r in t.get("runtimes", [])],
                    "indicators": [i["indicator"] for i in t.get("indicators", [])]})
    except Exception as e:                         # a binary rdis cannot load is still listed
        row["error"] = f"{type(e).__name__}: {e}"
    row["signature"] = codesign_info(path)
    return row


def _walk(root):
    """Regular files under root, never following symlinks, bounded in count."""
    seen = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(base, d)))
        for name in sorted(files):
            full = os.path.join(base, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            seen += 1
            if seen > MAX_FILES:
                return
            yield full


def _directory(path):
    out = {"kind": "app" if path.rstrip("/").endswith(".app") else "directory", "root": os.path.abspath(path),
           "plists": [], "binaries": [], "skipped": 0}
    for full in _walk(path):
        rel = os.path.relpath(full, path)
        try:
            with open(full, "rb") as fh:
                head = fh.read(4)
            if os.path.basename(full) == "Info.plist":
                with open(full, "rb") as fh:
                    facts = _plist_facts(fh.read(4 << 20))
                if facts:
                    out["plists"].append({"path": rel, **facts})
            if head in NATIVE or head[:2] == b"MZ":
                if os.path.getsize(full) > MAX_BINARY:
                    out["skipped"] += 1
                    continue
                out["binaries"].append(_binary_row(full, rel))
        except OSError:
            out["skipped"] += 1
    return out


def _package(path):
    info = pkgxar.analyze(path, list_files=False)
    out = {"kind": "pkg", "root": os.path.abspath(path), "components": info["components"], "scripts": info["scripts"],
           "plists": [], "binaries": [], "skipped": 0, "errors": info["errors"]}
    if "distribution" in info:
        out["distribution"] = info["distribution"]
    members = pkgxar._components(pkgxar.entries(path))
    with tempfile.TemporaryDirectory(prefix="rdis-pkg-") as tmp:
        for comp, files in members.items():
            if "Payload" not in files:
                continue
            try:
                cpio = pkgxar.cpio_members(pkgxar._decompress_payload(pkgxar.read_member(path, files["Payload"])))
            except pkgxar.PkgError as e:
                out["errors"].append(f"{comp}/Payload: {e}")
                continue
            for n, (name, mode, body) in enumerate(cpio):
                rel = name[2:] if name.startswith("./") else name
                if not pkgxar._is_file(mode) or not pkgxar._real(rel):
                    continue
                if os.path.basename(rel) == "Info.plist":
                    facts = _plist_facts(body[:4 << 20])
                    if facts:
                        out["plists"].append({"path": rel, **facts})
                if body[:4] in NATIVE or body[:2] == b"MZ":
                    dest = os.path.join(tmp, f"{n}-{re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(rel))[:60]}")
                    with open(dest, "wb") as fh:
                        fh.write(body)
                    os.chmod(dest, 0o700)
                    out["binaries"].append(_binary_row(dest, f"{comp + '/' if comp else ''}{rel}"))
    return out


def bundle_triage(path):
    """Triage a directory or flat package. Raises ValueError for anything that is neither."""
    if pkgxar.is_xar(path):
        try:
            out = _package(path)
        except pkgxar.PkgError as e:
            raise ValueError(f"unreadable package: {e}") from None
    elif os.path.isdir(path):
        out = _directory(path)
    else:
        raise ValueError("not a bundle or package")
    signed = [b for b in out["binaries"] if b["signature"].get("signed")]
    out["summary"] = {"binaries": len(out["binaries"]), "signed": len(signed),
                      "adhoc": sum(1 for b in signed if b["signature"].get("adhoc")),
                      "unsigned": sum(1 for b in out["binaries"] if b["signature"].get("signed") is False),
                      "with_entitlements": sum(1 for b in signed if b["signature"].get("entitlements")),
                      "permissions_requested": sorted({k for p in out["plists"] for k in p.get("usage", {})}),
                      "scripts": len(out.get("scripts", [])),
                      "scripts_with_findings": sum(1 for s in out.get("scripts", []) if s["findings"])}
    out["note"] = "Evidence from file contents and the system code-signing tool; none of it is a verdict about intent."
    return out
