"""Evidence-based binary triage: entropy, packing indicators, runtime identification, import and string facts.

Every finding names the evidence it rests on, and none is a verdict: a high-entropy executable section is
consistent with packing, and equally with embedded compressed or encrypted data. Nothing here says a
file is malicious.
"""
import math
import os

import lief

from .loader import open_image

ENTROPY_HIGH = 7.2          # bits per byte; compressed or encrypted data sits near 8, code and text far below
SAMPLE = 1 << 20            # bytes sampled from the start, middle and end of a large section
FEW_IMPORTS = 12
PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
                   ".petite": "Petite", ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
                   ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack", ".enigma1": "Enigma"}
RUNTIMES = (
    ("Go", (b"Go build ID", b"runtime.main", b"go.buildid", b"\xff Go buildinf:")),
    ("Rust", (b"rustc/", b"core::panicking", b"/rustc/", b"RUST_BACKTRACE")),
    ("Swift", (b"__swift5_", b"swift_retain", b"libswiftCore")),
    ("Objective-C", (b"__objc_classlist", b"objc_msgSend", b"__objc_methname")),
    ("Qt", (b"libQt", b"Qt5Core", b"Qt6Core", b"QtCore", b"_ZN7QObject")),
    ("Electron / Chromium", (b"Electron Framework", b"ELECTRON_RUN_AS_NODE", b"libffmpeg")),
    ("Flutter", (b"libflutter", b"FlutterEngine", b"io.flutter")),
    ("Unity / IL2CPP", (b"UnityPlayer", b"il2cpp_", b"libil2cpp")),
    ("Java VM", (b"JNI_CreateJavaVM", b"libjvm")),
    ("Bun", (b"Bun v", b"bun:main", b"BUN_RUNTIME")),
    ("Node.js / V8", (b"node::", b"NODE_OPTIONS", b"v8::internal")),
    ("Python (frozen)", (b"PyInstaller", b"_MEIPASS", b"Py_Initialize")),
    ("Dart AOT", (b"dart::", b"_kDartVmSnapshot", b"DartVM")),
    ("GCC", (b"GCC: (",)),
    ("Clang / LLVM", (b"clang version", b"Apple clang version")),
    (".NET", (b"BSJB", b"mscoree.dll", b"_CorExeMain")),
)


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in (data.count(bytes([b])) for b in range(256)) if c)


def _sample(read, va, size):
    if size <= 3 * SAMPLE:
        return read(va, size)
    return b"".join(read(va + off, SAMPLE) for off in (0, size // 2 - SAMPLE // 2, size - SAMPLE))


def _permissions(path):
    """Names of segments that are both writable and executable."""
    try:
        binary = lief.parse(path)
        if isinstance(binary, lief.ELF.Binary):
            return [str(s.type).split(".")[-1] for s in binary.segments if int(s.flags) & 1 and int(s.flags) & 2]
        if isinstance(binary, lief.PE.Binary):
            return [s.name for s in binary.sections if s.characteristics & 0x20000000 and s.characteristics & 0x80000000]
        fat = lief.MachO.parse(path)
        return [s.name for b in fat for s in b.segments if s.init_protection & 2 and s.init_protection & 4]
    except Exception:
        return []


def triage(path, arch=None):
    from . import bundle
    if bundle.is_bundle(path):
        return bundle.bundle_triage(path)
    image = open_image(path, arch=arch)
    sections, indicators = [], []
    for s in image.sections:
        data = _sample(image.read, s.va, s.size)
        sections.append({"name": s.name, "address": hex(s.va), "size": s.size, "executable": s.code,
                         "entropy": round(entropy(data), 3), "sampled": s.size > 3 * SAMPLE})
    for s in sections:
        if s["size"] >= 512 and s["entropy"] >= ENTROPY_HIGH:
            kind = "executable section" if s["executable"] else "section"
            indicators.append({"indicator": f"high-entropy {kind}", "severity": "notable" if s["executable"] else "informational",
                               "section": s["name"], "entropy": s["entropy"],
                               "evidence": f"{s['name']} has {s['entropy']} bits/byte over {s['size']} bytes (threshold {ENTROPY_HIGH})",
                               "consistent_with": ["packing", "encryption", "embedded compressed data"]})
    for s in image.sections:
        packer = PACKER_SECTIONS.get(s.name.lower())
        if packer:
            indicators.append({"indicator": "packer section name", "severity": "notable", "section": s.name, "evidence": f"section {s.name!r} is "
                               f"named like {packer}'s", "consistent_with": [packer]})
    code = [s for s in image.sections if s.code]
    if code and not any(s.va <= image.entry < s.va + s.size for s in code):
        indicators.append({"indicator": "entry point outside executable sections", "severity": "notable", "evidence": f"entry {image.entry:#x} "
                           "is not inside any executable section", "consistent_with": ["packing", "a stub", "a custom loader"]})
    if image.format != "raw" and len(image.imports) < FEW_IMPORTS and any(i["indicator"] == "high-entropy executable section" for i in indicators):
        indicators.append({"indicator": "few imports with high-entropy data", "severity": "notable", "evidence": f"{len(image.imports)} imports "
                           "alongside a high-entropy section", "consistent_with": ["packing"]})
    rwx = _permissions(path)
    if rwx:
        indicators.append({"indicator": "writable and executable segment", "severity": "notable", "evidence": f"segments {rwx} are both writable and executable",
                           "consistent_with": ["self-modifying code", "a packer", "a JIT"]})
    blob = b"".join(_sample(image.read, s.va, s.size) for s in image.sections if s.size)
    runtimes = [{"runtime": name, "evidence": [m.decode("latin-1") for m in markers if m in blob]}
                for name, markers in RUNTIMES]
    # Add Go build-info details to Go evidence
    go_detail = None
    try:
        from .gobin import read_build_info
        go_detail = read_build_info(path, image)
    except Exception:
        pass
    if go_detail:
        for r in runtimes:
            if r["runtime"] == "Go" and go_detail:
                r["go_version"] = go_detail.get("go_version")
                r["main_module"] = go_detail.get("path")
                r["dependencies"] = [d["path"] for d in go_detail.get("deps", [])]
                break
    return {
        "file": os.path.basename(path), "bytes": os.path.getsize(path), "format": image.format, "arch": image.arch.name,
        "entry": hex(image.entry), "sections": sections,
        "overall_entropy": round(entropy(blob[:4 * SAMPLE]), 3),
        "indicators": indicators,
        "runtimes": [r for r in runtimes if r["evidence"]],
        "imports": {"count": len(image.imports), "sample": sorted(set(image.imports.values()))[:10]},
        "note": "Indicators are evidence, not verdicts. They are consistent with the listed causes and do not show "
                "that a file is malicious.",
    }
