"""What rdis can do, per CPU and per interface, as data. Levels are separate on purpose: decoding an
instruction, finding functions, building a CFG, lifting to an IR and producing C are different claims.
`verified` names the test module that backs a CPU's evidence; a CPU without one is implemented but unverified."""
from . import sleigh

_CAPSTONE = {
    "x86": ("Capstone", "tests/maturity.py"), "x86_64": ("Capstone", "tests/maturity.py"),
    "arm": ("Capstone", "tests/test_architecture_encodings.py"), "arm64": ("Capstone", "tests/maturity.py"),
    "mips": ("Capstone", "tests/test_ir_semantics.py"), "mipsel": ("Capstone", "tests/test_ir_semantics.py"),
    "mips64": ("Capstone", "tests/test_ir_semantics.py"), "mips64el": ("Capstone", "tests/test_ir_semantics.py"),
    "riscv32": ("Capstone", "tests/test_ir_semantics.py"), "riscv64": ("Capstone", "tests/test_ir_semantics.py"),
}
_FIXTURE_CPUS = {"ppc", "m68k", "avr8", "msp430", "sparc", "sh4", "z80", "6502", "xtensa", "ebpf", "loongarch64"}


def architectures():
    rows = [{"name": n, "engine": e, "decode": True, "discovery": True, "cfg": True, "ir": True, "decompile": True,
             "verified": v} for n, (e, v) in _CAPSTONE.items()]
    for name, spec in sleigh._SPECS.items():
        rows.append({"name": name, "engine": "SLEIGH (pypcode)", "language": spec[0], "decode": True, "discovery": True,
                     "cfg": True, "ir": True, "decompile": "experimental (P-code reading; no compiler-built corpus)",
                     "calling_convention": bool(spec[2]),
                     "verified": "tests/test_sleigh.py" if name in _FIXTURE_CPUS else None})
    return rows


def capabilities():
    return {
        "architectures": architectures(),
        "any_sleigh_language": {"syntax": "sleigh:<language id>", "count": len(sleigh.languages()),
                                "levels": ["decode", "discovery", "cfg", "ir"], "calling_convention": False},
        "formats": ["Mach-O (thin, fat)", "ELF", "PE", "WebAssembly (listing only)", "raw firmware", "APK/IPA/AAR/JAR/ZIP/TAR/DMG"],
        "interfaces": ["web UI", "CLI", "MCP (stdio)", "console", "plugins (API 1)"],
        "notes": "A level marked true is implemented; `verified` names the evidence. See FEATURE_SUPPORT_MATRIX.md.",
    }
