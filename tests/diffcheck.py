"""Differential verification of the decompiler: does the pseudo-code *compute the same thing*?

For each function: compile the original C, decompile it with rdis, compile the decompiled C back
with clang next to the original, run both on test vectors, and report every input where they
disagree. A compile error in the decompiled code is also a failure -- the output must be valid C.

    run(src, arch, cases)  ->  list of problem strings (empty = verified)

`cases` is a list of (function, return C type, [argument tuples as C expressions]). x86-64 binaries
run under Rosetta on Apple Silicon; skipped automatically when it is unavailable.
"""
import os, re, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler

PRELUDE = """#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
typedef void *id;
typedef void *SEL;
"""


def _runner(arch):
    if arch == "x86_64" and os.uname().machine == "arm64":
        ok = subprocess.run(["arch", "-x86_64", "/usr/bin/true"], capture_output=True).returncode == 0
        return ["arch", "-x86_64"] if ok else None
    return []


def decompiled(prog, name, newname):
    """Decompiled C for `name`, renamed to `newname` so it can sit next to the original."""
    a = prog.resolve(name)
    text = Decompiler(prog, prog.functions[a]).c()
    shown = prog.display(a)
    # the signature is the line with the function name and an opening brace; recovered lookup
    # tables (static const arrays) may precede it, so rename that line, not line 0.
    lines = text.split("\n")
    for n, ln in enumerate(lines):
        if f" {shown}(" in ln and ln.rstrip().endswith("{"):
            lines[n] = ln.replace(f" {shown}(", f" {newname}(", 1)
            break
    return "\n".join(lines)


def run(src, arch, cases, opt="-O1", support="", vectorize=False):
    tmp = tempfile.mkdtemp(prefix="rdis_diff_")
    cfile = os.path.join(tmp, "orig.c")
    open(cfile, "w").write(src + ("\nint main(void){return 0;}\n" if "main(" not in src else ""))
    binary = os.path.join(tmp, "orig")
    # auto-vectorized loops lift to NEON/SSE intrinsics, which are checked by shape elsewhere;
    # executing them would need lane-accurate vector types, so the differential build is scalar
    novec = [] if vectorize else ["-fno-vectorize", "-fno-slp-vectorize"]
    r = subprocess.run(["clang", opt, *novec, "-arch", arch, "-w", cfile, "-o", binary], capture_output=True, text=True)
    if r.returncode:
        return [f"original did not compile: {r.stderr[:300]}"]
    runner = _runner(arch)
    if runner is None:
        return []  # cannot execute this architecture here
    prog = Program(open_image(binary)).analyze()
    body = re.sub(r"int main\s*\([^)]*\)\s*\{.*", "", src, flags=re.S)  # original functions only
    decs, calls = [], []
    for fn, rtype, argsets in cases:
        try:
            decs.append(decompiled(prog, "_" + fn, "dec_" + fn))
        except Exception as e:
            return [f"{fn}: decompiler raised {type(e).__name__}: {e}"]
        for args in argsets:
            a = ", ".join(args)
            shown = a.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")  # safe inside printf
            calls.append(f'fprintf(stderr, "CALL {fn}({shown})\\n");')  # pinpoints a crashing case
            if rtype in ("double", "float"):
                calls.append(f'{{ double o = {fn}({a}), d = ({rtype})dec_{fn}({a});'
                             f' if (!(fabs(o - d) <= 1e-9 * (1 + fabs(o)))) printf("MISMATCH {fn}({shown}) orig=%g dec=%g\\n", o, d); }}')
            else:
                calls.append(f'{{ long long o = ({rtype}){fn}({a}), d = ({rtype})dec_{fn}({a});'
                             f' if (o != d) printf("MISMATCH {fn}({shown}) orig=%lld dec=%lld\\n", o, d); }}')
    # support (test data) goes after the original source so it can use the source's own types
    harness = PRELUDE + body + "\n" + support + "\n" + "\n\n".join(decs) + \
        "\n\nint main(void) {\n" + "\n".join("    " + c for c in calls) + '\n    printf("DONE\\n");\n    return 0;\n}\n'
    hfile = os.path.join(tmp, "harness.c")
    open(hfile, "w").write(harness)
    hbin = os.path.join(tmp, "harness")
    # pointer <-> integer variable conversions are value-preserving on these 64-bit targets; let
    # them through as warnings so the check measures what the code computes, not type precision
    relax = ["-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types",
             "-Wno-error=int-to-pointer-cast", "-Wno-error=pointer-to-int-cast"]
    r = subprocess.run(["clang", "-O0", "-arch", arch, "-w", "-fwrapv", *relax, hfile, "-o", hbin, "-lm"],
                       capture_output=True, text=True)
    if r.returncode:
        errs = [ln for ln in r.stderr.splitlines() if "error:" in ln][:6]
        lines = harness.splitlines()
        context = []
        for err in errs:
            m = re.search(r":(\d+):\d+: error:", err)
            if not m:
                continue
            line_no = int(m.group(1))
            # Attribute a compiler diagnostic to the generated decompiler function, not only a
            # temporary file line number. This makes semantic regressions actionable in CI.
            owner = next((lines[i].strip() for i in range(min(line_no - 1, len(lines) - 1), -1, -1)
                          if re.search(r"\bdec_[A-Za-z0-9_]+\s*\(", lines[i])
                          and lines[i].rstrip().endswith("{")), "unknown generated function")
            context.append(f"{owner} (harness line {line_no})")
        detail = " | ".join(errs)
        if context:
            detail += " | generated function(s): " + ", ".join(dict.fromkeys(context))
            match = re.search(r"\b(dec_[A-Za-z0-9_]+)\s*\(", context[0])
            if match:
                fn_name = match.group(1)
                generated = next((d for d in decs
                                  if re.search(rf"\b{re.escape(fn_name)}\s*\(", d)), "")
                if generated:
                    detail += " | decompiled body: " + generated.replace("\n", " ; ")[:2200]
                try:
                    addr = prog.resolve("_" + fn_name[4:])
                    func = prog.functions.get(addr)
                    if func:
                        asm = "; ".join(f"{ins.address:#x} {ins.mnemonic} {ins.op_str}"
                                        for block in func.blocks.values() for ins in block.insns)
                        detail += " | original instructions: " + asm[:2600]
                except Exception:
                    pass
        return [f"decompiled C did not compile ({arch}): " + detail + f"  [{hfile}]"]
    r = subprocess.run(runner + [hbin], capture_output=True, text=True, timeout=8)
    out = r.stdout.splitlines()
    if "DONE" not in out:
        last = [ln for ln in r.stderr.splitlines() if ln.startswith("CALL ")][-1:] or ["?"]
        return [f"harness crashed ({arch}, rc={r.returncode}) in {last[0][5:]}  [{hfile}]"]
    mismatches = [ln for ln in out if ln.startswith("MISMATCH")]
    detailed = []
    for line in mismatches:
        match = re.match(r"MISMATCH\s+([A-Za-z0-9_]+)\(", line)
        if match:
            fn_name = "dec_" + match.group(1)
            generated = next((d for d in decs
                              if re.search(rf"\b{re.escape(fn_name)}\s*\(", d)), "")
            if generated:
                line += " | decompiled body: " + generated.replace("\n", " ; ")[:1500]
        detailed.append(line)
    return detailed
