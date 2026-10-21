"""How often does rdis put a function's end past the next function start the file itself declares?

The oracle is the linker's own function-start table (LC_FUNCTION_STARTS and symbols), which rdis does not
decide. A function that runs over the next declared start is a boundary error: its CFG, decompiled body and
cross-references are wrong.

    python tests/boundary_check.py N_BINARIES [arch]      # system arm64 Mach-O binaries by default
"""
import bisect
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import lief

from rdis.analysis import Program
from rdis.loader import open_image

lief.logging.disable()


def main():
    limit = int(sys.argv[1])
    arch = sys.argv[2] if len(sys.argv) > 2 else "arm64"
    files = sorted(f for d in ("/usr/bin", "/bin", "/usr/sbin") for f in glob.glob(d + "/*")
                   if os.path.isfile(f) and not os.path.islink(f))
    functions = crossing = binaries = 0
    worst, started = [], time.time()
    for path in files:
        if binaries >= limit:
            break
        try:
            image = open_image(path, arch=arch)
            if image.arch.name != arch:
                continue
            prog = Program(image).analyze(objc=False, swift=False)
        except Exception:
            continue
        starts = sorted(a for a, n in image.symbols.items() if image.is_code(a))
        if len(starts) < 20:
            continue
        binaries += 1
        bad = 0
        for addr, func in prog.functions.items():
            k = bisect.bisect_right(starts, addr)
            if k < len(starts) and func.end > starts[k]:
                bad += 1
        functions += len(prog.functions)
        crossing += bad
        worst.append((bad, os.path.basename(path), len(prog.functions)))
    worst.sort(reverse=True)
    print(json.dumps({"binaries": binaries, "functions": functions, "functions_crossing_next_start": crossing,
                      "rate_percent": round(100 * crossing / max(1, functions), 2),
                      "seconds": round(time.time() - started), "worst": worst[:4]}))


if __name__ == "__main__":
    main()
