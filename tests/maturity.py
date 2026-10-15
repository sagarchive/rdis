"""Decompiler maturity scoreboard: every case is compiled, decompiled, recompiled and executed.

    python tests/maturity.py [opt,simd,struct] [arm64,x86_64] [fn,...]

x86-64 cases run under Rosetta on Apple Silicon. Prints each failure and `SCORE ok/total`."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import diffcheck, maturity_cases as M

tiers = sys.argv[1].split(",") if len(sys.argv) > 1 else list(M.TIERS)
archs = sys.argv[2].split(",") if len(sys.argv) > 2 else ["arm64", "x86_64"]
only = set(sys.argv[3].split(",")) if len(sys.argv) > 3 else None
tot = ok = 0
for t in tiers:
    src, sup, cases, opts, vec = M.TIERS[t]
    for arch in archs:
        for opt in opts:
            for case in cases:
                if only and case[0] not in only:
                    continue
                probs = diffcheck.run(src, arch, [case], opt=opt, support=sup, vectorize=vec)
                tot += 1
                if probs:
                    print(f"FAIL {t:6} {arch:6} {opt} {case[0]:10} {probs[0][:230]}")
                else:
                    ok += 1
print(f"\nSCORE {ok}/{tot}")
if ok != tot:
    sys.exit(1)
