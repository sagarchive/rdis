"""How often does decompiled output contain goto? Structural fidelity metric (see Basque et al., SAILR, USENIX Security 2024).

    python tests/goto_check.py arm64|x86_64 N_BINARIES FUNCS_PER_BINARY
"""
import sys, glob, random, re, os, collections, json, time
sys.path.insert(0, ".")
import lief; lief.logging.disable()
from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler
arch, nb, per = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
bins = sorted(glob.glob("/usr/bin/*")); random.Random(3).shuffle(bins)
fn = withgoto = gotos = lines_total = done = 0; sizes = collections.Counter(); t0 = time.time()
bysize = {"small(<20 lines)": [0, 0], "medium(20-80)": [0, 0], "large(>80)": [0, 0]}
for b in bins:
    if done >= nb: break
    try: p = Program(open_image(b, arch=arch)).analyze(objc=False, swift=False)
    except Exception: continue
    if p.arch.name != arch: continue
    done += 1
    fs = sorted(p.functions); random.Random(1).shuffle(fs)
    for a in fs[:per]:
        try: c = Decompiler(p, p.functions[a]).c()
        except Exception: continue
        n = len(c.splitlines()); g = len(re.findall(r"\bgoto\b", c))
        fn += 1; gotos += g; withgoto += g > 0; lines_total += n
        k = "small(<20 lines)" if n < 20 else "medium(20-80)" if n <= 80 else "large(>80)"
        bysize[k][0] += 1; bysize[k][1] += g > 0
print(json.dumps({"arch": arch, "binaries": done, "functions": fn, "with_goto": withgoto, "pct_with_goto": round(100*withgoto/fn, 1),
                  "gotos_total": gotos, "gotos_per_100_lines": round(100*gotos/lines_total, 2),
                  "by_size": {k: f"{v[1]}/{v[0]} ({100*v[1]/max(1,v[0]):.0f}%)" for k, v in bysize.items()}, "seconds": round(time.time()-t0)}))
