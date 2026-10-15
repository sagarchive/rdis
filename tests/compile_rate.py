"""Real-world compile rate: decompile functions from the system's own binaries (/usr/bin) and check
that the C compiles (clang -fsyntax-only). External symbols a real build would get from headers
are declared generically; registers leaking as names (sp, fp, lr, cond) count as failures.

    python tests/compile_rate.py arm64|x86_64 N_BINARIES FUNCS_PER_BINARY
"""
import sys, glob, random, subprocess, tempfile, collections, re
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler

arch, nb, per = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PRE = ("#include <stdint.h>\n#include <string.h>\n#include <math.h>\ntypedef void *id; typedef void *SEL;\n"
       "typedef int64_t (*code)();\n")
FLAGS = ["-fsyntax-only", "-w", "-std=gnu11", "-Wno-error=implicit-function-declaration",
         "-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types",
         "-Wno-error=int-to-pointer-cast", "-Wno-error=pointer-to-int-cast", "-Wno-error=return-type"]
bins = sorted(glob.glob("/usr/bin/*"))
random.Random(3).shuffle(bins)
ok = tot = crash = 0
errs, ex, samples, undecl = collections.Counter(), {}, {}, collections.Counter()
tmp = tempfile.mkdtemp()
done = 0
for b in bins:
    if done >= nb:
        break
    try:
        p = Program(open_image(b, arch=arch)).analyze()
    except Exception:
        continue
    if p.arch.name != arch:
        continue
    done += 1
    fs = sorted(p.functions)
    random.Random(1).shuffle(fs)
    for a in fs[:per]:
        tot += 1
        try:
            c = Decompiler(p, p.functions[a]).c()
        except Exception as e:
            crash += 1
            errs[f"CRASH {type(e).__name__}"] += 1
            continue
        # undeclared globals/functions referenced by name: declare them generically
        names = set(re.findall(r"\b((?:sub|loc|data|off|_\w)[\w$.]*)\b", c)) - {"_vtbl1", "__int128"}
        decl = "".join(f"extern char {n}[];\n" for n in names if not re.search(rf"\b{re.escape(n)}\s*\(", c)
                       and re.fullmatch(r"[A-Za-z_$][\w$]*", n))
        if re.search(r"\[[\w()* ]+ \w+(:|\])|@\"", c):     # ObjC: forward-declare receiver classes
            decl += "".join(f"@class {k};\n" for k in set(re.findall(r"\[([A-Z]\w+) ", c)))
        called = set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", c))
        own = {m.group(1) for m in re.finditer(r"^\S.*?\b([A-Za-z_$][\w$]*)\(.*\{$", c, re.M)}
        decl += "".join(f"extern int64_t {n}();\n" for n in names if n in called and n.startswith("sub_")
                        and n not in own)
        f = f"{tmp}/f.c"
        open(f, "w").write(PRE + decl + c + "\n")
        objc = bool(re.search(r"\[[\w()* ]+ \w+(:|\])|@\"", c))      # ObjC message / NSString syntax
        REAL = {"cond", "fp", "sp", "lr"}      # registers leaking as names are decompiler bugs, not externs
        for _ in range(3):                      # externals a real build gets from headers
            r = subprocess.run(["clang", "-arch", arch, *FLAGS, *(["-x", "objective-c"] if objc else []), f],
                               capture_output=True, text=True)
            miss = set(re.findall(r"use of undeclared identifier '([A-Za-z_$][\w$]*)'", r.stderr)) - REAL
            if r.returncode == 0 or not miss:
                break
            src = open(f).read()
            open(f, "w").write("".join(f"extern char {n}[];\n" for n in miss) + src)
        if r.returncode == 0:
            ok += 1
        else:
            e = next((l.split("error:")[1].strip() for l in r.stderr.splitlines() if "error:" in l), "?")
            k = re.sub(r"'[^']*'", "'X'", e)[:80]
            mu = re.match(r"use of undeclared identifier '([^']+)'", e)
            if mu:
                undecl[re.sub(r"_\d+$|\d+$", "N", mu.group(1))] += 1
            errs[k] += 1
            ex.setdefault(k, (b, hex(a)))
            ln = next((l for l in r.stderr.splitlines() if "error:" in l), "")
            try:
                no = int(ln.split(":")[1]); src = open(f).read().split("\n")[no - 1].strip()
            except Exception:
                src = "?"
            samples.setdefault(k, []).append((e[:90] + f"   [{b.split('/')[-1]} {a:#x}]", src[:170]))
print(f"{arch}: {done} binaries, {tot} functions: compile {ok}/{tot} = {100 * ok / max(tot, 1):.1f}%, crashes {crash}")
for k, n in errs.most_common(12):
    print(f"  {n:4}  {k}")
    for e, src in samples.get(k, [])[:3]:
        print(f"          {e}\n            >> {src}")
print("undeclared identifiers:", undecl.most_common(15))
