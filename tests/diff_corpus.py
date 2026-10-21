"""Two builds of a small C program with known function correspondence, for scoring binary diffing.

v2 modifies 5 functions, deletes 3, adds 3 and emits every function in reverse order, so addresses all
move. Ground truth is the symbol table of the unstripped builds; the matcher only ever sees the stripped ones.
"""
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

COUNT = 36
MODIFIED = (3, 8, 14, 21, 30)
DELETED = (5, 17, 25)
ADDED = (100, 101, 102)
CALLEES = [i for i in range(COUNT) if i not in DELETED and i not in MODIFIED]


def _consts(n, bump=0):
    return 17 + 13 * n + bump, 3 + 7 * n % 29 + bump, 101 + 31 * n + bump


def _body(n, bump=0):
    k1, k2, k3 = _consts(n, bump)
    kind = n % 6
    if kind == 0:
        return (f"int fn_{n}(int n) {{ int s = {k1}; for (int i = 0; i < n; i++) {{ s += i * {k2}; "
                f"if (s > {k3}) s -= {k3}; }} return s; }}")
    if kind == 1:
        return (f"int fn_{n}(int x) {{ if (x < {k1}) return x * {k2}; else if (x < {k3}) return x + {k2}; "
                f"else if (x & 1) return x ^ {k1}; return x - {k3}; }}")
    if kind == 2:
        return (f"int fn_{n}(int x) {{ switch (x & 7) {{ case 0: return {k1}; case 1: return {k2} + x; "
                f"case 2: return x * {k3}; case 3: return x >> 1; case 4: return {k1} ^ x; case 5: return x - {k2}; "
                f"default: return 0; }} }}")
    if kind == 3:
        return (f"unsigned fn_{n}(unsigned h) {{ h ^= h >> 15; h *= {k1}u; h ^= h >> 13; h *= {k2}u; "
                f"h ^= h >> 16; return h + {k3}u; }}")
    if kind == 4:
        return (f'int fn_{n}(const char *s) {{ printf("fn_{n} saw %s with {k1}\\n", s); '
                f"return (int)strlen(s) + {k2}; }}")
    a, b = CALLEES[(n * 3) % len(CALLEES)], CALLEES[(n * 5 + 1) % len(CALLEES)]
    return (f"int fn_{n}(int x) {{ return fn_{a}_w(x + {k1}) + fn_{b}_w(x ^ {k2}); }}")


def _signature(n):
    kind = n % 6
    if kind == 3:
        return f"unsigned fn_{n}(unsigned h)"
    if kind == 4:
        return f"int fn_{n}(const char *s)"
    return f"int fn_{n}(int x)"


def _wrappers():
    out = []
    for n in CALLEES:
        if n % 6 in (0, 1, 2):
            out.append(f"static int fn_{n}_w(int x) {{ return fn_{n}(x); }}")
        elif n % 6 == 3:
            out.append(f"static int fn_{n}_w(int x) {{ return (int)fn_{n}((unsigned)x); }}")
        elif n % 6 == 4:
            out.append(f'static int fn_{n}_w(int x) {{ return fn_{n}(x > 0 ? "p" : "n"); }}')
        else:
            out.append(f"static int fn_{n}_w(int x) {{ return fn_{n}(x); }}")
    return out


def source(version):
    numbers = [n for n in range(COUNT) if version == 1 or n not in DELETED]
    if version == 2:
        numbers += list(ADDED)
    defs = {n: _body(n, bump=5 if version == 2 and n in MODIFIED else 0) for n in numbers}
    head = "#include <stdio.h>\n#include <string.h>\n"
    protos = "".join(f"static int fn_{n}_w(int x);\n" for n in CALLEES if n in numbers)
    protos += "".join(f"{_signature(n)};\n" for n in numbers)
    order = sorted(numbers, reverse=version == 2)
    body = "\n".join(f"__attribute__((noinline, used)) {defs[n]}" for n in order)
    wrappers = "\n".join(w for w in _wrappers() if int(w.split("fn_")[1].split("_w")[0]) in numbers)
    table = ", ".join(f"(void *)fn_{n}" for n in numbers)
    return (f"{head}{protos}\n{wrappers}\n{body}\n"
            f"static void *volatile table[] = {{ {table} }};\n"
            "int main(int argc, char **argv) { return argc > 99 ? ((int (*)(int))table[argc % "
            f"{len(numbers)}])(argc) : 0; }}\n")


def strip_command(path):
    return ["strip", path] if platform.system() == "Darwin" else ["strip", "--strip-all", path]


def build(workdir, version, opt="-O1"):
    """(unstripped path, stripped path) for one version, or None when no C compiler is available."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc or not shutil.which("strip"):
        return None
    workdir = Path(workdir)
    src = workdir / f"v{version}.c"
    src.write_text(source(version))
    full, stripped = workdir / f"v{version}-{opt[1:]}", workdir / f"v{version}-{opt[1:]}.stripped"
    flags = [opt, "-fno-inline", "-fno-stack-protector"]
    if platform.system() != "Darwin":
        flags += ["-fno-pie", "-no-pie"]
    subprocess.run([cc, *flags, str(src), "-o", str(full)], check=True, capture_output=True)
    shutil.copy(full, stripped)
    subprocess.run(strip_command(str(stripped)), check=True, capture_output=True)
    return full, stripped
