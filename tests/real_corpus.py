"""Real open-source programs built from pinned source, with function truth taken from `nm` on the unstripped build.

    python tests/real_corpus.py SOURCES_DIR WORKDIR

SOURCES_DIR holds sqlite/a.zip, lua/l.tgz and zlib/z.tgz; each is checked against the SHA-256 below before use.
Every program is built for arm64 and x86_64, once with the linker's function-start table and once without it,
because other tools may read that table too and the score must not depend on it silently.
"""
import hashlib
import os
import platform
import re
import subprocess
import sys
import tarfile
import zipfile

PINNED = {"sqlite/a.zip": "0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9",
          "lua/l.tgz": "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
          "zlib/z.tgz": "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"}
ARCHES = ("arm64", "x86_64")


def _verify(sources):
    for rel, digest in PINNED.items():
        with open(os.path.join(sources, rel), "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != digest:
                raise RuntimeError(f"{rel} does not match its pinned SHA-256")


def _extract(sources, work):
    with zipfile.ZipFile(os.path.join(sources, "sqlite/a.zip")) as z:
        z.extractall(work)
    for rel in ("lua/l.tgz", "zlib/z.tgz"):
        with tarfile.open(os.path.join(sources, rel)) as t:
            t.extractall(work, filter="data")


def _find(work, prefix):
    return os.path.join(work, next(d for d in sorted(os.listdir(work)) if d.startswith(prefix)))


def program_sources(work):
    sq, lua, zl = _find(work, "sqlite-amalgamation"), _find(work, "lua-"), _find(work, "zlib-")
    lua_c = [os.path.join(lua, "src", f) for f in sorted(os.listdir(os.path.join(lua, "src"))) if f.endswith(".c") and f != "luac.c"]
    zl_c = [os.path.join(zl, f) for f in sorted(os.listdir(zl)) if f.endswith(".c")] + [os.path.join(zl, "test", "example.c")]
    return {"sqlite": ([os.path.join(sq, "sqlite3.c"), os.path.join(sq, "shell.c")], ["-DSQLITE_THREADSAFE=0", "-DSQLITE_OMIT_LOAD_EXTENSION"], [sq]),
            "lua": (lua_c, ["-DLUA_USE_MACOSX"], [os.path.join(lua, "src")]),
            "zlib": (zl_c, ["-DHAVE_UNISTD_H", "-DHAVE_STDARG_H"], [zl])}


def nm_truth(path):
    out = subprocess.run(["nm", "-n", "-s", "__TEXT", "__text", path], capture_output=True, text=True, check=True).stdout
    truth = set()
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+) ([tT]) (\S+)$", line)
        if m and not m.group(3).startswith(("ltmp", "L", "l_")):
            truth.add(int(m.group(1), 16))
    return truth


def build(sources, work):
    """Yield dicts: name, stripped path, truth set, arch, function_starts flag."""
    if platform.system() != "Darwin":
        return
    _verify(sources)
    _extract(sources, work)
    for prog, (files, flags, includes) in program_sources(work).items():
        for arch in ARCHES:
            full = os.path.join(work, f"{prog}-{arch}.full")
            cmd = ["clang", "-O2", "-arch", arch, "-w", *flags, *[f"-I{i}" for i in includes], *files, "-o", full, "-lm"]
            if prog == "sqlite":
                cmd += ["-lz"]
            if subprocess.run(cmd, capture_output=True).returncode != 0:
                continue
            truth = nm_truth(full)
            for fs in (True, False):
                variant = full + ("" if fs else ".nofs")
                if not fs:
                    relink = [c for c in cmd if c != full] + ["-Wl,-no_function_starts"]
                    if subprocess.run([*relink, "-o", variant], capture_output=True).returncode != 0:
                        continue
                    truth_v = nm_truth(variant)
                else:
                    truth_v = truth
                stripped = variant + ".stripped"
                subprocess.run(["strip", "-o", stripped, variant], capture_output=True, check=True)
                yield {"name": f"{prog}-{arch}-{'fs' if fs else 'nofs'}", "stripped": stripped, "truth": truth_v}


if __name__ == "__main__":
    for e in build(sys.argv[1], sys.argv[2]):
        print(e["name"], len(e["truth"]), e["stripped"])
