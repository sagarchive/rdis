"""Swift and C++ demangling through the system tools (swift-demangle, c++filt), batched."""
import shutil, subprocess


def _tool(name):
    if shutil.which(name):
        return [name]
    if shutil.which("xcrun"):
        r = subprocess.run(["xcrun", "--find", name], capture_output=True, text=True)
        if r.returncode == 0:
            return [r.stdout.strip()]
    return None


def _pipe(cmd, names):
    r = subprocess.run(cmd, input="\n".join(names) + "\n", capture_output=True, text=True, timeout=60)
    out = r.stdout.split("\n")
    return dict(zip(names, out)) if r.returncode == 0 and len(out) >= len(names) else {}


def demangle_all(names):
    """{mangled: readable} for every name a tool could improve. Missing tools are skipped."""
    names = sorted(set(names))
    swift = [n for n in names if n.lstrip("_").startswith(("$s", "$S", "T0", "Tt"))]
    cxx = [n for n in names if n.lstrip("_").startswith("Z")]
    out = {}
    tool = _tool("swift-demangle")
    if tool and swift:
        out.update(_pipe(tool + ["--simplified"], swift))
    tool = _tool("c++filt")
    if tool and cxx:
        # c++filt wants the Itanium form `_Z...`; Mach-O adds one more leading underscore.
        fixed = [n[1:] if n.startswith("__Z") else n for n in cxx]
        res = _pipe(tool, fixed)
        out.update({orig: res.get(f, orig) for orig, f in zip(cxx, fixed)})
    return {k: v for k, v in out.items() if v and v != k}
