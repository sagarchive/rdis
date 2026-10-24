"""Persistent analysis database: reopen a big binary in seconds instead of re-analyzing it.

The cache is content-addressed (sha256 of the file + analysis options + a hash of the analysis
code itself, so an upgrade invalidates stale results) and stored as gzip JSON — never pickle, so a
planted cache file cannot run code. It holds the analysis *results* (functions, blocks, xrefs,
names, ARM modes, recovered tables) but not instructions: restored blocks decode lazily the first
time a function is viewed, which keeps the file small and the restore fast.

User edits (renames, comments, ...) are not here; they live in the per-binary `.rdb` sidecar.
"""
import gzip, hashlib, json, os, threading, time

from .analysis import Function, LazyBlock, Program
from .demangle import demangle_all
from .objc import ObjC
from .swift import Swift

FORMAT = 1
MIN_SECONDS = 1.5   # analyses faster than this re-run quicker than a cache read; don't store them
_KINDS = ["call", "jmp", "tail", "data"]


def _code_hash():
    h = hashlib.sha1(str(FORMAT).encode())
    here = os.path.dirname(__file__)
    # Cached Program snapshots include discovered functions/names/metadata. Changes to any
    # module that influences those results must invalidate the persistent snapshot.
    for m in ("analysis.py", "arch.py", "loader.py", "raw.py", "jni.py", "objc.py",
              "swift.py", "demangle.py", "typelib.py", "plugins.py", "cache.py", "gobin.py"):
        with open(os.path.join(here, m), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:12]


def _key(path, opts):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    h.update(json.dumps(opts, sort_keys=True).encode())
    return f"{h.hexdigest()[:32]}-{_code_hash()}"


def _dir():
    return os.environ.get("RDIS_CACHE_DIR", os.path.join(os.getcwd(), ".rdis_cache"))


def _thumb_of(prog, b):
    if isinstance(b, LazyBlock):
        return b._thumb
    if prog.arch.name != "arm" or not b.insns:
        return False
    return prog._insns.get((b.addr, True)) is b.insns[0]


def _snapshot(prog):
    funcs = []
    for f in prog.functions.values():
        blocks = []
        for b in f.blocks.values():
            d = b.delay
            blocks.append([b.addr, b.end, b.succs, d.address if d is not None else 0,
                           int(_thumb_of(prog, b))])
        funcs.append([f.addr, sorted(f.calls), blocks])
    xr = []
    for t, refs in prog.xrefs.items():
        if t is None:
            continue
        for src, k in refs:
            xr += [t, src, _KINDS.index(k)]
    return {
        "format": FORMAT,
        "names": [[a, n] for a, n in prog.names.items()],
        "tmode": [[a, int(v)] for a, v in prog._tmode.items()],
        "functions": funcs,
        "xrefs": xr,
        "value_tables": [[a, list(v)] for a, v in prog.value_tables.items()],
        "jump_tables": [[a, jt["base"], [[c, t] for c, t in jt["cases"].items()], jt.get("index")]
                        for a, jt in prog.jump_tables.items()],
        "jni": [[a, *v] for a, v in prog.jni_natives.items()],
    }


def _restore(image, data, objc, swift):
    p = Program(image)
    p._name_plt_stubs()                  # also fills image.imports with PLT stub names
    p.objc = ObjC(image) if objc else ObjC.empty(image)
    p.swift = Swift(image) if swift else Swift.empty(image)
    p.names = {a: n for a, n in data["names"]}
    p._tmode = {a: bool(v) for a, v in data["tmode"]}
    for fa, calls, blocks in data["functions"]:
        bl = {a: LazyBlock(p, a, end, succs, ds, bool(th)) for a, end, succs, ds, th in blocks}
        p.functions[fa] = Function(fa, bl, set(calls))
    xr = data["xrefs"]
    for n in range(0, len(xr), 3):
        p.xrefs[xr[n]].add((xr[n + 1], _KINDS[xr[n + 2]]))
    p.value_tables = {a: tuple(v) for a, v in data["value_tables"]}
    p.jump_tables = {a: {"base": base, "cases": {c: t for c, t in cases}, "index": idx}
                     for a, base, cases, idx in data["jump_tables"]}
    p.jni_natives = {a: (n, s, bool(t)) for a, n, s, t in data["jni"]}
    for a, (_, _, thumb) in p.jni_natives.items():
        if thumb:
            image.thumb.add(a)
    p.pretty = demangle_all(p.names.values())
    return p


def analyze(image, objc=True, swift=True, prologues=True, store=True):
    """Program(image).analyze(...), served from / saved to the analysis cache when possible."""
    opts = {"objc": objc, "swift": swift, "prologues": prologues, "arch": image.arch.name,
            "base": image.base, "entry": image.entry, "format": image.format}
    path = None
    try:
        path = os.path.join(_dir(), _key(image.path, opts) + ".json.gz")
        if os.path.exists(path):
            with gzip.open(path, "rt") as f:
                data = json.load(f)
            if data.get("format") == FORMAT:
                return _restore(image, data, objc, swift)
    except Exception:                     # unreadable/corrupt cache (truncated gzip -> EOFError, a
        pass                              # non-dict JSON -> AttributeError, ...): re-analyze
    t = time.time()
    prog = Program(image).analyze(objc=objc, swift=swift, prologues=prologues)
    # Apply Go function names recovered from the gopclntab (no-op for non-Go binaries,
    # never raises). Done here, after discovery, so stripped Go binaries expose real
    # names (e.g. main.main) in list_functions/decompile for both the CLI and MCP paths.
    try:
        from .gobin import apply_go_names
        apply_go_names(prog, image.path)
    except Exception:
        pass
    if store and path and time.time() - t >= MIN_SECONDS:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # per-thread temp: two server threads storing the same key must not interleave one file
            tmp = path + f".{os.getpid()}.{threading.get_ident()}.tmp"
            try:
                with gzip.open(tmp, "wt", compresslevel=3) as f:
                    json.dump(_snapshot(prog), f, separators=(",", ":"))
                os.replace(tmp, path)     # atomic: a concurrent reader never sees a partial file
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        except Exception:                 # failing to store must never lose a finished analysis
            pass
    return prog
