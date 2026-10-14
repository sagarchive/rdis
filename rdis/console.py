"""Command console: the bottom command bar in the UI (Hopper has a Python bar there).

    goto main            rename 0x1000 init     comment main entry point
    xrefs _printf        find usage             findhex 55 48 89 e5 ??
    decompile main       procs net              strings http
    mark P 0x1000        bookmark main          info

`py <expr>` evaluates Python against the open document only when the server was started with
--allow-python (local use). It is off by default: on a shared/online server it would be remote
code execution.
"""
import re
import shlex

HELP = __doc__.split("\n\n")[1]


def find_bytes(prog, pattern, limit=200):
    """Addresses where a hex byte pattern occurs; `??` matches any byte."""
    toks = pattern.replace(",", " ").split()
    if not toks or any(not re.fullmatch(r"[0-9a-fA-F]{2}|\?\?", t) for t in toks):
        raise ValueError("pattern must be hex bytes like '55 48 89 e5' (?? = any byte)")
    rx = re.compile(b"".join(b"." if t == "??" else re.escape(bytes([int(t, 16)])) for t in toks), re.S)
    out = []
    for s in prog.image.sections:
        data = prog.image.read(s.va, s.size)
        for m in rx.finditer(data):
            out.append(s.va + m.start())
            if len(out) >= limit:
                return out
    return out


def run(prog, line, allow_python=False):
    """Execute one console line. Returns {'output': str, 'goto': '0x..'?}."""
    line = line.strip()
    if not line:
        return {"output": ""}
    if line.startswith("py "):
        if not allow_python:
            return {"output": "python is disabled on this server (start it with --allow-python)"}
        ns = {"prog": prog, "doc": prog, "image": prog.image}
        try:
            return {"output": repr(eval(line[3:], ns))}  # noqa: S307 - gated, local-only by flag
        except Exception as e:
            return {"output": f"{type(e).__name__}: {e}"}
    try:
        argv = shlex.split(line)
    except ValueError as e:
        return {"output": f"parse error: {e}"}
    cmd, args = argv[0].lower(), argv[1:]
    try:
        return _dispatch(prog, cmd, args)
    except (KeyError, ValueError, IndexError) as e:
        return {"output": f"{cmd}: {e}"}


def _dispatch(prog, cmd, args):
    from .decompile import Decompiler

    def need(n):
        if len(args) <= n:
            raise IndexError("missing argument")
        return args[n]
    if cmd in ("help", "?"):
        return {"output": HELP}
    if cmd in ("goto", "g"):
        a = prog.resolve(need(0))
        return {"output": f"-> {a:#x} {prog.display(a) or ''}".rstrip(), "goto": hex(a)}
    if cmd in ("rename", "n"):
        a = prog.resolve(need(0))
        prog.rename(a, need(1))
        return {"output": f"renamed {a:#x} -> {args[1]}", "changed": True}
    if cmd in ("comment", ";"):
        a = prog.resolve(need(0))
        prog.comment(a, " ".join(args[1:]))
        return {"output": f"comment at {a:#x}", "changed": True}
    if cmd in ("xrefs", "x"):
        a = prog.resolve(need(0))
        from .render import _ref_name
        refs = prog.xrefs_to(a)
        lines = [f"{s:#x}  {k:<5} {_ref_name(prog, s)}" for s, k in refs] or ["no references"]
        return {"output": "\n".join(lines)}
    if cmd in ("decompile", "d"):
        a = prog.resolve(need(0))
        f = prog.function_at(a)
        if f is None:
            raise ValueError(f"no procedure at {a:#x}")
        return {"output": Decompiler(prog, f).c()}
    if cmd == "find":
        q = need(0).lower()
        hits = [f"{a:#x}  {n}" for a, n in sorted(prog.names.items()) if q in (prog.display(a) or n).lower()]
        hits += [f"{a:#x}  \"{s[:70]}\"" for a, s in sorted(prog.strings().items()) if q in s.lower()]
        return {"output": "\n".join(hits[:300]) or "no matches"}
    if cmd == "findhex":
        from .render import _ref_name
        hits = find_bytes(prog, " ".join(args))
        return {"output": "\n".join(f"{a:#x}  {_ref_name(prog, a)}" for a in hits) or "no matches"}
    if cmd == "procs":
        q = (args[0] if args else "").lower()
        rows = [f"{a:#x}  {prog.display(a)}" for a in sorted(prog.functions) if q in (prog.display(a) or "").lower()]
        return {"output": "\n".join(rows[:500]) or "no procedures"}
    if cmd == "strings":
        q = (args[0] if args else "").lower()
        rows = [f"{a:#x}  {s[:90]!r}" for a, s in sorted(prog.strings().items()) if q in s.lower()]
        return {"output": "\n".join(rows[:500]) or "no strings"}
    if cmd == "mark":
        kind, a = need(0).upper(), prog.resolve(need(1))
        if kind == "P":
            prog.create_function(a)
        elif kind == "U":
            prog.remove_function(a)
            prog.set_type(a, None)
        elif kind in ("D", "A", "C"):
            prog.set_type(a, {"D": "data", "A": "ascii", "C": "code"}[kind])
            if kind == "C":
                prog.create_function(a)
        else:
            raise ValueError("kind must be D, A, C, P or U")
        return {"output": f"marked {a:#x} as {kind}", "changed": True, "goto": hex(a)}
    if cmd == "bookmark":
        a = prog.resolve(need(0))
        on = a not in prog.bookmarks
        prog.bookmark(a, on)
        return {"output": f"{'bookmarked' if on else 'removed bookmark'} {a:#x}", "changed": True}
    if cmd == "info":
        im = prog.image
        return {"output": f"{im.path}\n{im.format} {im.arch.name}  entry {im.entry:#x}  base {im.base:#x}\n"
                          f"{len(prog.functions)} procedures, {len(prog.strings())} strings, "
                          f"{len(im.imports)} imports"}
    raise ValueError(f"unknown command '{cmd}' (try: help)")
