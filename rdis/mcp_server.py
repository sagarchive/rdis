"""MCP server for rdis over stdio JSON-RPC 2.0 -- no third-party deps.

Lets an AI agent (REA, Claude Desktop, etc.) drive the disassembler: open a binary, list
functions, disassemble, decompile, read strings/imports/classes, find cross-references.

Run:  python -m rdis.mcp_server
Register in an MCP client as command `python` args `["-m","rdis.mcp_server"]` (cwd = this repo),
or wrap with the venv's python. One binary is held open per session, keyed by path.
"""
import hashlib, json, os, sys
from collections import OrderedDict

from .loader import open_image
from .analysis import Program
from . import cache, render
from .decompile import Decompiler

_CACHE = OrderedDict()  # bounded LRU: (path, content fingerprint, options) -> Program
_CACHE_MAX = 8


def _prog(path, arch=None, loader=None, base=None):
    absolute = os.path.abspath(path)
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    stat = os.stat(path)
    key = (absolute, stat.st_size, stat.st_mtime_ns, digest.hexdigest(), arch, loader, base)
    if key in _CACHE:
        _CACHE.move_to_end(key)
        return _CACHE[key]
    opts = {}
    if loader:
        opts["loader"] = loader
    if base is not None:
        opts["base"] = base
    program = cache.analyze(open_image(path, arch=arch, **opts))
    _CACHE[key] = program
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return program


# ---- tool implementations ------------------------------------------------
def t_list_functions(path, arch=None, limit=1000, **k):
    # MCP clients can supply arbitrary numeric values; keep responses bounded and avoid
    # surprising negative slicing semantics.
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    limit = max(0, min(limit, 10000))
    p = _prog(path, arch, **k)
    items = [{"addr": hex(a), "name": p.display(a) or n}
             for a, n in sorted(p.names.items()) if a in p.functions]
    return {"count": len(items), "functions": items[:limit]}

def t_disassemble(path, func, arch=None, **k):
    p = _prog(path, arch, **k)
    f = p.function_at(p.resolve(func)) or p.functions[p.resolve(func)]
    return {"text": render.disassemble(p, f)}

def t_decompile(path, func, arch=None, **k):
    p = _prog(path, arch, **k)
    f = p.function_at(p.resolve(func)) or p.functions[p.resolve(func)]
    return {"c": Decompiler(p, f).c()}

def t_cfg(path, func, arch=None, **k):
    p = _prog(path, arch, **k)
    f = p.function_at(p.resolve(func)) or p.functions[p.resolve(func)]
    return {"dot": render.to_dot(p, f)}

def t_strings(path, arch=None, minlen=4, **k):
    p = _prog(path, arch, **k)
    return {"strings": [{"addr": hex(a), "text": s} for a, s in sorted(p.strings(minlen).items())]}

def t_imports(path, arch=None, **k):
    p = _prog(path, arch, **k)
    return {"imports": [{"addr": hex(a), "name": n} for a, n in sorted(p.image.imports.items())]}

def t_classes(path, arch=None, **k):
    p = _prog(path, arch, **k)
    objc = [c.declaration() for c in (p.objc.classes if p.objc else [])]
    swift = [t.declaration() for t in (p.swift.types if p.swift else [])]
    return {"objc": objc, "swift": swift}

def t_xrefs(path, addr, arch=None, **k):
    p = _prog(path, arch, **k)
    target = p.resolve(addr)
    return {"xrefs_to": [{"from": hex(a), "kind": kind, "in": p.display(a) or ""}
                         for a, kind in p.xrefs_to(target)]}

def t_rename(path, addr, name, arch=None, **k):
    p = _prog(path, arch, **k)
    p.rename(p.resolve(addr), name)
    p.save(p.rdb_path())
    return {"ok": True, "addr": hex(p.resolve(addr)), "name": name}

def t_comment(path, addr, text, arch=None, **k):
    p = _prog(path, arch, **k)
    p.comment(p.resolve(addr), text)
    p.save(p.rdb_path())
    return {"ok": True}

def t_hex(path, func, arch=None, **k):
    p = _prog(path, arch, **k)
    f = p.function_at(p.resolve(func)) or p.functions[p.resolve(func)]
    data = p.image.read(f.addr, min(f.end - f.addr, 4096))
    lines = []
    for o in range(0, len(data), 16):
        chunk = data[o:o + 16]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{f.addr + o:#010x}  {' '.join('%02x' % b for b in chunk):<47}  {asc}")
    return {"hexdump": "\n".join(lines)}

def t_info(path, arch=None, **k):
    p = _prog(path, arch, **k)
    return {"format": p.image.format, "arch": p.arch.name, "entry": hex(p.image.entry),
            "base": hex(p.image.base), "functions": len(p.functions),
            "sections": [{"name": s.name, "va": hex(s.va), "size": s.size, "code": s.code}
                         for s in p.image.sections]}


TOOLS = {
    "list_functions": (t_list_functions, "List discovered functions (addr, resolved name).",
                       {"path": "string", "arch": "string?", "limit": "integer?"}),
    "disassemble": (t_disassemble, "Annotated assembly for one function (name or 0xaddr).",
                    {"path": "string", "func": "string", "arch": "string?"}),
    "decompile": (t_decompile, "C-like pseudo-code for one function.",
                  {"path": "string", "func": "string", "arch": "string?"}),
    "cfg": (t_cfg, "Control-flow graph of one function as Graphviz DOT.",
            {"path": "string", "func": "string", "arch": "string?"}),
    "strings": (t_strings, "All C/UTF-16 strings with addresses.",
                {"path": "string", "arch": "string?", "minlen": "integer?"}),
    "imports": (t_imports, "Imported/external symbols.", {"path": "string", "arch": "string?"}),
    "classes": (t_classes, "Objective-C and Swift type declarations.",
                {"path": "string", "arch": "string?"}),
    "xrefs": (t_xrefs, "Cross-references to an address or symbol.",
              {"path": "string", "addr": "string", "arch": "string?"}),
    "hexdump": (t_hex, "Hex + ASCII dump of a function's bytes.",
                {"path": "string", "func": "string", "arch": "string?"}),
    "info": (t_info, "Format, architecture, entry point and sections.",
             {"path": "string", "arch": "string?"}),
    "rename": (t_rename, "Rename a function/address; persisted to <binary>.rdb.",
               {"path": "string", "addr": "string", "name": "string", "arch": "string?"}),
    "comment": (t_comment, "Attach a comment to an address; persisted to <binary>.rdb.",
                {"path": "string", "addr": "string", "text": "string", "arch": "string?"}),
}


def _schema(params):
    req = [k for k, v in params.items() if not v.endswith("?")]
    props = {k: {"type": v.rstrip("?")} for k, v in params.items()}
    return {"type": "object", "properties": props, "required": req}


# ---- JSON-RPC loop -------------------------------------------------------
def _handle(req):
    m = req.get("method")
    if m == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "rdis", "version": "1.0"}}
    if m == "tools/list":
        return {"tools": [{"name": n, "description": d, "inputSchema": _schema(p)}
                          for n, (_, d, p) in TOOLS.items()]}
    if m == "tools/call":
        name = req["params"]["name"]
        args = req["params"].get("arguments", {})
        fn = TOOLS[name][0]
        try:
            result = fn(**args)
            text = json.dumps(result, indent=2)
            return {"content": [{"type": "text", "text": text}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}],
                    "isError": True}
    raise ValueError(f"unknown method: {m}")


def main():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:   # one malformed line must not kill the server (JSON-RPC: reply with an error)
            req = json.loads(raw)
        except ValueError as e:
            req, bad = {}, {"code": -32700, "message": f"parse error: {e}"}
        else:
            bad = None if isinstance(req, dict) else {"code": -32600, "message": "invalid request"}
            req = req if isinstance(req, dict) else {}
        if bad:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": bad}) + "\n")
            sys.stdout.flush()
            continue
        if str(req.get("method") or "").startswith("notifications/"):
            continue  # no response expected
        try:
            result = _handle(req)
            resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
        except Exception as e:
            resp = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32000, "message": str(e)}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
