"""MCP server for rdis over stdio JSON-RPC 2.0 -- no third-party deps.

Lets an AI agent (REA, Claude Desktop, etc.) drive the disassembler: open a binary, list
functions, disassemble, decompile, read strings/imports/classes, find cross-references.

Run:  python -m rdis.mcp_server
Register in an MCP client as command `python` args `["-m","rdis.mcp_server"]` (cwd = this repo),
or wrap with the venv's python. One binary is held open per session, keyed by path.
"""
import hashlib, json, os, re, sys, threading, traceback
from collections import OrderedDict

from .loader import open_image
from . import cache, render
from .decompile import Decompiler

_CACHE_MAX = 16
_CACHE = OrderedDict()  # (absolute path, content digest, options) -> Program
_CACHE_LOCK = threading.RLock()


def _prog(path, arch=None, loader=None, base=None):
    # Path and stat metadata alone are not reliable: a binary may be replaced in place while
    # preserving size and mtime. The digest also prevents an old Program from being reused.
    absolute = os.path.abspath(os.fspath(path))
    digest = hashlib.sha256()
    with open(absolute, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    key = (absolute, digest.hexdigest(), arch, loader, base)
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None:
            _CACHE.move_to_end(key)
            return cached
    opts = {}
    if loader:
        opts["loader"] = loader
    if base is not None:
        opts["base"] = base
    result = cache.analyze(open_image(absolute, arch=arch, **opts))
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None:
            _CACHE.move_to_end(key)
            return cached
        _CACHE[key] = result
        while len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)
    return result


# ---- tool implementations ------------------------------------------------
MAX_PAGE = 5000
MAX_RESPONSE = 1_000_000


def _page(items, limit, offset, key):
    limit, offset = max(0, min(int(limit), MAX_PAGE)), max(0, int(offset))
    chunk = items[offset:offset + limit]
    return {"total": len(items), "offset": offset, "limit": limit, "returned": len(chunk),
            "truncated": offset + limit < len(items), key: chunk}


def t_list_functions(path, arch=None, limit=1000, offset=0, **k):
    p = _prog(path, arch, **k)
    items = [{"addr": hex(a), "name": p.display(a) or n}
             for a, n in sorted(p.names.items()) if a in p.functions]
    return {"count": len(items), **_page(items, limit, offset, "functions")}

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

def t_callgraph(path, func, arch=None, direction="both", depth=1, **k):
    # Reject invalid controls before touching the file/cache so malformed tool requests have
    # deterministic, cheap errors instead of triggering expensive analysis first.
    if direction not in ("both", "callers", "callees"):
        raise ValueError("call graph direction must be one of: both, callers, callees")
    if isinstance(depth, bool):
        raise ValueError("call graph depth must be an integer from 1 to 4")
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        raise ValueError("call graph depth must be an integer from 1 to 4") from None
    if not 1 <= depth <= 4:
        raise ValueError("call graph depth must be from 1 to 4")
    p = _prog(path, arch, **k)
    if getattr(p, "wasm", False):
        return {"name": str(func), "addr": str(func), "dot": None, "direction": direction,
                "depth": depth, "nodes": 1, "edges": 0, "truncated": False,
                "note": "WebAssembly call-graph edges are not yet reconstructed from validated module call indices."}
    addr = p.resolve(func)
    f = p.function_at(addr) or p.functions.get(addr)
    if f is None:
        raise ValueError(f"no procedure at {addr:#x}")
    return render.callgraph(p, f, direction=direction, depth=depth)

def t_strings(path, arch=None, minlen=4, limit=500, offset=0, **k):
    p = _prog(path, arch, **k)
    items = [{"addr": hex(a), "text": s} for a, s in sorted(p.strings(minlen).items())]
    return _page(items, limit, offset, "strings")

def t_imports(path, arch=None, limit=500, offset=0, **k):
    p = _prog(path, arch, **k)
    items = [{"addr": hex(a), "name": n} for a, n in sorted(p.image.imports.items())]
    return _page(items, limit, offset, "imports")

def t_classes(path, arch=None, limit=200, offset=0, **k):
    p = _prog(path, arch, **k)
    items = [("objc", c.declaration()) for c in (p.objc.classes if p.objc else [])]
    items += [("swift", t.declaration()) for t in (p.swift.types if p.swift else [])]
    out = _page(items, limit, offset, "types")
    types = out.pop("types")
    out["objc"] = [d for kind, d in types if kind == "objc"]
    out["swift"] = [d for kind, d in types if kind == "swift"]
    return out

def t_xrefs(path, addr, arch=None, limit=500, offset=0, **k):
    p = _prog(path, arch, **k)
    target = p.resolve(addr)
    items = [{"from": hex(a), "kind": kind, "in": p.display(a) or ""} for a, kind in p.xrefs_to(target)]
    return _page(items, limit, offset, "xrefs_to")

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


def _func(p, func):
    a = p.resolve(func)
    f = p.function_at(a) or p.functions.get(a)
    if f is None:
        raise KeyError(f"no function at {func}")
    return f

def _ref(p, a):
    return {"addr": hex(a), "name": p.display(a) or ""}

def t_search(path, query, arch=None, limit=200, offset=0, **k):
    from .server import _search          # the UI's search box: names, strings, address/hex
    return _page(_search(_prog(path, arch, **k), query), limit, offset, "results")

def t_lookup(path, addr, arch=None, **k):
    from .server import _addrinfo
    p = _prog(path, arch, **k)
    return _addrinfo(p, p.resolve(addr))

def t_callees(path, func, arch=None, limit=500, offset=0, **k):
    p = _prog(path, arch, **k)
    return _page([_ref(p, a) for a in sorted(_func(p, func).calls)], limit, offset, "callees")

def t_callers(path, func, arch=None, limit=500, offset=0, **k):
    p = _prog(path, arch, **k)
    f, seen = _func(p, func), set()
    for src, kind in p.xrefs_to(f.addr):
        c = p.function_at(src)
        if kind in ("call", "tail") and c is not None:
            seen.add(c.addr)
    return _page([_ref(p, a) for a in sorted(seen)], limit, offset, "callers")

def t_diff(path, other, limit=200, offset=0, arch=None, **k):
    from . import diff as diffmod
    out = diffmod.diff(_prog(path, arch, **k), _prog(other, arch, **k)).as_dict()
    total = len(out["matches"])
    out["matches"] = out["matches"][int(offset):int(offset) + int(limit)]
    out["page"] = {"offset": int(offset), "limit": int(limit), "total": total}
    return out

def t_signatures(path, db, arch=None, **k):
    from . import signatures
    out = signatures.match(_prog(path, arch, **k), signatures.load(db))
    rows = lambda items: [{**r, "addr": hex(r["addr"])} for r in items]
    return {"matches": rows(out["matches"]), "ambiguous": rows(out["ambiguous"])}

MAX_EMULATION_STEPS = 5_000_000

def t_emulate(path, func, args, max_steps=100_000, arch=None, **k):
    from .emulate import EmulationError, emulate
    p = _prog(path, arch, **k)
    steps = min(int(max_steps), MAX_EMULATION_STEPS)
    try:
        res = emulate(p, _func(p, func).addr, [int(a) for a in args], max_steps=steps)
    except EmulationError as e:
        return {"ok": False, "error": str(e), "budget": steps}
    return {"ok": True, "value": res.value, "hex": hex(res.value), "steps": res.steps, "budget": steps}

def t_unresolved(path, func=None, arch=None, **k):
    p = _prog(path, arch, **k)
    rows = p.unresolved([_func(p, func)] if func else None)
    return {"count": len(rows), "unresolved": [
        {**r, "addr": hex(r["addr"]), "function": hex(r["function"])} for r in rows]}

def t_basic_blocks(path, func, arch=None, limit=1000, offset=0, **k):
    p = _prog(path, arch, **k)
    f = _func(p, func)
    items = [{"start": hex(b.addr), "end": hex(b.end), "succs": [hex(s) for s in b.succs]}
             for _, b in sorted(f.blocks.items())]
    return _page(items, limit, offset, "blocks")

def t_stack_frame(path, func, arch=None, **k):
    p = _prog(path, arch, **k)
    return {"locals": [{"offset": o, "name": n, "type": t} for o, n, t in render._stack_vars(p, _func(p, func))]}

def t_read_bytes(path, addr, size=256, arch=None, **k):
    p = _prog(path, arch, **k)
    a = p.resolve(addr)
    return {"addr": hex(a), "hex": p.image.read(a, max(0, min(int(size), 65536))).hex()}

def t_find_bytes(path, pattern, limit=100, arch=None, **k):
    """`pattern`: hex bytes, `??` wildcards (e.g. "fd 7b ?? a9")."""
    p = _prog(path, arch, **k)
    toks = pattern.replace(" ", "")
    if len(toks) % 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2}|\?\?)+", toks):
        raise ValueError("pattern must be hex byte pairs, ?? for any byte")
    rx = re.compile(b"".join(b"." if toks[i:i + 2] == "??" else re.escape(bytes.fromhex(toks[i:i + 2]))
                             for i in range(0, len(toks), 2)), re.S)
    hits = []
    for sec in p.image.sections:
        data = p.image.read(sec.va, sec.size)
        for m in rx.finditer(data):
            hits.append({"addr": hex(sec.va + m.start()), "section": sec.name})
            if len(hits) >= limit:
                return {"matches": hits, "truncated": True}
    return {"matches": hits, "truncated": False}

def t_find_insns(path, regex, func=None, limit=200, arch=None, **k):
    """Instructions whose `mnemonic operands` text matches `regex`, in one or all functions."""
    p = _prog(path, arch, **k)
    rx, hits = re.compile(regex, re.I), []
    funcs = [_func(p, func)] if func else [p.functions[a] for a in sorted(p.functions)]
    for f in funcs:
        for b in f.blocks.values():
            for i in b.shown:
                if rx.search(f"{i.mnemonic} {i.op_str}"):
                    hits.append({"addr": hex(i.address), "insn": f"{i.mnemonic} {i.op_str}",
                                 "function": p.display(f.addr) or hex(f.addr)})
                    if len(hits) >= limit:
                        return {"matches": hits, "truncated": True}
    return {"matches": hits, "truncated": False}

def t_rename_many(path, items, arch=None, **k):
    """Batch rename: `items` is [{"addr": ..., "name": ...}, ...]."""
    p = _prog(path, arch, **k)
    for it in items:
        p.rename(p.resolve(it["addr"]), it["name"])
    p.save(p.rdb_path())
    return {"ok": True, "renamed": len(items)}

def t_define_function(path, addr, arch=None, **k):
    p = _prog(path, arch, **k)
    f = p.create_function(p.resolve(addr))
    p.save(p.rdb_path())
    return {"ok": f is not None, "blocks": len(f.blocks) if f else 0}

def t_undefine_function(path, addr, arch=None, **k):
    p = _prog(path, arch, **k)
    ok = p.remove_function(p.resolve(addr))
    p.save(p.rdb_path())
    return {"ok": ok}

def t_set_type(path, addr, kind, arch=None, **k):
    if kind not in ("data", "ascii", "code", ""):
        raise ValueError("kind must be data, ascii, code or empty to clear")
    p = _prog(path, arch, **k)
    p.set_type(p.resolve(addr), kind or None)
    p.save(p.rdb_path())
    return {"ok": True}

def t_bookmarks(path, addr=None, on=True, arch=None, **k):
    p = _prog(path, arch, **k)
    if addr is not None:
        p.bookmark(p.resolve(addr), on)
        p.save(p.rdb_path())
    return {"bookmarks": [_ref(p, a) for a in sorted(p.bookmarks)]}

def t_jump_tables(path, arch=None, **k):
    p = _prog(path, arch, **k)
    return {"jump_tables": [{"at": hex(a), "cases": {str(c): hex(t) for c, t in jt["cases"].items()}}
                            for a, jt in sorted(p.jump_tables.items())]}

def t_jni_natives(path, arch=None, **k):
    p = _prog(path, arch, **k)
    return {"natives": [{"addr": hex(a), "name": n, "signature": sig}
                        for a, (n, sig, _) in sorted(p.jni_natives.items())]}


TOOLS = {
    "list_functions": (t_list_functions, "List discovered functions (addr, resolved name).",
                       {"path": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "disassemble": (t_disassemble, "Annotated assembly for one function (name or 0xaddr).",
                    {"path": "string", "func": "string", "arch": "string?"}),
    "decompile": (t_decompile, "C-like pseudo-code for one function.",
                  {"path": "string", "func": "string", "arch": "string?"}),
    "cfg": (t_cfg, "Control-flow graph of one function as Graphviz DOT.",
            {"path": "string", "func": "string", "arch": "string?"}),
    "callgraph": (t_callgraph, "Bounded interprocedural callers/callees graph as Graphviz DOT with nodes, edges, direction, depth and truncation metadata.",
                  {"path": "string", "func": "string", "arch": "string?", "direction": "string?", "depth": "integer?"}),
    "strings": (t_strings, "All C/UTF-16 strings with addresses.",
                {"path": "string", "arch": "string?", "minlen": "integer?", "limit": "integer?", "offset": "integer?"}),
    "imports": (t_imports, "Imported/external symbols.", {"path": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "classes": (t_classes, "Objective-C and Swift type declarations.",
                {"path": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "xrefs": (t_xrefs, "Cross-references to an address or symbol.",
              {"path": "string", "addr": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "hexdump": (t_hex, "Hex + ASCII dump of a function's bytes.",
                {"path": "string", "func": "string", "arch": "string?"}),
    "info": (t_info, "Format, architecture, entry point and sections.",
             {"path": "string", "arch": "string?"}),
    "rename": (t_rename, "Rename a function/address; persisted to <binary>.rdb.",
               {"path": "string", "addr": "string", "name": "string", "arch": "string?"}),
    "comment": (t_comment, "Attach a comment to an address; persisted to <binary>.rdb.",
                {"path": "string", "addr": "string", "text": "string", "arch": "string?"}),
    "search": (t_search, "Search names and strings, or resolve an address/symbol.",
               {"path": "string", "query": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "lookup": (t_lookup, "What an address is: section, file offset, owning function, instruction, xref count.",
               {"path": "string", "addr": "string", "arch": "string?"}),
    "callees": (t_callees, "Functions called by a function.",
                {"path": "string", "func": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "callers": (t_callers, "Functions that call (or tail-call) a function.",
                {"path": "string", "func": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "diff": (t_diff, "Match functions of two builds (name, exact, shape, strings, call graph, similarity) with confidence and ambiguity.",
             {"path": "string", "other": "string", "limit": "integer?", "offset": "integer?", "arch": "string?"}),
    "signatures": (t_signatures, "Name unnamed functions from a local signature database (confidence + source; ambiguous hashes are listed, not guessed).",
                   {"path": "string", "db": "string", "arch": "string?"}),
    "emulate": (t_emulate, "Run a function in the P-code emulator on integer arguments (no host execution; stops with an error on anything unmodelled).",
                {"path": "string", "func": "string", "args": "array", "max_steps": "integer?", "arch": "string?"}),
    "unresolved": (t_unresolved, "Indirect jumps and calls whose target could not be established (never guessed).",
                   {"path": "string", "func": "string?", "arch": "string?"}),
    "basic_blocks": (t_basic_blocks, "Basic blocks of a function with successor edges.",
                     {"path": "string", "func": "string", "arch": "string?", "limit": "integer?", "offset": "integer?"}),
    "stack_frame": (t_stack_frame, "Recovered stack locals of a function (offset, name, type).",
                    {"path": "string", "func": "string", "arch": "string?"}),
    "read_bytes": (t_read_bytes, "Raw bytes at an address as hex (max 64 KiB).",
                   {"path": "string", "addr": "string", "size": "integer?", "arch": "string?"}),
    "find_bytes": (t_find_bytes, "Find a byte pattern (hex, ?? wildcards) in every section.",
                   {"path": "string", "pattern": "string", "limit": "integer?", "arch": "string?"}),
    "find_insns": (t_find_insns, "Find instructions matching a regex, in one function or all.",
                   {"path": "string", "regex": "string", "func": "string?", "limit": "integer?", "arch": "string?"}),
    "rename_many": (t_rename_many, "Rename many addresses at once: items=[{addr, name}].",
                    {"path": "string", "items": "array", "arch": "string?"}),
    "define_function": (t_define_function, "Mark an address as a function start and analyze it.",
                        {"path": "string", "addr": "string", "arch": "string?"}),
    "undefine_function": (t_undefine_function, "Remove the function starting at an address.",
                          {"path": "string", "addr": "string", "arch": "string?"}),
    "set_type": (t_set_type, "Mark an address as data, ascii or code (empty clears).",
                 {"path": "string", "addr": "string", "kind": "string", "arch": "string?"}),
    "bookmarks": (t_bookmarks, "List bookmarks; with addr, add (on=true) or remove one.",
                  {"path": "string", "addr": "string?", "on": "boolean?", "arch": "string?"}),
    "jump_tables": (t_jump_tables, "Recovered switch jump tables (case -> target).",
                    {"path": "string", "arch": "string?"}),
    "jni_natives": (t_jni_natives, "Android JNI natives recovered from RegisterNatives tables.",
                    {"path": "string", "arch": "string?"}),
}


WRITES = {"rename", "comment", "rename_many", "define_function", "undefine_function", "set_type", "bookmarks"}
COMMON = {"loader": "string?", "base": "any?"}
_TYPES = {"string": str, "integer": int, "array": list, "boolean": bool}


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _schema(params):
    params = {**params, **{k: v for k, v in COMMON.items() if k not in params}}
    req = [k for k, v in params.items() if not v.endswith("?")]
    props = {k: ({} if v.rstrip("?") == "any" else {"type": v.rstrip("?")}) for k, v in params.items()}
    return {"type": "object", "properties": props, "required": req, "additionalProperties": False}


def _validate(name, args):
    if name not in TOOLS:
        raise RpcError(-32602, f"unknown tool {name!r}")
    if not isinstance(args, dict):
        raise RpcError(-32602, "arguments must be an object")
    schema = _schema(TOOLS[name][2])["properties"]
    unknown = sorted(set(args) - set(schema))
    if unknown:
        raise RpcError(-32602, f"{name}: unknown argument(s) {unknown}")
    missing = [k for k in _schema(TOOLS[name][2])["required"] if k not in args]
    if missing:
        raise RpcError(-32602, f"{name}: missing required argument(s) {missing}")
    for key, value in args.items():
        want = schema[key].get("type")
        if want and (not isinstance(value, _TYPES[want]) or (want == "integer" and isinstance(value, bool))):
            raise RpcError(-32602, f"{name}: argument {key!r} must be {want}")


def _failure(code, message):
    return {"content": [{"type": "text", "text": json.dumps({"error": {"code": code, "message": message}})}],
            "isError": True}


def _call(name, args):
    _validate(name, args)
    try:
        text = json.dumps(TOOLS[name][0](**args), indent=1)
    except FileNotFoundError as e:
        return _failure("not_found", f"{e.filename or 'file'} does not exist")
    except KeyError as e:
        return _failure("not_found", str(e.args[0]) if e.args else "not found")
    except PermissionError as e:
        return _failure("denied", str(e))
    except (ValueError, TypeError, re.error) as e:
        return _failure("invalid_argument", str(e))
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        return _failure("internal", f"{type(e).__name__}: {e}")
    if len(text) > MAX_RESPONSE:
        return _failure("response_too_large", f"result is {len(text)} characters; use limit/offset to page it")
    return {"content": [{"type": "text", "text": text}]}


# ---- JSON-RPC loop -------------------------------------------------------
def _handle(req):
    m = req.get("method")
    if m == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "rdis", "version": "1.0"}}
    if m == "ping":
        return {}
    if m == "tools/list":
        return {"tools": [{"name": n, "description": d, "inputSchema": _schema(p),
                           "annotations": {"readOnlyHint": n not in WRITES, "destructiveHint": False,
                                           "openWorldHint": False}}
                          for n, (_, d, p) in TOOLS.items()]}
    if m == "tools/call":
        params = req.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise RpcError(-32602, "tools/call needs params.name")
        return _call(params["name"], params.get("arguments", {}))
    raise RpcError(-32601, f"unknown method: {m}")


def process_line(raw):
    """One JSON-RPC line in, the reply line out (None when no reply is due). Never raises."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        req = json.loads(raw)
    except (ValueError, RecursionError) as e:
        return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {e}"}})
    if not isinstance(req, dict):
        return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
    if str(req.get("method") or "").startswith("notifications/"):
        return None
    ident = req.get("id")
    if ident is not None and not isinstance(ident, (str, int, float)):
        ident = None
    try:
        reply = {"jsonrpc": "2.0", "id": ident, "result": _handle(req)}
    except RpcError as e:
        reply = {"jsonrpc": "2.0", "id": ident, "error": {"code": e.code, "message": str(e)}}
    except Exception as e:
        reply = {"jsonrpc": "2.0", "id": ident, "error": {"code": -32000, "message": f"{type(e).__name__}: {e}"}}
    try:
        return json.dumps(reply)
    except (TypeError, ValueError, RecursionError):
        return json.dumps({"jsonrpc": "2.0", "id": ident, "error": {"code": -32603, "message": "unserializable result"}})


def main():
    for raw in sys.stdin:
        reply = process_line(raw)
        if reply is not None:
            sys.stdout.write(reply + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
