"""rdis web app: a Hopper-style workspace in the browser. Zero third-party deps (stdlib http).

    PYTHONPATH=. python -m rdis.server [BINARY] [--arch arm64] [--port 8000] [--host 127.0.0.1]

Drop a file on the page (or pass BINARY) -> loader options -> analysis. One server holds several
documents. Security model, because this is meant to run as a free online tool:
  * uploads are capped (--max-mb) and stored under --upload-dir with a generated name;
  * opening arbitrary server-side paths is allowed only when bound to loopback;
  * the console's `py` command exists only with --allow-python (it is code execution).
"""
import argparse, hashlib, json, os, sys, threading, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import lief

from .loader import open_image
from .analysis import Program
from . import cache, containers, render, console
from .decompile import Decompiler

WEB = os.path.join(os.path.dirname(__file__), "web")
CFG = {"allow_python": False, "allow_paths": True, "persist": True, "single_user": True,
       "upload_dir": ".rdis_uploads", "max_mb": 128, "max_sessions": 128, "max_docs": 256,
       "max_analyses": 24}
LOCK = threading.Lock()  # guards the session and shared-analysis registries

# Per-visitor workspaces (cookie `rdis_sid`): one visitor's documents, renames and navigation never
# leak into another's. Each open document is a lightweight OVERLAY of a shared, immutable analysis,
# so N visitors on the same binary analyze it once and share the heavy data read-only. Both
# registries are LRU-bounded to cap memory.
from collections import OrderedDict
SESSIONS = OrderedDict()   # sid -> {"docs": OrderedDict(id -> overlay), "cur": id, "uploads": {...}}
ANALYSES = OrderedDict()   # content-key -> shared analyzed Program
_local = threading.local()  # the session of the request being handled


def session():
    return _local.session


def _get_session(sid):
    with LOCK:
        if sid not in SESSIONS:
            SESSIONS[sid] = {"docs": OrderedDict(), "cur": None, "uploads": {}}
            while len(SESSIONS) > CFG["max_sessions"]:
                # evict the oldest EMPTY workspace first: otherwise max_sessions cookieless requests
                # (each mints a session) wipe every real visitor's open documents
                old = next((k for k, v in SESSIONS.items() if not v["docs"] and k != sid), None)
                SESSIONS.pop(old) if old is not None else SESSIONS.popitem(last=False)
        SESSIONS.move_to_end(sid)
        return SESSIONS[sid]


def _shared_analysis(path, arch, objc, swift, prologues, loader, base):
    """Share one immutable analysis per exact input bytes and analysis configuration.

    File size and mtime are not identities: files can be replaced while preserving both.
    Hash the bytes so a stale Program can never be reused just because metadata was preserved.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    identity = {
        "path": os.path.abspath(path),
        "sha256": digest.hexdigest(),
        "arch": arch,
        "loader": loader,
        "base": base,
        "objc": bool(objc),
        "swift": bool(swift),
        "prologues": bool(prologues),
    }
    key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with LOCK:
        shared = ANALYSES.get(key)
        if shared is not None:
            ANALYSES.move_to_end(key)
            return shared
        gate = ANALYSES.setdefault("__gate__:" + key, threading.Lock())
    with gate:                       # only one thread analyzes this key; others wait and reuse
        with LOCK:
            shared = ANALYSES.get(key)
        if shared is None:
            try:
                shared = _analyze(path, arch, objc, swift, prologues, loader, base)
            except BaseException:    # a failed analysis must not leak its gate (one per bad upload)
                with LOCK:
                    ANALYSES.pop("__gate__:" + key, None)
                raise
            with LOCK:
                ANALYSES[key] = shared
                ANALYSES.pop("__gate__:" + key, None)   # only after the result is visible
                while len([k for k in ANALYSES if not k.startswith("__gate__:")]) > CFG["max_analyses"]:
                    for k in list(ANALYSES):
                        if not k.startswith("__gate__:"):
                            ANALYSES.pop(k)
                            break
    return shared


def _analyze(path, arch, objc, swift, prologues, loader, base):
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head == b"\0asm":                 # WebAssembly: its own parser/disassembler
        from .wasm import WasmProgram
        with open(path, "rb") as fh:
            return WasmProgram(path, fh.read())
    opts = {}
    if loader:
        opts["loader"] = loader
    if base:
        opts["base"] = base
    return cache.analyze(open_image(path, arch=arch, **opts), objc=objc, swift=swift, prologues=prologues)


# ---- documents -------------------------------------------------------------
def prog():
    s = session()
    if s["cur"] not in s["docs"]:
        raise LookupError("no document loaded")
    doc = s["docs"][s["cur"]]
    if isinstance(doc, PendingDoc):      # lazy: analyze on first view
        doc = _materialize(s["cur"], doc)
    return doc


def _extract(path, entry):
    return containers.extract(path, entry, CFG["upload_dir"], CFG["max_mb"])


class NotFound(LookupError):
    """Unknown API route (HTTP 404)."""


def _text(v, field, limit=4096):
    """A user-supplied name/comment must be a string: a dict or list stored here would persist into
    the .rdb and break search/decompile (`.lower()`/`.startswith()`) for that document for good."""
    if not isinstance(v, str):
        raise ValueError(f"'{field}' must be a string")
    if len(v) > limit:
        raise ValueError(f"'{field}' longer than {limit} characters")
    return v


class PendingDoc:
    """A document that is listed but not analyzed yet (lazy). Materialized on first view — used when
    the loader's 'Start automatic analysis' box is off, and for every member of an opened package."""
    __slots__ = ("display_name", "arch", "args")

    def __init__(self, disp, archname, args):
        self.display_name = disp
        self.arch = type("Arch", (), {"name": archname or "?"})()
        self.args = args


def _open_program(path, arch=None, objc=True, swift=True, prologues=True, loader=None, base=None,
                  name=None, entry=None):
    """Extract (if an archive member) and analyze, returning this session's private overlay view."""
    disp = name or os.path.basename(path)
    if entry:                            # an archive member (APK/IPA .so, etc.): extract then analyze
        disp = f"{disp}!{entry.split('/')[-1]}"
        path = _extract(path, entry)
    shared = _shared_analysis(path, arch, objc, swift, prologues, loader, base)
    p = shared.overlay()                 # this session's private edit view of the shared analysis
    p.display_name = disp
    if CFG["persist"] and CFG["single_user"]:
        p.load(p.rdb_path())             # reattach saved renames/comments (single-user local only)
    p._doc_key = hashlib.sha1(f"{path}|{arch}|{loader}".encode()).hexdigest()[:10]
    return p


def _put_doc(did, doc):
    s = session()
    s["docs"][did] = doc
    s["docs"].move_to_end(did)
    while len(s["docs"]) > CFG["max_docs"]:
        s["docs"].popitem(last=False)
    return did


def open_doc(path, arch=None, objc=True, swift=True, prologues=True, loader=None, base=None,
             name=None, entry=None, analyze=True):
    args = dict(path=path, arch=arch, objc=objc, swift=swift, prologues=prologues,
                loader=loader, base=base, name=name, entry=entry)
    if not analyze:                      # deferred: list it now, analyze when the user opens it
        disp = (name or os.path.basename(path)) + (f"!{entry.split('/')[-1]}" if entry else "")
        did = hashlib.sha1(f"{path}|{arch}|{loader}|{entry}".encode()).hexdigest()[:10]
        return _put_doc(did, PendingDoc(disp, arch, args))
    p = _open_program(**args)
    session()["cur"] = _put_doc(p._doc_key, p)
    return p._doc_key


def _materialize(did, pd):
    """Analyze a PendingDoc in place and return the resulting Program overlay."""
    p = _open_program(**pd.args)
    p.display_name = pd.display_name
    session()["docs"][did] = p
    return p


def _persist(P):
    """Write the sidecar DB only for a single-user local install. A multi-session server must never
    share one on-disk rdb between visitors, or one visitor's renames would load into another's."""
    if CFG["persist"] and CFG["single_user"]:
        P.save(P.rdb_path())


slices = containers.slices


# ---- GET API ---------------------------------------------------------------
def api(route, q):
    arg = lambda k, d=None: q.get(k, [d])[0]
    if route == "docs":
        s = session()
        return {"current": s["cur"], "docs": [{"id": k, "name": v.display_name, "arch": v.arch.name,
                                               "pending": isinstance(v, PendingDoc)}
                                              for k, v in s["docs"].items()],
                "allow_paths": CFG["allow_paths"], "allow_python": CFG["allow_python"],
                "persist": CFG["persist"], "max_mb": CFG["max_mb"]}
    if route == "slices":
        if not CFG["allow_paths"]:
            raise PermissionError("opening server paths is disabled on this server")
        return {"slices": slices(arg("path"))}
    P = prog()
    with P._analysis_lock:          # serialize lazy cache fills on the shared analysis
        return _api_doc(route, q, arg, P)


def _api_doc(route, q, arg, P):
    if route == "info":
        im = P.image
        return {"name": P.display_name, "path": im.path, "format": im.format, "arch": im.arch.name,
                "entry": hex(im.entry), "base": hex(im.base),
                "sections": [{"name": s.name, "va": hex(s.va), "size": s.size, "offset": s.offset,
                              "code": s.code} for s in im.sections],
                "counts": {"functions": len(P.functions), "strings": len(P.strings()),
                           "imports": len(im.imports), "labels": len(_labels(P)),
                           "classes": len(P.objc.classes) + len(P.objc.protocols) + len(P.swift.types)}}
    if route == "labels":
        return {"items": _labels(P)}
    if route == "functions":
        return {"items": [{"addr": hex(a), "type": "P", "name": P.display(a) or f"sub_{a:x}"}
                          for a in sorted(P.functions)]}
    if route == "strings":
        return {"items": [{"addr": hex(a), "type": "A", "name": s} for a, s in sorted(P.strings().items())]}
    if route == "imports":
        return {"items": [{"addr": hex(a), "type": "I", "name": P.display(a) or n}
                          for a, n in sorted(P.image.imports.items())]}
    if route == "bookmarks":
        return {"items": [{"addr": hex(a), "type": "B", "name": P.display(a) or hex(a)}
                          for a in sorted(P.bookmarks)]}
    if route == "classes":
        items = [{"name": c.name, "type": "@protocol" if c.is_protocol else "@interface",
                  "decl": c.declaration()} for c in P.objc.protocols + P.objc.classes]
        items += [{"name": t.name, "type": t.kind, "decl": t.declaration()} for t in P.swift.types]
        return {"items": items}
    if route in ("listing", "pseudo", "cfg"):
        f = _func(P, arg("func"))
        if getattr(P, "wasm", False):   # WebAssembly: disassembly listing only
            from . import wasm
            if route == "listing":
                return {"name": P.display(f.addr), "addr": hex(f.addr), "rows": wasm.listing_rows(P, f)}
            note = "// WebAssembly is a stack machine; pseudo-code and CFG are not yet available." \
                   "\n// Use the Assembly view for the disassembled module."
            return {"name": P.display(f.addr), "addr": hex(f.addr), "c": note, "dot": None}
        if route == "listing":
            return {"name": P.display(f.addr), "addr": hex(f.addr), "rows": render.listing(P, f)}
        if route == "pseudo":
            return {"name": P.display(f.addr), "addr": hex(f.addr), "c": Decompiler(P, f).c()}
        return {"name": P.display(f.addr), "addr": hex(f.addr), "dot": render.to_dot(P, f)}
    if route == "hex":
        a = P.resolve(arg("addr") or arg("func"))
        f = P.functions.get(a)
        n = min((f.end - a) if f else 256, 4096)
        data = P.image.read(a, max(n, 16))
        return {"addr": hex(a), "rows": [{"addr": hex(a + o), "hex": " ".join(f"{b:02x}" for b in data[o:o + 16]),
                                          "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data[o:o + 16])}
                                         for o in range(0, len(data), 16)]}
    if route == "xrefs":
        a = P.resolve(arg("addr"))
        return {"items": [{"addr": hex(s), "kind": k, "name": render._ref_name(P, s)} for s, k in P.xrefs_to(a)]}
    if route == "addrinfo":
        return _addrinfo(P, P.resolve(arg("addr")))
    if route == "search":
        return {"items": _search(P, arg("q", ""))}
    if route == "export":  # the analysis database (renames, comments, bookmarks, types, procs)
        return {"rdis_db": 1, "name": P.display_name, "arch": P.arch.name, **_db_dict(P)}
    raise NotFound(f"unknown route: {route}")


def _db_dict(P):
    return {"names": {str(k): v for k, v in P.user_names.items()},
            "comments": {str(k): v for k, v in P.comments.items()},
            "bookmarks": sorted(P.bookmarks), "types": {str(k): v for k, v in P.user_types.items()},
            "procs": sorted(P.user_procs), "removed": sorted(P.removed_procs)}


def _func(P, spec):
    a = P.resolve(spec)
    f = P.function_at(a) or P.functions.get(a)
    if f is None:
        raise LookupError(f"no procedure at {a:#x}")
    return f


def _labels(P):
    """Every named address with a Hopper-style type letter: P proc, I import, D data, B bookmark."""
    out = {}
    for a, n in P.names.items():
        if a in P.functions:
            t = "P"
        elif a in P.image.imports:
            t = "I"
        else:
            t = "D"
        out[a] = {"addr": hex(a), "type": t, "name": P.display(a) or n}
    for a, n in P.user_names.items():
        out.setdefault(a, {"addr": hex(a), "type": "D", "name": n})
    return [out[a] for a in sorted(out)]


def _addrinfo(P, a):
    """Right-hand inspector: where an address lives and what it is."""
    s = P.image.section_at(a)
    f = P.function_at(a)
    kind = P.user_types.get(a) or ("procedure" if a in P.functions else
                                   "code" if f else "string" if a in P.strings() else
                                   "import" if a in P.image.imports else "data")
    i = P.insn(a) if s and s.code else None
    return {"addr": hex(a), "name": P.display(a) or "", "section": s.name if s else "",
            "section_va": hex(s.va) if s else "", "file_offset": P.image.file_offset(a),
            "type": kind, "bookmarked": a in P.bookmarks, "comment": P.comments.get(a, ""),
            "procedure": (P.display(f.addr) if f else ""), "proc_offset": (a - f.addr) if f else None,
            "encoding": i.bytes.hex(" ").upper() if i else "",
            "insn": f"{i.mnemonic} {i.op_str}" if i else "", "xrefs": len(P.xrefs_to(a))}


def _search(P, q):
    """Unified search box: names, strings, and an address or hex pattern."""
    q = q.strip()
    if not q:
        return []
    out = []
    try:
        a = P.resolve(q)
        out.append({"addr": hex(a), "type": "@", "name": P.display(a) or hex(a)})
    except (KeyError, ValueError):
        pass
    ql = q.lower()
    out += [{"addr": hex(a), "type": "P" if a in P.functions else "D", "name": P.display(a) or n}
            for a, n in sorted(P.names.items()) if ql in (P.display(a) or n).lower()][:200]
    out += [{"addr": hex(a), "type": "A", "name": s} for a, s in sorted(P.strings().items()) if ql in s.lower()][:200]
    return out


# ---- POST API --------------------------------------------------------------
def post(route, body, raw=None, query=None):
    if route == "upload":
        return _upload(raw, (query or {}).get("name", ["upload.bin"])[0])
    if route == "open":
        if "token" in body:
            up = session()["uploads"].get(body["token"])
            if up is None:
                raise LookupError("unknown upload token (upload the file again)")
            path, name = up["path"], up["name"]
        else:
            if not CFG["allow_paths"]:
                raise PermissionError("opening server paths is disabled on this server")
            path, name = body["path"], None
        # no outer lock here: _shared_analysis and _get_session do their own locking, and the
        # global LOCK is non-reentrant (wrapping open_doc would self-deadlock on re-acquire).
        did = open_doc(path, arch=body.get("arch"), objc=body.get("objc", True),
                       swift=body.get("swift", True), prologues=body.get("prologues", True),
                       loader=body.get("loader"), base=body.get("base"), name=name,
                       entry=body.get("entry"), analyze=body.get("analyze", True))
        return {"ok": True, "id": did, "pending": not body.get("analyze", True)}
    if route == "open_all":
        # open every native library in a package (APK/IPA/AAR/JAR/ZIP/DMG) as its own document,
        # analyzed lazily on first view so a 200-library package opens instantly.
        if "token" in body:
            up = session()["uploads"].get(body["token"])
            if up is None:
                raise LookupError("unknown upload token (upload the file again)")
            path, name = up["path"], up["name"]
        else:
            if not CFG["allow_paths"]:
                raise PermissionError("opening server paths is disabled on this server")
            path, name = body["path"], None
        libs = [s for s in slices(path) if s.get("entry") and not s.get("disabled")]
        if not libs:
            raise ValueError("no native libraries to open in this package")
        libs = libs[:CFG["max_docs"]]
        first = None
        for sl in libs:
            did = open_doc(path, arch=sl.get("arch"), objc=body.get("objc", True),
                           swift=body.get("swift", True), prologues=body.get("prologues", True),
                           loader=sl.get("loader"), name=name, entry=sl["entry"], analyze=False)
            first = first or did
        session()["cur"] = first
        prog()  # materialize the first so the view is populated immediately
        return {"ok": True, "count": len(libs), "id": first}
    if route == "switch":
        if body["id"] not in session()["docs"]:
            raise KeyError("no such document")
        session()["cur"] = body["id"]
        return {"ok": True}
    if route == "close":
        s = session()
        s["docs"].pop(body.get("id", s["cur"]), None)
        s["cur"] = next(reversed(s["docs"]), None)
        return {"ok": True}
    P = prog()
    if route == "import":
        if body.get("rdis_db") != 1:
            raise ValueError("not an rdis database export")
        with P._analysis_lock:
            P.user_names.update({int(k): str(v) for k, v in body.get("names", {}).items()})
            P.comments.update({int(k): str(v) for k, v in body.get("comments", {}).items()})
            P.bookmarks.update(int(a) for a in body.get("bookmarks", []))
            P.user_types.update({int(k): str(v) for k, v in body.get("types", {}).items()})
            for a in list(body.get("procs", []))[:4096]:   # each one runs discovery: bound the work
                P.create_function(int(a))
            for a in body.get("removed", []):
                P.remove_function(int(a))
            _persist(P)
        return {"ok": True}
    with P._analysis_lock:   # edits and the console touch the overlay and shared caches: serialize
        if route == "rename":
            P.rename(P.resolve(body["addr"]), _text(body["name"], "name"))
        elif route == "comment":
            P.comment(P.resolve(body["addr"]), _text(body.get("text", ""), "text", 65536))
        elif route == "bookmark":
            a = P.resolve(body["addr"])
            P.bookmark(a, body.get("on", a not in P.bookmarks))
        elif route == "mark":
            return _save(P, console.run(P, f"mark {_text(body['kind'], 'kind')} {_text(body['addr'], 'addr')}"))
        elif route == "command":
            return _save(P, console.run(P, _text(body.get("line", ""), "line"), CFG["allow_python"]))
        else:
            raise NotFound(f"unknown route: {route}")
        _persist(P)
    return {"ok": True}


def _save(P, result):
    if result.get("changed"):
        _persist(P)
    return result


def _upload(raw, name):
    if not raw:
        raise ValueError("empty upload")
    if len(raw) > CFG["max_mb"] << 20:
        raise ValueError(f"file larger than {CFG['max_mb']} MB")
    os.makedirs(CFG["upload_dir"], exist_ok=True)
    digest = hashlib.sha256(raw).hexdigest()
    safe = "".join(c for c in os.path.basename(name) if c.isalnum() or c in "._-")[:64] or "upload.bin"
    path = os.path.join(CFG["upload_dir"], f"{digest[:16]}-{safe}")  # generated name: no traversal
    # content-addressed, so identical uploads from different visitors share one file. Write to a
    # per-call temp and atomically rename, or two concurrent writers truncate each other's file and
    # a reader sees a torn, partial binary.
    if not (os.path.exists(path) and os.path.getsize(path) == len(raw)):
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=CFG["upload_dir"])
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            os.replace(tmp, path)   # atomic on the same filesystem
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    session()["uploads"][digest[:16]] = {"path": path, "name": safe}
    return {"token": digest[:16], "name": safe, "size": len(raw), "sha256": digest, "slices": slices(path)}


# ---- HTTP ------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _bind_session(self):
        """Local installs share one workspace; a public server gives each visitor a cookie session."""
        self._new_sid = None
        if CFG["single_user"]:
            _local.session = _get_session("local")
            return
        import re, secrets
        m = re.search(r"(?:^|;\s*)rdis_sid=([0-9a-f]{32})", self.headers.get("Cookie", ""))
        sid = m.group(1) if m else None
        if sid is None:
            sid = self._new_sid = secrets.token_hex(16)
        _local.session = _get_session(sid)

    def _forbidden(self, post):
        """Reason to refuse a request that a hostile web page could have made, else None.

        A local (loopback) install has no auth, so without these checks any site the user visits
        could drive it: a cross-origin `text/plain` POST is a "simple" request that skips CORS
        preflight (CSRF: open server paths, run console commands -- with --allow-python that is code
        execution), and DNS rebinding lets a page read every GET route. So on loopback the Host must
        be loopback and a browser-sent Origin must be same-host, and every POST must carry a
        non-simple Content-Type (forces a preflight, which this server never grants)."""
        host = self.headers.get("Host") or ""
        if CFG["single_user"]:
            name = host[1:].split("]")[0] if host.startswith("[") else host.rsplit(":", 1)[0]
            if name not in ("127.0.0.1", "localhost", "::1"):
                return "bad Host header"
        if post:
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype not in ("application/json", "application/octet-stream"):
                return "POST needs Content-Type application/json or application/octet-stream"
            origin = self.headers.get("Origin")   # (multi-user relies on its SameSite=Strict cookie;
            # behind a proxy the Host it sees need not match the public Origin)
            if CFG["single_user"] and origin is not None and urlparse(origin).netloc != host:
                return "cross-origin request refused"
        return None

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if getattr(self, "_new_sid", None):
            self.send_header("Set-Cookie", f"rdis_sid={self._new_sid}; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(data)

    def _err(self, e):
        code = 404 if isinstance(e, NotFound) or isinstance(e, LookupError) and "no document" in str(e) else \
               403 if isinstance(e, PermissionError) else 400
        return self._send(code, json.dumps({"error": f"{e}"}), "application/json")

    def do_GET(self):
        self._bind_session()
        bad = self._forbidden(post=False)
        if bad:
            return self._send(403, json.dumps({"error": bad}), "application/json")
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, open(os.path.join(WEB, "index.html"), "rb").read(), "text/html; charset=utf-8")
        if u.path.startswith("/api/"):
            try:
                return self._send(200, json.dumps(api(u.path[5:], parse_qs(u.query))), "application/json")
            except Exception as e:
                return self._err(e)
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        self._bind_session()
        u = urlparse(self.path)
        bad = self._forbidden(post=True)
        if bad:
            return self._send(403, json.dumps({"error": bad}), "application/json")
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = -1
        if n < 0:   # rfile.read(-1) would block until the client hangs up, buffering all it sends
            return self._send(400, json.dumps({"error": "bad Content-Length"}), "application/json")
        if n > (CFG["max_mb"] << 20) + 1024:
            return self._send(413, json.dumps({"error": "payload too large"}), "application/json")
        raw = self.rfile.read(n)
        route = u.path[5:]
        try:
            body = {} if route == "upload" else json.loads(raw or b"{}")
            result = post(route, body, raw if route == "upload" else None, parse_qs(u.query))
            return self._send(200, json.dumps(result), "application/json")
        except Exception as e:
            return self._err(e)


def main(argv=None):
    p = argparse.ArgumentParser(prog="rdis.server")
    p.add_argument("binary", nargs="?")
    p.add_argument("--arch")
    p.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 to serve publicly)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-open", action="store_true")
    p.add_argument("--allow-python", action="store_true", help="enable `py` in the console (local only!)")
    p.add_argument("--upload-dir", default=".rdis_uploads")
    p.add_argument("--max-mb", type=int, default=128)
    p.add_argument("--desktop", action="store_true",
                   help="open in a native window (needs the 'desktop' extra: pip install rdis[desktop])")
    p.add_argument("--multi-user", action="store_true",
                   help="per-visitor cookie sessions even on loopback (for a shared instance behind a proxy)")
    a = p.parse_args(argv)
    loopback = a.host in ("127.0.0.1", "localhost", "::1")
    single = loopback and not a.multi_user   # one shared workspace only for a private local install
    CFG.update(allow_python=a.allow_python and loopback and not a.multi_user,
               allow_paths=loopback and not a.multi_user, persist=single,
               single_user=single, upload_dir=a.upload_dir, max_mb=a.max_mb)
    if a.allow_python and not loopback:
        print("rdis: --allow-python ignored on a non-loopback bind (it would be remote code execution)",
              flush=True)
    if a.binary:
        _local.session = _get_session("local")
        open_doc(a.binary, arch=a.arch)
    url = f"http://{'127.0.0.1' if a.host == '0.0.0.0' else a.host}:{a.port}"
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"rdis: serving {url}  (Ctrl-C to stop)" + (f"  -- opened {a.binary}" if a.binary else
          "\n      drop a binary, app or package on the page, or click Open file"))
    if a.desktop:
        try:
            import webview  # pywebview: native window on Win/Mac/Linux, one codebase
        except ImportError:
            sys.exit("--desktop needs pywebview: pip install 'rdis[desktop]'")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        webview.create_window("rdis", url, width=1500, height=950)
        webview.start()
        return
    if not a.no_open:
        webbrowser.open(url)
    srv.serve_forever()


if __name__ == "__main__":
    main()
