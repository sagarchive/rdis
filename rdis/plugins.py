"""Plugin SDK (API version 1). A plugin is a .py file that declares `RDIS_API = 1` and registers what it adds.

    from rdis import plugins
    RDIS_API = 1
    plugins.register_loader("fmt", probe, load)        # a file format: probe(path, opts) -> bool, load(path, arch=None, **opts) -> Image
    plugins.register_arch("mycpu", factory)            # a CPU backend: factory() -> an Arch
    plugins.register_tool("name", fn, "help")          # an analysis tool: fn(program, **kwargs) -> JSON-serialisable

Plugins run with the full privileges of the process, so they load only from directories named in
`RDIS_PLUGINS` (os.pathsep separated); nothing is loaded from the current directory. A plugin that fails to
import, declares another API version, or claims a name another plugin already owns is rejected with a
recorded reason; whatever it registered before failing is rolled back and every other plugin and the core
keep working. `status()` reports each plugin and why it was rejected.
"""
import importlib.util
import os
import pathlib

API_VERSION = 1
loaders, arches, tools = {}, {}, {}
_owners = {"loader": {}, "arch": {}, "tool": {}}
_report = []
_loaded = False
_current = None


def _claim(kind, table, name, value):
    if not isinstance(name, str) or not name:
        raise ValueError(f"{kind} name must be a non-empty string")
    if name in table:
        raise ValueError(f"{kind} {name!r} is already registered by {_owners[kind][name]}")
    table[name] = value
    _owners[kind][name] = _current["file"] if _current else "builtin"
    if _current:
        _current["registered"].append((kind, name))


def register_loader(name, probe, load):
    if not (callable(probe) and callable(load)):
        raise ValueError("a loader needs callable probe and load functions")
    _claim("loader", loaders, name, (probe, load))


def register_arch(name, factory):
    if not callable(factory):
        raise ValueError("an architecture needs a callable factory")
    _claim("arch", arches, name, factory)


def register_tool(name, fn, help=""):
    if not callable(fn):
        raise ValueError("a tool needs a callable")
    _claim("tool", tools, name, (fn, help))


def _rollback(registered):
    for kind, name in registered:
        {"loader": loaders, "arch": arches, "tool": tools}[kind].pop(name, None)
        _owners[kind].pop(name, None)


def _load_one(path):
    global _current
    row = {"file": str(path), "ok": False, "error": None, "registered": []}
    _current = row
    try:
        spec = importlib.util.spec_from_file_location(f"rdis_plugin_{path.stem}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        declared = getattr(module, "RDIS_API", None)
        if declared != API_VERSION:
            raise ValueError(f"declares RDIS_API = {declared!r}; this rdis implements API {API_VERSION}")
        row["ok"] = True
    except (Exception, SystemExit) as e:        # a plugin calling sys.exit() must not end the process
        row["error"] = f"{type(e).__name__}: {e}"
        _rollback(row["registered"])
        row["registered"] = []
    finally:
        _current = None
    row["registered"] = [{"kind": k, "name": n} for k, n in row["registered"]]
    _report.append(row)


def load_all():
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import raw  # built-in loader for headerless blobs
    for d in filter(None, os.environ.get("RDIS_PLUGINS", "").split(os.pathsep)):
        for f in sorted(pathlib.Path(d).glob("*.py")):
            _load_one(f)


def status():
    """One row per plugin file found: file, ok, error, and what it registered."""
    load_all()
    return [dict(row) for row in _report]


def find_loader(path, opts):
    load_all()
    if "loader" in opts:
        name = opts.pop("loader")
        if name not in loaders:
            raise ValueError(f"unknown loader {name!r} (available: {', '.join(sorted(loaders)) or 'none'})")
        return loaders[name][1]
    for name, (probe, load) in loaders.items():
        try:
            if probe(path, opts):
                return load
        except Exception as e:
            _report.append({"file": f"loader {name}", "ok": False, "error": f"probe failed: {type(e).__name__}: {e}",
                            "registered": []})
    return None


def find_arch(name):
    load_all()
    factory = arches.get(name)
    return factory() if factory else None
