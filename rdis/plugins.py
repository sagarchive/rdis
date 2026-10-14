"""Plugin SDK. A plugin is a .py file in $RDIS_PLUGINS (or ./plugins) that calls these at import.

    from rdis import plugins
    plugins.register_loader("raw", probe, load)        # custom file format
    plugins.register_arch("mycpu", factory)            # custom CPU backend
    plugins.register_tool("name", fn, "help text")     # extra MCP/CLI tool: fn(doc, **kwargs)
"""
import importlib.util, os, pathlib

loaders, arches, tools = {}, {}, {}
_loaded = False


def register_loader(name, probe, load):
    """probe(path, opts) -> bool; load(path, arch=None, **opts) -> loader.Image"""
    loaders[name] = (probe, load)


def register_arch(name, factory):
    arches[name] = factory


def register_tool(name, fn, help=""):
    tools[name] = (fn, help)


def load_all():
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import raw  # built-in example plugin: flat firmware/shellcode blobs
    for d in os.environ.get("RDIS_PLUGINS", "plugins").split(os.pathsep):
        for f in sorted(pathlib.Path(d).glob("*.py")):
            spec = importlib.util.spec_from_file_location(f"rdis_plugin_{f.stem}", f)
            spec.loader.exec_module(importlib.util.module_from_spec(spec))


def find_loader(path, opts):
    load_all()
    if "loader" in opts:
        return loaders[opts.pop("loader")][1]
    return next((load for probe, load in loaders.values() if probe(path, opts)), None)
