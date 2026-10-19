"""rdis CLI.

  rdis BIN                      list functions (addr, name)
  rdis BIN -f main              disassemble a function
  rdis BIN -f main --cfg        intraprocedural control-flow graph as Graphviz DOT
  rdis BIN -f main --callgraph  caller/callee graph as Graphviz DOT (direction/depth configurable)
  rdis BIN -f main -d           C pseudo-code (decompile)
  rdis BIN --strings            all strings
  rdis BIN --classes            Objective-C / Swift type declarations
  rdis BIN --imports            imported symbols
  rdis BIN --json ...           machine-readable form of any of the above
  rdis app.apk                  APK/IPA/AAR/JAR/ZIP/DMG: list the native libraries inside
  rdis app.apk -l lib/arm64-v8a/libfoo.so [any command above]   analyze that member
Options: --arch NAME (fat Mach-O slice), --loader raw --base 0xADDR (headerless blob).
"""
import argparse, json, sys

from .loader import open_image
from .analysis import Program
from . import cache, containers, render
from .decompile import Decompiler


def build(args, path):
    opts = {}
    if args.loader:
        opts["loader"] = args.loader
    if args.base:
        opts["base"] = args.base
    prog = cache.analyze(open_image(path, arch=args.arch, **opts))
    if isinstance(prog, Program):
        prog.load(prog.rdb_path(), allow_legacy=args.allow_legacy_rdb)  # local native workspace; legacy migration is opt-in
    return prog


def list_containers(path, libs, as_json=False):
    if as_json:
        print(json.dumps([{"entry": s["entry"], "arch": s.get("arch"), "size": s.get("size")}
                          for s in libs], indent=2))
    else:
        print(f"{path}: {len(libs)} native libraries")
        for s in libs:
            size = f"{s['size']:>10,} B" if s.get("size") is not None else " " * 13
            print(f"  {size}  {s.get('arch') or '-':<7}  {s['entry']}")
        print(f"\npick one with:  rdis {path} -l {libs[0]['entry']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="rdis", description="multi-format disassembler and decompiler")
    p.add_argument("binary")
    p.add_argument("-f", "--func", help="function name, sub_xxx, or 0xADDR")
    p.add_argument("-d", "--decompile", action="store_true", help="emit C pseudo-code")
    p.add_argument("--cfg", action="store_true", help="emit control-flow graph for one function (Graphviz DOT)")
    p.add_argument("--callgraph", action="store_true", help="emit bounded interprocedural caller/callee graph (Graphviz DOT)")
    p.add_argument("--callgraph-direction", choices=("both", "callers", "callees"), default="both",
                   help="call graph neighborhood direction (default: both)")
    p.add_argument("--callgraph-depth", type=int, choices=range(1, 5), default=1, metavar="{1,2,3,4}",
                   help="maximum number of call edges from the selected function (default: 1)")
    p.add_argument("--strings", action="store_true")
    p.add_argument("--classes", action="store_true", help="Objective-C / Swift declarations")
    p.add_argument("--imports", action="store_true")
    p.add_argument("-l", "--entry", metavar="MEMBER",
                   help="archive member to analyze (APK/IPA/AAR/JAR/ZIP/DMG): full path, or a "
                        "unique part like libfoo.so")
    p.add_argument("--arch", help="slice to use for a fat Mach-O (x86_64, arm64, ...)")
    p.add_argument("--loader", help="force a plugin loader (e.g. raw)")
    p.add_argument("--base", help="load address for --loader raw")
    p.add_argument("--allow-legacy-rdb", action="store_true",
                   help="import an old sidecar without a content hash (verify the original binary first)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.callgraph and not a.func:
        p.error("--callgraph requires -f/--func")
    if a.callgraph and (a.cfg or a.decompile):
        p.error("--callgraph cannot be combined with --cfg or --decompile")
    if not a.callgraph and (a.callgraph_direction != "both" or a.callgraph_depth != 1):
        p.error("--callgraph-direction and --callgraph-depth require --callgraph")
    try:
        path = a.binary
        if a.entry:
            path = containers.extract(path, containers.find_entry(path, a.entry))
        else:
            libs = [s for s in containers.slices(path) if s.get("entry") and not s.get("disabled")]
            if libs and len(libs) > 1:
                list_containers(path, libs, a.json)
                return
            if libs:
                print(f"rdis: 1 native library; analyzing {libs[0]['entry']}", file=sys.stderr)
                path = containers.extract(path, libs[0]["entry"])
        prog = build(a, path)
    except (KeyError, ValueError) as e:
        sys.exit(f"rdis: {e}")

    if a.strings:
        s = prog.strings()
        print(json.dumps({hex(k): v for k, v in s.items()}) if a.json else
              "\n".join(f"{k:#x}  {v!r}" for k, v in sorted(s.items())))
        return
    if a.imports:
        imp = prog.image.imports
        print(json.dumps({hex(k): v for k, v in imp.items()}) if a.json else
              "\n".join(f"{k:#x}  {v}" for k, v in sorted(imp.items())))
        return
    if a.classes:
        decls = [c.declaration() for c in (prog.objc.protocols if prog.objc else [])]
        decls += [c.declaration() for c in (prog.objc.classes if prog.objc else [])]
        decls += [t.declaration() for t in (prog.swift.types if prog.swift else [])]
        print(json.dumps(decls) if a.json else "\n\n".join(decls) or "; no Objective-C/Swift metadata")
        return
    if not a.func:
        items = {a2: (prog.display(a2) or n) for a2, n in prog.names.items() if a2 in prog.functions}
        print(json.dumps({hex(k): v for k, v in items.items()}) if a.json else
              "\n".join(f"{k:#010x}  {v}" for k, v in sorted(items.items())))
        return

    try:
        addr = prog.resolve(a.func)
    except KeyError as e:
        sys.exit(str(e))
    func = prog.function_at(addr) or prog.functions.get(addr)
    if func is None:
        sys.exit(f"no function at {a.func}")
    if a.decompile:
        print(Decompiler(prog, func).c())
    elif a.callgraph:
        if getattr(prog, "wasm", False):
            message = "WebAssembly call-graph edges are not yet reconstructed from validated module call indices"
            if a.json:
                print(json.dumps({"name": prog.display(addr), "addr": hex(addr), "dot": None,
                                  "direction": a.callgraph_direction, "depth": a.callgraph_depth,
                                  "nodes": 1, "edges": 0, "truncated": False, "note": message}))
            else:
                sys.exit(f"rdis: {message}")
            return
        result = render.callgraph(prog, func, direction=a.callgraph_direction, depth=a.callgraph_depth)
        print(json.dumps(result, sort_keys=True) if a.json else result["dot"])
    elif a.cfg:
        print(render.to_dot(prog, func))
    elif a.json:
        print(json.dumps({hex(b.addr): [f"{i.mnemonic} {i.op_str}" for i in b.shown]
                          for b in func.blocks.values()}))
    else:
        print(render.disassemble(prog, func))


if __name__ == "__main__":
    main()
