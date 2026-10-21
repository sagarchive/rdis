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


def run_diff(a, prog):
    from . import diff as diffmod
    other = build(a, a.diff)
    result = diffmod.diff(prog, other)
    out = result.as_dict()
    if a.transfer:
        report = diffmod.transfer(prog, other, result, a.min_confidence)
        other.save(other.rdb_path())
        out["transfer"] = {k: [{f: (hex(v) if isinstance(v, int) else v) for f, v in row.items()} for row in rows]
                           for k, rows in report.items()}
    if a.json:
        print(json.dumps(out, sort_keys=True))
        return
    c = out["counts"]
    print(f"matched {c['matched']}  only in A {c['only_a']}  only in B {c['only_b']}  ambiguous {c['ambiguous']}")
    print("by method: " + ", ".join(f"{k} {v}" for k, v in sorted(c["by_method"].items())))
    for m in out["matches"]:
        name = prog.display(int(m["a"], 16)) or ""
        print(f"  {m['a']} -> {m['b']}  {m['method']:<10} {m['confidence']:.2f}  {name}")
    for row in out["ambiguous"]:
        print(f"  {row['a']} ambiguous: {', '.join(row['candidates'])}")
    if a.transfer:
        t = out["transfer"]
        print(f"transferred {len(t['applied'])} annotations; skipped {len(t['skipped'])}")
        for row in t["skipped"]:
            print(f"  skipped {row['a']}: {row['reason']}")


def run_signatures(a, prog):
    from . import signatures
    if a.sig_make:
        db = signatures.make(prog)
        signatures.dump(db, a.sig_make)
        print(f"wrote {len(db['entries'])} signatures from {db['source']['name']} to {a.sig_make}")
        return
    out = signatures.match(prog, signatures.load(a.sig))
    if a.json:
        print(json.dumps({"matches": [{**m, "addr": hex(m["addr"])} for m in out["matches"]],
                          "ambiguous": [{**m, "addr": hex(m["addr"])} for m in out["ambiguous"]]}, sort_keys=True))
        return
    for m in out["matches"]:
        print(f"{m['addr']:#012x}  {m['name']}  confidence {m['confidence']:.2f}  ({m['size']} insns, from {m['source']})")
    for m in out["ambiguous"]:
        print(f"{m['addr']:#012x}  ambiguous: {', '.join(m['candidates'])}")
    print(f"{len(out['matches'])} named, {len(out['ambiguous'])} ambiguous")


def run_triage(a, path):
    from .triage import triage
    out = triage(path, arch=a.arch)
    if a.json:
        print(json.dumps(out, sort_keys=True))
        return
    print(f"{out['file']}: {out['format']} {out['arch']}, {out['bytes']:,} bytes, overall entropy {out['overall_entropy']}")
    for s in out["sections"]:
        print(f"  {s['name']:<18} {s['size']:>10,}  entropy {s['entropy']:<6}{'  exec' if s['executable'] else ''}")
    for r in out["runtimes"]:
        print(f"runtime hint: {r['runtime']} ({', '.join(r['evidence'])})")
    for i in out["indicators"]:
        print(f"[{i['severity']}] {i['indicator']}: {i['evidence']}; consistent with {', '.join(i['consistent_with'])}")
    print(out["note"])


def run_tool(a, prog):
    from . import plugins
    plugins.load_all()
    if a.tool not in plugins.tools:
        raise ValueError(f"no plugin tool {a.tool!r} (loaded: {', '.join(sorted(plugins.tools)) or 'none'})")
    try:
        kwargs = json.loads(a.tool_args)
    except ValueError as e:
        raise ValueError(f"--tool-args is not valid JSON: {e}") from None
    if not isinstance(kwargs, dict):
        raise ValueError("--tool-args must be a JSON object")
    print(json.dumps(plugins.tools[a.tool][0](prog, **kwargs), indent=1, sort_keys=True))


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


def list_archs():
    """CPUs rdis can load: Capstone-backed ones, then everything a SLEIGH spec describes."""
    from . import sleigh
    print("Capstone (full decompiler): x86 x86_64 arm arm64 mips mipsel mips64 mips64el riscv32 riscv64")
    print("\nSLEIGH short names (disassembly, CFG, P-code IR; --arch NAME):")
    for name, spec in sleigh._SPECS.items():
        print(f"  {name:<12} {spec[0]}")
    from . import plugins
    plugins.load_all()
    if plugins.arches:
        print("\nplugin architectures (RDIS_PLUGINS):")
        for name in sorted(plugins.arches):
            print(f"  {name}")
    ids = sleigh.languages()
    print(f"\nany of {len(ids)} SLEIGH languages as --arch sleigh:<id> (no calling convention):")
    print("  " + "\n  ".join(ids))


def list_plugins():
    from . import plugins
    rows = plugins.status()
    if not rows:
        print("no plugins loaded (set RDIS_PLUGINS to a directory of plugin .py files)")
    for r in rows:
        regs = ", ".join(f"{x['kind']} {x['name']}" for x in r["registered"]) or "nothing"
        print(f"{'ok      ' if r['ok'] else 'REJECTED'} {r['file']}: " + (f"registers {regs}" if r["ok"] else r["error"]))


def main(argv=None):
    if "--list-archs" in (sys.argv[1:] if argv is None else argv):
        return list_archs()
    if "--list-plugins" in (sys.argv[1:] if argv is None else argv):
        return list_plugins()
    if "--capabilities" in (sys.argv[1:] if argv is None else argv):
        from .capabilities import capabilities
        return print(json.dumps(capabilities(), indent=1, sort_keys=True))
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
    p.add_argument("--arch", help="slice for a fat Mach-O (x86_64, arm64, ...), or the CPU for --loader raw "
                                  "(ppc, sparc, m68k, avr8, ebpf, ...; see --list-archs)")
    p.add_argument("--list-archs", action="store_true", help="print every CPU rdis can load, then exit")
    p.add_argument("--capabilities", action="store_true", help="print what rdis supports per CPU and level, as JSON, then exit")
    p.add_argument("--list-plugins", action="store_true", help="print each plugin from RDIS_PLUGINS and why any was rejected")
    p.add_argument("--tool", metavar="NAME", help="run a tool registered by a plugin on this binary")
    p.add_argument("--tool-args", metavar="JSON", default="{}", help="keyword arguments for --tool, as a JSON object")
    p.add_argument("--loader", help="force a plugin loader (e.g. raw)")
    p.add_argument("--base", help="load address for --loader raw")
    p.add_argument("--allow-legacy-rdb", action="store_true",
                   help="import an old sidecar without a content hash (verify the original binary first)")
    p.add_argument("--sig-make", metavar="DB", help="write a signature database from this binary's named functions")
    p.add_argument("--sig", metavar="DB", help="name this binary's unnamed functions from a signature database")
    p.add_argument("--emulate", metavar="ARGS", help="run -f/--func in the P-code emulator with comma-separated "
                   "integer arguments (e.g. 7,0x10); stops with an error on anything it cannot model")
    p.add_argument("--max-steps", type=int, default=1_000_000, help="instruction budget for --emulate")
    p.add_argument("--triage", action="store_true", help="entropy, packing indicators and runtime identification (evidence, not verdicts)")
    p.add_argument("--diff", metavar="OTHER", help="match this binary's functions against another build of it")
    p.add_argument("--transfer", action="store_true",
                   help="with --diff: copy renames and comments onto OTHER for matches at or above --min-confidence")
    p.add_argument("--min-confidence", type=float, default=0.9, help="annotation transfer threshold (default 0.9)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.transfer and not a.diff:
        p.error("--transfer requires --diff")
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
        if a.triage:
            return run_triage(a, path)
        if a.tool:
            return run_tool(a, prog)
        if a.diff:
            return run_diff(a, prog)
        if a.sig or a.sig_make:
            return run_signatures(a, prog)
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
    if a.emulate is not None:
        from .emulate import EmulationError, emulate
        try:
            res = emulate(prog, func.addr, [int(t, 0) for t in a.emulate.split(",") if t.strip()], max_steps=a.max_steps)
        except (EmulationError, ValueError) as e:
            sys.exit(f"rdis: emulation stopped: {e}")
        print(json.dumps({"function": hex(func.addr), "value": res.value, "hex": hex(res.value), "steps": res.steps})
              if a.json else f"{res.value} ({hex(res.value)}) after {res.steps} instructions")
        return
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
