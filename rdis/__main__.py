"""rdis CLI.

  rdis BIN                      list functions (addr, name)
  rdis BIN -f main              disassemble a function
  rdis BIN -f main --cfg        control-flow graph as Graphviz DOT
  rdis BIN -f main -d           C pseudo-code (decompile)
  rdis BIN --strings            all strings
  rdis BIN --classes            Objective-C / Swift type declarations
  rdis BIN --imports            imported symbols
  rdis BIN --json ...           machine-readable form of any of the above
Options: --arch NAME (fat Mach-O slice), --loader raw --base 0xADDR (headerless blob).
"""
import argparse, json, sys

from .loader import open_image
from .analysis import Program
from . import render
from .decompile import Decompiler


def build(args):
    opts = {}
    if args.loader:
        opts["loader"] = args.loader
    if args.base:
        opts["base"] = args.base
    prog = Program(open_image(args.binary, arch=args.arch, **opts)).analyze()
    prog.load(prog.rdb_path())  # CLI owns one workspace: restore saved renames/comments
    return prog


def main(argv=None):
    p = argparse.ArgumentParser(prog="rdis", description="multi-format disassembler and decompiler")
    p.add_argument("binary")
    p.add_argument("-f", "--func", help="function name, sub_xxx, or 0xADDR")
    p.add_argument("-d", "--decompile", action="store_true", help="emit C pseudo-code")
    p.add_argument("--cfg", action="store_true", help="emit control-flow graph (Graphviz DOT)")
    p.add_argument("--strings", action="store_true")
    p.add_argument("--classes", action="store_true", help="Objective-C / Swift declarations")
    p.add_argument("--imports", action="store_true")
    p.add_argument("--arch", help="slice to use for a fat Mach-O (x86_64, arm64, ...)")
    p.add_argument("--loader", help="force a plugin loader (e.g. raw)")
    p.add_argument("--base", help="load address for --loader raw")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    prog = build(a)

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
    elif a.cfg:
        print(render.to_dot(prog, func))
    elif a.json:
        print(json.dumps({hex(b.addr): [f"{i.mnemonic} {i.op_str}" for i in b.insns]
                          for b in func.blocks.values()}))
    else:
        print(render.disassemble(prog, func))


if __name__ == "__main__":
    main()
