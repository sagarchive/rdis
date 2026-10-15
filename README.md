<p align="center"><img src="docs/brand/rdis-icon.svg" width="112" height="112" alt="rdis icon"></p>

<h1 align="center">rdis</h1>

A scriptable, multi-format disassembler and decompiler — a cross-platform, browser-based answer to
Hopper. Pure Python over [Capstone](https://www.capstone-engine.org/) (decoding) and
[LIEF](https://lief.re/) (binary parsing), with a from-scratch WebAssembly backend. Use it as a
Hopper-style web workspace, a CLI, an importable library, or a zero-dependency MCP server an AI
agent (e.g. [REA](https://github.com/morluto/rea)) can drive.

## Features

| Capability | rdis | Hopper |
|---|---|---|
| Formats | Mach-O (thin + fat), ELF, PE, **WebAssembly**, raw firmware | Mach-O/ELF/PE |
| Containers | **APK / IPA / AAR / JAR / ZIP** (open one lib or the whole package), **DMG** (via `hdiutil`), **tar / tar.gz / tar.xz**, transparent **gzip / xz / bzip2**; any other file opens as a **raw** binary | — |
| CPUs | x86, x86-64, **ARM (ARM + Thumb)**, ARM64, **MIPS32/64 (BE/LE, delay slots)**, **RISC-V 32/64 (+RVC)**, **WASM** | x86/x64/ARM |
| Stripped binaries | recovers a code range from executable segments when section headers are gone | yes |
| Multi-user web | **per-visitor sessions, shared read-only analysis, concurrency-tested** | single desktop app |
| Function / basic-block discovery | symbols, function-starts, `.pdata`, encoding-level prologue scan (incl. Dart/Flutter AOT), call graph | yes |
| Control-flow graph | Graphviz DOT, colored edges | yes (native view) |
| C pseudo-code | structuring + symbolic lifter (x86/ARM) and an **IR decompiler** (Ghidra P-code via `pypcode`, or our own MIPS/RISC-V frontend). **Checked by execution:** 124 `-O2`/`-O3`, vectorized and struct cases recompile and match; 96% / 95% of real arm64 / x86-64 functions compile | yes |
| Type/variable recovery | pointer vs int args, access-width types, void/value returns, named locals | yes |
| Objective-C metadata | classes, categories, **protocols** (+`@optional`, adoption), methods, ivars, properties, selectors, CFStrings | yes |
| Swift metadata | structs, classes, enums + fields, **protocol conformances**, demangled | yes |
| Struct/field reconstruction | declared `struct`s with typed fields (width, sign, float, **self-referential pointers** like `next`); IR path merges layouts **across calls** | yes |
| SIMD | **lane-exact, compilable C** for NEON and SSE via vector extensions (`(u32x4)a + (u32x4)b`, `__builtin_reduce_add`), not pseudo-intrinsics | intrinsics |
| Hex view | per-function hex + ASCII dump (CLI, GUI, MCP) | yes |
| Demangling | Swift + C++ (system tools) | yes |
| Cross-references | to any address/symbol | yes |
| Strings | ASCII + UTF-16 | yes |
| Scripting | import `rdis` as a library | Python API |
| Plugin SDK | custom loaders, CPUs, tools | SDK |
| AI integration | **built-in MCP server, zero deps** | MCP server |
| Debugger | LLDB batch wrapper (static + live) | LLDB/GDB |
| GUI | web three-pane (navigator / asm / pseudo-CFG), or native window | native app |
| Analysis database | renames + comments persisted to `<binary>.rdb`, shared by CLI/GUI/MCP; **content-addressed analysis cache** (`.rdis_cache/`) reopens a 9 MB Flutter lib in 0.6s instead of 31s | yes |
| Android JNI | **`env->FindClass(...)` naming for all 229 JNIEnv slots; `RegisterNatives` tables found and their natives named + typed** | no |
| Runs on Linux | **yes** | no (macOS only) |

How the decompiler is checked, reproducibly:

```sh
python tests/maturity.py                       # 124 cases: compile, decompile, recompile, run
python tests/compile_rate.py arm64 40 40       # real /usr/bin functions whose output compiles
```

API calls are typed from a library of 206 system prototypes (libc, POSIX, CoreFoundation, the
Objective-C runtime), and Objective-C methods decompile to valid Objective-C. 32-bit ARM/Thumb has
fewer verified idioms than arm64/x86-64. MIPS and RISC-V decompile through the IR,
tested on Debian's static busybox (1,200 functions, 0 failures). The pseudo-code is a reconstruction
of what the machine code computes, not the original source.

## Install

rdis needs Python 3.9 or newer and git. It installs into its own virtual environment.

macOS and Linux:

```sh
python3 -m venv ~/rdis-env
source ~/rdis-env/bin/activate
pip install "git+https://github.com/sagarchive/rdis.git"
rdis-gui                         # opens http://127.0.0.1:8000, then drop a binary on the page
```

Windows (PowerShell):

```powershell
py -m venv $HOME\rdis-env
$HOME\rdis-env\Scripts\Activate.ps1
pip install "git+https://github.com/sagarchive/rdis.git"
rdis-gui                         # then drop a binary on the page
```

If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
Next time, activate the environment again and run `rdis-gui`. To open a file straight away, pass
its path: `rdis-gui path/to/YourApp`. To update, run
`pip install --upgrade "git+https://github.com/sagarchive/rdis.git"`.

From source: `git clone https://github.com/sagarchive/rdis.git && cd rdis`, then `pip install .` inside
the environment. Extras: `pip install '.[desktop]'` (native window), `pip install '.[ir]'`
(Ghidra P-code semantics for the IR decompiler).

Optional external tools unlock more: `swift-demangle`, `c++filt` (demangling), `dot` (rendered
graphs), `lldb` (debugger).

## CLI

```sh
export PYTHONPATH=.
python -m rdis BIN                      # list functions
python -m rdis BIN -f main              # disassemble (annotated with names + strings)
python -m rdis BIN -f main -d           # decompile to C pseudo-code
python -m rdis BIN -f main --cfg | dot -Tpng -o cfg.png
python -m rdis BIN --strings
python -m rdis BIN --classes            # Objective-C / Swift declarations
python -m rdis BIN --imports
python -m rdis BIN --arch arm64 ...     # pick a fat Mach-O slice
python -m rdis blob.bin --loader raw --arch arm64 --base 0x8000 -f start -d   # headerless firmware
```

Add `--json` to most commands for machine-readable output.

## GUI

```sh
rdis-gui /path/to/binary --arch arm64        # opens http://127.0.0.1:8000 in your browser
rdis-gui /path/to/binary --desktop           # native window (needs the [desktop] extra)
```

Familiar three-pane layout: navigator (Proc / Str / Imp / Cls + filter) · disassembly with
clickable call targets · inspector (binary info, sections, cross-references). The top toggle
switches **Assembly / Pseudo-code / CFG / Hex**. Double-click a function to rename it; double-click an
instruction address to comment. Renames and comments save to `<binary>.rdb` next to the binary and
reload automatically.

Drop any file on the page: native binaries (Mach-O/ELF/PE/`.so`/`.dylib`) open directly;
**APK/IPA/AAR/JAR/ZIP**, **DMG** images and **tar** archives show a loader dialog listing the native
binaries inside; **gzip/xz/bzip2** files are decompressed automatically; and anything unrecognized
opens as a **raw** binary at a chosen architecture. Pick one (e.g. `lib/arm64-v8a/…​.so`), or
click **Open all N libraries** to load the whole package at once — every library becomes a switchable
document in the toolbar list and is analyzed lazily the first time you open it, so even a 200-library
APK opens instantly. Unchecking **Start automatic analysis** lists a file without analyzing it yet
(it analyzes when you select it). WebAssembly `.wasm` modules disassemble to their instruction
listing. (Dalvik `.dex` is Java bytecode — use a DEX tool like jadx; rdis is a native-code decompiler.)

### Hosting it for several people

```sh
rdis-gui --host 0.0.0.0 --port 8000          # public bind: automatically per-visitor
rdis-gui --multi-user                        # or force per-visitor sessions on loopback (behind a proxy)
```

Each visitor gets their own cookie session and their own documents, renames and navigation — nothing
is shared between people. When several open the **same** binary it is analyzed **once** and the heavy
read-only data is shared, so memory scales; each person's edits stay private. A public bind also
disables server-path opening and the `py` console command.

**Security boundary:** cookie sessions are isolation, not authentication. A public bind accepts
unauthenticated uploads and asks native parsers to inspect untrusted files; per-file upload limits
do not provide aggregate disk, CPU or memory quotas. Do **not** expose this server directly to the
internet as a multi-tenant service. Put it behind a trusted reverse proxy that enforces authentication,
request/time/resource limits and network policy, and keep the process least-privileged. The optional
`--multi-user` mode assumes the operator has already secured the proxy and does not itself provide
login or authorization.

The existing 20-visitor concurrency stress test (`tests/concurrency_test.py`) covers the tested
session workload, not every possible interleaving or hostile request. Works in current Chrome,
Firefox, Safari and Edge (the CFG uses viz.js/WASM and degrades to a notice if it can't load).

## Library

```python
from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler

prog = Program(open_image("/bin/ls", arch="arm64")).analyze()
for addr, name in prog.names.items():
    if addr in prog.functions:
        print(hex(addr), prog.display(addr))
print(Decompiler(prog, prog.functions[prog.resolve("_main")]).c())
```

## MCP server (for AI agents / REA)

Zero third-party dependencies — speaks MCP stdio JSON-RPC directly.

```sh
PYTHONPATH=. python -m rdis.mcp_server
```

Register in an MCP client with command `python`, args `["-m","rdis.mcp_server"]`, `cwd` = this repo
(use the venv's python). Tools (12): `info`, `list_functions`, `disassemble`, `decompile`, `cfg`,
`strings`, `imports`, `classes`, `xrefs`, `hexdump`, `rename`, `comment`.

These cover the native-provider surface [REA](https://github.com/morluto/rea) expects (pseudocode,
assembly, strings, symbols, calls, references), so rdis can act as a REA analysis provider in place
of Hopper/Ghidra/IDA.

## Plugins

Drop a `.py` file in `./plugins` (or `$RDIS_PLUGINS`) that registers at import:

```python
from rdis import plugins
plugins.register_loader("myfmt", probe_fn, load_fn)   # custom file format
plugins.register_arch("mycpu", arch_factory)          # custom CPU backend
plugins.register_tool("name", fn, "help")             # extra MCP/CLI tool
```

See `rdis/raw.py` for a complete loader plugin (headerless blobs).

## Tests

```sh
PYTHONPATH=. .venv/bin/python tests/test_rdis.py
```

Loads and fully analyzes system binaries, compiles small C/Objective-C/Swift fixtures (if `clang`/
`swiftc` are present) and checks disassembly, decompilation, type/variable recovery, struct-field
access, name recovery, Objective-C/Swift metadata (incl. protocols & conformances), and xrefs.

**Stress-tested** against 699 real binaries (Mach-O/ELF/PE across x86/x64/ARM/ARM64) covering
47k+ functions: zero crashes, zero malformed output. Large binaries analyze fast (bash ~2.5s,
dyld ~4.5s end to end).

## Layout

```
rdis/
  loader.py      formats -> uniform Image (Mach-O/ELF/PE + chained fixups)
  arch.py        CPU backends: decode + branch/data-ref facts
  analysis.py    functions, basic blocks, xrefs, strings
  decompile.py   CFG structuring (dominators, loops) -> nested C
  lift.py        per-block symbolic execution -> C statements
  objc.py        Objective-C runtime metadata + type-encoding decoder
  swift.py       Swift 5 type metadata
  demangle.py    Swift / C++ demangling via system tools
  render.py      annotated disassembly + DOT
  debug.py       LLDB batch wrapper
  mcp_server.py  MCP stdio server
  plugins.py     loader / CPU / tool registry
  raw.py         example plugin: headerless blobs
```
