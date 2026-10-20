# Feature support matrix

What rdis does, how each capability is tested, and where it stops. Loading a file, decoding its
instructions, finding functions, recovering control-flow edges, lifting to an IR and producing
equivalent C are separate levels of support, and a capability is only listed as verified for the
bounded behavior a test actually checks. Nothing here is a claim of parity with another tool.

| Status | Meaning |
|---|---|
| **Verified (bounded)** | A test with an independent oracle proves the stated behavior on the stated inputs. |
| **Partial** | Implemented and tested in part; the gaps column says what is not covered. |
| **Unsupported** | Not implemented. The product reports this rather than guessing. |

## Inputs

| Capability | Source | Evidence | Status | Not covered |
|---|---|---|---|---|
| Mach-O (thin and fat), ELF, PE | `rdis/loader.py` | product self-check; compiled ELF used by the browser tests | Partial | independent segment/offset truth per format; fat Mach-O and PE fixtures; malformed headers beyond fuzzing |
| Mach-O `LC_FUNCTION_STARTS` | `rdis/loader.py` | `/bin/ls` yields all 50 starts (LIEF's own list returns 24) | Verified (bounded) | `__DATA` function pointers |
| APK, IPA, AAR, JAR, ZIP, TAR, DMG, gzip/xz/bzip2 | `rdis/containers.py` | extraction, replacement and malformed-input tests in `tests/test_hardening.py` | Partial | nested depth, duplicate members, symlink and traversal corpus |
| Raw firmware blobs | `rdis/raw.py` | raw fixtures for every SLEIGH CPU in `tests/test_sleigh.py` | Partial | endianness/mode autodetection |
| WebAssembly parsing and function list | `rdis/wasm.py` | malformed-module mutation tests | Partial | spec-suite coverage; CFG and pseudo-code are explicitly unsupported |

## CPUs

| CPU | Source | Evidence | Status | Not covered |
|---|---|---|---|---|
| x86, x86-64 | `rdis/arch.py`, `rdis/lift.py` | 124-case execution-checked suite; 95.5% of 973 `/usr/bin` functions recompile; instruction-boundary fixtures | Partial | semantic equivalence beyond the suite; decoder opcode coverage |
| ARM, Thumb | `rdis/arch.py`, `rdis/lift.py` | boundary fixtures; mapping-symbol handling | Partial | interworking (`blx`) fixtures; fewer verified idioms than arm64 |
| ARM64 | `rdis/arch.py`, `rdis/lift.py`, `rdis/ir.py` | maturity suite; 97.3% of 1,085 functions recompile; hand-encoded branch CFG (4/4 edges) | Partial | larger licensed corpus; indirect-edge recall |
| MIPS32/64 (BE/LE), RISC-V 32/64 + RVC | `rdis/arch.py`, `rdis/ir_front.py` | boundary fixtures; busybox decompile run (1,200 functions, 0 failures) | Partial | ABI fixtures; branch-likely semantics; FP and atomics |
| PowerPC, 68k, AVR, MSP430, SPARC, SuperH, Z80, 6502, Xtensa, eBPF, LoongArch | `rdis/sleigh.py` (optional `pypcode`) | hand-assembled program per CPU, as raw blob and inside a real ELF: functions, call edge, 3-block CFG with delay slots, IR decompile (`tests/test_sleigh.py`) | Partial | no compiler-built corpus; no data cross-references; AVR registers appear as memory; SPARC register windows unmodelled |
| TriCore and the other endian/word-size variants; any of 194 `sleigh:<id>` languages | `rdis/sleigh.py` | same code path, no fixture of their own; language ids and ABI register names validated against the specs | Partial | no calling convention for `sleigh:<id>`, so parameters and returns are not recovered |

## Analysis

| Capability | Source | Evidence | Status | Not covered |
|---|---|---|---|---|
| Function discovery | `rdis/analysis.py` | compiler-built 7-function fixture, precision/recall/F1 = 1.0 for x86-64 ELF and ARM64 Mach-O at `-O0`/`-O2`, symbols and stripped | Verified (bounded) | other compilers, larger corpora, shared and overlapping tails |
| Very large binaries | `rdis/analysis.py` | 130 MB stripped Bun executable: 72,891 functions in 716 s at 8 GB peak (previously did not finish) | Verified (bounded) | no competitor timing on the same file; Python per-instruction overhead dominates |
| CFG edges | `rdis/analysis.py` | direct switch 48/48 edges at `-O0`; optimized x86-64 relative jump table 14/14 at `-O2`; AArch64 4/4; x86 loop 3/3; all F1 = 1.0 | Verified (bounded) | absolute-pointer tables; other compilers and ISAs |
| Unresolved indirect transfers | `Program.unresolved`, MCP `unresolved` | same x86-64 jump-table dispatcher with and without its bounds check: 6/6 edges versus none invented; bare `jmp rax`, `call rax`, AArch64 `br`/`blr` reported, not guessed (`tests/test_cfg_unresolved.py`) | Verified (bounded) | absolute-pointer tables; exception and unwind flow |
| Binary diffing and annotation transfer | `rdis/diff.py`, `rdis/fingerprint.py`, `--diff`, MCP `diff` | two builds of a 36-function program (5 modified, 3 deleted, 3 added, order reversed), scored against symbol-table truth, same flags, stripped: macOS arm64 clang precision 0.974 / recall 0.884, Linux x86-64 gcc precision 0.972 / recall 0.814; with symbols 100% on both; renames and comments transfer only at confidence >= 0.9 and never overwrite (`tests/test_diff.py`) | Verified (bounded) | across optimization levels recall falls on gcc (-O1 to -O2: precision 1.0, recall 0.09; clang stays at 0.88); modified functions with structural twins and no call context stay unmatched; one near-clone replacement is mispaired when stripped; synthetic corpus, no real release pairs |
| Library recognition (local signatures) | `rdis/signatures.py`, `--sig-make`, `--sig`, MCP `signatures` | database from build v1's symbols applied to the stripped v2: macOS clang 28 named, 28 correct, 0 wrong; Linux gcc 26 named, 26 correct, 0 wrong, 8 ambiguous (byte-identical wrappers); 0 names on an unrelated system binary (`/bin/ls`); ambiguous hashes and functions under 8 instructions are never auto-named (`tests/test_signatures.py`) | Verified (bounded) | no bundled signature corpus for libc or libc++; exact-hash only, so a recompiled or edited function is not recognised |
| Call graph (callers, callees, both) | `rdis/render.py`, GUI, CLI, console, MCP | unit tests; Chromium and Firefox geometry tests | Partial | independent call-graph precision/recall |
| Decompiler and typed IR | `rdis/decompile.py`, `rdis/ir.py` | 124/124 execution-equivalence cases | Partial | optimized exceptions, aliasing, vectors; address mapping from C back to instructions |
| Objective-C, Swift, JNI metadata | `rdis/objc.py`, `rdis/swift.py`, `rdis/jni.py` | self-check fixtures | Partial | versioned real binaries; malformed metadata |

## Interfaces

| Capability | Source | Evidence | Status | Not covered |
|---|---|---|---|---|
| Web UI, multi-user sessions | `rdis/server.py`, `rdis/web/index.html` | 20-visitor isolation and determinism test; Chromium and Firefox graph tests | Partial | route-by-route threat review; keyboard-only and screen-reader review |
| MCP server (33 tools) | `rdis/mcp_server.py` | typed schemas with read-only annotations; JSON-RPC error codes over a real stdio process; structured tool errors without tracebacks; pagination arithmetic; read-only tools proven not to write a sidecar; response-size guard (`tests/test_mcp_contract.py`) | Verified (bounded) | cancellation of a running tool; audit log and undo for writes; multi-client write coordination |
| Persistent cache and `.rdb` annotations | `rdis/cache.py`, `rdis/analysis.py` | invalidation and replacement regressions | Partial | schema migration; multi-process races |
| LLDB debugger | `rdis/debug.py` | argument-sanitization regression | Partial | remote targets; mapping a stopped PC to the static CFG |
| Plugin SDK | `rdis/plugins.py` | plugin loaders and architectures exist | Partial | versioned contract; broken-plugin isolation |
| P-code emulation | `rdis/emulate.py`, `--emulate`, MCP `emulate` | 135 compiled `-O2`/`-O3` scalar and array cases agree with native execution on arm64 and x86-64 (0 mismatches); on auto-vectorized NEON code 9 of 15 agree and 6 stop with an explicit unsupported-intrinsic error, none wrong (`tests/test_emulate.py`) | Verified (bounded) | no vector intrinsics, floating-point returns, system calls or threads; integer arguments only |
| Symbolic execution, taint | none | none | Unsupported | |
