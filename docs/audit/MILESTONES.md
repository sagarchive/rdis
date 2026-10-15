# RDIS Precision Engineering Milestones

Milestones are not complete until their acceptance gates have reproducible evidence. This PR is an initial hardening tranche; it does not claim the full programme is complete.

| ID | Scope | Current status | Exit gate |
|---|---|---|---|
| M0 | Baseline, inventory, evidence discipline | IN PROGRESS | Clean-environment test baseline recorded |
| M1 | Cache/document identity and concurrency | IN PROGRESS | Exact-content invalidation and concurrency tests pass |
| M2 | Binary/container safety and address mapping | IN PROGRESS | Bounded extraction and address interval tests pass |
| M3 | Web/MCP/debugger/plugin trust boundaries | IN PROGRESS | Threat model and negative security tests pass |
| M4 | Disassembly/function/CFG correctness | IN PROGRESS | Per-architecture discovery fixtures pass; precision/recall measured |
| M5 | IR and decompiler semantics | PLANNED | Execution-based semantic corpus passes; unsupported cases counted |
| M6 | Type recovery/platform metadata | PLANNED | Versioned metadata and ambiguity tests pass |
| M7 | UI, CLI, API, rendering | IN PROGRESS | End-to-end workflows, escaping and schema tests pass |
| M8 | Fuzzing and differential tests | IN PROGRESS | Fuzz campaign triaged; all crashes minimized into regression tests |
| M9 | Performance and scale | PLANNED | Reproducible baseline and before/after results recorded |
| M10 | Packaging and release | IN PROGRESS | Clean source/wheel/container install and entry points verified |

## M0 — Baseline
Pin commit and record Python/OS/dependency/compiler versions. Run existing test entry points in a clean environment, recording exact commands, exit codes, skips and blockers. Inventory all modules, public APIs, subprocesses, persistence paths, trust boundaries and map tests to invariants. README claims remain unverified until reproduced.

## M1 — Identity and caches
Define canonical analysis identity including content digest, loader, architecture/mode, base, entry point/options, relevant plugin configuration and schema/version. Audit persistent, web, MCP, document and extraction caches together. Test same-path replacement preserving size/mtime, option changes, corrupt cache, concurrent cold misses, eviction and shared-state mutation. Exit only when changed inputs cannot reuse incompatible results and caches are bounded.

## M2 — Input safety
Validate sizes, offsets, address ranges and malformed metadata. Stream decompression/extraction with explicit byte limits; reject oversized or incomplete output. Bind extraction entries to archive content and member identity. Test ZIP/TAR paths, duplicates, symlinks, corrupt streams, huge archives, invalid limits, cleanup, overlapping sections, gaps and interval boundaries.

## M3 — Security
Test local/public/multi-user/proxy modes, Host/Origin/CSRF controls, session isolation, path opening, Python evaluation, uploads, quotas, request deadlines, subprocess limits and cleanup. Treat Python plugins as executable trusted code unless a real sandbox exists. Exit only when privileged capabilities have explicit policy and negative tests.

## M4 — Disassembly and CFG
Cover direct/indirect calls, tail calls, jump tables, exception edges, recursion, overlapping code/data, stripped binaries, ARM/Thumb, MIPS delay slots, RISC-V compressed instructions and invalid streams. Measure discovery precision/recall on labelled fixtures.

## M5 — Decompiler semantics
Verify width, signedness, extensions/truncation, flags, overflow, memory effects, ABI, stack variables, branch/loop/merge semantics, floating point, SIMD lanes and unsupported instructions. Compile and execute generated code where applicable; compile rate alone is not correctness.

## M6 — Metadata
Test prototypes/conflicts, unknown imports, demangling failure, JNI bounds, Objective-C runtime variants, Swift relative pointers/version changes, malformed strings, duplicate names and partial metadata. Separate observed facts from inferred types.

## M7 — UX/API
Test HTML/SVG/JS escaping, large CFGs, missing assets, malformed requests, CLI exit codes, JSON schemas, accessibility, cancellation and parity between web/CLI/Python/MCP.

## M8 — Fuzzing
Run bounded reproducible fuzz campaigns on parsers and transformation boundaries. Minimize and preserve every crash/semantic mismatch. Differential comparisons must account for reference-tool versions and known semantic differences.

## M9 — Performance
Benchmark cold/warm analysis, first-result latency, full runtime, cache cost, peak memory, rendering, archive enumeration and concurrency using a fixed corpus/environment. Never trade correctness for speed.

## M10 — Release
Test clean source and wheel installs, supported Python/dependency versions, optional extras, packaged assets, Docker runtime, non-root operation and documented commands.

For every milestone record files, commit, exact commands, pass/fail/skip, results, benchmark deltas, remaining issues and DONE/IN PROGRESS/BLOCKED.