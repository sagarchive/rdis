# RDIS Engineering Milestones

Milestone status is evidence-based. A row stays IN PROGRESS until its stated exit gate passes on a recorded revision; prior successful runs do not automatically validate later changes.

## Repository-of-record and scope policy

This file is the single source of truth for milestone state, audit findings that need follow-up, validation evidence, and known blockers. Keep the PR's standalone research documentation intentionally small:
- Keep this milestone file and `docs/audit/COMPETITIVE_ROADMAP.md`.
- Put implementation evidence in executable tests and GitHub Actions; put user-facing product claims and usage in `README.md` and GitHub Pages.
- Do not add parallel audit registers, worklogs, test matrices, threat-model documents, benchmark protocols, resume notes or duplicate competitor inventories unless they are independently useful to end users or legally/operationally required. Consolidate their unique, still-relevant findings here or in the competitor roadmap, then remove redundant files from this PR.
- Before every code tranche: re-read this file, select one milestone, inspect every changed file and its callers/callees, write regression tests first when practical, implement the smallest safe change, run the narrow test, run the relevant broad test(s), inspect screenshots/artifacts, then update the status with the exact verified commit/run. Never call a milestone DONE based on an earlier commit.
- A passing CI run proves only its recorded revision and executed assertions. It does not prove feature parity, full security, semantic correctness for untested instructions, or that RDIS is universally better than a competitor.


| ID | Scope | Current status | Exit gate |
|---|---|---|---|
| M0 | Baseline, inventory, evidence discipline | IN PROGRESS | Clean-environment test baseline recorded |
| M1 | Cache/document identity and concurrency | IN PROGRESS | Exact-content invalidation tests and 20-visitor isolation/determinism stress pass; next source-flow audit must test whether `.rdb` sidecars are bound to the binary content they annotate and whether copy-on-write xref access leaks mutations through `get()`; wider multi-process cache races remain open |
| M2 | Binary/container safety and address mapping | IN PROGRESS | Bounded extraction and address interval tests pass |
| M3 | Web/MCP/debugger/plugin trust boundaries | IN PROGRESS | Bounded workers/analyses, request timeouts and configurable aggregate upload/extraction quota added; cleanup/retention and deployment security review remain open |
| M4 | Disassembly/function/CFG correctness | IN PROGRESS | Per-architecture discovery fixtures pass; precision/recall measured |
| M5 | IR and decompiler semantics | IN PROGRESS | Typed/provenance IR contract and canonical IR API now exposes per-op source attribution: NativeFront maps delay-slot ops to their actual addresses; pypcode multi-address IMARK bundles mark unprovable op origins inexact and preserve candidate addresses rather than guessing. FLOAT_NAN is typed as bool. IR JSON contract is schema v2. Regression coverage and end-to-end typed IR tests passed at commit `3846522257716e2695af89e32234c124de932640` in [CI run 38759746298](https://github.com/sagarchive/rdis/actions/runs/38759746298), including Python 3.10/3.12, Chromium, Firefox, and the macOS semantic/maturity suite. Still verify width/sign/flag/trap/memory effects, SSA and memory-SSA, aliasing, ABI, vector/floating semantics, unsupported-op tracking, and a larger current-head execution-equivalence corpus. Compile success is not semantic correctness |
| M6 | Type recovery/platform metadata | IN PROGRESS | StructDB retains access widths/type evidence, merges supported call links, emits packed/overlapping views and reports repeated-access array candidates without automatically asserting arrays; compiler-backed size/offset checks cover packed and overlap layouts. Still verify nested object graphs, signed/float/pointer conflicts, debug-info import, target ABI differences, metadata-version drift and confidence/provenance surfaced to users |
| M7 | UI, CLI, API, rendering | IN PROGRESS | CFG overview/detail layouts, pointer-centered wheel zoom, Shift+wheel pan, painted-pixel fit, aspect-aware schematic minimap, click-to-recenter, readable entry-focused start for tall/wide graphs, standalone SVG theme resolution and keyboard-focusable rounded nodes are implemented. On commit `c6f477b2`, Chromium and Firefox tests passed for 7-node branch/loop, 48-node tall, 180-node stress, 15-node wide fan-out/join and a pinned compiled ELF through the live RDIS server. Screenshot review caught and fixed three actual issues: Graphviz group styling washed out labels; SVG local transforms made the minimap viewBox miss its graph; and preserving the full aspect ratio compressed tall-graph blocks into a line. The minimap now maps transformed bounds to root SVG coordinates, draws a transparent viewport window, and deliberately uses a schematic full-frame scale; browser tests require visibly paintable block silhouettes and accurate viewport coverage, not only DOM node counts. Full-fit of the 180-node CFG reaches ~4% and is a topology overview rather than a reading mode; entry-focused zoom plus the minimap is the intended inspection path. A further screenshot review found two additional defects: wide fan-out CFGs opened at 100% with most branch destinations clipped, and standalone SVG export used the local graph bounding box as the root viewBox when Graphviz translated `g.graph`. Wide entry view now starts at 60–75%, dense tall minimaps use a taller thin-outlined thumbnail, and export transforms all four graph-bound corners into root-SVG coordinates. The full cross-browser and product run `38845070272` passed all five jobs on code/test commit `7621fb441a39fb25e3c0458bb044e28d69131fb2`; artifacts include real-ELF, dark/light, detail, keyboard focus, 180-node entry/fit, minimap navigation, wide fan-out and the standalone SVG whose viewBox is regression-checked against transformed root bounds. M7 remains open for dense switch/jump-table/Unicode/parallel-edge fixtures, manual screen-reader review and broader UI workflows. |
| M8 | Fuzzing and differential tests | IN PROGRESS | Deterministic malformed-WebAssembly mutation smoke test added to CI; sustained fuzz campaign and crash minimization remain open |
| M9 | Performance and scale | IN PROGRESS | Repeatable single-binary benchmark harness and CI smoke baseline added; fixed-corpus cold/warm and concurrent p50/p95 baselines still required |
| M10 | Packaging, release and discoverability | IN PROGRESS | Source/wheel/CLI/MCP checks and canonical/OG/Twitter/schema/sitemap/llms validation added to CI. Authoritative host-root robots policy remains blocked by the GitHub Pages project-site path unless a custom domain or account-root Pages site is configured |
| M11 | Competitive parity and measured differentiation | IN PROGRESS | Build a versioned, reproducible feature and correctness matrix for IDA/Hex-Rays, Ghidra, Binary Ninja, Hopper, Rizin/Cutter, angr and package/managed-code tools; run common ground-truth corpora where licensing/tool availability permits. No blanket 'beats them' claim without comparative data |
| M12 | Source-flow audit and PR scope discipline | IN PROGRESS | Every production Python module and browser/API flow is reviewed against callers, state mutation, errors, resource limits and tests; this PR carries only this milestone register and the competitor roadmap as added research documents |

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

For each milestone record the touched files, exact commit, Actions run, test commands, pass/fail/skip, artifact links, measured deltas and open issues directly in this file. Keep bulky execution data as CI artifacts; do not create another tracking document.

## M11 — Competitor parity and measurable differentiation

Use `COMPETITIVE_ROADMAP.md` as the detailed comparison and source index. Re-check official product documentation before making public claims. Separate:
1. Feature existence (documented / reproduced / absent / unknown).
2. Correctness (ground-truth fixtures, exact bytes/addresses/edges/types and execution equivalence).
3. Performance (same machine, corpus digest, tool version, options, repeated cold/warm runs, peak RSS and latency distributions).
4. Workflow quality (time-to-first-useful-result, navigation steps, state persistence, exports, scripting and batch reliability).

For the RDIS differentiators—open-source Python workflow, low-friction install, package-aware native library triage, multi-session browser UI, MCP/API—measure task completion and resilience, not just checklist presence. Compare against the strongest relevant competitor for each task rather than picking one tool as a universal baseline. Do not infer decompiler superiority from compilation rate or prettier pseudocode alone.

## M12 — Source-flow audit and PR hygiene

For every production module and high-risk flow, record the invariant and a regression test or an explicit reason testing is infeasible:
- Input bytes → format/container loader → mapped address/section → instruction decode → function discovery → basic blocks/CFG → xrefs/call graph → IR/lifter → decompiler/types/structs → render/API output.
- HTTP upload/session/cache/document lifecycle; MCP JSON-RPC/tool validation/cache/output limits; CLI argument parsing and exit status; database/cache serialization and invalidation.
- Plugin imports and debugger subprocesses; optional dependency missing/failure paths; browser loading/error/cancellation/theme/resize/large graph/export.
- Package metadata/entry points/asset inclusion; GitHub Pages canonical links, accessible navigation, install commands and scope-accurate comparison claims.

Close a finding only when its regression is present and the relevant test runs on the current candidate revision. Keep this PR focused: changed production behavior, meaningful tests, README/GitHub Pages updates, this file, and the competitor roadmap. Redundant planning records are not release artifacts.
