# RDIS: Competitive Parity and Product-Quality Roadmap

**Snapshot date:** 2026-10-19  
**Baseline branch:** main  
**Baseline commit inspected:** 96b931d32c807c5430518be6c280c98fb995ebb2  
**Purpose:** the authoritative, resumable engineering plan for pursuing category-leading reverse engineering—not a claim that feature parity or superiority has already been achieved.

## 0. Resume contract — read this first on every RDIS task

This document is the durable source of truth for ongoing RDIS work. The repository agent instructions in AGENTS.md require every RDIS-related session to read this document before acting.

**Current program state**
- Program: initialized; the product roadmap and evidence gates are being established on a separate draft-PR branch.
- Active milestone: M00 — baseline and evidence ledger.
- Current atomic task: add the deterministic runner for the committed `tests/baseline_corpus.json`, run it as part of the Python/macOS CI profiles, and inspect the machine-readable result/log artifacts. The corpus manifest already exists on this branch; the runner and its acceptance tests are the remaining M00 implementation gate.
- Last known main commit: 96b931d32c807c5430518be6c280c98fb995ebb2.
- Main-head verification: [hardening CI passed](https://github.com/sagarchive/rdis/actions/runs/39228787777) and [GitHub Pages deployment passed](https://github.com/sagarchive/rdis/actions/runs/39228786794).
- Product-code evidence inherited from merged PR #3: [full five-job verification on the review-fix commit](https://github.com/sagarchive/rdis/actions/runs/39228116226). Its feature work is on main; the later main commit primarily removed the old public roadmap documents and updated related CI/doc references.
- Do not assume the last known commit is still current. At the start of every resumed session, fetch current main, this file, the active PR/branch and the latest CI runs.

### Non-negotiable continuation procedure

1. Read this file completely before editing code, docs, workflows, or Pages for an RDIS task.
2. Compare current main and the working branch. Never resume from conversation memory when git history, the working tree, or CI provides better evidence.
3. Inspect the latest request entry at the bottom under **Append-only request ledger**, then locate the linked active milestone and its exact next atomic action.
4. Run the narrowest relevant tests first, add a regression for every confirmed defect, then run the wider affected suites. After a fix, rerun the failing test and the full required suite—do not merely edit the code and assume it works.
5. Update this file as work proceeds: milestone status, evidence links, commit SHA, tests and outcomes, known defects, and the next atomic action. Update the resume cursor before stopping.
6. Record new RDIS requests at the very end of the document. Do not overwrite or silently drop earlier entries. Link every request to the milestones it affects.
7. Mark an item **DONE** only when its written exit gate has reproducible evidence at a named commit. Source inspection, successful compilation, a pretty screenshot, a vendor feature page, or an AI opinion alone is not correctness proof.
8. Report failures and limitations plainly. Never invent results, screenshots, benchmark numbers, competitor behavior, or completed milestones.
9. Keep changes incremental and reversible. Use a conventional branch name, focused commits, one draft PR for the current user-directed work, a complete PR description and CI evidence. **Do not merge the PR** unless the user explicitly asks.
10. The user’s ambition is to beat the combined feature set of the competitors below. Treat that as the long-term objective, not permission to overclaim. The way to win is a breadth roadmap plus unusually strong correctness evidence, speed, usability, automation and workflow—not a feature-count contest alone.

If the work is interrupted, do not restart from scratch or ask the user to repeat context. Read the resume cursor, inspect the recorded commit and active branch, rerun the last failed or uncertain gate, update the ledger, and continue with the next atomic action.

## 1. Goal and definition of “beat competitors”

RDIS should become a first-choice reverse-engineering environment by combining:

- The analysis depth and decompilation quality expected from IDA Pro/Hex-Rays, Ghidra and Binary Ninja.
- The approachable, responsive graph/listing/navigation flow users expect from Hopper and Cutter.
- The breadth of CLI automation, emulation, analysis and patch workflows found in radare2.
- The deeper control-flow reasoning, symbolic execution and data-flow analyses represented by angr.
- The cross-format, cross-architecture reconstruction goals of RetDec and comparable decompilers.
- Reliable project persistence, version matching, scripting, plugin extensibility and debugging.
- A secure, low-friction browser workspace, package-aware loading, multi-user sessions, transparent evidence and agent automation.
- Better reproducibility: each supported claim can be reproduced from a pinned input corpus, tool version, command and output artifact.

“Beat” is not a subjective claim that RDIS is universally better. The release objective is to meet or exceed chosen reference tools on explicitly defined workflows, cover the competitors’ important workflows, and outperform them in RDIS’s chosen differentiators. A feature is not complete merely because there is a button or API endpoint. It must be correct, robust, accessible, fast enough, documented and tested.

### Product principles

1. **Correctness before apparent sophistication.** A smaller, semantically sound decompiler is more valuable than a wide, misleading one.
2. **Unknown is a valid result.** Preserve uncertainty for unresolved branches, indirect calls, inferred types and guessed symbols. Do not convert a heuristic into a false fact.
3. **Architecture support is a matrix, not a checkbox.** File opens, instructions decode, functions are found, edges are correct, types recover and decompilation semantics pass are different levels of support.
4. **Evidence beats marketing.** Publish reproducible metrics and explicit unsupported cases.
5. **Analyst state is a first-class asset.** Names, comments, types, bookmarks, patches, traces and review findings must survive restarts and binary updates.
6. **Automation is a product surface.** CLI, Python API, MCP and GUI must share stable schemas, analysis identity and meaningful errors.
7. **Safe by default.** Treat binaries, archives, project files, plugin code, debugger inputs and remote clients as untrusted.
8. **Measure the user’s whole task.** Load time, finding a function, following a path, comparing builds and exporting evidence matter more than a microbenchmark alone.
9. **Do not copy a feature without understanding its trade-offs.** Reproduce the user value, then design a maintainable RDIS-native implementation.
10. **Keep internal planning private from the marketing funnel by default.** This roadmap is in the repository for resumable engineering but is not linked from GitHub Pages, the sitemap or docs/llms.txt unless the user expressly requests publishing it. That respects the latest main commit’s removal of public audit/strategy-document links.

## 2. Current source baseline

### Verified from repository source

The current tree contains the main analysis modules: analysis.py, arch.py, loader.py, containers.py, cache.py, decompile.py, ir.py, ir_front.py, ir_model.py, lift.py, lift_simd.py, wasm.py, render.py, server.py, mcp_server.py, debug.py, plugins.py, typelib.py, objc.py, swift.py and jni.py, with supporting architecture/metadata modules.

Current test surfaces include:
- tests/test_rdis.py — product self-check.
- tests/maturity.py and tests/maturity_cases.py — execution-checked decompiler corpus.
- tests/compile_rate.py — real-binary compilation rate; **compilable output is not the same as semantically correct output**.
- tests/diffcheck.py — differential comparison.
- tests/test_ir_model.py and tests/test_ir_semantics.py — typed-IR contracts and semantic regressions.
- tests/test_hardening.py — cache, malformed-input, resource and rendering regressions.
- tests/browser_cfg.mjs — browser CFG regression suite.
- tests/concurrency_test.py — concurrent session isolation and deterministic output.
- tests/benchmark_analysis.py — repeatable analysis timing.

The merged PR #3 reports 124/124 execution-checked decompiler cases passing on the reviewed code, with separately measured real-binary C compile rates of 97.3% on 1,085 arm64 functions and 95.5% on 973 x86-64 functions in the stated corpus. Those are useful scoped results, **not proof of parity across all architectures or binaries**. See [the merged PR](https://github.com/sagarchive/rdis/pull/3) and its [post-review-fix CI run](https://github.com/sagarchive/rdis/actions/runs/39228116226).

The merged CFG work has a real Chromium/Firefox browser suite for small branch/loop graphs, tall and stress graphs, wide fan-out graphs and a compiled ELF opened through the live RDIS server. It checks graph/label bounds, navigation, minimap, keyboard actions, dark/light contrast and standalone SVG export. The recent full verification also passed the Python 3.10/3.12 hardening jobs and macOS self-check/maturity/concurrency jobs. This is current evidence for those fixtures; it is not yet a full accessibility, cross-platform, or dense real-world graph certification.

### Not established yet

The repository does **not** yet establish a current apples-to-apples benchmark against each competitor, function discovery precision/recall by architecture, broad CFG edge F1, comprehensive semantic equivalence across all advertised architectures, a sustained fuzzing budget, a verified vulnerability-analysis quality score, project-version tracking parity, a full interactive debugger parity matrix, or complete type-recovery accuracy. These gaps must remain visible until measured.

## 3. Primary competitor references

Research checked on 2026-10-19. These primary documents are evidence that a product documents a capability; they do **not** prove its accuracy or comparative quality.

| Reference product | Primary source | Capabilities to benchmark |
|---|---|---|
| IDA Pro / Hex-Rays | [IDA Pro official feature page](https://hex-rays.com/ida-pro); [official IDA MCP announcement](https://hex-rays.com/blog/hex-rays-ida-mcp-server); [IDA Domain API](https://ida-domain.docs.hex-rays.com/getting_started/) | Disassembly/decompilation, interactive debugger, platform/architecture support, SDK and scripting, plugins, signature/metadata reuse, headless/library workflows, multi-agent MCP and large-project workflows. The official MCP article is dated 2026-09-25; MCP is no longer a differentiator by itself. |
| Binary Ninja | [Official features](https://binary.ninja/features/); [user guide](https://docs.binary.ninja/guide/); [debugger guide](https://docs.binary.ninja/guide/debugger/index.html); [MCP server guide](https://docs.binary.ninja/guide/mcp.html) | Multiple IL levels, analysis APIs, debugger and remote targets, plugin manager, split/synchronized views, annotation and type workflows, patching, entropy/triage views, headless processing and MCP. |
| Ghidra | [Official NSA-maintained repository](https://github.com/NationalSecurityAgency/ghidra); [version-tracking documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html); [debugger documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Debug/Debugger/src/main/help/help/topics/Debugger/Debugger.html) | Broad processor/language and format framework, decompiler, SLEIGH language specification, scripting/extensions, dynamic debugger/trace views, project workflow, version tracking and moving annotations across binary revisions. |
| Hopper | [Official tutorial](https://www.hopperapp.com/tutorial.html) | CFG/minimap and viewport navigation, block grouping and editing, comments/labels, keyboard graph navigation, disassembly arrows, breakpoints/bookmarks, pseudo-code and native analyst workflow. |
| radare2 | [Official project](https://github.com/radareorg/radare2); [intro and command guide](https://github.com/radareorg/radare2/blob/master/doc/intro.md); [ESIL emulation documentation](https://github.com/radareorg/radare2/blob/master/doc/esil.md) | CLI-first workflows, graph and call graph, debugger backends, emulation, diffing, patching, scripting, projects, signatures and extensible IO/architecture/plugin systems. |
| Cutter | [Official feature documentation](https://cutter.re/docs/user-docs/features.html); [graph overview/search/type views](https://cutter.re/docs/user-docs/menus/menu-bar/windows-menu.html) | Desktop UX on top of Rizin: synchronized decompiler and listing, graph overview, searchable strings/data/hex, type and plugin-oriented workflows. |
| angr | [Official analyses API](https://docs.angr.io/en/latest/api/angr.analyses.html); [CFG recovery documentation](https://docs.angr.io/en/v9.2.63/analyses/cfg.html); [quickstart](https://docs.angr.io/en/latest/quickstart.html) | Static CFGFast versus more expensive emulated CFG, indirect control flow, symbolic execution, path constraints, data-flow/program analysis and automation. Expect meaningful speed/completeness trade-offs rather than one universally best CFG. |
| RetDec | [Official upstream project](https://github.com/avast/retdec) | Retargetable decompilation, executable-format support, compiler/packer detection, debug-information usage, C++ class/type reconstruction and high-level output. Upstream describes itself as being in limited maintenance; use it as a technical reference, not as a presumed fast-moving product competitor. |

Do not add claims about a competitor feature until the relevant official documentation or versioned binary proves it. Re-check these sources periodically because licenses, features, product versions and support matrices change.

## 4. How progress will be measured

Create a reproducible baseline first. Never invent targets from intuition when a short benchmark can establish the current distribution. For every benchmark, save the input corpus manifest, binary hashes, compiler/tool versions, options, OS, CPU, command line, raw outputs, test result and commit SHA.

### Correctness scorecard

- **Instruction decoding:** per-architecture valid/invalid instruction fixtures; decoded address/size/bytes and mode correctness; compare decoder output against controlled encodings and a second tool where relevant.
- **Loader/address mapping:** correct format, segments/sections, address/file-offset mappings, rebasing, overlap handling, endian/mode and explicit failure on malformed metadata.
- **Function discovery:** precision, recall and F1 against symbols/debug metadata and hand-reviewed fixture truth; separately report stripped binaries, compiler, architecture, optimized code and obfuscation.
- **CFG:** node/block precision and recall, edge precision/recall/F1, branch polarity, fall-through, jump-table targets, indirect edges and function-boundary correctness. Treat unresolved edges as an explicit category rather than counting them as correct guesses.
- **Decompilation:** keep compile rate, semantic execution equivalence, type quality and human readability as separate measures. Build/run original and recompiled snippets on generated inputs; include signed/unsigned overflow, truncation, flags, shifts, floating point, memory aliasing, calling conventions, tail calls, exceptions and vector semantics.
- **Types and metadata:** compare recovered parameters, return types, variables, struct fields and symbol names with debug information/source truth; score confidence calibration and false certainty.
- **Diff/version tracking:** function match precision/recall, changed-block localization, annotation transfer success, and explicit ambiguity handling.
- **Security/reliability:** crashes, hangs, memory growth, path escapes, decompression-limit violations, state leaks, unsafe output, malformed-protocol behavior and cleanup after failure.
- **Performance/scale:** cold/warm load and analysis time, cache hit rates, p50/p95 end-to-end latency, peak RSS, concurrency throughput, large-graph render time and timeout rate.
- **Usability:** timed representative tasks (open a package, locate a function, follow a branch, identify callers, annotate, compare two builds, export evidence). Count task success and misnavigation, not only UI frame time.
- **AI/MCP quality:** useful facts per token, tool-call count, task success, citation/address provenance, invalid-call rate, latency, write safety, cross-session isolation and reproducibility.

### Competitive test rules

- Compare current stable product versions and the exact same corpus/options wherever the competitor allows it.
- Report “not comparable” when a competitor is unavailable, commercial/licensed, or uses different assumptions. Do not fabricate results or evade licenses.
- Differential disagreement is a triage signal, not proof that either tool is correct. Resolve disagreements using source/compiled fixtures, instruction manuals, debug data and execution.
- Separate synthetic fixtures, compiler-generated corpora and real-world binaries. Keep licenses and redistribution rights documented.
- Preserve all raw results. Aggregate scores must not hide a severe architectural weakness.

## 5. Priority model

- **P0 — Trust:** semantic correctness, crash/security fixes, stale cache prevention, data integrity, no cross-session leakage, deterministic regressions.
- **P1 — Core analyst capability:** function/control-flow recovery, strong IR/decompiler, types/metadata, navigation and annotation persistence.
- **P2 — Workflow breadth:** debugger, traces, binary diff/version tracking, signatures, project portability, team workflows and headless batch.
- **P3 — Advanced differentiators:** bounded symbolic execution, taint/data-flow, path exploration, evidence-linked AI assistance, scalable triage and sophisticated binary lineage.

A P2/P3 feature must not be used to mask an unresolved P0 defect. The ordering below is dependency-driven, not a promise of completion dates.

## 6. Milestone register

Statuses in this first tracker are deliberately conservative: **PARTIAL** means there is a component or existing test, not that the full exit gate is satisfied. The baseline commit is the beginning of this roadmap.

### M00 — Baseline, ownership and resumability
**Status: PARTIAL — baseline manifests, redaction tests and artifact inspection verified; clean corpus/runner gates remain**

**Why:** Work cannot reliably continue across retries if there is no exact cursor, source commit or proof state.

**Implement:** freeze current main SHA and environment details; record exact test commands, outputs and skips; inventory public feature claims versus implementations and tests; keep this register append-only; make all further work branch/PR based.

**Exit gate:** the baseline log includes main SHA, Python/dependency/tool versions, OS/CPU, reproducible commands and CI run URLs; the initial feature/claim matrix marks VERIFIED, PARTIAL, UNVERIFIED or UNSUPPORTED; a resumed session can identify the next atomic task without asking the user to repeat instructions.

### M01 — Architecture/feature truth matrix and analysis identity
**Status: PARTIAL**

**Why:** The README combines format loading, decoder availability, analysis and decompilation support. Those must not be confused.

**Implement:** per-format and per-ISA support tables covering loader, decoder, mode/endianness, function discovery, CFG, lifter/IR, decompiler semantics, metadata and debugging. Record options and implementation/version identity in cache/project fingerprints. Include the plugin and optional dependency matrix.

**Exit gate:** every advertised capability maps to implementation modules, executable tests, known limitations and CI platform/versions. Cache identity tests cover same path/content replacement, same-size/same-mtime replacement, option changes, architecture/base-address/loader changes, concurrent misses and code/schema changes. No undocumented support claim is marked production.

### M02 — Loader, container, address-space and malformed-input safety
**Status: PARTIAL**

**Why:** All analysis depends on trustworthy address mapping and safe handling of hostile files/archives.

**Implement:** fixture every supported format/container including thin/fat binaries, truncated headers, overlaps, overlays, sparse/huge intervals, invalid offsets, nested/duplicate archive entries, symlinks/traversal, corrupt CRC, interrupted extraction and compression bombs. Use streaming byte limits, time/resource budgets, atomic cache writes and guaranteed cleanup.

**Exit gate:** deterministic valid fixtures map every expected address/file offset; malformed inputs fail explicitly with no partial cache or extracted output; fuzz findings become minimized regressions; per-member limits and aggregate-storage quotas are independently enforced.

### M03 — Instruction decoding and architecture semantics matrix
**Status: PARTIAL**

**Why:** A decoder opening a file is not proof that every decoded instruction, mode transition or address is right.

**Implement:** per-architecture encoding fixtures for x86/x64 prefixes, ARM/Thumb transitions, ARM64 branch/addressing forms, MIPS delay slots/endian variants, RISC-V compressed instructions, and WebAssembly framing/stack validation. Cross-check against architecture manuals and a second decoder when feasible.

**Exit gate:** supported instruction/mode/address tests have deterministic ground truth; invalid/truncated encodings are handled explicitly; mode, instruction size and address arithmetic do not silently drift; unsupported operations are identified and measured.

### M04 — Function discovery, control-flow, indirect branches and jump tables
**Status: PARTIAL**

**Why:** Missing functions or incorrect CFG edges poison xrefs, decompilation, types and UI navigation.

**Implement:** true functions versus tail/shared/overlapping blocks, thunks, recursive calls, indirect calls/jumps, jump tables, switch ranges, exceptions/unwind metadata, delay slots, function-pointer tables, compiler prologues, stripped binaries, code/data ambiguity and entry points. Add per-architecture and per-compiler corpora. Keep known and unresolved edges distinct.

**Exit gate:** function discovery precision/recall and CFG edge F1 are reported per architecture/compiler/optimization level; every known fixture edge is correct; switch outputs never reference undeclared/foreign labels; indirect/unresolved exits are explicit; differential disagreements have a disposition.

### M05 — Typed IR, data-flow, ABI semantics and decompiler correctness
**Status: PARTIAL**

**Why:** A plausible-looking C listing can be semantically wrong. The existing typed-IR and execution-checked suite is a base, not a universal correctness claim.

**Implement:** define and version the IR contract; document integer widths, signedness, overflow, flags, calling conventions, stack locations, memory operations, aliasing, endianness, vectors/floating-point and undefined/unsupported semantics. Use P-code/SLEIGH where applicable without claiming this makes RDIS the Ghidra decompiler. Maintain native frontends only where coverage and evidence justify them. Add reducer/minimizer for failures.

**Exit gate:** the maturity corpus passes execution-equivalence, not merely compile success; coverage is reported by operation family and ISA; unsupported semantics fail visibly rather than emitting confident wrong C; optimized and adversarial real-binary cases are represented; output has a structured mapping from C/IR expressions back to addresses/instructions.

### M06 — Type, structure, symbol and platform-metadata recovery
**Status: PARTIAL**

**Why:** Types are a principal driver of decompiler quality and analyst confidence.

**Implement:** ABI/prototype library coverage, DWARF/PDB and symbol/type ingestion where possible, imports and library signatures, C++ RTTI/vtables/inheritance, Swift/Objective-C metadata/version variants, JNI/native registration, enum/union/bitfield layouts, nested/self-referential structures, pointer-vs-integer discrimination, type propagation across callers/callees and explicit inference provenance.

**Exit gate:** debug-info-backed fixtures quantify field/prototype/type accuracy; ambiguity and conflicts are visible; inferred versus symbol/debug-backed/user-applied types are distinguishable; architecture ABI tests cover arguments, returns, stack variables and saved registers; metadata versions and malformed inputs fail safely.

### M07 — CFG and graph experience
**Status: PARTIAL**

**Current state:** main includes overview/detail, pointer-centered zoom, pan, fit, minimap, keyboard node selection, theme-aware SVG export and Chromium/Firefox regression tests, including small/tall/stress/wide graphs and live-binary testing.

**Why:** Hopper and Binary Ninja establish a high bar for graph navigation. A static screenshot of a graph is not a usable graph editor.

**Implement:** retain browser geometry and export tests; add dense switch/jump-table fixtures, parallel edges, Unicode/long labels, huge fan-out/join, unreachable blocks, self-loops and nested loops; complete edge-focus/navigation and keyboard movement; add viewport dragging/keyboard minimap operations; preserve address selection/labels while toggling view modes; profile render and interaction on large graphs. Fix visual findings at root cause, then rerun both Chromium and Firefox.

**Exit gate:** current browser matrix captures screenshots and exported SVG; graph nodes, labels, edges and minimap viewport stay within valid geometry; export viewBox contains all visible graph content; dark/light contrast and keyboard flows pass; screen-reader/manual accessibility review is recorded; large graphs remain navigable without implying that fit-to-whole-graph means readable labels.

### M08 — Synchronized workspace and analyst navigation
**Status: PLANNED**

**Why:** Modern RE tools synchronize assembly, CFG, pseudocode, data and references; view switching alone is not enough.

**Implement:** a shared selection model and stable address identity across listing, CFG, pseudo-code, hex, strings, imports, xrefs and types. Add predecessor/successor traversal, branch-condition inspection, loop/path highlighting, caller/callee navigation, cross-view scroll/highlight, search/quick-open, navigation history and bookmarks. Use virtualization and cancel obsolete rendering/analysis work.

**Exit gate:** UI integration tests verify synchronized addresses, selection persistence, back/forward and close/switch-document behavior; keyboard navigation is fully usable; large lists are virtualized; actions work through GUI and exposed API where appropriate.

### M09 — Durable project, annotations, undo/redo and binary lineage
**Status: PARTIAL**

**Why:** Analyst knowledge must survive sessions and software updates. Existing renames/comments and .rdb persistence are a foundation, not complete project/version tracking.

**Implement:** versioned project schema for names, comments, types, tags, bookmarks, graph layout overrides, analysis options, input hash, loader/base address and tool/schema versions. Add transactional saves, recovery after interruption, undo/redo, project export/import, migration, diff/merge conflicts and deterministic history. Build a function matcher for revised binaries using symbols, normalized bytes, CFG shape and optional semantics; show confidence and ambiguity.

**Exit gate:** kill/restart and corruption/recovery tests pass; round-trip preserves all supported annotations; migration from prior schema is tested; changed-binary matching precision/recall is reported; low-confidence matches never silently overwrite annotations; project portability and merge conflicts are tested.

### M10 — Function/call graph, references, signatures and library recognition
**Status: PARTIAL**

**Why:** Knowing that a function exists is less valuable than understanding its relationships and reusing established knowledge.

**Implement:** graph navigation for callers/callees/imports/exports, indirect calls and unresolved references; xref kinds and call sites; function/standard-library signatures; versioned local signature databases; compiler/packer heuristics; duplicate-function detection; string/resource cross-reference workflows. Import signatures only from sources with clear licensing and provenance.

**Exit gate:** callgraph fixtures and xref directionality are exact; library/signature matches have confidence/source attribution; false-positive rates are measured on unknown functions; no signature or name claim appears as certainty without evidence.

### M11 — Debugger, tracing and dynamic analysis
**Status: PARTIAL**

**Why:** The current LLDB wrapper is not equivalent to a full debugger or trace-integrated static analyzer.

**Implement:** formalize debugger backend protocol; breakpoint/watchpoint state, registers, memory, threads, stack traces, local/remote target support, architecture/platform matrix and safe process launch/attach. Correlate a stopped PC/runtime module address with static functions/CFG; import/export traces; align hit edges with static graph; preserve snapshots and reproducibility. Use existing LLDB/GDB backends instead of recreating every OS primitive.

**Exit gate:** backend matrix states tested and unsupported combinations; deterministic native test programs validate break/step/register/memory/backtrace and address mapping; debugger inputs are quoted/validated; timeouts and permissions are enforced; a dynamic trace can be mapped to static blocks without pretending an unobserved path is impossible.

### M12 — Emulation, symbolic execution, taint and vulnerability analysis
**Status: PLANNED**

**Why:** angr, radare2 and specialized frameworks go beyond static disassembly. RDIS needs selective, bounded advanced analysis rather than a shallow imitation of all frameworks.

**Implement:** first a bounded instruction/IR emulator for the subset already proven semantically correct; then function summaries, symbolic values, path constraints and indirect branch resolution. Add taint/source-sink tracking, cross-reference/data-flow queries and limited exploitability-oriented checks with explicit assumptions. Consider angr integration as an optional backend for difficult analysis cases; define stable result provenance instead of forcing a full rewrite.

**Exit gate:** every supported operation has interpreter/symbolic semantics tests; budgets terminate analysis safely; path constraints reproduce expected branch outcomes; false positive/negative rates are evaluated on labelled fixtures; reports state assumptions, unresolved states and evidence.

### M13 — MCP/AI agent integration and reproducible automation
**Status: PARTIAL**

**Why:** Current MCP functionality is useful, but IDA and Binary Ninja now also document MCP integration. “Has MCP” is no longer a defensible differentiator.

**Implement:** stable schema/versioning and consistent GUI/CLI/Python/MCP analysis identity; minimal composable and token-efficient tool surface; batch queries; structured output with addresses, instruction bytes, block edges, xrefs, type provenance and confidence; result-size budgets and pagination; cancellation/time budgets; read-only by default; explicit write actions for annotations/types/patches; audit trail/undo; safe multi-agent read/write coordination; no silent state changes. Add agent task fixtures for find-and-explain-function, data-flow tracing, build comparison and evidence-backed reports.

**Exit gate:** tool-schema contract tests; model-independent task benchmark; token count/tool call/latency/task success tracked; all outputs carry actionable address evidence; write operations are explicit/reversible; cross-session leakage tests pass; invalid input and budget exhaustion produce structured protocol errors; tools are not allowed to claim they executed analysis they did not run.

### M14 — Plugin SDK and third-party ecosystem
**Status: PARTIAL**

**Why:** IDA, Binary Ninja, Ghidra and radare2 scale capability with plugins and APIs.

**Implement:** versioned interfaces for loaders, architecture decoders, analysis passes, decompiler/lifter, type sources, renderers, import/export and MCP tools. Define capability metadata, dependency versions, compatibility checks, signed/trusted plugin source options and safe failure isolation. Plugin Python code is executable code; an allowlist is not a sandbox. Keep optional dependencies optional.

**Exit gate:** example plugin per major extension point; compatibility tests; plugin discovery and deterministic registration; broken plugins fail with a clear diagnostic without corrupting core analysis; install/uninstall/update and trust boundaries are documented; licensing is inventoried.

### M15 — Format, architecture and language breadth
**Status: PARTIAL**

**Why:** Broad architecture/file format support is an RDIS advantage only when every capability is honest about depth.

**Implement:** one machine-readable support matrix spanning ELF/PE/Mach-O/fat/archives/raw/firmware/WebAssembly and any new format candidates, architecture variants, calling conventions, ABI, endian/mode, debug information and metadata. Evaluate Windows ARM64, PPC, SPARC, additional RISC-V/vector subsets, managed bytecode and firmware/container ecosystems by target-user demand and test feasibility—not breadth alone. Add versioned loader/decoder fixtures for every supported claim.

**Exit gate:** support labels distinguish loader-only, disassembly, function analysis, CFG, decompilation, debug/type support; each marketed production cell has correctness fixtures, real binaries and explicit limitations; no broad “supports architecture” claim based solely on Capstone decode or generic P-code input.

### M16 — Binary diffing, version tracking and collaboration
**Status: PLANNED**

**Why:** Ghidra version tracking, signatures and team workflows address repeated work across releases. These are high-value differentiators beyond showing two files side by side.

**Implement:** function matching across builds; normalized byte hash, control-flow structure, caller/callee fingerprint and optional semantics; changed function/block/constant/string/import views; annotation transfer with confidence; project provenance; portable review bundles. Later add collaboration through explicit workspace/project storage, optimistic concurrency and visible conflict resolution instead of hidden shared mutable state.

**Exit gate:** known added/deleted/modified function corpus with match precision/recall; annotations transfer correctly on deterministic fixtures; ambiguous matches require review; project concurrency does not lose writes; analysis and annotations have separate hashes/version histories.

### M17 — Deobfuscation, binary triage and library identification
**Status: PLANNED**

**Why:** Commercial tools highlight deobfuscation, signature matching and triage. This area is only useful if confidence and false positives are visible.

**Implement:** entropy and executable/data section visualization; imports/strings/permissions summaries; packed/encrypted indicators; common compiler/library/runtime identification; local symbol/signature matching; simplify proven arithmetic/bit-vector idioms; indirect-control-flow recovery; optional SMT-backed simplification for specific IR forms. Add no AI-generated “malware verdict” without evidence.

**Exit gate:** labelled benign/packed/obfuscated corpus, precision/recall and calibration; semantics tests prove each deobfuscation rewrite preserves behavior under stated assumptions; triage reports include source/evidence and do not present heuristics as confirmed maliciousness.

### M18 — Performance, scale, cancellation and resource budgets
**Status: PARTIAL**

**Why:** An advanced feature that freezes on a large APK or 100k-function binary loses to a narrower responsive tool.

**Implement:** fixed representative small/medium/large corpus; CPU/RSS and p50/p95; cold/warm cache; parsing, analysis, decompile, graph-layout and render measurements; incremental analysis and lazy results; cancellation of obsolete work; bounded queues, cache sizes, uploads, decompression, graph node/edge count and response bytes. Avoid algorithmic complexity regressions on pathological CFGs and nested containers.

**Exit gate:** checked-in baseline manifest/raw data; CI trend reporting; no regression over an agreed tolerance without an explicit review; cancellation releases state; memory/time budgets are tested adversarially; concurrency target and supported resource profile are documented.

### M19 — Fuzzing, differential analysis and regression minimization
**Status: PARTIAL**

**Why:** The occasional malformed-input smoke test is not the same as sustained fuzzing.

**Implement:** per-loader/container/WASM/IR/decoder fuzz targets; mutation and grammar-based generators; deterministic seeds; timeout/RSS limits; crash minimization; corpus deduplication; architecture-aware differential checks; sanitization/property checks; regression fixture for every fixed bug. Test cache poisoning, same-file replacement, symlink/traversal, malformed JSON-RPC, output escaping and session isolation.

**Exit gate:** sustained fuzzing campaign with time/case budget documented; crash-free corpus count and coverage growth measured; all known crashes minimized and fixed or explicitly triaged; no malformed input escapes as an unhandled low-level exception; fuzz artifacts are attached to CI/release evidence.

### M20 — UI accessibility, docs, packaging, release and deployment trust
**Status: PARTIAL**

**Why:** A secure engine with poor install reliability or inaccessible navigation is not competitive.

**Implement:** wheel/source clean install across supported Python versions and operating systems; optional-extras matrix; Docker non-root/resource limit/hardening review; CSP/headers/auth/rate limit for remote deployment; upload retention and quotas; browser support matrix; responsive UI; keyboard/screen-reader tests; user-facing diagnostics; API/CLI schema compatibility; documentation generated/tested against actual commands. Keep public GitHub Pages, sitemap and docs/llms clean of internal-only roadmap links unless explicitly requested.

**Exit gate:** clean environment install/tests, release artifact verification, real-browser accessibility and cross-browser smoke, HTTP security checklist, data-retention and remote exposure tests, documentation links/checks and reproducible release notes all pass.

### M21 — Competitor parity scorecard and evidence-led release gate
**Status: NOT STARTED**

**Why:** We cannot claim to beat a combined competitor set by completing a checklist without comparing actual workflows.

**Implement:** versioned benchmark plans for the products in section 3; feature-to-feature mapping; representative tasks; deterministic binaries where licensing permits; competitor version and configuration capture; raw outputs and evaluator scripts. Score each competitor workflow as absent, partial, working, verified-correct or independently benchmarked. Define the RDIS-specific targets after baseline measurements.

**Exit gate:** every high-priority competitor capability maps to an RDIS implementation or a consciously documented non-goal; target workflows have reproducible results against the current stable releases; quality differences and uncertainties are public in release notes; no unsupported “beats X” claim ships.

## 7. High-priority competitor gap map

The following is the implementation order recommended by dependency and potential user value. It is a planned gap analysis, not a claim that all competitors expose identical features.

| Rank | Capability to deliver | Why it matters | Implementation approach | Proof before calling it done |
|---|---|---|---|---|
| P0 | Per-ISA function/CFG accuracy | Errors contaminate every downstream feature | Compiler fixtures, symbols/debug truth, indirect branches/switch tables and shared tails | Per-architecture function P/R and CFG edge F1 |
| P0 | Semantic decompiler and typed IR | Core analyst trust | IR contract, ABI/memory/width semantics, differential execution tests | Original and rebuilt program agree over generated inputs; unsupported ops are visible |
| P0 | Cache/project integrity and safe parsing | Stale state creates convincing but wrong results | Canonical identity, versioned schemas, bounded extraction and atomic persistence | Adversarial same-path, corruption, concurrency and recovery tests |
| P1 | Fast unified navigation and synchronized views | Reduces work per investigation | Address selection state, quick-open, xrefs, history, CFG/listing/pseudocode sync | Timed analyst tasks and integration tests |
| P1 | Full annotations and type workflows | Analysts build knowledge incrementally | Editable types/prototypes, bookmarks/tags/comments, undo/redo and durable projects | Round-trip/restart/version migration tests |
| P1 | Binary version tracking and diffing | Reuse of analyst work beats re-analysis from scratch | Function matching, changed blocks, confidence-ranked annotation transfer | Precision/recall and no silent bad transfers |
| P1 | Call graph, cross references, signatures | Program-level understanding | Call sites and unresolved calls, local signatures, symbol provenance | Exact fixture edges and measured false positives |
| P1 | Batch/headless and strong MCP | CI and AI-agent workflows | Stable JSON schemas, efficient batch/code-mode operations, budgets and explicit writes | Token/task/latency benchmark, isolation and reproducibility |
| P2 | Dynamic debugger/trace workflows | Static versus runtime truth | Backend interface, PC/static address mapping, breakpoint and trace support | Native/remote matrix and trace-to-CFG fixtures |
| P2 | Emulation, symbolic paths, taint | Advanced analyses no simple disassembler provides | Reuse proven IR semantics, bounded interpreter, constraint analysis, optional integrations | Semantic suite, budget enforcement, labelled benchmark |
| P2 | Debug data/types/library signature ingestion | Accuracy increases when using known metadata | DWARF/PDB and platform metadata, signature/versioned sources | Truth-data tests and licensing/provenance |
| P2 | Patch/assemble/compare workflow | Many analyst tasks require safe experimentation | Patch preview, byte diff, reversible changes, re-analysis invalidation | Round-trip, byte-hash, rollback and re-analysis tests |
| P2 | Plugin ecosystem | Community expands format/ISA/tool coverage | Versioned SDK and trust boundaries | Third-party example plugin CI matrix |
| P3 | Malware/firmware triage and deobfuscation | High-value specialized workflows | Entropy/section/capability indicators, proven rewrites, path/dataflow analysis | Labelled corpus and calibrated precision/recall |
| P3 | Collaboration and reproducible review reports | Long projects need handoff and multiple analysts | Project bundles, audit history, merge/conflict resolution, report artifact | Multi-session conflict and export/import tests |

## 8. Features we should add that are easy to miss

These features make the product reliable at scale and often matter more than a flashy decompiler output:

- **Provenance on every claim:** distinguish file metadata, symbols/debug info, deterministic decode, static heuristic, inferred type, runtime observation, plugin result and user annotation.
- **Explainable branch/function confidence:** show why a boundary/edge was inferred and which independent evidence supports it.
- **Reproducible analysis capsule:** binary digest, load options, tool/schema versions, analysis configuration and minimal saved artifact to reproduce a bug.
- **Coverage map and unsupported semantics viewer:** reveal unanalysed ranges, unresolved edges, unknown opcodes, unsupported lifter operations and decompiler fallbacks.
- **Evidence-preserving AI actions:** structured facts with exact address/bytes; proposed changes diffed before writing; audit log and undo; batch actions that can be replayed.
- **Resource policy profile:** local personal use, untrusted-file sandbox, multi-user server and isolated CI runner must have different explicit limits and permissions.
- **Crash minimizer and regression curator:** each bug turns into the smallest reproducible input and stable regression.
- **Project migrations and backups:** database schema versions and recovery paths, not only a saved comments file.
- **Determinism mode:** same file, options, plugin versions and engine commit produce stable structured outputs unless an explicitly documented randomized analysis is used.
- **Negative capability tests:** prove the product rejects invalid, unsupported or dangerous operations and tells the user what could not be established.
- **Accessibility and interaction budget:** keyboard-only completion, screen-reader review, browser memory and max render latency.
- **No silent success:** a fallback, missing optional tool, unverified instruction, timed-out analysis or partial output must be surfaced in structured results.

## 9. Release definition of done

A milestone does not close until all applicable points are satisfied:

- Acceptance criteria were written before the implementation was declared done.
- The exact commit and test commands are recorded.
- Focused tests and regression tests pass on the affected code.
- The broader required test suites pass; a failure is fixed or remains explicitly blocking.
- Browser changes have real screenshots, bounds/interaction assertions, at least the supported Chromium/Firefox matrix, exported artifacts where relevant, and accessibility checks.
- Correctness claims have an independent oracle (compiled source/debug symbols/instruction spec/reference tool/runtime behavior), not only a test written to match the implementation.
- Performance claims have a fixed corpus, cold/warm measurements and resource measurements.
- Threat/resource checks cover malformed input, timeouts, storage, cleanup, and remote exposure where relevant.
- Documentation describes what works and what remains unsupported.
- Evidence and limitations are reflected here and in the PR description.
- No P0 correctness/security issue remains open.
- PR is reviewed and CI green. **Do not merge** until the user asks.

## 10. Current resume cursor

This section is mutable; update it after every meaningful commit and before every interruption.

- **Last verified base:** main at 96b931d32c807c5430518be6c280c98fb995ebb2.
- **Current branch:** docs/competitive-parity-and-resume-roadmap.
- **Current active PR:** [#4 — docs: add resumable roadmap toward competitive parity](https://github.com/sagarchive/rdis/pull/4), open and draft; base is main; do not merge.
- **Milestone focus:** M00 — baseline and evidence ledger. M00 is PARTIAL; the environment-manifest pipeline is tested, but the immutable corpus and one-command baseline runner remain open.
- **Recent implementation commits:** 2089ecce947dfc29ece02ce9c29f9000e4c9f17e added environment capture; 14f258249a049032c8d4c33d15286e93e9900f1d added CI artifacts; a3efeadf395041f0a6779fa05523073e167a048f / 8ca556377969294f4497524dbe575daad826d34d added/corrected redaction; 99078dfa4a2eff58a387f068b2d18157c9a2f437 added capture tests; 8d2916d0d09b272f45f73aa326458cc3073dca07 wired them into CI; d56eb3ff0ccb860e0abfaa289e3c5f085bd31d73 and 25a6aeb885fe1c7765c5abe16722a85e822aedf4 corrected/tested PR head/base provenance; 039ea242e418d346702e96959479b81bcdd4fa2d recorded artifact review. Fetch live branch tip on resume; cursor updates are further commits.
- **Last completed action:** checked open/closed PRs and live CI; confirmed PR #3 was merged on 2026-10-19 and PR #4 is the only open PR. Inspected `tests/baseline_corpus.json`: it defines the MIT-licensed checked-in C fixture, the pinned in-place macOS `/bin/ls` sample, portable commands, and the macOS-arm64 profile. The branch cursor was stale because it still said the corpus manifest did not exist. The environment manifests/artifact inspection remains recorded below and in `BASELINE_REPORT.md`.
- **Next atomic action:** implement and unit-test `tests/run_baseline.py`; verify corpus/host-input hashes, execute selected commands without a shell, persist raw logs and a JSON pass/skip/fail summary keyed by the environment manifest; wire it into the Linux and macOS jobs; then inspect current-head artifacts. Do not start M01 or call M00 done until this works in CI and the remaining M00 support-matrix/pinning/retention gates are reviewed.
- **Current-main baseline evidence:** [hardening CI](https://github.com/sagarchive/rdis/actions/runs/39228787777) and [Pages deployment](https://github.com/sagarchive/rdis/actions/runs/39228786794) passed; [merged PR #3 full validation](https://github.com/sagarchive/rdis/actions/runs/39228116226) passed five jobs. BASELINE_REPORT.md records 42 hardening tests, 25 IR tests on Python 3.10/3.12, Chromium/Firefox, 124/124 maturity, 20-visitor determinism and the first /bin/ls benchmark.
- **Latest verified branch CI:** [run 39264434317](https://github.com/sagarchive/rdis/actions/runs/39264434317) passed all five jobs on PR #4 head `f9b433afe4bd1e5083d03014da65603b68307ca4`; this is a passing roadmap/corpus-manifest revision, not evidence that the runner exists or M00 is done.
- **Known limits:** competitor benchmarks and per-ISA function-discovery/CFG accuracy are not yet measured; pip versions are recorded rather than locked; fuzzing campaigns, manual accessibility review and multi-corpus performance baselines remain open.

## 11. Append-only request ledger — newest request at the end

Rules: append each new RDIS request as a new entry with date, exact intent, milestone links, status and the next atomic action. Update progress in that entry; do not erase its original intent. Each request may introduce new milestones, which must be appended to the register rather than silently replacing earlier goals.

### RQ-001 — 2026-10-19 — Create a resumable plan to beat the combined competitor set

**Request:** Inspect the latest merged main; learn from current source and official competitor documentation; establish milestones for core correctness, analysis breadth, graph/UI, debugging, decompilation, project workflows, automation, security, performance and release quality; create a new branch and one unmerged draft PR; keep reading/updating this register after each subsequent RDIS prompt; incrementally resume after errors or tool interruptions; add later requests at the end.

**Milestones:** M00–M21.  
**Status:** IN PROGRESS — roadmap/resume protocol and CI baseline reports are on draft PR #4; environment manifests are emitted and inspected, including secret redaction and PR head/base identity. M00 remains partial until the deterministic corpus manifest and baseline runner exist.  
**Next action:** keep the existing `tests/baseline_corpus.json`; implement and test the runner that verifies its hashes, executes its command profiles with bounded timeouts and no shell, writes stdout/stderr plus machine-readable results tied to the environment manifest, then record CI artifacts before reassessing M00.

### RQ-002 — 2026-10-19 — Check milestone/PR state and resume from the true cursor

**Request:** Re-check the live milestone roadmap, PRs, branches and CI instead of relying on conversation history; report which product changes are merged, which PR is active, and which milestone is actually next.

**Milestones:** M00, with dependency checks against M01–M21.

**Status:** IN PROGRESS — live GitHub state checked. PR #3 is merged; PR #4 is the sole open draft PR. Its latest known run, [39264434317](https://github.com/sagarchive/rdis/actions/runs/39264434317), passed all five jobs. The existing `tests/baseline_corpus.json` was present, contradicting the stale cursor that described the manifest as missing; it still lacks a tested one-command runner and artifact-level pass/skip/fail results.

**Next action:** add runner, unit tests and CI wiring; inspect the latest run and artifacts, update this cursor/report/PR description, and keep M00 PARTIAL until its full exit gate—including support matrix, dependency policy and durable baseline retention—is met.
