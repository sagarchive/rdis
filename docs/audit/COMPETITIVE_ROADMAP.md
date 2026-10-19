# Competitive feature review and product roadmap

**Scope:** RDIS compared with public feature documentation for Hopper, IDA, Ghidra and Binary Ninja. This is a product-level gap analysis, not a benchmark of correctness or performance. Vendor claims are treated as capability signals; every RDIS capability still needs a reproducible test.

## Sources checked

- Hopper product page (native UI, interactive CFG/PDF export, decompiler and integrated MCP server): https://www.hopperapp.com/
- Hopper tutorial (graph navigation, minimap, editable node labels/colors, references, undo/redo, hex view): https://www.hopperapp.com/tutorial.html
- IDA graph view documentation (keyboard cursor, custom layouts, node grouping, graph overview, proximity view, edge navigation): https://docs.hex-rays.com/8.4/user-guide/disassembler/graph-view
- IDA graphing tutorial: https://docs.hex-rays.com/9.0/user-guide/disassembler/graph-view/graphing_tutorial
- Ghidra Function Graph documentation (satellite view, path/loop highlighting, saved graph state, snapshots): https://www.tifkin.com/ghidra_markdown_docs/Ghidra_12.0.4_PUBLIC/FunctionGraphPlugin/Function_Graph/
- Ghidra beginner guide (function graph, decompiler, byte viewer, symbol tree, function call tree): https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html
- Binary Ninja feature page (IL stack, debugging, API/plugin ecosystem, triage, annotations, patching, multi-view UI): https://binary.ninja/features/
- Binary Ninja graph-view guide (fit/zoom-to-cursor, horizontal/vertical navigation, edge semantics, signature header, type/rename actions): https://docs.binary.ninja/guide/
- Binary Ninja 6.0's first-party MCP server announcement (published 3 September 2026): https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html
- Binary Ninja MCP documentation: https://dev-docs.binary.ninja/guide/mcp.html
- Official Ghidra releases (reviewed snapshot lists 12.1.4 as latest): https://github.com/NationalSecurityAgency/ghidra/releases
- Community Ghidra MCP integration (not an official NSA feature): https://github.com/hacr-lab/ghidra-mcp
- Community IDA Pro MCP adapter (third-party, depends on IDA Pro): https://github.com/mrexodia/ida-pro-mcp
- RDIS implementation under review: `rdis/web/index.html`, `rdis/analysis.py`, `rdis/render.py`, `rdis/ir.py`, `rdis/server.py`, `rdis/mcp_server.py`; public feature claims in `README.md` and `docs/index.html`.

## Executive decision

Do not try to copy every mature desktop feature at once. RDIS's most defensible position is a **portable, package-aware, low-setup reverse-engineering workspace with an open Python analysis engine**. MCP/API access is useful but is no longer unique: Binary Ninja 6.0 documents a first-party MCP server and third-party adapters exist for IDA and Ghidra. To compete credibly, RDIS must pair workflow simplicity with trustworthy analysis evidence and fast navigation.

## What competitors are demonstrably stronger at today

This table is based on the linked official product/documentation sources, not a hands-on accuracy bake-off. "Stronger today" means a documented capability or mature workflow that RDIS either lacks or has not demonstrated parity for; it does **not** mean the competitor always gives more correct results.

| Competitor | Areas where RDIS currently trails | Why that matters in real reverse engineering | What would close the gap / proof required |
|---|---|---|---|
| **IDA Pro + Hex-Rays** | Mature commercial disassembly/decompiler workflows, broad processor/module ecosystem, deeply developed decompiler transformations, debugging, database/project integrations and graph interaction | Analysts need reliable function boundaries, calling conventions, type recovery, large-project navigation and repeatable debugging—not just readable pseudocode | Build a fixed PE/ELF/Mach-O corpus; compare function starts, CFG edges, prototype/structure recovery and semantic equivalence. Prioritize function discovery + ABI/data-flow before marketing-style feature parity. Public baseline: [Hex-Rays decompiler](https://hex-rays.com/decompiler), [IDA graph view](https://docs.hex-rays.com/8.4/user-guide/disassembler/graph-view) |
| **Ghidra** | Full SLEIGH language descriptions/P-code semantics ecosystem, a mature multi-pass decompiler, data-flow/type propagation, project state, extensible scripts and broad architecture support; official releases are active (official release page lists Ghidra 12.1.4 as latest in the reviewed snapshot) | Optional `pypcode` gives RDIS an instruction-semantics frontend, but that is reuse of Ghidra's SLEIGH/P-code—not evidence that RDIS has surpassed Ghidra's analysis/decompiler | Keep `pypcode` for breadth while RDIS-owned typed IR, SSA, effects, aliasing, ABI recovery and struct constraints mature. Compare exact outputs on same binaries, execute recompiled output, and keep unsupported semantics visible. Sources: [SLEIGH/P-code design](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), [P-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html), [official releases](https://github.com/NationalSecurityAgency/ghidra/releases) |
| **Binary Ninja** | Layered LLIL/MLIL/SSA/HLIL, debugger, mature Python/C++/Rust automation, extension manager, triage/entropy views, type/annotation workflows, patching and synced/split views | A layered analysis lets experts inspect why a decompiler arrived at a value and automate tasks without treating C output as the only representation | Expose RDIS's semantic/analysis IR, then a validated SSA/value-flow view; add synchronized listing/CFG/decompiler selection, type edits and batch API. Sources: [official feature list](https://binary.ninja/features/), [user guide](https://docs.binary.ninja/guide/) |
| **Hopper** | Native analyst workflow polish: graph minimap/satellite, custom node groups/labels/colors, reference navigation, keyboard graph cursor, undo/redo and integrated disassembly/decompiler browsing | Analysts spend much of their time navigating, annotating and revisiting hypotheses | RDIS now has browser fit/minimap/zoom/export/accessibility tests; next close drag-to-navigate, edge/predecessor navigation, annotations, undo/redo and synchronized views. Source: [official Hopper tutorial](https://www.hopperapp.com/tutorial.html) |
| **Rizin + Cutter / radare2** | Broad command and scripting workflows, debugging, extensible plugin surface, interactive console tooling, project/session workflows; Rizin's RzIL emphasizes typed operation semantics | Reverse-engineering tasks need both a good UI and a dependable headless/scriptable engine | Preserve RDIS's low-setup browser/Python/MCP path; add stable JSON batch mode, cancellable jobs, versioned project state and explicit typed machine effects. Sources: [Rizin](https://rizin.re/), [Rizin RzIL](https://github.com/rizinorg/rizin/blob/dev/doc/rzil.md) |
| **angr** | Symbolic execution, constraints/SMT, dynamic/emulated CFG analysis, indirect-jump reasoning and composable program analyses | Some targets cannot be understood by static decoding alone; path conditions can resolve relationships a static decompiler cannot prove | Treat symbolic execution as an optional adapter or later plugin; first produce sound CFG/IR contracts. Sources: [angr CFG docs](https://docs.angr.io/en/latest/analyses/cfg.html), [angr capabilities](https://angr.io/) |
| **JEB / JADX / ILSpy** | Managed-code and Android/.NET workflows, resources/manifests, Java/C#/DEX decompilation and language-specific navigation | A native-library viewer is not a DEX/.NET decompiler; APK analysis often needs both managed and native views | Keep the scope clear today; later integrate or link to dedicated DEX/.NET tools and preserve cross-references from JNI/native symbols. Sources: [JADX](https://github.com/skylot/jadx), [ILSpy](https://github.com/icsharpcode/ILSpy), [JEB](https://www.pnfsoftware.com/jeb/) |

### RDIS's defensible strengths (not claims of universal superiority)

- **Low-friction, open workflow:** Python package, CLI, local browser UI and standard-library MCP endpoint are easy to script and inspect.
- **Package-aware native analysis:** inspect native members in APK/IPA/AAR/JAR/ZIP/archive containers without a manual extraction round-trip.
- **Cross-visitor web workflow:** sessions share heavy immutable analysis where valid while keeping user state separate; current CI has a 20-visitor regression.
- **Research-friendly code:** the loader/analysis/IR/lifter modules can be changed and benchmarked directly; it is not a closed product boundary.
- **Honest semantics boundary:** optional SLEIGH/P-code provides a broad frontend; RDIS's typed IR and structure hypotheses are experimental until equivalent semantic evidence exists.

The fastest path to be "better" is to win a narrow task with proof—such as package-to-native-library triage, reproducible analysis in CI, or evidence-linked agent workflows—while closing correctness gaps. Do not claim RDIS beats IDA/Ghidra/Binary Ninja in decompilation accuracy without a published, same-corpus benchmark.

## Real-world benchmark protocol (required before comparative claims)

Maintain a small, redistributable suite with source, compiler, flags, input digest and ground truth. Include optimized/unoptimized functions, switches/jump tables, indirect calls, tail calls, recursion, exceptions/unwind, PIC/relocations, stripped and symbolized files, packed/overlapping structures, arrays/nested structs, floats, atomics/volatile, vector lanes, ABI edge cases, malformed inputs and realistic libraries. Cover x86-64, ARM64, ARM/Thumb, MIPS, RISC-V and WASM where each tool genuinely supports the case.

Measure separately:
- **Decode:** exact instruction bytes/boundaries and invalid-stream handling.
- **Discovery:** function/basic-block precision and recall; false-positive and false-negative counts.
- **CFG:** node/edge precision and recall, branch polarity, fallthrough, delay-slot correctness and indirect-target resolution.
- **Semantics:** original versus recompiled execution over fixed and generated inputs; keep compile success, runtime equivalence, crashes and unsupported operations as separate columns.
- **Types/structures:** prototype/field type accuracy, `sizeof`/`offsetof` agreement, padding/packed/union correctness and evidence provenance.
- **Performance:** cold and warm wall time, time-to-first-result, p50/p95 latency, peak RSS, cache size, archive expansion, multi-binary throughput and concurrency.
- **Analyst workflow:** task completion rate/time for find-function, follow-xref, understand-loop, annotate-and-export and revisit-project tasks.

For each run record tool version/build, plugins, options, OS/CPU/RAM, Python/compiler versions and exact commands. Closed products may not expose the internals needed for automated ground truth; report "not comparable" rather than silently changing the case. Publish raw JSON/CSV and fixture hashes. No current RDIS-vs-competitor correctness or performance score is claimed until these runs exist.


### P0 — Graph correctness and interaction (current work)

| Improvement | Why it matters | Implementation direction | Acceptance evidence |
|---|---|---|---|
| Pixel-correct fit | Graphviz uses point-sized SVG dimensions and a viewBox; fitting only from user-unit `getBBox()` can clip or mis-size the graph | Measure the rendered graph group's browser pixel bounds before applying the CSS transform; fit against the visible graph viewport | Real Chromium screenshots and assertions for small, large, and detail graphs; every painted edge/node within viewport margins |
| Zoom and pan | Large graphs require predictable mouse/trackpad behavior | Pointer-centered wheel zoom, drag pan, Shift+wheel pan; explicit fit/reset/zoom controls | Browser test checks zoom changes, graph remains bounded after fit and controls remain operable |
| Inspectability | Analysts need to read nodes without guessing what is selected | Keyboard focus, visible focus ring, accessible labels, block selection, entry-block emphasis | Keyboard test plus screenshot; basic accessibility audit |
| Shareable output | Screenshots are not a scalable graph artifact | Export a standalone SVG with resolved CSS variables, stable viewBox, readable labels and sanitized filename | Parse exported SVG; assert no unresolved theme variables; open/render exported artifact in a browser |
| Large-graph legibility | Full instruction labels turn a CFG into an unreadable wall | Compact/detail modes, an aspect-aware minimap, readable entry-focused startup for tall and wide graphs, and label-to-shape bounds correction are implemented | Chromium screenshots cover a 7-node branch/loop, 48-node tall graph, 15-node wide fan-out/join and real ELF; whole-graph Fit is checked for clipping and is explicitly an overview action |

The browser test in `tests/browser_cfg.mjs` generates screenshot evidence in CI on successful runs. Keep the latest head green before marking the UI milestone complete; source-string tests alone do not establish visual correctness.

### Screenshot review findings (2026-10-16)

- The compiled ELF `branch_loop` CFG is readable at normal zoom: entry, true/false branches, loop-back edge, return block and edge legend are visible without clipping.
- The large synthetic CFG renders and the minimap makes the entry/current viewport and full graph shape discoverable. A full-graph Fit of a very tall, nearly linear graph naturally shrinks labels to tiny text (about 16% in the captured fixture); that is a limitation of overview scale, not a clipping defect. Keep the default entry-focused view readable and use the minimap/zoom to navigate; do not imply that full-fit makes every block readable.
- Light-theme overview of a huge graph is similarly low-detail by design. Verify text/edge contrast at readable zoom and test both themes for small/medium graphs, where actual label readability can be assessed.
- The wide fan-out fixture caught three navigation/readability issues: oversized SVG hitboxes could intercept the Fit toolbar, browser font metrics could let text exceed Graphviz node paths, and a 100% entry zoom clipped most branch destinations. The toolbar/legend now have explicit stacking order; node text is constrained to the rendered shape while the full label remains available as a title; wide entry views start at 60–75% and the browser test requires at least six branch destinations in view. The 180-node minimap looked like a solid bar at its old height, so tall-graph thumbnails are taller on desktop and use thin contrasting block outlines. Browser screenshots cover these cases.
- Standalone SVG inspection exposed an export-only coordinate bug: Graphviz translates `g.graph`, so its local `getBBox()` cannot be used directly as the root `viewBox`. Export now transforms all four graph-bound corners through the graph/root screen matrices; Chromium and Firefox assert that the downloaded viewBox matches those root-SVG bounds and verify theme variables are resolved.
- Remaining visual coverage: dense switch/jump-table graphs, long Unicode labels, overlapping/parallel edges, empty/failed DOT rendering, broader mobile graph navigation and 150+ node stress. Chromium and Firefox both pass the current screenshot/bounds/export suite; a second browser engine is no longer an open gate.

### P1 — Analyst workflow gaps versus mature tools

| Feature | Competitor signal | Why RDIS should add it | Proposed design |
|---|---|---|---|
| CFG minimap and viewport navigator | Hopper documents a minimap; IDA and Ghidra document graph overview/satellite views | Large functions become navigable without repeated zoom resets | Basic aspect-aware minimap with viewport rectangle and click-to-recenter is implemented and browser-tested; next add drag-to-navigate, keyboard controls and user sizing |
| Synchronized listing/graph/decompiler panes | Hopper presents multiple representations; Binary Ninja supports synchronized and split views | Reverse engineers constantly cross-check assembly, CFG and pseudocode | Shared address selection model; split-pane layout; selecting a block scrolls listing and highlights pseudocode range when mapping is known |
| In-graph references and edge navigation | Hopper and Binary Ninja expose references and edge navigation; IDA supports a keyboard current-node model and edge highlighting | Control flow is useful only if users can traverse it quickly | Click edge to inspect source/target and branch condition; keyboard arrow navigation among predecessor/successor blocks |
| Annotation system | Hopper/Binary Ninja support comments, tags, colors, names | Analysis needs to accumulate human knowledge, not just regenerate disassembly | Address/function/block comments, bookmarks, tags, block color; save in versioned `.rdb`; undo/redo journal |
| Call graph and xrefs browser | Ghidra exposes function call tree and symbol/reference views | Function CFG answers local flow; call graph answers program structure | Caller/callee graph with edge kind and callsite; filter imports, unresolved indirect calls and depth; cap rendering on huge binaries |
| Types and structures UI | Binary Ninja exposes types and smart-structure workflows | Better types improve decompilation and analyst trust | Type editor for typedef/struct/enum/prototype; import/export C headers and DWARF/PDB where supported; explicit source/confidence for inferred types |
| Search and navigation history | Hopper documents symbol/string filtering and back/forward stack | Analysts explore by symbol, address, string and xref repeatedly | Unified quick-open (symbols/functions/strings/addresses), search results pane, back/forward navigation, persistent bookmarks |
| Graph modes | Binary Ninja uses graph views for both disassembly and non-AST decompiler forms | Assembly CFG and structured pseudocode reveal different things | First ship robust assembly CFG; later add a separate pseudocode/IR graph so the user can choose representation |
| Binary comparison | Common high-value workflow for updates and malware variants | Differencing can reveal meaningful changes faster than reading two binaries independently | Function matching by normalized bytes, CFG shape and symbols; changed blocks/calls/types; side-by-side compare; never imply heuristic matches are certain |
| Project portability | Mature tools retain user analysis state | Reproducible review requires moving annotations with a binary | Versioned project bundle: binary hash, loader options, symbols, types, comments, bookmarks and analysis version; migration tests |

### P1 — Analysis quality before more decompiler syntax

1. **Per-architecture ground-truth fixtures.** Keep small compiled programs for x86-64, ARM64, ARM/Thumb, MIPS, RISC-V and WASM; include switches, tail calls, indirect branches, jump tables, exception/unwind metadata, recursion and position-independent code.
2. **Function discovery precision/recall.** Record expected functions and ranges for stripped and symbol-rich binaries. Report false positives and false negatives per architecture; compilation rate is not a correctness metric.
3. **CFG edge accuracy.** Compare expected basic blocks, predecessors/successors, branch polarity, fallthrough, delay slots and unresolved indirect edges. Test unusual control flow and overlapping/malformed sections.
4. **Decompiler semantic equivalence.** Execute original and recompiled output under generated inputs; include signed overflow, truncation, shifts, flags, floating-point, aliasing, vector lanes, stack arguments and ABI return conventions. Keep compile success separate from semantic pass rate.
5. **Confidence and provenance.** Label recovered facts as file metadata, symbol/debug info, deterministic analysis, heuristic inference or user annotation. Expose unsupported semantics and uncertainty instead of silently inventing clean C.
6. **Differential testing.** Compare instruction decoding and function boundaries against independent tools where licenses and CI constraints permit. Disagreements become minimized fixtures, not automatic votes that one tool is right.
7. **Fuzzing.** Fuzz each loader/container/parser independently, cap time/memory, minimize crashes and add every fixed crash as a regression. Include decompression bombs, nested archives, malformed LEB128, corrupt section tables and pathological graph input.

### P2 — Differentiators worth building

- **Evidence-first agent workflow:** MCP tools should return structured facts (address, bytes, block edges, xrefs, confidence, evidence) so agents can cite exact binary locations. The differentiator to test is reliable, reproducible data and explicit, reversible writes—not the presence or number of tools. Hopper's official product page and Binary Ninja 6.0 both document integrated MCP servers; third-party adapters also exist for IDA/Ghidra. Check each tool's version, tool coverage and deployment model rather than claiming MCP itself as a differentiator.
- **Reproducible analysis bundles:** export JSON/GraphML/DOT/SVG plus symbols, annotations, tool version and input digest for CI, reports and collaborative review.
- **Triage dashboard:** entropy/section maps, imports, suspicious permissions, strings, crypto/API clusters and function hotspots. Make it a prioritization aid, not an automated malware verdict.
- **Plugin contract and capability limits:** versioned loader/architecture/analysis/render hooks, explicit trust warning for Python plugins, deterministic plugin tests and optional allowlists.
- **Headless batch mode:** stable JSON output, machine-readable errors, incremental cache, bounded parallelism and reproducible corpus benchmarks for CI and malware triage pipelines.
- **Debugger integration later:** first make static analysis reliable; then align breakpoints/runtime traces with static CFG blocks and preserve trace provenance.

## Engineering guardrails

- One canonical analysis identity includes exact input content, loader/architecture/base-address settings, analysis options, and implementation/schema versions.
- All user-controlled graph labels, comments and symbol names must be escaped in SVG/HTML and DOT.
- Bound CPU, memory, decompression output, archive nesting, graph node count, request duration, cache size and aggregate storage.
- Treat unknown branch targets as unknown; never color an unproven edge as definitely true/false.
- Every feature needs a minimal fixture, a negative/adversarial case, and an end-to-end regression if it crosses API/UI boundaries.
- Benchmark fixed corpora: cold/warm latency, p50/p95, peak RSS, cache hit/miss, function discovery precision/recall, CFG edge accuracy, semantic pass rate and unsupported-feature rate.
- Do not compare decompiler accuracy using screenshots or source appearance. Use reproducible binaries, inputs and output semantics.

## Proposed milestone order

1. **M7a — CFG visual correctness:** pixel-based fit, browser screenshots, SVG export validation, dark/light theme and keyboard controls.
2. **M7b — Graph navigation:** minimap, selection/edge traversal, synchronized listing.
3. **M4 — Analysis truth:** per-ISA function/CFG fixtures and precision/recall.
4. **M5/M6 — Semantics and types:** confidence/provenance, ABI and structure recovery.
5. **M1/M2/M3 — Reliability/security closure:** cache races, retention/quotas, route-by-route and plugin/debugger review.
6. **M8/M9 — Fuzzing/performance:** fixed corpora, minimized crash set and reproducible baselines.
7. **M7c/M10 — Product workflow/release:** annotations, call graph, project bundles, browser accessibility, clean installs and documentation.

## Release gates

A milestone is complete only when the evidence is attached to the PR/CI: test commands, exact commit SHA, OS/Python/browser versions, artifacts, measured results and remaining limitations. If a browser run or corpus is unavailable, label it **not verified** rather than infer success from source inspection.
