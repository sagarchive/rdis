# Competitive feature review and product roadmap

**Scope:** RDIS compared with the current public feature descriptions for Hopper and Binary Ninja and the Ghidra beginner documentation. This is a product-level gap analysis, not a benchmark of correctness or performance. Vendor claims are treated as capability signals; every RDIS capability still needs a reproducible test.

## Sources checked

- Hopper product page: https://www.hopperapp.com/
- Hopper tutorial (graph navigation, minimap, editable node labels/colors, references, undo/redo, hex view): https://www.hopperapp.com/tutorial.html
- Ghidra beginner guide (function graph, decompiler, byte viewer, symbol tree, function call tree): https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html
- Binary Ninja feature page (IL stack, debugging, API/plugin ecosystem, triage, annotations, patching, multi-view UI): https://binary.ninja/features/
- Binary Ninja graph-view guide (fit/zoom-to-cursor, horizontal/vertical navigation, edge semantics, signature header, type/rename actions): https://docs.binary.ninja/guide/
- RDIS implementation under review: `rdis/web/index.html`, `rdis/analysis.py`, `rdis/render.py`, `rdis/ir.py`, `rdis/server.py`, `rdis/mcp_server.py`; public feature claims in `README.md` and `docs/index.html`.

## Executive decision

Do not try to copy every mature desktop feature at once. RDIS's most defensible position is a **portable, scriptable, package-aware reverse-engineering workspace with an open analysis engine and a first-class MCP/API workflow**. To compete credibly, it must pair that advantage with trustworthy analysis evidence and fast navigation.

### P0 — Graph correctness and interaction (current work)

| Improvement | Why it matters | Implementation direction | Acceptance evidence |
|---|---|---|---|
| Pixel-correct fit | Graphviz uses point-sized SVG dimensions and a viewBox; fitting only from user-unit `getBBox()` can clip or mis-size the graph | Measure the rendered graph group's browser pixel bounds before applying the CSS transform; fit against the visible graph viewport | Real Chromium screenshots and assertions for small, large, and detail graphs; every painted edge/node within viewport margins |
| Zoom and pan | Large graphs require predictable mouse/trackpad behavior | Pointer-centered wheel zoom, drag pan, Shift+wheel pan; explicit fit/reset/zoom controls | Browser test checks zoom changes, graph remains bounded after fit and controls remain operable |
| Inspectability | Analysts need to read nodes without guessing what is selected | Keyboard focus, visible focus ring, accessible labels, block selection, entry-block emphasis | Keyboard test plus screenshot; basic accessibility audit |
| Shareable output | Screenshots are not a scalable graph artifact | Export a standalone SVG with resolved CSS variables, stable viewBox, readable labels and sanitized filename | Parse exported SVG; assert no unresolved theme variables; open/render exported artifact in a browser |
| Large-graph legibility | Full instruction labels turn a CFG into an unreadable wall | Overview/detail modes, stable spacing, long-label and edge-label tests; future minimap | Screenshot fixtures with 7, 48, and 150+ nodes; no overlapping controls or clipped graph |

The browser test in `tests/browser_cfg.mjs` is intended to generate screenshot evidence in CI. The test must remain green before the UI milestone is marked complete; source-string tests alone do not establish visual correctness.

### P1 — Analyst workflow gaps versus mature tools

| Feature | Competitor signal | Why RDIS should add it | Proposed design |
|---|---|---|---|
| CFG minimap and viewport navigator | Hopper documents a minimap and direct viewport movement | Large functions become navigable without repeated zoom resets | SVG/canvas overview with viewport rectangle; click/drag to navigate; hide for small graphs |
| Synchronized listing/graph/decompiler panes | Hopper presents multiple representations; Binary Ninja supports synchronized and split views | Reverse engineers constantly cross-check assembly, CFG and pseudocode | Shared address selection model; split-pane layout; selecting a block scrolls listing and highlights pseudocode range when mapping is known |
| In-graph references and edge navigation | Hopper and Binary Ninja expose references and edge navigation | Control flow is useful only if users can traverse it quickly | Click edge to inspect source/target and branch condition; keyboard arrow navigation among predecessor/successor blocks |
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

- **AI-assisted review with evidence links:** MCP tools should return structured facts (address, bytes, block edges, xrefs, confidence, evidence) so agents can cite exact binary locations. Annotation writes must be explicit, reversible and auditable.
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
