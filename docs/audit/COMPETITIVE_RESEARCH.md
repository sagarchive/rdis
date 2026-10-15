# Competitive research: RDIS against established reverse-engineering workstations

**Research date:** 2026-10-15  
**Purpose:** turn a feature comparison into an evidence-led product roadmap. This is a product-design audit, not a claim of parity with commercial tools.

## Sources reviewed

- [Hopper product page](https://www.hopperapp.com/) and [Hopper tutorial](https://www.hopperapp.com/tutorial.html)
- [IDA graph view documentation](https://docs.hex-rays.com/8.4/user-guide/disassembler/graph-view) and [IDA graphing tutorial](https://docs.hex-rays.com/9.0/user-guide/disassembler/graph-view/graphing_tutorial)
- [Ghidra Function Graph documentation](https://www.tifkin.com/ghidra_markdown_docs/Ghidra_12.0.4_PUBLIC/FunctionGraphPlugin/Function_Graph/) and [Ghidra Program Graph documentation](https://ghidradocs.com/10.1.5_PUBLIC/help/ProgramGraph/help/topics/ProgramGraphPlugin/ProgramGraph.htm)
- [Binary Ninja User Guide](https://docs.binary.ninja/guide/) and [Binary Ninja HLIL documentation](https://docs.binary.ninja/dev/bnil-hlil.html)

Vendor documentation establishes that a feature exists; it does not prove its performance or quality. Feature comparisons below are qualitative, not a benchmark.

## Product position

RDIS already has a meaningful differentiated foundation: browser-first workflow, a Python library/CLI, multi-user web access, package-aware loading, a dependency-light MCP endpoint, and broad claimed CPU/file-format coverage. The next step is not to clone every UI control from IDA/Hopper. It is to make the analysis trustworthy, make the graph usable on real functions, and connect graph navigation to the rest of the analysis workspace.

**Positioning:** an accessible, scriptable, browser-first reverse-engineering workstation with reproducible analysis and an AI/MCP automation surface—not “IDA/Hopper parity” until parity has been tested feature by feature.

## Competitive findings

| Product | Strong graph/workflow capabilities documented by vendor | RDIS implication |
|---|---|---|
| Hopper | CFG and assembly/pseudo-code views; minimap; block navigation with arrow keys; node annotations/edits; symbol/string navigation; references and procedure predecessor/successor information; scripting and debugging | RDIS should prioritize a minimap, synchronized selection, xrefs and annotations before decorative graph effects |
| IDA | graph/text toggle; keyboard current-node model; node selection and movement; edge customization; grouping/collapsing; graph overview; proximity view; per-location zoom/navigation state | Huge CFGs need overview/navigation, stable layouts, keyboard semantics and a strategy for reducing visual complexity |
| Ghidra | primary + satellite views; compact configurable block fields; graph snapshots; saved colors/grouping/zoom/pan; scoped flow/path/loop highlighting | Add focus/hover path tracing, loop highlighting, saved view state and useful screenshots/exports |
| Binary Ninja | CFG and IL graph views; cursor zoom, fit and scrolling; branch-type colors; interactive function/type header; context actions; IL debug reports | Offer multiple graph layers (assembly and lifted/decompiler IR), explicit analysis confidence, and a way to explain decompiler transformations |

## Current RDIS graph: audit and verification

The graph renderer in `rdis/web/index.html` uses Viz.js/Graphviz DOT to render SVG. The UI has fit/zoom controls, pointer-centred wheel zoom, drag pan, a detail toggle, SVG export, and keyboard-focusable blocks.

The current high-risk graph defects to guard against are:

1. **Fit correctness:** Graphviz uses point-based intrinsic dimensions and browser SVG CSS pixels differ. Fit must measure painted graph bounds after clearing the transform, then centre/scale the full graph.
2. **Large and narrow viewports:** the first render must not clip labels, arrows, or nodes on desktop and mobile. A minimum scale must not fight the fit operation.
3. **Navigation semantics:** zoom-in, zoom-out, fit and reset must be consistent; zoom must be anchored to the pointer; pan must not start when dragging a node/control.
4. **Export fidelity:** downloaded SVG must not depend on CSS variables defined only by the app page; viewBox must include all graph content; file names must be safe; no temporary object URL leak.
5. **Branch meaning:** T/F labels and colors must only claim semantics when the target/edge meaning is known. Unknown edges must remain visibly unresolved, not be guessed.
6. **Accessibility:** nodes need keyboard focus, a visible focus ring, labels and reliable keyboard actions. Color must not be the only branch distinction.
7. **Error visibility:** missing renderer, invalid DOT, empty CFG and unsupported architectures must show a truthful state, not silently fall back to unrelated bytes.
8. **Regression evidence:** unit/source-string tests are insufficient alone. CI should launch a real browser, render a representative DOT fixture, assert actual graph bounds and interactions, export an SVG, and preserve desktop/mobile screenshots as artifacts.

A Playwright smoke test is being added for a 14-node CFG fixture. It should be considered accepted only after the CI run passes and the produced screenshots and SVG have been inspected. It is not a substitute for a manual visual review on real application binaries.

## Roadmap: priority order

### P0 — Correctness and trust (blockers)

**P0.1 — CFG visual regression suite**
- Use a deterministic fixture with entry, branch, join, loop/back-edge, long labels and many nodes.
- Run Chromium at desktop and mobile viewports.
- Assert all 14 nodes render; graph bounds fit the viewport after Fit; zoom controls change scale; keyboard focus works; exported SVG is standalone and has no unresolved theme variables.
- Store screenshots and exported SVG as CI artifacts.
- Add fixtures for empty graph, renderer failure, unsupported WASM graph, and very large graphs.

**P0.2 — Analysis truthfulness**
- Make unresolved branch targets, indirect jumps and uncertain function boundaries explicit.
- Never show a guessed T/F interpretation as a fact.
- Track unsupported instructions and incomplete lifts in structured diagnostics.
- Ensure all cache keys include content identity and all analysis-affecting options.

**P0.3 — Security and resource ceilings**
- Keep binary/container input bounded; add aggregate disk/cache quotas, expiry/cleanup and request cancellation.
- Fuzz loaders, decompressors, WASM framing and API parsers.
- Document the trust boundary for Python plugins, LLDB and public web hosting.

### P1 — Make the graph competitive

**P1.1 — Satellite/minimap**
- Render a small, low-detail overview with the current viewport rectangle.
- Clicking or dragging the viewport recentres the primary graph.
- Use the same source geometry as the primary graph; keep it responsive and accessible.
- Acceptance: viewport tracks pan/zoom, works on large graphs, and never blocks node interaction.

**P1.2 — Real graph navigation**
- Arrow keys move the active block to the nearest geometric neighbour; Enter selects; Shift+Enter opens the listing; Escape returns focus to the graph.
- Add explicit predecessor/successor navigation and edge hover/highlighting.
- Keep keyboard cursor, selected address, listing and inspector synchronized.
- Acceptance: navigation can traverse every node in a deterministic CFG fixture without a mouse.

**P1.3 — Flow/path analysis**
- On selection, optionally highlight reachable successors, predecessors, paths between two blocks and loops containing a block.
- Keep analysis distinct from visual layout; compute graph relationships from CFG edges, not SVG pixel positions.
- Show a legend and provide a “clear highlights” action.
- Acceptance: known graph fixtures verify reachable-set and loop membership against expected results.

**P1.4 — Useful block detail controls**
- Offer compact, assembly-detail and pseudo/IR labels where the backend has trustworthy data.
- Allow per-graph display settings (addresses, bytes, comments, instruction count) and truncate oversized blocks with an expand affordance.
- Acceptance: toggles do not change graph topology or active address.

**P1.5 — Persistent analyst state**
- Persist graph zoom/pan, node colours, comments/bookmarks and optionally custom layouts per document-content identity + function + analysis version.
- Add undo/redo for analyst edits before adding destructive binary editing.
- Never key user state by file path alone.
- Acceptance: close/reopen and same-path replacement tests prove state isolation and safe invalidation.

**P1.6 — Large graph performance**
- Benchmark 50, 250, 1,000 and 5,000 block synthetic CFGs.
- If SVG interaction becomes slow, add level-of-detail rendering, edge simplification, collapsible regions or a canvas renderer while retaining SVG export.
- Avoid arbitrary graph truncation; if a safety cap is required, explain what was omitted.
- Acceptance: publish render time, fit time, interaction latency and memory, with the tested browser/hardware recorded.

### P1 — Analysis engine and decompiler

**P1.7 — Function discovery and CFG accuracy**
- Create per-architecture compiled fixtures for direct/indirect calls, tail calls, switch tables, exception edges, thunks, PLT/stubs, overlapping code/data and stripped binaries.
- Measure precision/recall for functions and edge accuracy; report unsupported/ambiguous cases.
- Differentially compare against trusted tools when licensed/available, while manually adjudicating disagreements.

**P1.8 — Semantic decompiler corpus**
- Test output behavior, not only whether emitted C compiles.
- Compile small source fixtures with known results; compare original and decompiled behavior over deterministic and randomized inputs where safe.
- Cover signed overflow, widths, shifts, flags, pointer arithmetic, floating-point, stack variables, calling conventions, SIMD and control-flow structuring.
- Record a minimized regression for every confirmed semantic defect.

**P1.9 — Cross-reference and call graph**
- Build bidirectional code/data xrefs and a function call graph with unresolved indirect calls represented explicitly.
- Support navigation from call site to callee and back, import/export references, and “who references this address?”
- Add incremental invalidation when annotations or analysis options change.

**P1.10 — Type and symbol workflows**
- Rename, comment, bookmark, set type/signature and annotate blocks from graph/listing/pseudocode consistently.
- Add confidence/provenance to inferred types; preserve analyst overrides separately from inferred results.
- Keep edits undoable and persist them in the analysis database.

### P2 — Workflow, interoperability and release quality

**P2.1 — Multi-view synchronization**
- Keep listing, CFG, pseudo-code/IR, hex and inspector selection synchronized.
- Add back/forward navigation and “reveal active address” across views.

**P2.2 — Export and reporting**
- SVG and PDF graph export; optional DOT/JSON CFG export with node addresses, edges, labels and uncertainty metadata.
- A report bundle with binary hash, loader/arch/options, tool version, analysis warnings and generated artifacts.

**P2.3 — Debugger integration**
- Breakpoint/run-to-block actions where LLDB supports them; clearly distinguish static edges from observed runtime paths.
- Preserve debugger timeout, output and subprocess safety limits.

**P2.4 — Plugin/API contracts**
- Version the plugin API; provide typed examples, capability declarations and explicit trust warnings.
- Keep CLI, Python API, HTTP and MCP semantics aligned; test equivalent results and error codes.

**P2.5 — CI and packaging**
- Python-version and OS matrix; wheel install tests; package-data checks; deterministic self-check; fuzz smoke corpus; browser screenshots; performance artifacts.
- Publish unsupported features and known limitations instead of presenting a format/architecture name as proof of complete semantic coverage.

## Acceptance scorecard

Do not claim “competitive with Hopper/IDA/Ghidra/Binary Ninja” based on feature names alone. Track these separately:

- **Correctness:** function discovery precision/recall, CFG edge accuracy, semantic mismatches, cache invalidation failures.
- **Graph UX:** no clipping in screenshots; first-fit correctness; node/edge navigation success; keyboard-only completion; SVG export opened in a standalone viewer.
- **Scale:** 50/250/1,000/5,000-block render and interaction metrics.
- **Reliability:** crashes, malformed-input rejection, resource-ceiling enforcement, fuzz findings and regression rate.
- **Workflow:** time to locate a symbol, follow xrefs, understand a loop, rename/comment a block and return to the previous address.
- **Transparency:** every advertised feature has a test, an evidence artifact or an explicit limitation.

## Release rule

The browser CFG suite is an initial visual regression gate, not the end of graph QA. Before calling the graph redesign complete, inspect the desktop/mobile screenshots and standalone SVG from CI, then add at least one real CFG captured from a compiled fixture. Keep the PR draft until the latest head is green and the open milestones have evidence or a clearly documented residual-risk decision.
