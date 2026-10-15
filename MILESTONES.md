# RDIS Precision Engineering Milestones

This is a gated execution plan. A milestone is complete only when implementation, regression coverage, test output and residual risks are recorded.

## M0 — Baseline and inventory
- [ ] Record base commit and clean-worktree assumption.
- [ ] Map all source, tests, packaging, CLI, web and MCP entry points.
- [ ] Capture current install/test commands and environment versions.
- [ ] Separate existing test claims from independently reproduced results.

## M1 — Identity, cache correctness and concurrency
- [ ] Use content fingerprints plus all analysis-affecting options for shared-analysis identity.
- [ ] Ensure document IDs cannot alias across changed bytes, base address, loader or analysis flags.
- [ ] Bound MCP cache memory and invalidate on same-path replacement.
- [ ] Test cache hits, misses, option variation, same-size replacement, concurrency and failure cleanup.
- [ ] Audit persistent cache code fingerprint and schema migration behaviour.

## M2 — Binary/container safety and address mapping
- [ ] Reject decompression overflow rather than analyzing a truncated prefix.
- [ ] Bind extraction cache entries to archive content.
- [ ] Enforce exact member-size checks and atomic cleanup on errors.
- [ ] Test section lookup with overlapping and very large segments.
- [ ] Audit ZIP/TAR/DMG limits, path traversal, duplicate names, symlinks, malformed headers and aggregate disk use.
- [ ] Test address overflow, file offsets, section overlap precedence and unmapped reads.

## M3 — Web, sessions, MCP, debugger and plugin trust
- [ ] Document safe loopback defaults and public deployment assumptions.
- [ ] Review upload size/count/disk quotas, request bodies, timeouts, concurrency and cleanup.
- [ ] Review cookie flags, session eviction, CSRF/origin behaviour and cross-session isolation.
- [ ] Bound MCP argument sizes and result payloads; return useful errors without traceback leakage.
- [ ] Verify debugger subprocess arguments/timeouts/output limits.
- [ ] Document plugin trust and ensure optional Python evaluation cannot be enabled accidentally.

## M4 — Disassembly and control-flow discovery
- [ ] Build per-architecture fixtures for branches, calls, tail calls, jump tables, indirect branches and delay slots.
- [ ] Check function boundaries, symbol aliases, overlapping code and stripped binaries.
- [ ] Measure discovery precision/recall against symbol/debug-info corpora.
- [ ] Compare instruction decoding and target resolution against Capstone and trusted tools.

## M5 — IR and decompiler semantics
- [ ] Validate signed/unsigned arithmetic, width truncation, overflow, flags and casts.
- [ ] Validate calling conventions, stack variables, branches, loops, switch and indirect calls.
- [ ] Validate SIMD lane width, signedness, saturation, shuffles and floating-point edge cases.
- [ ] Compile generated C where applicable and compare execution results against original fixtures.
- [ ] Keep unsupported/uncertain constructs explicit rather than silently inventing semantics.

## M6 — Types, symbols and platform metadata
- [ ] Test demangling and malformed symbol strings.
- [ ] Test Objective-C/Swift metadata across compiler/runtime versions.
- [ ] Test JNI table bounds, pointer width, relocation handling and Thumb pointers.
- [ ] Test type recovery for structs, unions, pointers, signedness, arrays and variadic calls.
- [ ] Preserve confidence/provenance for inferred types.

## M7 — UI, rendering, CLI and API contracts
- [ ] Escape all user-controlled strings in HTML, SVG, DOT and JSON.
- [ ] Test large function graphs, huge string sets and empty/error states.
- [ ] Keep CLI, Python API, browser UI and MCP results consistent where contracts overlap.
- [ ] Verify route input validation, export/import round trips and useful error messages.

## M8 — Fuzzing, differential and adversarial testing
- [ ] Add bounded fuzz harnesses for loaders, containers, WASM and metadata parsers.
- [ ] Maintain a minimized regression corpus for every crash or semantic mismatch.
- [ ] Test malformed/truncated inputs, compression bombs, huge counts and resource exhaustion.
- [ ] Track crashes, hangs, memory spikes, false discoveries and semantic mismatches.

## M9 — Performance and scalability
- [ ] Benchmark cold/warm cache, load, analysis, decompile and rendering.
- [ ] Track peak memory, throughput, cache hit rate and concurrent-user behaviour.
- [ ] Require repeatable workloads and record machine/runtime versions.
- [ ] Optimize only with profiling evidence and regression tests.

## M10 — Packaging, reproducibility and documentation
- [ ] Test clean install, wheel contents, supported Python versions and optional extras.
- [ ] Check Docker defaults, permissions, exposed ports, health checks and non-root execution.
- [ ] Verify README feature claims against tests and documented limitations.
- [ ] Produce a final evidence matrix and one consolidated PR with test results.

## Gate policy
No milestone is called complete without evidence. Security-sensitive changes require negative tests; semantic changes require a correctness fixture; performance changes require before/after measurements. Any unresolved P0/P1 finding must be explicitly listed in the PR.
