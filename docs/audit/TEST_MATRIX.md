# RDIS Test Matrix

This is a coverage plan, not a claim that every case already exists.

| Layer | Cases | Required assertion |
|---|---|---|
| Loaders | ELF, PE, thin/fat Mach-O, raw, WASM; truncated headers, bad offsets | Correct format or explicit parse error |
| Address map | Gaps, overlaps, zero-size, huge intervals, exact boundaries | Correct containing interval or no match |
| Containers | ZIP/TAR/compression/DMG; corrupt CRC, truncation, same-path rewrite, duplicate member, traversal, symlink, expansion bomb | Exact bytes or explicit failure; no partial cache |
| Cache | Cold/warm, same-size/mtime replacement, changed options, corrupt cache, concurrent miss | Correct invalidation and recovery |
| Disassembly | Advertised ISAs, invalid opcodes, unaligned targets, Thumb, delay slots, RVC | Correct boundaries/mode |
| CFG | Branches, loops, jump tables, indirect edges, tail calls, exceptions | Edge accuracy and deterministic output |
| IR | Width/sign, overflow, flags, memory, unsupported opcode | Equivalent semantics or explicit unsupported state |
| SIMD | Lane order, saturation, shifts, reductions, conversions | Lane-by-lane equivalence |
| WASM | Invalid LEB128, section/index mismatch, stack type errors, 259 deterministic malformed/mutated inputs | Explicit validation error; malformed inputs must not leak low-level parser exceptions |
| Metadata | JNI/ObjC/Swift/symbols, missing/partial/versioned metadata | Bounded parsing and explicit uncertainty |
| HTTP | Oversized/incomplete body, invalid JSON, Host/Origin, concurrent sessions, aggregate upload/cache quota | Bounded response, correct status and isolation; quota regressions and 20-visitor stress test passed in CI |
| MCP | Valid/invalid tool calls, malformed JSON-RPC, large output, file replacement | Protocol errors and current analysis |
| Rendering | HTML-like names/comments, huge CFG, Unicode, compact/detail CFG modes, entry highlight, known-target T/F edges, unresolved conditional targets, pointer-centered zoom, fit, standalone SVG export and keyboard-focusable nodes; Playwright desktop/mobile screenshots, fit bounds, zoom and exported CSS-variable checks | Browser screenshots and SVG are CI artifacts; visual inspection and real-binary CFG coverage remain required |
| CLI/API | Documented commands, invalid args, missing optional tools | Stable schemas and meaningful exit codes |
| Packaging | Source/wheel/Docker, optional extras | Entry points/assets work |
| Performance | Small/medium/large, cold/warm, concurrent | Time/RSS recorded; no unexplained regression |

Preserve existing entry points: `python tests/test_rdis.py`, `python tests/maturity.py`, `python tests/compile_rate.py arm64 40 40` where supported, `python tests/diffcheck.py`, `python tests/concurrency_test.py <server-url>`, and `python -m unittest discover -s tests -p 'test_hardening.py' -v`. Record unavailable tools as skips/blockers, not passes.