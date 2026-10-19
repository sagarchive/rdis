# RDIS Feature / Claim Support Matrix

**Purpose:** Initial source-linked inventory for M00/M01. This distinguishes an implemented capability from proven correctness. It is not a parity claim against IDA Pro/Hex-Rays, Ghidra, Binary Ninja, Hopper, radare2/Cutter, angr or RetDec.

**Baseline:** main at 96b931d32c807c5430518be6c280c98fb995ebb2. Product changes from merged PR #3 are included on main. The reproducible baseline runner is exercised on PR #4 head 24cfdc9e0f1786bc89984aee1ff9f76fb3b7113a in [CI run 39266670036](https://github.com/sagarchive/rdis/actions/runs/39266670036). The run used the PR's tested merge checkout while its environment manifests separately record PR head/base identities.

## Status definitions

- **VERIFIED (bounded):** a concrete test proves the stated bounded behavior at the recorded revision; not exhaustive correctness.
- **PARTIAL:** implementation and/or tests exist, but major acceptance gates remain unmeasured.
- **UNVERIFIED:** a claim is not yet tied to a reproducible end-to-end test in this matrix.
- **UNSUPPORTED (explicit):** the product should clearly report this limitation.

## Matrix

| Area / claim | Implementation source | Current executable evidence | Status | Main gaps / next validation |
|---|---|---|---|---|
| Package build and CLI entry points | pyproject.toml; rdis/__main__.py; rdis/server.py; rdis/mcp_server.py | Python 3.10/3.12 wheel install; rdis --help, rdis-gui --help and MCP initialize in baseline profiles | VERIFIED (bounded) | Optional extras, clean OS matrix beyond current CI, release-install reproducibility |
| Environment and corpus provenance | tests/capture_environment.py; tests/baseline_corpus.json; tests/run_baseline.py | Manifest/hash/redaction tests; current-head run 39266670036 emitted summaries and raw logs | VERIFIED (bounded) | Permanent artifact retention, expanded licensed corpus, dependency constraints strategy |
| ELF / PE / Mach-O loading | rdis/loader.py (LIEF) | Product self-check; macOS /bin/ls load/analysis benchmark; compiled ELF CFG fixture used by browser CI | PARTIAL | Independent expected segment/offset/symbol fixtures per format; PE/fat Mach-O truth fixtures; malformed-header coverage |
| ZIP / APK / IPA / AAR / JAR / TAR / compressed input | rdis/containers.py | tests/test_hardening.py extraction, same-path replacement and malformed-input cases | PARTIAL | Nested archive depth, duplicate members, symlinks/path traversal, quota cleanup and more host formats |
| Raw binary loading | rdis/raw.py; rdis/loader.py; plugin loader | Raw loader/API exists; some product checks exercise raw fixtures | PARTIAL | Base address, endian, ISA mode, file-offset mapping and boundary truth fixtures |
| x86 / x86-64 decoding and analysis | rdis/arch.py; rdis/analysis.py; rdis/lift.py; rdis/ir_front.py | Maturity suite, real-binary compile-rate corpus, typed-IR tests; fixed NOP/RET byte-boundary tests added in tests/test_architecture_encodings.py | PARTIAL | Decoder-mode/opcode coverage and function-discovery precision/recall; compilation is not semantic equivalence |
| ARM / Thumb | rdis/arch.py; rdis/loader.py; rdis/analysis.py; rdis/lift.py; rdis/ir_front.py | ARM/Thumb decoder and mapping-symbol handling exist; fixed A32/T16 NOP/BX-LR byte-boundary tests added | PARTIAL | ARM-vs-Thumb interworking/BLX, mapping-symbol fixtures and CFG edge F1 remain open |
| ARM64 / AArch64 | rdis/arch.py; rdis/loader.py; rdis/analysis.py; rdis/ir_front.py; rdis/ir.py | macOS arm64 /bin/ls benchmark; 124-case execution-checked maturity suite; fixed A64 NOP/RET byte-boundary tests added | PARTIAL | Larger licensed corpus, discovery precision/recall, indirect edges, ABI/type recovery and uncovered semantic cases |
| MIPS32/64, big/little endian and delay slots | rdis/arch.py; rdis/ir_front.py; rdis/analysis.py | Native IR frontend and delay-slot logic; big/little-endian NOP/JR byte-boundary tests added for MIPS32/64 | PARTIAL | Independent fixtures for o32/n64 ABI, branch-likely and delay-slot side effects remain open |
| RISC-V32/64 and compressed instructions | rdis/arch.py; rdis/ir_front.py | Capstone mode and native frontend paths exist; 32-bit and 16-bit compressed instruction boundaries are now covered by fixtures | PARTIAL | Floating-point/atomic coverage, ABI and semantic differential tests remain open |
| WebAssembly parsing and function listings | rdis/wasm.py | Deterministic malformed-WASM mutation tests and bounded parsing regressions | PARTIAL | Spec-suite/version/proposal coverage, typed validation and independent disassembly oracle |
| WebAssembly CFG / C-like decompilation | rdis/wasm.py; rdis/server.py explicitly report unsupported CFG/pseudo-code | API/UI explicitly surface the limitation | UNSUPPORTED (explicit) | A separate future stack-to-CFG/decompilation milestone; do not infer support from listing support |
| Function discovery | rdis/analysis.py; loader symbols, function starts and exception metadata | Product self-check and current baseline corpus | PARTIAL | Truth-labelled per-ISA fixtures and precision/recall/F1 for stripped, optimized, thunk, tail-call and jump-table cases |
| CFG analysis and graph rendering | rdis/analysis.py; rdis/render.py; rdis/web/index.html | Chromium/Firefox browser suites: geometry, large/tall/wide graphs, minimap, keyboard selection, theme contrast, SVG export and live ELF integration | VERIFIED (bounded) | Real-world graph edge F1, screen-reader review, more browser/device versions |
| Decompiler / typed IR | rdis/decompile.py; rdis/ir.py; rdis/ir_front.py; rdis/lift.py | 124/124 execution-checked maturity cases on merged product revision; current-head baseline runner runs maturity on macOS | PARTIAL | Broader per-ISA corpus for optimized control flow, exceptions, aliasing, FP/vector and calling conventions; report semantic rate separately from compile rate |
| Objective-C / Swift / JNI metadata | rdis/objc.py; rdis/swift.py; rdis/jni.py; rdis/typelib.py; rdis/demangle.py | Existing product self-check and metadata fixture paths | PARTIAL | Versioned real binaries, truth-labelled protocol/generic/selector/RegisterNatives fixtures, malformed metadata tests |
| Cross-references, imports, strings, symbols, bookmarks | rdis/analysis.py; rdis/render.py; rdis/server.py | API routes and existing product tests | PARTIAL | Xref precision/recall, relocation/bind variants, UTF-16 and false-positive-string fixtures |
| .rdb annotations and persistent analysis cache | rdis/analysis.py; rdis/cache.py; rdis/server.py | Cache invalidation and persistent-state regressions in merged PR #3 | PARTIAL | Multi-process cache races, schema upgrade/recovery, backups and annotation migration across binary revisions |
| Web sessions and resource safety | rdis/server.py; rdis/containers.py; rdis/mcp_server.py | 20-visitor isolation/determinism stress and resource-related hardening regressions | PARTIAL | Route-by-route threat review, hostile-client stress, full quota lifecycle, remote deployment auth/authorization |
| MCP server | rdis/mcp_server.py | MCP initialize command and product checks | PARTIAL | Tool schemas, invalid requests, result caps, timeouts/cancellation and auditable AI edits |
| LLDB debugger | rdis/debug.py | Scalar argument sanitization regression and optional debugger path | PARTIAL | Versioned LLDB integration, remote targets, output/time caps and runtime/static address mapping |
| Plugin SDK | rdis/plugins.py and loader/architecture hooks | Plugin mechanisms and docs exist | PARTIAL | Versioned plugin contract, capability policy/allowlist and conformance tests |
| Emulation, symbolic execution, taint and vulnerability analysis | No complete product-level implementation established by this baseline matrix | No end-to-end correctness corpus recorded | UNVERIFIED / ROADMAP | Treat as M12; define supported semantics and acceptance oracles before advertising support |
| Binary diff/version tracking/annotation transfer | No complete end-to-end product workflow established by this baseline matrix | No labelled pairwise binary corpus or transfer scorecard | UNVERIFIED / ROADMAP | M16: function/block match precision/recall, changed-code localization and ambiguity handling |
| Fuzzing and differential correctness | tests/test_hardening.py; tests/maturity.py; tests/diffcheck.py | Deterministic mutation smoke corpus and runtime-equivalence tests in CI | PARTIAL | Sustained fuzz campaigns, coverage trends, crash minimization and independent-tool adjudication |
| Performance and memory | tests/benchmark_analysis.py plus macOS server RSS capture | Pinned /bin/ls smoke benchmark and raw artifacts | PARTIAL | Multi-size/multi-ISA corpus, cold/warm timings, p50/p95, peak/steady RSS and regression budgets |
| Browser accessibility and UX | rdis/web/index.html; tests/browser_cfg.mjs | Chromium/Firefox automation, geometry assertions, theme checks and screenshots | PARTIAL | Keyboard-only analyst tasks, screen reader, zoom/text scaling, touch input and device-size matrix |
| Competitor parity / comparative quality | DEVELOPMENT_ROADMAP.md primary vendor references and quality scorecard | Research sources define capability benchmarks; no full apples-to-apples scorecard | UNVERIFIED as a comparative result | Same corpora/options/oracles and versioned competitor runs; documentation alone does not prove relative quality |

## Current baseline evidence

The latest verified PR #4 revision 24cfdc9e0f1786bc89984aee1ff9f76fb3b7113a passed [CI run 39266670036](https://github.com/sagarchive/rdis/actions/runs/39266670036). Baseline runner results: 9 passed / 1 platform skip / 0 failures on each Python profile; 12 passed / 1 platform skip / 0 failures on macOS. These counts are runner entries and command profiles, not the total unit-test count.

## Next matrix increment

The new unit suite exercises instruction boundaries for x86/x86-64, ARM/Thumb, AArch64, MIPS32/64 in both endiannesses, and RISC-V32/64 with compressed encodings. It is a decoder smoke gate, not proof of CFG or decompiler correctness; the current-head CI result is required before treating this coverage as verified. Next extend the corpus with licensed or generated ground-truth binaries for each advertised architecture and important format. Each input must record provenance/license, SHA-256, build command, expected function/CFG facts and test coverage. Do not mark a row VERIFIED until its architecture-specific acceptance tests and negative cases pass in CI.
