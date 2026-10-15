# RDIS Source Audit Register

## Evidence policy
Separate confirmed defects, likely defects, risks, coverage gaps, improvements and unverified claims. A fix is verified only after its regression test actually runs. Runtime tests were not executed by the source-authoring step for this PR.

## Module inventory
- Binary loading: `rdis/loader.py`, `raw.py`, `arch.py` — offsets, address ranges, malformed headers, architecture modes.
- Analysis: `analysis.py` — function discovery, blocks, CFG, xrefs, partial results, determinism.
- Cache: `cache.py`, `server.py`, `mcp_server.py` — content/options identity, schema invalidation, eviction, concurrency, mutable state.
- Containers: `containers.py` — compression, ZIP/TAR/DMG, extraction identity, symlinks, subprocesses.
- Decompiler/IR: `decompile.py`, `ir.py`, `ir_front.py`, `lift.py`, `lift_simd.py`, `neon.py`, `sse.py`, `wasm.py` — semantics and unsupported operations.
- Metadata: `typelib.py`, `demangle.py`, `jni.py`, `objc.py`, `swift.py` — bounds, ABI, version variation and uncertain inference.
- Interfaces: `server.py`, `mcp_server.py`, `render.py`, `console.py`, `web/index.html`, `__main__.py` — access controls, escaping, API contracts and errors.
- Plugins/debugger: `plugins.py`, `debug.py` — executable trust, subprocess controls, compatibility and timeouts.
- Tests: `test_rdis.py`, `maturity.py`, `maturity_cases.py`, `compile_rate.py`, `diffcheck.py`, `concurrency_test.py`.
- Packaging: `pyproject.toml`, `Dockerfile`, ignore files, README/docs/assets.

## Findings addressed in this PR

### RDIS-AUDIT-001 — Web shared-analysis key used size + second-resolution mtime
Previous key: absolute path, size, `int(st_mtime)`, and selected options. Same-size replacement preserving timestamp could reuse stale analysis. Change: SHA-256 content plus canonical JSON identity for path, digest, architecture, loader, base and analysis flags. Runtime server-level regression remains pending.

### RDIS-AUDIT-002 — MCP cache was stale-prone and unbounded
Previous key omitted content identity and cache had no eviction. Change: absolute path + SHA-256 + options, lock, LRU cap of 16. Runtime MCP integration tests remain pending.

### RDIS-AUDIT-003 — Decompression could silently truncate
Previous code wrote one capped read without detecting extra output. Change: limit-plus-one streaming read rejects overflow and validates max_mb. Test added; runtime result pending.

### RDIS-AUDIT-004 — TAR extraction cache omitted archive bytes
Previous key used path/member/size. Change: include archive digest, member offset/name/size and configured limit; verify exact copied size. Test added; runtime result pending.

### RDIS-AUDIT-005 — ZIP extraction did not explicitly verify complete member copy
Change: content-based cache identity and bounded streaming with declared-size verification. Test added; adversarial corrupt archive coverage remains open.

### RDIS-AUDIT-006 — Section lookup used a fixed 256 MiB scan cutoff
Change: prefix maximum interval ends allow termination only when all earlier sections have ended. Boundary regression tests added; runtime result pending.

## Open gaps
Full suite/runtime baseline, complete line-level review, architecture semantic coverage, web quota/cleanup tests, penetration testing, sustained fuzzing, performance baselines and independent reproduction of README claims remain open.
### RDIS-AUDIT-007 — Persistent cache version identity omitted the entry point and several analysis modules

- **Area:** M1, `rdis/cache.py`
- **Evidence:** cache key options omitted `image.entry`; code fingerprint previously covered only a small subset of modules that can influence the saved Program snapshot.
- **Failure mode:** different entry-point configurations or changes in analysis/metadata-related code could leave old snapshots eligible for reuse.
- **Change:** include the image entry point in cache options and expand the code fingerprint to analysis, architecture, loader, raw loader, JNI, Objective-C, Swift, demangling, type library, plugins, and cache code.
- **Verification:** focused cache-option tests and full cache restore tests remain to be added/run.

### RDIS-AUDIT-008 — HTTP request handling lacked a request timeout and explicit framing rejection

- **Area:** M3, `rdis/server.py`
- **Evidence:** request bodies were read using Content-Length without an explicit socket timeout; Transfer-Encoding was not rejected.
- **Failure mode:** slow/incomplete requests could occupy handler threads; ambiguous/chunked framing was not an explicitly supported contract.
- **Change:** add a socket timeout, reject Transfer-Encoding and duplicate/malformed/missing Content-Length, detect incomplete bodies, validate port/upload limit, and cap concurrent handler workers with a 503 response under saturation.
- **Verification:** HTTP guards and the 20-visitor isolation/determinism stress test passed in GitHub Actions on macOS/Python 3.12 at commit `b0008467`; Python 3.10/3.12 hardening jobs also passed.

### RDIS-AUDIT-009 — WebAssembly parser had unbounded/truncated section reads

- **Area:** M2/M4, `rdis/wasm.py`
- **Evidence:** LEB128/name helpers indexed or sliced without validating input bounds; section sizes could extend past the module; malformed sections were silently swallowed.
- **Failure mode:** truncated input could raise low-level exceptions or be accepted as a partial module without a visible parse warning.
- **Change:** add header/section bounds checks, bounded LEB128/name reads, bounded constant-expression scanning, common non-function import descriptor skipping, and recorded section errors.
- **Verification:** malformed-header/section/LEB/name regression tests added; CI result pending.

### RDIS-AUDIT-010 — User-controlled line breaks could disrupt CFG DOT labels

- **Area:** M7, `rdis/render.py`
- **Evidence:** DOT label escaping covered backslashes and quotes but left carriage returns/newlines literal.
- **Failure mode:** multi-line comments or metadata could break the generated DOT label and cause graph rendering failures.
- **Change:** escape CR/LF as Graphviz newline sequences; add a regression test for newline, quote and backslash handling.
- **Verification:** regression test added; CI result pending.

### RDIS-AUDIT-011 — Maturity suite could report semantic failures with exit code zero

- **Area:** M5/M10, `tests/maturity.py`
- **Evidence:** the script printed a `SCORE ok/total` but did not exit non-zero when `ok != total`.
- **Failure mode:** CI or automation could treat a failed execution-checked decompilation suite as a successful command.
- **Change:** exit with status 1 whenever any case fails.
- **Verification:** macOS CI now runs the product self-check and maturity suite; results pending.

### RDIS-AUDIT-012 — Jump-table recovery could absorb adjacent function code

- **Area:** M4/M5, `rdis/analysis.py`
- **Evidence:** macOS execution-checked regression run produced a decompiled `sw(int)` function containing `strsum`'s loop, a pointer-typed switch key, and labels whose targets were not emitted. The original instruction trace showed an indexed table load and a separate ADR-relative target base.
- **Failure mode:** any executable-section address constant could be mistaken for the jump-table storage base; int32 offsets were then added to the wrong base and accepted merely because the result was in an executable section.
- **Change:** only consider actual indexed loads with scale 4; separate table storage address from branch-relative target base; require all recovered targets to remain within the owning function's address interval.
- **Verification:** the full macOS differential suite is rerunning after this fix; closure depends on all relevant execution tests passing.

### RDIS-AUDIT-013 — NEON CNT relied on a Clang-version-specific builtin

- **Area:** M5, `rdis/neon.py`
- **Evidence:** the macOS ARM64 execution-checked suite failed to compile generated C because `__builtin_elementwise_popcount` was unavailable in the runner's Apple Clang.
- **Failure mode:** valid NEON `CNT` instructions could not be represented as compilable C on the supported toolchain.
- **Change:** replace the newer builtin with a portable per-byte SWAR popcount helper registered in the generated-C dependency set.
- **Verification:** subsequent full self-check passed all 20 functions across six differential builds; the suite then stopped at a separate overly strict tail-call assertion, now corrected. Final rerun pending.


### RDIS-AUDIT-014 — LEA-derived pointer arithmetic could scale byte offsets by element size
- **Area:** M5, `rdis/lift.py`
- **Evidence:** the execution-based x86-64 SIMD corpus showed generated code like `&rdi[rsi_1] + 0x10`; C scales that addition in `int *` units, while the machine instruction adds bytes.
- **Failure mode:** vector-loop tail pointers can skip or read the wrong elements, changing sums and in-place updates.
- **Change:** cast computed address-of expressions through `char *` before integer add/sub; add a focused regression and rerun the execution-based corpus.
- **Verification:** the post-fix execution-based maturity suite passed 124/124 cases on macOS/Python 3.12 at commit `ce32ca4b`; focused hardening tests also passed on Python 3.10/3.12.

### RDIS-AUDIT-015 — Pinned floating-point memory expressions could default to int64_t
- **Area:** M5, `rdis/lift.py`
- **Evidence:** the ARM64 vectorized float-reduction case emitted an `int64_t` temporary for an expression containing `*(float *)`; converting intermediate values to integer truncates fractions.
- **Failure mode:** otherwise compilable pseudo-C returns the wrong numeric result.
- **Change:** recognize typed float/double pointer loads when inferring a pinned temporary's scalar type; add a regression for both widths.
- **Verification:** focused regression and the execution-based maturity suite passed at commit `ce32ca4b`; the maturity scoreboard was 124/124.



### RDIS-AUDIT-016 — Upload and extraction cache had no aggregate disk quota
- **Area:** M2/M3, `rdis/server.py`, `rdis/containers.py`
- **Evidence:** per-file/member caps did not bound the combined bytes retained by repeated uploads and extracted members.
- **Failure mode:** repeated valid requests could exhaust the service's writable disk.
- **Change:** add `--max-upload-storage-mb` (default 1024 MiB), preflight upload writes, enforce the same aggregate limit on atomic extraction-cache writes, serialize quota checks, and return HTTP 507 when storage is exhausted.
- **Verification:** aggregate upload/cache quota regressions added; current-head CI run pending. Retention/cleanup policy for stale files remains an open follow-up.
