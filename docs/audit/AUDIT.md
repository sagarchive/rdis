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
- **Verification:** runtime HTTP negative tests and concurrency stress tests remain pending.

### RDIS-AUDIT-009 — WebAssembly parser had unbounded/truncated section reads

- **Area:** M2/M4, `rdis/wasm.py`
- **Evidence:** LEB128/name helpers indexed or sliced without validating input bounds; section sizes could extend past the module; malformed sections were silently swallowed.
- **Failure mode:** truncated input could raise low-level exceptions or be accepted as a partial module without a visible parse warning.
- **Change:** add header/section bounds checks, bounded LEB128/name reads, bounded constant-expression scanning, common non-function import descriptor skipping, and recorded section errors.
- **Verification:** malformed-header/section/LEB/name regression tests added; CI result pending.
