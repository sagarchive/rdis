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