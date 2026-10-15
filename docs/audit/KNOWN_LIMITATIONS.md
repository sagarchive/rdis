# Known Audit Limitations

## Established by source inspection
- Web shared-analysis key used file size and second-resolution mtime rather than exact content.
- MCP Program cache omitted content digest and eviction.
- Decompression wrote a capped prefix without checking for additional output.
- TAR extraction cache identity omitted archive content.
- ZIP extraction did not explicitly verify copied bytes against declared member size.
- Section lookup used a fixed-distance early-stop condition for overlapping sections.

The focused hardening suite passed on Python 3.10 and 3.12 on commit 5d84528d (including cache/container/address-map/HTTP/MCP/WASM/rendering and CFG tests). Subsequent commits change the differential harness diagnostics and compatibility macros; their current-head run is pending. The execution-based maturity suite still exposes SIMD semantic mismatches (ARM64 float reduction and x86-64 integer vector sum/update), which remain correctness defects rather than waived tests.

## Not established
- Whether a current release has a remotely exploitable vulnerability.
- Whether every instruction lifter, loader or metadata parser is semantically correct.
- Whether published maturity/concurrency figures reproduce cleanly.
- Whether every supported OS/Python/dependency combination works.
- Whether public deployment has sufficient aggregate disk quotas, analysis deadlines, request timeouts and cleanup.
- Whether all rendering contexts are correctly escaped.
- Whether architecture support meets an external accuracy target.

For unconfirmed findings, record input, environment, command and result as NOT REPRODUCED; do not silently drop them.