# Known Audit Limitations

## Established by source inspection
- Web shared-analysis key used file size and second-resolution mtime rather than exact content.
- MCP Program cache omitted content digest and eviction.
- Decompression wrote a capped prefix without checking for additional output.
- TAR extraction cache identity omitted archive content.
- ZIP extraction did not explicitly verify copied bytes against declared member size.
- Section lookup used a fixed-distance early-stop condition for overlapping sections.

The focused hardening suite (including aggregate quota and deterministic malformed-WebAssembly smoke tests), full product self-check, execution-based maturity suite (124/124), and 20-visitor isolation/determinism stress test passed on macOS/Python 3.12 and Python 3.10/3.12 at commit `b0008467`. Subsequent commits improve unknown-target CFG labeling and add corresponding regressions/docs; current-head CI is rerunning. The 124-case corpus is evidence, not proof of correctness for every ISA or instruction.

## Not established
- Whether a current release has a remotely exploitable vulnerability.
- Whether every instruction lifter, loader or metadata parser is semantically correct.
- Whether published maturity/concurrency figures reproduce cleanly.
- Whether every supported OS/Python/dependency combination works.
- Whether quota-pressure cleanup/retention policies and deployment-specific analysis deadlines are sufficient; aggregate upload/extraction storage now has a configurable cap.
- Whether all rendering contexts are correctly escaped.
- Whether architecture support meets an external accuracy target.

For unconfirmed findings, record input, environment, command and result as NOT REPRODUCED; do not silently drop them.