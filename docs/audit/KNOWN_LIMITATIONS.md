# Known Audit Limitations

## Established by source inspection
- Web shared-analysis key used file size and second-resolution mtime rather than exact content.
- MCP Program cache omitted content digest and eviction.
- Decompression wrote a capped prefix without checking for additional output.
- TAR extraction cache identity omitted archive content.
- ZIP extraction did not explicitly verify copied bytes against declared member size.
- Section lookup used a fixed-distance early-stop condition for overlapping sections.

This PR changes these paths and adds focused tests. Runtime execution is still required before calling the changes verified.

## Not established
- Whether a current release has a remotely exploitable vulnerability.
- Whether every instruction lifter, loader or metadata parser is semantically correct.
- Whether published maturity/concurrency figures reproduce cleanly.
- Whether every supported OS/Python/dependency combination works.
- Whether public deployment has sufficient aggregate disk quotas, analysis deadlines, request timeouts and cleanup.
- Whether all rendering contexts are correctly escaped.
- Whether architecture support meets an external accuracy target.

For unconfirmed findings, record input, environment, command and result as NOT REPRODUCED; do not silently drop them.