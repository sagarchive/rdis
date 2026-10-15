# Test Matrix

| Layer | Required evidence | Current work |
|---|---|---|
| Address mapping | Sections, overlapping segments, very large ranges, file offsets | Regression for >256 MiB overlapping lookup added |
| Compression | Exact cap, cap+1, corrupt stream, truncated stream, cleanup | Oversize regression added |
| Archive extraction | Same path/member/size after archive replacement, invalid member, size mismatch | Same-size replacement regression added |
| Shared analysis | Same-size same-mtime replacement, options, concurrency, failure gate cleanup | Implementation updated; dedicated tests pending |
| MCP cache | Same-path replacement, option variation, max entries | Same-path replacement and limit tests added; max-entry eviction test pending |
| Persistent analysis cache | Any package module edit/addition invalidates prior snapshot | Regression added for new and modified module fingerprints |
| WebAssembly | Truncated header, section size, LEB128 length | Malformed framing regressions added |
| Graphviz | Control characters, quotes, backslashes in labels | Escaping regression added |
| Upload/session state | Token metadata growth under repeated uploads | Per-session bound and regression added; aggregate disk quota still pending |
| HTTP concurrency | Session isolation, deterministic concurrent analysis, slow/over-capacity clients | Multi-visitor stress test added to CI; current-head run pending |
| Debugger | Quotes, backslashes and control characters in scalar command arguments | Unit regression added; LLDB integration not exercised in CI |
| Decompiler | Cross-architecture executable differential corpus | Existing tests need full run and independent baseline |
| Web security | session isolation, auth assumptions, quotas, escaping | Audit pending |
| Packaging | clean install, wheel contents, Python matrix, Docker hardening | Audit pending |

## Execution record

- GitHub source inspection and branch edits are possible in this workflow.
- Local Python execution has not yet been established for the working branch. Do not treat newly added tests as passed until they are actually run.
