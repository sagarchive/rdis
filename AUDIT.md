# RDIS Engineering Audit

Status: in progress. This file tracks evidence, not assumptions. Findings must be reproduced against a named commit before being described as confirmed.

## Evidence labels

- **Confirmed** — reproducer or test fails on the base revision and passes after the change.
- **Observed risk** — source path demonstrates a plausible failure mode; test or deployment context still needs validation.
- **Coverage gap** — no adequate test currently demonstrates the stated property.
- **Unverified claim** — README or interface claim not independently reproduced.
- **Not run** — execution was not available in the current workflow; never equate with passing.

## Initial review findings

| Area | Finding | Status | Mitigation / next evidence |
|---|---|---|---|
| `Image.section_at` | Fixed 256 MiB backscan cutoff can skip an earlier long/overlapping section | Source-confirmed risk; regression added | Prefix maximum end lookup; run regression and full suite |
| compressed inputs | Decompression read cap could silently truncate a stream without detecting excess output | Source-confirmed risk; regression added | Read limit + 1 and reject oversize |
| TAR extraction cache | Path/member/size key can reuse stale bytes after same-size archive replacement | Source-confirmed risk; regression added | Archive SHA-256 included in cache key |
| web shared analysis | Path/size/whole-second mtime key can collide after replacement | Source-confirmed risk; implementation updated | Content fingerprint + options; test replacement and concurrency |
| web document identity | Document key omitted content and analysis options | Source-confirmed risk; implementation updated | Fingerprint and analysis options in key |
| MCP cache | Unbounded cache keyed without content identity | Source-confirmed risk; implementation updated | SHA-256/stat/options key and bounded LRU |
| persistent cache code fingerprint | Manual allowlist omitted modules that affect analysis, allowing stale persisted snapshots after some code changes | Source-confirmed risk; implementation updated | Hash all sorted package Python modules; regression covers additions and edits |
| WebAssembly framing | Truncated header/section lengths could be tolerated or partially parsed | Source-confirmed risk; implementation updated | Validate header/version, section bounds and truncated LEB128; malformed-input tests |
| Graphviz labels | Control characters in comments/decoded strings could alter label framing | Source-confirmed risk; implementation updated | Strip control characters before escaping quotes/backslashes; regression test |
| upload session metadata | Session upload-token dictionary could grow without a per-session bound | Source-confirmed risk; implementation updated | Bound retained upload-token references; aggregate cache-directory disk quotas remain open |
| HTTP worker exhaustion | Thread-per-request server and unbounded parallel analyses could amplify slow-client or unique-binary load | Source-confirmed risk; implementation updated | 32 request workers, 15-second socket timeout, four concurrent analyses, capacity responses; stress test in CI |
| debugger command construction | Path, breakpoint symbol and run arguments were interpolated into LLDB command text | Source-confirmed risk; implementation updated | Quote scalar arguments and reject control characters; constrain disassembly/memory counts |
| public web deployment | Host/origin checks are not authentication; uploads and parsing are attacker-controlled | Needs route-by-route threat review | Validate defaults, authentication assumptions, quotas, timeouts, cleanup and resource bounds |
| decompiler | Existing compile/recompile tests are useful but not a proof of semantic equivalence | Coverage limitation | Add executable differential corpus and compare observable outputs |

## Review protocol

For each finding record: source path and lines at reviewed commit, input/preconditions, impact, minimal reproducer, expected/actual behaviour, regression test, fix commit, test commands and outcomes. Avoid reporting speculative exploitability as established fact.
