# RDIS Threat Model

## Assets
Analysis integrity; confidentiality of uploaded binaries and annotations; host filesystem/processes; CPU/memory/threads/temp storage/cache/output bandwidth; integrity of HTML/SVG/JSON/MCP responses.

## Trust boundaries and controls
- Uploads: treat all bytes and filenames as hostile; size limits, bounded parsing, safe names and cleanup.
- Archives: hostile metadata/paths/compressed streams/symlinks; expansion and member limits, exact-size checks, traversal prevention.
- HTTP: hostile headers/body/Host/Origin/cookies/routes; body framing and size limits, CSRF/Host controls, isolation and deadlines.
- Reverse proxy: do not trust forwarded headers without an explicit deployment contract.
- Visitors: no cross-session documents/uploads/annotations; random session IDs and bounded registries.
- MCP: validate JSON-RPC and tool arguments; bound inputs/outputs and use structured errors.
- Plugins: Python imports execute code; treat plugins as trusted unless actually sandboxed.
- Debugger/processes: fixed argument arrays, no shell interpolation, timeout, bounded output, explicit opt-in.
- Cache/sidecars: stale/corrupt files are possible; content/version identity, atomic writes, safe parse failure.
- Rendering: symbols, strings and comments are untrusted; context-sensitive escaping and output bounds.

## Required negative tests
- Public mode cannot open arbitrary host paths or enable Python evaluation.
- Session A cannot read/change session B state.
- Hostile browser origins cannot trigger privileged local actions.
- Invalid/oversized/incomplete HTTP bodies fail within bounds.
- Archive paths and symlinks cannot escape extraction storage.
- Oversized decompression fails without leaving a partial artifact.
- Corrupt cache rebuilds safely.
- Plugin/debugger errors do not leak secrets or unbounded tracebacks.
- Pathological input stays within CPU, memory, disk and output budgets.

## Deployment guidance
Use an authenticated proxy and network rate limiting for public deployments; run as an unprivileged account; isolate writable directories; apply CPU/memory/process/disk quotas; avoid sensitive host mounts; enable only trusted plugins; define upload retention and cleanup; log bounded metadata, not binaries or secrets.