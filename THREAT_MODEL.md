# RDIS Threat Model (working draft)

## Assets
- Binary contents and derived analysis results.
- Per-session renames, comments, bookmarks and type annotations.
- Host files reachable by the server process.
- Server CPU, memory, disk, subprocesses and availability.
- Plugin/debugger execution privileges.

## Trust boundaries
1. Uploaded binaries and archives are untrusted parser inputs.
2. A browser request may be untrusted even when it reaches a local server.
3. A remote client is not trusted merely because it passes an Origin check.
4. Plugins and the optional Python console execute code and must be treated as trusted operator-controlled capabilities.
5. Cached data must not cross content, option, or session boundaries incorrectly.

## Primary abuse cases to test
- Crafted binary or metadata triggers parser crash, pathological CPU, memory exhaustion or out-of-bounds behaviour in dependencies.
- Compression/archive bomb exceeds decompressed, aggregate disk or scan limits.
- Same path and metadata with replaced bytes returns stale analysis.
- Session identifiers or shared state expose another visitor's edits or document.
- Publicly reachable server accepts arbitrary paths or uploads without authentication.
- User-controlled names/comments become HTML/SVG/DOT injection.
- MCP requests create unbounded work, payloads or cache entries.
- Debugger/plugin/Python execution crosses the intended privilege boundary.

## Required controls
- Explicit safe defaults and a clear statement that the service is not an authenticated multi-tenant hosting product unless that guarantee is implemented.
- Per-file and aggregate resource limits, deadlines, bounded concurrency and cleanup.
- Content- and option-aware cache identity.
- Session isolation tests and safe cookie handling.
- Context-appropriate output escaping.
- Optional code execution disabled by default and strongly documented.
- Fuzzing and minimized regression corpus.

This draft identifies risks to validate; it does not assert that every listed exploit is currently possible.
