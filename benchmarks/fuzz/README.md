# Fuzz campaigns

`tests/fuzz.py` runs deterministic mutation campaigns over every parser and decoder that reads untrusted bytes.
A case is fully determined by `(target, seed, index)`, so any finding replays exactly:
`python tests/fuzz.py --replay elf 3 17`. Workers run in subprocesses so a native crash or hang is recorded instead
of ending the run, and each distinct failure is minimized by delta debugging.

| Target | Input | Acceptable outcome |
|---|---|---|
| `elf` | mutated ELF and Mach-O files, then analysis and decompilation | opens, or `ValueError` |
| `zip` | mutated archives, listing and extraction | lists/extracts, or `ValueError` |
| `wasm` | mutated WebAssembly modules | parses, or `ValueError` |
| `mcp` | mutated JSON-RPC lines through the real handler | always a well-formed reply |
| `decode` | random bytes through 17 CPU decoders | a list of instructions |
| `ir` | random machine code through analysis and the IR decompiler | completes |

Anything else (another exception type, a timeout, memory above 3 GiB, a native crash) is a failure.

`campaign-2026-10-20-darwin-arm64.json`: 18 seeds x 200 cases per target (21,600 cases), 0 failures, on the code at the
commit that adds this file. The same harness found eight distinct defects in its first runs: an ELF with an unknown CPU
number, three archive error types, a Mach-O without a dynamic symbol table, and three
segmentation faults inside pypcode's SLEIGH on malformed delay slots. Each has a regression test.

Scope: no Mach-O/PE-specific seeds beyond a compiled sample, no grammar-based generation, no coverage guidance, and a
short campaign by fuzzing standards. It shows these inputs are handled; it does not show the absence of other bugs.
