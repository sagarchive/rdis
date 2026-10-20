# Same-task scorecard

`tests/scorecard.py` runs identical tasks on identical binaries with rdis and any competitor installed on the machine,
and records raw numbers with versions, binary hashes and the host. A tool that is not installed is recorded as
`not_available` with the reason; nothing is estimated.

```sh
python tests/scorecard.py --out benchmarks/scorecard/results/$(date +%F)-$(uname -s | tr A-Z a-z)-$(uname -m).json
python tests/scorecard.py --sources SOURCES_DIR --out ...  # add the real-program corpus (see below)
python tests/scorecard.py --extra path/to/big-binary      # also time a larger file (hash recorded, no truth)
```

## Tasks

| Task | Metric | Oracle |
|---|---|---|
| `function_discovery` | recall of the unstripped build's functions found in the stripped build, extras reported separately, wall time, peak RSS | `nm` on the unstripped build, `__TEXT,__text` only |
| `analysis_resources` | wall time and peak RSS of a fresh process (`--extra` binaries) | none (resource measurement only) |

The corpus is two builds of a 36-function C program (`tests/diff_corpus.py`) plus, with `--sources`, SQLite 3.54.1, Lua 5.4.8
and zlib 1.3.2 (`tests/real_corpus.py`, sources pinned by SHA-256). Each program is built with clang `-O2` for arm64 and x86_64,
once with the linker's function-start table (`fs`) and once without it (`nofs`), because other tools may read that table and
the score must not depend on it silently. Every tool is scored only on addresses inside `__TEXT,__text`, so stub entries
are not counted against anyone. Results differ by platform and compiler; the result file records both.

## Result: 2026-10-21, macOS arm64, rdis `89ed6f4`

Cells are recall / extra functions / wall time / peak RSS. Higher recall and fewer extras are better.

| Build | rdis | Ghidra 12.1.4 | radare2 6.2.4 |
|---|---|---|---|
| lua-arm64-fs | 0.999 / 23 / 0.8s / 270 MiB | 0.999 / 1 / 6.1s / 706 MiB | 0.999 / 2 / 1.7s / 35 MiB |
| lua-arm64-nofs | 0.972 / 24 / 0.8s / 270 MiB | 0.907 / 4 / 5.9s / 741 MiB | 0.916 / 24 / 1.6s / 34 MiB |
| lua-x86_64-fs | 0.999 / 14 / 1.0s / 367 MiB | 0.997 / 2 / 6.6s / 763 MiB | 0.999 / 4 / 1.2s / 31 MiB |
| lua-x86_64-nofs | 0.979 / 16 / 1.0s / 367 MiB | 0.976 / 2 / 6.7s / 761 MiB | 0.686 / 4 / 0.8s / 29 MiB |
| sqlite-arm64-fs | 1.000 / 4 / 4.7s / 1260 MiB | 0.999 / 10 / 14.4s / 1189 MiB | 1.000 / 0 / 9.2s / 120 MiB |
| sqlite-arm64-nofs | 0.958 / 15 / 4.8s / 1252 MiB | 0.751 / 16 / 13.0s / 1173 MiB | 0.834 / 73 / 7.8s / 116 MiB |
| sqlite-x86_64-fs | 1.000 / 5 / 6.6s / 1870 MiB | 1.000 / 14 / 15.8s / 1141 MiB | 1.000 / 7 / 6.6s / 102 MiB |
| sqlite-x86_64-nofs | 0.978 / 20 / 6.7s / 1857 MiB | 0.948 / 14 / 15.7s / 1162 MiB | 0.666 / 6 / 4.6s / 91 MiB |
| zlib-arm64-fs | 0.994 / 0 / 0.4s / 145 MiB | 0.994 / 0 / 4.5s / 615 MiB | 0.994 / 0 / 0.5s / 22 MiB |
| zlib-arm64-nofs | 0.855 / 3 / 0.4s / 144 MiB | 0.709 / 1 / 4.4s / 499 MiB | 0.680 / 17 / 0.5s / 21 MiB |
| zlib-x86_64-fs | 0.995 / 1 / 0.5s / 188 MiB | 0.995 / 0 / 5.2s / 625 MiB | 0.995 / 0 / 0.4s / 22 MiB |
| zlib-x86_64-nofs | 0.947 / 1 / 0.5s / 185 MiB | 0.825 / 0 / 5.1s / 552 MiB | 0.670 / 0 / 0.3s / 21 MiB |

Reading it honestly:
- With the function-start table every tool reaches about 0.99-1.00 recall, so that case does not separate them.
- Without it, rdis has the highest recall on all six builds. Its extras are comparable to Ghidra's and radare2's on most builds
  (rdis 0-24, Ghidra 0-16, radare2 0-73) and higher than Ghidra's on both lua builds (14-24 against 1-4).
- rdis is faster than Ghidra on every build and faster than radare2 on the larger ones, slower than radare2 on the smallest.
- rdis uses far more memory than radare2 (about 10x on the large binaries) and about the same as Ghidra on sqlite.
- This is one corpus, one compiler, one optimisation level, three programs, thin Mach-O files. It does not cover ELF/PE
  output, optimised-for-size builds, C++/Rust/Go, or stripped binaries from other compilers.

## Competitors

| Tool | Command used | Needs |
|---|---|---|
| radare2 | `r2 -q -e scr.color=0 -e bin.relocs.apply=true -c "aaa;aflj" BIN` | `r2` on `PATH` |
| Ghidra | `analyzeHeadless PROJECT scorecard -import BIN -overwrite -scriptPath benchmarks/scorecard/ghidra -postScript ExportFunctions.java OUT -deleteProject` | a JDK and `GHIDRA_INSTALL_DIR` (or `analyzeHeadless` on `PATH`) |

Both adapters were run on real installs (radare2 6.2.4 built from the release tarball; Ghidra 12.1.4 with Temurin 21.0.12), and
the first run exposed two adapter bugs (a `--` that stopped radare2 opening the file, and a missing Ghidra project directory),
now fixed. Install either tool yourself (this repository never installs software) and rerun the command above.

Reading a result: a lower recall for another tool is a fact about that tool on this corpus and configuration only.
Default analysis options are used for every tool; differences in options, versions and compilers change the numbers.
