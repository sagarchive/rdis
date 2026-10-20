# Same-task scorecard

`tests/scorecard.py` runs identical tasks on identical binaries with rdis and any competitor installed on the machine,
and records raw numbers with versions, binary hashes and the host. A tool that is not installed is recorded as
`not_available` with the reason; nothing is estimated.

```sh
python tests/scorecard.py --out benchmarks/scorecard/results/$(date +%F)-$(uname -s | tr A-Z a-z)-$(uname -m).json
python tests/scorecard.py --extra path/to/big-binary      # also time a larger file (hash recorded, no truth)
```

## Tasks

| Task | Metric | Oracle |
|---|---|---|
| `function_discovery` | recall of the unstripped build's functions found in the stripped build, extras reported separately, wall time, peak RSS | the symbol table of the unstripped build |
| `analysis_resources` | wall time and peak RSS of a fresh process (`--extra` binaries) | none (resource measurement only) |

The corpus is two builds of a 36-function C program (`tests/diff_corpus.py`), built with the local compiler, so
results differ by platform and compiler; the result file records both.

## Competitors

| Tool | Command used | Needs |
|---|---|---|
| radare2 | `r2 -q -e scr.color=0 -e bin.relocs.apply=true -c "aaa;aflj" -- BIN` | `r2` on `PATH` |
| Ghidra | `analyzeHeadless PROJECT scorecard -import BIN -overwrite -scriptPath benchmarks/scorecard/ghidra -postScript ExportFunctions.java OUT -deleteProject` | a JDK and `GHIDRA_INSTALL_DIR` (or `analyzeHeadless` on `PATH`) |

The radare2 and Ghidra adapters follow each tool's documented command line and are unit-tested against canned
output, but have not been run against a real installation yet: their rows carry `"adapter_verified": false` until
they are. Install either tool yourself (this repository never installs software), rerun the command above, and the
rows are filled in.

Reading a result: a lower recall for another tool is a fact about that tool on this corpus and configuration only.
Default analysis options are used for every tool; differences in options, versions and compilers change the numbers.
