# RDIS Benchmark Protocol

No performance claim is made by this hardening change. Content hashing adds I/O in exchange for correct identity; measure its cost.

A deterministic harness now exists at `tests/benchmark_analysis.py`. CI runs a three-repeat smoke baseline against macOS `/bin/ls` (arm64) and prints JSON including binary SHA-256, per-run analysis time, function/block/string counts, environment and process peak RSS. It uses a fresh `Program` each repeat; the OS page cache may be warm. This is a reproducibility gate, not a universal performance claim.

Reproduce locally with:
```sh
python tests/benchmark_analysis.py /bin/ls --arch arm64 --repeat 5 --output benchmark.json
```
Keep the JSON artifact with the commit and environment before comparing revisions.

Record CPU/RAM/OS, Python, Capstone/LIEF, compiler and flags, optional tools, commit SHA and filesystem. Fix a distributable corpus and record SHA-256 for each fixture.

Workloads: stripped/unstripped executables, medium/large libraries, multi-library archives, WASM, high-function/high-xref inputs, and concurrent same/different-content opens.

Measure cold analysis time, warm restore time, time to first result, total runtime, peak RSS, output size, cache hits/bytes, archive extraction time, concurrent p50/p95 latency, error count, and semantic pass/fail. Compile rate is not semantic correctness.

Run at least five repetitions after one documented warm-up, report median and range, separate cold/warm cache, avoid competing workloads, and preserve raw commands/results. Reject any optimisation that regresses correctness. Set targets only after the baseline is measured.