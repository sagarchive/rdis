# RDIS Benchmark Protocol

No performance claim is made by this initial hardening change. Content hashing adds I/O in exchange for correct identity; measure its cost.

Record CPU/RAM/OS, Python, Capstone/LIEF, compiler and flags, optional tools, commit SHA and filesystem. Fix a distributable corpus and record SHA-256 for each fixture.

Workloads: stripped/unstripped executables, medium/large libraries, multi-library archives, WASM, high-function/high-xref inputs, and concurrent same/different-content opens.

Measure cold analysis time, warm restore time, time to first result, total runtime, peak RSS, output size, cache hits/bytes, archive extraction time, concurrent p50/p95 latency, error count, and semantic pass/fail. Compile rate is not semantic correctness.

Run at least five repetitions after one documented warm-up, report median and range, separate cold/warm cache, avoid competing workloads, and preserve raw commands/results. Reject any optimisation that regresses correctness. Set targets only after the baseline is measured.