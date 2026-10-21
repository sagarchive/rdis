# RDIS baseline corpus v4 — 2026-10-20

This is a permanent, license-safe record for a bounded reproducibility/correctness baseline. It is **not** a comprehensive architecture accuracy or performance scorecard.

## Source and execution evidence

- Live corpus ID: `rdis-baseline-corpus-v4`
- Live manifest snapshot: [manifest.json](manifest.json)
- Machine-readable results: [truth-results.json](truth-results.json)
- Record: [record.json](record.json)
- Successful five-job CI run: https://github.com/sagarchive/rdis/actions/runs/39411079671
- Candidate source PR: https://github.com/sagarchive/rdis/pull/5 (draft, unmerged at capture time)
- PR head tested: `987ad310f7784826ad198d238fc9ea2682865fa6`
- Tested GitHub merge checkout: `29fdc234129abccfa95aeeef8f99eb6e07d8e554`
- Base `main` at capture: `96b931d32c807c5430518be6c280c98fb995ebb2`

No host-provided executable is committed. The macOS runner's `/bin/ls` is fingerprinted/analyzed in place.

## Reproduce the truth tests

Install the current project with the recorded constraints for the target Python profile, then run:

```sh
python -m unittest discover -s tests -p 'test_analysis_truth.py' -v
python -m unittest discover -s tests -p 'test_baseline_runner.py' -v
python tests/run_baseline.py --profile portable --output-dir artifacts/baseline/run \
  --environment-manifest artifacts/baseline/manifest.json
```

The first command covers the compiler-produced function/CFG fixtures. The optimized relative jump-table test compiles an x86-64 PIE with `cc -O2 -fPIE -pie`, independently decodes instruction destinations with GNU `objdump`, parses 12 signed 32-bit table offsets from `.rodata`, and compares the resulting expected block edges with RDIS output.

## Exact bounded results

| Fixture | Expected edges/functions | Observed | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| x86-64 direct switch, `-O0`, jump tables disabled | 48 CFG edges | 48 | 1.000 | 1.000 | 1.000 |
| x86-64 optimized PIE relative jump table, `-O2`, 12 cases | 14 CFG edges | 14 | 1.000 | 1.000 | 1.000 |
| Hand-encoded AArch64 branch fixture | 4 CFG edges | 4 | 1.000 | 1.000 | 1.000 |
| Hand-encoded x86-64 loop fixture | 3 CFG edges | 3 | 1.000 | 1.000 | 1.000 |
| x86-64 function-start fixture, `-O0`/`-O2`, symbols/stripped | 7 starts per configuration | 7 each | 1.000 | 1.000 | 1.000 |

On the captured Ubuntu 24.04/GCC 13.3 run, the relative jump table base was `0x2004`, the indirect dispatch instruction was `0x12dd`, and all 12 target entries resolved to valid instruction addresses. Exact machine-generated addresses can change if compiler/linker versions change; the test is designed to fail rather than accept a different shape silently.

## Limits

These results apply only to these fixtures/compiler settings. They do not establish switch/jump-table accuracy across compilers, 64-bit absolute tables, other ISAs, unresolved indirect-call recall, exception/unwind flow, overlapping/shared/tail blocks, or general decompiler semantic correctness. CI artifacts have time-limited retention; this directory keeps the source/manifest fingerprints, summary metrics and links permanently.
