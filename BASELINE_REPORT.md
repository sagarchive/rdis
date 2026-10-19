# RDIS Baseline Report

**Baseline source:** main  
**Baseline SHA:** 96b931d32c807c5430518be6c280c98fb995ebb2  
**Captured:** 2026-10-19  
**Status:** initial CI-backed baseline; reproducibility and correctness measurement gaps remain.

## 1. Source and workflow evidence

- Current-main hardening workflow: [run 39228787777](https://github.com/sagarchive/rdis/actions/runs/39228787777) — all five jobs passed.
- Current-main Pages deployment: [run 39228786794](https://github.com/sagarchive/rdis/actions/runs/39228786794) — passed.
- Merged CFG/analysis product change verification: [run 39228116226](https://github.com/sagarchive/rdis/actions/runs/39228116226) — all five jobs passed after the switch recovery review fix.
- This report does not claim a fresh local run. Execution evidence is from those GitHub Actions runs and logs.
- CI workflow: .github/workflows/hardening.yml. It builds/installs a wheel, verifies packaged UI assets and CLI/MCP entry points, syntax-checks the app and Pages JavaScript, checks SEO/discovery files, runs hardening and typed-IR tests, runs Chromium/Firefox browser tests, then runs the macOS full self-check, benchmark, maturity and concurrency jobs.

## 2. Test results on the current main SHA

| Layer | Environment / command | Observed result | What it proves—and does not prove |
|---|---|---|---|
| Package and command smoke | Python 3.10 and 3.12 CI jobs; wheel build/install; rdis --help, rdis-gui --help, MCP initialize | Passed | Wheel exposes the UI and entry points launch. Does not establish every optional-extra combination. |
| Hardening regression tests | Python 3.10.22 and 3.12.15 on Ubuntu 24.04 runners; unittest discover for test_hardening.py | 42 tests passed on each runtime | The covered regression suite passed. Not a proof against untested malformed inputs or exhaustive fuzzing. |
| Typed IR contracts/semantics | Python 3.10.22 and 3.12.15; unittest discover for test_ir_*.py | 25 tests passed on each runtime | Covered contracts and semantic regressions passed. Coverage still needs to be quantified by opcode/ISA. |
| Browser CFG suite | Chromium and Firefox on Ubuntu runners; tests/browser_cfg.mjs | Both passed | Test fixtures cover graph geometry, dense/tall/wide cases, minimap/navigation, keyboard interaction, contrast, SVG export and live-server integration. Does not replace manual screen-reader or broad browser/device review. |
| Full product self-check | macOS 14.8.9 arm64, CPython 3.12.10; python tests/test_rdis.py | Passed | Existing product assertions passed at this commit. It is not a formal proof of all features. |
| Decompiler maturity | macOS 14.8.9 arm64, CPython 3.12.10; python tests/maturity.py | SCORE 124/124 | Current execution-checked suite passes. Its representativeness and architecture coverage remain limited. |
| Multi-visitor correctness | macOS; rdis-gui in multi-user mode plus tests/concurrency_test.py | 20 concurrent visitors + determinism check; 0 reported problems | Covered sessions did not leak/corrupt results in this test. Does not substitute for longer stress, multi-process cache and hostile-client tests. |
| Browser artifacts | Current main run | [Chromium screenshots/export](https://github.com/sagarchive/rdis/actions/runs/39228787777/artifacts/12175357412); [Firefox screenshots/export](https://github.com/sagarchive/rdis/actions/runs/39228787777/artifacts/12175966470) | Downloadable evidence for the exact main run. Artifact retention is time-limited. |

### Test environment facts visible in the logs

- Linux jobs used Ubuntu 24.04 runners with CPython 3.10.22 and 3.12.15.
- Browser execution used Playwright Chromium 156.0.8078.4 and Firefox 157.0 in the observed run.
- macOS job reported macOS 14.8.9 arm64 and CPython 3.12.10.
- GitHub-hosted runner and downloaded browser versions are mutable over time; record them again for any later comparison.

## 3. Initial performance sample

From the benchmark output in [current-main CI run 39228787777](https://github.com/sagarchive/rdis/actions/runs/39228787777):

| Metric | Observed value |
|---|---:|
| Input | /bin/ls on the macOS arm64 runner |
| Input SHA-256 | 5a83882945a6d212134c6f417b2af54e90dfdb53e589e99c5bc2deae5c68673b |
| Input size | 154,352 bytes |
| Analysis architecture | arm64 |
| Functions / basic blocks | 42 / 918 |
| Sections / strings | 11 / 99 |
| Repetitions | 3 fresh Program instances |
| Analysis seconds | 0.080719, 0.085993, 0.088508 |
| Median analysis seconds | 0.085993 |
| Peak RSS | 107,003,904 bytes |
| Environment | CPython 3.12.10, macOS-14.8.9-arm64-arm-64bit |

**Interpretation:** one small-binary smoke benchmark provides a seed for later comparisons, not a performance claim. The benchmark note explicitly says the OS page cache may be warm and there is no performance threshold. It does not measure cold-start wall time, p50/p95 across a corpus, very large binaries, memory after many files, graph rendering or concurrency throughput.

## 4. Inherited real-binary and decompiler figures

The merged [PR #3 description](https://github.com/sagarchive/rdis/pull/3) reports, for its stated 40-binary macOS /usr/bin corpus and compiler-output checks:

- arm64: 1,085 functions; 97.3% output compiled.
- x86-64: 973 functions; 95.5% output compiled.

It also reports 124/124 execution-checked maturity cases. Compile rate measures whether emitted C compiles; it is not the same as runtime semantic equivalence, type fidelity or readability. Keep these as inherited PR evidence, and rerun/archive raw outputs under the baseline protocol before using them for future trend comparisons.

## 5. Reproducibility gaps found in the current CI baseline

These are open gates, not failures in the passing workflow:

1. **No full dependency lock/snapshot is attached.** The workflow upgrades pip and installs minimum-compatible packages dynamically; pyproject.toml declares ranges, not exact versions. The observed outputs do not provide a complete pip freeze for each job.
2. **No single machine-readable run manifest.** The benchmark JSON captures its own environment/input data, but test, browser and dependency facts are scattered through workflow logs.
3. **No architecture-wide correctness scorecard.** Function-discovery precision/recall, CFG node/edge F1, decoder mismatch rates and type-recovery scores are not currently calculated across a truth-labelled corpus.
4. **No apples-to-apples competitor scorecard.** Vendor docs confirm documented capabilities, not comparative correctness or performance.
5. **No sustained fuzzing gate.** Deterministic malformed-WebAssembly mutation tests are useful; time-bounded fuzz campaigns, coverage trends, crash minimization and corpus retention still need to be implemented.
6. **No stable performance thresholds.** The single /bin/ls run has no regression budget and is not a representative workload suite.
7. **Accessibility evidence is incomplete.** Browser interaction screenshots do not replace keyboard-only task review, screen-reader/manual inspection, zoomed text review or broad OS/browser coverage.
8. **Security/retention review is incomplete.** The existing guards are valuable, but route-by-route deployment, upload retention, quotas, public-service authentication/authorization, project data lifecycle and plugin trust still require explicit tests.

## 7. Baseline artifact inspection

The CI manifest/artifact pipeline was exercised on [run 39262355129](https://github.com/sagarchive/rdis/actions/runs/39262355129); all five jobs passed and the artifacts were downloaded for inspection.

| Artifact | Contents inspected | Observed facts |
|---|---|---|
| [Python 3.10 manifest](https://github.com/sagarchive/rdis/actions/runs/39262355129/artifacts/12189898955) | `manifest.json`, `pip-freeze.txt` | Runner reported Linux, CPython 3.10.22; manifest SHA-256 matched the exact freeze file. |
| [Python 3.12 manifest](https://github.com/sagarchive/rdis/actions/runs/39262355129/artifacts/12190418418) | `manifest.json`, `pip-freeze.txt` | Separate runtime inventory and hashed freeze file are produced. |
| [Chromium manifest](https://github.com/sagarchive/rdis/actions/runs/39262355129/artifacts/12190413389) | `manifest.json`, `pip-freeze.txt` | Browser version recorded as 156.0.8078.4; freeze digest matched. |
| [Firefox manifest](https://github.com/sagarchive/rdis/actions/runs/39262355129/artifacts/12191996829) | `manifest.json`, `pip-freeze.txt` | A browser-specific manifest/freeze artifact is produced. |
| [macOS baseline bundle](https://github.com/sagarchive/rdis/actions/runs/39262355129/artifacts/12189929202) | `manifest.json`, `pip-freeze.txt`, `benchmark.json`, `server-rss-kib.log`, `server.log` | Runner reported macOS 14.8.9 arm64 / CPython 3.12.10; freeze digest matched and benchmark/raw server evidence was included. |

### Provenance correction discovered during artifact review

The first manifests recorded `GITHUB_SHA`, which is the synthetic merge-checkout SHA for a `pull_request` workflow, not the source branch's PR head SHA. That is the right identity for the tested merge tree but is ambiguous if stored alone. The capture code now records separate fields for the tested checkout SHA, pull-request head SHA, pull-request base SHA and PR number by reading the runner's event payload. A regression test supplies a synthetic event and checks these fields. The current-head CI rerun must pass before that provenance correction is considered verified.

The artifact review demonstrates that exact pip-freeze hashes and useful environment metadata are being saved. It does not yet prove all artifacts have the correct head/base identity on the latest branch commit; that is the next verification gate.

## 6. M00 exit status

**M00: PARTIAL — CI baseline recorded; machine-readable environment capture is implemented in the active PR but awaits current-head CI and artifact inspection.**

Before M00 can be closed:
- [ ] Verify the CI-captured clean-environment manifests include OS/CPU, Python/Node/browser/compiler versions, pip freeze and exact source SHA.
- [ ] Inspect the new artifacts for every relevant job, and verify their recorded SHA matches the corresponding run.
- [ ] Keep raw benchmark JSON, RSS/server logs and browser artifacts indexed by workflow run/commit; add hashes and clear retention instructions.
- [ ] Run the complete baseline command set on a clean checkout and distinguish passes, skips and unavailable optional tools.
- [ ] Confirm the manifest-capture regression tests pass on Python 3.10 and 3.12 and that URLs with credentials/query tokens are redacted.
- [ ] Keep the main baseline SHA and all comparison inputs immutable for future trend reports.

### M00 follow-up implementation (current PR branch; pending CI)

- `tests/capture_environment.py` writes `manifest.json` and a hashed `pip-freeze.txt`, records source/CI/runtime metadata and selected tool/browser versions, and avoids a full process-environment dump.
- The pip-freeze sanitizer redacts URL user-info and common secret/token query parameters before writing the artifact.
- `tests/test_baseline_capture.py` tests manifest/freeze hashing, secret-safe output and the redaction rules.
- `.github/workflows/hardening.yml` now uploads baseline-manifest artifacts for the Python 3.10/3.12 jobs, Chromium/Firefox browser jobs and macOS test/benchmark job. The macOS artifact also captures the raw benchmark and server RSS/logs where present.
- These changes are not yet marked verified until the current-head CI passes and the generated artifacts are inspected.

**Next action:** wait only in the sense of checking current tool state—not background work: query the newest PR CI run now, fix any failing test/workflow, then inspect the resulting artifacts and update this report/cursor. Do not mark M00 done until the above checklist is satisfied.
