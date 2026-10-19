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

1. **No committed replayable dependency lock exists yet.** The runner now archives a redacted, hashed pip-freeze file per job, so each CI environment is auditable. pyproject.toml deliberately retains compatibility ranges for users; a reviewed platform/Python-specific constraints strategy is still needed for repeatable future benchmark runs.
2. **The first machine-readable baseline record now exists; a cross-run scorecard does not.** Per-job environment manifests plus the baseline runner's summary.json capture source/corpus hashes, PR/base/tested-checkout identities, environment-manifest digest, pass/skip/fail results, durations, output fingerprints and raw-log paths. A normalized comparison across multiple corpus versions and architectures remains future work.
3. **No architecture-wide correctness scorecard.** Function-discovery precision/recall, CFG node/edge F1, decoder mismatch rates and type-recovery scores are not currently calculated across a truth-labelled corpus.
4. **No apples-to-apples competitor scorecard.** Vendor docs confirm documented capabilities, not comparative correctness or performance.
5. **No sustained fuzzing gate.** Deterministic malformed-WebAssembly mutation tests are useful; time-bounded fuzz campaigns, coverage trends, crash minimization and corpus retention still need to be implemented.
6. **No stable performance thresholds.** The single /bin/ls run has no regression budget and is not a representative workload suite.
7. **Accessibility evidence is incomplete.** Browser interaction screenshots do not replace keyboard-only task review, screen-reader/manual inspection, zoomed text review or broad OS/browser coverage.
8. **Security/retention review is incomplete.** The existing guards are valuable, but route-by-route deployment, upload retention, quotas, public-service authentication/authorization, project data lifecycle and plugin trust still require explicit tests.

## 7. Baseline artifact inspection

The CI manifest/artifact pipeline was inspected on [run 39262355129](https://github.com/sagarchive/rdis/actions/runs/39262355129) and then re-verified with the pull-request head/base identity fix on [run 39262871176](https://github.com/sagarchive/rdis/actions/runs/39262871176). All five jobs passed on run 39262871176. The subsequent [current-head run 39263076792](https://github.com/sagarchive/rdis/actions/runs/39263076792) also passed all five jobs on commit `039ea242e418d346702e96959479b81bcdd4fa2d`.

### Inspected artifacts — run 39262871176

| Artifact | Contents inspected | Verified observations |
|---|---|---|
| [Python 3.10 manifest](https://github.com/sagarchive/rdis/actions/runs/39262871176/artifacts/12190843008) | `manifest.json`, `pip-freeze.txt` | CPython 3.10.22 on Linux; freeze file SHA-256 matches the manifest. |
| [Python 3.12 manifest](https://github.com/sagarchive/rdis/actions/runs/39262871176/artifacts/12190788396) | `manifest.json`, `pip-freeze.txt` | CPython 3.12.15; freeze file SHA-256 matches. |
| [Chromium manifest](https://github.com/sagarchive/rdis/actions/runs/39262871176/artifacts/12190179276) | `manifest.json`, `pip-freeze.txt` | Chromium 156.0.8078.4; freeze file SHA-256 matches. |
| [Firefox manifest](https://github.com/sagarchive/rdis/actions/runs/39262871176/artifacts/12191578243) | `manifest.json`, `pip-freeze.txt` | Firefox 157.0; freeze file SHA-256 matches. |
| [macOS baseline bundle](https://github.com/sagarchive/rdis/actions/runs/39262871176/artifacts/12191228180) | `manifest.json`, `pip-freeze.txt`, `benchmark.json`, `server-rss-kib.log`, `server.log` | macOS 14.8.9 arm64 / CPython 3.12.10; freeze hash matches; benchmark and raw server evidence are present. |

For all five manifests I downloaded and inspected, the fields `pull_request_head_sha`, `pull_request_base_sha`, `tested_checkout_sha`, `pull_request_number` and `run_id` were present. The PR head matched `25a6aeb885fe1c7765c5abe16722a85e822aedf4`; the base matched current main `96b931d32c807c5430518be6c280c98fb995ebb2`; the tested checkout SHA was the synthetic merge commit `571b7755c953fa57a8a5b3fd2d9e622aeaddd638`; the run ID was `39262871176`. This distinction is intentional: `GITHUB_SHA` is the tested PR merge checkout, while the source branch head is recorded separately. The baseline collector does not dump the full process environment. The regression tests also check URL user-info and common secret/token query-parameter redaction.

Artifacts are uploaded with 30-day retention. They are reproducibility evidence for a particular CI run; do not assume they are permanent archival records. Release/benchmark decisions should retain the exact needed artifacts or publish a versioned artifact bundle.

## 8. M00 exit status

**M00: PARTIAL — initial corpus, no-shell runner, raw command logs, environment-linked machine-readable summaries and an initial source-linked support matrix are implemented and CI-verified. M00 remains open for broader ground-truth corpus coverage, reviewed baseline promotion/retention, and a committed replayable dependency-constraints strategy.**

### Completed with CI evidence

- [x] Collect machine-readable environment manifests and exact `pip freeze` per Python/browser/macOS job.
- [x] Record tested checkout SHA separately from PR head/base SHAs and PR number.
- [x] Verify SHA-256 of the emitted `pip-freeze.txt` against each inspected manifest.
- [x] Record actual Playwright browser versions in the browser manifests.
- [x] Archive the macOS benchmark JSON and server RSS/logs alongside the runtime manifest.
- [x] Test manifest identity and redaction behavior on the hardening Python matrix.
- [x] Confirm all five jobs pass on the initial artifact-inspection run [39262871176](https://github.com/sagarchive/rdis/actions/runs/39262871176).
- [x] Add versioned corpus manifest, bounded no-shell command runner, input SHA-256/Git-blob checks, timeout handling, raw stdout/stderr files and machine-readable pass/skip/fail summary linked to the environment-manifest SHA.
- [x] Add runner regressions for correct source fingerprints, intentional hash mismatch, profile inheritance/architecture aliases, argv safety, recorded-output hashes, timeout handling and environment-manifest linkage.
- [x] Execute the portable runner in Python 3.10 and 3.12 CI and the extended profile on macOS arm64. [Run 39266670036](https://github.com/sagarchive/rdis/actions/runs/39266670036) passed all five jobs on runner head 24cfdc9e0f1786bc89984aee1ff9f76fb3b7113a.
- [x] Inspect current-run baseline artifacts: [Python 3.10](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12192808301), [Python 3.12](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12192828699), [macOS arm64](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12193303015). The Python profiles each report 9 passed / 1 platform skip / 0 failures; macOS reports 12 passed / 1 platform skip / 0 failures. The C source SHA and pinned macOS /bin/ls SHA/size matched the manifest.
- [x] Add the initial source-linked [FEATURE_SUPPORT_MATRIX.md](FEATURE_SUPPORT_MATRIX.md); it explicitly separates bounded verified behaviors from partial, unverified and unsupported claims. Exact-head CI for this matrix addition is tracked separately from the runner's green run.

### Still required before M00 is DONE

- [ ] Expand the corpus beyond the initial checked-in branch/loop C fixture plus host-local macOS /bin/ls: add independently checked small/medium inputs for additional formats/ISAs, with license/provenance, SHA-256, generation command and expected function/CFG/analysis facts.
- [ ] Adopt and implement a durable promotion rule: keep per-run CI artifacts as short-lived diagnostics (30 days for baseline bundles; 14 days for browser screenshots) and promote only reviewed, accepted baselines into a versioned repository path containing summaries, environment manifests, constraints hashes and benchmark JSON. Never commit binaries without redistribution rights.
- [ ] Implement the chosen pinning policy for benchmark jobs: retain pyproject compatibility ranges for consumer installs, add reviewed platform/Python-specific constraints for reproducible CI baselines, and update pins only in deliberate dependency-upgrade changes. Current pip-freeze artifacts document the resolved environment but are not themselves a committed lock.
- [ ] Keep measuring support by architecture; the new matrix is only an initial inventory. Function-discovery precision/recall, CFG edge F1, decode/opcode coverage and decompiler semantic rates remain M01/M03–M05 exit gates.

**Next atomic action:** expand the versioned corpus with one independently truth-checked non-x86_64 fixture (prefer a small ARM64 or PE/ELF fixture depending on a reproducible compiler/toolchain), then add the baseline promotion/retention policy and platform-specific constraints files. Re-run the runner and CI, inspect the artifacts, and keep M00 PARTIAL until those remaining gates are satisfied.


## 9. Current baseline runner evidence — PR #4

**Exact tested revision:** PR head `24cfdc9e0f1786bc89984aee1ff9f76fb3b7113a`, base main `96b931d32c807c5430518be6c280c98fb995ebb2`, tested merge checkout `84daa61bf91428d8d1781e89ab9fcda50cf8049f`, run `39266670036`. The [five-job CI run passed](https://github.com/sagarchive/rdis/actions/runs/39266670036).

| Profile artifact | Runner summary | Input evidence | Link |
|---|---|---|---|
| Python 3.10 on Linux x86_64 | 9 passed / 1 platform skip / 0 failed | C fixture SHA-256 `242c4bbcb9ba9641e826f04d5a4fa3d41e4c20e62eba9469bbd2420908023484`, 566 bytes; compiled fixture recorded at 17,312 bytes with hash `caa4210c09c24dadeb4f78158c2a0eb937f83fdfcbfbdb80742429f7219afca4` | [Artifact](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12192808301) |
| Python 3.12 on Linux x86_64 | 9 passed / 1 platform skip / 0 failed | Same C source and generated ELF fingerprints as the Python 3.10 profile | [Artifact](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12192828699) |
| macOS arm64 / CPython 3.12.10 | 12 passed / 1 platform skip / 0 failed | /bin/ls SHA-256 `5a83882945a6d212134c6f417b2af54e90dfdb53e589e99c5bc2deae5c68673b`, size 154,352 bytes; benchmark JSON retained | [Artifact](https://github.com/sagarchive/rdis/actions/runs/39266670036/artifacts/12193303015) |

Each artifact includes manifest.json, pip-freeze.txt, run/summary.json, command stdout/stderr logs, and generated outputs where applicable. The summary records the corpus-manifest SHA-256 `d7a28de12fcb44aae67ea4523b4a8661bb132cf7754c545153407aa6b8f05334`, PR head/base, tested checkout SHA, and environment-manifest digest. Counts above describe baseline runner entries and commands, not the number of assertions inside each test suite.

### Policy decision

- Every CI run uploads baseline evidence for 30 days; browser screenshots/export artifacts use the configured 14-day diagnostic retention.
- A baseline is promoted only after a reviewed PR and green CI. Promotion should commit the corpus version, source/host input fingerprints, summary.json, redacted pip-freeze/environment manifest, benchmark JSON and a README with generation commands under a versioned `benchmarks/baselines/<corpus-id>/<baseline-label>/` directory. Raw binaries are committed only when licensing permits; otherwise store source/generation instructions and hashes.
- Keep pyproject.toml dependency ranges for consumer compatibility. Reproducible benchmark/test jobs will use reviewed, platform/Python-specific constraints files; the current per-run pip-freeze is audit evidence, not a dependency lock. A pin change requires deliberate review and a fresh baseline run.
- The policy is documented here; the first committed promoted baseline bundle and actual constraints files remain open work.

### Current evidence boundary

The support matrix was added on the subsequent PR branch revision `4faac5aaf2648e11de79871ef29b7b2096107132` and CI passed on that matrix revision in [run 39267587715](https://github.com/sagarchive/rdis/actions/runs/39267587715). The roadmap/report updates after that matrix revision are being revalidated on the latest PR head; do not infer that a queued run has passed.
