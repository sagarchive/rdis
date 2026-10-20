# RDIS corpus-v2 baseline — 2026-10-19

This directory is the **permanent summary record** for the first green run of the expanded baseline corpus. The binary payloads are not redistributed here. The raw CI archives are linked below and expire under repository artifact-retention policy; `record.json` and the frozen `manifest.json` preserve the run identity, hashes, outcome counts, environment/freeze digests, constraints digests, and the one measured smoke benchmark.

## Exact provenance

- Workflow: [Hardening regression tests, run 39271318107](https://github.com/sagarchive/rdis/actions/runs/39271318107)
- Source PR head tested: `59f739dba0f938f5c4c371b32eee56cc94f15e70`
- PR base: `96b931d32c807c5430518be6c280c98fb995ebb2`
- GitHub's tested merge checkout: `f64c2b696e2b9d8596726614958693ae2adc7150`
- Corpus manifest SHA-256: `47c5a2724f96158b5be429e7776ed2e3b5e42245abdd30e3433421a20493ab90`
- Shared constraints SHA-256: `a7d98d79192afdd4fd22a8d4b5f7183c3bdfb293a953d5d1896f700959871051`

The run passed all five CI jobs, including Chromium and Firefox graph tests. The portable baseline runner recorded 11 passed / 1 platform skip / 0 failed entries and commands on each Linux Python profile; macOS arm64 recorded 14 passed / 1 platform skip / 0 failed. Those are runner-item counts, **not** test assertion counts.

## Raw evidence archives

- [Linux CPython 3.10 baseline + logs + environment](https://github.com/sagarchive/rdis/actions/runs/39271318107/artifacts/12195432559)
- [Linux CPython 3.12 baseline + logs + environment](https://github.com/sagarchive/rdis/actions/runs/39271318107/artifacts/12194853180)
- [macOS arm64 baseline + logs + benchmark + environment](https://github.com/sagarchive/rdis/actions/runs/39271318107/artifacts/12195103536)
- [Chromium CFG screenshots/export](https://github.com/sagarchive/rdis/actions/runs/39271318107/artifacts/12195482502)
- [Firefox CFG screenshots/export](https://github.com/sagarchive/rdis/actions/runs/39271318107/artifacts/12194244197)

The exact v2 manifest is also frozen as `manifest.json` beside this record; the live corpus has since advanced to v3. The full manifest used per job and `pip-freeze.txt` are included in the downloadable baseline archives. Their SHA-256 digests and the constraints-file hashes are duplicated in `record.json` so the archive can be verified independently.

## Reproduce the portable baseline

Use the exact repository checkout/commit to reproduce this result; do not run against a moving branch and call it the same baseline.

Linux x86_64 / Python 3.10:

```sh
python -m pip install pip==26.2.1
python -m pip install -c constraints/baseline-ci.txt -c constraints/baseline-linux-py310.txt -e .
python tests/run_baseline.py --manifest tests/baseline_corpus.json --profile portable --output-dir artifacts/baseline/run
```

Linux x86_64 / Python 3.12:

```sh
python -m pip install pip==26.2.1
python -m pip install -c constraints/baseline-ci.txt -c constraints/baseline-linux-py312.txt -e .
python tests/run_baseline.py --manifest tests/baseline_corpus.json --profile portable --output-dir artifacts/baseline/run
```

macOS arm64 / Python 3.12:

```sh
python -m pip install pip==26.2.1
python -m pip install -c constraints/baseline-ci.txt -c constraints/baseline-macos-arm64-py312.txt -e .
python tests/run_baseline.py --manifest tests/baseline_corpus.json --profile macos-arm64 --output-dir artifacts/baseline/run
```

When using CI, pass `--environment-manifest artifacts/baseline/manifest.json` after the environment capture step as in `.github/workflows/hardening.yml`. The host-local `/bin/ls` entry is deliberately skipped outside its exact macOS arm64 host condition.

## What this baseline proves — and does not prove

It proves that the committed source and hand-encoded AArch64 byte fixture fingerprints matched, targeted decoder/branch facts and the configured regression commands passed in the recorded environments, and the current build produced a repeatable first timing point for one arm64 executable.

It does **not** establish broad architecture support, function-discovery precision/recall, CFG edge F1, semantic decompilation accuracy outside the existing bounded maturity corpus, an apples-to-apples competitor ranking, or a performance regression threshold. The macOS `/bin/ls` benchmark was three repeats with a fresh analysis object per repeat; OS page cache may have been warm, and no threshold was applied.

No non-redistributable host binary is committed. Keep all newly promoted corpora license/provenance checked and maintain unknown/unsupported outcomes explicitly.
