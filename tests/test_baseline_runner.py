"""Tests for the reproducible baseline corpus runner."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("run_baseline.py")
SPEC = importlib.util.spec_from_file_location("rdis_run_baseline", SCRIPT)
assert SPEC and SPEC.loader
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class BaselineCorpusTests(unittest.TestCase):
    def test_committed_corpus_manifest_and_checked_in_fixture_are_valid(self):
        root = SCRIPT.parents[1]
        manifest_path = root / "tests" / "baseline_corpus.json"
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        baseline.validate_manifest(manifest)
        entries, by_id = baseline.verify_entries(manifest, root, baseline.host_context())
        self.assertEqual(manifest["corpus_id"], "rdis-baseline-corpus-v2")
        for identifier in ("cfg-fixture-source", "arm64-branch-fixture"):
            with self.subTest(entry=identifier):
                self.assertEqual(by_id[identifier]["status"], "passed", by_id[identifier])
                self.assertEqual(
                    by_id[identifier]["sha256"],
                    next(e["sha256"] for e in manifest["entries"] if e["id"] == identifier),
                )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(entries)

    def test_platform_constraint_overlays_match_captured_environment_profiles(self):
        root = SCRIPT.parents[1]
        common_path = root / "constraints" / "baseline-ci.txt"
        common = common_path.read_text(encoding="utf-8")
        self.assertIn("capstone==5.0.9", common)
        self.assertIn("lief==1.0.0", common)
        self.assertIn("pip==26.2.1", common)
        self.assertNotIn("certifi==", common, "host-observed certifi pin belongs in the macOS overlay")

        overlays = {
            "linux-py310": root / "constraints" / "baseline-linux-py310.txt",
            "linux-py312": root / "constraints" / "baseline-linux-py312.txt",
            "macos-arm64-py312": root / "constraints" / "baseline-macos-arm64-py312.txt",
        }
        for profile, path in overlays.items():
            with self.subTest(profile=profile):
                self.assertTrue(path.is_file(), f"missing constraints overlay: {path}")
                self.assertTrue(path.read_text(encoding="utf-8").startswith("#"))
        py310 = overlays["linux-py310"].read_text(encoding="utf-8")
        self.assertIn("setuptools==79.0.1", py310)
        self.assertIn("tomli==2.5.0", py310)
        macos = overlays["macos-arm64-py312"].read_text(encoding="utf-8")
        self.assertIn("certifi==2026.7.22", macos)

        workflow = (root / ".github" / "workflows" / "hardening.yml").read_text(encoding="utf-8")
        self.assertIn("CONSTRAINTS_OVERLAY: constraints/baseline-linux-py${{ matrix.python-version }}.txt", workflow)
        self.assertIn("CONSTRAINTS_OVERLAY: constraints/baseline-linux-py312.txt", workflow)
        self.assertIn("CONSTRAINTS_OVERLAY: constraints/baseline-macos-arm64-py312.txt", workflow)
        self.assertIn('--constraints-file "$CONSTRAINTS_OVERLAY"', workflow)
        self.assertIn('-c "$CONSTRAINTS_OVERLAY"', workflow)

    def test_hash_mismatch_is_reported_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "fixture.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            data = source.read_bytes()
            manifest = {
                "schema_version": 1,
                "corpus_id": "unit-test",
                "entries": [{
                    "id": "fixture",
                    "kind": "checked-in-source",
                    "path": "fixture.c",
                    "size_bytes": len(data),
                    "sha256": "0" * 64,
                    "git_blob_sha1": baseline.git_blob_sha1(data),
                    "required": True,
                }],
                "profiles": [{"id": "portable", "when": {}, "commands": []}],
            }
            baseline.validate_manifest(manifest)
            entries, by_id = baseline.verify_entries(manifest, root, baseline.host_context())
            self.assertEqual(by_id["fixture"]["status"], "failed")
            self.assertIn("SHA-256 mismatch", by_id["fixture"]["reason"])

    def test_profile_inheritance_and_machine_aliases_are_deterministic(self):
        manifest = {
            "schema_version": 1,
            "corpus_id": "profile-test",
            "entries": [],
            "profiles": [
                {"id": "portable", "when": {}, "commands": [
                    {"id": "base", "argv": ["python", "-V"], "required": True}
                ]},
                {"id": "mac-arm", "when": {"system": "Darwin", "machine": "arm64"},
                 "extends": ["portable"], "commands": [
                    {"id": "mac", "argv": ["python", "-V"], "required": True}
                ]},
            ],
        }
        baseline.validate_manifest(manifest)
        profiles, commands = baseline.selected_commands(
            manifest, {"system": "Darwin", "machine": "arm64"}, ["mac-arm"]
        )
        self.assertEqual(profiles, ["mac-arm"])
        self.assertEqual([c["id"] for c in commands], ["base", "mac"])
        self.assertTrue(baseline.matches_when({"machine": "x86_64"}, {"machine": "AMD64"}))
        self.assertTrue(baseline.matches_when({"machine": "arm64"}, {"machine": "aarch64"}))
        self.assertFalse(baseline.matches_when({"system": "Linux"}, {"system": "Darwin"}))

    def test_command_uses_argv_logs_raw_output_and_fingerprints_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output_dir = root / "artifacts" / "baseline-run"
            output_dir.mkdir(parents=True)
            command = {
                "id": "argv-not-shell",
                "argv": [
                    "{python}", "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('payload'); print(sys.argv[2])",
                    "{output_dir}/generated/output.bin",
                    "; echo NOT_A_SHELL",
                ],
                "stdout_contains": "; echo NOT_A_SHELL",
                "record_outputs": ["{output_dir}/generated/output.bin"],
                "timeout_seconds": 5,
                "required": True,
            }
            result = baseline.run_command(command, root, output_dir, baseline.host_context(), {})
            self.assertEqual(result["status"], "passed", result)
            stdout = output_dir / result["stdout_log"]
            stderr = output_dir / result["stderr_log"]
            self.assertIn("; echo NOT_A_SHELL", stdout.read_text(encoding="utf-8"))
            self.assertEqual(stderr.read_text(encoding="utf-8"), "")
            output = output_dir / result["recorded_outputs"][0]["path"]
            self.assertEqual(output.read_bytes(), b"payload")
            self.assertEqual(result["recorded_outputs"][0]["sha256"], hashlib.sha256(b"payload").hexdigest())

    def test_timeout_is_failed_and_still_leaves_raw_logs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output_dir = root / "baseline-run"
            command = {
                "id": "times-out",
                "argv": ["{python}", "-c", "import time; time.sleep(5)"],
                "timeout_seconds": 0.25,
                "required": True,
            }
            result = baseline.run_command(command, root, output_dir, baseline.host_context(), {})
            self.assertEqual(result["status"], "failed", result)
            self.assertEqual(result["reason"], "command exceeded timeout")
            self.assertTrue((output_dir / result["stdout_log"]).is_file())
            self.assertTrue((output_dir / result["stderr_log"]).is_file())

    def test_summary_links_environment_manifest_and_preserves_skip_states(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            output_dir = root / "artifacts" / "baseline-run"
            env_path = root / "artifacts" / "baseline" / "manifest.json"
            env_path.parent.mkdir(parents=True)
            env_doc = {"job": "unit-baseline", "git": {"tested_checkout_sha": None}}
            env_raw = (json.dumps(env_doc) + "\n").encode()
            env_path.write_bytes(env_raw)
            command = {"id": "portable-ok", "argv": ["{python}", "-c", "print('ok')"],
                       "stdout_contains": "ok", "timeout_seconds": 5, "required": True}
            manifest = {
                "schema_version": 1,
                "corpus_id": "summary-test",
                "entries": [{
                    "id": "inapplicable",
                    "kind": "host-system-binary",
                    "path": "/definitely/not/used/on-this-host",
                    "size_bytes": 0,
                    "sha256": "0" * 64,
                    "when": {"system": "__never_this_os__"},
                    "required_when_matched": True,
                }],
                "profiles": [{"id": "portable", "when": {}, "commands": [command]}],
            }
            baseline.validate_manifest(manifest)
            source_manifest = root / "tests" / "baseline_corpus.json"
            source_manifest.write_text(json.dumps(manifest), encoding="utf-8")
            corpus_hash = hashlib.sha256(source_manifest.read_bytes()).hexdigest()
            summary = baseline.run_baseline(
                manifest, corpus_hash, root, output_dir, ["portable"], env_path, source_manifest
            )
            self.assertEqual(summary["status"], "passed", summary)
            self.assertEqual(summary["environment_manifest"]["sha256"], hashlib.sha256(env_raw).hexdigest())
            self.assertEqual(summary["environment_manifest"]["job"], "unit-baseline")
            self.assertEqual(summary["entries"][0]["status"], "skipped")
            self.assertEqual(summary["commands"][0]["status"], "passed")
            saved = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["corpus"]["manifest_sha256"], corpus_hash)
            self.assertTrue(saved["started_at_utc"])
            self.assertTrue(saved["finished_at_utc"])


if __name__ == "__main__":
    unittest.main()
