"""Regression tests for the CI environment/baseline artifact collector."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("capture_environment.py")
SPEC = importlib.util.spec_from_file_location("rdis_capture_environment", SCRIPT)
assert SPEC and SPEC.loader
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class EnvironmentCaptureTests(unittest.TestCase):
    def test_pip_freeze_redacts_url_credentials_and_sensitive_query_values(self):
        source = (
            "private-lib @ https://build-user:top-secret@example.invalid/pkg.whl"
            "?token=abc123&sha256=deadbeef\n"
            "other-lib @ https://example.invalid/wheel.whl?api_key=another-secret\n"
        )
        result = capture.redact_pip_freeze(source)
        self.assertNotIn("top-secret", result)
        self.assertNotIn("abc123", result)
        self.assertNotIn("another-secret", result)
        self.assertIn("https://<redacted>@", result)
        self.assertIn("token=<redacted>", result)
        self.assertIn("api_key=<redacted>", result)
        self.assertIn("sha256=deadbeef", result)

    def test_manifest_and_freeze_are_written_with_exact_digest_without_environment_dump(self):
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env.update({
                "GITHUB_SHA": "test-commit-sha",
                "GITHUB_JOB": "capture-test",
                "RDIS_PRIVATE_SENTINEL": "must-not-be-recorded",
            })
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--output-dir", td,
                    "--job", "capture-test",
                    "--command", "python -m unittest example",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=90,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            manifest_path = Path(td) / "manifest.json"
            freeze_path = Path(td) / "pip-freeze.txt"
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(freeze_path.is_file())
            manifest = json.loads(manifest_path.read_text())
            freeze = freeze_path.read_bytes()
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["job"], "capture-test")
            self.assertEqual(manifest["git"]["sha"], "test-commit-sha")
            self.assertEqual(manifest["commands"], ["python -m unittest example"])
            self.assertEqual(
                manifest["dependencies"]["pip_freeze_sha256"],
                hashlib.sha256(freeze).hexdigest(),
            )
            self.assertTrue(manifest["dependencies"]["pip_freeze_redacted"])
            self.assertNotIn("RDIS_PRIVATE_SENTINEL", manifest["curated_ci_environment"])
            self.assertNotIn("must-not-be-recorded", manifest_path.read_text())
            self.assertNotIn("must-not-be-recorded", freeze_path.read_text())


if __name__ == "__main__":
    unittest.main()
