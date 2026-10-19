#!/usr/bin/env python3
"""Capture a reproducible, secret-safe runtime manifest for RDIS CI jobs.

This script intentionally records a curated set of environment metadata and pip freeze
rather than dumping the complete process environment (which may contain secrets).
Optional tool/browser probes are captured with their return code instead of silently
inventing a version or making the manifest step hide a test failure.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone


def probe(argv: list[str], timeout: int = 15) -> dict:
    """Run a version/probe command safely, capturing failure as data."""
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[:12000],
            "stderr": result.stderr.strip()[:4000],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}"}


def maybe_version(name: str, args: list[str] | None = None) -> dict:
    executable = shutil.which(name)
    if not executable:
        return {"available": False}
    result = probe([executable, *(args or ["--version"])])
    result["available"] = result.get("returncode") == 0
    result["path"] = executable
    return result


def package_versions() -> dict[str, str]:
    wanted = {
        "rdis", "capstone", "lief", "pypcode", "pywebview", "playwright",
        "setuptools", "wheel", "build",
    }
    versions: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name", "")
        normalized = name.lower().replace("_", "-")
        if normalized in wanted:
            versions[normalized] = dist.version
    return dict(sorted(versions.items()))


def node_package_version(name: str) -> dict:
    package_json = Path("node_modules") / name / "package.json"
    if not package_json.is_file():
        return {"available": False}
    try:
        data = json.loads(package_json.read_text())
        return {"available": True, "version": data.get("version"), "path": str(package_json)}
    except (OSError, ValueError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def capture_browser_version(browser: str) -> dict:
    """Ask the same installed Playwright package used by the browser suite."""
    script = (
        'import {' + browser + '} from "playwright"; '
        f'const b = await {browser}.launch({{headless:true}}); '
        'console.log(JSON.stringify({browser: process.env.PLAYWRIGHT_BROWSER, '
        'version: b.version()})); await b.close();'
    )
    node = shutil.which("node")
    if not node:
        return {"error": "node executable not available"}
    result = probe([node, "--input-type=module", "-e", script], timeout=30)
    if result.get("returncode") == 0:
        try:
            result["version_info"] = json.loads(result["stdout"].splitlines()[-1])
        except (ValueError, IndexError):
            result["parse_error"] = "Could not parse Playwright browser-version output"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--command", action="append", default=[])
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    freeze = probe([sys.executable, "-m", "pip", "freeze", "--all"], timeout=60)
    freeze_text = freeze.get("stdout", "")
    (out / "pip-freeze.txt").write_text(freeze_text + ("\n" if freeze_text else ""))
    freeze_bytes = (out / "pip-freeze.txt").read_bytes()

    git_sha = os.environ.get("GITHUB_SHA")
    if not git_sha:
        git = probe(["git", "rev-parse", "HEAD"])
        git_sha = git.get("stdout") if git.get("returncode") == 0 else None

    safe_ci_env = (
        "GITHUB_ACTIONS", "GITHUB_WORKFLOW", "GITHUB_JOB", "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
        "RUNNER_OS", "RUNNER_ARCH", "PLAYWRIGHT_BROWSER",
    )
    libc_name, libc_version = platform.libc_ver()
    manifest = {
        "schema_version": 1,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "job": args.job,
        "git": {
            "sha": git_sha,
            "ref": os.environ.get("GITHUB_REF"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "job_name": os.environ.get("GITHUB_JOB"),
            "event": os.environ.get("GITHUB_EVENT_NAME"),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "libc": {"name": libc_name, "version": libc_version},
            "python": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
                "version_full": sys.version,
                "executable": sys.executable,
            },
        },
        "tool_versions": {
            "python_pip": probe([sys.executable, "-m", "pip", "--version"]),
            "node": maybe_version("node"),
            "npm": maybe_version("npm"),
            "playwright_node_package": node_package_version("playwright"),
            "cc": maybe_version("cc"),
            "clang": maybe_version("clang"),
            "gcc": maybe_version("gcc"),
            "git": maybe_version("git"),
            "installed_python_distributions": package_versions(),
            "playwright_browser": capture_browser_version(args.browser) if args.browser else None,
        },
        "dependencies": {
            "pip_freeze_file": "pip-freeze.txt",
            "pip_freeze_sha256": hashlib.sha256(freeze_bytes).hexdigest(),
            "pip_freeze_returncode": freeze.get("returncode"),
            "pip_freeze_error": freeze.get("error"),
        },
        "commands": args.command,
        "curated_ci_environment": {
            key: os.environ[key] for key in safe_ci_env if key in os.environ
        },
        "evidence_policy": {
            "complete_environment_dump": False,
            "reason": "Avoid recording credentials or unrelated process environment values.",
            "missing_optional_tools_are_not_assumed_passes": True,
        },
    }
    if freeze.get("returncode") != 0:
        errors.append("pip freeze failed; inspect dependencies.pip_freeze_returncode")
    manifest["capture_errors"] = errors
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({
        "manifest": str(out / "manifest.json"),
        "pip_freeze_sha256": manifest["dependencies"]["pip_freeze_sha256"],
        "job": args.job,
        "git_sha": git_sha,
        "capture_errors": errors,
    }, indent=2))
    # The artifact should still be uploaded on a failed test job. Test outcome is governed
    # by the actual test steps; capture failures remain visible in the manifest.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
