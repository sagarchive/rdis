#!/usr/bin/env python3
"""Run the versioned RDIS baseline corpus with hash checks and retained raw logs.

The manifest is executable configuration: only run a manifest from a source tree you trust.
Commands are passed as argv arrays (never through a shell), have explicit timeouts, and write
stdout/stderr to separate files. A missing required tool, hash mismatch, timeout or failed
assertion makes the run fail; platform-inapplicable checks are recorded as skips.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = 1
CONDITION_KEYS = {"system", "machine"}


def normalize_machine(value: str) -> str:
    """Normalize common architecture spellings without conflating different ISAs."""
    lowered = str(value).strip().lower()
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86-64": "x86_64",
        "aarch64": "arm64",
        "arm64e": "arm64",
    }
    return aliases.get(lowered, lowered)


def host_context() -> Dict[str, str]:
    return {
        "system": platform.system(),
        "machine": normalize_machine(platform.machine()),
    }


def matches_when(when: Optional[Dict[str, Any]], host: Dict[str, str]) -> bool:
    """Return true only when every specified, supported host constraint matches."""
    if not when:
        return True
    for key, expected in when.items():
        if key not in CONDITION_KEYS:
            return False
        actual = host.get(key)
        if actual is None:
            return False
        if key == "machine":
            actual, expected = normalize_machine(actual), normalize_machine(str(expected))
        if actual != expected:
            return False
    return True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def validate_manifest(manifest: Dict[str, Any]) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported corpus manifest schema_version")
    if not isinstance(manifest.get("corpus_id"), str) or not manifest["corpus_id"].strip():
        raise ValueError("corpus_id must be a non-empty string")
    for collection_name in ("entries", "profiles"):
        if not isinstance(manifest.get(collection_name), list):
            raise ValueError(collection_name + " must be a list")
    for collection_name in ("entries", "profiles"):
        seen = set()
        for item in manifest[collection_name]:
            identifier = item.get("id") if isinstance(item, dict) else None
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(collection_name + " entries need non-empty ids")
            if identifier in seen:
                raise ValueError("duplicate " + collection_name + " id: " + identifier)
            seen.add(identifier)
            when = item.get("when", {})
            if not isinstance(when, dict) or set(when) - CONDITION_KEYS:
                raise ValueError("invalid when condition on " + identifier)
    for entry in manifest["entries"]:
        if entry.get("kind") not in ("checked-in-source", "host-system-binary"):
            raise ValueError("unsupported corpus entry kind: " + str(entry.get("kind")))
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("entry needs a valid sha256: " + entry["id"])
        if not isinstance(entry.get("size_bytes"), int) or entry["size_bytes"] < 0:
            raise ValueError("entry needs a non-negative size_bytes: " + entry["id"])
    profile_ids = {p["id"] for p in manifest["profiles"]}
    for profile in manifest["profiles"]:
        commands = profile.get("commands", [])
        if not isinstance(commands, list):
            raise ValueError("commands must be a list on profile " + profile["id"])
        parents = profile.get("extends", [])
        if not isinstance(parents, list) or any(parent not in profile_ids for parent in parents):
            raise ValueError("profile has an unknown extends target: " + profile["id"])
        for command in commands:
            if not isinstance(command, dict) or not isinstance(command.get("id"), str) or not command["id"]:
                raise ValueError("profile commands need non-empty ids: " + profile["id"])
            argv = command.get("argv")
            if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
                raise ValueError("command argv must be a non-empty string list: " + command["id"])
            timeout = command.get("timeout_seconds", 120)
            if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3600:
                raise ValueError("invalid command timeout: " + command["id"])
            if command.get("when") and (
                not isinstance(command["when"], dict) or set(command["when"]) - CONDITION_KEYS
            ):
                raise ValueError("invalid command when condition: " + command["id"])


def _entry_path(entry: Dict[str, Any], root: Path) -> Path:
    raw = entry.get("path")
    if not isinstance(raw, str) or not raw:
        raise ValueError("entry path must be a non-empty string: " + entry["id"])
    supplied = Path(raw)
    if entry["kind"] == "host-system-binary":
        if not supplied.is_absolute():
            raise ValueError("host-system-binary path must be absolute: " + entry["id"])
        return supplied
    if supplied.is_absolute():
        raise ValueError("checked-in source path must be repository-relative: " + entry["id"])
    resolved = (root / supplied).resolve()
    root_resolved = root.resolve()
    if not resolved.is_relative_to(root_resolved):
        raise ValueError("checked-in source escapes repository root: " + entry["id"])
    return resolved


def verify_entries(
    manifest: Dict[str, Any], root: Path, host: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Hash each platform-applicable corpus input without copying or modifying it."""
    results: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in manifest["entries"]:
        identifier = entry["id"]
        required = bool(entry.get("required", entry.get("required_when_matched", True)))
        result: Dict[str, Any] = {
            "id": identifier,
            "kind": entry["kind"],
            "path": entry.get("path"),
            "required": required,
            "status": "skipped",
        }
        if not matches_when(entry.get("when"), host):
            result["reason"] = "entry does not apply to this OS/architecture"
            results.append(result)
            by_id[identifier] = result
            continue
        try:
            path = _entry_path(entry, root)
            result["resolved_path"] = str(path)
            if not path.is_file():
                raise FileNotFoundError("input file is missing")
            size = path.stat().st_size
            result["size_bytes"] = size
            result["sha256"] = sha256_file(path)
            if size != entry["size_bytes"]:
                raise ValueError(
                    "size mismatch: expected " + str(entry["size_bytes"]) + ", observed " + str(size)
                )
            if result["sha256"].lower() != entry["sha256"].lower():
                raise ValueError("SHA-256 mismatch; review the input and update the manifest intentionally")
            expected_blob = entry.get("git_blob_sha1")
            if expected_blob:
                blob = git_blob_sha1(path.read_bytes())
                result["git_blob_sha1"] = blob
                if blob.lower() != str(expected_blob).lower():
                    raise ValueError("Git blob SHA-1 mismatch")
            result["status"] = "passed"
            result["reason"] = "input fingerprint matches manifest"
        except (OSError, ValueError) as exc:
            result["status"] = "failed" if required else "skipped"
            result["reason"] = str(exc)
        results.append(result)
        by_id[identifier] = result
    return results, by_id


def selected_commands(
    manifest: Dict[str, Any], host: Dict[str, str], requested_profiles: Optional[List[str]]
) -> Tuple[List[str], List[Dict[str, Any]]]:
    profiles = {profile["id"]: profile for profile in manifest["profiles"]}
    if requested_profiles:
        roots = []
        for identifier in requested_profiles:
            if identifier not in profiles:
                raise ValueError("unknown profile: " + identifier)
            if not matches_when(profiles[identifier].get("when"), host):
                raise ValueError("requested profile does not apply to this host: " + identifier)
            roots.append(identifier)
    else:
        roots = [
            profile["id"] for profile in manifest["profiles"]
            if matches_when(profile.get("when"), host)
        ]

    ordered_profiles: List[str] = []
    visiting = set()
    visited = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("profile extends cycle at " + identifier)
        if identifier in visited:
            return
        visiting.add(identifier)
        for parent in profiles[identifier].get("extends", []):
            if matches_when(profiles[parent].get("when"), host):
                visit(parent)
        visiting.remove(identifier)
        visited.add(identifier)
        ordered_profiles.append(identifier)

    for identifier in roots:
        visit(identifier)

    commands: List[Dict[str, Any]] = []
    seen_commands: Dict[str, Dict[str, Any]] = {}
    for profile_id in ordered_profiles:
        for command in profiles[profile_id].get("commands", []):
            identifier = command["id"]
            if identifier in seen_commands:
                if seen_commands[identifier] != command:
                    raise ValueError("conflicting duplicate command id: " + identifier)
                continue
            seen_commands[identifier] = command
            commands.append(dict(command, profile=profile_id))
    return roots, commands


def _expand(value: str, root: Path, output_dir: Path, python_executable: str) -> str:
    return (
        value.replace("{python}", python_executable)
        .replace("{repo_root}", str(root.resolve()))
        .replace("{output_dir}", str(output_dir.resolve()))
    )


def _safe_id(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return safe[:100] or "command"


def _resolve_recorded_output(value: str, root: Path, output_dir: Path) -> Path:
    expanded = Path(_expand(value, root, output_dir, sys.executable))
    resolved = expanded.resolve() if expanded.is_absolute() else (root / expanded).resolve()
    if not resolved.is_relative_to(output_dir.resolve()):
        raise ValueError("record_outputs must remain inside output_dir: " + value)
    return resolved


def _text_file_contains(path: Path, expected: Any) -> bool:
    values = expected if isinstance(expected, list) else [expected]
    data = path.read_text(encoding="utf-8", errors="replace")
    return all(str(value) in data for value in values)


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass


def run_command(
    command: Dict[str, Any],
    root: Path,
    output_dir: Path,
    host: Dict[str, str],
    entry_results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Execute one command and retain its raw outputs and recorded output fingerprints."""
    identifier = command["id"]
    required = bool(command.get("required", True))
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    slug = _safe_id(identifier)
    stdout_path = logs_dir / (slug + ".stdout.txt")
    stderr_path = logs_dir / (slug + ".stderr.txt")
    stdout_path.touch()
    stderr_path.touch()
    result: Dict[str, Any] = {
        "id": identifier,
        "profile": command.get("profile"),
        "required": required,
        "argv": command["argv"],
        "timeout_seconds": command.get("timeout_seconds", 120),
        "status": "skipped",
        "stdout_log": str(stdout_path.relative_to(output_dir)),
        "stderr_log": str(stderr_path.relative_to(output_dir)),
        "recorded_outputs": [],
    }

    if not matches_when(command.get("when"), host):
        result["reason"] = "command does not apply to this OS/architecture"
        return result

    requirements = command.get("requires_entries", [])
    missing = [
        entry_id for entry_id in requirements
        if entry_id not in entry_results or entry_results[entry_id].get("status") != "passed"
    ]
    if missing:
        result["status"] = "failed" if required else "skipped"
        result["reason"] = "required corpus input(s) were not verified: " + ", ".join(missing)
        return result

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "generated").mkdir(parents=True, exist_ok=True)
    argv = [_expand(value, root, output_dir, sys.executable) for value in command["argv"]]
    result["argv"] = argv
    executable = argv[0]
    found = (
        Path(executable).is_file()
        if os.path.isabs(executable) or os.sep in executable
        else shutil.which(executable) is not None
    )
    if not found:
        result["status"] = "failed" if required else "skipped"
        result["reason"] = "executable not found: " + executable
        return result

    stdin_text = command.get("stdin")
    stdin_bytes = stdin_text.encode("utf-8") if isinstance(stdin_text, str) else None
    started = time.monotonic()
    timed_out = False
    try:
        with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
            process = subprocess.Popen(
                argv,
                cwd=str(root),
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                shell=False,
                start_new_session=(os.name != "nt"),
            )
            try:
                process.communicate(input=stdin_bytes, timeout=float(result["timeout_seconds"]))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process(process)
                process.communicate()
            returncode = process.returncode
    except OSError as exc:
        result["status"] = "failed" if required else "skipped"
        result["reason"] = type(exc).__name__ + ": " + str(exc)
        result["duration_seconds"] = round(time.monotonic() - started, 6)
        return result

    result["duration_seconds"] = round(time.monotonic() - started, 6)
    result["returncode"] = returncode
    result["stdout_bytes"] = stdout_path.stat().st_size
    result["stderr_bytes"] = stderr_path.stat().st_size
    if timed_out:
        result["status"] = "failed" if required else "skipped"
        result["reason"] = "command exceeded timeout"
        return result

    expected_code = int(command.get("expected_exit_code", 0))
    if returncode != expected_code:
        result["reason"] = "exit code mismatch: expected " + str(expected_code) + ", observed " + str(returncode)
    elif command.get("stdout_contains") is not None and not _text_file_contains(
        stdout_path, command["stdout_contains"]
    ):
        result["reason"] = "required text not found in stdout"
    elif command.get("stderr_contains") is not None and not _text_file_contains(
        stderr_path, command["stderr_contains"]
    ):
        result["reason"] = "required text not found in stderr"
    else:
        output_errors = []
        for item in command.get("record_outputs", []):
            try:
                path = _resolve_recorded_output(item, root, output_dir)
                if not path.is_file():
                    raise FileNotFoundError("recorded output does not exist")
                output_info = {
                    "path": str(path.relative_to(output_dir.resolve())),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
                result["recorded_outputs"].append(output_info)
            except (OSError, ValueError) as exc:
                output_errors.append(item + ": " + str(exc))
        if output_errors:
            result["reason"] = "; ".join(output_errors)
        else:
            result["status"] = "passed"
            result["reason"] = "exit code and output assertions passed"
    if result["status"] != "passed":
        result["status"] = "failed" if required else "skipped"
    return result


def _git_sha(root: Path) -> Optional[str]:
    env_sha = os.environ.get("GITHUB_SHA")
    if env_sha:
        return env_sha
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True,
            text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _pr_identity() -> Dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pr = event.get("pull_request") or {}
        if not pr:
            return {}
        return {
            "pull_request_number": pr.get("number"),
            "pull_request_head_sha": (pr.get("head") or {}).get("sha"),
            "pull_request_base_sha": (pr.get("base") or {}).get("sha"),
        }
    except (OSError, ValueError, TypeError):
        return {}


def run_baseline(
    manifest: Dict[str, Any],
    manifest_sha256: str,
    root: Path,
    output_dir: Path,
    requested_profiles: Optional[List[str]] = None,
    environment_manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    validate_manifest(manifest)
    host = host_context()
    output_dir.mkdir(parents=True, exist_ok=True)
    entries, entry_results = verify_entries(manifest, root, host)
    roots, commands = selected_commands(manifest, host, requested_profiles)

    environment_link: Dict[str, Any] = {"provided": False}
    errors: List[str] = []
    if environment_manifest_path is not None:
        env_path = environment_manifest_path
        if not env_path.is_absolute():
            env_path = root / env_path
        try:
            raw_env = env_path.read_bytes()
            env_data = json.loads(raw_env.decode("utf-8"))
            environment_link = {
                "provided": True,
                "path": str(env_path),
                "sha256": hashlib.sha256(raw_env).hexdigest(),
                "job": env_data.get("job"),
                "git": env_data.get("git", {}),
            }
            checkout = _git_sha(root)
            captured_checkout = (env_data.get("git") or {}).get("tested_checkout_sha")
            if checkout and captured_checkout and checkout != captured_checkout:
                errors.append(
                    "environment manifest checkout SHA does not match runner checkout: "
                    + str(captured_checkout) + " != " + checkout
                )
        except (OSError, ValueError, TypeError) as exc:
            environment_link = {"provided": True, "path": str(env_path), "error": str(exc)}
            errors.append("environment manifest could not be verified: " + str(exc))

    command_results = [
        run_command(command, root, output_dir, host, entry_results)
        for command in commands
    ]
    entry_failures = [
        item for item in entries
        if item["status"] == "failed" and item.get("required", True)
    ]
    command_failures = [
        item for item in command_results
        if item["status"] == "failed" and item.get("required", True)
    ]
    summary = {
        "schema_version": 1,
        "status": "failed" if errors or entry_failures or command_failures else "passed",
        "started_at_utc": None,
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "corpus": {
            "id": manifest["corpus_id"],
            "schema_version": manifest["schema_version"],
            "manifest_path": str((root / "tests" / "baseline_corpus.json").resolve()),
            "manifest_sha256": manifest_sha256,
        },
        "host": {
            **host,
            "python": sys.version,
            "python_executable": sys.executable,
        },
        "git": {
            "tested_checkout_sha": _git_sha(root),
            **_pr_identity(),
        },
        "environment_manifest": environment_link,
        "selected_profiles": roots,
        "entries": entries,
        "commands": command_results,
        "errors": errors,
        "counts": {
            "passed": sum(x["status"] == "passed" for x in entries + command_results),
            "failed": sum(x["status"] == "failed" for x in entries + command_results),
            "skipped": sum(x["status"] == "skipped" for x in entries + command_results),
        },
    }
    summary["started_at_utc"] = datetime.now(timezone.utc).isoformat()
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    (output_dir / "summary.json").write_text(rendered, encoding="utf-8")
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="tests/baseline_corpus.json")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output-dir", default="artifacts/baseline-run")
    parser.add_argument("--profile", action="append", help="profile id (may be repeated); defaults to all host-matching profiles")
    parser.add_argument("--environment-manifest", help="optional environment manifest to hash and link")
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        validate_manifest(manifest)
        environment_path = Path(args.environment_manifest) if args.environment_manifest else None
        summary = run_baseline(
            manifest,
            hashlib.sha256(raw).hexdigest(),
            root,
            output_dir,
            requested_profiles=args.profile,
            environment_manifest_path=environment_path,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        summary = {
            "schema_version": 1,
            "status": "failed",
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "errors": [type(exc).__name__ + ": " + str(exc)],
            "counts": {"passed": 0, "failed": 1, "skipped": 0},
        }
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
