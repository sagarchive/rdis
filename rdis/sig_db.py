"""Build and manage pre-computed signature databases from system libraries.

A signature database is a collection of function signatures (address-masked instruction hashes)
built from known libraries like libc, libc++, OpenSSL, BoringSSL, zlib, etc.
These databases can be used to name functions in stripped binaries.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .signatures import make, dump, load, FORMAT, MIN_INSNS
from .loader import open_image
from .analysis import Program
from . import cache


# Common system library names to search for
SYSTEM_LIBS = {
    "libc": ["libc.so", "libc.so.6", "libc.dylib", "libc.*.dylib", "msvcrt.dll"],
    "libc++": ["libc++.so", "libc++.so.1", "libc++.dylib", "libc++abi.so", "libc++abi.dylib"],
    "OpenSSL": ["libssl.so", "libssl.so.*", "libssl.dylib", "libcrypto.so", "libcrypto.so.*", "libcrypto.dylib"],
    "BoringSSL": ["libssl.so", "libcrypto.so"],
    "zlib": ["libz.so", "libz.so.*", "libz.dylib", "zlib1.dll"],
    "libm": ["libm.so", "libm.so.6", "libm.dylib"],
    "libpthread": ["libpthread.so", "libpthread.so.0", "libpthread.dylib"],
    "libdl": ["libdl.so", "libdl.so.2", "libdl.dylib"],
    "librt": ["librt.so", "librt.so.1"],
}


def find_system_libraries(lib_dirs: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Find system libraries in standard locations.

    Args:
        lib_dirs: Additional directories to search. If None, uses standard system paths.

    Returns:
        Dict mapping library family name to list of found library paths.
    """
    if lib_dirs is None:
        lib_dirs = [
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
            "/opt/homebrew/lib",
            "/lib",
            "/lib64",
            "/System/Library",
            "/usr/lib/system",
        ]

    found = {name: [] for name in SYSTEM_LIBS}

    for lib_dir in lib_dirs:
        if not os.path.isdir(lib_dir):
            continue
        for root, dirs, files in os.walk(lib_dir):
            for fname in files:
                for lib_name, patterns in SYSTEM_LIBS.items():
                    for pattern in patterns:
                        if _match_pattern(fname, pattern):
                            full_path = os.path.join(root, fname)
                            if os.path.isfile(full_path) and not os.path.islink(full_path):
                                found[lib_name].append(full_path)
                            break

    for lib_name in found:
        found[lib_name] = list(dict.fromkeys(found[lib_name]))

    return found


def _match_pattern(fname: str, pattern: str) -> bool:
    """Simple glob-style pattern matching."""
    if "*" not in pattern:
        return fname == pattern
    import fnmatch
    return fnmatch.fnmatch(fname, pattern)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_signature_db_from_libraries(
    lib_paths: List[str],
    arch: str,
    min_insns: int = MIN_INSNS,
    max_funcs_per_lib: int = 5000,
) -> dict:
    """Build a signature database from a list of library files.

    Args:
        lib_paths: Paths to library files (ELF, Mach-O, PE)
        arch: Target architecture (x86_64, arm64, etc.)
        min_insns: Minimum instructions for a function to be signed
        max_funcs_per_lib: Maximum functions to process per library (performance)

    Returns:
        Signature database dict
    """
    all_entries = {}
    sources = []

    for lib_path in lib_paths:
        try:
            prog = cache.analyze(open_image(lib_path, arch=arch))
            if not isinstance(prog, Program):
                print(f"  Skipping {lib_path}: not a supported format", file=sys.stderr)
                continue

            lib_name = os.path.basename(lib_path)
            lib_sha256 = _sha256(lib_path)
            sources.append({"name": lib_name, "sha256": lib_sha256, "path": lib_path})

            lib_db = make(prog, min_insns=min_insns)

            for exact_hash, entry in lib_db["entries"].items():
                if exact_hash not in all_entries:
                    all_entries[exact_hash] = {
                        "names": entry["names"].copy(),
                        "size": entry["size"],
                        "sources": [{"name": lib_name, "sha256": lib_sha256}],
                    }
                else:
                    for name in entry["names"]:
                        if name not in all_entries[exact_hash]["names"]:
                            all_entries[exact_hash]["names"].append(name)
                    all_entries[exact_hash]["sources"].append({"name": lib_name, "sha256": lib_sha256})

        except Exception as e:
            print(f"  Error processing {lib_path}: {e}", file=sys.stderr)
            continue

    return {
        "format": FORMAT,
        "min_insns": min_insns,
        "arch": arch,
        "sources": sources,
        "entries": all_entries,
    }


def build_platform_signature_db(
    output_path: str,
    arch: str,
    lib_dirs: Optional[List[str]] = None,
    min_insns: int = MIN_INSNS,
    extra_libs: Optional[List[str]] = None,
) -> dict:
    """Build a comprehensive signature database for a platform/architecture.

    This finds system libraries automatically and builds a combined database.

    Args:
        output_path: Where to write the database JSON
        arch: Target architecture
        lib_dirs: Additional library directories to search
        min_insns: Minimum instructions for signing
        extra_libs: Additional specific library paths to include

    Returns:
        The built signature database
    """
    print(f"Building signature database for {arch}...", file=sys.stderr)

    found = find_system_libraries(lib_dirs)

    all_libs = []
    for lib_name, paths in found.items():
        if paths:
            print(f"  Found {lib_name}: {len(paths)} libraries", file=sys.stderr)
            all_libs.extend(paths[:10])

    if extra_libs:
        all_libs.extend(extra_libs)

    if not all_libs:
        raise ValueError(f"No system libraries found for {arch}")

    print(f"  Processing {len(all_libs)} libraries...", file=sys.stderr)

    db = build_signature_db_from_libraries(all_libs, arch, min_insns)

    dump(db, output_path)
    print(f"  Wrote {len(db['entries'])} signatures from {len(db['sources'])} libraries to {output_path}", file=sys.stderr)

    return db


def merge_signature_dbs(db_paths: List[str], output_path: str) -> dict:
    """Merge multiple signature databases into one.

    Args:
        db_paths: Paths to signature database JSON files
        output_path: Where to write the merged database

    Returns:
        Merged signature database
    """
    merged_entries = {}
    merged_sources = []
    arch = None
    min_insns = MIN_INSNS

    for db_path in db_paths:
        db = load(db_path)
        if arch is None:
            arch = db["arch"]
            min_insns = db.get("min_insns", MIN_INSNS)
        elif db["arch"] != arch:
            raise ValueError(f"Architecture mismatch: {db['arch']} vs {arch}")
        min_insns = min(min_insns, db.get("min_insns", MIN_INSNS))

        for src in db.get("sources", []):
            if src not in merged_sources:
                merged_sources.append(src)

        for exact_hash, entry in db["entries"].items():
            if exact_hash not in merged_entries:
                merged_entries[exact_hash] = entry.copy()
            else:
                for name in entry["names"]:
                    if name not in merged_entries[exact_hash]["names"]:
                        merged_entries[exact_hash]["names"].append(name)
                for src in entry.get("sources", []):
                    if src not in merged_entries[exact_hash].get("sources", []):
                        merged_entries[exact_hash].setdefault("sources", []).append(src)

    merged = {
        "format": FORMAT,
        "min_insns": min_insns,
        "arch": arch,
        "sources": merged_sources,
        "entries": merged_entries,
    }

    dump(merged, output_path)
    return merged


def match_with_db(prog: Program, db_path: str, min_insns: Optional[int] = None) -> dict:
    """Match functions in a program against a signature database.

    Args:
        prog: Analyzed program
        db_path: Path to signature database
        min_insns: Override minimum instructions

    Returns:
        Match results with matches and ambiguous
    """
    db = load(db_path)
    return match(prog, db, min_insns)


def match_multiple_dbs(prog: Program, db_paths: List[str], min_insns: Optional[int] = None) -> dict:
    """Match against multiple signature databases, combining results.

    Args:
        prog: Analyzed program
        db_paths: List of signature database paths
        min_insns: Override minimum instructions

    Returns:
        Combined match results
    """
    all_matches = []
    all_ambiguous = []

    for db_path in db_paths:
        try:
            result = match_with_db(prog, db_path, min_insns)
            all_matches.extend(result["matches"])
            all_ambiguous.extend(result["ambiguous"])
        except Exception as e:
            print(f"Warning: failed to match against {db_path}: {e}", file=sys.stderr)

    by_addr = {}
    for m in all_matches:
        addr = m["addr"]
        if addr not in by_addr or m["confidence"] > by_addr[addr]["confidence"]:
            by_addr[addr] = m

    amb_by_addr = {}
    for a in all_ambiguous:
        addr = a["addr"]
        if addr not in amb_by_addr:
            amb_by_addr[addr] = a
        else:
            for c in a["candidates"]:
                if c not in amb_by_addr[addr]["candidates"]:
                    amb_by_addr[addr]["candidates"].append(c)

    return {
        "matches": sorted(by_addr.values(), key=lambda m: m["addr"]),
        "ambiguous": sorted(amb_by_addr.values(), key=lambda a: a["addr"]),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build system library signature database")
    parser.add_argument("output", help="Output database path")
    parser.add_argument("--arch", required=True, help="Target architecture")
    parser.add_argument("--lib-dir", action="append", help="Additional library directory")
    parser.add_argument("--extra-lib", action="append", help="Extra library file to include")
    parser.add_argument("--min-insns", type=int, default=MIN_INSNS, help="Minimum instructions")

    args = parser.parse_args()
    build_platform_signature_db(
        args.output,
        args.arch,
        lib_dirs=args.lib_dir,
        min_insns=args.min_insns,
        extra_libs=args.extra_lib,
    )