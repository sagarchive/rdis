"""Repeatable, non-gating analysis benchmark for a fixed binary corpus.

Example (macOS):
    python tests/benchmark_analysis.py /bin/ls --arch arm64 --repeat 3 --output benchmark.json

Each repetition constructs a fresh Program. The OS file cache may be warm; this is not a claim
about persistent-cache performance. Keep the JSON artifact with the commit, OS and Python version.
"""
import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time

try:
    import resource
except ImportError:  # Windows
    resource = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rdis.analysis import Program
from rdis.loader import open_image


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def peak_rss_bytes():
    if resource is None:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux and the BSDs used here report KiB.
    return int(value if sys.platform == "darwin" else value * 1024)


def benchmark(path, arch, repeat):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    samples = []
    final_counts = {}
    for _ in range(repeat):
        started = time.perf_counter()
        program = Program(open_image(path, arch=arch)).analyze()
        samples.append(time.perf_counter() - started)
        final_counts = {
            "functions": len(program.functions),
            "basic_blocks": sum(len(fn.blocks) for fn in program.functions.values()),
            "strings": len(program.strings()),
            "sections": len(program.image.sections),
        }
        del program
    return {
        "path": path,
        "sha256": digest(path),
        "size_bytes": os.path.getsize(path),
        "arch": arch,
        "repeat": repeat,
        "analysis_seconds": [round(x, 6) for x in samples],
        "median_seconds": round(statistics.median(samples), 6),
        "min_seconds": round(min(samples), 6),
        "max_seconds": round(max(samples), 6),
        **final_counts,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="+", help="binary paths; keep corpus constant between runs")
    parser.add_argument("--arch", help="architecture for a fat Mach-O; applies to each input")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", help="write JSON to this path as well as stdout")
    args = parser.parse_args(argv)
    if args.repeat < 1 or args.repeat > 20:
        parser.error("--repeat must be between 1 and 20")
    result = {
        "schema_version": 1,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "implementation": platform.python_implementation(),
            "note": "fresh Program per repetition; OS page cache may be warm; no performance threshold",
        },
        "benchmarks": [benchmark(path, args.arch, args.repeat) for path in args.binary],
        "peak_rss_bytes": peak_rss_bytes(),
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
