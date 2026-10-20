"""Same-task scorecard: run identical tasks on identical binaries with rdis and any competitor installed here.

    python tests/scorecard.py                       # corpus built from source, all tools found on PATH
    python tests/scorecard.py --extra big.bin       # also time an extra binary (hash recorded, no truth)
    python tests/scorecard.py --out result.json

A tool that is not installed is recorded as `not_available` with the reason; nothing is estimated. Each
adapter follows the tool's documented command line. Radare2 and Ghidra adapters were exercised on real installs
(radare2 6.2.4, Ghidra 12.1.4 with Temurin 21); the result records each tool's version.

Tasks
  function_discovery   entry points found in a stripped build, scored against the unstripped build's symbols
  analysis_resources   wall time and peak RSS of a fresh process analysing the binary
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GHIDRA_SCRIPT_DIR = os.path.join(ROOT, "benchmarks", "scorecard", "ghidra")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def child_peak_rss(cmd, timeout=1800, env=None):
    """Run `cmd` in a child and report (rc, stdout, seconds, peak RSS bytes) using wait4's rusage."""
    start = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    chunks = []
    import threading
    reader = threading.Thread(target=lambda: chunks.append(proc.stdout.read()), daemon=True)
    reader.start()
    deadline = time.time() + timeout
    while True:
        pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
        if pid:
            break
        if time.time() > deadline:
            proc.kill()
            os.wait4(proc.pid, 0)
            return None, "", timeout, 0
        time.sleep(0.02)
    reader.join(5)
    proc.stdout.close()
    proc.returncode = os.waitstatus_to_exitcode(status)
    rss = usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)
    return proc.returncode, (chunks[0] if chunks else b"").decode("utf-8", "replace"), time.perf_counter() - start, rss


def text_ranges(path):
    import lief
    lief.logging.disable()
    fat = lief.MachO.parse(path)
    if fat is None:
        return None
    return [(sec.virtual_address, sec.virtual_address + sec.size) for b in fat for sec in b.sections
            if sec.name == "__text" and sec.segment_name == "__TEXT"]


def restrict(found, path):
    ranges = text_ranges(path)
    return found if ranges is None else {a for a in found if any(lo <= a < hi for lo, hi in ranges)}


def ghidra_version():
    home = os.environ.get("GHIDRA_INSTALL_DIR")
    props = os.path.join(home or "", "Ghidra", "application.properties")
    if not os.path.exists(props):
        return None
    with open(props) as fh:
        return next((l.split("=", 1)[1].strip() for l in fh if l.startswith("application.version=")), None)


def score(truth, found):
    tp = len(truth & found)
    return {"truth": len(truth), "found": len(found), "true_positives": tp, "missed": len(truth - found),
            "extra": len(found - truth), "recall": round(tp / len(truth), 4) if truth else None,
            "precision_vs_truth_and_extras": round(tp / len(found), 4) if found else None}


# ---- adapters: each returns (function entry addresses, tool version) or raises ToolUnavailable ----
class ToolUnavailable(Exception):
    pass


def rdis_functions(path):
    cmd = [sys.executable, "-m", "rdis", path, "--json"]
    rc, out, secs, rss = child_peak_rss(cmd, env={**os.environ, "PYTHONPATH": ROOT, "RDIS_CACHE_DIR": tempfile.mkdtemp()})
    if rc != 0:
        raise RuntimeError(f"rdis exited {rc}")
    return {int(a, 16) for a in json.loads(out)}, secs, rss


def rdis_version():
    return "git " + (subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True,
                                    text=True).stdout.strip() or "unknown")


def radare2_command(binary):
    r2 = shutil.which("r2") or shutil.which("radare2")
    if not r2:
        raise ToolUnavailable("radare2 (r2) not found on PATH")
    return [r2, "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true", "-c", "aaa;aflj", binary]


def radare2_parse(stdout):
    start = stdout.find("[")
    if start < 0:
        return set()
    return {f.get("addr", f.get("offset")) for f in json.loads(stdout[start:]) if not f.get("name", "").startswith("sym.imp.")}


def radare2_version():
    r2 = shutil.which("r2") or shutil.which("radare2")
    return subprocess.run([r2, "-v"], capture_output=True, text=True).stdout.splitlines()[0] if r2 else None


def ghidra_command(binary, workdir):
    head = shutil.which("analyzeHeadless")
    home = os.environ.get("GHIDRA_INSTALL_DIR")
    if not head and home:
        candidate = os.path.join(home, "support", "analyzeHeadless")
        head = candidate if os.path.exists(candidate) else None
    if not head:
        raise ToolUnavailable("Ghidra analyzeHeadless not found (set GHIDRA_INSTALL_DIR or add it to PATH)")
    if not shutil.which("java"):
        raise ToolUnavailable("Ghidra needs a Java runtime; none found")
    out = os.path.join(workdir, "ghidra-functions.json")
    os.makedirs(os.path.join(workdir, "project"), exist_ok=True)
    return [head, os.path.join(workdir, "project"), "scorecard", "-import", binary, "-overwrite", "-scriptPath",
            GHIDRA_SCRIPT_DIR, "-postScript", "ExportFunctions.java", out, "-deleteProject"], out


def ghidra_parse(path):
    with open(path) as fh:
        return {f["addr"] for f in json.load(fh) if not f.get("external")}


TOOLS = ("rdis", "radare2", "ghidra")


def measure_function_discovery(tool, stripped, truth, workdir):
    if tool == "rdis":
        found, secs, rss = rdis_functions(stripped)
        return {"status": "measured", "adapter_verified": True, "version": rdis_version(), "seconds": round(secs, 3),
                "peak_rss_bytes": rss, **score(truth, restrict(found, stripped))}
    if tool == "radare2":
        cmd = radare2_command(stripped)
        rc, out, secs, rss = child_peak_rss(cmd)
        if rc != 0:
            return {"status": "failed", "reason": f"r2 exited {rc}", "version": radare2_version()}
        return {"status": "measured", "adapter_verified": True, "version": radare2_version(), "seconds": round(secs, 3),
                "peak_rss_bytes": rss, **score(truth, restrict(radare2_parse(out), stripped))}
    if tool == "ghidra":
        cmd, outfile = ghidra_command(stripped, workdir)
        rc, _, secs, rss = child_peak_rss(cmd, timeout=3600)
        if rc != 0 or not os.path.exists(outfile):
            return {"status": "failed", "reason": f"analyzeHeadless exited {rc}"}
        return {"status": "measured", "adapter_verified": True, "seconds": round(secs, 3),
                "peak_rss_bytes": rss, **score(truth, restrict(ghidra_parse(outfile), stripped))}
    raise ValueError(tool)


def build_corpus(workdir):
    import diff_corpus
    from rdis.analysis import Program
    from rdis.loader import open_image
    entries = []
    for version in (1, 2):
        built = diff_corpus.build(workdir, version)
        if built is None:
            return []
        full, stripped = built
        prog = Program(open_image(str(full))).analyze(objc=False, swift=False)
        truth = {a for a in prog.functions if (prog.display(a) or "").lstrip("_").startswith(("fn_", "main"))}
        entries.append({"name": f"c-program-v{version}", "stripped": str(stripped), "truth": truth})
    return entries


def run(args):
    workdir = tempfile.mkdtemp(prefix="rdis-scorecard-")
    result = {"schema": 1, "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                       "python": platform.python_version()},
              "tools": {}, "corpus": [], "tasks": {"function_discovery": {}, "analysis_resources": {}}}
    corpus = build_corpus(workdir)
    if args.sources:
        import real_corpus
        corpus += list(real_corpus.build(args.sources, workdir))
    for entry in corpus:
        result["corpus"].append({"name": entry["name"], "sha256": sha256(entry["stripped"]),
                                 "bytes": os.path.getsize(entry["stripped"]), "truth_functions": len(entry["truth"])})
    for tool in args.tools.split(","):
        for entry in corpus:
            try:
                row = measure_function_discovery(tool, entry["stripped"], entry["truth"], workdir)
            except ToolUnavailable as e:
                row = {"status": "not_available", "reason": str(e)}
            except Exception as e:
                row = {"status": "failed", "reason": f"{type(e).__name__}: {e}"}
            result["tasks"]["function_discovery"].setdefault(tool, {})[entry["name"]] = row
    for path in args.extra:
        info = {"sha256": sha256(path), "bytes": os.path.getsize(path)}
        for tool in args.tools.split(","):
            try:
                if tool == "rdis":
                    _, secs, rss = rdis_functions(path)
                    row = {"status": "measured", "adapter_verified": True, "seconds": round(secs, 3), "peak_rss_bytes": rss}
                elif tool == "radare2":
                    rc, _, secs, rss = child_peak_rss(radare2_command(path), timeout=args.timeout)
                    row = {"status": "measured" if rc == 0 else "failed", "adapter_verified": True,
                           "seconds": round(secs, 3), "peak_rss_bytes": rss}
                else:
                    cmd, _ = ghidra_command(path, workdir)
                    rc, _, secs, rss = child_peak_rss(cmd, timeout=args.timeout)
                    row = {"status": "measured" if rc == 0 else "failed", "adapter_verified": True,
                           "seconds": round(secs, 3), "peak_rss_bytes": rss}
            except ToolUnavailable as e:
                row = {"status": "not_available", "reason": str(e)}
            result["tasks"]["analysis_resources"].setdefault(tool, {})[os.path.basename(path)] = {**info, **row}
    versions = {"rdis": rdis_version(), "radare2": None, "ghidra": ghidra_version()}
    try:
        versions["radare2"] = radare2_version()
    except Exception:
        pass
    result["tools"] = {t: {"version": versions.get(t),
                           "available": not all(r.get("status") == "not_available" for r in
                                                result["tasks"]["function_discovery"].get(t, {}).values())}
                       for t in args.tools.split(",")}
    shutil.rmtree(workdir, ignore_errors=True)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tools", default=",".join(TOOLS))
    p.add_argument("--extra", action="append", default=[], help="extra binary to time (hash recorded, no truth)")
    p.add_argument("--sources", help="directory with pinned program sources (see tests/real_corpus.py)")
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--out")
    args = p.parse_args()
    result = run(args)
    text = json.dumps(result, indent=1, sort_keys=True)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + "\n")
    for task, per_tool in result["tasks"].items():
        for tool, rows in per_tool.items():
            for name, row in rows.items():
                detail = (f"recall {row.get('recall')} extra {row.get('extra')} {row.get('seconds')}s "
                          f"{(row.get('peak_rss_bytes') or 0) >> 20} MiB") if row["status"] == "measured" else row.get("reason", "")
                print(f"{task:20} {tool:8} {name:18} {row['status']:14} {detail}")


if __name__ == "__main__":
    main()
