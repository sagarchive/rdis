"""Deterministic fuzzing campaign over every parser and decoder that reads untrusted bytes.

    python tests/fuzz.py                               # 10 seeds x 200 cases per target
    python tests/fuzz.py --seeds 10 --cases 1000 --targets elf,zip,wasm --out result.json
    python tests/fuzz.py --replay elf 3 17             # re-run one case

A case is fully determined by (target, seed, index), so every finding replays exactly. Workers run in
subprocesses so a native crash or hang is a recorded finding instead of the end of the campaign; each
distinct failure is then minimized by delta debugging. A failure is any outcome other than success or
the documented error type for that target.
"""
import argparse
import json
import os
import platform
import random
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CASE_SECONDS = 20
MAX_RSS = 3 << 30
WASM = bytes.fromhex("0061736d01000000" "0105016000017f" "03020100" "0a0601040041" "2a0b")
BOUNDARY = [0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


def seed_corpus():
    import sleigh_fixtures as F
    out = {"elf": [F.elf(n)[0] for n in ("ppc", "ebpf", "m68k")], "wasm": [WASM]}
    tmp = tempfile.mkdtemp(prefix="rdis-fuzz-seed-")
    src = os.path.join(tmp, "t.c")
    with open(src, "w") as fh:
        fh.write("int helper(int x){return x*3+1;}\nint main(int c,char**v){int s=0;for(int i=0;i<c;i++)s+=helper(i);"
                 "switch(c){case 1:return s;case 2:return s+1;case 3:return s+2;default:return 0;}}\n")
    native = os.path.join(tmp, "native")
    cc = shutil.which("cc")
    if cc and subprocess.run([cc, "-O1", src, "-o", native], capture_output=True).returncode == 0:
        out["elf"].append(open(native, "rb").read())
    shutil.rmtree(tmp, ignore_errors=True)
    names = ["a.txt", "lib/b.so", "assets/c.bin"]
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in names:
            z.writestr(n, (b"\x7fELF" + os.urandom(0) + bytes(range(64))) * 4)
    out["zip"] = [buf.getvalue()]
    out["decode"] = [bytes(range(256)) * 4]
    out["mcp"] = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "list_functions", "arguments": {"path": "/bin/ls", "limit": 5}}}).encode()]
    return out


def mutate(data, rng):
    data = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        kind = rng.randrange(7)
        if not data:
            data = bytearray(rng.randbytes(rng.randint(1, 32)))
        n = len(data)
        if kind == 0:
            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(n)] ^= 1 << rng.randrange(8)
        elif kind == 1:
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(n)] = rng.choice(BOUNDARY) & 0xFF
        elif kind == 2:
            del data[rng.randrange(n):]
        elif kind == 3:
            at = rng.randrange(n)
            del data[at:at + rng.randint(1, max(1, n // 4))]
        elif kind == 4:
            at = rng.randrange(n)
            data[at:at] = data[at:at + rng.randint(1, 64)] or rng.randbytes(8)
        elif kind == 5:
            at = rng.randrange(n)
            data[at:at] = rng.randbytes(rng.randint(1, 32))
        else:
            size = rng.choice((2, 4, 8))
            span = min(n - size, 512)
            if span > 0:
                at = rng.randrange(0, span) // size * size
                value = rng.choice(BOUNDARY + [n, n - 1, n + 1])
                data[at:at + size] = (value & ((1 << 8 * size) - 1)).to_bytes(size, rng.choice(("little", "big")))
    return bytes(data)


def make_case(target, seed, index, corpus):
    rng = random.Random(seed * 1_000_003 + index)
    if target == "decode":
        return rng.randbytes(rng.randint(1, 96))
    pool = corpus[{"elf": "elf", "macho": "elf", "zip": "zip", "wasm": "wasm", "mcp": "mcp", "ir": "decode"}[target]]
    base = rng.choice(pool)
    if target == "ir":
        return rng.randbytes(rng.randint(8, 400))
    return mutate(base, rng)


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


def with_limit(fn):
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, CASE_SECONDS)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def run_case(target, data, seed, workdir):
    """None on an acceptable outcome, else (exception type, message, location)."""
    try:
        with_limit(lambda: dispatch(target, data, seed, workdir))
    except Timeout:
        return ("Timeout", f"no result in {CASE_SECONDS}s", "")
    except MemoryError:
        return ("MemoryError", "", "")
    except Exception as e:
        tb = e.__traceback__
        where = ""
        while tb:
            if "/rdis/" in tb.tb_frame.f_code.co_filename or "/pypcode" in tb.tb_frame.f_code.co_filename:
                where = f"{os.path.basename(tb.tb_frame.f_code.co_filename)}:{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}"
            tb = tb.tb_next
        return (type(e).__name__, str(e)[:160], where)
    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > (MAX_RSS if platform.system() == "Darwin" else MAX_RSS >> 10):
        return ("MemoryGrowth", "peak RSS above 3 GiB", "")
    return None


def dispatch(target, data, seed, workdir):
    from rdis.analysis import Program
    from rdis.loader import open_image
    if target in ("elf", "macho"):
        path = os.path.join(workdir, "case.bin")
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            image = open_image(path)
        except ValueError:
            return
        prog = Program(image).analyze(objc=False, swift=False)
        from rdis.decompile import Decompiler
        for addr in sorted(prog.functions)[:3]:
            Decompiler(prog, prog.functions[addr]).c()
    elif target == "zip":
        from rdis import containers
        path = os.path.join(workdir, "case.zip")
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            rows = containers.slices(path)
            for row in rows[:2]:
                if row.get("entry"):
                    containers.extract(path, row["entry"], workdir, 8)
        except ValueError:
            return
    elif target == "wasm":
        from rdis.wasm import WasmProgram
        try:
            WasmProgram("case.wasm", data)
        except ValueError:
            return
    elif target == "mcp":
        from rdis import mcp_server
        for line in data.decode("utf-8", "replace").splitlines():
            reply = mcp_server.process_line(line)
            if reply is not None:
                json.loads(reply)
    elif target == "decode":
        from rdis import arch as archmod
        name = ("ppc", "sparc", "m68k", "avr8", "msp430", "xtensa", "sh4", "ebpf", "loongarch64", "tricore", "z80",
                "6502", "arm64", "x86_64", "arm", "mips", "riscv64")[seed % 17]
        a = archmod.make(name)
        for i in a.decode_run(data, 0x1000):
            a.kind(i), a.target(i), i.mnemonic, i.op_str
    elif target == "ir":
        from rdis.decompile import Decompiler
        name = ("ppc", "sparc", "m68k", "msp430", "xtensa", "sh4", "ebpf", "loongarch64", "arm64", "x86_64", "mips",
                "riscv64")[seed % 12]
        path = os.path.join(workdir, "case.raw")
        with open(path, "wb") as fh:
            fh.write(data)
        prog = Program(open_image(path, loader="raw", arch=name, base=0x1000)).analyze(prologues=False)
        for addr in sorted(prog.functions)[:2]:
            Decompiler(prog, prog.functions[addr]).c()
    else:
        raise ValueError(f"unknown target {target}")


def worker(target, seed, start, count):
    corpus = seed_corpus()
    workdir = tempfile.mkdtemp(prefix="rdis-fuzz-")
    os.environ["RDIS_CACHE_DIR"] = os.path.join(workdir, "cache")
    findings, ran = [], 0
    for index in range(start, start + count):
        failure = run_case(target, make_case(target, seed, index, corpus), seed, workdir)
        ran += 1
        if failure:
            findings.append({"index": index, "type": failure[0], "message": failure[1], "where": failure[2]})
    shutil.rmtree(workdir, ignore_errors=True)
    print(json.dumps({"ran": ran, "findings": findings}))


def run_worker(target, seed, start, count, timeout):
    cmd = [sys.executable, os.path.abspath(__file__), "--worker", target, str(seed), str(start), str(count)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "hang"
    if r.returncode != 0:
        return None, f"crash rc={r.returncode}: {r.stderr.strip().splitlines()[-1][:120] if r.stderr.strip() else ''}"
    return json.loads(r.stdout.strip().splitlines()[-1]), None


def isolate(target, seed, start, count, reason, timeout):
    """Binary-split a range whose worker died until single crashing cases remain."""
    if count == 1:
        return [{"index": start, "type": "NativeCrashOrHang", "message": reason, "where": ""}]
    half = count // 2
    found = []
    for lo, n in ((start, half), (start + half, count - half)):
        res, why = run_worker(target, seed, lo, n, timeout)
        if why:
            found += isolate(target, seed, lo, n, why, timeout)
        else:
            found += res["findings"]
    return found


def minimize(target, seed, data, signature):
    """Delta-debug `data` while the same failure (type and location) still occurs."""
    workdir = tempfile.mkdtemp(prefix="rdis-fuzz-min-")
    os.environ["RDIS_CACHE_DIR"] = os.path.join(workdir, "cache")

    def fails(blob):
        f = run_case(target, blob, seed, workdir)
        return f is not None and (f[0], f[2]) == signature

    chunk = max(1, len(data) // 2)
    while chunk >= 1:
        i, shrank = 0, False
        while i < len(data):
            trial = data[:i] + data[i + chunk:]
            if trial and fails(trial):
                data, shrank = trial, True
            else:
                i += chunk
        if not shrank:
            chunk //= 2
    shutil.rmtree(workdir, ignore_errors=True)
    return data


def campaign(args):
    targets = args.targets.split(",")
    corpus = seed_corpus()
    report = {"platform": f"{platform.system()} {platform.machine()}", "python": platform.python_version(),
              "seeds": args.seeds, "cases_per_seed": args.cases, "case_timeout_s": CASE_SECONDS, "targets": {}}
    for target in targets:
        entry = {"ran": 0, "findings": []}
        for seed in range(args.seeds):
            res, why = run_worker(target, seed, 0, args.cases, CASE_SECONDS * args.cases + 60)
            if why:
                found = isolate(target, seed, 0, args.cases, why, CASE_SECONDS * 20 + 60)
                entry["ran"] += args.cases
            else:
                found, entry["ran"] = res["findings"], entry["ran"] + res["ran"]
            for f in found:
                f["seed"] = seed
                entry["findings"].append(f)
        groups = {}
        for f in entry["findings"]:
            groups.setdefault((f["type"], f["where"]), []).append(f)
        entry["distinct"] = []
        for (etype, where), items in sorted(groups.items()):
            first = items[0]
            data = make_case(target, first["seed"], first["index"], corpus)
            small = minimize(target, first["seed"], data, (etype, where)) if etype != "NativeCrashOrHang" else data
            entry["distinct"].append({"type": etype, "where": where, "message": first["message"], "occurrences": len(items),
                                      "replay": f"python tests/fuzz.py --replay {target} {first['seed']} {first['index']}",
                                      "original_bytes": len(data), "minimized_bytes": len(small),
                                      "minimized_hex": small[:512].hex()})
        del entry["findings"]
        report["targets"][target] = entry
        print(f"{target:6} ran {entry['ran']:6}  distinct failures {len(entry['distinct'])}", flush=True)
        for d in entry["distinct"]:
            print(f"   {d['type']} at {d['where']} x{d['occurrences']}: {d['message'][:100]}", flush=True)
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=1, sort_keys=True)
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=10)
    p.add_argument("--cases", type=int, default=200)
    p.add_argument("--targets", default="elf,zip,wasm,mcp,decode,ir")
    p.add_argument("--out")
    p.add_argument("--worker", nargs=4, metavar=("TARGET", "SEED", "START", "COUNT"))
    p.add_argument("--replay", nargs=3, metavar=("TARGET", "SEED", "INDEX"))
    a = p.parse_args()
    if a.worker:
        t, s, st, c = a.worker
        worker(t, int(s), int(st), int(c))
    elif a.replay:
        t, s, i = a.replay
        data = make_case(t, int(s), int(i), seed_corpus())
        workdir = tempfile.mkdtemp(prefix="rdis-fuzz-replay-")
        print(run_case(t, data, int(s), workdir) or "no failure")
    else:
        report = campaign(a)
        sys.exit(1 if any(v["distinct"] for v in report["targets"].values()) else 0)


if __name__ == "__main__":
    main()
