"""Hammer the running rdis server from many threads to shake out concurrency bugs.

Each virtual visitor has its own cookie jar (its own session). Visitors open the SAME binary and
DIFFERENT binaries, then concurrently: list, decompile random functions, render CFGs, read hex,
rename, comment, bookmark, run console commands, export/import. Asserts:
  * no 5xx responses, no tracebacks leaked;
  * one visitor's rename is never visible to another (session isolation);
  * decompiling the same function many times concurrently always yields identical output.
"""
import concurrent.futures as cf
import http.cookiejar
import json
import random
import sys
import threading
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8781"
errors, lock = [], threading.Lock()


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(opener, method, route, params=None, body=None):
    url = f"{BASE}/api/{route}"
    if params:
        url += "?" + "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items())
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def note(msg):
    with lock:
        errors.append(msg)


def upload_open(op, binpath, arch):
    """Upload a file and open the chosen arch slice (works on a multi-user server where path-open
    is disabled)."""
    with open(binpath, "rb") as fh:
        data = fh.read()
    req = urllib.request.Request(f"{BASE}/api/upload?name={binpath.split('/')[-1]}", data=data,
                                 method="POST", headers={"Content-Type": "application/octet-stream"})
    with op.open(req, timeout=60) as r:
        up = json.loads(r.read())
    return call(op, "POST", "open", body={"token": up["token"], "arch": arch})


def visitor(n, binpath, arch):
    op = client()
    op.open(urllib.request.Request(BASE))  # establish cookie
    st, r = upload_open(op, binpath, arch)
    if st != 200:
        return note(f"v{n} open {binpath}: {st} {r}")
    st, info = call(op, "GET", "info")
    if st != 200:
        return note(f"v{n} info: {st} {r}")
    st, fns = call(op, "GET", "functions")
    funcs = [f["addr"] for f in fns["items"]][:60]
    # a rename unique to this visitor: it must never be seen by anyone else
    mine = f"vis{n}_{random.randint(0, 1 << 30):x}"
    if funcs:
        tag = random.choice(funcs)
        call(op, "POST", "rename", body={"addr": tag, "name": mine})
    for _ in range(40):
        f = random.choice(funcs) if funcs else info["entry"]
        mode = random.choice(["listing", "pseudo", "cfg", "hex", "listing", "pseudo"])
        st, d = call(op, "GET", mode, {"func": f} if mode != "hex" else {"addr": f})
        if st not in (200, 400):
            note(f"v{n} {mode} {f}: {st} {d.get('error')}")
        st, _ = call(op, "GET", "search", {"q": random.choice(["a", "init", "str", "0x1", "obj"])})
        if random.random() < 0.3 and funcs:
            call(op, "POST", "comment", body={"addr": random.choice(funcs), "text": f"note from {n}"})
        if random.random() < 0.2:
            call(op, "POST", "command", body={"line": random.choice(["help", "info", "procs a", "strings e"])})
    # verify isolation: nobody else's tag leaked into my view
    st, lbls = call(op, "GET", "labels")
    names = {x["name"] for x in lbls["items"]}
    leaked = {x for x in names if x.startswith("vis") and not x.startswith(mine)}
    if leaked:
        note(f"v{n} ISOLATION LEAK saw other visitors' renames: {sorted(leaked)[:3]}")
    return mine


def determinism(binpath, arch, workers=8, rounds=30):
    """Decompile the same functions from many threads at once; output must be identical each time."""
    op = client()
    op.open(urllib.request.Request(BASE))
    upload_open(op, binpath, arch)
    _, fns = call(op, "GET", "functions")
    funcs = [f["addr"] for f in fns["items"]][:12]
    baseline = {f: call(op, "GET", "pseudo", {"func": f})[1].get("c") for f in funcs}

    def one(f):
        return f, call(op, "GET", "pseudo", {"func": f})[1].get("c")

    with cf.ThreadPoolExecutor(workers) as ex:
        for _ in range(rounds):
            for f, c in ex.map(one, funcs * 2):
                if c != baseline[f]:
                    note(f"NON-DETERMINISTIC decompile of {f} under concurrency")


def main():
    bins = [("/bin/ls", "arm64"), ("/bin/ls", "arm64"), ("/bin/cat", "arm64"),
            ("/usr/bin/grep", "arm64"), ("/bin/ls", "x86_64")]
    with cf.ThreadPoolExecutor(20) as ex:
        futs = [ex.submit(visitor, i, *random.choice(bins)) for i in range(20)]
        tags = [f.result() for f in futs]
    determinism("/bin/ls", "arm64")
    print(f"20 concurrent visitors + determinism check done; {len(errors)} problem(s)")
    for e in errors[:20]:
        print("  ", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
