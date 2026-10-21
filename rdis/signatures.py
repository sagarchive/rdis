"""Local function signatures: name functions in a stripped binary from a binary that has symbols.

A signature is the address-masked instruction hash of a function body. A wrong name is worse than no
name, so tiny functions are never signed, a hash shared by differently named functions is reported
as ambiguous rather than picked from, and every match carries its source database and a confidence.
"""
import hashlib
import json
import os

from .fingerprint import features, is_generated

FORMAT = 1
MIN_INSNS = 8
TIERS = ((32, 0.97), (16, 0.9), (8, 0.8), (0, 0.6))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def confidence(size):
    return next((c for floor, c in TIERS if size >= floor), 0.0)


def make(prog, min_insns=MIN_INSNS):
    """Signature database (a JSON-serializable dict) from the named functions of `prog`."""
    entries = {}
    for addr, func in prog.functions.items():
        f = features(prog, func)
        if f.size < min_insns or is_generated(f.name):
            continue
        entry = entries.setdefault(f.exact, {"names": [], "size": f.size})
        if f.name not in entry["names"]:
            entry["names"].append(f.name)
    return {"format": FORMAT, "min_insns": min_insns, "arch": prog.arch.name,
            "source": {"name": os.path.basename(prog.image.path), "sha256": _sha256(prog.image.path)},
            "entries": entries}


def match(prog, db, min_insns=None):
    """Names for the unnamed functions of `prog`: {"matches": [...], "ambiguous": [...]}."""
    if db.get("format") != FORMAT:
        raise ValueError(f"unsupported signature database format {db.get('format')!r}")
    if db.get("arch") != prog.arch.name:
        raise ValueError(f"database is for {db.get('arch')}, binary is {prog.arch.name}")
    floor = max(min_insns or 0, db.get("min_insns", MIN_INSNS))
    matches, ambiguous = [], []
    for addr, func in sorted(prog.functions.items()):
        f = features(prog, func)
        if f.size < floor or not is_generated(f.name):
            continue
        entry = db["entries"].get(f.exact)
        if entry is None:
            continue
        row = {"addr": addr, "size": f.size, "source": db["source"]["name"]}
        if len(entry["names"]) == 1:
            matches.append({**row, "name": entry["names"][0], "confidence": confidence(f.size)})
        else:
            ambiguous.append({**row, "candidates": sorted(entry["names"])})
    return {"matches": matches, "ambiguous": ambiguous}


def dump(db, path):
    with open(path, "w") as fh:
        json.dump(db, fh, indent=1, sort_keys=True)


def load(path):
    with open(path) as fh:
        return json.load(fh)
