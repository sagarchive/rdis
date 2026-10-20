"""Match the functions of two builds of a program and carry analyst annotations across.

Passes run from the most to the least specific; a pass only accepts a pairing that is unique on both
sides, so ambiguity is reported instead of guessed (BinDiff and Diaphora order their passes the same way):

    name        the same symbol name on both sides
    exact       identical address-masked instruction stream
    shape       identical mnemonic stream and CFG shape
    strings     identical referenced strings and block count
    callgraph   the i-th call of a matched pair, when both make the same number of calls
    similarity  mutual best trigram overlap with a clear margin
"""
from collections import defaultdict
from dataclasses import dataclass, field

from .fingerprint import features, similarity

CONFIDENCE = {"name": 1.0, "exact": 0.95, "shape": 0.85, "strings": 0.8}
MIN_INSNS = 3
MARGIN = 0.1
ACCEPT = 0.8
CANDIDATE_CAP = 200


@dataclass
class Match:
    a: int
    b: int
    method: str
    confidence: float


@dataclass
class DiffResult:
    matches: list = field(default_factory=list)
    only_a: list = field(default_factory=list)
    only_b: list = field(default_factory=list)
    ambiguous: list = field(default_factory=list)

    def by_method(self):
        out = defaultdict(int)
        for m in self.matches:
            out[m.method] += 1
        return dict(out)

    def as_dict(self):
        hexa = lambda v: hex(v)
        return {
            "counts": {"matched": len(self.matches), "only_a": len(self.only_a), "only_b": len(self.only_b),
                       "ambiguous": len(self.ambiguous), "by_method": self.by_method()},
            "matches": [{"a": hexa(m.a), "b": hexa(m.b), "method": m.method, "confidence": round(m.confidence, 3)}
                        for m in sorted(self.matches, key=lambda m: m.a)],
            "only_a": [hexa(a) for a in self.only_a],
            "only_b": [hexa(b) for b in self.only_b],
            "ambiguous": [{"a": hexa(a), "candidates": [hexa(c) for c in cands]} for a, cands in self.ambiguous],
        }


class _Matcher:
    def __init__(self, pa, pb, min_insns):
        self.fa = {a: features(pa, f) for a, f in pa.functions.items()}
        self.fb = {b: features(pb, f) for b, f in pb.functions.items()}
        self.min_insns = min_insns
        self.matched_a, self.matched_b, self.matches = set(), set(), []
        self.pair = {}
        self.back = {}
        self.callers_a, self.callers_b = self._callers(self.fa), self._callers(self.fb)

    def accept(self, a, b, method, confidence):
        self.matched_a.add(a)
        self.matched_b.add(b)
        self.pair[a], self.back[b] = b, a
        self.matches.append(Match(a, b, method, confidence))

    @staticmethod
    def _callers(feats):
        out = defaultdict(list)
        for addr, f in feats.items():
            for target in set(f.callees):
                if target in feats:
                    out[target].append(addr)
        return out

    def named_apart(self, a, b):
        return bool(self.fa[a].name and self.fb[b].name and self.fa[a].name != self.fb[b].name)

    def consistent(self, a, b):
        if self.named_apart(a, b):
            return False
        ca, cb = self.fa[a].callees, self.fb[b].callees
        if len(ca) != len(cb):
            return False
        for x, y in zip(ca, cb):
            if x in self.pair and self.pair[x] != y:
                return False
            if y in self.back and self.back[y] != x:
                return False
        return True

    def free(self, side, matched):
        return {k: v for k, v in side.items() if k not in matched}

    def unique_pass(self, method, key):
        left, right = defaultdict(list), defaultdict(list)
        for a, f in self.free(self.fa, self.matched_a).items():
            k = key(f)
            if k is not None:
                left[k].append(a)
        for b, f in self.free(self.fb, self.matched_b).items():
            k = key(f)
            if k is not None:
                right[k].append(b)
        for k, aa in left.items():
            bb = right.get(k)
            if bb and len(aa) == 1 and len(bb) == 1 and (method == "name" or self.consistent(aa[0], bb[0])):
                self.accept(aa[0], bb[0], method, CONFIDENCE[method])

    def propagate(self):
        changed = True
        while changed:
            changed = False
            for m in list(self.matches):
                ca, cb = self.fa[m.a].callees, self.fb[m.b].callees
                if len(ca) == len(cb):
                    for x, y in zip(ca, cb):
                        if x in self.fa and y in self.fb and x not in self.matched_a and y not in self.matched_b \
                                and not self.named_apart(x, y) and similarity(self.fa[x], self.fb[y]) >= 0.5:
                            self.accept(x, y, "callgraph", round(m.confidence * 0.9, 3))
                            changed = True
                up_a = [x for x in self.callers_a.get(m.a, ()) if x not in self.matched_a]
                up_b = [y for y in self.callers_b.get(m.b, ()) if y not in self.matched_b]
                if len(up_a) == 1 and len(up_b) == 1 and similarity(self.fa[up_a[0]], self.fb[up_b[0]]) >= 0.5 \
                        and self.consistent(up_a[0], up_b[0]):
                    self.accept(up_a[0], up_b[0], "callgraph", round(m.confidence * 0.9, 3))
                    changed = True

    def similar(self):
        ambiguous = []
        left = self.free(self.fa, self.matched_a)
        right = self.free(self.fb, self.matched_b)
        buckets = defaultdict(list)
        for b, f in right.items():
            buckets[f.nblocks].append(b)
        best = {}
        for a, f in left.items():
            pool = [b for n in (f.nblocks - 1, f.nblocks, f.nblocks + 1) for b in buckets.get(n, ())][:CANDIDATE_CAP]
            scored = sorted(((similarity(f, right[b]), b) for b in pool), reverse=True)
            if scored and scored[0][0] >= 0.5:
                best[a] = scored
        reverse = {}
        for a, scored in best.items():
            for s, b in scored[:2]:
                reverse.setdefault(b, []).append((s, a))
        for a, scored in best.items():
            s0, b0 = scored[0]
            runner = scored[1][0] if len(scored) > 1 else 0.0
            back = sorted(reverse[b0], reverse=True)
            mutual = back[0][1] == a and (len(back) == 1 or back[0][0] - back[1][0] >= MARGIN)
            if s0 >= ACCEPT and s0 - runner >= MARGIN and mutual and self.consistent(a, b0):
                self.accept(a, b0, "similarity", round(s0 * 0.8, 3))
            elif s0 >= 0.6:
                ambiguous.append((a, [b for s, b in scored if s >= s0 - MARGIN][:5]))
        return ambiguous


def diff(prog_a, prog_b, min_insns=MIN_INSNS):
    m = _Matcher(prog_a, prog_b, min_insns)
    m.unique_pass("name", lambda f: f.name or None)
    m.unique_pass("exact", lambda f: f.exact if f.size >= min_insns else None)
    m.propagate()
    m.unique_pass("shape", lambda f: (f.mnemonics, f.shape) if f.size >= min_insns else None)
    m.propagate()
    m.unique_pass("strings", lambda f: (f.strings, f.nblocks) if f.strings else None)
    m.propagate()
    ambiguous = m.similar()
    m.propagate()
    taken = {a for a in m.matched_a}
    ambiguous = [(a, c) for a, c in ambiguous if a not in taken]
    return DiffResult(sorted(m.matches, key=lambda x: x.a),
                      sorted(set(m.fa) - m.matched_a), sorted(set(m.fb) - m.matched_b), ambiguous)


def transfer(prog_a, prog_b, result, min_confidence=0.9):
    """Copy user renames (and, for byte-identical code, instruction comments) from A to B.

    Matches below `min_confidence` and ambiguous functions are never transferred; they are returned
    with a reason so a reviewer can decide."""
    from .fingerprint import function_insns
    applied, skipped = [], []
    for m in result.matches:
        name = prog_a.user_names.get(m.a)
        cmts = {i.address: prog_a.comments[i.address] for i in function_insns(prog_a.functions[m.a])
                if i.address in prog_a.comments}
        if not name and not cmts:
            continue
        if m.confidence < min_confidence:
            skipped.append({"a": m.a, "b": m.b, "reason": f"confidence {m.confidence} below {min_confidence}"})
            continue
        if name and m.b not in prog_b.user_names:
            prog_b.rename(m.b, name)
            applied.append({"a": m.a, "b": m.b, "kind": "name"})
        if cmts and m.method in ("exact", "name"):
            ia, ib = function_insns(prog_a.functions[m.a]), function_insns(prog_b.functions[m.b])
            if len(ia) == len(ib) and all(x.mnemonic == y.mnemonic for x, y in zip(ia, ib)):
                for x, y in zip(ia, ib):
                    if x.address in cmts and y.address not in prog_b.comments:
                        prog_b.comment(y.address, cmts[x.address])
                        applied.append({"a": x.address, "b": y.address, "kind": "comment"})
            else:
                skipped.append({"a": m.a, "b": m.b, "reason": "instruction layout differs; comments not transferred"})
    for a, cands in result.ambiguous:
        if a in prog_a.user_names:
            skipped.append({"a": a, "b": None, "reason": f"ambiguous between {len(cands)} candidates"})
    return {"applied": applied, "skipped": skipped}
