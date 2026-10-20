import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdis.analysis import Program
from rdis.arch import make
from rdis.diff import diff, transfer
from rdis.loader import Image, Section, open_image

BASE = 0x1000

F1 = "89f8" "83c007" "6bc003" "83e801" "c3"
F1_EDITED = "89f8" "83c009" "6bc003" "83e801" "c3"
F2 = "83ff0a" "7e06" "b801000000" "c3" "31c0" "c3"
F3 = "8d047f" "c1e002" "f7d8" "f7d0" "c3"


def _call(here, target):
    return b"\xe8" + ((target - (here + 5)) & 0xFFFFFFFF).to_bytes(4, "little")


def program(layout, pad=0):
    """main calls each function in `layout` (a list of (name, hex bytes)); returns (Program, {name: address})."""
    main_len = 5 * len(layout) + 1
    addr, where = BASE + pad + main_len, {}
    bodies = b""
    for name, hexbytes in layout:
        where[name] = addr
        raw = bytes.fromhex(hexbytes)
        bodies += raw
        addr += len(raw)
    main = b"".join(_call(BASE + pad + 5 * i, where[name]) for i, (name, _) in enumerate(layout)) + b"\xc3"
    code = b"\x90" * pad + main + bodies
    image = Image("<diff-fixture>", "raw", make("x86_64"), BASE + pad, BASE, [Section(".text", BASE, len(code), 0, True)],
                  {}, {}, lambda va, n: code[va - BASE:va - BASE + n] if BASE <= va < BASE + len(code) else b"",
                  lambda va: None)
    where["main"] = BASE + pad
    return Program(image).analyze(objc=False, swift=False, prologues=False), where


class HandEncodedDiffTests(unittest.TestCase):
    def setUp(self):
        self.a, self.wa = program([("f1", F1), ("f2", F2), ("f3", F3)])
        self.b, self.wb = program([("f3", F3), ("f2", F2), ("f1", F1_EDITED)], pad=16)
        self.result = diff(self.a, self.b)
        self.pairs = {m.a: m for m in self.result.matches}

    def test_every_function_pairs_with_its_counterpart_despite_moved_addresses(self):
        for name in ("main", "f1", "f2", "f3"):
            m = self.pairs[self.wa[name]]
            self.assertEqual(m.b, self.wb[name], name)
        self.assertEqual((self.result.only_a, self.result.only_b, self.result.ambiguous), ([], [], []))

    def test_methods_and_confidence_reflect_how_much_matched(self):
        self.assertEqual(self.pairs[self.wa["f2"]].method, "exact")
        self.assertEqual(self.pairs[self.wa["f3"]].method, "exact")
        self.assertEqual(self.pairs[self.wa["f1"]].method, "shape")
        self.assertLess(self.pairs[self.wa["f1"]].confidence, self.pairs[self.wa["f2"]].confidence)

    def test_a_changed_function_with_no_twin_is_unmatched_when_its_shape_changes(self):
        other, where = program([("f3", F3), ("f2", F2), ("f1", F3)], pad=16)
        result = diff(self.a, other)
        self.assertNotIn(self.wa["f1"], {m.a for m in result.matches if m.b == where["f1"] and m.method == "exact"})

    def test_transfer_applies_high_confidence_names_and_comments_and_skips_the_rest(self):
        self.a.rename(self.wa["f2"], "check_limit")
        self.a.rename(self.wa["f1"], "scale")
        first = self.a.functions[self.wa["f2"]].blocks[self.wa["f2"]].insns[0].address
        self.a.comment(first, "limit is 10")
        report = transfer(self.a, self.b, self.result, min_confidence=0.9)
        self.assertEqual(self.b.user_names.get(self.wb["f2"]), "check_limit")
        self.assertNotIn(self.wb["f1"], self.b.user_names)
        self.assertEqual(self.b.comments.get(self.wb["f2"]), "limit is 10")
        reasons = [row["reason"] for row in report["skipped"]]
        self.assertTrue(any("below 0.9" in r for r in reasons), reasons)
        self.assertEqual(sorted(row["kind"] for row in report["applied"]), ["comment", "name"])

    def test_lowering_the_threshold_transfers_the_shape_match(self):
        self.a.rename(self.wa["f1"], "scale")
        transfer(self.a, self.b, self.result, min_confidence=0.8)
        self.assertEqual(self.b.user_names.get(self.wb["f1"]), "scale")

    def test_existing_names_in_the_target_are_never_overwritten(self):
        self.a.rename(self.wa["f2"], "check_limit")
        self.b.rename(self.wb["f2"], "mine")
        transfer(self.a, self.b, self.result)
        self.assertEqual(self.b.user_names[self.wb["f2"]], "mine")

    def test_duplicate_functions_are_ambiguous_not_guessed(self):
        a, wa = program([("g1", F2), ("g2", F2)])
        b, wb = program([("g1", F2), ("g2", F2)], pad=16)
        result = diff(a, b)
        exact = [m for m in result.matches if m.method == "exact" and m.a in (wa["g1"], wa["g2"])]
        self.assertEqual(exact, [])

    def test_json_form_is_stable_and_hex_addressed(self):
        out = self.result.as_dict()
        json.dumps(out)
        self.assertEqual(out["counts"]["matched"], 4)
        self.assertTrue(all(row["a"].startswith("0x") for row in out["matches"]))


try:
    import diff_corpus
except ImportError:
    diff_corpus = None


class CompiledCorpusScore(unittest.TestCase):
    """Two builds of a 36-function program (5 functions modified, 3 deleted, 3 added, order reversed).
    Ground truth is the symbol table of the unstripped builds; the matcher only sees the stripped ones."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        built = None
        if diff_corpus is not None:
            try:
                built = (diff_corpus.build(cls.tmp.name, 1), diff_corpus.build(cls.tmp.name, 2))
            except Exception:
                built = None
        if not built or None in built:
            raise unittest.SkipTest("no C compiler and strip available")
        cls.v1, cls.v2 = built

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def labels(path):
        p = Program(open_image(str(path))).analyze()
        return {a: p.display(a).lstrip("_") for a in p.functions if (p.display(a) or "").lstrip("_").startswith("fn_")}

    def score(self, a_path, b_path, truth_a, truth_b):
        result = diff(Program(open_image(str(a_path))).analyze(), Program(open_image(str(b_path))).analyze())
        tp = fp = 0
        wrong = []
        for m in result.matches:
            na, nb = truth_a.get(m.a), truth_b.get(m.b)
            if na is None and nb is None:
                continue
            if na == nb:
                tp += 1
            else:
                fp += 1
                wrong.append((na, nb, m.method))
        common = set(truth_a.values()) & set(truth_b.values())
        metrics = {"matched": len(result.matches), "true_positives": tp, "false_positives": fp,
                   "common_functions": len(common), "precision": round(tp / max(1, tp + fp), 4),
                   "recall": round(tp / len(common), 4), "by_method": result.by_method(), "wrong": wrong}
        return result, metrics

    def test_stripped_builds_precision_and_recall(self):
        truth_a, truth_b = self.labels(self.v1[0]), self.labels(self.v2[0])
        result, metrics = self.score(self.v1[1], self.v2[1], truth_a, truth_b)
        print("DIFF_METRIC " + json.dumps({"corpus": "36-function C program, v1->v2, stripped", **metrics},
                                          sort_keys=True))
        self.assertGreaterEqual(metrics["precision"], 0.9, metrics)
        self.assertGreaterEqual(metrics["recall"], 0.7, metrics)
        exact = [m for m in result.matches if m.method == "exact"]
        self.assertTrue(exact)
        self.assertTrue(all(truth_a.get(m.a) == truth_b.get(m.b) for m in exact if m.a in truth_a or m.b in truth_b))

    def test_across_optimization_levels_a_wrong_match_is_rarer_than_a_miss(self):
        built = diff_corpus.build(self.tmp.name, 2, "-O2")
        truth_a, truth_b = self.labels(self.v1[0]), self.labels(built[0])
        _, metrics = self.score(self.v1[1], built[1], truth_a, truth_b)
        print("DIFF_METRIC " + json.dumps({"corpus": "36-function C program, v1 -O1 -> v2 -O2, stripped", **metrics},
                                          sort_keys=True))
        self.assertGreaterEqual(metrics["precision"], 0.9, metrics)
        self.assertGreater(metrics["true_positives"], metrics["false_positives"] * 5, metrics)

    def test_builds_with_symbols_match_by_name(self):
        truth_a, truth_b = self.labels(self.v1[0]), self.labels(self.v2[0])
        _, metrics = self.score(self.v1[0], self.v2[0], truth_a, truth_b)
        print("DIFF_METRIC " + json.dumps({"corpus": "36-function C program, v1->v2, with symbols", **metrics},
                                          sort_keys=True))
        self.assertEqual(metrics["precision"], 1.0, metrics)
        self.assertEqual(metrics["recall"], 1.0, metrics)


if __name__ == "__main__":
    unittest.main()
