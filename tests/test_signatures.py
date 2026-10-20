import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdis import signatures
from rdis.fingerprint import is_generated
from rdis.analysis import Program
from rdis.arch import make
from rdis.loader import Image, Section, open_image
from test_diff import F1, F2, F3, _call

BASE = 0x1000
TINY = "31c0c3"


def program(layout, pad=0, named=False):
    main_len = 5 * len(layout) + 1
    addr, where, bodies = BASE + pad + main_len, {}, b""
    for name, hexbytes in layout:
        where[name] = addr
        bodies += bytes.fromhex(hexbytes)
        addr += len(bytes.fromhex(hexbytes))
    main = b"".join(_call(BASE + pad + 5 * i, where[n]) for i, (n, _) in enumerate(layout)) + b"\xc3"
    code = b"\x90" * pad + main + bodies
    symbols = {a: n for n, a in where.items()} if named else {}
    image = Image("<sig-fixture>", "raw", make("x86_64"), BASE + pad, BASE, [Section(".text", BASE, len(code), 0, True)],
                  symbols, {}, lambda va, n: code[va - BASE:va - BASE + n] if BASE <= va < BASE + len(code) else b"",
                  lambda va: None)
    return Program(image).analyze(objc=False, swift=False, prologues=False), where


class SignatureTests(unittest.TestCase):
    def db(self, layout=None, min_insns=4):
        prog, _ = program(layout or [("alpha", F1), ("beta", F2), ("gamma", F3)], named=True)
        prog.image.path = __file__
        return signatures.make(prog, min_insns)

    def test_stripped_and_moved_copies_are_named_with_source_and_confidence(self):
        db = self.db()
        target, where = program([("c", F3), ("a", F1), ("b", F2)], pad=24)
        out = signatures.match(target, db)
        names = {m["addr"]: m["name"] for m in out["matches"]}
        self.assertEqual(names[where["a"]], "alpha")
        self.assertEqual(names[where["b"]], "beta")
        self.assertEqual(names[where["c"]], "gamma")
        self.assertTrue(all(m["source"] == "test_signatures.py" and 0 < m["confidence"] < 1 for m in out["matches"]))

    def test_an_edited_function_is_not_named(self):
        db = self.db()
        edited = F1.replace("83c007", "83c009")
        target, where = program([("a", edited), ("b", F2), ("c", F3)])
        names = {m["addr"] for m in signatures.match(target, db)["matches"]}
        self.assertNotIn(where["a"], names)
        self.assertIn(where["b"], names)

    def test_identical_bodies_with_different_names_are_ambiguous(self):
        db = self.db([("one", F2), ("two", F2)])
        target, where = program([("x", F2)])
        out = signatures.match(target, db)
        self.assertEqual(out["matches"], [])
        self.assertEqual(out["ambiguous"][0]["candidates"], ["one", "two"])

    def test_tiny_functions_are_never_signed_or_matched(self):
        db = self.db([("tiny", TINY), ("beta", F2)], min_insns=4)
        self.assertEqual([e["names"] for e in db["entries"].values()], [["beta"]])
        target, where = program([("t", TINY)])
        self.assertEqual(signatures.match(target, db)["matches"], [])

    def test_already_named_functions_keep_their_names(self):
        db = self.db()
        target, where = program([("kept", F2)], named=True)
        self.assertEqual(signatures.match(target, db)["matches"], [])

    def test_wrong_architecture_and_format_are_rejected(self):
        db = self.db()
        target, _ = program([("a", F1)])
        with self.assertRaises(ValueError):
            signatures.match(target, {**db, "arch": "arm64"})
        with self.assertRaises(ValueError):
            signatures.match(target, {**db, "format": 99})

    def test_database_round_trips_through_json(self):
        db = self.db()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sig.json")
            signatures.dump(db, path)
            self.assertEqual(signatures.load(path), db)

    def test_mcp_tool_returns_hex_addresses(self):
        from rdis.mcp_server import _handle
        db = self.db()
        target, where = program([("a", F1), ("b", F2)])
        with tempfile.TemporaryDirectory() as d:
            sig, blob = os.path.join(d, "sig.json"), os.path.join(d, "blob.bin")
            signatures.dump(db, sig)
            code = target.image.read(BASE, 0x200)
            with open(blob, "wb") as fh:
                fh.write(code)
            r = _handle({"method": "tools/call", "params": {"name": "signatures", "arguments": {
                "path": blob, "db": sig, "arch": "x86_64", "loader": "raw", "base": BASE}}})
        self.assertFalse(r.get("isError"), r)
        out = json.loads(r["content"][0]["text"])
        self.assertTrue(all(m["addr"].startswith("0x") for m in out["matches"]))


try:
    import diff_corpus
except ImportError:
    diff_corpus = None


class CompiledCorpusScore(unittest.TestCase):
    """Signatures from the symbols of build v1, applied to the stripped builds. Ground truth is the
    symbol table of the unstripped build the stripped one was made from."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        try:
            cls.v1, cls.v2 = diff_corpus.build(cls.tmp.name, 1), diff_corpus.build(cls.tmp.name, 2)
        except Exception:
            cls.v1 = cls.v2 = None
        if not cls.v1 or not cls.v2:
            raise unittest.SkipTest("no C compiler and strip available")
        cls.db = signatures.make(Program(open_image(str(cls.v1[0]))).analyze())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def truth(path):
        p = Program(open_image(str(path))).analyze()
        return {a: p.display(a).lstrip("_") for a in p.functions if not is_generated(p.display(a))}

    def score(self, stripped, unstripped):
        out = signatures.match(Program(open_image(str(stripped))).analyze(), self.db)
        truth = self.truth(unstripped)
        right = sum(1 for m in out["matches"] if truth.get(m["addr"]) == m["name"].lstrip("_"))
        return out, right, len(out["matches"]) - right

    def test_other_version_is_named_without_a_single_wrong_name(self):
        out, right, wrong = self.score(self.v2[1], self.v2[0])
        print("SIGNATURE_METRIC " + json.dumps({"database": "v1 symbols", "target": "v2 stripped",
                                                "named": len(out["matches"]), "correct": right, "wrong": wrong,
                                                "ambiguous": len(out["ambiguous"])}, sort_keys=True))
        self.assertEqual(wrong, 0)
        self.assertGreaterEqual(right, 20)

    def test_same_build_stripped_recovers_nearly_every_signed_function(self):
        out, right, wrong = self.score(self.v1[1], self.v1[0])
        unique = sum(len(entry["names"]) == 1 for entry in self.db["entries"].values())
        self.assertEqual(wrong, 0)
        self.assertGreaterEqual(right, unique - 2)
        self.assertEqual(len(out["matches"]) + len(out["ambiguous"]) >= unique, True)

    @unittest.skipUnless(os.path.exists("/bin/ls"), "needs /bin/ls")
    def test_unrelated_system_binary_gets_no_names(self):
        try:
            prog = Program(open_image("/bin/ls", arch=self.db["arch"])).analyze()
        except ValueError:
            self.skipTest("no /bin/ls slice for this architecture")
        if prog.arch.name != self.db["arch"]:
            self.skipTest("architecture differs")
        self.assertEqual(signatures.match(prog, self.db)["matches"], [])


if __name__ == "__main__":
    unittest.main()
