import json
import unittest

from rdis.analysis import Program
from rdis.arch import make
from rdis.loader import Image, Section

BASE, TABLE = 0x1000, 0x2000


def _x86(code, table=b""):
    sections = [Section(".text", BASE, len(code), 0, True)]
    if table:
        sections.append(Section(".rodata", TABLE, len(table), 0, False))

    def read(va, n):
        for s, blob in ((sections[0], code), (sections[-1], table)):
            if s.va <= va < s.va + len(blob):
                return blob[va - s.va:va - s.va + n]
        return b""

    return Image("<fixture>", "raw", make("x86_64"), BASE, BASE, sections, {}, {}, read, lambda va: None)


def _arm64(words):
    code = b"".join(w.to_bytes(4, "little") for w in words)
    return Image("<fixture>", "raw", make("arm64"), BASE, BASE, [Section(".text", BASE, len(code), 0, True)],
                 {}, {}, lambda va, n: code[va - BASE:va - BASE + n] if BASE <= va < BASE + len(code) else b"",
                 lambda va: None)


def _edges(func):
    return {(b.addr, s) for b in func.blocks.values() for s in b.succs}


def _metrics(expected, observed):
    tp = len(expected & observed)
    p = tp / len(observed) if observed else 1.0
    r = tp / len(expected) if expected else 1.0
    return {"precision": round(p, 4), "recall": round(r, 4), "false_positives": sorted(observed - expected)}


CASES = [0x1015, 0x101b, 0x1021, 0x1027]


def dispatcher(bounded):
    """cmp edi,3 / ja default / lea rcx,[rip+table] / movsxd rax,[rcx+rdi*4] / add rax,rcx / jmp rax,
    then four `mov eax,imm; ret` cases and a default. Unbounded replaces cmp+ja with nops."""
    guard = bytes.fromhex("83ff03" "7728") if bounded else b"\x90" * 5
    body = guard + bytes.fromhex("488d0df40f0000" "486304b9" "4801c8" "ffe0")
    for imm in (10, 20, 30, 40):
        body += b"\xb8" + imm.to_bytes(4, "little") + b"\xc3"
    body += bytes.fromhex("31c0c3")
    table = b"".join(((c - TABLE) & 0xFFFFFFFF).to_bytes(4, "little") for c in CASES)
    return body, table


class UnresolvedTransferTests(unittest.TestCase):
    def analyze(self, image):
        return Program(image).analyze(objc=False, swift=False, prologues=False)

    def test_bounded_jump_table_is_resolved_edge_for_edge(self):
        code, table = dispatcher(bounded=True)
        p = self.analyze(_x86(code, table))
        f = p.functions[BASE]
        expected = {(0x1000, 0x102d), (0x1000, 0x1005)} | {(0x1005, c) for c in CASES}
        m = _metrics(expected, _edges(f))
        print("CFG_EDGE_METRIC " + json.dumps({"fixture": "x86-64-bounded-jump-table", **m}, sort_keys=True))
        self.assertEqual(_edges(f), expected)
        self.assertEqual(p.unresolved(), [])

    def test_same_dispatcher_without_a_bound_gets_no_invented_edges(self):
        code, table = dispatcher(bounded=False)
        p = self.analyze(_x86(code, table))
        f = p.functions[BASE]
        self.assertEqual(_edges(f), set())
        self.assertEqual(set(p.functions), {BASE})
        self.assertEqual(p.jump_tables, {})
        rows = p.unresolved()
        self.assertEqual([(r["kind"], r["addr"]) for r in rows], [("jump", 0x1013)])
        self.assertEqual(rows[0]["function"], BASE)

    def test_indirect_jump_through_a_register(self):
        p = self.analyze(_x86(bytes.fromhex("4889f8" "ffe0")))
        self.assertEqual(_edges(p.functions[BASE]), set())
        self.assertEqual([r["kind"] for r in p.unresolved()], ["jump"])

    def test_indirect_call_is_unresolved_but_flow_continues(self):
        p = self.analyze(_x86(bytes.fromhex("ffd0" "c3")))
        f = p.functions[BASE]
        self.assertEqual(f.calls, set())
        self.assertEqual(len(f.blocks), 1)
        self.assertEqual([(r["kind"], r["addr"]) for r in p.unresolved()], [("call", BASE)])

    def test_direct_call_and_ret_are_not_reported(self):
        p = self.analyze(_x86(bytes.fromhex("e801000000" "c3" "c3")))
        self.assertEqual(p.functions[BASE].calls, {0x1006})
        self.assertEqual(p.unresolved(), [])

    def test_aarch64_br_and_blr_register_targets(self):
        blr_x8, br_x9, ret = 0xD63F0100, 0xD61F0120, 0xD65F03C0
        p = self.analyze(_arm64([blr_x8, ret]))
        self.assertEqual([(r["kind"], r["addr"]) for r in p.unresolved()], [("call", BASE)])
        self.assertEqual(p.functions[BASE].calls, set())
        q = self.analyze(_arm64([br_x9]))
        self.assertEqual([(r["kind"], r["addr"]) for r in q.unresolved()], [("jump", BASE)])
        self.assertEqual(_edges(q.functions[BASE]), set())

    def test_mcp_exposes_unresolved_with_hex_addresses(self):
        import os, tempfile
        from rdis.mcp_server import _handle
        code, table = dispatcher(bounded=False)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "blob.bin")
            with open(path, "wb") as fh:
                fh.write(code)
            r = _handle({"method": "tools/call", "params": {"name": "unresolved", "arguments": {
                "path": path, "arch": "x86_64", "loader": "raw", "base": BASE}}})
        self.assertFalse(r.get("isError"), r)
        out = json.loads(r["content"][0]["text"])
        self.assertEqual(out["unresolved"][0]["addr"], "0x1013")


if __name__ == "__main__":
    unittest.main()
