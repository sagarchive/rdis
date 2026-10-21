"""Address-independent function fingerprints, shared by binary diffing and signature matching."""
import hashlib
import re
from dataclasses import dataclass

from .arch import CALL

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{3,}")
_NOPS = {"nop", "nop.w", "c.nop", "fnop", "data16", "cs"}


def is_generated(name):
    return not name or name.startswith(("sub_", "loc_"))


def function_insns(func):
    out = []
    for addr in sorted(func.blocks):
        out += func.blocks[addr].shown
    return out


def normalize(insn):
    """Mnemonic plus operands with address-sized constants masked, so relocation and layout changes do not alter it."""
    return f"{insn.mnemonic} {_ADDRESS.sub('K', insn.op_str)}"


@dataclass(frozen=True)
class Features:
    addr: int
    name: str
    size: int
    nblocks: int
    shape: tuple
    exact: str
    mnemonics: str
    grams: frozenset
    strings: frozenset
    callees: tuple


def _digest(text):
    return hashlib.sha1(text.encode()).hexdigest()[:20]


def features(prog, func):
    ins = function_insns(func)
    mnemonics = [i.mnemonic for i in ins if i.mnemonic not in _NOPS]
    blocks = [func.blocks[a] for a in sorted(func.blocks)]
    strings, callees = set(), []
    table = prog.strings()
    for block in blocks:
        regs = {}
        for i in block.shown:
            for ref in prog.arch.data_refs(i, regs):
                if ref in table:
                    strings.add(table[ref])
            if prog.arch.kind(i) == CALL:
                callees.append(prog.call_target(i, {}))
    grams = frozenset(zip(mnemonics, mnemonics[1:], mnemonics[2:])) or frozenset([tuple(mnemonics)])
    shape = (len(blocks), sum(len(b.succs) for b in blocks), tuple(len(b.succs) for b in blocks))
    name = prog.display(func.addr) or ""
    return Features(func.addr, "" if is_generated(name) else name, len(ins), len(blocks), shape,
                    _digest("\n".join(normalize(i) for i in ins)), _digest(" ".join(mnemonics)),
                    grams, frozenset(strings), tuple(callees))


def similarity(a, b):
    """Jaccard overlap of mnemonic trigrams, scaled by how close the two sizes are."""
    if not a.grams or not b.grams:
        return 0.0
    overlap = len(a.grams & b.grams) / len(a.grams | b.grams)
    return overlap * min(a.size, b.size) / max(a.size, b.size)
