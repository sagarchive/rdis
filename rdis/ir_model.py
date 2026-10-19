"""Typed, provenance-preserving IR contract for RDIS frontends.

The current decompiler consumes P-code-shaped tuples directly. This module provides the next
boundary: validated operations with explicit widths, signedness, effects and original instruction
addresses. It deliberately does not claim to replace an architecture semantics frontend; correctness
still depends on the frontend lowering each machine instruction faithfully.
"""
from dataclasses import dataclass
import json


_KINDS = {"int", "float", "bool", "pointer", "control", "unknown"}
_SIGNEDNESS = {"signed", "unsigned", "signless", "unknown"}
_EFFECTS = {
    "LOAD": ("memory_read",),
    "STORE": ("memory_write",),
    "CALL": ("call", "memory_read", "memory_write"),
    "CALLIND": ("call", "memory_read", "memory_write"),
    "RETURN": ("control",),
    "BRANCH": ("control",),
    "CBRANCH": ("control",),
    "BRANCHIND": ("control", "indirect"),
    "CALLOTHER": ("intrinsic",),
    "ASM": ("unknown",),
}

_BINARY = {
    "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
    "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
    "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_AND",
    "BOOL_OR", "BOOL_XOR", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV",
    "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
}
_UNARY = {
    "INT_2COMP", "INT_NEGATE", "INT_ZEXT", "INT_SEXT", "INT_NEGATE", "BOOL_NEGATE",
    "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_TRUNC", "FLOAT_CEIL", "FLOAT_FLOOR",
    "FLOAT_ROUND", "FLOAT_NAN", "POPCOUNT", "LZCOUNT", "INT2FLOAT", "FLOAT2FLOAT", "FLOAT2INT",
}
_COMPARISONS = {
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
    "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "BOOL_AND", "BOOL_OR", "BOOL_XOR", "BOOL_NEGATE", "FLOAT_EQUAL",
    "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
}
_SIGNED_OPS = {"INT_SDIV", "INT_SREM", "INT_SRIGHT", "INT_SLESS", "INT_SLESSEQUAL", "INT_SBORROW", "INT_SCARRY"}
_UNSIGNED_OPS = {"INT_DIV", "INT_REM", "INT_RIGHT", "INT_LESS", "INT_LESSEQUAL"}


@dataclass(frozen=True)
class IRType:
    """A machine-independent scalar type. Width is in bits; zero means not established."""

    kind: str = "unknown"
    bits: int = 0
    signedness: str = "unknown"
    address_space: str = ""

    def __post_init__(self):
        if self.kind not in _KINDS:
            raise ValueError("unsupported IR type kind: " + self.kind)
        if self.signedness not in _SIGNEDNESS:
            raise ValueError("unsupported signedness: " + self.signedness)
        if self.bits < 0 or self.bits > 4096:
            raise ValueError("IR bit width must be between 0 and 4096")

    def to_dict(self):
        return {"kind": self.kind, "bits": self.bits, "signedness": self.signedness,
                "address_space": self.address_space}


@dataclass(frozen=True)
class Varnode:
    """A typed storage/value reference from a frontend, retaining its original storage class."""

    kind: str
    size: int = 0                     # source representation uses bytes
    name: str = ""
    value: object = None
    address_space: str = ""

    def __post_init__(self):
        if self.size < 0 or self.size > 512:
            raise ValueError("varnode size must be between 0 and 512 bytes")
        if self.kind not in {"register", "constant", "temporary", "address", "opaque"}:
            raise ValueError("unsupported varnode kind: " + self.kind)

    @classmethod
    def from_frontend(cls, node):
        if not isinstance(node, tuple) or not node:
            return cls("opaque", name=repr(node))
        kind = node[0]
        if kind == "reg" and len(node) >= 3:
            return cls("register", int(node[2]), name=str(node[1]), address_space="register")
        if kind == "const" and len(node) >= 3:
            return cls("constant", int(node[2]), value=node[1], address_space="constant")
        if kind == "tmp" and len(node) >= 3:
            return cls("temporary", int(node[2]), name=repr(node[1]), value=node[1], address_space="unique")
        if kind == "ram" and len(node) >= 3:
            return cls("address", int(node[2]), value=node[1], address_space="ram")
        return cls("opaque", name=repr(node))

    @property
    def type(self):
        if self.kind == "constant" and isinstance(self.value, str):
            return IRType("unknown", self.size * 8, "unknown", self.address_space)
        if self.kind == "address":
            return IRType("pointer", self.size * 8, "unsigned", self.address_space)
        if self.kind == "register" and self.name.lower().startswith(("f", "v")):
            # Register naming is only a hint; operation semantics may refine this to float/vector.
            return IRType("unknown", self.size * 8, "unknown", self.address_space)
        if self.kind == "constant":
            return IRType("int", self.size * 8, "signless", self.address_space)
        return IRType("unknown", self.size * 8, "unknown", self.address_space)

    def to_dict(self):
        value = self.value
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, (str, int, float, bool)) or value is None:
            pass
        else:
            value = repr(value)
        return {"kind": self.kind, "size": self.size, "name": self.name, "value": value,
                "address_space": self.address_space}


@dataclass(frozen=True)
class OpSpec:
    minimum_inputs: int
    maximum_inputs: int
    output: str = "required"   # required, forbidden, optional
    effects: tuple = ()


def _spec(opcode):
    if opcode in {"COPY", "LOAD"}:
        return OpSpec(1, 1, "required", _EFFECTS.get(opcode, ()))
    if opcode == "STORE":
        return OpSpec(2, 2, "forbidden", _EFFECTS[opcode])
    if opcode in {"BRANCH", "BRANCHIND"}:
        return OpSpec(1, 1, "forbidden", _EFFECTS[opcode])
    if opcode == "CBRANCH":
        return OpSpec(2, 2, "forbidden", _EFFECTS[opcode])
    if opcode in {"CALL", "CALLIND"}:
        return OpSpec(1, 1, "forbidden", _EFFECTS[opcode])
    if opcode == "RETURN":
        return OpSpec(0, 1, "forbidden", _EFFECTS[opcode])
    if opcode == "CALLOTHER":
        return OpSpec(1, 64, "optional", _EFFECTS[opcode])
    if opcode in _BINARY:
        return OpSpec(2, 2, "required")
    if opcode in _UNARY:
        return OpSpec(1, 1, "required")
    if opcode in {"PIECE", "SUBPIECE"}:
        return OpSpec(2, 2, "required")
    if opcode == "PTRADD":
        return OpSpec(3, 3, "required")
    if opcode == "PTRSUB":
        return OpSpec(2, 2, "required")
    if opcode == "CAST":
        return OpSpec(1, 1, "required")
    if opcode == "SEGMENTOP":
        return OpSpec(2, 2, "required")
    if opcode == "INSERT":
        return OpSpec(4, 4, "required")
    if opcode == "EXTRACT":
        return OpSpec(3, 3, "required")
    if opcode == "MULTIEQUAL":
        return OpSpec(1, 256, "required")
    if opcode == "INDIRECT":
        return OpSpec(2, 2, "required")
    if opcode == "CPOOLREF":
        return OpSpec(1, 64, "required")
    if opcode in {"NEW", "INSERT", "EXTRACT"}:
        return OpSpec(2, 4, "required")
    if opcode in {"IMARK", "UNIMPLEMENTED"}:
        return OpSpec(0, 64, "optional", ("metadata",))
    if opcode == "ASM":
        return OpSpec(0, 64, "forbidden", _EFFECTS[opcode])
    return None


@dataclass(frozen=True)
class IRInstruction:
    """One lowered semantic operation, with the source machine instruction as provenance."""

    source_address: int
    sequence: int
    opcode: str
    output: object = None              # Varnode | None
    inputs: tuple = ()
    result_type: IRType = IRType()
    effects: tuple = ()
    # source_address is the translation anchor; exactness is explicit because some frontends
    # bundle delay-slot semantics and do not expose the originating instruction for every op.
    source_address_exact: bool = True
    source_candidates: tuple = ()

    @classmethod
    def from_frontend(cls, address, sequence, opcode, output, inputs, *,
                      source_address_exact=True, source_candidates=()):
        out = Varnode.from_frontend(output) if output is not None else None
        ins = tuple(Varnode.from_frontend(v) for v in inputs)
        if opcode in _COMPARISONS or opcode == "FLOAT_NAN":
            typ = IRType("bool", 1, "unsigned")
        elif opcode in {"PTRADD", "PTRSUB"}:
            typ = IRType("pointer", out.size * 8 if out else 0, "unsigned",
                         out.address_space if out else "")
        elif opcode.startswith("FLOAT_") or opcode in {"INT2FLOAT", "FLOAT2FLOAT"}:
            typ = IRType("float", out.size * 8 if out else 0, "signless")
        elif opcode in _SIGNED_OPS:
            typ = IRType("int", out.size * 8 if out else 0, "signed")
        elif opcode in _UNSIGNED_OPS:
            typ = IRType("int", out.size * 8 if out else 0, "unsigned")
        elif out is not None and out.kind == "address":
            typ = IRType("pointer", out.size * 8, "unsigned", out.address_space)
        elif out is not None:
            typ = IRType("int", out.size * 8, "signless")
        else:
            typ = IRType("control" if opcode in {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN", "CALL", "CALLIND"} else "unknown")
        spec = _spec(opcode)
        effects = spec.effects if spec is not None else ("unknown",)
        candidates = tuple(dict.fromkeys(int(a) for a in source_candidates))
        return cls(int(address), int(sequence), str(opcode), out, ins, typ, tuple(effects),
                   bool(source_address_exact), candidates)

    def validate(self):
        problems = []
        if self.source_address < 0:
            problems.append("source address cannot be negative")
        if self.sequence < 0:
            problems.append("operation sequence cannot be negative")
        if not isinstance(self.source_address_exact, bool):
            problems.append("source-address exactness must be boolean")
        if any(not isinstance(a, int) or isinstance(a, bool) or a < 0 for a in self.source_candidates):
            problems.append("source-address candidates must be non-negative integers")
        if not self.source_address_exact and not self.source_candidates:
            problems.append("inexact source address must retain at least one candidate")
        spec = _spec(self.opcode)
        if spec is None:
            problems.append(f"unsupported opcode: {self.opcode}")
            return tuple(problems)
        n = len(self.inputs)
        if not spec.minimum_inputs <= n <= spec.maximum_inputs:
            problems.append(f"{self.opcode} expects {spec.minimum_inputs}..{spec.maximum_inputs} inputs, got {n}")
        if spec.output == "required" and self.output is None:
            problems.append(f"{self.opcode} requires an output")
        if spec.output == "forbidden" and self.output is not None:
            problems.append(f"{self.opcode} must not have an output")
        if self.output is not None and self.output.size == 0 and self.opcode not in {"CALLOTHER", "UNIMPLEMENTED"}:
            problems.append(f"{self.opcode} has a zero-width output")
        return tuple(problems)

    def to_dict(self):
        return {"source_address": self.source_address, "source_address_exact": self.source_address_exact,
                "source_candidates": list(self.source_candidates), "sequence": self.sequence,
                "opcode": self.opcode, "output": self.output.to_dict() if self.output else None,
                "inputs": [v.to_dict() for v in self.inputs], "result_type": self.result_type.to_dict(),
                "effects": list(self.effects)}


@dataclass(frozen=True)
class IRBlock:
    address: int
    instructions: tuple
    successors: tuple = ()

    def to_dict(self):
        return {"address": self.address, "successors": list(self.successors),
                "instructions": [op.to_dict() for op in self.instructions]}


@dataclass(frozen=True)
class IRFunction:
    architecture: str
    entry: int
    blocks: tuple

    def validate(self):
        problems = []
        addresses = [b.address for b in self.blocks]
        if len(addresses) != len(set(addresses)):
            problems.append("duplicate basic-block address")
        if self.entry not in set(addresses):
            problems.append("entry address does not identify a basic block")
        known = set(addresses)
        for block in self.blocks:
            for successor in block.successors:
                if successor not in known:
                    problems.append(f"block {block.address:#x} references missing successor {successor:#x}")
            for op in block.instructions:
                problems.extend(f"{op.source_address:#x}:{op.sequence}: {issue}" for issue in op.validate())
        return tuple(problems)

    def to_dict(self):
        return {"schema_version": 2, "architecture": self.architecture, "entry": self.entry,
                "blocks": [b.to_dict() for b in sorted(self.blocks, key=lambda b: b.address)]}

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_function_ir(prog, func, frontend=None):
    """Lower one analyzed function to typed, provenance-preserving operations.

    This is intentionally a parallel IR contract for audits and downstream passes. It does not alter
    the established decompiler output until callers explicitly opt into an IR pass.
    """
    if frontend is None:
        from . import ir_front
        frontend = ir_front.frontend(prog.arch)
    if frontend is None:
        raise ValueError(f"no IR frontend available for {getattr(prog.arch, 'name', 'unknown architecture')}")
    thumb_insns = getattr(prog, "_insns", {})
    blocks = []
    for addr, block in sorted(func.blocks.items()):
        covered = set()
        lowered = []
        source_sequences = {}
        # MIPS and other delayed-control-flow architectures keep the delay-slot instruction
        # separately from the block's main instruction list. Preserve it unless the frontend
        # explicitly reports that its translated sequence already covers that source address.
        source_insns = getattr(block, "shown", None)
        if source_insns is None:
            source_insns = list(block.insns)
            delay = getattr(block, "delay", None)
            if delay is not None:
                source_insns.append(delay)
        for insn in source_insns:
            if insn.address in covered:
                continue
            thumb = getattr(prog.arch, "name", "") == "arm" and thumb_insns.get((insn.address, True)) is insn
            code = prog.image.read(insn.address, 16)
            detailed = getattr(frontend, "translate_with_provenance", None)
            if callable(detailed):
                result = detailed(code, insn.address, thumb)
                if len(result) == 3:
                    raw_ops, consumed, op_addresses = result
                else:
                    raise ValueError("translate_with_provenance must return (ops, consumed, op_addresses)")
                exact_by_op = [address is not None for address in op_addresses]
            else:
                raw_ops, consumed = frontend.translate(code, insn.address, thumb)
                op_addresses = [insn.address] * len(raw_ops or ())
                exact_by_op = [True] * len(op_addresses)
            consumed = tuple(dict.fromkeys(int(a) for a in (consumed or ()) if isinstance(a, int) and not isinstance(a, bool)))
            covered.update(a for a in consumed if a != insn.address)
            if raw_ops is None:
                raw_ops = [("ASM", None, [f"{insn.mnemonic} {insn.op_str}".strip()])]
                op_addresses, exact_by_op = [insn.address], [True]
            # P-code/native frontends may emit several operations for one source instruction or a
            # bundle of instructions. Sequence numbers are per source address, never per bundle.
            for index, item in enumerate(raw_ops):
                raw_address = op_addresses[index] if index < len(op_addresses) else insn.address
                source_exact = index < len(exact_by_op) and exact_by_op[index] and raw_address is not None
                source_address = int(raw_address) if raw_address is not None else int(insn.address)
                candidates = () if source_exact else tuple(consumed or (insn.address,))
                sequence = source_sequences.get(source_address, 0)
                source_sequences[source_address] = sequence + 1
                if len(item) != 3:
                    lowered.append(IRInstruction.from_frontend(
                        source_address, sequence, "UNIMPLEMENTED", None, (),
                        source_address_exact=source_exact, source_candidates=candidates))
                    continue
                opcode, output, inputs = item
                lowered.append(IRInstruction.from_frontend(
                    source_address, sequence, opcode, output, tuple(inputs or ()),
                    source_address_exact=source_exact, source_candidates=candidates))
        blocks.append(IRBlock(int(addr), tuple(lowered), tuple(block.succs)))
    return IRFunction(str(getattr(prog.arch, "name", "unknown")), int(func.addr), tuple(blocks))
