"""Bounded P-code interpreter: run a function on concrete arguments, on any CPU a SLEIGH spec describes.

Semantics come from the spec's own P-code, so one interpreter covers every architecture. Anything it
cannot model (an unimplemented operation, a CALLOTHER intrinsic, memory that is neither mapped nor
stack) raises EmulationError naming the cause; it never returns a guessed value. Execution is bounded
by an instruction budget.
"""
import math
import struct
from dataclasses import dataclass

try:
    import pypcode
except ImportError:
    pypcode = None

from . import ir_front, sleigh

PAGE = 4096
STACK_SIZE = 1 << 20
SENTINEL = 0xDEADBEEF00

LINK = {"arm64": "x30", "arm": "lr", "riscv64": "ra", "riscv32": "ra", "mips": "ra", "mipsel": "ra",
        "mips64": "ra", "mips64el": "ra", "ppc": "LR", "ppcle": "LR", "ppc64": "LR", "ppc64le": "LR",
        "loongarch64": "ra", "xtensa": "a0", "xtensabe": "a0", "sparc": "o7", "sparc64": "o7"}
STACK_RETURN = {"x86", "x86_64", "m68k", "avr8", "msp430", "z80", "6502"}
ABI = {"x86_64": (["RDI", "RSI", "RDX", "RCX", "R8", "R9"], "RAX", "RSP"),
       "arm64": ([f"x{n}" for n in range(8)], "x0", "sp"),
       "riscv64": ([f"a{n}" for n in range(8)], "a0", "sp"),
       "riscv32": ([f"a{n}" for n in range(8)], "a0", "sp"),
       "mips": ([f"a{n}" for n in range(4)], "v0", "sp"), "mipsel": ([f"a{n}" for n in range(4)], "v0", "sp"),
       "arm": (["r0", "r1", "r2", "r3"], "r0", "sp")}


class EmulationError(Exception):
    pass


@dataclass
class Result:
    value: int
    steps: int


def _mask(v, size):
    return v & ((1 << (8 * size)) - 1)


def _signed(v, size):
    v = _mask(v, size)
    return v - (1 << (8 * size)) if v >> (8 * size - 1) else v


def _float(v, size):
    if size == 4:
        return struct.unpack("<f", struct.pack("<I", _mask(v, 4)))[0]
    if size == 8:
        return struct.unpack("<d", struct.pack("<Q", _mask(v, 8)))[0]
    raise EmulationError(f"unsupported float size {size}")


def _bits(f, size):
    try:
        if size == 4:
            return struct.unpack("<I", struct.pack("<f", f))[0]
        return struct.unpack("<Q", struct.pack("<d", f))[0]
    except OverflowError:
        return _bits(math.copysign(math.inf, f), size)


class _Sparse:
    """Byte store addressed by offset. Sparse on purpose: a fixed array silently misplaces writes
    past its end, and register and scratch offsets in a SLEIGH spec can be large."""

    def __init__(self):
        self.cells = {}

    def get(self, offset, size):
        return int.from_bytes(bytes(self.cells.get(offset + i, 0) for i in range(size)), "little")

    def put(self, offset, size, value):
        for i, byte in enumerate(_mask(value, size).to_bytes(size, "little")):
            self.cells[offset + i] = byte


class Machine:
    def __init__(self, prog, max_steps=1_000_000):
        if pypcode is None:
            raise EmulationError("the emulator needs pypcode (pip install 'rdis[ir]')")
        lang = ir_front._lang(prog.arch, False)
        if lang is None:
            raise EmulationError(f"no SLEIGH language for {prog.arch.name}")
        self.prog, self.max_steps, self.lang = prog, max_steps, lang
        self.ctx = pypcode.Context(lang)
        self.regs = {name: v for name, v in self.ctx.registers.items()}
        self.reg_bytes, self.uniq = _Sparse(), _Sparse()
        self.pages, self.mapped = {}, []
        self.width = prog.arch.bits // 8
        self.stack_top = (0x7FFE00000000 if self.width == 8 else 0x7F000000) + STACK_SIZE
        self.stack = (self.stack_top - STACK_SIZE, self.stack_top)

    def reg_name(self, name):
        for cand in (name, name.upper(), name.lower()):
            if cand in self.regs:
                return self.regs[cand]
        raise EmulationError(f"unknown register {name!r}")

    def set_reg(self, name, value):
        v = self.reg_name(name)
        self.reg_bytes.put(v.offset, v.size, value)

    def get_reg(self, name):
        v = self.reg_name(name)
        return self.reg_bytes.get(v.offset, v.size)

    def map(self, addr, data):
        self.mapped.append((addr, addr + len(data)))
        self.write(addr, bytes(data))

    def _in_stack(self, a):
        return self.stack[0] <= a < self.stack[1]

    def _in_mapped(self, a):
        return any(lo <= a < hi for lo, hi in self.mapped)

    def _in_image(self, a):
        return any(s.va <= a < s.va + s.size for s in self.prog.image.sections)

    def _page(self, addr):
        base = addr - addr % PAGE
        page = self.pages.get(base)
        if page is None:
            if not (self._in_stack(addr) or self._in_mapped(addr) or self._in_image(addr)):
                raise EmulationError(f"access to unmapped memory at {addr:#x}")
            page = self.pages[base] = bytearray(PAGE)
            for s in self.prog.image.sections:
                lo, hi = max(s.va, base), min(s.va + s.size, base + PAGE)
                if lo < hi:
                    page[lo - base:hi - base] = self.prog.image.read(lo, hi - lo).ljust(hi - lo, b"\0")
        return page

    def read(self, addr, n):
        return bytes(self._page(a)[a % PAGE] for a in range(addr, addr + n))

    def write(self, addr, data):
        for i, byte in enumerate(data):
            a = addr + i
            self._page(a)[a % PAGE] = byte

    def value(self, v):
        n = v.space.name
        if n == "const":
            return _mask(v.offset, v.size)
        if n == "register":
            return self.reg_bytes.get(v.offset, v.size)
        if n == "unique":
            return self.uniq.get(v.offset, v.size)
        return int.from_bytes(self.read(v.offset, v.size), "little")

    def store(self, v, value):
        n = v.space.name
        if n == "register":
            self.reg_bytes.put(v.offset, v.size, value)
        elif n == "unique":
            self.uniq.put(v.offset, v.size, value)
        else:
            self.write(v.offset, _mask(value, v.size).to_bytes(v.size, "little"))

    def setup(self, args):
        abi = ABI.get(self.prog.arch.name) or (self.prog.arch.args, self.prog.arch.ret, self.prog.arch.sp)
        arg_regs, _, sp = abi
        if len(args) > len(arg_regs):
            raise EmulationError(f"{self.prog.arch.name}: at most {len(arg_regs)} register arguments")
        top = self.stack_top - 64
        self.set_reg(sp, top)
        for reg, value in zip(arg_regs, args):
            self.set_reg(reg, value)
        if self.prog.arch.name in STACK_RETURN:
            top -= self.width
            self.write(top, _mask(SENTINEL, self.width).to_bytes(self.width, "little"))
            self.set_reg(sp, top)
        elif self.prog.arch.name in LINK:
            self.set_reg(LINK[self.prog.arch.name], SENTINEL)
        else:
            raise EmulationError(f"no link register known for {self.prog.arch.name}")

    def run(self, entry, args, memory=()):
        for addr, data in memory:
            self.map(addr, data)
        self.setup(args)
        pc, steps = entry, 0
        while pc != _mask(SENTINEL, self.width):
            if steps >= self.max_steps:
                raise EmulationError(f"instruction budget of {self.max_steps} exhausted at {pc:#x}")
            pc = self.step(pc)
            steps += 1
        abi = ABI.get(self.prog.arch.name) or (None, self.prog.arch.ret, None)
        return Result(self.get_reg(abi[1]), steps)

    def step(self, pc):
        code = self.prog.image.read(pc, 16)
        if not code:
            raise EmulationError(f"execution reached unmapped address {pc:#x}")
        try:
            ops = sleigh.safe_translate(self.ctx, self.lang, code, pc, max_instructions=1).ops
        except Exception as e:
            raise EmulationError(f"cannot translate instruction at {pc:#x}: {e}") from None
        fall, i = pc, 0
        while i < len(ops):
            op = ops[i]
            name = op.opcode.name
            if name == "IMARK":
                last = op.inputs[-1]
                fall = last.offset + last.size
                i += 1
                continue
            jump = self.execute(name, op)
            if jump is None:
                i += 1
            elif jump[0] == "rel":
                i += jump[1]
            else:
                return _mask(jump[1], self.width)
        return fall

    def execute(self, name, op):
        ins, out = op.inputs, op.output
        v = [self.value(x) for x in ins] if name not in ("LOAD", "STORE", "BRANCH", "CBRANCH", "CALL") else None
        if name == "BRANCH":
            return self._target(ins[0])
        if name == "CBRANCH":
            return self._target(ins[0]) if self.value(ins[1]) & 1 else None
        if name == "CALL":
            return self._target(ins[0])
        if name in ("BRANCHIND", "CALLIND", "RETURN"):
            return ("abs", v[0])
        if name == "LOAD":
            addr = self.value(ins[1])
            self.store(out, int.from_bytes(self.read(addr, out.size), "little"))
            return None
        if name == "STORE":
            self.write(self.value(ins[1]), _mask(self.value(ins[2]), ins[2].size).to_bytes(ins[2].size, "little"))
            return None
        if name == "CALLOTHER":
            raise EmulationError(f"unsupported intrinsic {op}")
        handler = _OPS.get(name)
        if handler is None:
            raise EmulationError(f"unsupported P-code operation {name}")
        self.store(out, handler(v, ins, out.size))
        return None

    @staticmethod
    def _target(vn):
        if vn.space.name == "const":
            return ("rel", _signed(vn.offset, vn.size))
        return ("abs", vn.offset)


def _div(f):
    def op(v, ins, out):
        if v[1] == 0:
            raise EmulationError("division by zero")
        return f(v, ins)
    return op


def _sdiv(v, ins):
    a, b = _signed(v[0], ins[0].size), _signed(v[1], ins[1].size)
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _srem(v, ins):
    a, b = _signed(v[0], ins[0].size), _signed(v[1], ins[1].size)
    return a - _sdiv(v, ins) * b


def _fbin(f):
    return lambda v, ins, out: _bits(f(_float(v[0], ins[0].size), _float(v[1], ins[1].size)), out)


def _fun(f):
    return lambda v, ins, out: _bits(f(_float(v[0], ins[0].size)), out)


def _fdiv(a, b):
    if b == 0:
        return math.copysign(math.inf, a) if a else math.nan
    return a / b


_OPS = {
    "COPY": lambda v, i, o: v[0],
    "INT_ZEXT": lambda v, i, o: v[0],
    "INT_SEXT": lambda v, i, o: _signed(v[0], i[0].size),
    "INT_ADD": lambda v, i, o: v[0] + v[1],
    "INT_SUB": lambda v, i, o: v[0] - v[1],
    "INT_MULT": lambda v, i, o: v[0] * v[1],
    "INT_2COMP": lambda v, i, o: -v[0],
    "INT_NEGATE": lambda v, i, o: ~v[0],
    "INT_AND": lambda v, i, o: v[0] & v[1],
    "INT_OR": lambda v, i, o: v[0] | v[1],
    "INT_XOR": lambda v, i, o: v[0] ^ v[1],
    "INT_LEFT": lambda v, i, o: 0 if v[1] >= 8 * o else v[0] << v[1],
    "INT_RIGHT": lambda v, i, o: 0 if v[1] >= 8 * i[0].size else v[0] >> v[1],
    "INT_SRIGHT": lambda v, i, o: (-1 if _signed(v[0], i[0].size) < 0 else 0) if v[1] >= 8 * i[0].size
    else _signed(v[0], i[0].size) >> v[1],
    "INT_EQUAL": lambda v, i, o: int(v[0] == v[1]),
    "INT_NOTEQUAL": lambda v, i, o: int(v[0] != v[1]),
    "INT_LESS": lambda v, i, o: int(v[0] < v[1]),
    "INT_LESSEQUAL": lambda v, i, o: int(v[0] <= v[1]),
    "INT_SLESS": lambda v, i, o: int(_signed(v[0], i[0].size) < _signed(v[1], i[1].size)),
    "INT_SLESSEQUAL": lambda v, i, o: int(_signed(v[0], i[0].size) <= _signed(v[1], i[1].size)),
    "INT_CARRY": lambda v, i, o: int(v[0] + v[1] >= 1 << (8 * i[0].size)),
    "INT_SCARRY": lambda v, i, o: int(not -(1 << (8 * i[0].size - 1)) <= _signed(v[0], i[0].size)
                                      + _signed(v[1], i[1].size) < 1 << (8 * i[0].size - 1)),
    "INT_SBORROW": lambda v, i, o: int(not -(1 << (8 * i[0].size - 1)) <= _signed(v[0], i[0].size)
                                       - _signed(v[1], i[1].size) < 1 << (8 * i[0].size - 1)),
    "INT_DIV": _div(lambda v, i: v[0] // v[1]),
    "INT_REM": _div(lambda v, i: v[0] % v[1]),
    "INT_SDIV": _div(_sdiv),
    "INT_SREM": _div(_srem),
    "BOOL_NEGATE": lambda v, i, o: v[0] ^ 1,
    "BOOL_AND": lambda v, i, o: v[0] & v[1],
    "BOOL_OR": lambda v, i, o: v[0] | v[1],
    "BOOL_XOR": lambda v, i, o: v[0] ^ v[1],
    "PIECE": lambda v, i, o: (v[0] << (8 * i[1].size)) | v[1],
    "SUBPIECE": lambda v, i, o: v[0] >> (8 * v[1]),
    "POPCOUNT": lambda v, i, o: bin(v[0]).count("1"),
    "LZCOUNT": lambda v, i, o: 8 * i[0].size - v[0].bit_length(),
    "PTRADD": lambda v, i, o: v[0] + v[1] * v[2],
    "PTRSUB": lambda v, i, o: v[0] + v[1],
    "FLOAT_ADD": _fbin(lambda a, b: a + b),
    "FLOAT_SUB": _fbin(lambda a, b: a - b),
    "FLOAT_MULT": _fbin(lambda a, b: a * b),
    "FLOAT_DIV": _fbin(_fdiv),
    "FLOAT_NEG": _fun(lambda a: -a),
    "FLOAT_ABS": _fun(abs),
    "FLOAT_SQRT": _fun(lambda a: math.sqrt(a) if a >= 0 else math.nan),
    "FLOAT_CEIL": _fun(lambda a: float(math.ceil(a)) if math.isfinite(a) else a),
    "FLOAT_FLOOR": _fun(lambda a: float(math.floor(a)) if math.isfinite(a) else a),
    "FLOAT_EQUAL": lambda v, i, o: int(_float(v[0], i[0].size) == _float(v[1], i[1].size)),
    "FLOAT_NOTEQUAL": lambda v, i, o: int(_float(v[0], i[0].size) != _float(v[1], i[1].size)),
    "FLOAT_LESS": lambda v, i, o: int(_float(v[0], i[0].size) < _float(v[1], i[1].size)),
    "FLOAT_LESSEQUAL": lambda v, i, o: int(_float(v[0], i[0].size) <= _float(v[1], i[1].size)),
    "FLOAT_NAN": lambda v, i, o: int(math.isnan(_float(v[0], i[0].size))),
    "FLOAT_INT2FLOAT": lambda v, i, o: _bits(float(_signed(v[0], i[0].size)), o),
    "FLOAT_FLOAT2FLOAT": lambda v, i, o: _bits(_float(v[0], i[0].size), o),
    "FLOAT_TRUNC": lambda v, i, o: int(_float(v[0], i[0].size)),
}


def emulate(prog, entry, args, memory=(), max_steps=1_000_000):
    """Call the function at `entry` with integer `args`; `memory` is [(address, bytes)] mapped for the call."""
    return Machine(prog, max_steps).run(entry, list(args), memory)
