"""arm64 NEON -> compilable, lane-exact C using Clang/GCC vector extensions.

Every vector register holds a `v128` (16 bytes). An instruction views its operands with the lane
type of its arrangement (`.4s` -> `u32x4`, `.16b` -> `u8x16`, `.2d` float -> `f64x2`), applies an
ordinary C operator or a Clang element-wise builtin, and converts back:

    add  v0.4s, v4.4s, v0.4s   ->  v0 = (v128)((u32x4)v4 + (u32x4)v0);
    addv s0, v0.4s             ->  s = __builtin_reduce_add((u32x4)v0);
    umax v1.16b, v1.16b, v2.16b->  v1 = (v128)__builtin_elementwise_max((u8x16)v1, (u8x16)v2);

So vectorized loops decompile to C that compiles and computes the same lanes (verified by the
differential suite), instead of opaque pseudo-intrinsics. 64-bit (`D`) forms zero the upper half,
as the hardware does. Unmodeled instructions return NA and fall back to the intrinsic-style call.
"""
import re

from capstone import arm64 as a64

NA = object()
_VAS = {getattr(a64, n): n[len("ARM64_VAS_"):] for n in dir(a64) if n.startswith("ARM64_VAS_")}
VEC = "(v128)"


def _shape(op):
    """(lane bits, lane count) of a vector operand's arrangement, e.g. 4S -> (32, 4)."""
    m = re.fullmatch(r"(\d+)([BHSDQ])", _VAS.get(op.vas, "") or "")
    if not m:
        m2 = re.fullmatch(r"([BHSDQ])", _VAS.get(op.vas, "") or "")
        if m2:
            return {"B": 8, "H": 16, "S": 32, "D": 64, "Q": 128}[m2.group(1)], 1
        return None
    return {"B": 8, "H": 16, "S": 32, "D": 64, "Q": 128}[m.group(2)], int(m.group(1))


def T(bits, kind="u"):
    """128-bit vector type with `bits`-wide lanes: kind u / i (signed) / f (float)."""
    return f"{kind}{bits}x{128 // bits}"


TYPEDEFS = {**{f"u{b}x{128 // b}": f"uint{b}_t" for b in (8, 16, 32, 64)},
            **{f"i{b}x{128 // b}": f"int{b}_t" for b in (8, 16, 32, 64)},
            "f32x4": "float", "f64x2": "double"}

_POPCOUNT_U8X16_HELPER = """static inline u8x16 rdis_popcount_u8x16(u8x16 x) {
    x = x - ((x >> 1) & (u8x16){85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85});
    x = (x & (u8x16){51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51}) +
        ((x >> 2) & (u8x16){51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51});
    return (x + (x >> 4)) & (u8x16){15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15};
}"""


def preamble(used):
    """Type definitions the lifted vector code needs (emitted once per function)."""
    out = ["typedef uint8_t v128 __attribute__((vector_size(16)));",
           "typedef uint8_t v128u __attribute__((vector_size(16), aligned(1)));   /* unaligned memory */"]
    for t in sorted(used):
        if t in TYPEDEFS:
            out.append(f"typedef {TYPEDEFS[t]} {t} __attribute__((vector_size(16)));")
    return out + [""]


def is_vec(lf, v):
    return isinstance(v, str) and (v.startswith(VEC) or v in getattr(lf, "_vecnames", ()))


def _p(lf, v):
    return v if lf._atomic(v) else f"({v})"


def _view(lf, v, t):
    lf._vtypes.add(t)
    if v in ("0", "0.0"):
        return f"({t}){{0}}"
    if not is_vec(lf, v):      # a scalar in the register (fmov s0, w2): lane 0, upper lanes zero
        return f"({t}){{{v}}}"
    return f"({t}){_p(lf, v)}"


def _lane(lf, v, t, k):
    """Lane `k` of a vector viewed as `t` (parenthesized: subscript binds tighter than a cast)."""
    if not is_vec(lf, v) and v not in ("0", "0.0"):
        return f"({TYPEDEFS[t]}){_p(lf, v)}" if str(k) == "0" else "0"   # scalar: lane 0 only
    return f"({_view(lf, v, t)})[{k}]"


def _out(lf, e, t, lanes, half):
    """Back to v128; a 64-bit (D) arrangement keeps the low half and zeroes the rest."""
    lf._vtypes.add(t)
    if half:
        n = 128 // int(t.split("x")[0][1:])
        idx = ", ".join(str(k) for k in range(n // 2)) + ", " + ", ".join(str(n + k) for k in range(n // 2))
        e = f"__builtin_shufflevector({e}, ({t}){{0}}, {idx})"
    return f"{VEC}({e})"


_SIGNED = {"sshr", "smax", "smin", "smaxv", "sminv", "cmgt", "cmge", "cmlt", "cmle", "sshll",
           "sshll2", "sxtl", "sxtl2", "smull", "smull2", "smlal", "smlal2", "saddlv", "saddlp",
           "scvtf", "sqadd", "sqsub", "abs", "saddw", "saddw2", "sshl", "neg", "fcvtzs"}
_BIN = {"add": "+", "sub": "-", "mul": "*", "and": "&", "orr": "|", "eor": "^",
        "fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}
_CMP = {"cmeq": "==", "cmgt": ">", "cmge": ">=", "cmhi": ">", "cmhs": ">=", "cmtst": None,
        "fcmeq": "==", "fcmgt": ">", "fcmge": ">="}
_EW = {"umax": "max", "smax": "max", "umin": "min", "smin": "min", "fmax": "max", "fmin": "min",
       "fmaxnm": "max", "fminnm": "min", "uqadd": "add_sat", "sqadd": "add_sat", "uqsub": "sub_sat",
       "sqsub": "sub_sat"}
_RED = {"addv": "add", "umaxv": "max", "smaxv": "max", "uminv": "min", "sminv": "min",
        "fmaxv": "max", "fminv": "min", "fmaxnmv": "max", "fminnmv": "min"}


def _kind(m):
    return "f" if m.startswith("f") or m in ("scvtf", "ucvtf") else ("i" if m in _SIGNED else "u")


def lift(lf, i, regs):
    m, ops = i.mnemonic, i.operands
    lf.__dict__.setdefault("_vtypes", set())
    lf.__dict__.setdefault("_vecnames", set())
    if not ops:
        return NA
    o0 = ops[0]
    sh0 = _shape(o0) if o0.type == a64.ARM64_OP_REG else None
    rn0 = i.reg_name(o0.reg) if o0.type == a64.ARM64_OP_REG else ""

    def val(n):
        v = lf._op(ops[n], i, regs)
        o = ops[n]
        if o.type == a64.ARM64_OP_REG and _shape(o) and o.vector_index < 0 and not is_vec(lf, v) \
                and v not in ("0", "0.0"):
            # a scalar living in a vector register (ldr d5 / fmov s0, w2): its own type in lane 0,
            # upper lanes zero, then reinterpreted -- bit-exact, never a numeric conversion
            lv = getattr(lf, "_lastview", {}).get(lf._canon(i.reg_name(o.reg)), "u64x2")
            lf._vtypes.add(lv)
            v = f"{VEC}({lv}){{{v}}}"
        return v

    def assign(e):
        lf._vtypes.add("v128")
        return lf._assign(o0, e, i, regs)

    mem = next((o for o in ops if o.type == a64.ARM64_OP_MEM), None)   # post-index: imm comes last
    if m == "ldr" and rn0.startswith("q") and mem is None and len(ops) == 2 and ops[1].type == a64.ARM64_OP_IMM:
        raw = lf.prog.image.read(ops[1].imm, 16)         # literal-pool vector constant
        if len(raw) == 16:
            lf._vtypes.add("v128")
            return assign(f"{VEC}{{{', '.join(hex(b) for b in raw)}}}")
    # -- 128-bit loads / stores through q registers ------------------------------------
    if m in ("ldr", "ldur", "str", "stur") and rn0.startswith("q") and mem is not None:
        addr = lf._addr(mem, i, regs)
        lf._vtypes.add("v128")
        if m.startswith("ld"):
            return assign(f"{VEC}*(v128u *){_p(lf, addr)}")
        loc = f"*(v128u *){_p(lf, addr)}"
        lf._flush_for_store(loc, regs)
        return f"{loc} = {val(0)};"
    if m in ("ldp", "stp") and rn0.startswith("q") and len(ops) >= 3 and mem is not None:
        base = lf._addr(mem, i, regs)
        hi = lf._bin(f"(char *){_p(lf, base)}", "+", "16")
        lf._vtypes.add("v128")
        if m == "ldp":
            lf._assign(ops[0], f"{VEC}*(v128u *){_p(lf, base)}", i, regs)
            return lf._assign(ops[1], f"{VEC}*(v128u *)({hi})", i, regs)
        a, b = val(0), val(1)
        lf._flush(regs, lambda v: bool(lf._READS_MEM.search(v)))
        return f"*(v128u *){_p(lf, base)} = {a};\n*(v128u *)({hi}) = {b};"
    if m == "fmov" and len(ops) == 2 and ops[1].type == a64.ARM64_OP_REG and rn0[:1] in "wx":
        src = val(1)                                        # fmov w8, s0: lane 0 bits of a vector
        if is_vec(lf, src):
            bits = 32 if rn0[0] == "w" else 64
            t = T(bits, "u")
            lf._vtypes.add(t)
            return lf._assign(o0, _lane(lf, src, t, 0), i, regs)
        return NA
    if sh0 is None and m not in _RED and m not in ("umov", "smov", "faddp", "addp", "uaddlv", "saddlv"):
        if not (m in ("mov", "ins", "dup") and "[" in i.op_str):
            return NA
    # -- scalar results from vectors -----------------------------------------------------
    if m in _RED and len(ops) == 2:
        bits, n = _shape(ops[1])
        t = T(bits, _kind(m))
        lf._vtypes.add(t)
        return lf._assign(o0, f"__builtin_reduce_{_RED[m]}({_view(lf, val(1), t)})", i, regs)
    if m in ("uaddlv", "saddlv") and len(ops) == 2:
        bits, n = _shape(ops[1])
        k = _kind(m)
        src = T(bits, k)
        lf._vtypes.add(src)
        widened = f"__builtin_convertvector({_view(lf, val(1), src)}, {_wtype(lf, bits * 2, k, 128 // bits)})"
        return lf._assign(o0, f"__builtin_reduce_add({widened})", i, regs)
    if m in ("faddp", "addp") and len(ops) == 2:            # scalar pairwise: lane0 + lane1
        bits, n = _shape(ops[1])
        t = T(bits, "f" if m == "faddp" else "u")
        return lf._assign(o0, f"{_lane(lf, val(1), t, 0)} + {_lane(lf, val(1), t, 1)}", i, regs)
    if m in ("umov", "smov", "mov", "dup") and len(ops) == 2 and ops[1].vector_index >= 0 and rn0[:1] in "wxbhsd":
        bits, _ = _shape(ops[1])
        k = "f" if rn0[:1] in "sd" and bits >= 32 else ("i" if m == "smov" else "u")
        t = T(bits, k)                                   # mov s1, v0.s[3]: a float lane
        return lf._assign(o0, f"{_lane(lf, val(1), t, ops[1].vector_index)}", i, regs)
    if m in ("mov", "ins") and len(ops) == 2 and o0.vector_index >= 0:   # insert a lane
        bits, _ = _shape(o0)
        t = T(bits, "u")
        lf._vtypes.add(t)
        src = val(1)
        if ops[1].type == a64.ARM64_OP_REG and ops[1].vector_index >= 0:
            src = f"{_lane(lf, src, T(_shape(ops[1])[0], 'u'), ops[1].vector_index)}"
        return assign(f"{VEC}__ins_{t}({_view(lf, val(0), t)}, {o0.vector_index}, {src})")
    bits, n = sh0 if sh0 else (None, None)
    half = bool(bits) and bits * n == 64
    # -- element-wise ---------------------------------------------------------------------
    if m == "movi" or m == "mvni":
        imm = ops[1].imm if len(ops) > 1 and ops[1].type == a64.ARM64_OP_IMM else 0
        if len(ops) > 1 and ops[1].shift.type == 1:
            imm <<= ops[1].shift.value
        if imm == 0 and m == "movi":
            return assign(f"{VEC}{{0}}")                     # the zero vector
        if bits == 64 and n == 2 and m == "movi":            # 2d form: byte mask immediate
            t = T(64)
            return assign(_out(lf, f"({t}){{0}} + {hex(imm)}ull", t, n, False))
        t = T(bits or 32)
        imm = (~imm) & ((1 << (bits or 32)) - 1) if m == "mvni" else imm
        return assign(_out(lf, f"({t}){{0}} + {hex(imm)}", t, n, half))
    if m == "dup" and len(ops) == 2:
        t = T(bits)
        src = val(1)
        if ops[1].vector_index >= 0:
            src = f"{_lane(lf, src, T(_shape(ops[1])[0]), ops[1].vector_index)}"
        return assign(_out(lf, f"({t}){{0}} + ({TYPEDEFS[t]}){_p(lf, src)}", t, n, half))
    if m == "ld1r" and ops[-1].type == a64.ARM64_OP_MEM:
        t = T(bits)
        addr = lf._addr(ops[-1], i, regs)
        return assign(_out(lf, f"({t}){{0}} + *({TYPEDEFS[t]} *){_p(lf, addr)}", t, n, half))
    if m in ("ld1", "st1") and ops[-1].type == a64.ARM64_OP_MEM and len(ops) == 2:
        addr = lf._addr(ops[-1], i, regs)
        if m == "ld1":
            return assign(f"{VEC}*(v128u *){_p(lf, addr)}")
        lf._vtypes.add("v128")
        return f"*(v128u *){_p(lf, addr)} = {val(0)};"
    if m in _BIN and len(ops) == 3:
        k = _kind(m)
        t = T(bits, k)
        return assign(_out(lf, f"{_view(lf, val(1), t)} {_BIN[m]} {_view(lf, val(2), t)}", t, n, half))
    if m in ("eor3", "bcax") and len(ops) == 4:             # SHA-3: a ^ b ^ c, a ^ (b & ~c)
        t = T(8)
        a, b, c = (_view(lf, val(k), t) for k in (1, 2, 3))
        return assign(_out(lf, f"{a} ^ {b} ^ {c}" if m == "eor3" else f"{a} ^ ({b} & ~{c})", t, 16, False))
    if m in ("bic", "orn") and len(ops) == 3 and ops[2].type == a64.ARM64_OP_REG:
        t = T(bits)
        a, b = _view(lf, val(1), t), _view(lf, val(2), t)
        return assign(_out(lf, f"{a} {'&' if m == 'bic' else '|'} ~{b}", t, n, half))
    if m in ("bic", "orr") and len(ops) == 2 and ops[1].type == a64.ARM64_OP_IMM:   # immediate forms
        t = T(bits)
        imm = ops[1].imm << (ops[1].shift.value if ops[1].shift.type == 1 else 0)
        a = _view(lf, val(0), t)
        return assign(_out(lf, f"{a} {'& ~' if m == 'bic' else '| '}{hex(imm)}", t, n, half))
    if m in ("mla", "mls", "fmla", "fmls") and len(ops) == 3:
        k = _kind(m)
        t = T(bits, k)
        b = val(2)
        bv = (f"{_lane(lf, b, T(_shape(ops[2])[0], k), ops[2].vector_index)}"
              if ops[2].vector_index >= 0 else _view(lf, b, t))
        e = f"{_view(lf, val(0), t)} {'+' if m in ('mla', 'fmla') else '-'} {_view(lf, val(1), t)} * {bv}"
        return assign(_out(lf, e, t, n, half))
    if m in _CMP and len(ops) == 3:
        k = "u" if m in ("cmeq", "cmhi", "cmhs", "cmtst") else ("f" if m[0] == "f" else "i")
        t = T(bits, k)
        a = _view(lf, val(1), t)
        b = _view(lf, val(2), t) if ops[2].type == a64.ARM64_OP_REG else f"({t}){{0}}"
        e = f"({a} & {b}) != 0" if m == "cmtst" else f"{a} {_CMP[m]} {b}"
        return assign(_out(lf, e, T(bits, "i"), n, half))
    if m in _CMP and len(ops) == 2:                         # compare with #0
        k = "f" if m[0] == "f" else "i"
        t = T(bits, k)
        return assign(_out(lf, f"{_view(lf, val(1), t)} {_CMP[m]} ({t}){{0}}", T(bits, "i"), n, half))
    if m in _EW and len(ops) == 3:
        t = T(bits, _kind(m))
        return assign(_out(lf, f"__builtin_elementwise_{_EW[m]}({_view(lf, val(1), t)}, {_view(lf, val(2), t)})",
                           t, n, half))
    if m in ("shl", "ushr", "sshr") and len(ops) == 3 and ops[2].type == a64.ARM64_OP_IMM:
        t = T(bits, "i" if m == "sshr" else "u")
        return assign(_out(lf, f"{_view(lf, val(1), t)} {'<<' if m == 'shl' else '>>'} {ops[2].imm}", t, n, half))
    if m in ("ushl", "sshl") and len(ops) == 3:             # per-lane shift; negative = right
        k = "i" if m == "sshl" else "u"
        t, ts = T(bits, k), T(bits, "i")
        a, s = _view(lf, val(1), t), f"(({ts}){_p(lf, val(2))} << {bits - 8} >> {bits - 8})"
        return assign(_out(lf, f"__vshl_{t}({a}, {s})", t, n, half)) if _helper(lf, f"vshl_{t}") else NA
    if m in ("neg", "fneg", "mvn", "not", "abs", "fabs", "cnt") and len(ops) == 2:
        k = _kind(m)
        t = T(bits, k)
        a = _view(lf, val(1), t)
        if m == "cnt":
            lf.__dict__.setdefault("_vextra", {})["rdis_popcount_u8x16"] = _POPCOUNT_U8X16_HELPER
        e = {"neg": f"-{a}", "fneg": f"-{a}", "mvn": f"~{a}", "not": f"~{a}",
             "abs": f"__builtin_elementwise_abs({a})", "fabs": f"__builtin_elementwise_abs({a})",
             "cnt": f"rdis_popcount_u8x16({a})"}[m]
        return assign(_out(lf, e, t, n, half))
    if m in ("bsl", "bit", "bif") and len(ops) == 3:
        t = T(8)
        d, a, b = _view(lf, val(0), t), _view(lf, val(1), t), _view(lf, val(2), t)
        e = {"bsl": f"({a} & {d}) | ({b} & ~{d})", "bit": f"({a} & {b}) | ({d} & ~{b})",
             "bif": f"({d} & {b}) | ({a} & ~{b})"}[m]
        return assign(_out(lf, e, t, n, half))
    if m in ("mov", "orr") and len(ops) in (2, 3) and "[" not in i.op_str and \
            (len(ops) == 2 or ops[1].reg == ops[2].reg):
        return assign(f"{VEC}{_p(lf, val(1))}" if not is_vec(lf, val(1)) else val(1))
    if m in ("zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2", "ext", "rev64", "rev32", "rev16") and len(ops) >= 2:
        return _permute(lf, m, ops, val, assign, bits, n, half)
    if m in ("ushll", "sshll", "ushll2", "sshll2", "uxtl", "sxtl", "uxtl2", "sxtl2") and len(ops) >= 2:
        sbits, sn = _shape(ops[1])
        k = "i" if m.startswith("s") else "u"
        hi = m.endswith("2")
        src = _half(lf, val(1), T(sbits, k), hi)
        sh = ops[2].imm if len(ops) > 2 and ops[2].type == a64.ARM64_OP_IMM else 0
        t = T(bits, k)
        e = f"__builtin_convertvector({src}, {t})" + (f" << {sh}" if sh else "")
        return assign(_out(lf, e, t, n, False))
    if m in ("xtn", "xtn2") and len(ops) == 2:              # narrow each lane, into the low/high half
        sbits, _ = _shape(ops[1])
        narrow = _wtype(lf, bits, "u", 128 // sbits)
        e = f"__builtin_convertvector({_view(lf, val(1), T(sbits))}, {narrow})"
        t = T(bits)
        if m == "xtn":
            return assign(_out(lf, f"__builtin_shufflevector({e}, ({narrow}){{0}}, "
                               f"{', '.join(str(k) for k in range(128 // sbits * 2))})", t, n, False))
        lo = f"__builtin_shufflevector({_view(lf, val(0), t)}, {_view(lf, val(0), t)}, {', '.join(str(k) for k in range(128 // sbits))})"
        idx = ", ".join(str(k) for k in range(128 // sbits * 2))
        return assign(_out(lf, f"__builtin_shufflevector({lo}, {e}, {idx})", t, n, False))
    if m in ("uaddw", "saddw", "uaddw2", "saddw2", "usubw", "ssubw", "usubw2", "ssubw2") and len(ops) == 3:
        k = "i" if m.startswith("s") else "u"
        sbits, _ = _shape(ops[2])
        t = T(bits, k)
        w = f"__builtin_convertvector({_half(lf, val(2), T(sbits, k), m.endswith('2'))}, {t})"
        return assign(_out(lf, f"{_view(lf, val(1), t)} {'-' if 'sub' in m else '+'} {w}", t, n, False))
    if m in ("umull", "smull", "umull2", "smull2", "umlal", "smlal", "umlal2", "smlal2",
             "umlsl", "smlsl", "umlsl2", "smlsl2") and len(ops) == 3:
        k = "i" if m.startswith("s") else "u"
        sbits, _ = _shape(ops[1])
        hi = m.endswith("2")
        t = T(bits, k)
        a = f"__builtin_convertvector({_half(lf, val(1), T(sbits, k), hi)}, {t})"
        bsrc = val(2)
        if ops[2].vector_index >= 0:
            b = f"({t}){{0}} + {_lane(lf, bsrc, T(sbits, k), ops[2].vector_index)}"
        else:
            b = f"__builtin_convertvector({_half(lf, bsrc, T(sbits, k), hi)}, {t})"
        prod = f"{a} * {b}"
        if "ml" in m[1:4]:
            prod = f"{_view(lf, val(0), t)} {'-' if 'sl' in m else '+'} {prod}"
        return assign(_out(lf, prod, t, n, False))
    if m in ("uaddlp", "saddlp") and len(ops) == 2:          # pairwise add long
        k = "i" if m[0] == "s" else "u"
        sbits, sn = _shape(ops[1])
        s = _view(lf, val(1), T(sbits, k))
        cnt = 128 // sbits
        ev = ", ".join(str(2 * j) for j in range(cnt // 2))
        od = ", ".join(str(2 * j + 1) for j in range(cnt // 2))
        wt = _wtype(lf, bits, k, cnt // 2)
        e = (f"__builtin_convertvector(__builtin_shufflevector({s}, {s}, {ev}), {wt}) + "
             f"__builtin_convertvector(__builtin_shufflevector({s}, {s}, {od}), {wt})")
        return assign(_out(lf, e, T(bits, k), n, half))
    if m in ("addp", "faddp") and len(ops) == 3:             # vector pairwise add
        t = T(bits, "f" if m == "faddp" else "u")
        a, b = _view(lf, val(1), t), _view(lf, val(2), t)
        cnt = 128 // bits
        ev = ", ".join(str(2 * j) for j in range(cnt))
        od = ", ".join(str(2 * j + 1) for j in range(cnt))
        return assign(_out(lf, f"__builtin_shufflevector({a}, {b}, {ev}) + __builtin_shufflevector({a}, {b}, {od})",
                           t, n, half))
    if m in ("scvtf", "ucvtf", "fcvtzs", "fcvtzu") and len(ops) == 2 and sh0:
        to_f = m.endswith("cvtf")
        src_k = ("i" if m == "scvtf" else "u") if to_f else "f"
        dst_k = "f" if to_f else ("i" if m == "fcvtzs" else "u")
        t = T(bits, dst_k)
        return assign(_out(lf, f"__builtin_convertvector({_view(lf, val(1), T(bits, src_k))}, {t})", t, n, half))
    if m == "tbl" and len(ops) == 3:                         # single-register table lookup
        t = T(8)
        return assign(_out(lf, f"__vtbl1({_view(lf, val(1), t)}, {_view(lf, val(2), t)})", t, n, half)) \
            if _helper(lf, "vtbl1") else NA
    return NA


def _wtype(lf, bits, kind, count):
    """A vector type of `count` lanes of `bits` (any total size) for convertvector targets."""
    name = f"{kind}{bits}x{count}"
    base = {"f32": "float", "f64": "double"}.get(f"{kind}{bits}") or (("u" if kind == "u" else "") + f"int{bits}_t")
    lf._vextra = getattr(lf, "_vextra", {})
    lf._vextra[name] = f"typedef {base} {name} __attribute__((vector_size({bits * count // 8})));"
    return name


def _half(lf, v, t, hi):
    """Low or high half (as a vector of half the lanes) of a 128-bit view."""
    n = int(t.split("x")[1])
    idx = ", ".join(str(k + (n // 2 if hi else 0)) for k in range(n // 2))
    _wtype(lf, int(t.split("x")[0][1:]), t[0], n // 2)
    return f"__builtin_shufflevector({_view(lf, v, t)}, {_view(lf, v, t)}, {idx})"


def _permute(lf, m, ops, val, assign, bits, n, half):
    cnt = 128 // bits if not half else n
    t = T(bits)
    a = _view(lf, val(1), t)
    b = _view(lf, val(2), t) if len(ops) > 2 and ops[2].type == a64.ARM64_OP_REG else a
    L = 128 // bits                                          # lanes in the 128-bit view
    if m in ("rev64", "rev32", "rev16"):
        grp = {"rev64": 64, "rev32": 32, "rev16": 16}[m] // bits
        idx = [g * grp + (grp - 1 - k) for g in range(L // grp) for k in range(grp)]
        return assign(_out(lf, f"__builtin_shufflevector({a}, {a}, {', '.join(map(str, idx))})", t, n, half))
    if m == "ext":
        k = ops[3].imm if len(ops) > 3 else 0                # byte offset
        t8 = T(8)
        a8, b8 = _view(lf, val(1), t8), _view(lf, val(2), t8)
        nb = 16 if not half else 8
        idx = [(k + j) if k + j < nb else (16 + k + j - nb) for j in range(nb)] + list(range(nb, 16)) * 0
        idx = idx + [16] * (16 - len(idx))
        return assign(_out(lf, f"__builtin_shufflevector({a8}, {b8}, {', '.join(map(str, idx))})", t8, 16, False))
    h = cnt // 2
    if m in ("zip1", "zip2"):
        base = 0 if m == "zip1" else h
        idx = [x for j in range(h) for x in (base + j, L + base + j)]
    elif m in ("uzp1", "uzp2"):
        off = 0 if m == "uzp1" else 1
        idx = [2 * j + off for j in range(h)] + [L + 2 * j + off for j in range(h)]
    else:
        off = 0 if m == "trn1" else 1
        idx = [x for j in range(h) for x in (2 * j + off, L + 2 * j + off)]
    idx = idx + [L] * (L - len(idx))                         # D forms: upper lanes from b's lane 0
    return assign(_out(lf, f"__builtin_shufflevector({a}, {b}, {', '.join(map(str, idx))})", t, n, half))


_HELPERS = {
    "vtbl1": ("static inline u8x16 __vtbl1(u8x16 t, u8x16 ix) { u8x16 r; "
              "for (int k = 0; k < 16; k++) r[k] = ix[k] < 16 ? t[ix[k] & 15] : 0; return r; }"),
}


def _helper(lf, name):
    if name.startswith("vshl_"):
        t = name[5:]
        lane = TYPEDEFS[t]
        n = 128 // int(t.split("x")[0][1:])
        bits = int(t.split("x")[0][1:])
        lf._vhelp = getattr(lf, "_vhelp", {})
        lf._vhelp[name] = (f"static inline {t} __{name}({t} a, i{bits}x{n} s) {{ {t} r; for (int k = 0; k < {n}; k++) "
                           f"r[k] = s[k] >= 0 ? ({lane})(s[k] < {bits} ? a[k] << s[k] : 0) : "
                           f"({lane})(-s[k] < {bits} ? a[k] >> -s[k] : (a[k] < 0 ? -1 : 0)); return r; }}")
        lf._vtypes.add(f"i{bits}x{n}")
        return True
    if name in _HELPERS:
        lf._vhelp = getattr(lf, "_vhelp", {})
        lf._vhelp[name] = _HELPERS[name]
        return True
    return False


def ins_helpers(used):
    out = []
    for t in sorted(used):
        if t in TYPEDEFS and t[0] in "ui":
            out.append(f"static inline {t} __ins_{t}({t} v, int k, {TYPEDEFS[t]} x) {{ v[k] = x; return v; }}")
    return out


_HELPER_TYPES = re.compile(r"\b([uif]\d+x\d+)\b")


def decls(lf, counts=None):
    """The typedefs and helpers the function's text actually uses, in dependency order."""
    if not getattr(lf, "_vtypes", None):
        return []
    use = (lambda n: True) if counts is None else (lambda n: bool(counts.get(n)))
    helpers = [h for name, h in getattr(lf, "_vhelp", {}).items() if use("__" + name)]
    ins = [h for h in ins_helpers(lf._vtypes) if use(h.split("(")[0].split()[-1])]
    extra = [h for name, h in getattr(lf, "_vextra", {}).items() if use(name)]
    needed = {t for t in lf._vtypes if use(t)}
    for h in helpers + ins + extra:              # a helper's own lane types
        needed |= set(_HELPER_TYPES.findall(h))
    if not (needed or helpers or ins or use("v128") or use("v128u")):
        return []
    out = ["typedef uint8_t v128 __attribute__((vector_size(16)));"]
    if use("v128u"):
        out.append("typedef uint8_t v128u __attribute__((vector_size(16), aligned(1)));   /* unaligned memory */")
    out += [f"typedef {TYPEDEFS[t]} {t} __attribute__((vector_size(16)));" for t in sorted(needed) if t in TYPEDEFS]
    return out + extra + ins + helpers + [""]
