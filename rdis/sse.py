"""x86 SSE/SSE4 -> compilable, lane-exact C with vector extensions (the x86 twin of neon.py).

`paddd xmm0, xmm1` -> `xmm0 = (v128)((u32x4)xmm0 + (u32x4)xmm1);`, `pshufd xmm0, xmm1, 0xee` ->
`__builtin_shufflevector`, `pmovmskb` -> a small helper. Same types and conventions as neon.py, so a
vectorized x86 loop decompiles to C that compiles and computes the same lanes. 256-bit (ymm)
forms are not modeled yet and fall back to the intrinsic-style call.
"""
from capstone import x86

from .neon import NA, VEC, T, TYPEDEFS, is_vec, _p, _view, _out, _lane, _wtype

_INT = {  # mnemonic -> (lane bits, C operator or builtin, lane kind)
    **{f"padd{s}": (b, "+", "u") for s, b in (("b", 8), ("w", 16), ("d", 32), ("q", 64))},
    **{f"psub{s}": (b, "-", "u") for s, b in (("b", 8), ("w", 16), ("d", 32), ("q", 64))},
    "pmullw": (16, "*", "u"), "pmulld": (32, "*", "u"),
    "pand": (64, "&", "u"), "por": (64, "|", "u"), "pxor": (64, "^", "u"),
    "andps": (32, "&", "u"), "orps": (32, "|", "u"), "xorps": (32, "^", "u"),
    "andpd": (64, "&", "u"), "orpd": (64, "|", "u"), "xorpd": (64, "^", "u"),
    **{f"pcmpeq{s}": (b, "==", "u") for s, b in (("b", 8), ("w", 16), ("d", 32), ("q", 64))},
    **{f"pcmpgt{s}": (b, ">", "i") for s, b in (("b", 8), ("w", 16), ("d", 32), ("q", 64))},
    **{f"pmaxs{s}": (b, "max", "i") for s, b in (("b", 8), ("w", 16), ("d", 32))},
    **{f"pmins{s}": (b, "min", "i") for s, b in (("b", 8), ("w", 16), ("d", 32))},
    **{f"pmaxu{s}": (b, "max", "u") for s, b in (("b", 8), ("w", 16), ("d", 32))},
    **{f"pminu{s}": (b, "min", "u") for s, b in (("b", 8), ("w", 16), ("d", 32))},
    "paddusb": (8, "add_sat", "u"), "paddusw": (16, "add_sat", "u"), "paddsb": (8, "add_sat", "i"),
    "paddsw": (16, "add_sat", "i"), "psubusb": (8, "sub_sat", "u"), "psubusw": (16, "sub_sat", "u"),
    "psubsb": (8, "sub_sat", "i"), "psubsw": (16, "sub_sat", "i"),
    "addps": (32, "+", "f"), "subps": (32, "-", "f"), "mulps": (32, "*", "f"), "divps": (32, "/", "f"),
    "addpd": (64, "+", "f"), "subpd": (64, "-", "f"), "mulpd": (64, "*", "f"), "divpd": (64, "/", "f"),
    "maxps": (32, "max", "f"), "minps": (32, "min", "f"), "maxpd": (64, "max", "f"), "minpd": (64, "min", "f"),
}
_SHIFT = {"psllw": (16, "<<", "u"), "pslld": (32, "<<", "u"), "psllq": (64, "<<", "u"),
          "psrlw": (16, ">>", "u"), "psrld": (32, ">>", "u"), "psrlq": (64, ">>", "u"),
          "psraw": (16, ">>", "i"), "psrad": (32, ">>", "i")}
_UNPACK = {"punpcklbw": (8, 0), "punpckhbw": (8, 1), "punpcklwd": (16, 0), "punpckhwd": (16, 1),
           "punpckldq": (32, 0), "punpckhdq": (32, 1), "punpcklqdq": (64, 0), "punpckhqdq": (64, 1),
           "unpcklps": (32, 0), "unpckhps": (32, 1), "unpcklpd": (64, 0), "unpckhpd": (64, 1)}
_WIDEN = {f"pmov{z}x{a}{b}": (sa, sb, "u" if z == "z" else "i")
          for z in "zs" for a, sa in (("b", 8), ("w", 16), ("d", 32)) for b, sb in (("w", 16), ("d", 32), ("q", 64))
          if sb > sa}
_MOVES = {"movdqu", "movdqa", "movups", "movaps", "movupd", "movapd", "lddqu", "movntdq", "movntps"}
_HELP = {
    "pmovmskb": "static inline int32_t __pmovmskb(i8x16 v) { int32_t m = 0; for (int k = 0; k < 16; k++) m |= (v[k] < 0) << k; return m; }",
    "movmskps": "static inline int32_t __movmskps(i32x4 v) { int32_t m = 0; for (int k = 0; k < 4; k++) m |= (v[k] < 0) << k; return m; }",
    "movmskpd": "static inline int32_t __movmskpd(i64x2 v) { return (v[0] < 0) | (v[1] < 0) << 1; }",
    "pshufb": "static inline u8x16 __pshufb(u8x16 a, u8x16 ix) { u8x16 r; for (int k = 0; k < 16; k++) r[k] = ix[k] & 0x80 ? 0 : a[ix[k] & 15]; return r; }",
    "pmaddwd": "static inline i32x4 __pmaddwd(i16x8 a, i16x8 b) { i32x4 r; for (int k = 0; k < 4; k++) r[k] = a[2*k] * b[2*k] + a[2*k+1] * b[2*k+1]; return r; }",
    "psadbw": "static inline u64x2 __psadbw(u8x16 a, u8x16 b) { u64x2 r = {0, 0}; for (int k = 0; k < 16; k++) r[k / 8] += a[k] > b[k] ? a[k] - b[k] : b[k] - a[k]; return r; }",
    "packssdw": "static inline i16x8 __packssdw(i32x4 a, i32x4 b) { i16x8 r; for (int k = 0; k < 8; k++) { int32_t x = k < 4 ? a[k] : b[k-4]; r[k] = x > 32767 ? 32767 : x < -32768 ? -32768 : x; } return r; }",
    "packsswb": "static inline i8x16 __packsswb(i16x8 a, i16x8 b) { i8x16 r; for (int k = 0; k < 16; k++) { int16_t x = k < 8 ? a[k] : b[k-8]; r[k] = x > 127 ? 127 : x < -128 ? -128 : x; } return r; }",
    "packuswb": "static inline u8x16 __packuswb(i16x8 a, i16x8 b) { u8x16 r; for (int k = 0; k < 16; k++) { int16_t x = k < 8 ? a[k] : b[k-8]; r[k] = x > 255 ? 255 : x < 0 ? 0 : x; } return r; }",
    "packusdw": "static inline u16x8 __packusdw(i32x4 a, i32x4 b) { u16x8 r; for (int k = 0; k < 8; k++) { int32_t x = k < 4 ? a[k] : b[k-4]; r[k] = x > 65535 ? 65535 : x < 0 ? 0 : x; } return r; }",
    "vshift": None,
}
_HELP_TYPES = {"pmovmskb": ("i8x16",), "movmskps": ("i32x4",), "movmskpd": ("i64x2",), "pshufb": ("u8x16",),
               "pmaddwd": ("i16x8", "i32x4"), "psadbw": ("u8x16", "u64x2"), "packssdw": ("i32x4", "i16x8"),
               "packsswb": ("i16x8", "i8x16"), "packuswb": ("i16x8", "u8x16"), "packusdw": ("i32x4", "u16x8")}


def _need(lf, name):
    lf._vhelp = getattr(lf, "_vhelp", {})
    lf._vhelp[name] = _HELP[name]
    lf._vtypes.update(_HELP_TYPES.get(name, ()))


def lift(lf, i, regs):
    m, ops = i.mnemonic, i.operands
    lf.__dict__.setdefault("_vtypes", set())
    lf.__dict__.setdefault("_vecnames", set())
    if any(o.type == x86.X86_OP_REG and i.reg_name(o.reg).startswith(("ymm", "zmm")) for o in ops):
        return NA
    avx = m.startswith("v") and len(ops) >= 3
    base = m[1:] if m.startswith("v") and (m[1:] in _INT or m[1:] in _SHIFT or m[1:] in _UNPACK or
                                           m[1:] in _WIDEN or m[1:] in _MOVES or m[1:] in _HELP or
                                           m[1:] in ("pshufd", "shufps", "pandn", "andnps", "andnpd",
                                                     "movd", "movq", "pslldq", "psrldq")) else m
    xmm = [o.type == x86.X86_OP_REG and i.reg_name(o.reg).startswith("xmm") for o in ops]
    if not any(xmm):
        return NA

    def raw(n):
        return lf._op(ops[n], i, regs)

    def V(n, t):
        """Operand n viewed as vector type t (register, 16-byte memory, or a scalar in lane 0)."""
        o = ops[n]
        lf._vtypes.add(t)
        if o.type == x86.X86_OP_MEM:
            refs = lf.arch.data_refs(i, {}) if o.mem.base == x86.X86_REG_RIP else []
            cst = lf._ro_bytes(refs[0], 16) if refs and (o.size in (16, 0)) else None
            if cst is not None:                             # constant-pool vector: a literal
                lf._vtypes.add("v128")
                return f"({t})(v128){{{', '.join(hex(b) for b in cst)}}}"
            addr = lf._addr(o, i, regs)
            if o.size == 16 or not o.size:
                return f"({t})*(v128u *){_p(lf, addr)}"
            lt = {4: "u32x4", 8: "u64x2", 2: "u16x8", 1: "u8x16"}[o.size]
            lf._vtypes.add(lt)
            return f"({t})({lt}){{*({TYPEDEFS[lt]} *){_p(lf, addr)}}}"
        v = raw(n)
        if is_vec(lf, v) or v in ("0", "0.0"):
            return _view(lf, v, t)
        lv = getattr(lf, "_lastview", {}).get(lf._canon(i.reg_name(o.reg)), "f64x2")
        lf._vtypes.add(lv)
        return f"({t})({lv}){{{v}}}"                    # scalar in lane 0, bit-exact

    def put(e):
        lf._vtypes.add("v128")
        return lf._assign(ops[0], e, i, regs)

    a_i, b_i = (1, 2) if avx else (0, len(ops) - 1)     # SSE: d = d OP s ; AVX: d = a OP b
    regs_used = {o.reg for o in ops[a_i:b_i + 1] if o.type == x86.X86_OP_REG}
    if len(ops) >= 2 and all(o.type == x86.X86_OP_REG for o in ops[a_i:b_i + 1]) and len(regs_used) == 1:
        if base in ("pxor", "xorps", "xorpd", "psubb", "psubw", "psubd", "psubq", "pandn", "andnps", "andnpd"):
            return put(f"{VEC}{{0}}")                      # zero idiom: x ^ x
        if base.startswith("pcmpeq"):
            return put(f"{VEC}((u8x16){{0}} + 0xff)")      # all ones: x == x
    # -- moves --------------------------------------------------------------------------------
    if base in _MOVES and len(ops) == 2:
        if ops[0].type == x86.X86_OP_MEM:
            addr = lf._addr(ops[0], i, regs)
            loc = f"*(v128u *){_p(lf, addr)}"
            lf._flush_for_store(loc, regs)
            lf._vtypes.add("v128")
            return f"{loc} = {V(1, 'v128')};"
        return put(f"{VEC}{V(1, 'u8x16')}")
    if base in ("movd", "movq") and len(ops) == 2:
        if xmm[0] and not xmm[1]:                        # gpr/mem -> xmm low lane, upper zero
            lt = "u32x4" if ops[1].size == 4 else "u64x2"
            lf._vtypes.add(lt)
            src = raw(1)
            return put(f"{VEC}({lt}){{{src}}}")
        if xmm[1] and not xmm[0]:                        # xmm low lane -> gpr / mem
            lt = "u32x4" if (ops[0].size or 8) == 4 else "u64x2"
            v = raw(1)
            if not is_vec(lf, v):
                return NA
            if ops[0].type == x86.X86_OP_MEM:
                return f"*({TYPEDEFS[lt]} *){_p(lf, lf._addr(ops[0], i, regs))} = {_lane(lf, v, lt, 0)};"
            return lf._assign(ops[0], _lane(lf, v, lt, 0), i, regs)
        if base == "movq" and xmm[0] and xmm[1]:         # low 64 bits, upper zeroed
            return put(_out(lf, f"__builtin_shufflevector({V(1, 'u64x2')}, (u64x2){{0}}, 0, 2)", "u64x2", 2, False))
        return NA
    # -- element-wise ---------------------------------------------------------------------
    if base in _INT and len(ops) >= 2:
        bits, op, k = _INT[base]
        t = T(bits, k)
        a, b = V(a_i, t), V(b_i, t)
        if op in ("max", "min", "add_sat", "sub_sat"):
            e = f"__builtin_elementwise_{op}({a}, {b})"
        else:
            e = f"{a} {op} {b}"
        return put(_out(lf, e, T(bits, "i") if op in ("==", ">") else t, 128 // bits, False))
    if base in ("pandn", "andnps", "andnpd") and len(ops) >= 2:      # d = ~a & b
        t = T(64)
        return put(_out(lf, f"~{V(a_i, t)} & {V(b_i, t)}", t, 2, False))
    if base in _SHIFT and len(ops) >= 2:
        bits, op, k = _SHIFT[base]
        t = T(bits, k)
        a = V(a_i, t)
        c = ops[-1]
        if c.type == x86.X86_OP_IMM:
            if c.imm >= bits:
                return put(_out(lf, f"{a} >> {bits - 1}" if k == "i" else f"({t}){{0}}", t, 128 // bits, False))
            return put(_out(lf, f"{a} {op} {c.imm}", t, 128 // bits, False))
        cnt = f"{V(len(ops) - 1, 'u64x2')}[0]"
        fill = f"{a} >> {bits - 1}" if k == "i" else f"({t}){{0}}"
        return put(_out(lf, f"({cnt} < {bits} ? {a} {op} ({TYPEDEFS[t]}){cnt} : {fill})", t, 128 // bits, False))
    if base in ("pslldq", "psrldq") and ops[-1].type == x86.X86_OP_IMM:
        n = min(ops[-1].imm, 16)
        a = V(a_i, "u8x16")
        if base == "psrldq":
            idx = [k + n if k + n < 16 else 16 for k in range(16)]
        else:
            idx = [k - n if k >= n else 16 for k in range(16)]
        return put(_out(lf, f"__builtin_shufflevector({a}, (u8x16){{0}}, {', '.join(map(str, idx))})", "u8x16", 16, False))
    # -- shuffles -------------------------------------------------------------------------
    if base == "pshufd" and ops[-1].type == x86.X86_OP_IMM:
        im = ops[-1].imm
        idx = [(im >> (2 * k)) & 3 for k in range(4)]
        a = V(1, "u32x4")
        return put(_out(lf, f"__builtin_shufflevector({a}, {a}, {', '.join(map(str, idx))})", "u32x4", 4, False))
    if base in ("pshuflw", "pshufhw") and ops[-1].type == x86.X86_OP_IMM:
        im = ops[-1].imm
        sel = [(im >> (2 * k)) & 3 for k in range(4)]
        idx = (sel + [4, 5, 6, 7]) if base == "pshuflw" else ([0, 1, 2, 3] + [4 + s for s in sel])
        a = V(1, "u16x8")
        return put(_out(lf, f"__builtin_shufflevector({a}, {a}, {', '.join(map(str, idx))})", "u16x8", 8, False))
    if base in ("shufps", "shufpd") and ops[-1].type == x86.X86_OP_IMM:
        im = ops[-1].imm
        bits = 32 if base == "shufps" else 64
        t = T(bits, "f")
        a, b = V(a_i, t), V(2 if avx else 1, t)        # lanes 0-1 from a, 2-3 from b
        if bits == 32:
            idx = [im & 3, (im >> 2) & 3, 4 + ((im >> 4) & 3), 4 + ((im >> 6) & 3)]
        else:
            idx = [im & 1, 2 + ((im >> 1) & 1)]
        return put(_out(lf, f"__builtin_shufflevector({a}, {b}, {', '.join(map(str, idx))})", t, 128 // bits, False))
    if base in _UNPACK and len(ops) >= 2:
        bits, hi = _UNPACK[base]
        t = T(bits)
        n = 128 // bits
        a, b = V(a_i, t), V(b_i, t)
        off = n // 2 if hi else 0
        idx = [x for k in range(n // 2) for x in (off + k, n + off + k)]
        return put(_out(lf, f"__builtin_shufflevector({a}, {b}, {', '.join(map(str, idx))})", t, n, False))
    if base in ("movhlps", "movlhps") and len(ops) >= 2:
        t = "u64x2"
        a, b = V(a_i, t), V(b_i, t)
        idx = "3, 1" if base == "movhlps" else "0, 2"
        return put(_out(lf, f"__builtin_shufflevector({a}, {b}, {idx})", t, 2, False))
    if base in ("movddup", "movshdup", "movsldup") and len(ops) == 2:
        if base == "movddup":
            a = V(1, "u64x2")
            return put(_out(lf, f"__builtin_shufflevector({a}, {a}, 0, 0)", "u64x2", 2, False))
        a = V(1, "u32x4")
        idx = "1, 1, 3, 3" if base == "movshdup" else "0, 0, 2, 2"
        return put(_out(lf, f"__builtin_shufflevector({a}, {a}, {idx})", "u32x4", 4, False))
    if base == "palignr" and ops[-1].type == x86.X86_OP_IMM:
        n = ops[-1].imm
        lo, hi = V(len(ops) - 2, "u8x16"), V(a_i, "u8x16")       # concat(dst, src) >> n bytes
        idx = [k + n if k + n < 32 else 32 for k in range(16)]
        idx = [x if x < 32 else 0 for x in idx]
        return put(_out(lf, f"__builtin_shufflevector({lo}, {hi}, {', '.join(map(str, idx))})", "u8x16", 16, False))
    # -- widening / narrowing / reductions ------------------------------------------------
    if base in _WIDEN and len(ops) == 2:
        sb, db, k = _WIDEN[base]
        n = 128 // db
        src = f"__builtin_shufflevector({V(1, T(sb, k))}, {V(1, T(sb, k))}, {', '.join(str(j) for j in range(n))})"
        _wtype(lf, sb, k, n)
        return put(_out(lf, f"__builtin_convertvector({src}, {T(db, k)})", T(db, k), n, False))
    if base in ("pmovmskb", "movmskps", "movmskpd") and len(ops) == 2:
        _need(lf, base)
        t = _HELP_TYPES[base][0]
        return lf._assign(ops[0], f"__{base}({V(1, t)})", i, regs)
    if base in ("pshufb", "pmaddwd", "psadbw", "packssdw", "packsswb", "packuswb", "packusdw") and len(ops) >= 2:
        _need(lf, base)
        ts = _HELP_TYPES[base]
        return put(_out(lf, f"__{base}({V(a_i, ts[0])}, {V(b_i, ts[0])})", ts[-1], 16, False))
    if base == "pmuludq" and len(ops) >= 2:
        a, b = V(a_i, "u64x2"), V(b_i, "u64x2")
        return put(_out(lf, f"({a} & 0xffffffff) * ({b} & 0xffffffff)", "u64x2", 2, False))
    if base in ("phaddd", "phaddw", "haddps", "haddpd") and len(ops) >= 2:
        bits = {"phaddd": 32, "phaddw": 16, "haddps": 32, "haddpd": 64}[base]
        t = T(bits, "f" if base.startswith("hadd") else "u")
        n = 128 // bits
        a, b = V(a_i, t), V(b_i, t)
        ev = ", ".join(str(2 * j) for j in range(n))
        od = ", ".join(str(2 * j + 1) for j in range(n))
        return put(_out(lf, f"__builtin_shufflevector({a}, {b}, {ev}) + __builtin_shufflevector({a}, {b}, {od})", t, n, False))
    if base in ("pabsb", "pabsw", "pabsd") and len(ops) == 2:
        t = T({"b": 8, "w": 16, "d": 32}[base[-1]], "i")
        return put(_out(lf, f"__builtin_elementwise_abs({V(1, t)})", t, 16, False))
    if base in ("sqrtps", "sqrtpd") and len(ops) == 2:
        t = "f32x4" if base == "sqrtps" else "f64x2"
        return put(_out(lf, f"__builtin_elementwise_sqrt({V(1, t)})", t, 4, False))
    if base in ("cvtdq2ps", "cvttps2dq", "cvtps2dq") and len(ops) == 2:
        src, dst = ("i32x4", "f32x4") if base == "cvtdq2ps" else ("f32x4", "i32x4")
        v = V(1, src)
        if base == "cvtps2dq":
            v = f"__builtin_elementwise_rint({v})"
        return put(_out(lf, f"__builtin_convertvector({v}, {dst})", dst, 4, False))
    if base in ("cvtdq2pd", "cvtps2pd") and len(ops) == 2:
        src = "i32x4" if base == "cvtdq2pd" else "f32x4"
        _wtype(lf, 32, src[0], 2)
        lo = f"__builtin_shufflevector({V(1, src)}, {V(1, src)}, 0, 1)"
        return put(_out(lf, f"__builtin_convertvector({lo}, f64x2)", "f64x2", 2, False))
    if base in ("pinsrb", "pinsrw", "pinsrd", "pinsrq") and ops[-1].type == x86.X86_OP_IMM:
        t = T({"b": 8, "w": 16, "d": 32, "q": 64}[base[-1]])
        k = ops[-1].imm & (128 // int(t[1:].split("x")[0]) - 1)
        return put(f"{VEC}__ins_{t}({V(a_i, t)}, {k}, {raw(len(ops) - 2)})")
    if base in ("pextrb", "pextrw", "pextrd", "pextrq") and ops[-1].type == x86.X86_OP_IMM:
        t = T({"b": 8, "w": 16, "d": 32, "q": 64}[base[-1]])
        k = ops[-1].imm & (128 // int(t[1:].split("x")[0]) - 1)
        return lf._assign(ops[0], f"({V(1, t)})[{k}]", i, regs)
    if base in ("pblendw", "blendps", "blendpd") and ops[-1].type == x86.X86_OP_IMM:
        bits = {"pblendw": 16, "blendps": 32, "blendpd": 64}[base]
        n = 128 // bits
        im = ops[-1].imm
        t = T(bits)
        a, b = V(a_i, t), V(len(ops) - 2 if not avx else 2, t)
        idx = [n + k if (im >> k) & 1 else k for k in range(n)]
        return put(_out(lf, f"__builtin_shufflevector({a}, {b}, {', '.join(map(str, idx))})", t, n, False))
    return NA
