"""SIMD, floating-point and extended-integer lifting for the per-block lifter.

Vector code has no natural C form, so -- like IDA's `_mm_*` output -- packed operations become the
compiler intrinsics a programmer would have written (`_mm_add_epi32(a, b)`, `vaddq(a, b)`). Scalar
floating point becomes ordinary C arithmetic, casts and libm calls. Any other vector instruction
falls back to an intrinsic-style call named after the mnemonic, so it is an expression with its
operands rather than an opaque `/* asm */` comment.

`lift(lf, insn, regs)` returns a statement, None (value tracked, nothing to emit) or NA (not ours).
"""
import re

from capstone import x86, arm64 as a64

from . import neon, sse

NA = object()


def _uint(bits):
    return {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}.get(bits, "uint64_t")

# ---- x86 ------------------------------------------------------------------
_X86_PACKED = {
    "addps": "_mm_add_ps", "addpd": "_mm_add_pd", "subps": "_mm_sub_ps", "subpd": "_mm_sub_pd",
    "mulps": "_mm_mul_ps", "mulpd": "_mm_mul_pd", "divps": "_mm_div_ps", "divpd": "_mm_div_pd",
    "andps": "_mm_and_ps", "andpd": "_mm_and_pd", "orps": "_mm_or_ps", "orpd": "_mm_or_pd",
    "xorps": "_mm_xor_ps", "xorpd": "_mm_xor_pd", "andnps": "_mm_andnot_ps", "andnpd": "_mm_andnot_pd",
    "maxps": "_mm_max_ps", "minps": "_mm_min_ps", "maxpd": "_mm_max_pd", "minpd": "_mm_min_pd",
    "sqrtps": "_mm_sqrt_ps", "sqrtpd": "_mm_sqrt_pd", "rcpps": "_mm_rcp_ps", "rsqrtps": "_mm_rsqrt_ps",
    "paddb": "_mm_add_epi8", "paddw": "_mm_add_epi16", "paddd": "_mm_add_epi32", "paddq": "_mm_add_epi64",
    "psubb": "_mm_sub_epi8", "psubw": "_mm_sub_epi16", "psubd": "_mm_sub_epi32", "psubq": "_mm_sub_epi64",
    "paddusb": "_mm_adds_epu8", "psubusb": "_mm_subs_epu8", "paddsw": "_mm_adds_epi16",
    "pand": "_mm_and_si128", "pandn": "_mm_andnot_si128", "por": "_mm_or_si128", "pxor": "_mm_xor_si128",
    "pcmpeqb": "_mm_cmpeq_epi8", "pcmpeqw": "_mm_cmpeq_epi16", "pcmpeqd": "_mm_cmpeq_epi32",
    "pcmpeqq": "_mm_cmpeq_epi64", "pcmpgtb": "_mm_cmpgt_epi8", "pcmpgtw": "_mm_cmpgt_epi16",
    "pcmpgtd": "_mm_cmpgt_epi32", "pminub": "_mm_min_epu8", "pmaxub": "_mm_max_epu8",
    "pminsw": "_mm_min_epi16", "pmaxsw": "_mm_max_epi16", "pminsd": "_mm_min_epi32", "pmaxsd": "_mm_max_epi32",
    "pmulld": "_mm_mullo_epi32", "pmullw": "_mm_mullo_epi16", "pmuludq": "_mm_mul_epu32",
    "pmaddwd": "_mm_madd_epi16", "pavgb": "_mm_avg_epu8", "psadbw": "_mm_sad_epu8",
    "punpcklbw": "_mm_unpacklo_epi8", "punpckhbw": "_mm_unpackhi_epi8", "punpcklwd": "_mm_unpacklo_epi16",
    "punpckhwd": "_mm_unpackhi_epi16", "punpckldq": "_mm_unpacklo_epi32", "punpckhdq": "_mm_unpackhi_epi32",
    "punpcklqdq": "_mm_unpacklo_epi64", "punpckhqdq": "_mm_unpackhi_epi64",
    "unpcklps": "_mm_unpacklo_ps", "unpckhps": "_mm_unpackhi_ps", "unpcklpd": "_mm_unpacklo_pd",
    "unpckhpd": "_mm_unpackhi_pd", "packuswb": "_mm_packus_epi16", "packsswb": "_mm_packs_epi16",
    "packssdw": "_mm_packs_epi32", "pshufb": "_mm_shuffle_epi8", "pmovmskb": "_mm_movemask_epi8",
    "movmskps": "_mm_movemask_ps", "movmskpd": "_mm_movemask_pd", "ptest": "_mm_testz_si128",
    "pmovzxbw": "_mm_cvtepu8_epi16", "pmovzxbd": "_mm_cvtepu8_epi32", "pmovsxbw": "_mm_cvtepi8_epi16",
    "cvtdq2ps": "_mm_cvtepi32_ps", "cvtps2dq": "_mm_cvtps_epi32", "cvttps2dq": "_mm_cvttps_epi32",
    "cvtps2pd": "_mm_cvtps_pd", "cvtpd2ps": "_mm_cvtpd_ps", "haddps": "_mm_hadd_ps", "addsubps": "_mm_addsub_ps",
    "aesenc": "_mm_aesenc_si128", "aesenclast": "_mm_aesenclast_si128", "aesdec": "_mm_aesdec_si128",
    "aesdeclast": "_mm_aesdeclast_si128", "aesimc": "_mm_aesimc_si128", "pclmulqdq": "_mm_clmulepi64_si128",
    "sha256rnds2": "_mm_sha256rnds2_epu32", "sha256msg1": "_mm_sha256msg1_epu32", "sha256msg2": "_mm_sha256msg2_epu32",
    "crc32": "_mm_crc32",
}
_X86_IMM = {  # ops whose last operand is an immediate control byte
    "pshufd": "_mm_shuffle_epi32", "pshuflw": "_mm_shufflelo_epi16", "pshufhw": "_mm_shufflehi_epi16",
    "shufps": "_mm_shuffle_ps", "shufpd": "_mm_shuffle_pd", "palignr": "_mm_alignr_epi8",
    "pslldq": "_mm_slli_si128", "psrldq": "_mm_srli_si128", "pblendw": "_mm_blend_epi16",
    "blendps": "_mm_blend_ps", "blendpd": "_mm_blend_pd", "insertps": "_mm_insert_ps", "pinsrb": "_mm_insert_epi8",
    "pinsrw": "_mm_insert_epi16", "pinsrd": "_mm_insert_epi32", "pinsrq": "_mm_insert_epi64",
    "pextrb": "_mm_extract_epi8", "pextrw": "_mm_extract_epi16", "pextrd": "_mm_extract_epi32",
    "pextrq": "_mm_extract_epi64", "roundss": "_mm_round_ss", "roundsd": "_mm_round_sd",
    "cmpps": "_mm_cmp_ps", "cmppd": "_mm_cmp_pd", "dpps": "_mm_dp_ps", "aeskeygenassist": "_mm_aeskeygenassist_si128",
}
_X86_SHIFT = {"psllw": "_mm_slli_epi16", "pslld": "_mm_slli_epi32", "psllq": "_mm_slli_epi64",
              "psrlw": "_mm_srli_epi16", "psrld": "_mm_srli_epi32", "psrlq": "_mm_srli_epi64",
              "psraw": "_mm_srai_epi16", "psrad": "_mm_srai_epi32"}
_X86_SCALAR = {"addss": "+", "addsd": "+", "subss": "-", "subsd": "-", "mulss": "*", "mulsd": "*",
               "divss": "/", "divsd": "/"}
_X86_FMIN = {"maxss": "fmaxf", "maxsd": "fmax", "minss": "fminf", "minsd": "fmin",
             "sqrtss": "sqrtf", "sqrtsd": "sqrt"}
_X86_CVT = {"cvtsi2sd": "(double)", "cvtsi2ss": "(float)", "cvtss2sd": "(double)", "cvtsd2ss": "(float)",
            "cvttsd2si": "(int64_t)", "cvttss2si": "(int64_t)", "cvtsd2si": "(int64_t)lrint",
            "cvtss2si": "(int64_t)lrintf", "cvtusi2sd": "(double)", "cvtusi2ss": "(float)"}
_X86_MOVES = {"movss", "movsd", "movd", "movq", "movdqa", "movdqu", "movapd", "movupd", "movaps", "movups",
              "movlps", "movhps", "movlpd", "movhpd", "movntdq", "movntps", "movnti", "lddqu", "movddup",
              "movshdup", "movsldup", "movabs"}
_X86_ZERO = {"xorps", "xorpd", "pxor", "pcmpeqd"}  # same-register forms: zero (pcmpeqd = all ones)

# ---- arm64 ----------------------------------------------------------------
_ARM_FBIN = {"fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}
_ARM_FFN = {"fabs": "fabs", "fsqrt": "sqrt", "fmax": "fmax", "fmin": "fmin", "fmaxnm": "fmax",
            "fminnm": "fmin", "frintz": "trunc", "frintm": "floor", "frintp": "ceil", "frinta": "round",
            "frintn": "rint", "frintx": "rint", "frinti": "nearbyint"}
_ARM_CVT_INT = {"fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvtps", "fcvtpu",
                "fcvtns", "fcvtnu"}
_ARM_EXT = {"sxtb": "(int8_t)", "sxth": "(int16_t)", "sxtw": "(int32_t)", "uxtb": "(uint8_t)",
            "uxth": "(uint16_t)", "uxtw": "(uint32_t)"}
_ARM_BITS = {"rev": "__builtin_bswap64", "rev32": "__builtin_bswap32", "rev16": "__rev16",
             "rbit": "__builtin_bitreverse64", "clz": "__builtin_clzll", "cls": "__builtin_clrsbll",
             "cnt": "vcntq"}
_ARM_PAC = {"paciza", "pacizb", "pacia", "pacib", "pacda", "pacdb", "pacdza", "pacdzb", "autiza",
            "autizb", "autia", "autib", "autda", "autdb", "autdza", "autdzb", "xpaci", "xpacd",
            "xpaclri", "paciasp", "pacibsp", "autiasp", "autibsp", "pacia1716", "autia1716", "bti"}
_VEC = re.compile(r"\bv\d+\.(\d+)?[bhsdq]\b|\{")


def _cast(lf, t, v):
    """`(t)v`, parenthesizing a compound operand so the cast covers all of it."""
    return f"{t}{v}" if lf._atomic(v) else f"{t}({v})"


def _regname(lf, op, i):
    return lf._canon(i.reg_name(op.reg))


def _vector_x86(i):
    return any(op.type == x86.X86_OP_REG and i.reg_name(op.reg)[:3] in ("xmm", "ymm", "zmm") for op in i.operands)


def lift(lf, i, regs):
    return _x86(lf, i, regs) if lf.x86 else _arm(lf, i, regs)


# ---- x86 ------------------------------------------------------------------
def _x86(lf, i, regs):
    m, ops = i.mnemonic, i.operands
    avx = m.startswith("v") and len(m) > 1 and (m[1:] in _X86_PACKED or m[1:] in _X86_IMM or
                                                 m[1:] in _X86_SCALAR or m[1:] in _X86_FMIN or
                                                 m[1:] in _X86_SHIFT or m[1:] in _X86_MOVES or
                                                 m[1:] in _X86_ZERO or m[1:] in _X86_CVT)
    base = m[1:] if avx else m
    op = lambda n: lf._op(ops[n], i, regs)
    if m.startswith("rep") and (" movs" in m or " stos" in m):   # string ops are memcpy/memset
        size = {"b": 1, "w": 2, "d": 4, "q": 8}.get(m[-1], 1)
        n = regs.get("rcx", "rcx") if size == 1 else lf._bin(regs.get("rcx", "rcx"), "*", str(size))
        dst = regs.get("rdi", "rdi")
        if " movs" in m:
            return f"memcpy({dst}, {regs.get('rsi', 'rsi')}, {n});"
        return f"memset({dst}, {regs.get('rax', 'rax')}, {n});"
    if not ops:
        if m in ("cdq", "cqo", "cwd"):
            regs["rdx"] = f"({regs.get('rax', 'rax')} < 0) ? -1 : 0"   # sign spread into rdx
            return None
        if m in ("cdqe", "cwde", "cbw"):
            regs["rax"] = _cast(lf, "(int64_t)", regs.get("rax", "rax"))
            return None
        if m in ("ud2", "int3", "hlt"):
            return "__builtin_trap();"
        if m in ("vzeroupper", "vzeroall", "lfence", "mfence", "sfence", "pause", "cld", "std", "clc"):
            return None
        return NA
    r = sse.lift(lf, i, regs)           # lane-exact SSE via vector extensions (compilable C)
    if r is not sse.NA:
        return r
    # three-operand AVX forms read (src1, src2); legacy SSE forms are dst = dst OP src
    srcs = (lambda: [op(1), op(2)]) if avx and len(ops) >= 3 else (lambda: [op(0), op(-1)])
    if base in _X86_ZERO and len({(o.type, o.reg if o.type == x86.X86_OP_REG else None) for o in ops}) == 1:
        return lf._assign(ops[0], "~0" if base == "pcmpeqd" else "0", i, regs)
    if base in ("movss", "movsd") and len(ops) == 2 and ops[1].type == x86.X86_OP_MEM:
        refs = lf.arch.data_refs(i, {})
        raw = lf._ro_bytes(refs[0], 4 if base == "movss" else 8) if refs else None
        if raw is not None:                              # constant-pool float / double
            import math, struct
            v = struct.unpack("<f" if base == "movss" else "<d", raw)[0]
            if math.isfinite(v):
                return lf._assign(ops[0], f"{v!r}f" if base == "movss" else repr(v), i, regs)
    if base in _X86_MOVES and len(ops) >= 2:
        return lf._assign(ops[0], op(-1), i, regs)
    if base in _X86_SCALAR:
        a, b = srcs()
        return lf._assign(ops[0], lf._bin(a, _X86_SCALAR[base], b), i, regs)
    if base in _X86_FMIN:
        args = srcs() if base.startswith(("max", "min")) else [op(-1)]
        return lf._assign(ops[0], f"{_X86_FMIN[base]}({', '.join(args)})", i, regs)
    if base in _X86_CVT:
        v, cast = op(-1), _X86_CVT[base]
        call = cast.endswith(("lrint", "lrintf"))     # (int64_t)lrint(x) needs its call parens
        return lf._assign(ops[0], f"{cast}({v})" if call or not lf._atomic(v) else f"{cast}{v}", i, regs)
    if base in _X86_IMM:
        fn = _X86_IMM[base].replace("_mm_", "_mm256_") if _wide(i) else _X86_IMM[base]
        args = [op(n) for n in range(1 if (avx or base.startswith(("pshuf", "pext"))) else 0, len(ops))]
        return lf._assign(ops[0], f"{fn}({', '.join(args)})", i, regs)
    if base in _X86_SHIFT:
        fn = _X86_SHIFT[base].replace("_mm_", "_mm256_") if _wide(i) else _X86_SHIFT[base]
        a, b = srcs()
        return lf._assign(ops[0], f"{fn}({a}, {b})", i, regs)
    if base in _X86_PACKED:
        fn = _X86_PACKED[base].replace("_mm_", "_mm256_") if _wide(i) else _X86_PACKED[base]
        unary = base.startswith(("cvt", "pmovzx", "pmovsx", "movmsk", "pmovmsk", "sqrt", "rcp", "rsqrt")) \
            or base == "aesimc"
        args = [op(-1)] if unary or len(ops) < 2 else srcs()
        if base == "ptest":  # sets flags only
            regs["__cmp__"] = ("test", srcs())
            return None
        return lf._assign(ops[0], f"{fn}({', '.join(args)})", i, regs)
    if m in ("ucomisd", "comisd", "ucomiss", "comiss", "vucomisd", "vcomisd", "vucomiss", "vcomiss"):
        regs["__cmp__"] = ("cmp", [op(0), op(1)])
        return None
    # ---- integer extras
    if m in ("div", "idiv") and len(ops) == 1:          # rax = rdx:rax / src, rdx = remainder
        bits = (ops[0].size or 8) * 8
        t = ("int" if m == "idiv" else "uint") + f"{bits}_t"
        num, d = f"({t}){lf._paren(regs.get('rax', 'rax'))}", f"({t}){lf._paren(op(0))}"
        regs["rdx"] = f"(int64_t)({num} % {d})"
        regs["rax"] = f"(int64_t)({num} / {d})"
        return None
    if m in ("mul", "imul") and len(ops) == 1:          # rdx:rax = rax * src (double width)
        bits = (ops[0].size or 8) * 8
        s_ = m == "imul"
        a, b = lf._paren(regs.get("rax", "rax")), lf._paren(op(0))
        if bits == 64:
            w, c = ("__int128", "(int64_t)") if s_ else ("unsigned __int128", "(uint64_t)")
            regs["rdx"] = f"(int64_t)((({w}){c}{a} * {c}{b}) >> 64)"
            regs["rax"] = f"(int64_t)({c}{a} * {c}{b})"
        else:
            w, c = ("int64_t", f"(int{bits}_t)") if s_ else ("uint64_t", f"(uint{bits}_t)")
            regs["rdx"] = f"(int64_t)(({w}){c}{a} * {c}{b} >> {bits})"
            regs["rax"] = f"(int64_t)({c}({c}{a} * {c}{b}))"
        return None
    if m == "imul" and len(ops) == 3:                    # imul dst, src, imm
        return lf._assign(ops[0], lf._bin(op(1), "*", op(2)), i, regs)
    if m in ("shl", "shr", "sar", "sal") and len(ops) == 1:  # shift by one
        return lf._assign(ops[0], lf._bin(op(0), "<<" if m in ("shl", "sal") else ">>", "1"), i, regs)
    if m in ("adc", "sbb") and len(ops) == 2:
        a, b = op(0), op(1)
        cf = _carry_x86(lf, regs)
        if m == "sbb" and a == b:                        # sbb r, r: 0 or -1 from the carry flag
            return lf._assign(ops[0], f"-({cf})", i, regs)
        return lf._assign(ops[0], lf._bin(lf._bin(a, "+" if m == "adc" else "-", b), "+" if m == "adc" else "-",
                                          cf if lf._atomic(cf) else f"({cf})"), i, regs)
    if m in ("rol", "ror") and len(ops) == 2:
        bits = (ops[0].size or 8) * 8
        fn = f"__builtin_rotate{'left' if m == 'rol' else 'right'}{bits}"
        return lf._assign(ops[0], f"{fn}(({_uint(bits)})({op(0)}), {op(1)})", i, regs)
    if m in ("bsf", "tzcnt"):
        bits = (ops[0].size or 8) * 8
        return lf._assign(ops[0], f"__builtin_ctzg(({_uint(bits)}){lf._paren(op(1))}, {bits})", i, regs)
    if m in ("bsr",):
        bits = (ops[0].size or 8) * 8
        return lf._assign(ops[0], f"{bits - 1} - __builtin_clzg(({_uint(bits)}){lf._paren(op(1))})", i, regs)
    if m == "lzcnt":
        bits = (ops[0].size or 8) * 8
        return lf._assign(ops[0], f"__builtin_clzg(({_uint(bits)}){lf._paren(op(1))}, {bits})", i, regs)
    if m == "popcnt":
        bits = (ops[0].size or 8) * 8
        return lf._assign(ops[0], f"__builtin_popcountg(({_uint(bits)}){lf._paren(op(1))})", i, regs)
    if m == "bswap":
        return lf._assign(ops[0], f"__builtin_bswap64({op(0)})", i, regs)
    if m in ("bt",):
        regs["__cmp__"] = ("bt", [op(0), op(1)])
        return None
    if m in ("bts", "btr", "btc") and len(ops) == 2:
        a, b = op(0), op(1)
        e = {"bts": f"{a} | (1 << {b})", "btr": f"{a} & ~(1 << {b})", "btc": f"{a} ^ (1 << {b})"}[m]
        regs["__cmp__"] = ("bt", [a, b])
        return lf._assign(ops[0], e, i, regs)
    if m == "xchg" and len(ops) == 2:
        a, b = op(0), op(1)
        if a == b:
            return None  # xchg ax, ax is a nop
        lf._assign(ops[0], b, i, regs)
        return lf._assign(ops[1], a, i, regs)
    if m == "andn" and len(ops) == 3:
        return lf._assign(ops[0], f"~{op(1)} & {op(2)}", i, regs)
    if m in ("prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta", "prefetchw", "clflush"):
        return None
    if _vector_x86(i) and ops and ops[0].type in (x86.X86_OP_REG, x86.X86_OP_MEM):
        # any other vector op: an intrinsic-style call keeps operands and data flow visible
        args = [lf._op(o, i, regs) for o in ops[1:]] or [lf._op(ops[0], i, regs)]
        return lf._assign(ops[0], f"__{m}({', '.join(args)})", i, regs)
    return NA


def _carry_x86(lf, regs):
    """The x86 carry flag as C, from the flag-setter that preceded it."""
    cmp = regs.get("__cmp__")
    if cmp and len(cmp) > 2:                             # flag-setter recorded its own carry
        return cmp[2]
    if cmp and cmp[0] == "cmp" and len(cmp[1]) == 2:    # cmp a, b / sub: CF = a < b (unsigned)
        a, b = cmp[1]
        return lf._bin(lf._cast_u(a), "<", lf._cast_u(b))
    if cmp and cmp[0] == "bt":
        a, b = cmp[1]
        return lf._bin(lf._bin(a, ">>", b), "&", "1")
    return "0"  # test/and/or/xor clear CF; anything else we do not model reads as no carry


def _carry_arm(lf, regs):
    """arm64 C flag: for a subtraction (cmp/subs) it is "no borrow", i.e. a >= b unsigned."""
    cmp = regs.get("__cmp__")
    if cmp and cmp[0] == "cmp" and len(cmp[1]) == 2:
        a, b = cmp[1]
        return lf._bin(lf._cast_u(a), ">=", lf._cast_u(b))
    return "0"


def _wide(i):
    return any(op.type == x86.X86_OP_REG and i.reg_name(op.reg).startswith("ymm") for op in i.operands)


# ---- arm64 ----------------------------------------------------------------
def _arm(lf, i, regs):
    m, ops = i.mnemonic, i.operands
    op = lambda n: lf._op(ops[n], i, regs)
    vector = bool(_VEC.search(i.op_str))
    if m in _ARM_PAC:
        return None  # pointer authentication: security plumbing, no data-flow meaning
    if m in ("udf", "brk", "hlt"):
        return "__builtin_trap();"
    if m in ("dmb", "dsb", "isb", "yield", "prfm", "prfum", "clrex", "csdb", "esb", "sev", "wfe", "wfi"):
        return None
    if m in ("msub", "smsubl", "umsubl") and len(ops) == 4:   # d = c - a*b
        return lf._assign(ops[0], lf._bin(op(3), "-", lf._bin(op(1), "*", op(2))), i, regs)
    if m in ("smaddl", "umaddl") and len(ops) == 4:           # d = a*b + c
        return lf._assign(ops[0], lf._bin(lf._bin(op(1), "*", op(2)), "+", op(3)), i, regs)
    if m in ("smnegl", "umnegl") and len(ops) == 3:
        return lf._assign(ops[0], f"-({lf._bin(op(1), '*', op(2))})", i, regs)
    if m in ("ubfx", "sbfx") and len(ops) == 4:               # extract `width` bits at `lsb`
        lsb, w = ops[2].imm, ops[3].imm
        e = f"({op(1)} >> {lsb}) & {hex((1 << w) - 1)}"
        return lf._assign(ops[0], e if m == "ubfx" else _cast(lf, "(int64_t)", e), i, regs)
    if m in ("ubfiz", "sbfiz") and len(ops) == 4:             # insert in zero: (x & mask) << lsb
        lsb, w = ops[2].imm, ops[3].imm
        return lf._assign(ops[0], f"({op(1)} & {hex((1 << w) - 1)}) << {lsb}", i, regs)
    if m in ("bfi", "bfxil") and len(ops) == 4:
        lsb, w = ops[2].imm, ops[3].imm
        mask = (1 << w) - 1
        src = f"({op(1)} >> {lsb}) & {hex(mask)}" if m == "bfxil" else f"({op(1)} & {hex(mask)}) << {lsb}"
        keep = hex(~mask & 0xFFFFFFFFFFFFFFFF) if m == "bfxil" else hex(~(mask << lsb) & 0xFFFFFFFFFFFFFFFF)
        return lf._assign(ops[0], f"({op(0)} & {keep}) | ({src})", i, regs)
    if m == "extr" and len(ops) == 4:
        return lf._assign(ops[0], f"__extr({op(1)}, {op(2)}, {ops[3].imm})", i, regs)
    if m in _ARM_EXT and len(ops) == 2:
        v = _cast(lf, _ARM_EXT[m], op(1))
        if (i.reg_name(ops[0].reg) or "w")[0] == "x":
            v = f"(int64_t){v}"           # sxtw x8, w0: a 64-bit value, so later math is 64-bit
        return lf._assign(ops[0], v, i, regs)
    if m in _ARM_BITS and len(ops) == 2 and not vector:
        w32 = (i.reg_name(ops[0].reg) or "x")[0] == "w"
        x = op(1)
        u = _cast(lf, "(uint32_t)" if w32 else "(uint64_t)", x)
        expr = {   # width-exact, and defined where the C builtins are not (clz of 0 is the width)
            "rbit": f"__builtin_bitreverse{32 if w32 else 64}({u})",
            "clz": f"__builtin_clzg({u}, {32 if w32 else 64})",
            "cls": f"__builtin_clrsb{'' if w32 else 'll'}({_cast(lf, '(int32_t)' if w32 else '(int64_t)', x)})",
            "rev": f"__builtin_bswap{32 if w32 else 64}({u})",
            "rev32": f"__builtin_bswap32({u})" if w32 else
                     f"__builtin_rotateright64(__builtin_bswap64({u}), 32)",
            "rev16": f"__builtin_rotateright32(__builtin_bswap32({u}), 16)" if w32 else
                     f"((({u} & 0x00ff00ff00ff00ffull) << 8) | (({u} >> 8) & 0x00ff00ff00ff00ffull))",
        }.get(m, f"{_ARM_BITS[m]}({x})")
        return lf._assign(ops[0], expr, i, regs)
    if m in ("cinc", "cinv", "cneg") and len(ops) == 2:       # cinc d, s, cc
        cond = lf._cc_expr(regs.get("__cmp__"), lf._cc_name(i))
        s = op(1)
        alt = {"cinc": lf._bin(s, "+", "1"), "cinv": f"~{lf._paren(s)}", "cneg": lf._neg(s)}[m]
        return lf._assign(ops[0], f"({cond}) ? {alt} : {s}", i, regs)
    if m in ("ccmp", "ccmn") and len(ops) >= 2:
        # conditional compare chains a second test onto the first (a && b / a || b); keep the newest
        # comparison so the branch still reads as a real condition.
        regs["__cmp__"] = ("cmp" if m == "ccmp" else "cmn", [op(0), op(1)])
        return None
    if m in ("adc", "sbc", "adcs", "sbcs", "ngc", "ngcs") and len(ops) >= 2:
        c = _carry_arm(lf, regs)
        if m.startswith("ngc"):                          # ngc d, s  =  0 - s - !C
            return lf._assign(ops[0], f"{lf._neg(op(1))} - !({c})", i, regs)
        if m.startswith("adc"):                          # adc: a + b + C
            return lf._assign(ops[0], lf._bin(lf._bin(op(1), "+", op(2)), "+", f"({c})"), i, regs)
        return lf._assign(ops[0], lf._bin(lf._bin(op(1), "-", op(2)), "-", f"!({c})"), i, regs)  # sbc: a - b - !C
    # ---- floating point / NEON
    if m in ("fcmp", "fcmpe"):
        regs["__cmp__"] = ("cmp", [op(0), op(1) if len(ops) > 1 else "0.0"])
        return None
    if m == "fcsel" and len(ops) == 3:
        cond = lf._cc_expr(regs.get("__cmp__"), lf._cc_name(i))
        return lf._assign(ops[0], f"({cond}) ? {op(1)} : {op(2)}", i, regs)
    r = neon.lift(lf, i, regs)          # lane-exact NEON via vector extensions (compilable C)
    if r is not neon.NA:
        return r
    if m == "movi" and len(ops) == 2:
        imm = ops[1].imm if ops[1].type == a64.ARM64_OP_IMM else None
        return lf._assign(ops[0], "0" if imm == 0 else f"vdupq_n({imm if imm is not None else op(1)})", i, regs)
    if not vector:
        if m in _ARM_FBIN and len(ops) == 3:
            return lf._assign(ops[0], lf._bin(op(1), _ARM_FBIN[m], op(2)), i, regs)
        if m == "fnmul" and len(ops) == 3:
            return lf._assign(ops[0], f"-({lf._bin(op(1), '*', op(2))})", i, regs)
        if m in ("fmadd", "fmsub", "fnmadd", "fnmsub") and len(ops) == 4:
            prod = lf._bin(op(1), "*", op(2))
            e = {"fmadd": lf._bin(prod, "+", op(3)), "fmsub": lf._bin(op(3), "-", prod),
                 "fnmadd": f"-({lf._bin(prod, '+', op(3))})", "fnmsub": lf._bin(prod, "-", op(3))}[m]
            return lf._assign(ops[0], e, i, regs)
        if m == "fneg" and len(ops) == 2:
            return lf._assign(ops[0], lf._neg(op(1)), i, regs)
        if m in _ARM_FFN:
            args = [op(n) for n in range(1, len(ops))]
            return lf._assign(ops[0], f"{_ARM_FFN[m]}({', '.join(args)})", i, regs)
        if m == "fmov" and len(ops) == 2:
            src = ops[1]
            v = repr(src.fp) if src.type == a64.ARM64_OP_FP else op(1)
            return lf._assign(ops[0], v, i, regs)
        if m in ("scvtf", "ucvtf") and len(ops) >= 2:
            t = "double" if i.reg_name(ops[0].reg).startswith("d") else "float"
            return lf._assign(ops[0], _cast(lf, f"({t})", op(1)), i, regs)
        if m in _ARM_CVT_INT and len(ops) >= 2:
            t = "uint64_t" if m.endswith("u") else "int64_t"
            return lf._assign(ops[0], _cast(lf, f"({t})", op(1)), i, regs)
        if m == "fcvt" and len(ops) == 2:
            t = {"d": "double", "s": "float", "h": "_Float16"}.get(i.reg_name(ops[0].reg)[0], "double")
            return lf._assign(ops[0], _cast(lf, f"({t})", op(1)), i, regs)
    if m.startswith(("ld1", "ld2", "ld3", "ld4")) and ops and ops[-1].type == a64.ARM64_OP_MEM:
        addr = lf._addr(ops[-1], i, regs)
        return lf._assign(ops[0], f"v{m.split('.')[0]}q({addr})", i, regs)
    if m.startswith(("st1", "st2", "st3", "st4")) and ops and ops[-1].type == a64.ARM64_OP_MEM:
        addr = lf._addr(ops[-1], i, regs)
        return f"v{m.split('.')[0]}q({addr}, {op(0)});"
    if m in ("mov", "orr") and vector and "[" not in i.op_str and len(ops) in (2, 3) \
            and (len(ops) == 2 or ops[1].reg == ops[2].reg):
        return lf._assign(ops[0], op(1), i, regs)            # register-to-register vector move
    if m in ("umov", "smov", "mov", "ins") and len(ops) == 2 and "[" in i.op_str and vector:
        lane = re.search(r"\[(\d+)\]", i.op_str)
        idx = lane.group(1) if lane else "0"
        if "[" in i.op_str.split(",")[0]:               # mov v0.s[1], w1  -> insert lane
            return lf._assign(ops[0], f"vsetq_lane({op(1)}, {op(0)}, {idx})", i, regs)
        return lf._assign(ops[0], f"vgetq_lane({op(1)}, {idx})", i, regs)
    if m == "dup" and len(ops) == 2:
        return lf._assign(ops[0], f"vdupq_n({op(1)})", i, regs)
    if m in ("addv", "uaddlv", "saddlv", "addp") and len(ops) == 2:
        inner = op(1)                                   # horizontal sum of a per-byte popcount = popcount
        mp = re.fullmatch(r"vcntq\((.*)\)", inner)
        if mp:
            return lf._assign(ops[0], f"__builtin_popcountll({mp.group(1)})", i, regs)
        return lf._assign(ops[0], f"vaddvq({inner})", i, regs)
    if vector and ops and ops[0].type == a64.ARM64_OP_REG:
        # NEON: ACLE-style intrinsic named after the operation (vaddq, vzip1q, vcmeqq, ...)
        args = [op(n) for n in range(1, len(ops))]
        return lf._assign(ops[0], f"v{m}q({', '.join(args)})", i, regs)
    return NA
