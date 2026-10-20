import struct
def le16(*w): return b"".join(struct.pack("<H", x & 0xffff) for x in w)
def be16(*w): return b"".join(struct.pack(">H", x & 0xffff) for x in w)
def be32(*w): return b"".join(struct.pack(">I", x & 0xffffffff) for x in w)
def le32(*w): return b"".join(struct.pack("<I", x & 0xffffffff) for x in w)

def ppc():  # f@0 calls g, beq over li, blr ; g@0x30
    f = be32(0x9421fff0, 0x7c0802a6, 0x48000001 | (0x30 - 8) & 0x03fffffc, 0x2c030000, 0x41820008, 0x38600001, 0x7c0803a6, 0x38210010, 0x4e800020)
    return (f + be32(*[0x60000000]*3)).ljust(0x30, b"\0") + be32(0x38630001, 0x4e800020), 0x10000, 0x10000, 0x10030, 3

def m68k(): # f@0: link; bsr g; tst.l d0; beq.s +2; moveq #1,d0; unlk; rts ; g
    g = 0x14
    f = be16(0x4e56, 0x0000) + be16(0x6100, g - 6) + be16(0x4a80, 0x6702, 0x7001, 0x4e5e, 0x4e75)
    return f.ljust(g, b"\0") + be16(0x4e75), 0x1000, 0x1000, 0x1000 + g, 3

def avr8(): # f@0: rcall g; cpi r24,0; breq +1; ldi r24,1; ret ; g
    g = 0x0c; k = ((g - 2) // 2) & 0xfff
    f = le16(0xd000 | k, 0x3080, 0xf009, 0xe081, 0x9508)
    return f.ljust(g, b"\0") + le16(0x9508), 0x100, 0x100, 0x100 + g, 3

def msp430(): # f: call #g; tst r12; jeq +1; mov #1,r12; ret ; g
    g = 0x0e
    f = le16(0x12b0, 0x4400 + g, 0x930c, 0x2401, 0x431c, 0x4130)
    return f.ljust(g, b"\0") + le16(0x4130), 0x4400, 0x4400, 0x4400 + g, 3

def sparc(): # f: save; call g; nop; cmp %o0,0; be L; nop; mov 1,%o0; L: ret; restore ; g: retl; nop
    g = 0x24
    f = be32(0x9de3bfa0, 0x40000000 | (((g - 4) >> 2) & 0x3fffffff), 0x01000000, 0x80a22000, 0x02800000 | 3, 0x01000000, 0x90102001, 0x81c7e008, 0x81e80000)
    return f.ljust(g, b"\0") + be32(0x81c3e008, 0x01000000), 0x2000, 0x2000, 0x2000 + g, 3

def sh4():  # f: bsr g; nop; tst r0,r0; bt L; mov #1,r0; L: rts; nop ; g: rts; nop
    g = 0x0e
    f = be16(0xb000 | ((g - 4) // 2), 0x0009, 0x2008, 0x8900, 0xe001, 0x000b, 0x0009)
    return f.ljust(g, b"\0") + be16(0x000b, 0x0009), 0x3000, 0x3000, 0x3000 + g, 3

def z80():  # f: call g; or a; jr z,+2; ld a,1; ret ; g: ret
    g = 0x0a
    f = bytes([0xcd, g, 0x00 | 0x40, 0xb7, 0x28, 0x02, 0x3e, 0x01, 0xc9])
    f = bytes([0xcd]) + struct.pack("<H", 0x4000 + g) + bytes([0xb7, 0x28, 0x02, 0x3e, 0x01, 0xc9])
    return f.ljust(g, b"\0") + bytes([0xc9]), 0x4000, 0x4000, 0x4000 + g, 3

def mos6502():  # f: jsr g; lda #0; beq +2; lda #1; rts ; g: rts
    g = 0x0b
    f = bytes([0x20]) + struct.pack("<H", 0x8000 + g) + bytes([0xa9, 0x00, 0xf0, 0x02, 0xa9, 0x01, 0x60])
    return f.ljust(g, b"\0") + bytes([0x60]), 0x8000, 0x8000, 0x8000 + g, 3

def xtensa(): # f: call0 g; beq a2,a3,L; movi a2,1; L: ret ; g: ret   (all 3-byte)
    g = 0x10
    call0 = 0x000005 | ((((g) - ((0 & ~3) + 4)) >> 2) << 6)
    f = (call0).to_bytes(3, "little") + bytes([0x37, 0x12, 0x02]) + bytes([0x22, 0xa0, 0x01]) + bytes([0x80, 0x00, 0x00])
    return f.ljust(g, b"\0") + bytes([0x80, 0x00, 0x00]), 0x4000, 0x4000, 0x4000 + g, 3

def ebpf():  # f: call g(local); jeq r0,0,+1; mov r0,1; exit ; g: mov r0,2 ; exit
    ins = lambda op, dst=0, src=0, off=0, imm=0: struct.pack("<BBhi", op, (src << 4) | dst, off, imm)
    f = ins(0x85, 0, 1, 0, 4 - 0 - 1) + ins(0x15, 0, 0, 1, 0) + ins(0xb7, 0, 0, 0, 1) + ins(0x95)
    return f + ins(0xb7, 0, 0, 0, 2) + ins(0x95), 0x1000, 0x1000, 0x1020, 3

def loongarch64():  # f: bl g; beqz $a0,L; addi.d $a0,$zero,1; L: jirl $zero,$ra,0 ; g: jirl
    g = 0x10
    bl = lambda here, tgt: 0x54000000 | ((((tgt - here) >> 2) & 0xffff) << 10) | ((((tgt - here) >> 2) >> 16) & 0x3ff)
    beqz = lambda rj, off: 0x40000000 | (((off >> 2) & 0xffff) << 10) | (rj << 5) | (((off >> 2) >> 16) & 0x1f)
    f = le32(bl(0, g), beqz(4, 8), 0x02c00000 | (1 << 10) | (0 << 5) | 4, 0x4c000020)
    return f + le32(0x4c000020), 0x1000, 0x1000, 0x1000 + g, 3

FIXTURES = {"ppc": ppc, "m68k": m68k, "avr8": avr8, "msp430": msp430, "sparc": sparc, "sh4": sh4,
            "z80": z80, "6502": mos6502, "xtensa": xtensa, "ebpf": ebpf, "loongarch64": loongarch64}


# ELF machine numbers for the CPUs above that have an ELF ABI
ELF_MACHINE = {"ppc": (20, 32, ">"), "m68k": (4, 32, ">"), "avr8": (83, 32, "<"), "msp430": (105, 32, "<"),
               "sparc": (2, 32, ">"), "sh4": (42, 32, ">"), "xtensa": (94, 32, "<"), "ebpf": (247, 64, "<"),
               "loongarch64": (258, 64, "<")}


def elf(name, code=None, section=".text", sh_flags=6, ph_flags=5, entry=None):
    """Smallest ELF that LIEF parses: one PT_LOAD and one section holding the fixture (or `code`)."""
    fixture_code, base, fixture_entry, _, _ = FIXTURES[name]()
    code = fixture_code if code is None else code
    entry = fixture_entry if entry is None else entry
    machine, bits, e = ELF_MACHINE[name]
    wide = bits == 64
    ehsize, phsize, shsize = (64, 56, 64) if wide else (52, 32, 40)
    shstr = b"\0" + section.encode() + b"\0.shstrtab\0"
    code_off = ehsize + phsize
    str_off = code_off + len(code)
    sh_off = (str_off + len(shstr) + 7) & ~7
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1 if e == "<" else 2, 1]) + b"\0" * 9
    addr = "Q" if wide else "I"
    hdr = ident + struct.pack(e + "HHI" + addr * 3 + "IHHHHHH", 2, machine, 1, entry, ehsize, sh_off, 0,
                              ehsize, phsize, 1, shsize, 3, 2)
    if wide:
        ph = struct.pack(e + "IIQQQQQQ", 1, ph_flags, code_off, base, base, len(code), len(code), 4)
    else:
        ph = struct.pack(e + "IIIIIIII", 1, code_off, base, base, len(code), len(code), ph_flags, 4)
    sec = lambda nm, ty, fl, ad, off, sz: struct.pack(
        e + "II" + addr * 4 + "IIII" if not wide else e + "IIQQQQIIQQ",
        *((nm, ty, fl, ad, off, sz, 0, 0, 1, 0) if wide else (nm, ty, fl, ad, off, sz, 0, 0, 1, 0)))
    shdrs = sec(0, 0, 0, 0, 0, 0) + sec(1, 1, sh_flags, base, code_off, len(code)) + sec(len(section) + 2, 3, 0, 0, str_off, len(shstr))
    return (hdr + ph + code + shstr).ljust(sh_off, b"\0") + shdrs, base, entry
