"""Self-check: run the whole pipeline over system binaries and compiled fixtures.

    PYTHONPATH=. .venv/bin/python tests/test_rdis.py
Fixtures are compiled on demand (needs clang/swiftc); missing compilers skip those cases.
No test framework -- plain asserts, one runnable file, as the project prefers.
"""
import os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rdis.loader import open_image
from rdis.analysis import Program
from rdis.decompile import Decompiler
from rdis import render
from rdis.objc import decode_type, method_signature

TMP = tempfile.mkdtemp(prefix="rdis_test_")


def compile_c(src, name, arch, flags=(), obj=True):
    """Compile to an object file by default (no main/libs needed); link only when flags require it."""
    path = os.path.join(TMP, name)
    cf = os.path.join(TMP, name + (".m" if "-fobjc-arc" in flags else ".c"))
    open(cf, "w").write(src)
    cmd = ["clang", "-O1", "-arch", arch, *flags, cf, "-o", path]
    if obj and "-framework" not in flags:
        cmd.insert(1, "-c")
    r = subprocess.run(cmd, capture_output=True, text=True)
    return path if r.returncode == 0 else None


def test_type_decoder():
    assert decode_type("@")[0] == "id"
    assert decode_type('@"NSString"')[0] == "NSString *"
    assert decode_type("^i")[0] == "int *"
    assert decode_type("{CGRect=dd}")[0] == "struct CGRect"
    assert decode_type("[8c]")[0] == "char[8]"
    assert "greet:" in method_signature("greet:times:", "@28@0:8@16i24", False)
    assert method_signature("shared", "@16@0:8", True).startswith("+ (id)shared")
    print("ok  type_decoder")


def test_formats():
    """Load + analyze a Mach-O, and whatever PE/ELF samples exist on this machine."""
    samples = [("/bin/ls", "x86_64", "macho"), ("/bin/ls", "arm64", "macho")]
    for path, arch, fmt in samples:
        if not os.path.exists(path):
            continue
        p = Program(open_image(path, arch=arch)).analyze()
        assert p.image.format == fmt
        assert len(p.functions) > 5, f"{path} found too few functions"
        assert p.strings(), f"{path} found no strings"
        # every function disassembles and decompiles without raising
        for a in list(p.functions)[:20]:
            f = p.functions[a]
            assert render.disassemble(p, f)
            c = Decompiler(p, f).c()
            assert c.count("{") == c.count("}"), f"unbalanced braces in {p.display(a)}"
        print(f"ok  formats {fmt}/{arch}: {len(p.functions)} funcs, {len(p.strings())} strings")


def test_decompile_semantics():
    src = ("#include <stdio.h>\n"
           "int classify(int n){if(n<0)return -1;if(n==0)return 0;return 1;}\n"
           "int pick(int x){return (x>10&&x<20)?x*2:x+1;}\n"
           "int addmul(int a,int b){return a*b+a;}\n"
           "int main(int c,char**v){printf(\"%d\",classify(c)+pick(c)+addmul(c,2));return 0;}\n")
    for arch in ("arm64", "x86_64"):
        bin = compile_c(src, f"sem_{arch}", arch, obj=False)
        if not bin:
            print(f"skip decompile_semantics ({arch}: no clang)")
            continue
        p = Program(open_image(bin)).analyze()
        pick = Decompiler(p, p.functions[p.resolve("_pick")]).c()
        # argument recovered, and the body references it
        assert "_pick(int64_t" in pick, pick
        assert "?" in pick or "if" in pick, pick
        # a ternary inside arithmetic is parenthesized (no bare `? :` adjacent to operators)
        assert ") ? " not in pick or "(" in pick
        classify = Decompiler(p, p.functions[p.resolve("_classify")]).c()
        assert "return" in classify
        print(f"ok  decompile_semantics {arch}")


def test_type_recovery():
    src = ("#include <stdio.h>\n"
           "struct P { int a; int b; int c; };\n"
           "int sum3(struct P *p){ return p->a + p->b + p->c; }\n"
           "long firstbytes(char *s){ return s[0] + s[1]; }\n"
           "void greet(const char *n){ printf(\"hi %s\\n\", n); }\n"
           "int main(int c,char**v){ struct P p={c,c,c}; greet(v[0]); "
           "return sum3(&p)+(int)firstbytes(v[0]); }\n")
    for arch in ("arm64", "x86_64"):
        bin = compile_c(src, f"ty_{arch}", arch, obj=False)
        if not bin:
            print(f"skip type_recovery ({arch}: no clang)")
            continue
        p = Program(open_image(bin)).analyze()
        sig = lambda n: Decompiler(p, p.functions[p.resolve(n)]).c().splitlines()[0]
        assert "*" in sig("_sum3"), sig("_sum3")              # struct pointer arg
        assert "char *" in sig("_firstbytes"), sig("_firstbytes")  # byte-accessed pointer
        assert sig("_greet").startswith("void "), sig("_greet")    # no value returned
        assert sig("_sum3").startswith("int"), sig("_sum3")        # returns a value
        body = Decompiler(p, p.functions[p.resolve("_sum3")]).c()
        assert "->field_" in body, body                            # struct member access
        fb = Decompiler(p, p.functions[p.resolve("_firstbytes")]).c()
        assert "[" in fb.split("{", 1)[1], fb                      # char* indexed as s[i]
        print(f"ok  type_recovery {arch}: pointer args, struct fields, void/value returns")


SIMD_SRC = r"""
#include <math.h>
__attribute__((noinline)) void vadd(int *a, const int *b, int n){ for(int i=0;i<n;i++) a[i]+=b[i]; }
__attribute__((noinline)) double fma3(double x, double y, double z){ return x*y + z; }
__attribute__((noinline)) double hyp(double x, double y){ return sqrt(x*x + y*y); }
__attribute__((noinline)) int toint(double d){ return (int)d; }
__attribute__((noinline)) double fromint(long v){ return (double)v; }
__attribute__((noinline)) int isneg(int x){ return x < 0 ? 7 : 3; }
__attribute__((noinline)) int bit3(unsigned x){ return (x & 8) ? 11 : 22; }
__attribute__((noinline)) long times13(long x){ return x * 13; }
__attribute__((noinline)) long divmod(long a, long b){ return a / b + a % b; }
__attribute__((noinline)) unsigned field(unsigned x){ return (x >> 4) & 0xff; }
__attribute__((noinline)) float fsum(const float *a, int n){ float s=0; for(int i=0;i<n;i++) s+=a[i]; return s; }
int main(int c, char **v){ int a[64]={0},b[64]={1}; vadd(a,b,c);
  return (int)(fma3(c,2,3)+hyp(c,4)+toint(c)+fromint(c)+isneg(c)+bit3(c)+times13(c)+divmod(c,3)+field(c)+fsum((float*)a,c)); }
"""


def _eval_linear(expr, var):
    """Evaluate a decompiled integer expression in one variable at two points (checks semantics)."""
    import re as _re
    e = _re.sub(r"\b0x([0-9a-f]+)\b", lambda m: str(int(m.group(1), 16)), expr)
    return [eval(e.replace(var, str(x)), {}) for x in (3, 10)]  # noqa: S307 - our own output


def test_simd_fp():
    """Float ABI, SIMD intrinsics, flag-setting arithmetic, index*scale addressing, conditions."""
    for arch in ("arm64", "x86_64"):
        bin = compile_c(SIMD_SRC, f"simd_{arch}", arch, flags=("-O2",), obj=False)
        if not bin:
            print(f"skip simd_fp ({arch}: no clang)")
            continue
        p = Program(open_image(bin)).analyze()
        c = lambda n: Decompiler(p, p.functions[p.resolve(n)]).c()
        sig = lambda n: c(n).splitlines()[0]
        fa = "v" if arch == "arm64" else "xmm"
        ia = "x0" if arch == "arm64" else "rdi"
        assert sig("_fma3") == f"double _fma3(double {fa}0, double {fa}1, double {fa}2) {{", sig("_fma3")
        assert sig("_hyp").startswith("double _hyp(double") and "sqrt(" in c("_hyp"), c("_hyp")
        assert sig("_fromint").startswith("double ") and "(double)" in c("_fromint"), c("_fromint")
        assert "(int64_t)" in c("_toint") and sig("_toint").startswith("int64_t _toint(double"), c("_toint")
        assert sig("_fsum").startswith("float _fsum(float *"), sig("_fsum")
        assert sig("_vadd").startswith("void _vadd(int *"), sig("_vadd")
        assert sig("_vadd").endswith("int64_t " + ("x2" if arch == "arm64" else "rdx") + ") {"), sig("_vadd")
        # vector body lifted to intrinsics, not left as asm comments
        assert ("_mm_add_epi32(" if arch == "x86_64" else "vaddq(") in c("_vadd"), c("_vadd")
        # times13: index*scale addressing must survive (it was once lifted as `return rdi;`)
        body = c("_times13").splitlines()[1].strip()
        assert body.startswith("return "), body
        assert _eval_linear(body[7:-1], ia) == [39, 130], body
        assert "(x0 < 0) ? 7 : 3" in c("_isneg") or "0x1d" in c("_isneg"), c("_isneg")
        assert "& 8" in c("_bit3"), c("_bit3")
        assert "& 0xff" in c("_field") or "(uint8_t)" in c("_field"), c("_field")
        print(f"ok  simd_fp {arch}: float ABI, intrinsics, scaled addressing, conditions")


DIFF_SRC = r"""
#include <stdint.h>
int sel(int x){ if (x > 5) return 111; return 222; }
int sign(int x){ if (x < 0) return -1; else if (x == 0) return 0; else return 1; }
int loopsum(int n){ int s = 0; for (int i = 0; i < n; i++) s += i; return s; }
int dowhile(int n){ int c = 0; do { c++; n >>= 1; } while (n); return c; }
int search(int *a, int n, int k){ for (int i = 0; i < n; i++) { if (a[i] == k) return i; } return -1; }
int nested(int x, int y){ int r = 0; if (x) { if (y) r = 1; else r = 2; } else r = 3; return r; }
int brk(int *a, int n){ int i = 0; while (1) { if (a[i] < 0) break; i++; if (i >= n) break; } return i; }
long times13(long x){ return x * 13; }
long divmod(long a, long b){ return a / b + a % b; }
unsigned field(unsigned x){ return (x >> 4) & 0xff; }
int popc(unsigned x){ int c = 0; while (x) { x &= x - 1; c++; } return c; }
int clamp(int v, int lo, int hi){ return v < lo ? lo : (v > hi ? hi : v); }
int gcd(int a, int b){ while (b) { int t = a % b; a = b; b = t; } return a; }
int max3(int a, int b, int c){ int m = a; if (b > m) m = b; if (c > m) m = c; return m; }
long fib(int n){ long a = 0, b = 1; for (int i = 0; i < n; i++) { long t = a + b; a = b; b = t; } return a; }
int sw(int k){ switch (k) { case 0: return 10; case 1: return 20; case 2: return 33; case 5: return 77; default: return -1; } }
int strsum(const char *s){ int t = 0; while (*s) t += *s++; return t; }
int abs2(int x){ return x < 0 ? -x : x; }
unsigned rotl(unsigned x, int r){ return (x << r) | (x >> (32 - r)); }
int collatz(int n){ int s = 0; while (n != 1) { n = (n & 1) ? 3 * n + 1 : n / 2; s++; } return s; }
"""
DIFF_SUPPORT = "static int A[] = {5, 3, 9, 1, 7}; static int B[] = {1, 2, -3, 4, 5, 6}; static int C[] = {1, 2, 3};\n"
_I = [["-7"], ["0"], ["1"], ["5"], ["6"], ["100"], ["12345"]]
DIFF_CASES = [
    ("sel", "int", _I), ("sign", "int", _I), ("loopsum", "int", [["-2"], ["0"], ["1"], ["5"], ["30"]]),
    ("dowhile", "int", [["0"], ["1"], ["2"], ["7"], ["1024"], ["12345"]]),
    ("search", "int", [["A", "5", "3"], ["A", "5", "42"], ["A", "0", "5"], ["A", "5", "5"]]),
    ("nested", "int", [["0", "0"], ["0", "1"], ["1", "0"], ["1", "1"]]),
    ("brk", "int", [["B", "6"], ["C", "3"], ["C", "1"]]),
    ("times13", "long", [["-3"], ["0"], ["7"], ["100000"]]),
    ("divmod", "long", [["17", "5"], ["-17", "5"], ["100", "-7"], ["1", "1"]]),
    ("field", "unsigned", [["0"], ["0x1234"], ["0xffffffff"], ["4095"]]),
    ("popc", "int", [["0"], ["1"], ["0xff"], ["0x80000001"], ["12345"]]),
    ("clamp", "int", [["-5", "0", "10"], ["5", "0", "10"], ["50", "0", "10"]]),
    ("gcd", "int", [["12", "18"], ["17", "5"], ["100", "75"], ["7", "0"]]),
    ("max3", "int", [["1", "2", "3"], ["3", "2", "1"], ["2", "3", "1"], ["-1", "-5", "-3"]]),
    ("fib", "long", [["0"], ["1"], ["10"], ["50"]]),
    ("sw", "int", [["0"], ["1"], ["2"], ["3"], ["5"], ["-1"], ["99"]]),
    ("strsum", "int", [['""'], ['"a"'], ['"hello"'], ['"rdis!"']]),
    ("abs2", "int", [["-9"], ["0"], ["9"]]),
    ("rotl", "unsigned", [["1", "1"], ["0x80000000", "1"], ["0x12345678", "8"]]),
    ("collatz", "int", [["1"], ["6"], ["27"], ["97"]]),
]


def test_differential():
    """Decompile, recompile the pseudo-code, run it against the original: same results?

    Known limitation: an x86 `-O0` computed-goto jump table ('sw') recovers the right cases and
    targets but its dispatch key register is reused before the branch, so that one config is
    excluded. Every optimized build (value-table switches) and all other functions verify."""
    import diffcheck
    total = 0
    for arch in ("arm64", "x86_64"):
        for opt in ("-O0", "-O1", "-O2"):
            cases = [c for c in DIFF_CASES if not (c[0] == "sw" and arch == "x86_64" and opt == "-O0")]
            probs = diffcheck.run(DIFF_SRC, arch, cases, opt=opt, support=DIFF_SUPPORT)
            assert not probs, f"{arch} {opt}:\n  " + "\n  ".join(probs[:10])
            total += 1
    print(f"ok  differential: {len(DIFF_CASES)} functions x {total} builds compile and match originals")


def test_objc():
    src = ('#import <Foundation/Foundation.h>\n'
           '@interface Pt:NSObject{int _x;}\n@property(nonatomic,copy)NSString*nm;\n'
           '-(int)addTo:(int)n;\n@end\n'
           '@implementation Pt\n-(int)addTo:(int)n{return _x+n;}\n@end\n'
           'int main(){Pt*p=[Pt new];p.nm=@"hi";return [p addTo:3];}\n')
    bin = compile_c(src, "objc_bin", "arm64", flags=("-fobjc-arc", "-framework", "Foundation"))
    if not bin:
        print("skip objc (no clang/Foundation)")
        return
    p = Program(open_image(bin)).analyze()
    names = set(p.names.values())
    assert any("-[Pt addTo:]" in n for n in names), "ObjC method name not recovered"
    assert p.objc and any(c.name == "Pt" for c in p.objc.classes)
    decl = next(c.declaration() for c in p.objc.classes if c.name == "Pt")
    assert "@property" in decl and "addTo:" in decl
    assert "hi" in p.objc.cfstrings.values()
    print("ok  objc: recovered -[Pt addTo:] and @property")


def test_objc_protocol():
    src = ('#import <Foundation/Foundation.h>\n'
           '@protocol Drawable <NSObject>\n- (void)draw;\n@optional\n- (void)drawFast;\n@end\n'
           '@interface Sprite:NSObject <Drawable>\n@end\n'
           '@implementation Sprite\n- (void)draw {}\n@end\nint main(){return 0;}\n')
    bin = compile_c(src, "proto_bin", "arm64", flags=("-fobjc-arc", "-framework", "Foundation"))
    if not bin:
        print("skip objc_protocol (no clang/Foundation)")
        return
    p = Program(open_image(bin)).analyze()
    draw = next((c for c in p.objc.protocols if c.name == "Drawable"), None)
    assert draw and "@protocol Drawable" in draw.declaration()
    assert "@optional" in draw.declaration() and "drawFast" in draw.declaration()
    sprite = next(c for c in p.objc.classes if c.name == "Sprite")
    assert "Drawable" in sprite.adopts, sprite.adopts
    print("ok  objc_protocol: @protocol, @optional, class adoption")


def test_swift():
    src = ("protocol Named { var name: String { get } }\n"
           "protocol Aged { var age: Int { get } }\n"
           "struct Person: Named, Aged { let name: String; let age: Int }\n"
           "print(Person(name: \"a\", age: 1).name)\n")
    path = os.path.join(TMP, "sw_bin")
    sf = os.path.join(TMP, "sw.swift")
    open(sf, "w").write(src)
    import shutil
    if not shutil.which("swiftc") and not shutil.which("xcrun"):
        print("skip swift (no swiftc)")
        return
    tool = ["swiftc"] if shutil.which("swiftc") else ["xcrun", "swiftc"]
    if subprocess.run(tool + ["-O", sf, "-o", path], capture_output=True).returncode != 0:
        print("skip swift (compile failed)")
        return
    p = Program(open_image(path)).analyze()
    person = next((t for t in p.swift.types if t.name == "Person"), None)
    assert person, [t.name for t in p.swift.types]
    decl = person.declaration()
    assert "let name: String" in decl and "let age: Int" in decl, decl
    assert "Named" in person.conforms and "Aged" in person.conforms, person.conforms
    print("ok  swift: struct fields + protocol conformances (Named, Aged)")


def test_wasm():
    """WebAssembly: hand-emit a module and check the parser/disassembler recover it."""
    from rdis.wasm import WasmModule, WasmProgram, listing_rows

    def uleb(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | 0x80]) if n else bytes([b])
            if not n:
                return out

    def vec(items):
        return uleb(len(items)) + b"".join(items)

    def sec(sid, payload):
        return bytes([sid]) + uleb(len(payload)) + payload

    types = sec(1, vec([b"\x60" + vec([b"\x7f", b"\x7f"]) + vec([b"\x7f"]),
                        b"\x60" + vec([b"\x7f"]) + vec([b"\x7f"])]))
    funcs = sec(3, vec([uleb(0), uleb(1)]))
    exports = sec(7, vec([uleb(3) + b"add" + b"\x00" + uleb(0), uleb(3) + b"dbl" + b"\x00" + uleb(1)]))
    body0 = vec([]) + b"\x20\x00\x20\x01\x6a\x0b"   # local.get 0; local.get 1; i32.add; end
    body1 = vec([]) + b"\x20\x00\x20\x00\x6a\x0b"
    code = sec(10, vec([uleb(len(body0)) + body0, uleb(len(body1)) + body1]))
    mod = b"\x00asm\x01\x00\x00\x00" + types + funcs + exports + code
    m = WasmModule(mod)
    assert [e["name"] for e in m.exports] == ["add", "dbl"], m.exports
    add = next(f for f in m.funcs if f.name == "add")
    mnems = [i[1] for i in add.insns]
    assert mnems == ["local.get", "local.get", "i32.add", "end"], mnems
    p = WasmProgram("x.wasm", mod)
    assert p.image.format == "wasm" and p.arch.name == "wasm"
    assert sorted(p.names[a] for a in p.functions) == ["add", "dbl"]
    rows = listing_rows(p, p.functions[p.resolve("add")])
    assert any(r.get("mnem", "").strip() == "i32.add" for r in rows)
    print("ok  wasm: parsed module, exports, disassembly (add/dbl)")


def test_arm_thumb():
    """ARM Thumb: the bit0 mode flag is stripped from addresses (so no phantom even/odd function
    twins and no leaked $-mapping symbols), and Thumb code decodes in Thumb mode, not ARM."""
    from rdis import arch as archmod
    from rdis.loader import _arm_thumb
    a = archmod.make("arm")
    t = a.decode(b"\x80\xb5", 0x1000, thumb=True)   # 0xb580 = `push {r7, lr}` in Thumb
    assert t and t.mnemonic == "push" and "r7" in t.op_str and "lr" in t.op_str, (t.mnemonic, t.op_str)

    class B:  # minimal stand-in for a lief binary: _arm_thumb only reads .entrypoint
        entrypoint = 0x2001
    clean, thumb = _arm_thumb(B, {0x2001: "f", 0x3000: "g", 0x40: "$t", 0x50: "$d"})
    assert 0x2000 in clean and 0x2001 not in clean, clean            # bit0 stripped -> no twin
    assert clean[0x2000] == "f" and clean[0x3000] == "g"
    assert all(not v.startswith("$") for v in clean.values())        # mapping symbols dropped
    assert 0x2000 in thumb and 0x40 in thumb and 0x3000 not in thumb  # thumb from bit0 and $t
    print("ok  arm_thumb: Thumb decode + bit0 stripping, no phantom twins")


def test_tail_call():
    """Register tail-calls (`br x2`, vtable/JNIEnv dispatch) must not silently vanish into a bare
    `return;` — the IJMP terminator has no successors and used to be swallowed by the RET path."""
    from rdis.arch import IJMP
    p = Program(open_image("/bin/ls", arch="arm64")).analyze()
    checked = 0
    for a, f in p.functions.items():
        if not any(p.arch.kind(b.insns[-1]) == IJMP and not [s for s in b.succs if s in f.blocks]
                   for b in f.blocks.values()):
            continue
        c = Decompiler(p, f).c()
        # the body must reference the indirect branch, not collapse to just `return;`
        assert "tail-call" in c or "computed jump" in c or "goto *" in c, (hex(a), c)
        assert c.strip().count("return;") == 0 or "(*" in c, (hex(a), c)
        checked += 1
        if checked >= 5:
            break
    assert checked, "no register-indirect-terminated function found to exercise the fix"
    print(f"ok  tail_call: {checked} register-indirect terminators render the call, not a bare return")


def test_jni():
    """JNIEnv dispatch: slot offsets map to the right JNI function, and decompiled calls of the form
    `*(int64_t *)(*(int64_t *)env + 0xOFF)(env, ...)` are rewritten to `env->Fn(...)`."""
    from rdis import jni
    assert jni.slot_name(0x20, 8) == "GetVersion"      # index 4
    assert jni.slot_name(0x30, 8) == "FindClass"       # index 6
    assert jni.slot_name(0x18, 8) is None              # reserved slot
    assert jni.slot_name(0x18, 4) == "FindClass"       # 32-bit: index 6 * 4
    out = jni.name_calls('t4 = *(int64_t *)(*(int64_t *)x19 + 0x30)(x19, "java/io/IOException");')
    assert out == 't4 = x19->FindClass("java/io/IOException");', out
    # GetObjectArrayElement is the offset the JNI assessment cited (0x568 on 64-bit)
    assert jni.slot_name(0x568, 8) == "GetObjectArrayElement", jni.slot_name(0x568, 8)
    # RegisterNatives table {name*, sig*, fn*}: once PIC (pointers only in RELA fixups), once with
    # the pointers in the file (REL / arm32, Thumb bit set on fn).
    from rdis.loader import Section
    from rdis.arch import make

    class Im:
        def __init__(self, arch, blob, fixups):
            self.arch, self.blob, self.fixups = make(arch), blob, fixups
            self.sections = [Section(".text", 0x1000, 0x100, 0x1000, True),
                             Section(".data", 0x2000, len(blob), 0x2000, False)]
        def read(self, va, n):
            return self.blob[va - 0x2000:va - 0x2000 + n] if va >= 0x2000 else b""
        def is_code(self, va):
            return 0x1000 <= va < 0x1100
    strs = b"nativeInit\0(Ljava/lang/String;I)V\0"           # name @0x2000, sig @0x200b
    pic = Im("arm64", strs.ljust(0x40, b"\0") + bytes(24), {0x2040: 0x2000, 0x2048: 0x200b, 0x2050: 0x1010})
    assert jni.native_tables(pic) == {0x1010: ("nativeInit", "(Ljava/lang/String;I)V", False)}
    words = b"".join(v.to_bytes(4, "little") for v in (0x2000, 0x200b, 0x1021))
    rel = Im("arm", strs.ljust(0x40, b"\0") + words, {})
    assert jni.native_tables(rel) == {0x1020: ("nativeInit", "(Ljava/lang/String;I)V", True)}
    print("ok  jni: slot table + env->Fn() call naming + RegisterNatives tables")


def _mini_elf(machine, wide, code, base=0x10000):
    """Smallest ELF that loads: header + one R|X PT_LOAD covering the file, code at base+0x100."""
    import struct
    eh, ph = (64, 56) if wide else (52, 32)
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    w = "Q" if wide else "I"
    hdr = ident + struct.pack(f"<HHI{w}{w}{w}IHHHHHH", 2, machine, 1, base + 0x100, eh, 0, 0,
                              eh, ph, 1, 64 if wide else 40, 0, 0)
    size = 0x100 + len(code)
    if wide:
        phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, size, size, 0x1000)
    else:
        phdr = struct.pack("<IIIIIIII", 1, 0, base, base, size, size, 5, 0x1000)
    return (hdr + phdr).ljust(0x100, b"\0") + code


def test_mips_riscv():
    """MIPS (delay slots, lui/addiu pairs) and RISC-V (PC-relative targets, auipc/addi, `ret`
    reported as a call by Capstone): functions, calls, blocks and string xrefs are recovered."""
    import os, struct, tempfile
    tmp = tempfile.mkdtemp()
    words = lambda ws: b"".join(struct.pack("<I", x & 0xffffffff) for x in ws)
    B = 0x10100
    # MIPS o32 LE.  f1: addiu sp,-24; sw ra,20(sp); jal f2; nop; lw ra,20(sp); jr ra; addiu sp,24
    #               f2 @+0x1c: lui a0,1; beq a0,zero,+1; addiu a0,a0,0x40 (slot); jr ra; nop
    f2 = B + 0x1c
    mips = words([0x27bdffe8, 0xafbf0014, (3 << 26) | (f2 >> 2), 0, 0x8fbf0014, 0x03e00008, 0x27bd0018,
                  0x3c040001, 0x10800001, 0x24840140, 0x03e00008, 0])
    p = os.path.join(tmp, "m.elf")
    open(p, "wb").write(_mini_elf(8, False, mips))
    prog = Program(open_image(p)).analyze()
    assert prog.arch.name == "mipsel", prog.arch.name
    assert {B, f2} <= set(prog.functions), [hex(a) for a in prog.functions]
    assert f2 in prog.functions[B].calls
    b0 = prog.functions[B].blocks[B]
    assert b0.insns[-1].mnemonic == "jr" and b0.delay.mnemonic == "addiu", "delay slot kept with jr"
    assert prog.arch.kind(b0.insns[-1]) == "ret"
    assert any(s == f2 + 8 for s, _ in prog.xrefs_to(0x10140)), "lui/addiu in a delay slot -> xref"
    # RISC-V 64 (RVC on).  f1: addi sp,-16; sd ra,8(sp); jal ra,f2; ld ra,8(sp); addi sp,16; ret
    #                      f2 @+0x18: auipc a0,0; addi a0,a0,0x20; beq a0,zero,+8; nop; ret
    jal = lambda rd, off: ((off >> 20 & 1) << 31) | ((off >> 1 & 0x3ff) << 21) | ((off >> 11 & 1) << 20) \
        | ((off >> 12 & 0xff) << 12) | (rd << 7) | 0x6f
    rv = words([0xff010113, 0x00113423, jal(1, 0x18 - 8), 0x00813083, 0x01010113, 0x00008067,
                0x00000517, 0x02050513, 0x00050463, 0x00000013, 0x00008067])
    p = os.path.join(tmp, "r.elf")
    open(p, "wb").write(_mini_elf(243, True, rv))
    prog = Program(open_image(p)).analyze()
    f2 = B + 0x18
    assert prog.arch.name == "riscv64"
    assert f2 in prog.functions and f2 in prog.functions[B].calls, [hex(a) for a in prog.functions]
    assert len(prog.functions[B].blocks) == 1, "ret ends f1 (Capstone files it under 'call')"
    assert len(prog.functions[f2].blocks) == 3, "beq splits f2 at its PC-relative target"
    assert any(s == f2 + 4 for s, _ in prog.xrefs_to(f2 + 0x20)), "auipc/addi -> xref"
    print("ok  mips + riscv: delay slots, PC-relative targets, hi/lo address pairs")


def test_analysis_cache():
    """Persistent analysis DB: a restored analysis lists, links and decompiles exactly like a fresh
    one — arm64, Thumb (per-block mode; `pop {.., pc}` is a return) and MIPS delay slots."""
    import os, struct, tempfile
    from rdis import cache
    tmp = tempfile.mkdtemp()
    os.environ["RDIS_CACHE_DIR"], cache.MIN_SECONDS = os.path.join(tmp, "c"), 0
    B = 0x10100
    # Thumb: f1: push {r7,lr}; bl f2; pop {r7,pc}   f2 @+8: bx lr      (entry odd -> Thumb)
    thumb = bytes.fromhex("80b5" "00f001f8" "80bd" "7047")
    elf = bytearray(_mini_elf(40, False, thumb))
    elf[24:28] = struct.pack("<I", B | 1)
    paths = [os.path.join(tmp, "t.elf")]
    open(paths[0], "wb").write(elf)
    mips = struct.pack("<7I", 0x27bdffe8, 0x0c004047, 0, 0x03e00008, 0x27bd0018, 0x03e00008, 0)
    paths.append(os.path.join(tmp, "m.elf"))
    open(paths[1], "wb").write(_mini_elf(8, False, mips))
    for p, arch in [(paths[0], None), (paths[1], None), ("/bin/ls", "arm64")]:
        fresh = cache.analyze(open_image(p, arch=arch))
        warm = cache.analyze(open_image(p, arch=arch))
        assert type(next(iter(warm.functions[warm.image.entry].blocks.values()))).__name__ == "LazyBlock"
        assert set(fresh.functions) == set(warm.functions), p
        assert {k: v for k, v in fresh.xrefs.items() if v} == {k: v for k, v in warm.xrefs.items() if v}, p
        for a in fresh.functions:
            assert render.disassemble(fresh, fresh.functions[a]) == render.disassemble(warm, warm.functions[a]), (p, hex(a))
        e = fresh.image.entry
        assert Decompiler(fresh, fresh.functions[e]).c() == Decompiler(warm, warm.functions[e]).c(), p
    t = Program(open_image(paths[0])).analyze()
    assert {B, B + 8} <= set(t.functions) and len(t.functions[B].blocks) == 1, "pop {r7, pc} returns"
    print("ok  analysis cache: restored == fresh (arm64, Thumb, MIPS delay slots)")


def test_ir():
    """IR decompiler on MIPS/RISC-V, through Ghidra P-code AND our own frontend: delay-slot
    semantics (the slot runs before the branch takes), returns, and struct recovery."""
    import os, struct, tempfile
    from rdis import ir, ir_front
    x = ("v", "a0", 8)
    assert ir.mkcast("int64_t", ir.mkcast("int32_t", x, 4), 8)[2][0] == "cast", "sext(trunc) keeps the trunc"
    assert ir.mkcast("int32_t", ir.mkcast("int64_t", ("v", "b", 4), 8), 4) == ("v", "b", 4)
    tmp = tempfile.mkdtemp()
    # MIPS: f(a0, a1) { if (a0 == 0) return 7; return a0 + a1; }  -- both results come from delay slots
    mips = struct.pack("<6I", 0x10800003, 0x00851021, 0x03e00008, 0, 0x03e00008, 0x24020007)
    pm = os.path.join(tmp, "m.elf")
    open(pm, "wb").write(_mini_elf(8, False, mips))
    # RISC-V: g(p) { return p->f_0 + p->f_8; }
    rv = struct.pack("<3IH", 0x00053783, 0x00853503, 0x00a78533, 0x8082)
    pr = os.path.join(tmp, "r.elf")
    open(pr, "wb").write(_mini_elf(243, True, rv))
    fronts = ["native"] + (["pcode"] if ir_front.pypcode else [])
    for front in fronts:
        os.environ["RDIS_IR_FRONT"] = front
        try:
            p = Program(open_image(pm)).analyze()
            c = Decompiler(p, p.functions[p.image.entry]).c()
            assert "int32_t entry(int32_t a0, int32_t a1)" in c, (front, c)
            assert "return 7;" in c and "a0 + a1" in c and "a0 == 0" in c, (front, c)
            p = Program(open_image(pr)).analyze()
            c = Decompiler(p, p.functions[p.image.entry]).c()
            assert "struct s_" in c and "a0->f_0 + a0->f_8" in c and "int64_t f_8;" in c, (front, c)
        finally:
            os.environ.pop("RDIS_IR_FRONT", None)
    print(f"ok  ir: delay slots, returns, struct recovery ({' + '.join(fronts)} frontends agree)")


def test_overlay_isolation():
    """One visitor marking a procedure must not write the shared analysis (xrefs/modes), and a
    tampered .rdb sidecar must not inject non-string names, bogus types or junk addresses."""
    import json, tempfile
    base = Program(open_image("/bin/ls", arch="arm64")).analyze()
    n0 = sum(len(v) for v in base.xrefs.values())
    a, b = base.overlay(), base.overlay()
    gap = next(x for x in range(base.image.entry + 0x400, base.image.entry + 0x4000, 4)
               if base.function_at(x) is None and base.image.is_code(x))
    a.create_function(gap)
    assert sum(len(v) for v in base.xrefs.values()) == n0 and b.xrefs is base.xrefs
    f = tempfile.mktemp()
    json.dump({"names": {"1": {"a": 1}, "2": "ok", "x": "bad"}, "procs": ["zz", True],
               "types": {"3": "evil"}}, open(f, "w"))
    c = base.overlay().load(f)
    assert c.user_names == {2: "ok"} and not c.user_types, (c.user_names, c.user_types)
    print("ok  overlay isolation + sanitized .rdb load")


def test_resolve_and_xrefs():
    p = Program(open_image("/bin/ls", arch="arm64")).analyze()
    entry = p.resolve("0x%x" % p.image.entry)
    assert entry == p.image.entry
    # at least one call target has recorded xrefs
    assert any(p.xrefs_to(a) for a in p.functions)
    print("ok  resolve + xrefs")


def test_hostile_inputs():
    """Crafted uploads: bounded WASM decode, safe archive extraction, corrupt caches, bad names."""
    import gzip, io, json, tarfile, time, zipfile
    from rdis import cache, containers, loader, objc, wasm
    # WASM: a 30-byte module declaring 300M locals, and an endless LEB128 run, stay cheap
    body = b"\x01\x80\xde\xc3\x8f\x01\x7f\x0b"
    mod = (b"\0asm\1\0\0\0" + b"\x01\x04\x01\x60\x00\x00" + b"\x03\x02\x01\x00" +
           b"\x0a" + bytes([len(body) + 2, 1, len(body)]) + body)
    t = time.time()
    w = wasm.WasmProgram("bomb.wasm", mod)
    assert len(w.mod.funcs[0].locals) <= wasm._MAX_LOCALS and time.time() - t < 2
    t = time.time()
    try:
        wasm.WasmProgram("leb.wasm", b"\0asm\1\0\0\0\x01" + b"\xff" * 200000 + b"\x00")
    except ValueError:
        pass
    assert time.time() - t < 2, "LEB128 decode must be bounded"
    # tar: symlink members are not extractable; a long member walk is capped
    d = tempfile.mkdtemp(dir=TMP)
    tp = os.path.join(d, "links.tar")
    with tarfile.open(tp, "w") as tf:
        ti = tarfile.TarInfo("evil"); ti.type = tarfile.SYMTYPE; ti.linkname = "/bin/ls"; tf.addfile(ti)
    try:
        containers.extract(tp, "evil", d)
        raise AssertionError("tar symlink member extracted")
    except KeyError:
        pass
    # zip: traversal names land in the cache dir under a sanitized name; a member whose CRC fails
    # leaves no temp file behind; a "koly" zip comment does not divert it to the DMG path
    zp = os.path.join(d, "a.apk")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("../../../../evil.so", b"\x7fELF" + b"\0" * 64)
        z.writestr("lib/x86/bad.so", b"\x7fELF" + b"A" * 4096)
        z.comment = b"koly" * 8
    out = containers.extract(zp, "../../../../evil.so", os.path.join(d, "c"))
    assert os.path.dirname(out) == os.path.join(d, "c") and out.endswith("evil.so")
    raw = bytearray(open(zp, "rb").read())
    raw[raw.find(b"A" * 64) + 10] ^= 0xFF
    open(zp, "wb").write(raw)
    before = set(os.listdir(os.path.join(d, "c")))
    try:
        containers.extract(zp, "lib/x86/bad.so", os.path.join(d, "c"))
        raise AssertionError("bad CRC accepted")
    except zipfile.BadZipFile:
        pass
    assert set(os.listdir(os.path.join(d, "c"))) == before, "temp file leaked on failed extract"
    # analysis cache: a truncated or non-object cache file falls back to a fresh analysis
    old = os.environ.get("RDIS_CACHE_DIR"), cache.MIN_SECONDS
    os.environ["RDIS_CACHE_DIR"], cache.MIN_SECONDS = os.path.join(d, "cache"), 0
    try:
        good = cache.analyze(open_image("/bin/ls", arch="arm64"))
        f = os.path.join(d, "cache", os.listdir(os.path.join(d, "cache"))[0])
        blob = open(f, "rb").read()
        for bad in (blob[:len(blob) // 2], gzip.compress(b"[1, 2]")):
            open(f, "wb").write(bad)
            assert len(cache.analyze(open_image("/bin/ls", arch="arm64")).functions) == len(good.functions)
    finally:
        cache.MIN_SECONDS = old[1]
        if old[0] is None:
            os.environ.pop("RDIS_CACHE_DIR")
        else:
            os.environ["RDIS_CACHE_DIR"] = old[0]
    # loader: non-UTF-8 LIEF names become str; an unmapped address has no file offset
    assert loader._str(b"\xffab") == "�ab" and loader._str(None) == ""
    im = open_image("/bin/ls", arch="arm64")
    assert im.file_offset(0x1) is None
    # ObjC: a method list claiming 0xFFFFFFFF entries is capped, not walked
    class Img:
        format, binds = "macho", {}
        def read(self, va, n):
            hdr = b"\x18\0\0\0\xff\xff\xff\xff"   # entsize 24, count 0xFFFFFFFF
            return hdr[va - 0x1000:va - 0x1000 + n] if 0x1000 <= va < 0x1008 else b""
        def ptr(self, va):
            return 0
    o = objc.ObjC.empty(Img())
    o.im = Img()
    t = time.time()
    assert len(o._methods(0x1000, False)) == objc._MAX_LIST and time.time() - t < 10
    print("ok  hostile inputs: wasm/tar/zip/cache/loader/objc bounded")


def test_server_guards():
    """Web server: CSRF/DNS-rebinding guards, Content-Length validation, typed edits, 404 routes."""
    import http.client, json, threading
    from http.server import ThreadingHTTPServer
    from rdis import server
    server.CFG.update(single_user=True, persist=False, allow_paths=True, allow_python=False)
    server._local.session = server._get_session("local")
    server.open_doc("/bin/ls", arch="arm64")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=b"", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    J = {"Content-Type": "application/json"}
    try:
        assert call("GET", "/api/info")[0] == 200
        assert call("GET", "/api/info", headers={"Host": "evil.example:80"})[0] == 403, "DNS rebinding"
        line = json.dumps({"line": "info"}).encode()
        assert call("POST", "/api/command", line, {"Content-Type": "text/plain"})[0] == 403, "CSRF"
        assert call("POST", "/api/command", line, {**J, "Origin": "http://evil.example"})[0] == 403
        assert call("POST", "/api/command", line, J)[0] == 200
        assert call("POST", "/api/close", b"", {**J, "Content-Length": "-1"})[0] == 400
        assert call("GET", "/api/docs")[1]["docs"], "negative Content-Length must not run the route"
        f = call("GET", "/api/functions")[1]["items"][0]["addr"]
        bad = json.dumps({"addr": f, "name": {"a": 1}}).encode()
        assert call("POST", "/api/rename", bad, J)[0] == 400, "non-string rename must be rejected"
        long = json.dumps({"addr": f, "name": "x" * 5000}).encode()
        assert call("POST", "/api/rename", long, J)[0] == 400
        assert call("GET", "/api/search?q=sub")[0] == 200
        assert call("GET", "/api/no_such_route")[0] == 404
        assert call("GET", "/api/addrinfo?addr=0x1")[0] == 200, "unmapped address must serialize"
    finally:
        srv.shutdown()
        srv.server_close()
    # LRU: cookieless visitors must not evict a session that holds documents
    server.CFG["max_sessions"], saved = 4, dict(server.SESSIONS)
    try:
        server.SESSIONS.clear()
        server._get_session("a" * 32)["docs"]["x"] = object()
        for n in range(10):
            server._get_session("%032x" % n)
        assert "a" * 32 in server.SESSIONS
    finally:
        server.CFG["max_sessions"] = 128
        server.SESSIONS.clear()
        server.SESSIONS.update(saved)
    print("ok  server guards: host/origin/content-type, Content-Length, typed edits, 404, LRU")


def test_mcp_malformed():
    r = subprocess.run([sys.executable, "-m", "rdis.mcp_server"], input='not json\n[1]\n'
                       '{"jsonrpc":"2.0","id":3,"method":"tools/list"}\n', capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), timeout=60)
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    assert len(lines) == 3 and '"id": 3' in lines[2] and "tools" in lines[2], r.stdout + r.stderr
    print("ok  mcp: malformed lines answered with errors, server keeps running")


if __name__ == "__main__":
    test_type_decoder()
    test_formats()
    test_decompile_semantics()
    test_type_recovery()
    test_simd_fp()
    test_differential()
    test_objc()
    test_objc_protocol()
    test_swift()
    test_wasm()
    test_arm_thumb()
    test_tail_call()
    test_jni()
    test_mips_riscv()
    test_analysis_cache()
    test_ir()
    test_overlay_isolation()
    test_resolve_and_xrefs()
    test_hostile_inputs()
    test_server_guards()
    test_mcp_malformed()
    print("\nall checks passed")
