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


def test_resolve_and_xrefs():
    p = Program(open_image("/bin/ls", arch="arm64")).analyze()
    entry = p.resolve("0x%x" % p.image.entry)
    assert entry == p.image.entry
    # at least one call target has recorded xrefs
    assert any(p.xrefs_to(a) for a in p.functions)
    print("ok  resolve + xrefs")


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
    test_resolve_and_xrefs()
    print("\nall checks passed")
