"""Decompiler maturity suite: harder, compiler-optimized code checked by execution (diffcheck).

Three tiers, matching what a mature decompiler must handle:
  OPT    heavily optimized scalar code (-O2/-O3: unrolling, magic division, selects, inlining)
  SIMD   auto-vectorized loops (-O3 with the vectorizer on): the output must compile and agree
  STRUCT pointer-to-struct code: lists, nested structs, arrays of structs

Each tier: (C source, support globals, cases) — cases are (function, return type, [arg tuples]).
"""

OPT_SRC = r"""
#include <stdint.h>
int udiv7(unsigned x){ return x / 7; }
int sdiv10(int x){ return x / 10; }
int smod3(int x){ return x % 3; }
long mulhi(long a, long b){ return (long)(((__int128)a * b) >> 64); }
int isel(int a, int b, int c){ return a > b ? (b > c ? b : c) : a; }
int bitrev8(unsigned x){ unsigned r = 0; for (int i = 0; i < 8; i++) { r = (r << 1) | (x & 1); x >>= 1; } return r; }
int matsum(int *m, int rows, int cols){ int s = 0; for (int i = 0; i < rows; i++) for (int j = 0; j < cols; j++) s += m[i * cols + j] * (i + j); return s; }
int poly(int x){ return ((3 * x + 5) * x - 7) * x + 11; }
static int sq(int x){ return x * x; }
int sumsq(int n){ int s = 0; for (int i = 1; i <= n; i++) s += sq(i); return s; }
int cntz(unsigned x){ return x ? __builtin_ctz(x) : 32; }
int lg2(unsigned x){ return x ? 31 - __builtin_clz(x) : -1; }
long minl(long *a, int n){ long m = a[0]; for (int i = 1; i < n; i++) if (a[i] < m) m = a[i]; return m; }
int ackish(int m, int n){ while (m > 0) { n = n ? n * 2 + m : 1; m--; } return n; }
int digits(unsigned x){ int d = 1; while (x >= 10) { x /= 10; d++; } return d; }
int parity(unsigned x){ x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; x &= 0xf; return (0x6996 >> x) & 1; }
int sat8(int x){ return x < -128 ? -128 : x > 127 ? 127 : x; }
int sumarr(int *a, int n){ int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
int fact(int n){ return n <= 1 ? 1 : n * fact(n - 1); }
unsigned hash(const char *s){ unsigned h = 2166136261u; while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; } return h; }
int bsearch_i(int *a, int n, int k){ int lo = 0, hi = n - 1; while (lo <= hi) { int mid = (lo + hi) >> 1; if (a[mid] == k) return mid; if (a[mid] < k) lo = mid + 1; else hi = mid - 1; } return -1; }
int sw_dense(int k){ switch (k) { case 0: return 3; case 1: return 1; case 2: return 4; case 3: return 1; case 4: return 5; case 5: return 9; case 6: return 2; case 7: return 6; default: return 0; } }
int sw_sparse(int k){ switch (k) { case 7: return 1; case 100: return 2; case 1000: return 3; case -5: return 4; default: return 5; } }
"""
OPT_SUPPORT = ("static int S[] = {1, 3, 5, 7, 9, 11, 13}; static int M[] = {1, 2, 3, 4, 5, 6};\n"
               "static long L[] = {5, -2, 9, -7, 3};\n")
_N = [["-100"], ["-7"], ["-1"], ["0"], ["1"], ["6"], ["7"], ["99"], ["12345"], ["2147483647"]]
_U = [["0"], ["1"], ["7"], ["10"], ["255"], ["0x80000000"], ["0xffffffff"], ["123456789"]]
OPT_CASES = [
    ("udiv7", "int", _U), ("sdiv10", "int", _N), ("smod3", "int", _N),
    ("mulhi", "long", [["3", "5"], ["0x7fffffffffffffff", "3"], ["-9", "0x4000000000000000"]]),
    ("isel", "int", [["1", "2", "3"], ["3", "2", "1"], ["3", "1", "2"], ["5", "5", "5"]]),
    ("bitrev8", "int", _U), ("matsum", "int", [["M", "2", "3"], ["M", "3", "2"], ["M", "0", "3"], ["M", "1", "6"]]),
    ("poly", "int", _N), ("sumsq", "int", [["0"], ["1"], ["10"], ["100"]]),
    ("cntz", "int", _U), ("lg2", "int", _U), ("minl", "long", [["L", "5"], ["L", "1"], ["L", "3"]]),
    ("ackish", "int", [["0", "5"], ["3", "0"], ["4", "2"]]), ("digits", "int", _U), ("parity", "int", _U),
    ("sat8", "int", _N), ("sumarr", "int", [["S", "7"], ["S", "0"], ["S", "3"], ["M", "6"]]),
    ("fact", "int", [["0"], ["1"], ["5"], ["10"]]),
    ("hash", "unsigned", [['""'], ['"a"'], ['"hello world"']]),
    ("bsearch_i", "int", [["S", "7", "1"], ["S", "7", "13"], ["S", "7", "6"], ["S", "7", "7"], ["S", "0", "1"]]),
    ("sw_dense", "int", [["-1"], ["0"], ["3"], ["7"], ["8"]]),
    ("sw_sparse", "int", [["7"], ["100"], ["1000"], ["-5"], ["0"]]),
]

SIMD_SRC = r"""
#include <stdint.h>
int vsum(int *a, int n){ int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
long vdot(int *a, int *b, int n){ long s = 0; for (int i = 0; i < n; i++) s += (long)a[i] * b[i]; return s; }
int vmax(int *a, int n){ int m = a[0]; for (int i = 1; i < n; i++) m = a[i] > m ? a[i] : m; return m; }
int vcount(const unsigned char *s, int n, int c){ int k = 0; for (int i = 0; i < n; i++) k += s[i] == c; return k; }
int vaxpy(int *y, int *x, int a, int n){ for (int i = 0; i < n; i++) y[i] += a * x[i]; int s = 0; for (int i = 0; i < n; i++) s ^= y[i]; return s; }
float vfsum(float *a, int n){ float s = 0; for (int i = 0; i < n; i++) s += a[i] * 0.5f; return s; }
"""
SIMD_SUPPORT = ("static int V[40] = {3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5,0,2,8,8,4,1,9,7};\n"
                "static int W[40] = {2,7,1,8,2,8,1,8,2,8,4,5,9,0,4,5,2,3,5,3,6,0,2,8,7,4,7,1,3,5,2,6,6,2,4,9,7,7,5,7};\n"
                "static unsigned char T[64] = \"the quick brown fox jumps over the lazy dog, then the dog sleeps\";\n"
                "static int Y1[40], Y2[40]; static float F[37] = {1.5f, 2.25f, -3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};\n"
                "static int *fresh(int *y){ for (int i = 0; i < 40; i++) y[i] = i * 3 - 7; return y; }\n")
SIMD_CASES = [
    ("vsum", "int", [["V", "40"], ["V", "3"], ["V", "17"], ["V", "0"]]),
    ("vdot", "long", [["V", "W", "40"], ["V", "W", "5"], ["V", "W", "33"]]),
    ("vmax", "int", [["V", "40"], ["V", "1"], ["V", "9"], ["W", "38"]]),
    ("vcount", "int", [["T", "64", "'e'"], ["T", "64", "' '"], ["T", "5", "'q'"], ["T", "37", "'o'"]]),
    ("vaxpy", "int", [["fresh(Y1)", "W", "3", "40"], ["fresh(Y2)", "V", "-2", "19"]]),
    ("vfsum", "float", [["F", "37"], ["F", "4"], ["F", "13"]]),
]

STRUCT_SRC = r"""
#include <stdint.h>
struct node { int val; struct node *next; };
struct pt { int x, y; };
struct rect { struct pt lo, hi; int color; };
struct rec { char tag; short n; long total; double w; };
int listsum(struct node *p){ int s = 0; while (p) { s += p->val; p = p->next; } return s; }
int listlen(struct node *p){ int n = 0; for (; p; p = p->next) n++; return n; }
int area(struct rect *r){ return (r->hi.x - r->lo.x) * (r->hi.y - r->lo.y) + r->color; }
long recupd(struct rec *r, long v){ r->n += 1; r->total += v; return r->total * r->n + r->tag; }
int ptsum(struct pt *p, int n){ int s = 0; for (int i = 0; i < n; i++) s += p[i].x * 3 + p[i].y; return s; }
int inside(struct rect *r, struct pt *p){ return p->x >= r->lo.x && p->x < r->hi.x && p->y >= r->lo.y && p->y < r->hi.y; }
"""
STRUCT_SUPPORT = ("struct node N3 = {7, 0}, N2 = {-2, &N3}, N1 = {5, &N2};\n"
                  "struct rect R = {{1, 2}, {11, 7}, 4}; struct pt P[3] = {{1, 2}, {3, 4}, {-5, 6}};\n"
                  "struct pt Q1 = {5, 5}, Q2 = {0, 5}, Q3 = {10, 6};\n"
                  "struct rec RC = {'z', 3, 100, 1.5};\n"
                  "static struct rec *frc(void){ static struct rec r; r = RC; return &r; }\n")
STRUCT_CASES = [
    ("listsum", "int", [["&N1"], ["&N3"], ["0"]]), ("listlen", "int", [["&N1"], ["&N2"], ["0"]]),
    ("area", "int", [["&R"]]), ("recupd", "long", [["frc()", "5"], ["frc()", "-50"]]),
    ("ptsum", "int", [["P", "3"], ["P", "1"], ["P", "0"]]),
    ("inside", "int", [["&R", "&Q1"], ["&R", "&Q2"], ["&R", "&Q3"]]),
]

TIERS = {
    "opt": (OPT_SRC, OPT_SUPPORT, OPT_CASES, ("-O2", "-O3"), False),
    "simd": (SIMD_SRC, SIMD_SUPPORT, SIMD_CASES, ("-O3",), True),
    "struct": (STRUCT_SRC, STRUCT_SUPPORT, STRUCT_CASES, ("-O1", "-O3"), False),
}
