"""Decompile every function of a binary with Ghidra's headless decompiler (needs GHIDRA_INSTALL_DIR and a JDK).

Ghidra's output uses its own type names and helper pseudo-functions; PRELUDE defines them so the text can be
compiled, which is the same courtesy any recompilation study extends. Nothing in it changes what the code computes.
The "Decompiler Parameter ID" analysis, off by default in headless mode, is switched on so Ghidra recovers return
types and parameters; without it the comparison would handicap Ghidra.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "benchmarks", "scorecard", "ghidra")

PRELUDE = r"""
#include <stdbool.h>
typedef unsigned char undefined, undefined1, byte, uchar;
typedef unsigned short undefined2, word, ushort;
typedef unsigned int undefined4, dword, uint;
typedef unsigned long long undefined8, qword, ulonglong, ulong;
typedef long long longlong;
typedef unsigned char undefined3[3], undefined5[5], undefined6[6], undefined7[7];
#define CONCAT11(a,b) ((unsigned short)(((unsigned)(unsigned char)(a)<<8)|(unsigned char)(b)))
#define CONCAT22(a,b) ((unsigned)(((unsigned)(unsigned short)(a)<<16)|(unsigned short)(b)))
#define CONCAT44(a,b) ((unsigned long long)(((unsigned long long)(unsigned)(a)<<32)|(unsigned)(b)))
#define CONCAT412(a,b) CONCAT44(a,b)
#define SUB41(a,n) ((unsigned char)((unsigned)(a)>>(8*(n))))
#define SUB42(a,n) ((unsigned short)((unsigned)(a)>>(8*(n))))
#define SUB81(a,n) ((unsigned char)((unsigned long long)(a)>>(8*(n))))
#define SUB82(a,n) ((unsigned short)((unsigned long long)(a)>>(8*(n))))
#define SUB84(a,n) ((unsigned)((unsigned long long)(a)>>(8*(n))))
#define SUB164(a,n) ((unsigned)((unsigned __int128)(a)>>(8*(n))))
#define SUB168(a,n) ((unsigned long long)((unsigned __int128)(a)>>(8*(n))))
#define ZEXT14(a) ((unsigned)(unsigned char)(a))
#define ZEXT24(a) ((unsigned)(unsigned short)(a))
#define ZEXT48(a) ((unsigned long long)(unsigned)(a))
#define ZEXT816(a) ((unsigned __int128)(unsigned long long)(a))
#define SEXT14(a) ((int)(signed char)(a))
#define SEXT24(a) ((int)(short)(a))
#define SEXT48(a) ((long long)(int)(a))
#define SEXT816(a) ((__int128)(long long)(a))
#define CARRY4(a,b) ((unsigned)(a)+(unsigned)(b)<(unsigned)(a))
#define CARRY8(a,b) ((unsigned long long)(a)+(unsigned long long)(b)<(unsigned long long)(a))
#define SCARRY4(a,b) ((((int)(a)>=0)==((int)(b)>=0))&&((((int)((unsigned)(a)+(unsigned)(b)))>=0)!=((int)(a)>=0)))
#define SCARRY8(a,b) ((((long long)(a)>=0)==((long long)(b)>=0))&&((((long long)((unsigned long long)(a)+(unsigned long long)(b)))>=0)!=((long long)(a)>=0)))
#define SBORROW4(a,b) ((((int)(a)>=0)!=((int)(b)>=0))&&((((int)((unsigned)(a)-(unsigned)(b)))>=0)!=((int)(a)>=0)))
#define SBORROW8(a,b) ((((long long)(a)>=0)!=((long long)(b)>=0))&&((((long long)((unsigned long long)(a)-(unsigned long long)(b)))>=0)!=((long long)(a)>=0)))
#define POPCOUNT(a) __builtin_popcountll((unsigned long long)(a))
#define LZCOUNT(a) ((a)?__builtin_clzll((unsigned long long)(a))-(int)(64-8*sizeof(a)):(int)(8*sizeof(a)))
#define ROUND(a) ((double)(a))
#define halt_baddata() __builtin_trap()
"""


def available():
    head = shutil.which("analyzeHeadless") or os.path.join(os.environ.get("GHIDRA_INSTALL_DIR", ""), "support", "analyzeHeadless")
    return bool(os.path.exists(head) and shutil.which("java")) and head


_cache = {}


def decompile_all(binary, timeout=900):
    """{function name: C} for the binary; identical bytes are decompiled once per process."""
    import hashlib
    with open(binary, "rb") as fh:
        key = hashlib.sha256(fh.read()).hexdigest()
    if key not in _cache:
        _cache[key] = _decompile(binary, timeout)
    return _cache[key]


def _decompile(binary, timeout):
    head = available()
    if not head:
        raise RuntimeError("Ghidra or a JDK is not available")
    work = tempfile.mkdtemp(prefix="rdis-ghidra-")
    out = os.path.join(work, "decomp.json")
    os.makedirs(os.path.join(work, "p"))
    cmd = [head, os.path.join(work, "p"), "d", "-import", binary, "-overwrite", "-scriptPath", SCRIPTS,
           "-preScript", "EnableParamId.java", "-postScript", "DecompileAll.java", out, "-deleteProject"]
    subprocess.run(cmd, capture_output=True, timeout=timeout)
    if not os.path.exists(out):
        raise RuntimeError("Ghidra produced no output")
    with open(out) as fh:
        return json.load(fh)


def renamed(code, name, newname):
    """Rename `name` (and Mach-O's underscore-prefixed form) everywhere in the function text."""
    return re.sub(rf"\b_?{re.escape(name)}\b", newname, code)
