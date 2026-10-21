"""Example loader plugin: files that start with b"TINY", one architecture byte, then raw code.

    RDIS_PLUGINS=examples/plugins python -m rdis sample.tiny
"""
from rdis import arch as archmod, plugins
from rdis.loader import Image, Section

RDIS_API = 1
ARCHES = {1: "x86_64", 2: "arm64"}
BASE = 0x400000


def probe(path, opts):
    with open(path, "rb") as fh:
        return fh.read(4) == b"TINY"


def load(path, arch=None, **_):
    with open(path, "rb") as fh:
        blob = fh.read()
    code = blob[5:]
    cpu = archmod.make(ARCHES[blob[4]])
    read = lambda va, n: code[va - BASE:va - BASE + n] if BASE <= va < BASE + len(code) else b""
    return Image(path, "tiny", cpu, BASE, BASE, [Section(".text", BASE, len(code), 5, True)], {BASE: "entry"}, {}, read,
                 lambda va: va - BASE + 5 if BASE <= va < BASE + len(code) else None)


plugins.register_loader("tiny", probe, load)
