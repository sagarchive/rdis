"""Built-in loader plugin for headerless blobs (firmware, shellcode): `--loader raw --arch arm64 --base 0x8000`."""
from . import arch as archmod, plugins
from .loader import Image, Section


def load(path, arch=None, base=0, **_):
    data = open(path, "rb").read()
    base = int(base, 0) if isinstance(base, str) else base
    a = archmod.make(arch or "x86_64")
    read = lambda va, n: data[va - base: va - base + n] if base <= va < base + len(data) else b""
    off = lambda va: va - base if base <= va < base + len(data) else None
    return Image(path, "raw", a, base, base, [Section("raw", base, len(data), 0, True)],
                 {base: "start"}, {}, read, off)


plugins.register_loader("raw", lambda path, opts: False, load)  # only by explicit --loader raw
