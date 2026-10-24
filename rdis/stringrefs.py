"""Which functions reference each string.

Data references are recorded per target address during analysis; a reference may point into the middle of a
string (merged tails, Go's concatenated blob), so each reference is attributed to the string that contains it.
"""
import bisect


def string_refs(prog, strings=None, cap=None):
    """{string address: [{"function": address, "name": name, "site": instruction address}]}, sorted, deduplicated."""
    strings = prog.strings() if strings is None else strings
    starts = sorted(strings)
    ends = [a + len(strings[a].encode("utf-8", "replace")) for a in starts]
    found = {}
    slots = {}
    if prog._go_functions():
        from .gobin import string_slots
        slots = string_slots(prog.image)
    for target, refs in list(prog.xrefs.items()):
        target = slots.get(target, target)
        i = bisect.bisect_right(starts, target) - 1
        if i < 0 or target >= ends[i]:
            continue
        for site, kind in refs:
            if kind != "data":
                continue
            fn = prog.function_at(site)
            if fn is not None:
                found.setdefault(starts[i], {})[(fn.addr, site)] = None
    out = {}
    for addr, sites in found.items():
        rows = [{"function": f, "name": prog.display(f), "site": s} for f, s in sorted(sites)]
        out[addr] = rows[:cap] if cap else rows
    return out
