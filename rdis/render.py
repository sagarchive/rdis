"""Text and DOT output for disassembly and CFGs, with resolved names and inline comments."""
from .arch import CALL, JMP, CJMP, IJMP
from .lift import cstr_lit

FLOW = (CALL, JMP, CJMP, IJMP)


def _comment(prog, i):
    """Trailing `; comment` for an instruction: resolved call/branch target, string ref, symbol."""
    # only control flow has a branch target; a trailing immediate elsewhere (adrp page, mov #imm)
    # is data, and naming it after whatever symbol sits there would be wrong.
    t = prog.call_target(i, {}) if prog.arch.kind(i) in FLOW else None
    if t is not None:
        name = prog.display(t)
        if name:
            return name
    for r in prog.arch.data_refs(i, {}):
        s = prog.strings().get(r)
        if s is not None:
            return cstr_lit(s)
        cf = prog.objc.cfstrings.get(r) if prog.objc else None
        if cf is not None:
            return "@" + cstr_lit(cf)
        n = prog.display(r)
        if n:
            return n
    return ""


def _stack_vars(prog, func):
    """(offset, name, type) of stack locals, from the decompiler's type inference."""
    from .decompile import Decompiler
    if prog.arch.name not in Decompiler.LEGACY:     # the IR owns this ISA: its frame recovery
        from .ir import IRLifter
        lf = IRLifter(prog)
        lf.signature(func, "f")
        for b in func.blocks.values():
            lf.block(b)
        off = lambda n: (-1 if n.startswith("var_") else 1) * int(n.split("_")[1], 16)
        from .ir import _SINT
        return sorted((off(n), n, _SINT.get(sz, "int64_t")) for n, sz in lf._locals.items())
    from .lift import Lifter
    lf = Lifter(prog)
    lf.signature(func, "f")
    return sorted((off, lf._localname[off], lf._localtype.get(off, "int64_t")) for off in lf._localname)


def listing(prog, func):
    """Hopper-style linear listing of one procedure as structured rows for the UI.

    Row kinds: section, banner, vars, label, insn, endp. Instruction rows carry the encoding
    bytes, a clickable `target`, and `jump` (intra-procedure branch target) for gutter arrows.
    """
    rows = []
    sec = prog.image.section_at(func.addr)
    if sec and sec.va == func.addr:
        rows.append({"kind": "section", "text": f"Section {sec.name}",
                     "detail": f"Range: [{sec.va:#x}; {sec.va + sec.size:#x}[ ({sec.size} bytes)  "
                               f"File offset: {sec.offset}"})
    name = prog.display(func.addr) or f"sub_{func.addr:x}"
    rows.append({"kind": "banner", "addr": hex(func.addr), "text": name})
    svars = _stack_vars(prog, func)
    if svars:
        rows.append({"kind": "vars", "items": [{"off": off, "name": n, "type": t} for off, n, t in svars]})
    blocks = sorted(func.blocks)
    for a in blocks:
        b = func.blocks[a]
        refs = [{"addr": hex(s), "kind": k, "name": _ref_name(prog, s)} for s, k in prog.xrefs_to(a)]
        rows.append({"kind": "label", "addr": hex(a),
                     "text": f"{name}:" if a == func.addr else f"loc_{a:x}:", "xrefs": refs})
        for i in b.shown:
            k = prog.arch.kind(i)
            t = prog.call_target(i, {}) if k in FLOW else None
            row = {"kind": "insn", "addr": hex(i.address), "bytes": i.bytes.hex(" "),
                   "mnem": i.mnemonic, "ops": i.op_str, "comment": _comment(prog, i),
                   "user": prog.comments.get(i.address, ""), "flow": k}
            if t is not None and (t in prog.functions or t in prog.image.imports):
                row["target"] = {"addr": hex(t), "name": prog.display(t) or hex(t)}
            if k in (JMP, CJMP) and t in func.blocks:
                row["jump"] = hex(t)
            rows.append(row)
    rows.append({"kind": "endp", "text": "endp"})
    return rows


def _ref_name(prog, a):
    """`EntryPoint+64` style location for an xref source, like Hopper's CODE XREF comments."""
    f = prog.function_at(a)
    if f is None:
        return hex(a)
    base = prog.display(f.addr) or f"sub_{f.addr:x}"
    return base if a == f.addr else f"{base}+{a - f.addr}"


def line(prog, i):
    c = _comment(prog, i)
    user = prog.comments.get(i.address)
    if user:
        c = f"{user}" + (f"  ({c})" if c else "")
    text = f"{i.address:#010x}  {i.mnemonic:<9} {i.op_str}"
    return f"{text:<48} ; {c}" if c else text


def disassemble(prog, func):
    out = []
    name = prog.display(func.addr) or f"sub_{func.addr:x}"
    out.append(f"; ---- {name}  ({len(func.blocks)} blocks) ----")
    for a in sorted(func.blocks):
        b = func.blocks[a]
        refs = [f"{s:#x}" for s, k in prog.xrefs_to(a)]
        out.append(f"loc_{a:x}:" + (f"   ; xrefs: {', '.join(refs)}" if refs and a != func.addr else ""))
        out += ["    " + line(prog, i) for i in b.shown]
    return "\n".join(out)


def _dot_label(s, limit=90):
    """Escape one line of text for a Graphviz quoted (record) label. Backslash and quote must be
    escaped or the label terminates early and the node box renders with text spilling outside it."""
    if len(s) > limit:
        s = s[:limit - 1] + "…"
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _cfg_block_label(prog, b, limit=64, max_lines=42):
    """Left-justified basic-block body for a CFG node: `addr  mnemonic operands  ; target`.
    Long blocks are capped so one merged block can't blow up the whole layout."""
    insns = b.shown
    lines = []
    for i in insns[:max_lines]:
        c = prog.comments.get(i.address) or _comment(prog, i)
        txt = f"{i.address:x}  {i.mnemonic} {i.op_str}".rstrip()
        if c:
            txt += f"   ; {c}"
        lines.append(_dot_label(txt, limit))
    if len(insns) > max_lines:
        lines.append(_dot_label(f"… {len(insns) - max_lines} more", limit))
    return "".join(l + "\\l" for l in lines)


def to_dot(prog, func):
    """Control-flow graph as Graphviz DOT. IDA edge convention: green = branch taken,
    red = not taken, blue = unconditional / normal flow. A loop back-edge (to an earlier
    block) is drawn non-constraining so the top-down ranking stays clean."""
    entry = func.addr
    out = ['digraph "cfg" {',
           '  bgcolor="transparent";',
           # fontname "Courier": viz.js has exact metrics for it and sizes each box a touch WIDE,
           # while the page renders the (narrower) app monospace — so text always fits, never clips.
           '  graph [rankdir=TB nodesep=0.3 ranksep="0.42 equally" splines=polyline fontname="Courier"];',
           '  node [shape=box style="rounded" fontname="Courier" fontsize=10 margin="0.16,0.08"];',
           '  edge [arrowsize=0.7 penwidth=1.2];']
    for a in sorted(func.blocks):
        b = func.blocks[a]
        body = _cfg_block_label(prog, b)
        attrs = f'label="{body}" id="n{a:#x}"'
        if a == entry:
            attrs += ' root=true penwidth=2'   # entry block stands out
        out.append(f'  "{a:#x}" [{attrs}];')
        last = b.insns[-1]
        taken = prog.arch.target(last)
        k = prog.arch.kind(last)
        for s in b.succs:
            color = "green" if k == CJMP and s == taken else "red" if k == CJMP else "blue"
            back = " constraint=false" if s <= a else ""   # loop edge: don't distort the ranks
            out.append(f'  "{a:#x}" -> "{s:#x}" [color={color}{back}];')
    return "\n".join(out + ["}"])
