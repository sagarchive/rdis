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
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _cfg_block_label(prog, b, limit=72, max_lines=42):
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


def to_dot(prog, func, detail=False):
    """Control-flow graph as Graphviz DOT. IDA edge convention: green = branch taken,
    red = not taken, blue = unconditional / normal flow. A loop back-edge (to an earlier
    block) is drawn non-constraining so the top-down ranking stays clean."""
    entry = func.addr
    # A CFG is a control-flow map first, not a second disassembly listing. The UI exposes
    # a detail toggle when the user wants more instructions in each node.
    line_limit, line_count = (72, 42) if detail else (54, 12)
    out = ['digraph "cfg" {',
           '  bgcolor="transparent";',
           # More breathing room keeps loop-heavy graphs readable; non-constraining back-edges
           # preserve a clean top-down rank layout without forcing cycles into the main flow.
           '  graph [rankdir=TB nodesep=0.42 ranksep="0.62 equally" splines=polyline fontname="Courier", pad=0.22];',
           '  node [shape=box style="rounded" fontname="Courier" fontsize=10 margin="0.18,0.10"];',
           '  edge [arrowsize=0.72 penwidth=1.35];']
    for a in sorted(func.blocks):
        b = func.blocks[a]
        body = _cfg_block_label(prog, b, limit=line_limit, max_lines=line_count)
        attrs = f'label="{body}" id="n{a:#x}"'
        if a == entry:
            attrs += ' class="entry" root=true penwidth=2 color="#d9974f"'   # entry block stands out
        out.append(f'  "{a:#x}" [{attrs}];')
        last = b.insns[-1]
        taken = prog.arch.target(last)
        k = prog.arch.kind(last)
        for s in b.succs:
            branch_known = k == CJMP and taken is not None and taken in b.succs
            if branch_known:
                color = "green" if s == taken else "red"
                label = ' label="T"' if s == taken else ' label="F"'
            elif k == CJMP:
                color, label = "gray", ""  # do not claim taken/not-taken when the target is unresolved
            else:
                color, label = "blue", ""
            back = " constraint=false" if s <= a else ""   # loop edge: don't distort the ranks
            out.append(f'  "{a:#x}" -> "{s:#x}" [color={color}{label}{back}];')
    return "\n".join(out + ["}"])


# Interprocedural call graph — intentionally bounded for interactive use.
CALLGRAPH_MAX_NODES = 120
CALLGRAPH_MAX_EDGES = 400
CALLGRAPH_MAX_INCOMING = 256


def callgraph(prog, func, direction="both", depth=1):
    """Return bounded caller/callee graph data and Graphviz DOT around one function.

    Function.calls provides recovered local call/tail-call targets. Reverse xrefs provide caller
    edges without scanning every function in the binary. Direct callsites are also inspected to
    retain external/import edges that are deliberately not inserted in Function.calls. Unknown
    targets remain explicitly unresolved; the graph never fabricates a named local function.
    """
    if direction not in ("both", "callers", "callees"):
        raise ValueError("direction must be one of: both, callers, callees")
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        raise ValueError("depth must be an integer from 1 to 4") from None
    if not 1 <= depth <= 4:
        raise ValueError("depth must be from 1 to 4")

    root = int(func.addr)
    nodes = {}
    levels = {root: 0}
    queue = [root]
    edges = {}
    truncated = False

    def node_meta(address):
        address = int(address)
        if address in prog.functions:
            name = prog.display(address) or f"sub_{address:x}"
            return {"addr": address, "name": str(name), "kind": "function"}
        imports = getattr(prog.image, "imports", {})
        if address in imports:
            name = prog.display(address) or imports[address] or f"import_{address:x}"
            return {"addr": address, "name": str(name), "kind": "import"}
        name = prog.display(address) or f"unresolved_{address:x}"
        return {"addr": address, "name": str(name), "kind": "unresolved"}

    def add_node(address, level):
        nonlocal truncated
        address = int(address)
        if address in nodes:
            return True, False
        if len(nodes) >= CALLGRAPH_MAX_NODES:
            truncated = True
            return False, False
        meta = node_meta(address)
        meta["level"] = level
        nodes[address] = meta
        levels[address] = level
        return True, True

    def add_edge(source, target, kind, site=None):
        nonlocal truncated
        key = (int(source), int(target))
        if key not in edges and len(edges) >= CALLGRAPH_MAX_EDGES:
            truncated = True
            return
        edge = edges.setdefault(key, {"source": key[0], "target": key[1], "kinds": set(), "sites": set()})
        edge["kinds"].add(kind)
        if site is not None:
            edge["sites"].add(int(site))

    def incoming(address):
        refs = []
        for source, kind in prog.xrefs_to(address):
            if kind not in ("call", "tail"):
                continue
            owner = prog.function_at(source)
            if owner is None or owner.addr not in prog.functions:
                continue
            refs.append((owner.addr, address, kind, source))
        if len(refs) > CALLGRAPH_MAX_INCOMING:
            refs = refs[:CALLGRAPH_MAX_INCOMING]
            nonlocal_mark_truncated[0] = True
        return refs

    # A mutable flag lets the nested incoming helper report a reference cap.
    nonlocal_mark_truncated = [False]

    def outgoing(address):
        target_sites = {}
        target_kinds = {}
        owner = prog.functions.get(address)
        if owner is None:
            return []
        for target in owner.calls:
            target = int(target)
            target_sites.setdefault(target, set())
            target_kinds.setdefault(target, set())
        # Include known call targets which are imports or indirect targets that are not local
        # Function.calls. Reset address-tracking state per block, matching Program._build.
        for block in owner.blocks.values():
            regs = {}
            for insn in block.insns:
                kind = prog.arch.kind(insn)
                if kind in (CALL, JMP, CJMP, IJMP):
                    target = prog.call_target(insn, regs)
                    if target is not None:
                        target = int(target)
                        if kind == CALL:
                            target_sites.setdefault(target, set()).add(int(insn.address))
                            target_kinds.setdefault(target, set()).add("call")
                        elif kind in (JMP, CJMP) and target not in owner.blocks and (
                            target in prog.functions or
                            target in getattr(prog.image, "imports", {}) or
                            target in getattr(prog.image, "symbols", {}) or
                            not prog.image.is_code(target)
                        ):
                            target_sites.setdefault(target, set()).add(int(insn.address))
                            target_kinds.setdefault(target, set()).add("tail")
                else:
                    prog.arch.data_refs(insn, regs)
        return [
            (address, target, next(iter(sorted(target_kinds.get(target, {"call"})))),
             sorted(target_sites.get(target, ())))
            for target in sorted(target_sites)
        ]

    add_node(root, 0)
    while queue:
        address = queue.pop(0)
        level = levels[address]
        if level >= depth or nodes[address]["kind"] != "function":
            continue

        if direction in ("both", "callers"):
            for source, target, kind, site in incoming(address):
                ok, fresh = add_node(source, level + 1)
                if not ok:
                    continue
                add_edge(source, target, kind, site)
                if fresh and level + 1 < depth:
                    queue.append(source)

        if direction in ("both", "callees"):
            for source, target, kind, sites in outgoing(address):
                ok, fresh = add_node(target, level + 1)
                if not ok:
                    continue
                if sites:
                    for site in sites:
                        add_edge(source, target, kind, site)
                else:
                    add_edge(source, target, kind)
                if fresh and level + 1 < depth and nodes[target]["kind"] == "function":
                    queue.append(target)

    if nonlocal_mark_truncated[0]:
        truncated = True

    out = [
        'digraph "callgraph" {',
        '  bgcolor="transparent";',
        '  graph [rankdir=LR nodesep=0.38 ranksep=0.72 splines=polyline fontname="Courier" pad=0.24];',
        '  node [shape=box style="rounded,filled" fontname="Courier" fontsize=10 margin="0.16,0.10"];',
        '  edge [color=blue arrowsize=0.72 penwidth=1.35 fontname="Courier" fontsize=9];',
    ]
    for address in sorted(nodes):
        meta = nodes[address]
        kind = meta["kind"]
        name = "".join(ch if ch.isprintable() else " " for ch in meta["name"])
        first = _dot_label(name, 72)
        second = _dot_label(f"{address:#x} · {kind}", 72)
        label = first + "\\l" + second + "\\l"
        svg_id = f"cg_{kind}_{address:x}"
        classes = "cg-" + kind + (" cg-root" if address == root else "")
        attrs = [f'label="{label}"', f'id="{svg_id}"', f'class="{classes}"']
        if address == root:
            attrs.extend(['root=true', 'penwidth=2.2', 'color="#d9974f"'])
        elif kind == "import":
            attrs.extend(['shape=component', 'style="rounded,dashed,filled"'])
        elif kind == "unresolved":
            attrs.extend(['style="rounded,dashed,filled"'])
        out.append(f'  "n_{address:x}" [{", ".join(attrs)}];')

    for (source, target), edge in sorted(edges.items()):
        if source not in nodes or target not in nodes:
            continue
        kinds = edge["kinds"]
        label = ""
        if "tail" in kinds and "call" not in kinds:
            label = ' label="tail"'
        elif len(edge["sites"]) > 1:
            label = f' label="{len(edge["sites"])} sites"'
        color = "gray" if nodes[target]["kind"] != "function" else "blue"
        out.append(f'  "n_{source:x}" -> "n_{target:x}" [color={color}{label}];')

    dot = "\n".join(out + ["}"])
    return {
        "name": prog.display(root) or f"sub_{root:x}",
        "addr": hex(root),
        "dot": dot,
        "direction": direction,
        "depth": depth,
        "nodes": len(nodes),
        "edges": len(edges),
        "truncated": truncated,
        "node_limit": CALLGRAPH_MAX_NODES,
        "edge_limit": CALLGRAPH_MAX_EDGES,
    }
