import assert from "node:assert/strict";
import fs from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { chromium, firefox } from "playwright";

const root = process.cwd();
const browserName = process.env.PLAYWRIGHT_BROWSER || "chromium";
const browserType = browserName === "firefox" ? firefox : chromium;
const out = "artifacts/cfg-browser-" + browserName;
fs.mkdirSync(out, { recursive: true });
const server = spawn("python3", ["-m", "http.server", "8765", "--bind", "127.0.0.1"], {
  cwd: root, stdio: "ignore"
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let realServer = null;

function dotGraph(count, detail = false) {
  const lines = [
    "digraph cfg {",
    'graph [rankdir=TB, bgcolor="transparent", pad="0.25", nodesep="0.32", ranksep="0.42", splines=true];',
    'node [shape=box, style="rounded,filled", fillcolor="#222834", color="#4b5566", fontcolor="#e4eaf2", fontname="monospace", fontsize=10, margin="0.12,0.08"];',
    'edge [color="blue", arrowsize=0.65, fontname="monospace", fontsize=9];'
  ];
  for (let i = 0; i < count; i++) {
    const label = detail
      ? `0x${(0x1000 + i * 16).toString(16)}\\lpush rbp\\lmov rbp, rsp\\lsub rsp, 0x20\\lcall sub_401000\\l`
      : `0x${(0x1000 + i * 16).toString(16)}\\l${i === 0 ? "entry" : i === count - 1 ? "return" : "block " + i}\\l`;
    lines.push(`b${i} [label="${label}"${i === 0 ? ', color="#d9974f", penwidth=2.2' : ""}];`);
  }
  for (let i = 0; i < count - 1; i++) {
    if (i === 0 && count > 3) {
      lines.push(`b${i} -> b${i + 1} [color="green", label="T"];`);
      lines.push(`b${i} -> b${i + 2} [color="red", label="F"];`);
    } else if (!(i === 1 && count > 3)) {
      lines.push(`b${i} -> b${i + 1};`);
    }
  }
  if (count > 4) lines.push(`b${count - 2} -> b2 [color="blue", label="loop"];`);
  lines.push("}");
  return lines.join("\n");
}

function dotCallGraph(rootAddress = 0x1000, rootName = "branch_loop_fixture", direction = "both", depth = 1) {
  const callerAddress = rootAddress + 0x3000;
  const grandcallerAddress = rootAddress + 0x4000;
  const calleeAddress = rootAddress + 0x1000;
  const importAddress = rootAddress + 0x8000;
  const unresolvedAddress = rootAddress + 0x9000;
  const nodes = new Map([[rootAddress, {name: rootName, kind: "function", root: true}]]);
  const edges = [];
  const add = (addr, name, kind = "function") => nodes.set(addr, {name, kind, root: false});
  if (direction !== "callees") {
    add(callerAddress, "caller_fixture");
    edges.push([callerAddress, rootAddress, "caller"]);
    if (depth >= 2) {
      add(grandcallerAddress, "grandcaller_fixture");
      edges.push([grandcallerAddress, callerAddress, "call"]);
    }
  }
  if (direction !== "callers") {
    add(calleeAddress, "callee_fixture");
    edges.push([rootAddress, calleeAddress, "call"]);
    if (depth >= 2) {
      add(importAddress, "puts", "import");
      add(unresolvedAddress, "unresolved_external", "unresolved");
      edges.push([calleeAddress, importAddress, "call"], [calleeAddress, unresolvedAddress, "unresolved"]);
    }
  }
  const lines = [
    'digraph "callgraph" {',
    'graph [rankdir=LR, bgcolor="transparent", nodesep=0.45, ranksep=0.72, pad=0.24];',
    'node [shape=box, style="rounded,filled", fillcolor="#222834", color="#4b5566", fontcolor="#e4eaf2", fontname="monospace", fontsize=10, margin="0.16,0.10"];',
    'edge [color="blue", arrowsize=0.72, fontname="monospace", fontsize=9];'
  ];
  for (const [addr, node] of nodes) {
    const classes = "cg-" + node.kind + (node.root ? " cg-root" : "");
    const styles = node.root ? ', color="#d9974f", penwidth=2.2' :
      node.kind === "import" ? ', shape=component, style="rounded,dashed,filled"' :
      node.kind === "unresolved" ? ', style="rounded,dashed,filled"' : "";
    const label = node.name + "\\l0x" + addr.toString(16) + " · " + node.kind + "\\l";
    lines.push('"0x' + addr.toString(16) + '" [label="' + label + '", id="cg_' + node.kind + '_' + addr.toString(16) + '", class="' + classes + '"' + styles + "];");
  }
  for (const [source, target, kind] of edges) {
    lines.push('"0x' + source.toString(16) + '" -> "0x' + target.toString(16) + '" [color="' + (kind === "unresolved" ? "gray" : "blue") + '", label="' + kind + '"];');
  }
  lines.push("}");
  return lines.join("\n");
}
function dotWideGraph() {
  const lines = [
    "digraph wide_cfg {",
    'graph [rankdir=TB, bgcolor="transparent", pad="0.25", nodesep="0.18", ranksep="0.52", splines=true];',
    'node [shape=box, style="rounded,filled", fillcolor="#222834", color="#4b5566", fontcolor="#e4eaf2", fontname="monospace", fontsize=10, margin="0.12,0.08"];',
    'edge [color="blue", arrowsize=0.65, fontname="monospace", fontsize=9];',
    'entry [label="0x3000\\lentry: validate packet length and metadata\\l", class="entry", color="#d9974f", penwidth=2.2];',
    'join [label="0x3100\\ljoin: normalize status and cleanup\\l"];',
    'exit [label="0x3110\\lreturn status\\l"];'
  ];
  for (let i = 0; i < 12; i++) {
    const addr = (0x3010 + i * 0x10).toString(16);
    const detail = i === 5 ? 'validate packet metadata and overflow-safe length' : 'verify bounds and dispatch';
    lines.push('case' + i + ' [label="0x' + addr + '\\lcase ' + i + ': ' + detail + '\\l"];');
  }
  lines.push('{ rank=same; ' + Array.from({length:12}, (_,i) => 'case' + i).join('; ') + '; }');
  for (let i = 0; i < 12; i++) {
    const color = i === 0 ? 'green' : i === 1 ? 'red' : 'blue';
    const label = i === 0 ? 'T' : i === 1 ? 'F' : 'case ' + i;
    lines.push('entry -> case' + i + ' [color="' + color + '", label="' + label + '"];');
    lines.push('case' + i + ' -> join [color="blue"];');
  }
  lines.push('join -> exit [color="blue"];');
  lines.push('join -> case4 [color="blue", label="retry loop"];');
  lines.push('}');
  return lines.join("\n");
}

try {
  await sleep(700);
  const browser = await browserType.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  page.on("pageerror", e => { throw e; });
  // Exercise the same pinned viz.js CDN resource that the real UI uses.
  // The browser CI job has network access; no alternate renderer is substituted.
  let opened = false;
  const apiPosts = [];
  const callgraphQueries = [];
  const fixtureInfo = {
    id: "doc-1", name: "fixture.bin", path: "fixture.bin", format: "elf", arch: "x86_64",
    entry: "0x1000", base: "0x0", counts: {functions: 1, strings: 1, imports: 1, classes: 0},
    sections: [{name: ".text", va: "0x1000", size: 64, code: true}]
  };
  const fixtureRows = [
    {kind: "section", text: "Section .text", detail: "0x1000–0x1040"},
    {kind: "banner"},
    {kind: "label", addr: "0x1000", text: "loc_1000", xrefs: []},
    {kind: "insn", addr: "0x1000", bytes: "90", mnem: "nop", ops: "", target: null, jump: null, flow: "flow", comment: "entry", user: null},
    {kind: "label", addr: "0x1001", text: "loc_1001", xrefs: []},
    {kind: "insn", addr: "0x1001", bytes: "c3", mnem: "ret", ops: "", target: null, jump: null, flow: "ret", comment: "", user: null},
    {kind: "endp"}
  ];
  await page.route("**/api/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const endpoint = url.pathname.split("/").pop();
    let payload = null;
    if (request.method() === "POST") {
      try { payload = request.postDataJSON(); } catch {}
      apiPosts.push({endpoint, payload});
    }
    let body = {};
    if (endpoint === "docs") body = opened
      ? {docs: [{id: "doc-1", name: "fixture.bin", arch: "x86_64", pending: false}], current: "doc-1", allow_paths: false}
      : {docs: [], current: null, allow_paths: false};
    else if (endpoint === "upload") body = {name: "fixture.bin", size: 2, token: "upload-1",
      slices: [{entry: "", arch: "x86_64", loader: "elf", label: "ELF executable", size: 2}]};
    else if (endpoint === "open") { opened = true; body = {id: "doc-1"}; }
    else if (endpoint === "info") body = fixtureInfo;
    else if (["labels", "functions", "strings", "imports", "classes", "bookmarks"].includes(endpoint)) {
      const items = {
        labels: [{addr: "0x1000", name: "loc_1000", type: "code"}],
        functions: [{addr: "0x1000", name: "branch_loop_fixture", type: "func"}],
        strings: [{addr: "0x2000", name: "hello fixture", type: "string"}],
        imports: [{addr: "0x3000", name: "printf", type: "import"}],
        classes: [], bookmarks: []
      };
      body = {items: items[endpoint]};
    }
    else if (endpoint === "addrinfo") body = {addr: url.searchParams.get("addr"), type: "code", name: "fixture_block",
      file_offset: 0, section: ".text", encoding: "90", insn: "nop", procedure: "branch_loop_fixture",
      proc_offset: 0, comment: "", bookmarked: false};
    else if (endpoint === "xrefs") body = {items: []};
    else if (endpoint === "listing") body = {name: "branch_loop_fixture", addr: "0x1000", rows: fixtureRows};
    else if (endpoint === "pseudo") body = {name: "branch_loop_fixture", addr: "0x1000",
      c: "int branch_loop_fixture(int x) {\n    return x + 1;\n}"};
    else if (endpoint === "hex") body = {addr: url.searchParams.get("addr") || "0x1000",
      rows: [{addr: "0x1000", hex: "90 c3", ascii: ".."}]};
    else if (endpoint === "export") body = {version: 1, name: "fixture.bin", annotations: []};
    else if (endpoint === "mark") body = {output: "marked " + (payload?.kind || "")};
    else if (endpoint === "callgraph") {
      const addr = url.searchParams.get("func") || "0x1000";
      const direction = url.searchParams.get("direction") || "both";
      const depth = Number(url.searchParams.get("depth") || "1");
      callgraphQueries.push({addr, direction, depth});
      const addrNum = Number(BigInt(addr));
      const rootName = addr.toLowerCase() === "0x1000" ? "branch_loop_fixture" : "selected_function";
      const dot = dotCallGraph(addrNum, rootName, direction, depth);
      body = {name: rootName, addr, dot, direction, depth,
        nodes: dot.split("\n").filter(line => line.includes("[label=")).length,
        edges: (dot.match(/ -> /g) || []).length,
        truncated: false, node_limit: 64, edge_limit: 128};
    }
    else if (endpoint === "cfg") {
      const addr = url.searchParams.get("func") || "0x1000";
      const count = addr === "0x2100" ? 180 : addr === "0x2000" ? 48 : 7;
      body = {name: addr === "0x2100" ? "stress_180_cfg_fixture" : addr === "0x2000" ? "large_cfg_fixture" : addr === "0x3000" ? "wide_cfg_fixture" : "branch_loop_fixture",
        addr, dot: addr === "0x3000" ? dotWideGraph() : dotGraph(count, url.searchParams.get("detail") === "1")};
    }
    await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(body)});
  });

  await page.goto("http://127.0.0.1:8765/rdis/web/index.html", {waitUntil: "networkidle"});
  await page.evaluate(() => { document.documentElement.dataset.theme = "dark"; });

  // Exercise the actual browser open flow through upload -> loader dialog -> open -> first listing.
  const uploadChooserPromise = page.waitForEvent("filechooser");
  await page.locator("#bOpen").click();
  const uploadChooser = await uploadChooserPromise;
  await uploadChooser.setFiles({name: "fixture.bin", mimeType: "application/octet-stream", buffer: Buffer.from([0x90, 0xc3])});
  await page.locator("#dlg #dOk").waitFor();
  await page.locator("#dlg #dOk").click();
  await page.locator("#view .lst").waitFor();
  assert.equal(await page.locator("#stArch").textContent(), "ELF x86_64");
  assert.equal(await page.locator("#view .lst .r:not(.lb)[data-a='0x1000']").count(), 1);

  // Exercise the main representations and chrome controls while the document is open.
  await page.locator('#modes button[data-mode="pseudo"]').click();
  await page.locator("#view .pw pre.c").waitFor();
  assert((await page.locator("#view .pw pre.c").textContent()).includes("return x + 1"));
  await page.locator('#modes button[data-mode="hex"]').click();
  await page.locator("#view .hex").waitFor();
  assert((await page.locator("#view .hex").textContent()).includes("90 c3"));
  await page.locator('#modes button[data-mode="listing"]').click();
  await page.locator("#view .lst").waitFor();
  const bytesBefore = await page.evaluate(() => S.bytes);
  await page.locator("#bBytes").click();
  assert.notEqual(await page.evaluate(() => S.bytes), bytesBefore, "instruction-byte toggle should change state");
  await page.locator("#bBytes").click();

  // Navigation panes, rail tabs and theme toggling must not corrupt the active document.
  await page.locator("#bNav").click();
  assert(await page.locator("#nav").evaluate(el => el.classList.contains("hide")));
  await page.locator("#bNav").click();
  await page.locator("#bInsp").click();
  assert(await page.locator("#insp").evaluate(el => el.classList.contains("hide")));
  await page.locator("#bInsp").click();
  await page.locator('.rail button[data-tab="functions"]').click();
  assert(await page.locator('.rail button[data-tab="functions"]').evaluate(el => el.classList.contains("on")));
  await page.locator("#q").fill("branch_loop");
  assert.equal(await page.locator("#list .nrow").count(), 1);
  await page.locator("#q").fill("");
  const themeBefore = await page.locator("html").getAttribute("data-theme");
  await page.locator("#bTheme").click();
  assert.notEqual(await page.locator("html").getAttribute("data-theme"), themeBefore);
  await page.locator("#bTheme").click();

  // Help, console controls, database export/import and analysis actions.
  await page.locator("#bHelp").click();
  await page.locator("#overlay.show #hC").click();
  const exportPromise = page.waitForEvent("download");
  await page.locator("#bExport").click();
  const dbDownload = await exportPromise;
  assert(dbDownload.suggestedFilename().endsWith(".rdb.json"));
  const importChooserPromise = page.waitForEvent("filechooser");
  await page.locator("#bImport").click();
  const importChooser = await importChooserPromise;
  await importChooser.setFiles({name: "fixture.rdb.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({version: 1, annotations: []}))});
  await page.waitForTimeout(150);
  for (const kind of ["D", "A", "C", "P", "U"]) {
    await page.locator('#marks button[data-k="' + kind + '"]').click();
  }
  await page.waitForFunction(() => (document.querySelector("#log")?.textContent.match(/marked [DACPU]/g) || []).length >= 5);
  assert.deepEqual(apiPosts.filter(p => p.endpoint === "mark").map(p => p.payload?.kind).sort(), ["A", "C", "D", "P", "U"]);
  await page.locator("#bCon").click();
  assert(await page.locator("#console").evaluate(el => el.classList.contains("small")));
  await page.locator("#bCon").click();
  await page.locator("#bClear").click();
  assert.equal(await page.locator("#log").textContent(), "");

  // Graph-specific regression fixtures follow against the same real renderer.
  await page.evaluate(() => showCFG("0x1000", false));
  await page.locator("#graph > svg g.graph").waitFor();
  await page.locator("#zfit").click();
  await page.waitForTimeout(250);

  const fitCheck = async () => page.evaluate(() => {
    const g = document.querySelector("#graph");
    const graph = g.querySelector(":scope > svg g.graph");
    const v = g.getBoundingClientRect(), r = graph.getBoundingClientRect();
    return { viewport: { left: v.left, top: v.top, right: v.right, bottom: v.bottom },
      graph: { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height },
      nodes: g.querySelectorAll(":scope > svg g.node").length, zoom: document.querySelector("#zval").textContent };
  });
  let fit = await fitCheck();
  assert.equal(fit.nodes, 7, "fixture should render all basic blocks");
  assert.equal(await page.locator("#gminimap").isVisible(), false, "small graphs should not waste space on a minimap");
  const darkTextStyle = await page.locator("#graph > svg g.node text").first().evaluate(el => ({
    fill: getComputedStyle(el).fill, stroke: getComputedStyle(el).stroke
  }));
  assert.equal(darkTextStyle.fill, "rgb(228, 234, 242)", JSON.stringify(darkTextStyle));
  assert.equal(darkTextStyle.stroke, "none", "node text must not inherit the graph's edge stroke");
  assert(fit.graph.left >= fit.viewport.left + 3, JSON.stringify(fit));
  assert(fit.graph.top >= fit.viewport.top + 50, JSON.stringify(fit));
  assert(fit.graph.right <= fit.viewport.right - 3, JSON.stringify(fit));
  assert(fit.graph.bottom <= fit.viewport.bottom - 40, JSON.stringify(fit));
  await page.screenshot({ path: `${out}/branch-loop-dark.png`, fullPage: false });

  // Keyboard access must select a block and visibly expose focus.
  const firstNode = page.locator("#graph > svg g.node").first();
  await page.locator("#zsvg").focus();
  await page.keyboard.press("Tab");
  assert(await firstNode.evaluate(el => el === document.activeElement), "Tab from graph toolbar should focus the first CFG block");
  await page.keyboard.press("Space");
  assert(await firstNode.evaluate(el => el.classList.contains("cur")), "Space should select focused block");
  const focusStroke = await firstNode.locator("path, polygon").first().evaluate(el => parseFloat(getComputedStyle(el).strokeWidth));
  assert(focusStroke >= 2.4, "focused CFG block must have a visible outline; width=" + focusStroke);
  await page.screenshot({ path: `${out}/keyboard-focus.png`, fullPage: false });

  // Wheel zoom should keep the graph under the pointer approximately anchored.
  const before = await page.evaluate(() => ({ zoom: document.querySelector("#zval").textContent }));
  await page.locator("#graph").hover({ position: { x: 600, y: 350 } });
  await page.mouse.wheel(0, -120);
  await page.waitForTimeout(100);
  const after = await page.evaluate(() => document.querySelector("#zval").textContent);
  assert.notEqual(after, before.zoom, "wheel should change zoom");

  // Detail view uses a new render; verify the toolbar reflects the mode and still fits.
  await page.locator("#gdetail").click();
  await page.locator("#graph > svg g.graph").waitFor();
  await page.waitForTimeout(200);
  assert.equal(await page.locator("#gdetail").getAttribute("aria-pressed"), "true");
  await page.locator("#zfit").click();
  await page.waitForTimeout(150);
  await page.screenshot({ path: `${out}/branch-loop-detail.png`, fullPage: false });

  // Long CFGs should open at a readable entry scale; explicit Fit remains available for overview.
  await page.evaluate(() => showCFG("0x2000", false));
  await page.locator("#graph > svg g.graph").waitFor();
  await page.waitForTimeout(150);
  const entryZoom = parseInt(await page.locator("#zval").textContent(), 10);
  assert(entryZoom >= 50, `tall CFG should start at readable scale, got ${entryZoom}%`);
  await page.screenshot({ path: `${out}/large-graph-entry-view.png`, fullPage: false });
  await page.locator("#zfit").click();
  await page.waitForTimeout(200);
  fit = await fitCheck();
  assert.equal(fit.nodes, 48, "large fixture should render all blocks");
  assert.equal(await page.locator("#gminimap").isVisible(), true, "large graphs should show the minimap");
  assert.equal(await page.locator("#gminimap .minimap-viewport").count(), 1, "minimap should show the current viewport");
  assert(fit.graph.left >= fit.viewport.left + 2, JSON.stringify(fit));
  assert(fit.graph.top >= fit.viewport.top + 50, JSON.stringify(fit));
  assert(fit.graph.right <= fit.viewport.right - 2, JSON.stringify(fit));
  assert(fit.graph.bottom <= fit.viewport.bottom - 40, JSON.stringify(fit));
  await page.screenshot({ path: `${out}/large-graph-fit.png`, fullPage: false });

  // Minimap clicks should recenter the viewport without starting a background drag.
  const transformBeforeMiniClick = await page.locator("#graph > svg").getAttribute("style");
  await page.locator("#gminimap").click({ position: { x: 80, y: 24 } });
  await page.waitForTimeout(100);
  const transformAfterMiniClick = await page.locator("#graph > svg").getAttribute("style");
  assert.notEqual(transformAfterMiniClick, transformBeforeMiniClick, "minimap click should recenter the graph");
  await page.screenshot({ path: `${out}/large-graph-minimap-navigation.png`, fullPage: false });

  // Stress the layout engine beyond 150 nodes: all nodes/edges must remain inside the fitted graph,
  // the minimap remains available, and the overview/detail UI must not disappear under the SVG.
  await page.evaluate(() => showCFG("0x2100", false));
  await page.locator("#graph > svg g.graph").waitFor();
  await page.waitForTimeout(150);
  const stressEntryZoom = parseInt(await page.locator("#zval").textContent(), 10);
  assert(stressEntryZoom >= 50, "180-node CFG should start at readable entry-focused zoom, got " + stressEntryZoom + "%");
  assert.equal(await page.locator("#gminimap").isVisible(), true, "180-node CFG should show the minimap in entry view");
  const entryMini = await page.locator("#gminimap svg").evaluate(el => {
    const rect = el.querySelector(".minimap-viewport");
    const vb = el.viewBox.baseVal;
    const host = el.parentElement.getBoundingClientRect();
    const shapes = [...el.querySelectorAll("g.node polygon, g.node path")];
    const visiblyPaintable = shapes.filter(shape => {
      const r = shape.getBoundingClientRect();
      const style = getComputedStyle(shape);
      const paints = style.stroke !== "none" && parseFloat(style.strokeWidth || "0") > 0;
      return paints && r.width > 0.05 && r.height > 0.05 &&
        r.right > host.left && r.left < host.right && r.bottom > host.top && r.top < host.bottom;
    }).length;
    return {height: Number(rect.getAttribute("height")), viewBoxHeight: vb.height,
      hostHeight: host.height, viewportFill: getComputedStyle(rect).fill,
      blockShapes: shapes.length, visiblyPaintable,
      widestBlock: Math.max(0, ...[...el.querySelectorAll("g.node")].map(n => {
        const shape = n.querySelector("polygon, path");
        return shape ? shape.getBoundingClientRect().width : 0;
      })),
      nodeStyle: (() => {
        const shape = el.querySelector("g.node polygon, g.node path");
        if (!shape) return null;
        const style = getComputedStyle(shape);
        return {fill: style.fill, stroke: style.stroke, strokeWidth: parseFloat(style.strokeWidth)};
      })(),
      labels: el.querySelectorAll("text").length,
      preserveAspectRatio: el.getAttribute("preserveAspectRatio"),
      viewBox: {x: vb.x, y: vb.y, width: vb.width, height: vb.height}};
  });
  assert(entryMini.height < entryMini.viewBoxHeight * 0.75,
    "entry-focused minimap viewport must represent only the visible region, not cover the whole graph: " + JSON.stringify(entryMini));
  assert.equal(entryMini.labels, 0, "minimap should suppress microscopic node and edge labels");
  assert(entryMini.blockShapes >= 180, "minimap should preserve block silhouettes");
  assert(entryMini.visiblyPaintable >= 180,
    "minimap must paint block silhouettes in the thumbnail, not merely retain hidden DOM shapes: " + JSON.stringify(entryMini));
  assert(entryMini.widestBlock >= 8,
    "tall-graph minimap should show visible block silhouettes rather than a single sub-pixel line: " + JSON.stringify(entryMini));
  assert(entryMini.hostHeight >= 200,
    "desktop minimap for tall CFGs needs enough pixels to distinguish block structure: " + JSON.stringify(entryMini));
  assert(entryMini.nodeStyle && entryMini.nodeStyle.stroke !== "none" && entryMini.nodeStyle.strokeWidth <= 1,
    "dense minimaps should use thin, distinct block outlines instead of merging filled nodes into a bar: " + JSON.stringify(entryMini.nodeStyle));
  assert.equal(entryMini.preserveAspectRatio, "none", "minimap should fill its schematic overview frame");
  assert.equal(entryMini.viewportFill, "none", "viewport window should not cover minimap topology");
  await page.screenshot({path: out + "/stress-180-entry-view.png", fullPage: false});
  await page.locator("#zfit").click();
  await page.waitForTimeout(300);
  fit = await fitCheck();
  assert.equal(fit.nodes, 180, "stress fixture should render all 180 basic blocks");
  assert.equal(await page.locator("#gminimap").isVisible(), true, "180-node CFG should show the minimap");
  assert.equal(await page.locator("#gminimap text").count(), 0, "minimap should not contain unreadably scaled node/edge labels");
  assert(await page.locator("#gminimap g.node polygon, #gminimap g.node path").count() >= 180,
    "minimap should preserve block silhouettes rather than collapsing into a text line");
  assert(await page.locator("#graph > svg g.node text").count() > 0, "main graph must retain its full labels");
  assert(fit.graph.left >= fit.viewport.left + 2, JSON.stringify(fit));
  assert(fit.graph.top >= fit.viewport.top + 50, JSON.stringify(fit));
  assert(fit.graph.right <= fit.viewport.right - 2, JSON.stringify(fit));
  assert(fit.graph.bottom <= fit.viewport.bottom - 40, JSON.stringify(fit));
  const fitAllZoom = parseInt(await page.locator("#zval").textContent(), 10);
  assert(fitAllZoom < 20, "stress fixture should reproduce the expected small fit-all scale: " + fitAllZoom);
  await page.screenshot({ path: `${out}/stress-180-graph-fit.png`, fullPage: false });

  // Fit-all proves the graph can be fully overviewed but makes a tall chain hard to read.
  // The explicit Entry action must restore the readable starting view without reopening the file.
  assert.equal(await page.locator("#zentry").isVisible(), true, "CFG should expose a readable Entry action");
  await page.locator("#zentry").click();
  await page.waitForTimeout(200);
  const entryReturnZoom = parseInt(await page.locator("#zval").textContent(), 10);
  assert(entryReturnZoom >= 50, "Entry should restore readable scale after fit-all: " + entryReturnZoom);
  const entryNodeBounds = await page.locator("#graph > svg g.node").first().evaluate(el => {
    const r = el.getBoundingClientRect(), v = document.querySelector("#graph").getBoundingClientRect();
    return {left:r.left,top:r.top,right:r.right,bottom:r.bottom,
      viewport:{left:v.left,top:v.top,right:v.right,bottom:v.bottom}};
  });
  assert(entryNodeBounds.left >= entryNodeBounds.viewport.left, JSON.stringify(entryNodeBounds));
  assert(entryNodeBounds.top >= entryNodeBounds.viewport.top + 50, JSON.stringify(entryNodeBounds));
  assert(entryNodeBounds.right <= entryNodeBounds.viewport.right, JSON.stringify(entryNodeBounds));
  assert(entryNodeBounds.bottom <= entryNodeBounds.viewport.bottom, JSON.stringify(entryNodeBounds));
  await page.screenshot({ path: `${out}/stress-180-entry-after-fit.png`, fullPage: false });

  // Wide fan-out/join graph with long labels catches horizontal clipping and minimap aspect bugs.
  await page.evaluate(() => go("0x3000", {mode: "cfg"}));
  await page.locator("#graph > svg g.graph").waitFor();
  assert.equal(await page.locator("#glayout").getAttribute("data-layout"), "LR",
    "a switch-style high-fanout CFG should auto-select a vertical fan-out layout");
  const wideEntryZoom = parseInt(await page.locator("#zval").textContent(), 10);
  assert(wideEntryZoom >= 60 && wideEntryZoom <= 85,
    "wide CFG entry layout should fit the branch neighborhood and shared join, got " + wideEntryZoom + "%");
  const visibleWideNodes = await page.evaluate(() => {
    const host = document.querySelector("#graph").getBoundingClientRect();
    return [...document.querySelectorAll("#graph > svg g.node")].filter(node => {
      const r = node.getBoundingClientRect();
      return r.right > host.left && r.left < host.right && r.bottom > host.top && r.top < host.bottom;
    }).length;
  });
  assert(visibleWideNodes >= 6,
    "wide CFG entry view should expose multiple branch destinations, not just the entry node: " + visibleWideNodes);
  const wideNeighborhood = await page.evaluate(() => {
    const host = document.querySelector("#graph").getBoundingClientRect();
    const nodes = [...document.querySelectorAll("#graph > svg g.node")];
    const fullyVisible = node => {
      const r = node.getBoundingClientRect();
      return r.left >= host.left + 1 && r.right <= host.right - 1 &&
        r.top >= host.top + 50 && r.bottom <= host.bottom - 42;
    };
    const nodeName = node => node.querySelector(":scope > title")?.textContent?.trim() || "";
    const entry = nodes.find(n => nodeName(n) === "entry");
    const cases = nodes.filter(n => /^case\d+$/.test(nodeName(n)));
    const join = nodes.find(n => nodeName(n) === "join");
    const exit = nodes.find(n => nodeName(n) === "exit");
    return { entryVisible: !!entry && fullyVisible(entry),
      joinVisible: !!join && fullyVisible(join),
      exitVisible: !!exit && fullyVisible(exit),
      visibleCases: cases.filter(fullyVisible).length, totalCases: cases.length,
      titles: nodes.map(nodeName) };
  });
  assert(wideNeighborhood.entryVisible, "horizontal layout must keep the entry inside the unobscured viewport");
  assert(wideNeighborhood.joinVisible, "horizontal entry view must include the shared join instead of clipping it at the right edge: " + JSON.stringify(wideNeighborhood));
  assert(wideNeighborhood.exitVisible, "horizontal entry view should include the return/exit successor when its join is visible: " + JSON.stringify(wideNeighborhood));
  assert(wideNeighborhood.visibleCases >= 10,
    "wide CFG should fit nearly all 12 direct branch targets in the readable initial view: " +
    JSON.stringify(wideNeighborhood));
  const labelOverflow = await page.evaluate(() => {
    const problems = [];
    document.querySelectorAll("#graph > svg g.node").forEach(node => {
      const shape = node.querySelector("polygon, path");
      if (!shape) return;
      const s = shape.getBBox();
      node.querySelectorAll("text").forEach(text => {
        const t = text.getBBox();
        if (t.x < s.x - 1 || t.y < s.y - 1 || t.x + t.width > s.x + s.width + 1 || t.y + t.height > s.y + s.height + 1) {
          problems.push({node: node.querySelector("title")?.textContent, shape: {x:s.x,y:s.y,w:s.width,h:s.height}, text: {x:t.x,y:t.y,w:t.width,h:t.height}});
        }
      });
    });
    return problems;
  });
  assert.deepEqual(labelOverflow, [], "CFG text must fit inside its rendered node shape: " + JSON.stringify(labelOverflow));
  await page.screenshot({ path: out + "/wide-graph-entry-view.png", fullPage: false });

  // The user can switch layout direction explicitly; the graph must re-render in the chosen
  // orientation, preserve all nodes, and return to the fan-out-friendly automatic layout.
  await page.locator("#glayout").click();
  await page.waitForFunction(() => document.querySelector("#glayout")?.getAttribute("data-layout") === "TB");
  await page.locator("#graph > svg g.graph").waitFor();
  await page.waitForTimeout(180);
  assert.equal(await page.locator("#graph > svg g.node").count(), 15);
  const topDownFit = await fitCheck();
  assert(topDownFit.graph.left >= topDownFit.viewport.left + 2, JSON.stringify(topDownFit));
  assert(topDownFit.graph.top >= topDownFit.viewport.top + 50, JSON.stringify(topDownFit));
  assert(topDownFit.graph.right <= topDownFit.viewport.right - 2, JSON.stringify(topDownFit));
  assert(topDownFit.graph.bottom <= topDownFit.viewport.bottom - 40, JSON.stringify(topDownFit));
  await page.screenshot({ path: out + "/wide-graph-top-down-layout.png", fullPage: false });
  // Entry is a semantic reset, not another Fit-all: return to the automatic fan-out-friendly
  // orientation and readable root/cases/join/exit context after the user tries top-down layout.
  await page.locator("#zentry").click();
  await page.waitForFunction(() => document.querySelector("#glayout")?.getAttribute("data-layout") === "LR");
  await page.locator("#graph > svg g.graph").waitFor();
  await page.waitForTimeout(120);
  assert(parseInt(await page.locator("#zval").textContent(), 10) >= 60,
    "Entry should restore readable fan-out view after top-down fit");

  await page.locator("#zfit").click();
  await page.waitForTimeout(150);
  const wideFit = await fitCheck();
  assert.equal(wideFit.nodes, 15, "wide fan-out fixture should render entry, 12 cases, join and exit");
  assert.equal(await page.locator("#gminimap").isVisible(), true, "wide graphs should show the minimap");
  assert(wideFit.graph.left >= wideFit.viewport.left + 2, JSON.stringify(wideFit));
  assert(wideFit.graph.top >= wideFit.viewport.top + 2, JSON.stringify(wideFit));
  assert(wideFit.graph.right <= wideFit.viewport.right - 2, JSON.stringify(wideFit));
  assert(wideFit.graph.bottom <= wideFit.viewport.bottom - 2, JSON.stringify(wideFit));
  await page.screenshot({ path: out + "/wide-graph-fit.png", fullPage: false });

  // Theme switching should not break rendering; the downloaded SVG must be parseable/self-contained.
  await page.evaluate(() => { document.documentElement.dataset.theme = "light"; });
  await page.waitForTimeout(100);
  const lightTextStyle = await page.locator("#graph > svg g.node text").first().evaluate(el => ({
    fill: getComputedStyle(el).fill, stroke: getComputedStyle(el).stroke
  }));
  assert.equal(lightTextStyle.fill, "rgb(42, 47, 56)", JSON.stringify(lightTextStyle));
  assert.equal(lightTextStyle.stroke, "none", "light-theme text should remain crisp and unoutlined");
  await page.screenshot({ path: `${out}/large-graph-light.png`, fullPage: false });
  const expectedExportBounds = await page.locator("#graph > svg").evaluate(svg => {
    const graph = svg.querySelector("g.graph"), local = graph.getBBox();
    const graphCtm = graph.getScreenCTM(), rootInverse = svg.getScreenCTM().inverse();
    const corners = [
      [local.x, local.y], [local.x + local.width, local.y],
      [local.x, local.y + local.height], [local.x + local.width, local.y + local.height]
    ].map(([x, y]) => {
      const p = svg.createSVGPoint(); p.x = x; p.y = y;
      return p.matrixTransform(graphCtm).matrixTransform(rootInverse);
    });
    const xs = corners.map(p => p.x), ys = corners.map(p => p.y);
    return {x: Math.min(...xs), y: Math.min(...ys),
      width: Math.max(...xs) - Math.min(...xs), height: Math.max(...ys) - Math.min(...ys)};
  });
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#zsvg").click();
  const download = await downloadPromise;
  const file = `${out}/${download.suggestedFilename()}`;
  await download.saveAs(file);
  const exported = fs.readFileSync(file, "utf8");
  assert(exported.includes("<svg"), "SVG export should be XML SVG");
  assert(!/var\\(--g-(?:node|edge|text|flow)\\)/.test(exported), "export should resolve graph theme colors");
  assert(!exported.includes("var(--mono)"), "export should resolve graph font variable");
  const exportedViewBox = exported.match(/viewBox="([^"]+)"/);
  assert(exportedViewBox, "standalone SVG must have an explicit viewBox");
  const viewBox = exportedViewBox[1].trim().split(/[ ,]+/).map(Number);
  assert.equal(viewBox.length, 4, exportedViewBox[1]);
  const expectedViewBox = [expectedExportBounds.x - 12, expectedExportBounds.y - 12,
    expectedExportBounds.width + 24, expectedExportBounds.height + 24];
  expectedViewBox.forEach((value, i) => assert(Math.abs(viewBox[i] - value) < 2,
    "export viewBox must use transformed root-SVG bounds; expected " + expectedViewBox + " got " + viewBox));

  // The interprocedural Calls view should preserve node kinds, direction/depth controls, and SVG export.
  await page.locator('#modes button[data-mode="callgraph"]').click();
  await page.locator("#graph > svg g.graph").waitFor();
  const initialCallgraphRequest = callgraphQueries.at(-1);
  const initialCallgraphRoot = await page.locator("#graph > svg g.node.cg-root > title").first().textContent();
  assert.equal(initialCallgraphRoot, initialCallgraphRequest.addr,
    "the selected function's address must be the root of the rendered call graph");
  assert.equal(await page.locator("#cgDirection").inputValue(), "both");
  assert.equal(await page.locator("#cgDepth").inputValue(), "1");
  assert(await page.locator("#graph > svg g.node.cg-function").count() >= 2);
  assert.equal(await page.locator("#graph > svg g.node.cg-import").count(), 0);
  let callFit = await fitCheck();
  assert(callFit.graph.left >= callFit.viewport.left + 3, "small call graph clipped on left: " + JSON.stringify(callFit));
  assert(callFit.graph.top >= callFit.viewport.top + 50, "small call graph overlaps toolbar: " + JSON.stringify(callFit));
  assert(callFit.graph.right <= callFit.viewport.right - 3, "small call graph clipped on right: " + JSON.stringify(callFit));
  assert(callFit.graph.bottom <= callFit.viewport.bottom - 36, "small call graph overlaps legend: " + JSON.stringify(callFit));
  await page.screenshot({path: out + "/callgraph-both-depth1.png", fullPage: false});

  await page.locator("#cgDirection").selectOption("callers");
  await page.locator("#cgDepth").selectOption("2");
  await page.waitForFunction(() => document.querySelectorAll("#graph > svg g.node.cg-function").length === 3);
  assert(callgraphQueries.some(q => q.direction === "callers" && q.depth === 2),
    "changing call graph direction/depth should issue an API request");
  assert.equal(await page.locator("#graph > svg g.node.cg-import").count(), 0);
  assert.equal(await page.locator("#graph > svg g.node.cg-unresolved").count(), 0);
  await page.screenshot({path: out + "/callgraph-callers-depth2.png", fullPage: false});

  await page.locator("#cgDirection").selectOption("callees");
  await page.locator("#cgDepth").selectOption("2");
  await page.waitForFunction(() => document.querySelectorAll("#graph > svg g.node.cg-import").length === 1);
  assert.equal(await page.locator("#graph > svg g.node.cg-unresolved").count(), 1);
  assert(callgraphQueries.some(q => q.direction === "callees" && q.depth === 2));
  callFit = await fitCheck();
  assert.equal(callFit.nodes, 4, "callee depth-2 fixture should include function, callee, import and unresolved nodes");
  assert(callFit.graph.left >= callFit.viewport.left + 3, "callee depth-2 graph clipped on left: " + JSON.stringify(callFit));
  assert(callFit.graph.top >= callFit.viewport.top + 50, "callee depth-2 graph overlaps toolbar: " + JSON.stringify(callFit));
  assert(callFit.graph.right <= callFit.viewport.right - 3, "callee depth-2 graph clipped on right: " + JSON.stringify(callFit));
  assert(callFit.graph.bottom <= callFit.viewport.bottom - 36, "callee depth-2 graph overlaps legend: " + JSON.stringify(callFit));
  await page.screenshot({path: out + "/callgraph-callees-depth2.png", fullPage: false});
  const callsSvgPromise = page.waitForEvent("download");
  await page.locator("#zsvg").click();
  const callsSvg = await callsSvgPromise;
  assert(callsSvg.suggestedFilename().endsWith("-callgraph.svg"));

  // Inspect the public GitHub Pages section that documents the shipped call-graph workflow.
  const pagesPage = await browser.newPage({viewport: {width: 1440, height: 1000}, deviceScaleFactor: 1});
  pagesPage.on("pageerror", e => { throw e; });
  // Disable scroll-timeline entrance animations in screenshot CI so the artifact depicts settled
  // product content instead of a transient, partially transparent frame.
  await pagesPage.emulateMedia({reducedMotion: "reduce"});
  await pagesPage.goto("http://127.0.0.1:8765/docs/index.html", {waitUntil: "domcontentloaded"});
  await pagesPage.locator("#deep-h").waitFor();
  await pagesPage.locator("#deep-h").scrollIntoViewIfNeeded();
  assert(await pagesPage.getByText("See the shape of a function.", {exact: true}).isVisible());
  const cfgHelp = await pagesPage.locator("section[aria-labelledby='deep-h'] .duo").first().innerText();
  assert(cfgHelp.includes("Entry") && cfgHelp.includes("LR/TB"), "Pages CFG help must explain Entry and layout switching");
  assert(!cfgHelp.includes("**Entry**") && !cfgHelp.includes("**LR/TB**"), "HTML help must not show literal Markdown asterisks");
  await pagesPage.waitForTimeout(150);
  await pagesPage.screenshot({path: out + "/github-pages-cfg-feature.png", fullPage: false});

  await pagesPage.locator("#calls-h").scrollIntoViewIfNeeded();
  assert(await pagesPage.getByText("Follow a function through the program.", {exact: true}).isVisible());
  assert.equal(await pagesPage.locator('svg[aria-label*="Call graph with a selected parse_packet function"]').count(), 1);
  await pagesPage.waitForTimeout(150);
  await pagesPage.screenshot({path: out + "/github-pages-callgraph-feature.png", fullPage: false});

  // End-to-end smoke: real compiled ELF -> RDIS server/analysis/render -> real Chromium CFG.
  // This complements the synthetic large-graph fixtures above, which isolate layout behavior.
  assert(fs.existsSync("/tmp/rdis-cfg-fixture"), "compiled real-binary fixture is missing");
  const nm = spawnSync("nm", ["-n", "/tmp/rdis-cfg-fixture"], { encoding: "utf8" });
  assert.equal(nm.status, 0, nm.stderr);
  const symbol = nm.stdout.match(/^([0-9a-fA-F]+)\s+T\s+branch_loop$/m);
  assert(symbol, "branch_loop symbol missing from compiled fixture");
  const realAddress = "0x" + BigInt("0x" + symbol[1]).toString(16);
  realServer = spawn("python3", ["-m", "rdis.server", "/tmp/rdis-cfg-fixture",
    "--no-open", "--host", "127.0.0.1", "--port", "8766", "--upload-dir", "/tmp/rdis-cfg-uploads"], {
    cwd: root, stdio: "ignore"
  });
  let ready = false;
  for (let i = 0; i < 80; i++) {
    try {
      const response = await fetch("http://127.0.0.1:8766/api/docs");
      if (response.ok) { ready = true; break; }
    } catch {}
    await sleep(250);
  }
  assert(ready, "RDIS server did not become ready for real-binary smoke test");
  const realPage = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  realPage.on("pageerror", e => { throw e; });
  await realPage.goto("http://127.0.0.1:8766/", { waitUntil: "networkidle" });
  // Navigate through the app's real mode/selection path so the toolbar state matches the graph view.
  await realPage.evaluate(addr => go(addr, {mode: "cfg"}), realAddress);
  await realPage.locator("#graph > svg g.graph").waitFor({ timeout: 15000 });
  await realPage.locator("#zfit").click();
  await realPage.waitForTimeout(200);
  const realMetrics = await realPage.evaluate(() => {
    const host = document.querySelector("#graph");
    const graph = host.querySelector(":scope > svg g.graph");
    const v = host.getBoundingClientRect(), r = graph.getBoundingClientRect();
    return { nodes: host.querySelectorAll(":scope > svg g.node").length,
      edges: host.querySelectorAll(":scope > svg g.edge").length,
      viewport: { left: v.left, top: v.top, right: v.right, bottom: v.bottom },
      graph: { left: r.left, top: r.top, right: r.right, bottom: r.bottom } };
  });
  assert(realMetrics.nodes >= 4, "real RDIS CFG should contain multiple basic blocks: " + JSON.stringify(realMetrics));
  assert(realMetrics.edges >= 3, "real RDIS CFG should contain control-flow edges: " + JSON.stringify(realMetrics));
  assert(realMetrics.graph.left >= realMetrics.viewport.left + 2, JSON.stringify(realMetrics));
  assert(realMetrics.graph.top >= realMetrics.viewport.top + 50, JSON.stringify(realMetrics));
  assert(realMetrics.graph.right <= realMetrics.viewport.right - 2, JSON.stringify(realMetrics));
  assert(realMetrics.graph.bottom <= realMetrics.viewport.bottom - 40, JSON.stringify(realMetrics));
  await realPage.screenshot({ path: `${out}/real-binary-cfg.png`, fullPage: false });
  await browser.close();
  console.log("CFG browser tests passed in " + browserName + "; screenshots and SVG are in " + out + "/");
} finally {
  server.kill("SIGTERM");
  realServer?.kill("SIGTERM");
}
