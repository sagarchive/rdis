import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "rdis/web/index.html"));
const out = path.join(root, "artifacts");
fs.mkdirSync(out, { recursive: true });

const nodes = Array.from({ length: 14 }, (_, i) => {
  const addr = (0x1000 + i * 0x10).toString(16);
  const label = i === 0 ? "entry: parse_header" : i === 13 ? "exit: return status" :
    i % 4 === 0 ? "block_" + i + ": validate length and bounds" :
    i % 3 === 0 ? "block_" + i + ": handle conditional branch" : "block_" + i + ": load, compare, update state";
  const instr = i % 2 ? "cmp x0, #0" : "ldr x1, [x0]";
  const tail = i % 3 ? "b.ne" : "add x2, x2, #1";
  return 'n' + i + ' [label="' + addr + ': ' + label + '\\n' + instr + '\\n' + tail + '", ' +
    (i === 0 ? 'class="entry"' : "") + "];";
}).join("\n");
const edges = Array.from({ length: 13 }, (_, i) => {
  const next = i + 1;
  if (i === 4) return "n" + i + ' -> n2 [label="T", color="green"]; n' + i + ' -> n' + next + ' [label="F", color="red"];';
  if (i === 8) return "n" + i + ' -> n5 [label="loop", color="blue"]; n' + i + ' -> n' + next + ' [color="blue"];';
  return "n" + i + " -> n" + next + ' [color="blue"];';
}).join("\n");
const dot = 'digraph cfg { graph [rankdir=TB, nodesep=0.35, ranksep=0.48, pad=0.2]; ' +
  'node [shape=box, style="rounded", fontname="monospace", fontsize=10, margin="0.14,0.10"]; ' +
  'edge [fontname="monospace", fontsize=9, arrowsize=0.7]; ' + nodes + "\n" + edges + "\n}";

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(html); return;
  }
  if (url.pathname === "/api/docs") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ docs: [], current: null, allow_paths: false })); return;
  }
  if (url.pathname === "/api/cfg") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ dot, name: "cfg_visual_regression_fixture", addr: "0x1000" })); return;
  }
  res.writeHead(404, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "not found" }));
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await page.goto("http://127.0.0.1:" + address.port + "/", { waitUntil: "networkidle" });
  await page.evaluate(() => showCFG("0x1000"));
  await page.locator("#graph svg g.graph").waitFor();
  await page.waitForTimeout(250);
  await page.locator("#zfit").click();
  await page.waitForTimeout(100);
  await page.screenshot({ path: path.join(out, "cfg-desktop.png"), fullPage: true });

  const measure = async () => page.evaluate(() => {
    const g = document.querySelector("#graph"), target = document.querySelector("#graph svg g.graph");
    const a = g.getBoundingClientRect(), b = target.getBoundingClientRect();
    return { viewport: { x: a.x, y: a.y, right: a.right, bottom: a.bottom }, graph: { x: b.x, y: b.y, right: b.right, bottom: b.bottom }, zoom: document.querySelector("#zval").textContent, nodes: document.querySelectorAll("#graph g.node").length };
  });
  let m = await measure();
  assert.equal(m.nodes, 14, "expected 14 rendered CFG nodes, got " + m.nodes);
  assert(m.graph.x >= m.viewport.x - 2 && m.graph.y >= m.viewport.y - 2 &&
    m.graph.right <= m.viewport.right + 2 && m.graph.bottom <= m.viewport.bottom + 2,
    "fit clipped graph: " + JSON.stringify(m));

  const before = m.zoom;
  await page.locator("#zin").click();
  assert.notEqual((await measure()).zoom, before, "zoom-in button did not change zoom");
  await page.locator("#zfit").click();
  const first = page.locator("#graph g.node").first();
  await first.focus();
  assert.equal(await first.evaluate(el => el === document.activeElement), true, "CFG block cannot receive keyboard focus");

  const downloadPromise = page.waitForEvent("download");
  await page.locator("#zsvg").click();
  const download = await downloadPromise;
  const file = path.join(out, "cfg-export.svg");
  await download.saveAs(file);
  const exported = fs.readFileSync(file, "utf8");
  assert.match(exported, /<svg\b/, "SVG export is not an SVG document");
  assert(!/var\(--(?:g-node|g-edge|g-text|g-flow|accent|ok|err|faint|mono)\)/.test(exported),
    "SVG export still depends on page CSS custom properties");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(100);
  await page.locator("#zfit").click();
  await page.waitForTimeout(100);
  await page.screenshot({ path: path.join(out, "cfg-mobile.png"), fullPage: true });
  m = await measure();
  assert.equal(m.nodes, 14, "mobile viewport lost CFG nodes");
  assert(m.graph.x >= m.viewport.x - 2 && m.graph.y >= m.viewport.y - 2 &&
    m.graph.right <= m.viewport.right + 2 && m.graph.bottom <= m.viewport.bottom + 2,
    "mobile fit clipped graph: " + JSON.stringify(m));
  assert.deepEqual(errors, [], "browser JavaScript errors: " + errors.join("; "));
  console.log(JSON.stringify({ result: "PASS", desktop: "artifacts/cfg-desktop.png", mobile: "artifacts/cfg-mobile.png", export: "artifacts/cfg-export.svg", metrics: m, browserErrors: errors }, null, 2));
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}
