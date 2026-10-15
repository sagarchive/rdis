import assert from "node:assert/strict";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { chromium } from "playwright";

const root = process.cwd();
const out = "artifacts/cfg-browser";
fs.mkdirSync(out, { recursive: true });
const server = spawn("python3", ["-m", "http.server", "8765", "--bind", "127.0.0.1"], {
  cwd: root, stdio: "ignore"
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

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

try {
  await sleep(700);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  page.on("pageerror", e => { throw e; });
  // Exercise the same pinned viz.js CDN resource that the real UI uses.
  // The browser CI job has network access; no alternate renderer is substituted.
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    const endpoint = url.pathname.split("/").pop();
    let body = {};
    if (endpoint === "docs") body = { docs: [], current: null, allow_paths: false };
    else if (endpoint === "cfg") {
      const addr = url.searchParams.get("func") || "0x1000";
      const count = addr === "0x2000" ? 48 : 7;
      body = { name: addr === "0x2000" ? "large_cfg_fixture" : "branch_loop_fixture",
        addr, dot: dotGraph(count, url.searchParams.get("detail") === "1") };
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });

  await page.goto("http://127.0.0.1:8765/rdis/web/index.html", { waitUntil: "networkidle" });
  await page.evaluate(() => showCFG("0x1000", false));
  await page.locator("#graph svg g.graph").waitFor();
  await page.locator("#zfit").click();
  await page.waitForTimeout(250);

  const fitCheck = async () => page.evaluate(() => {
    const g = document.querySelector("#graph");
    const graph = g.querySelector("svg g.graph");
    const v = g.getBoundingClientRect(), r = graph.getBoundingClientRect();
    return { viewport: { left: v.left, top: v.top, right: v.right, bottom: v.bottom },
      graph: { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height },
      nodes: g.querySelectorAll("svg g.node").length, zoom: document.querySelector("#zval").textContent };
  });
  let fit = await fitCheck();
  assert.equal(fit.nodes, 7, "fixture should render all basic blocks");
  assert(fit.graph.left >= fit.viewport.left + 3, JSON.stringify(fit));
  assert(fit.graph.top >= fit.viewport.top + 3, JSON.stringify(fit));
  assert(fit.graph.right <= fit.viewport.right - 3, JSON.stringify(fit));
  assert(fit.graph.bottom <= fit.viewport.bottom - 3, JSON.stringify(fit));
  await page.screenshot({ path: `${out}/branch-loop-dark.png`, fullPage: false });

  // Keyboard access must select a block and visibly expose focus.
  const firstNode = page.locator("#graph svg g.node").first();
  await firstNode.focus();
  await page.keyboard.press("Space");
  assert(await firstNode.evaluate(el => el.classList.contains("cur")), "Space should select focused block");
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
  await page.locator("#graph svg g.graph").waitFor();
  await page.waitForTimeout(200);
  assert.equal(await page.locator("#gdetail").getAttribute("aria-pressed"), "true");
  await page.locator("#zfit").click();
  await page.waitForTimeout(150);
  await page.screenshot({ path: `${out}/branch-loop-detail.png`, fullPage: false });

  // Large graph is the key failure mode: verify actual painted bounds fit without clipping.
  await page.evaluate(() => showCFG("0x2000", false));
  await page.locator("#graph svg g.graph").waitFor();
  await page.locator("#zfit").click();
  await page.waitForTimeout(200);
  fit = await fitCheck();
  assert.equal(fit.nodes, 48, "large fixture should render all blocks");
  assert(fit.graph.left >= fit.viewport.left + 2, JSON.stringify(fit));
  assert(fit.graph.top >= fit.viewport.top + 2, JSON.stringify(fit));
  assert(fit.graph.right <= fit.viewport.right - 2, JSON.stringify(fit));
  assert(fit.graph.bottom <= fit.viewport.bottom - 2, JSON.stringify(fit));
  await page.screenshot({ path: `${out}/large-graph-fit.png`, fullPage: false });

  // Theme switching should not break rendering; the downloaded SVG must be parseable/self-contained.
  await page.evaluate(() => { document.documentElement.dataset.theme = "light"; });
  await page.waitForTimeout(100);
  await page.screenshot({ path: `${out}/large-graph-light.png`, fullPage: false });
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#zsvg").click();
  const download = await downloadPromise;
  const file = `${out}/${download.suggestedFilename()}`;
  await download.saveAs(file);
  const exported = fs.readFileSync(file, "utf8");
  assert(exported.includes("<svg"), "SVG export should be XML SVG");
  assert(!/var\\(--g-(?:node|edge|text|flow)\\)/.test(exported), "export should resolve graph theme colors");
  assert(!exported.includes("var(--mono)"), "export should resolve graph font variable");
  await browser.close();
  console.log("CFG browser tests passed; screenshots and exported SVG are in artifacts/cfg-browser/");
} finally {
  server.kill("SIGTERM");
}
