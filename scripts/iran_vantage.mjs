#!/usr/bin/env node
// Iran-datacenter vantage stage (check-host.net, keyless).
//
//   node scripts/iran_vantage.mjs            hourly run (<= 20 start calls)
//   node scripts/iran_vantage.mjs --dry      measure but write nothing
//   node scripts/iran_vantage.mjs --smoke    live parser smoke (1.1.1.1:443 + https://example.com), writes nothing
//
// Reads only public bridge/ projections, never sends a fingerprint, cert or url
// path to check-host, appends to data/iran_vantage.jsonl and keeps one cursor
// per source file in data/iran_vantage_cursors.json.  It never edits any
// iran_likely_working_*.txt and never fails the collector (exit 0 on API trouble).
// A check-host Iran node is a datacenter TCP/HTTPS vantage - NOT a Tor, obfs4,
// WebTunnel, meek or Snowflake handshake.
import fs from "node:fs";
import path from "node:path";
import {
  SOURCES, MAX_CALLS_PER_RUN, MIN_START_GAP_MS, POLL_INTERVAL_MS, MAX_POLLS, USER_AGENT,
  discoverNodes, planSource, parseNodeResult, buildRecord, pickIranNodes, summarizeVantage,
} from "./lib/iran_vantage.mjs";

const BASE = "https://check-host.net";
const ROOT = process.env.IV_ROOT || process.cwd();
const OUT = path.join(ROOT, "data/iran_vantage.jsonl");
const CURSORS = path.join(ROOT, "data/iran_vantage_cursors.json");
const MAX_BODY = 1_000_000;
const args = new Set(process.argv.slice(2));
const DRY = args.has("--dry");
const SMOKE = args.has("--smoke");
const SUMMARY = path.join(ROOT, "data/iran_vantage_summary.json");
// Iran nodes per check-host call (same quota: one start call covers all of them).
const NODES_PER_CALL = Math.min(4, Math.max(1, Number.parseInt(process.env.IV_IRAN_NODES_PER_CALL || "3", 10) || 3));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (m) => console.log(`[iran-vantage] ${m}`);
const warn = (m) => console.log(`::warning::[iran-vantage] ${m}`);

class StopBatch extends Error {}

async function get(url) {
  const res = await fetch(url, {
    headers: { Accept: "application/json", "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 403 || res.status === 429) throw new StopBatch(`HTTP ${res.status}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BODY) throw new Error("response too large");
  return JSON.parse(text);
}

let lastStart = 0;
let startCalls = 0;
async function startCheck(kind, hostParam, nodes) {
  const wait = lastStart + MIN_START_GAP_MS - Date.now();
  if (wait > 0) await sleep(wait);
  lastStart = Date.now();
  startCalls += 1;
  const q = nodes.map((n) => `&node=${encodeURIComponent(n)}`).join("");
  const j = await get(`${BASE}/check-${kind}?host=${encodeURIComponent(hostParam)}${q}`);
  if (!j || j.ok !== 1 || typeof j.request_id !== "string" || !/^[A-Za-z0-9]+$/.test(j.request_id)) {
    throw new StopBatch("start response ok != 1");
  }
  return j.request_id;
}

async function pollResult(requestId, names) {
  let last = {};
  for (let i = 0; i < MAX_POLLS; i++) {
    await sleep(POLL_INTERVAL_MS);
    const j = await get(`${BASE}/check-result/${requestId}`);
    last = j && typeof j === "object" ? j : {};
    if (names.every((n) => last[n] !== null && last[n] !== undefined)) break;
  }
  return last;
}

/** One check-host call: up to NODES_PER_CALL Iran nodes + one control node -> one record per Iran node. */
async function measure(target, iranNodes, controlNode) {
  const kind = target.method === "https" ? "http" : "tcp";
  const nodes = Array.isArray(iranNodes) ? iranNodes : [iranNodes];
  const names = [...nodes.map((n) => n.name), controlNode.name];
  const id = await startCheck(kind, target.target, names);
  const res = await pollResult(id, names);
  const control = parseNodeResult(res[controlNode.name], target.method);
  const testedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  return nodes.map((iranNode) => buildRecord({
    target, iranNode, controlNode, requestId: id, testedAt,
    iran: parseNodeResult(res[iranNode.name], target.method), control,
  }));
}

function readLines(rel) {
  try {
    return fs.readFileSync(path.join(ROOT, rel), "utf8").split(/\r?\n/);
  } catch {
    return null;
  }
}

function loadCursors() {
  try {
    const j = JSON.parse(fs.readFileSync(CURSORS, "utf8"));
    return j && typeof j === "object" && !Array.isArray(j) ? j : {};
  } catch {
    return {};
  }
}

function appendRecord(rec) {
  if (DRY) return;
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  let prefix = "";
  if (fs.existsSync(OUT)) {
    const fd = fs.openSync(OUT, "r");
    const size = fs.fstatSync(fd).size;
    if (size > 0) {
      const b = Buffer.alloc(1);
      fs.readSync(fd, b, 0, 1, size - 1);
      if (b[0] !== 0x0a) prefix = "\n";
    }
    fs.closeSync(fd);
  }
  fs.appendFileSync(OUT, `${prefix}${JSON.stringify(rec)}\n`);
}

function saveCursors(c) {
  if (DRY) return;
  fs.mkdirSync(path.dirname(CURSORS), { recursive: true });
  const sorted = Object.fromEntries(Object.entries(c).sort(([a], [b]) => a.localeCompare(b)));
  fs.writeFileSync(CURSORS, `${JSON.stringify(sorted, null, 2)}\n`);
}

function writeSummary() {
  if (DRY) return;
  try {
    const raw = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8").split(/\r?\n/).slice(-6000) : [];
    const recs = [];
    for (const l of raw) { if (!l) continue; try { recs.push(JSON.parse(l)); } catch { /* skip torn line */ } }
    fs.writeFileSync(SUMMARY, `${JSON.stringify(summarizeVantage(recs, Date.now()), null, 2)}\n`);
  } catch (e) {
    warn(`summary not written: ${e.message}`);
  }
}

function unavailable(reason) {
  const rec = {
    status: "vantage_unavailable",
    reason,
    tested_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    vantage: "check-host-iran-datacenter",
  };
  warn(`vantage_unavailable: ${reason}`);
  appendRecord(rec);
}

async function smoke() {
  const nodes = discoverNodes(await get(`${BASE}/nodes/hosts`));
  log(`Iran nodes: ${nodes.iran.length}`);
  for (const n of nodes.iran) log(`  ${n.name}  ${n.ip}  ${n.asn}  ${n.city}`);
  if (!nodes.iran.length || !nodes.control) {
    log("SMOKE FAIL: no Iran node or no control node");
    return 1;
  }
  const ir = nodes.iran[0];
  let bad = 0;
  for (const t of [
    { method: "tcp", target: "1.1.1.1:443", transport: "smoke", line_verb: "smoke", source_file: "smoke" },
    { method: "https", target: "https://example.com/", transport: "smoke", line_verb: "smoke", source_file: "smoke" },
  ]) {
    const [r] = await measure(t, [ir], nodes.control);
    const want = t.method === "tcp" ? "open" : "answered";
    const ok = r.iran === want && r.control === want;
    log(`  ${t.method} ${t.target}: iran=${r.iran} control=${r.control} codes=${r.http_code_iran}/${r.http_code_control} class=${r.class} ${ok ? "OK" : "FAIL"}`);
    if (!ok) bad += 1;
  }
  return bad ? 1 : 0;
}

async function main() {
  if (SMOKE) return smoke();

  let nodePayload;
  try {
    nodePayload = await get(`${BASE}/nodes/hosts`);
  } catch (e) {
    unavailable(`node_list_error:${e.message}`);
    return 0;
  }
  const { iran, control } = discoverNodes(nodePayload);
  if (!iran.length) { unavailable("no_iran_node"); return 0; }
  if (!control) { unavailable("no_control_node"); return 0; }
  log(`${iran.length} Iran node(s), control ${control.name}`);

  const cursors = loadCursors();
  const seen = new Set();
  const seed = Math.floor(Date.now() / 3_600_000);
  const tally = {};
  let calls = 0;
  let aborted = false;

  for (const src of SOURCES) {
    if (aborted || calls >= MAX_CALLS_PER_RUN) break;
    const rel = src.files.find((f) => fs.existsSync(path.join(ROOT, f)));
    if (!rel) continue;
    const lines = readLines(rel);
    if (!lines) continue;
    const plan = planSource({
      transport: src.transport, sourceFile: rel, lines, cursor: cursors[rel],
      take: src.take, unit: src.unit, callsLeft: MAX_CALLS_PER_RUN - calls, seen,
    });
    const skips = {};
    for (const s of plan.skipLog) skips[s] = (skips[s] || 0) + 1;
    log(`${src.transport} <- ${rel}: ${plan.items.length} item(s), skips ${JSON.stringify(skips)}`);
    let lastCursor = null;
    for (const item of plan.items) {
      let done = true;
      for (const t of item.targets) {
        const picked = pickIranNodes(iran, seed + calls * NODES_PER_CALL, NODES_PER_CALL);
        try {
          const recs = await measure(t, picked, control);
          calls += 1;
          for (const rec of recs) {
            appendRecord(rec);
            tally[rec.class] = (tally[rec.class] || 0) + 1;
          }
          log(`  ${t.method} ${t.target} via ${picked.map((n) => n.name).join(",")} -> ${recs.map((r) => r.class).join(",")} (${recs[0].request_id})`);
        } catch (e) {
          done = false;
          aborted = true;
          warn(`${e instanceof StopBatch ? "batch stopped" : "check failed"}: ${e.message}`);
          break;
        }
      }
      if (!done) break;
      lastCursor = item.cursorAfter;
    }
    if (!aborted) cursors[rel] = plan.finalCursor;
    else if (lastCursor !== null) cursors[rel] = lastCursor;
  }

  saveCursors(cursors);
  writeSummary();
  log(`done: ${calls} measurement(s), classes ${JSON.stringify(tally)}${aborted ? " (batch stopped early)" : ""}`);
  if (process.env.GITHUB_STEP_SUMMARY && !DRY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `### Iran datacenter vantage (check-host.net)\n\nMeasurements: ${calls}. Classes: \`${JSON.stringify(tally)}\`.\n\nTCP/HTTPS from an Iranian *datacenter* node only - not a Tor/obfs4/WebTunnel/meek/Snowflake handshake.\n`);
  }
  return 0;
}

main().then((c) => process.exit(c)).catch((e) => {
  if (SMOKE) { console.error(e); process.exit(1); }
  warn(`unexpected error (collector unaffected): ${e && e.message}`);
  process.exit(0);
});
