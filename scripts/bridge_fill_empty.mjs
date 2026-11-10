#!/usr/bin/env node
/**
 * bridge_fill_empty.mjs — keeps "orphan" lists alive.
 *
 * Some published files had no generator that refreshed them, so they sat empty or
 * frozen for months (export/ech_top_bridges.txt: 1 line, last touched 113 days ago) or
 * were stray copies that silently drifted from their canonical list
 * (bridge/snowflake_ipv6_tested, bridge/snowflak_ipv4_ipv6_all.txt). This tool:
 *
 *   1. syncs every alias file from its canonical list (byte-identical copy),
 *   2. rebuilds export/ech_top_bridges.txt from the AI-ranked pool: CDN-shielded /
 *      HTTPS-fronted bridges first (their endpoint cannot be blocked without collateral
 *      damage and TLS-ECH capable CDNs hide the SNI), diversified by network,
 *   3. NEVER deletes: lines already in ech_top_bridges.txt are kept (appended after the
 *      ranked ones) and only valid Orbot lines are ever written.
 *
 * Usage: node scripts/bridge_fill_empty.mjs [--root <dir>] [--ech-top 80] [--dry]
 */
import { readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";
import { repairForOrbot, isDialPlaceholder } from "./lib/orbot_format.mjs";
import { iranScoreAI, loadModel, parseLite, rangeKey } from "./lib/iran_antidpi_learn.mjs";
import { isCdnIpv4 } from "./lib/iran_antidpi_model.mjs";

const argv = process.argv.slice(2);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[index + 1] : fallback;
};
const ROOT = path.resolve(opt("--root", process.cwd()));
const TOP = Number(opt("--ech-top", "80")) || 80;
const DRY = argv.includes("--dry");

const ALIASES = [
  ["bridge/snowflake_ipv6_tested.txt", "bridge/snowflake_ipv6_tested"],
  ["bridge/snowflake_ipv4_ipv6_all.txt", "bridge/snowflak_ipv4_ipv6_all.txt"],
];

const read = async (rel) => {
  try {
    return await readFile(path.join(ROOT, rel), "utf8");
  } catch {
    return null;
  }
};

async function writeIfChanged(rel, body) {
  if ((await read(rel)) === body) return false;
  if (!DRY) await writeFile(path.join(ROOT, rel), body, "utf8");
  return true;
}

/* ------------------------------------------------------------------ aliases */
let synced = 0;
for (const [canonical, alias] of ALIASES) {
  const body = await read(canonical);
  if (!body || !body.trim()) continue;
  if (await writeIfChanged(alias, body)) {
    synced += 1;
    console.log(`[fill-empty] alias ${alias} <- ${canonical}`);
  }
}

/* ---------------------------------------------------------------- ech top N */
const SOURCES = [
  "export/orbot/orbot_iran_antidpi.txt", "export/orbot/orbot_harvest_live.txt",
  "export/orbot/orbot_webtunnel.txt", "export/orbot/orbot_obfs4.txt", "export/orbot/orbot_top.txt",
  "export/orbot/orbot_extended.txt", "bridge/iran_likely_working_webtunnel.txt",
  "bridge/iran_likely_working_obfs4.txt", "bridge/webtunnel_72h.txt", "bridge/obfs4_72h.txt",
];

const model = await loadModel(ROOT);
const pool = new Map();
const density = new Map();
for (const rel of SOURCES) {
  const body = await read(rel);
  if (!body) continue;
  for (const raw of body.split(/\r?\n/)) {
    const fixed = repairForOrbot(raw);
    if (!fixed.ok || isDialPlaceholder(fixed.line, fixed.transport)) continue;
    const parsed = parseLite(fixed.line);
    if (!parsed || !parsed.fp) continue;
    if (parsed.transport !== "webtunnel" && parsed.transport !== "obfs4") continue;
    if (pool.has(parsed.identity)) continue;
    pool.set(parsed.identity, parsed);
    const key = parsed.isIpv4 ? parsed.host.split(".").slice(0, 3).join(".") : null;
    if (key) density.set(key, (density.get(key) ?? 0) + 1);
  }
}

function echBonus(parsed) {
  let bonus = 0;
  if (parsed.transport === "webtunnel") bonus += 10;
  if (parsed.isIpv4 && isCdnIpv4(parsed.host)) bonus += 8;
  if (parsed.params.url && /^https:\/\//i.test(parsed.params.url)) bonus += 4;
  if (parsed.port === 443) bonus += 4;
  return bonus;
}

const ranked = [...pool.values()]
  .map((parsed) => {
    const key = parsed.isIpv4 ? parsed.host.split(".").slice(0, 3).join(".") : null;
    const ai = iranScoreAI(parsed, { density: key ? density.get(key) : 1 }, model);
    return { parsed, score: ai.score + echBonus(parsed) };
  })
  .sort((a, b) => b.score - a.score || a.parsed.line.localeCompare(b.parsed.line));

const perRange = new Map();
const perUrlHost = new Map();
const chosen = [];
for (const item of ranked) {
  if (chosen.length >= TOP) break;
  const range = item.parsed.isIpv4 ? item.parsed.host.split(".").slice(0, 3).join(".") : rangeKey(item.parsed) ?? item.parsed.host;
  let urlHost = null;
  try {
    urlHost = item.parsed.params.url ? new URL(item.parsed.params.url).hostname : null;
  } catch {
    urlHost = null;
  }
  if ((perRange.get(range) ?? 0) >= 1) continue;
  if (urlHost && (perUrlHost.get(urlHost) ?? 0) >= 2) continue;
  perRange.set(range, 1);
  if (urlHost) perUrlHost.set(urlHost, (perUrlHost.get(urlHost) ?? 0) + 1);
  chosen.push(item.parsed.line);
}

let echWritten = false;
if (chosen.length > 0) {
  const existing = ((await read("export/ech_top_bridges.txt")) ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const keep = existing.filter((line) => !chosen.includes(line) && !line.startsWith("#"));
  echWritten = await writeIfChanged("export/ech_top_bridges.txt", [...chosen, ...keep].join("\n") + "\n");
}
console.log(`[fill-empty] aliases synced=${synced} ech_top candidates=${pool.size} chosen=${chosen.length} written=${echWritten}`);
if (!(await stat(path.join(ROOT, "export")).catch(() => null))) console.log("[fill-empty] no export/ directory");
