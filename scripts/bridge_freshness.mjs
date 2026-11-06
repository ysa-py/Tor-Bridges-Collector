#!/usr/bin/env node
/**
 * bridge_freshness.mjs — "is every published bridge list alive and moving?" watchdog.
 *
 * For every file in bridge/ it records sha256, bridge-line count and when the CONTENT last
 * changed (carried over from the previous manifest, so it works with shallow CI checkouts).
 * Files that are empty / comment-only, or whose content has not moved for --stale-hours
 * while their siblings did, are reported in the step summary. Nothing is ever deleted or
 * rewritten here: healing is done by bridge_autofill / bridge_harvest, this tool only makes
 * silence visible.
 *
 *   node scripts/bridge_freshness.mjs [--dir bridge] [--out data/bridge_freshness.json]
 *        [--stale-hours 36] [--strict]
 * Exit 0 unless --strict and an empty list exists.
 */
import { readdir, readFile, writeFile, mkdir, appendFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

const argv = process.argv.slice(2);
const opt = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const DIR = opt("--dir", "bridge");
const OUT = opt("--out", "data/bridge_freshness.json");
const STALE_HOURS = Number(opt("--stale-hours", "36"));
const now = new Date();

const isBridgeLine = (line) => /^(?:(?:obfs4|webtunnel|snowflake|meek_lite|dnstt)\s+)?(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])(?::\d{1,5})?\s/.test(line.trim());

let previous = {};
try {
  previous = JSON.parse(await readFile(OUT, "utf8")).files ?? {};
} catch {
  /* first run */
}

const files = {};
const empty = [];
const stale = [];
for (const name of (await readdir(DIR)).sort()) {
  const full = path.join(DIR, name);
  let buf;
  try {
    buf = await readFile(full);
  } catch {
    continue;
  }
  if (!/\.(txt|json)$/.test(name) && !/^snowflake_ipv6_tested$/.test(name)) continue;
  const text = buf.toString("utf8");
  const sha = createHash("sha256").update(buf).digest("hex");
  const lines = name.endsWith(".txt") || !name.includes(".") ? text.split(/\r?\n/).filter(isBridgeLine).length : null;
  const before = previous[name];
  const changedAt = before && before.sha256 === sha ? before.last_changed_at : now.toISOString();
  const ageHours = Math.round((now - new Date(changedAt)) / 36e5);
  files[name] = { sha256: sha, bytes: buf.length, bridges: lines, last_changed_at: changedAt, unchanged_hours: ageHours };
  if (buf.length === 0 || (lines !== null && lines === 0 && name.endsWith(".txt"))) empty.push(name);
}

// A list is "stale" when it did not move for a long time although the pool as a whole did.
const newestMove = Math.max(...Object.values(files).map((f) => new Date(f.last_changed_at).getTime()));
for (const [name, f] of Object.entries(files)) {
  if (f.unchanged_hours >= STALE_HOURS && newestMove - new Date(f.last_changed_at) >= STALE_HOURS * 36e5) stale.push(name);
}

const report = { generated_at: now.toISOString(), stale_hours: STALE_HOURS, files_total: Object.keys(files).length, empty, stale, files };
await mkdir(path.dirname(OUT), { recursive: true });
await writeFile(OUT, JSON.stringify(report, null, 1) + "\n");

const summary = `[bridge-freshness] files=${report.files_total} empty=${empty.length} stale>=${STALE_HOURS}h=${stale.length}`;
console.log(summary);
for (const n of empty) console.log(`  EMPTY  ${n}`);
for (const n of stale) console.log(`  STALE  ${n} (${files[n].unchanged_hours}h)`);
if (process.env.GITHUB_STEP_SUMMARY) {
  await appendFile(process.env.GITHUB_STEP_SUMMARY, `### Bridge freshness\n\n${summary}\n\n${[...empty.map((n) => `- empty: \`${n}\``), ...stale.map((n) => `- stale: \`${n}\``)].join("\n")}\n`).catch(() => {});
}
process.exit(argv.includes("--strict") && empty.length ? 1 : 0);
