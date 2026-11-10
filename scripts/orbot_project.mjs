#!/usr/bin/env node
/**
 * orbot_project.mjs — permanent fix for Orbot's "Invalid bridge format".
 *
 * Orbot validates every line of a paste and rejects the whole paste when one fails.
 * Lists under export/ (packs, rotation lists, *.torrc, elite packs...) are built by
 * other generators and legitimately contain `Bridge ` prefixes, `#` headers and
 * address-less snowflake/meek_lite lines. Rewriting them in place would break their
 * byte-exact generators and invariants, so this tool never touches them. Instead, every
 * hour it projects each such list into a paste-ready twin:
 *
 *     export/orbot/orbot_pack_<name>.txt     (only lines Orbot accepts + Tor can use)
 *     export/orbot/orbot_pack_manifest.json  (what was repaired / why a line was skipped)
 *
 * Nothing is deleted from the sources. Conjure is dropped (Orbot cannot use it). Lists
 * that are already 100% valid need no twin and get none.
 *
 * Usage: node scripts/orbot_project.mjs [--root <dir>] [--check] [--json <file>]
 *   --check  exit 1 when a projected file would still contain a line Orbot rejects
 */
import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { repairText, isOrbotValid, cleanBridgeLines } from "./lib/orbot_format.mjs";

const argv = process.argv.slice(2);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[index + 1] : fallback;
};
const ROOT = path.resolve(opt("--root", process.cwd()));
const CHECK = argv.includes("--check");
const JSON_OUT = opt("--json", null);

/** Domain / report files that are not bridge lists at all. */
const SKIP = /^(ct_|orbot_|.*report|.*manifest|reality_configs|bridges_api)/i;
const OUT_DIR = "export/orbot";
const PREFIX = "orbot_pack_";

async function writeIfChanged(rel, body) {
  const absolute = path.join(ROOT, rel);
  let previous = null;
  try {
    previous = await readFile(absolute, "utf8");
  } catch {
    /* new file */
  }
  if (previous === body) return false;
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, body, "utf8");
  return true;
}

const manifest = { generatedAt: new Date().toISOString(), note: "paste-ready twins of export/ lists; sources are never modified", packs: [] };
let hard = 0;
let written = 0;

let entries = [];
try {
  entries = await readdir(path.join(ROOT, "export"), { withFileTypes: true });
} catch {
  console.log("[orbot-project] no export/ directory — nothing to do");
}

for (const entry of entries.filter((item) => item.isFile() && /\.(txt|torrc)$/.test(item.name)).sort((a, b) => a.name.localeCompare(b.name))) {
  if (SKIP.test(entry.name)) continue;
  const source = `export/${entry.name}`;
  const raw = await readFile(path.join(ROOT, source), "utf8");
  const lines = cleanBridgeLines(raw);
  const invalidAsIs = lines.filter((line) => !isOrbotValid(line)).length;
  const { lines: good, rejected, repaired } = repairText(raw);
  const record = {
    source,
    lines: lines.length,
    invalidAsIs,
    projected: good.length,
    repaired,
    skipped: rejected,
    twin: null,
  };
  if (invalidAsIs > 0 && good.length > 0) {
    const base = entry.name.replace(/\.(txt|torrc)$/, "");
    const twin = `${OUT_DIR}/${PREFIX}${base}.txt`;
    const stillBad = good.filter((line) => !isOrbotValid(line));
    if (stillBad.length > 0) hard += stillBad.length;
    if (await writeIfChanged(twin, good.join("\n") + "\n")) written += 1;
    record.twin = twin;
  }
  manifest.packs.push(record);
}

const body = JSON.stringify(manifest, null, 1) + "\n";
// keep the manifest stable between runs when nothing but the timestamp would change
let previous = null;
try {
  previous = JSON.parse(await readFile(path.join(ROOT, `${OUT_DIR}/orbot_pack_manifest.json`), "utf8"));
} catch {
  /* first run */
}
const same = previous && JSON.stringify(previous.packs) === JSON.stringify(manifest.packs);
if (!same) await writeIfChanged(`${OUT_DIR}/orbot_pack_manifest.json`, body);

const twins = manifest.packs.filter((pack) => pack.twin);
console.log(`[orbot-project] sources=${manifest.packs.length} twins=${twins.length} (files rewritten: ${written}) still-invalid=${hard}`);
for (const pack of twins) {
  const skipped = Object.entries(pack.skipped).map(([k, v]) => `${k}=${v}`).join(",");
  console.log(`  ${pack.source.padEnd(38)} -> ${path.basename(pack.twin)}  lines=${pack.projected} repaired=${pack.repaired}${skipped ? "  skipped:" + skipped : ""}`);
}
if (JSON_OUT) await writeFile(path.resolve(JSON_OUT), body, "utf8");
if (CHECK && hard > 0) {
  console.error("[orbot-project] HARD: projected lines Orbot would reject");
  process.exit(1);
}
console.log("[orbot-project] OK");
