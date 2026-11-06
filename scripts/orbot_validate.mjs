#!/usr/bin/env node
/**
 * orbot_validate.mjs — Orbot/Tor Browser for Android bridge conformance gate.
 *
 * Orbot validates EVERY non-blank pasted line and rejects the whole paste if one
 * line fails, which surfaces as "Invalid bridge format". This script checks the
 * published lists with the current Orbot regex and the stricter legacy regex,
 * then reports duplicates, unreachable TEST-NET placeholders, missing
 * fingerprints and argument characters that older builds reject.
 *
 * Usage:
 *   node scripts/orbot_validate.mjs                       # scan bridge + export/orbot
 *   node scripts/orbot_validate.mjs --dir export/orbot    # one directory
 *   node scripts/orbot_validate.mjs --check               # exit 1 on any HARD error
 *   node scripts/orbot_validate.mjs --fix                 # safe in-place normalisation
 *   node scripts/orbot_validate.mjs --json report.json    # machine readable report
 *
 * Exit codes: 0 ok, 1 hard violations (current Orbot) or --check with findings.
 * Only exact duplicates / BOM / CR / "Bridge " prefix / duplicate params are
 * touched by --fix. No bridge line is ever deleted or rewritten semantically.
 */
import { readdir, readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";

const CURRENT_ORBOT = /^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$/;
const LEGACY_ORBOT = /^(obfs4|webtunnel)\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d{1,5})\s+)([0-9A-F]{40})(\s+\S+)*$/;
const FINGERPRINT40 = /(?:^|\s)([0-9a-fA-F]{40})(?=\s|$)/;
const TEST_NET = /(?:^|\s)(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};

const fix = flag("--fix");
const check = flag("--check");
const jsonOut = value("--json", null);
const explicitDirs = args
  .map((arg, index) => (arg === "--dir" ? args[index + 1] : null))
  .filter(Boolean);
const dirs = explicitDirs.length > 0 ? explicitDirs : ["bridge", "export/orbot", "export"];

/** Safe, semantic-preserving normalisation. */
function normalise(line) {
  let out = line.replace(/^\uFEFF/, "").replace(/\r$/, "").replace(/\u00A0/g, " ").trimEnd();
  out = out.replace(/^\s*Bridge\s+/i, "");
  const tokens = out.split(/\s+/);
  if (tokens.length > 2) {
    const head = tokens.slice(0, 3);
    const seen = new Set();
    const params = [];
    for (const token of tokens.slice(3)) {
      const eq = token.indexOf("=");
      const key = eq > 0 ? token.slice(0, eq) : null;
      if (key) {
        if (seen.has(key)) continue; // drop duplicated key, first one wins
        seen.add(key);
      }
      params.push(token);
    }
    out = [...head, ...params].join(" ");
  }
  const fp = FINGERPRINT40.exec(out);
  if (fp) out = out.replace(fp[1], fp[1].toUpperCase());
  return out;
}

async function collectFiles(dir) {
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) return [];
  } catch {
    return [];
  }
  const entries = await readdir(dir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".txt"))
    .map((entry) => path.join(dir, entry.name))
    .filter((file) => !/node_modules/.test(file));
}

const files = (await Promise.all(dirs.map(collectFiles))).flat().sort();
const report = { generatedAt: new Date().toISOString(), dirs, files: [], totals: {} };
const totals = { lines: 0, invalid: 0, legacyInvalid: 0, duplicates: 0, placeholders: 0, noFingerprint: 0, fixed: 0 };

for (const file of files) {
  const original = await readFile(file, "utf8");
  const rawLines = original.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const seen = new Set();
  const kept = [];
  const entry = { file, lines: rawLines.length, invalid: 0, legacyInvalid: 0, duplicates: 0, placeholders: 0, noFingerprint: 0, samples: [] };

  for (const rawLine of rawLines) {
    const line = normalise(rawLine);
    if (!line) continue;
    if (seen.has(line)) {
      entry.duplicates += 1;
      continue;
    }
    seen.add(line);
    kept.push(line);

    if (!CURRENT_ORBOT.test(line)) {
      entry.invalid += 1;
      if (entry.samples.length < 3) entry.samples.push({ line: line.slice(0, 160), reason: "current Orbot regex" });
    }
    if (!LEGACY_ORBOT.test(line)) entry.legacyInvalid += 1;
    if (TEST_NET.test(line)) entry.placeholders += 1;
    if (!FINGERPRINT40.test(line)) entry.noFingerprint += 1;
  }

  if (fix) {
    const next = kept.join("\n") + (kept.length > 0 ? "\n" : "");
    if (next !== original) {
      await writeFile(file, next, "utf8");
      entry.fixed = true;
    }
  }

  for (const key of ["lines", "invalid", "legacyInvalid", "duplicates", "placeholders", "noFingerprint"]) {
    totals[key] += entry[key];
  }
  if (entry.fixed) totals.fixed += 1;
  report.files.push(entry);
}

report.totals = totals;

if (report.files.length === 0) {
  console.error("[orbot-validate] no .txt lists found in: " + dirs.join(", "));
}

const hard = report.files.filter((entry) => entry.invalid > 0);
const warnings = report.files.filter((entry) => entry.duplicates > 0 || entry.placeholders > 0 || entry.noFingerprint > 0);
const legacyOnly = report.files.filter((entry) => entry.legacyInvalid > entry.invalid);

console.log("[orbot-validate] files=%d lines=%d hard=%d legacyOnly=%d duplicates=%d placeholders=%d noFingerprint=%d",
  report.files.length, totals.lines, totals.invalid, legacyOnly.length, totals.duplicates, totals.placeholders, totals.noFingerprint);
for (const entry of report.files) {
  console.log(
    "  %s lines=%d invalid=%d legacyInvalid=%d dupes=%d placeholder=%d noFP=%d%s",
    entry.file.padEnd(42), entry.lines, entry.invalid, entry.legacyInvalid, entry.duplicates, entry.placeholders, entry.noFingerprint,
    entry.fixed ? " fixed" : "",
  );
  for (const sample of entry.samples) console.log("    ! " + sample.reason + ": " + sample.line);
}
if (warnings.length > 0) console.log("[orbot-validate] warnings: lists containing placeholders/duplicates are not paste-ready: " + warnings.map((entry) => path.basename(entry.file)).join(", "));
if (legacyOnly.length > 0) console.log("[orbot-validate] note: " + legacyOnly.length + " list(s) contain IPv6/snowflake/meek/vanilla lines that older Orbot builds reject; point users to orbot_top.txt for legacy devices.");

if (jsonOut) {
  await writeFile(jsonOut, JSON.stringify(report, null, 2));
  console.log("[orbot-validate] report written to " + jsonOut);
}

if (hard.length > 0) {
  console.error("[orbot-validate] FAIL: " + hard.map((entry) => `${entry.file} (${entry.invalid})`).join(", "));
  process.exit(1);
}
if (check && report.files.some((entry) => entry.duplicates > 0 || entry.invalid > 0)) {
  console.error("[orbot-validate] FAIL(--check): duplicates or invalid lines present");
  process.exit(1);
}
console.log("[orbot-validate] OK: every published line matches the current Orbot regex");
