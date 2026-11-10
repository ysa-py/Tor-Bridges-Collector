#!/usr/bin/env node
/**
 * orbot_validate.mjs — Orbot / Tor Browser for Android bridge conformance gate.
 *
 * Orbot validates EVERY non-blank pasted line and rejects the whole paste when a
 * single line fails, which the user sees as "Invalid bridge format". This script
 * applies the same regex as Orbot's CustomBridgeBottomSheet to the published
 * lists and reports what would break a paste.
 *
 * Scope:
 *   default          export/orbot  (the paste-ready publication)
 *   --dir <path>     additional/alternative directory (repeatable)
 *   --all            also scan bridge/ and export/ (collector data sets)
 *   --soft           report only, never exit non-zero (dataset files may use a
 *                    different column layout on purpose)
 *
 * Usage:
 *   node scripts/orbot_validate.mjs
 *   node scripts/orbot_validate.mjs --check --json orbot-conformance-report.json
 *   node scripts/orbot_validate.mjs --all --soft --json full-report.json
 *   node scripts/orbot_validate.mjs --dir export/orbot --fix
 *
 * Exit codes: 0 ok, 1 hard violations (unless --soft).
 * No bridge line is ever deleted or rewritten semantically; --fix only removes
 * exact duplicates and normalises BOM/CR, the "Bridge " prefix, duplicated
 * parameters and fingerprint case.
 */
import { readdir, readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";
import { semanticProblems } from "./lib/orbot_format.mjs";

const CURRENT_ORBOT = /^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$/;
const LEGACY_ORBOT = /^(obfs4|webtunnel)\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d{1,5})\s+)([0-9A-F]{40})(\s+\S+)*$/;
const FINGERPRINT40 = /(?:^|\s)([0-9a-fA-F]{40})(?=\s|$)/;
const TEST_NET = /(?:^|\s)(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;

const args = process.argv.slice(2);
const has = (name) => args.includes(name);
const valueOf = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};

const fix = has("--fix");
const soft = has("--soft");
const jsonOut = valueOf("--json", null);
const dirArgs = args
  .map((arg, index) => (arg === "--dir" ? args[index + 1] : null))
  .filter(Boolean);
const dirs = dirArgs.length > 0 ? dirArgs : has("--all") ? ["export/orbot", "bridge", "export"] : ["export/orbot"];

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
      if (eq > 0) {
        const key = token.slice(0, eq);
        if (seen.has(key)) continue;
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

async function collect(dir) {
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) return [];
  } catch {
    return [];
  }
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isFile() && /\.(txt|torrc|lst)$/.test(entry.name)) files.push(path.join(dir, entry.name));
  }
  return files;
}

const files = (await Promise.all(dirs.map(collect))).flat().sort();
const report = { generatedAt: new Date().toISOString(), dirs, files: [] };
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
      if (entry.samples.length < 3) entry.samples.push(line.slice(0, 150));
    } else if (!line.startsWith("#")) {
      // Regex-valid but unusable: Orbot accepts the paste, then Tor answers "configuration is
      // invalid" when the user taps Connect (octet > 255, port 0 / > 65535, obfs4 without cert=...).
      const problems = semanticProblems(line);
      if (problems.length > 0) {
        entry.invalid += 1;
        entry.semantic = (entry.semantic ?? 0) + 1;
        if (entry.samples.length < 3) entry.samples.push(`[${problems[0]}] ${line.slice(0, 140)}`);
      }
    }
    if (!LEGACY_ORBOT.test(line)) entry.legacyInvalid += 1;
    // TEST-NET is only a dead placeholder for transports that dial the IP (obfs4 / vanilla).
    // Snowflake / meek_lite / webtunnel lines from Tor itself use it as a dummy address
    // and connect through url= / front=, so they are real bridges.
    if (TEST_NET.test(line) && (/^(obfs4\s|\d)/i.test(line.trim()) || !/\b(url|front|fronts)=/.test(line))) entry.placeholders += 1;
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
report.ok = totals.invalid === 0;

if (report.files.length === 0) console.error("[orbot-validate] no lists found in: " + dirs.join(", "));

console.log(
  "[orbot-validate] files=%d lines=%d hard=%d duplicates=%d placeholders=%d noFingerprint=%d fixed=%d",
  report.files.length, totals.lines, totals.invalid, totals.duplicates, totals.placeholders, totals.noFingerprint, totals.fixed,
);
for (const entry of report.files) {
  const interesting = entry.invalid > 0 || entry.duplicates > 0 || entry.placeholders > 0 || entry.noFingerprint > 0 || entry.fixed;
  if (!interesting) continue;
  console.log(
    "  %s lines=%d invalid=%d legacyInvalid=%d dupes=%d placeholder=%d noFP=%d%s",
    entry.file.padEnd(44), entry.lines, entry.invalid, entry.legacyInvalid, entry.duplicates,
    entry.placeholders, entry.noFingerprint, entry.fixed ? " fixed" : "",
  );
  for (const sample of entry.samples) console.log("    ! not pasteable: " + sample);
}

if (jsonOut) {
  await writeFile(jsonOut, JSON.stringify(report, null, 2));
  console.log("[orbot-validate] report: " + jsonOut);
}

if (!report.ok) {
  const failing = report.files.filter((entry) => entry.invalid > 0).map((entry) => `${entry.file} (${entry.invalid})`);
  console.error("[orbot-validate] FAIL: " + failing.join(", "));
  if (!soft) process.exit(1);
  console.error("[orbot-validate] (soft mode: exit 0)");
} else {
  console.log("[orbot-validate] OK: every line matches the current Orbot regex");
}
