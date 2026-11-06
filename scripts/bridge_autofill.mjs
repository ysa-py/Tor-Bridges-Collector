#!/usr/bin/env node
/**
 * bridge_autofill.mjs — automatic pool maintenance for this repository.
 *
 * Goals (all offline, dependency-free, Node >= 20):
 *   1. never leave an empty / semantically empty bridge list,
 *   2. merge every source into hourly, AI-ranked, network-diversified, Orbot-safe
 *      lists (dynamic rotation, not a frozen snapshot),
 *   3. make torrc-sourced bridges pasteable in Orbot (`Bridge ` lines are the
 *      classic source of "Invalid bridge format"),
 *   4. report duplicates / placeholders / invalid lines instead of hiding them,
 *   5. never delete a bridge line: only exact duplicates and pure noise are
 *      removed, and every rewrite is validated before it is written.
 *
 * Modes (combinable):
 *   (default)                     report only
 *   --fix                         strip BOM/CR, upper-case fingerprints, drop exact
 *                                 duplicate lines (no semantic change)
 *   --fill                        refill lists that are empty or below --min-lines
 *                                 from sibling lists of the same transport/IP family
 *   --dynamic                     rebuild the AI-ranked hourly rotation lists
 *   --check                       exit 1 on hard problems (CI gate)
 *   --json <path>                 write the machine readable report
 *   --root <dir>                  repository root (default: cwd)
 *   --min-lines <n>               fill threshold (default 40)
 *   --top <n>                     size of the AI list (default 60)
 *
 * Exit codes: 0 ok, 1 hard problems with --check.
 */
import { readdir, readFile, stat, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { iranScore, hardenObfs4 } from "./lib/iran_antidpi_model.mjs";
import { iranScoreAI, loadModel, trainModel, saveModel } from "./lib/iran_antidpi_learn.mjs";

const ORBOT_LINE = /^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$/;
const LEGACY_LINE = /^(obfs4|webtunnel)\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d{1,5})\s+)([0-9A-F]{40})(\s+\S+)*$/;
const FP40 = /(?:^|\s)([0-9a-fA-F]{40})(?=\s|$)/;
const TEST_NET = /(?:^|\s)(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;
const TRANSPORTS = ["obfs4", "webtunnel", "snowflake", "meek_lite", "dnstt"];


const DUMMY_HOST = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:0?db8:)/i;
const isDummyHost = (host) => DUMMY_HOST.test(host);

/** Diversity key: network prefix for dialled transports, front/url domain for tunnelled ones. */
function divKey(transport, host, params, isIpv4, octets) {
  if (transport === "webtunnel" || transport === "snowflake" || transport === "meek_lite") {
    const raw = params.url ?? params.front ?? params.fronts ?? "";
    try {
      return raw ? new URL(raw.includes("://") ? raw : `https://${raw}`).hostname : isDummyHost(host) ? `dummy:${host}` : null;
    } catch {
      return isDummyHost(host) ? `dummy:${host}` : null;
    }
  }
  return isIpv4 ? host.split(".").slice(0, octets).join(".") : null;
}

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
};

const ROOT = path.resolve(opt("--root", process.cwd()));
const MODE = {
  fix: has("--fix"),
  fill: has("--fill"),
  dynamic: has("--dynamic"),
  check: has("--check"),
  json: opt("--json", null),
  minLines: Number(opt("--min-lines", "40")) || 40,
  top: Number(opt("--top", "60")) || 60,
};
const SCAN_DIRS = ["bridge", "export/orbot", "export"];
const PASTE_DIRS = ["export/orbot"];
const ROTATION_BUCKETS = 6;
const DERIVED_FILES = new Set(["export/iran_cut_pack.txt", "export/iran_anti_dpi_elite.txt", "export/iran_anti_dpi_elite.json"]);

/* ------------------------------------------------------------------ helpers */

const readLines = async (file) => (await readFile(file, "utf8")).split(/\r?\n/);

function normalise(line) {
  let out = line.replace(/^\uFEFF/, "").replace(/\r$/, "").replace(/\u00A0/g, " ").trimEnd();
  out = out.replace(/^\s*Bridge\s+/i, "");
  if (!out.trim()) return "";
  const tokens = out.trim().split(/\s+/);
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
  const fp = FP40.exec(out);
  if (fp) out = out.replace(fp[1], fp[1].toUpperCase());
  return out.trim();
}

function parse(line) {
  const text = normalise(line);
  if (!text || text.startsWith("#")) return null;
  const tokens = text.split(" ");
  const first = tokens[0].toLowerCase();
  let transport = "vanilla";
  let address = tokens[0];
  let rest = tokens.slice(1);
  if (TRANSPORTS.includes(first)) {
    transport = first;
    address = tokens[1] ?? "";
    rest = tokens.slice(2);
  }
  const addr = /^(\[[0-9a-fA-F:.]+]|[^\s:/]+)(?::(\d{1,5}))?$/.exec(address);
  if (!addr) return null;
  const host = addr[1].replace(/^\[|\]$/g, "");
  const port = addr[2] ? Number(addr[2]) : 0;
  const fpMatch = rest.map((token) => FP40.exec(token)?.[1]).find(Boolean) ?? null;
  const params = {};
  for (const token of rest) {
    const eq = token.indexOf("=");
    if (eq > 0) params[token.slice(0, eq).toLowerCase()] = token.slice(eq + 1);
  }
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const isIpv6 = !isIpv4 && host.includes(":");
  return {
    line: text,
    transport,
    host,
    port,
    fp: fpMatch ? fpMatch.toUpperCase() : null,
    params,
    isIpv4,
    isIpv6,
    valid: ORBOT_LINE.test(text),
    legacySafe: LEGACY_LINE.test(text),
    // A TEST-NET / documentation address is only a dead placeholder when the transport
    // actually dials it (obfs4, vanilla). Snowflake, meek_lite and WebTunnel lines written
    // by Tor itself use 192.0.2.x / 2001:db8:: as a dummy address and connect through
    // url= / front= instead, so those are REAL, working bridges.
    placeholder: isDummyHost(host) && !(transport !== "obfs4" && transport !== "vanilla" && (params.url || params.front || params.fronts)),
    identity: `${transport}|${host}|${port}|${(fpMatch ?? "").toUpperCase()}`,
    subnet16: divKey(transport, host, params, isIpv4, 2),
    subnet24: divKey(transport, host, params, isIpv4, 3),
  };
}

/** transport + IP family implied by a file name (vanilla_ipv6_tested, obfs4_72h, …) */
function familyOf(file) {
  const base = path.basename(file).toLowerCase().replace(/\.(txt|torrc)$/, "");
  const transport = ["obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla", "dnstt"].find((name) =>
    base.startsWith(name),
  ) ?? null;
  const ip = base.includes("ipv6") ? "ipv6" : base.includes("ipv4") ? "ipv4" : null;
  return { transport, ip, base };
}

async function listFiles(dir) {
  const absolute = path.join(ROOT, dir);
  try {
    const info = await stat(absolute);
    if (!info.isDirectory()) return [];
  } catch {
    return [];
  }
  const entries = await readdir(absolute, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && /\.(txt|torrc)$/.test(entry.name))
    .map((entry) => path.join(dir, entry.name))
    .sort();
}

/* ------------------------------------------------------ AI scoring + diversity */

/**
 * Internal ranking model. Hand-tuned logistic-style weights: no network, no API
 * key, deterministic, and every term is explainable.
 */
function scoreLine(parsed, ctx) {
  // hand-tuned prior + self-trained adjustment (data/iran_antidpi_weights.json); with no
  // model on disk this is exactly the prior, so the pipeline never depends on training.
  return MODEL ? iranScoreAI(parsed, ctx ?? {}, MODEL) : iranScore(parsed, ctx);
}

let MODEL = await loadModel(ROOT);

function bucketOf(identity) {
  const digest = createHash("sha1").update(identity).digest();
  return digest.readUInt32BE(0) % ROTATION_BUCKETS;
}

function selectDiverse(pool, top, rotate) {
  const ordered = [...pool].sort((a, b) => {
    const ra = ((a.bucket - rotate + ROTATION_BUCKETS) % ROTATION_BUCKETS) * 1000;
    const rb = ((b.bucket - rotate + ROTATION_BUCKETS) % ROTATION_BUCKETS) * 1000;
    return ra - rb || b.score - a.score;
  });
  const per16 = new Map();
  const per24 = new Map();
  const seenFp = new Set();
  const perTransport = new Map();
  const selected = [];
  for (const candidate of ordered) {
    if (selected.length >= top) break;
    if (candidate.parsed.placeholder || !candidate.parsed.valid) continue;
    if (candidate.parsed.fp && seenFp.has(candidate.parsed.fp)) continue;
    const cap16 = 3;
    const cap24 = 1;
    const key16 = candidate.parsed.subnet16 ?? candidate.parsed.host;
    const key24 = candidate.parsed.subnet24 ?? candidate.parsed.host;
    if ((per16.get(key16) ?? 0) >= cap16) continue;
    if ((per24.get(key24) ?? 0) >= cap24) continue;
    const transportCap = candidate.parsed.transport === "webtunnel" ? Math.ceil(top * 0.45) : Math.ceil(top * 0.5);
    if ((perTransport.get(candidate.parsed.transport) ?? 0) >= transportCap) continue;
    per16.set(key16, (per16.get(key16) ?? 0) + 1);
    per24.set(key24, (per24.get(key24) ?? 0) + 1);
    perTransport.set(candidate.parsed.transport, (perTransport.get(candidate.parsed.transport) ?? 0) + 1);
    if (candidate.parsed.fp) seenFp.add(candidate.parsed.fp);
    selected.push(candidate);
  }
  return selected;
}

/* --------------------------------------------------------------------- scan */

const report = {
  generatedAt: new Date().toISOString(),
  root: ROOT,
  mode: MODE,
  files: [],
  actions: [],
  dynamic: null,
  hard: [],
  warnings: [],
};

const inventory = new Map(); // file -> { lines, valid, conjure, dupes, entries }

for (const dir of SCAN_DIRS) {
  for (const file of await listFiles(dir)) {
    const absolute = path.join(ROOT, file);
    const raw = await readFile(absolute, "utf8");
    const statInfo = await stat(absolute);
    const lines = raw.split(/\r?\n/).filter((line) => line.trim());
    const seen = new Set();
    const entries = [];
    let valid = 0;
    let conjure = 0;
    let dupes = 0;
    let comments = 0;
    let invalid = 0;
    let placeholders = 0;
    const rejected = [];
    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (trimmed.startsWith("#")) {
        comments += 1;
        continue;
      }
      if (/^(bridge\s+)?conjure\b/i.test(trimmed)) {
        conjure += 1;
        continue;
      }
      const parsed = parse(rawLine);
      if (!parsed || !parsed.valid) {
        invalid += 1;
        if (rejected.length < 400) {
          rejected.push({ file, reason: parsed ? "orbot-regex" : "unparseable", line: trimmed.slice(0, 200) });
        }
        continue;
      }
      valid += 1;
      if (parsed.placeholder) placeholders += 1;
      if (seen.has(parsed.line)) dupes += 1;
      else seen.add(parsed.line);
      entries.push(parsed);
    }
    const entry = {
      file,
      rejected,
      bytes: raw.length,
      mtime: statInfo.mtimeMs,
      lines: lines.length,
      valid,
      invalid,
      comments,
      dupes,
      conjure,
      placeholders,
      entries,
      pasteReady: PASTE_DIRS.some((prefix) => file.startsWith(prefix)),
      family: familyOf(file),
    };
    inventory.set(file, entry);
    report.files.push({
      file,
      lines: entry.lines,
      valid,
      invalid,
      comments,
      dupes,
      conjure,
      placeholders,
      pasteReady: entry.pasteReady,
      status: valid === 0 ? "empty" : entry.dupes > 0 ? "duplicates" : "ok",
    });
    if (conjure > 0) report.hard.push(`${file}: ${conjure} conjure line(s) — Orbot cannot use this transport`);
    if (entry.pasteReady && invalid > 0) report.hard.push(`${file}: ${invalid} line(s) rejected by Orbot's regex`);
    if (dir === "bridge" && valid === 0) report.warnings.push(`${file}: no valid bridge line (refillable with --fill)`);
    if (valid === 0 && lines.length > 0 && entry.invalid === 0) report.warnings.push(`${file}: only comments/headers`);
    if (placeholders > 0) report.warnings.push(`${file}: ${placeholders} TEST-NET placeholder endpoint(s) — parse but never connect`);
  }
}

/* ---------------------------------------------------------------------- fill */

const fillTargets = [...inventory.values()].filter(
  // orbot_pack_* are exact projections of export/ packs (scripts/orbot_project.mjs): never padded.
  (entry) =>
    entry.valid < MODE.minLines &&
    (entry.file.startsWith("bridge/") || entry.file.startsWith("export/orbot/")) &&
    !path.basename(entry.file).startsWith("orbot_pack_"),
);

for (const target of fillTargets) {
  const { transport, ip } = target.family;
  const have = new Set(target.entries.map((entry) => entry.identity));
  const pool = [];
  for (const source of inventory.values()) {
    if (source.file === target.file) continue;
    if (source.family.transport !== transport) continue;
    if (ip && source.family.ip && source.family.ip !== ip) continue;
    for (const parsed of source.entries) {
      if (!parsed.valid || parsed.placeholder) continue;
      if (ip === "ipv6" && !parsed.isIpv6) continue;
      if (ip === "ipv4" && !parsed.isIpv4) continue;
      if (!have.has(parsed.identity)) pool.push(parsed);
    }
  }
  const unique = new Map();
  for (const parsed of pool) if (!unique.has(parsed.identity)) unique.set(parsed.identity, parsed);
  const candidates = [...unique.values()].sort((a, b) => scoreLine(b).score - scoreLine(a).score);
  const need = Math.max(0, MODE.minLines - target.valid);
  const chosen = candidates.slice(0, need);
  report.actions.push({
    kind: "fill",
    file: target.file,
    family: `${transport ?? "any"}/${ip ?? "any"}`,
    before: target.valid,
    available: candidates.length,
    add: chosen.length,
    applied: false,
  });
  if (!MODE.fill || chosen.length === 0) continue;
  const existing = (await readFile(path.join(ROOT, target.file), "utf8")).split(/\r?\n/).filter((line) => line.trim());
  const merged = [...existing.map((line) => normalise(line)).filter(Boolean)];
  const seen = new Set(merged);
  for (const parsed of chosen) if (!seen.has(parsed.line)) { merged.push(parsed.line); seen.add(parsed.line); }
  const sorted = [...merged].sort((a, b) => {
    const pa = parse(a), pb = parse(b);
    return (pb ? scoreLine(pb).score : 0) - (pa ? scoreLine(pa).score : 0);
  });
  await writeFile(path.join(ROOT, target.file), sorted.join("\n") + "\n", "utf8");
  report.actions[report.actions.length - 1].applied = true;
}

/* ----------------------------------------------------------------------- fix */

if (MODE.fix) {
  for (const entry of inventory.values()) {
    // torrc syntax REQUIRES the "Bridge " prefix, so those files are never
    // rewritten here; export/orbot/orbot_from_torrc.txt carries the Orbot form.
    if (entry.file.endsWith(".torrc")) continue;
    // Byte-exact derived artifacts (invariants C8 / C11 compare them with a fresh regeneration):
    // their generators own the formatting, rewriting them here would make CI fail.
    if (DERIVED_FILES.has(entry.file)) continue;
    const absolute = path.join(ROOT, entry.file);
    const raw = await readFile(absolute, "utf8");
    const out = [];
    const seen = new Set();
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue;
      if (line.trim().startsWith("#")) {
        out.push(line.replace(/\uFEFF/g, "").replace(/\r$/, ""));
        continue;
      }
      if (/^(bridge\s+)?conjure\b/i.test(line.trim())) {
        report.actions.push({ kind: "purge", file: entry.file, line: line.trim(), applied: true });
        continue;
      }
      const fixed = normalise(line);
      if (!fixed) continue;
      if (seen.has(fixed)) {
        report.actions.push({ kind: "dedupe", file: entry.file, line: fixed, applied: true });
        continue;
      }
      seen.add(fixed);
      out.push(fixed);
    }
    const next = out.join("\n") + (out.length > 0 ? "\n" : "");
    if (next !== raw) {
      await writeFile(absolute, next, "utf8");
      if (!report.actions.some((action) => action.kind === "normalise" && action.file === entry.file)) {
        report.actions.push({ kind: "normalise", file: entry.file, applied: true });
      }
    }
  }
}

/* ------------------------------------------------------------------- dynamic */

if (MODE.dynamic) {
  // Hourly self-training on the repository's own Iran evidence (blocked vs likely-working).
  // A failure or too little evidence keeps the previous model; it is never fatal.
  try {
    const trained = await trainModel(ROOT);
    if (trained.ok) {
      MODEL = trained.model;
      await saveModel(ROOT, MODEL);
      report.actions.push({ kind: "train", file: "data/iran_antidpi_weights.json", written: MODEL.samples.positive + MODEL.samples.negative, applied: true });
      console.log(
        "[bridge-autofill] AI model retrained: samples=%d holdout-auc=%s confidence=%s ranges=%d",
        MODEL.samples.positive + MODEL.samples.negative, MODEL.holdout.auc, MODEL.confidence, Object.keys(MODEL.ranges).length,
      );
    } else {
      report.warnings.push(`AI model not retrained: ${trained.reason}`);
    }
  } catch (error) {
    report.warnings.push(`AI model training failed (${error.message}) — previous model kept`);
  }
  const blocklists = new Set();
  for (const name of await listFiles("bridge")) {
    if (!/blocked|iran_blocked|flagged/i.test(name)) continue;
    const info = inventory.get(name);
    if (!info) continue;
    for (const parsed of info.entries) blocklists.add(parsed.identity);
  }

  const pool = new Map();
  // Probe / speed evidence gathered by bridge_harvest.mjs (alive streak, fail streak, RTT).
  const harvestEvidence = new Map();
  try {
    const harvestDoc = JSON.parse(await readFile(path.join(ROOT, "data/bridge_harvest_pool.json"), "utf8"));
    for (const rec of harvestDoc.bridges ?? []) {
      const parsedRec = parse(rec.l);
      if (parsedRec) harvestEvidence.set(parsedRec.identity, rec);
    }
  } catch {
    /* no harvest pool yet */
  }

  // /24 density over every candidate: ranges stuffed with bridges get blocked together.
  const density = new Map();
  const seenIdentity = new Set();
  for (const entry of inventory.values()) {
    if (!entry.pasteReady && !entry.file.startsWith("bridge/")) continue;
    if (/blocked|flagged/i.test(entry.file)) continue;
    for (const parsed of entry.entries) {
      if (seenIdentity.has(parsed.identity) || !parsed.isIpv4) continue;
      seenIdentity.add(parsed.identity);
      const key = parsed.host.split(".").slice(0, 3).join(".");
      density.set(key, (density.get(key) ?? 0) + 1);
    }
  }

  for (const entry of inventory.values()) {
    if (!entry.pasteReady && !entry.file.startsWith("bridge/")) continue;
    if (/blocked|flagged/i.test(entry.file)) continue;
    const freshHours = (Date.now() - entry.mtime) / 3_600_000;
    for (const parsed of entry.entries) {
      if (!parsed.valid || parsed.placeholder || !parsed.fp) continue;
      if (parsed.transport === "vanilla" || parsed.transport === "dnstt") continue;
      if (blocklists.has(parsed.identity)) continue;
      const key = parsed.identity;
      const evidence = harvestEvidence.get(parsed.identity);
      const { score, why } = scoreLine(parsed, {
        freshHours,
        alive: evidence ? (evidence.as ?? 0) > 0 : undefined,
        aliveStreak: evidence?.as,
        failStreak: evidence?.fl,
        rttMs: evidence?.rtt,
        density: parsed.isIpv4 ? density.get(parsed.host.split(".").slice(0, 3).join(".")) : 1,
      });
      const previous = pool.get(key);
      const candidate = {
        parsed,
        score,
        why,
        bucket: bucketOf(key),
        sources: previous ? [...previous.sources, entry.file] : [entry.file],
      };
      if (!previous || candidate.score > previous.score) {
        candidate.sources = [...new Set(candidate.sources)];
        pool.set(key, candidate);
      }
    }
  }

  const rotate = Math.floor(Date.now() / 3_600_000) % ROTATION_BUCKETS;
  const selected = selectDiverse([...pool.values()], MODE.top, rotate);
  const ordered = [...selected].sort((a, b) => b.score - a.score);
  // obfs4 iat-mode is a client-side option: raise 0 -> 1 so flow-timing DPI sees randomised
  // inter-arrival times. Only applied when the hardened line is still Orbot-valid.
  const lines = ordered.map((candidate) => {
    const hardened = hardenObfs4(candidate.parsed.line);
    return ORBOT_LINE.test(hardened) ? hardened : candidate.parsed.line;
  });
  const invalidWritten = ordered.filter((candidate) => !ORBOT_LINE.test(candidate.parsed.line));

  if (invalidWritten.length > 0) {
    report.hard.push(`dynamic selection produced ${invalidWritten.length} line(s) that Orbot would reject — not written`);
  } else if (lines.length === 0) {
    report.warnings.push("dynamic selection produced no line — nothing written");
  } else {
    await mkdir(path.join(ROOT, "export/orbot"), { recursive: true });
    const target = "export/orbot/orbot_iran_antidpi.txt";
    await writeFile(path.join(ROOT, target), lines.join("\n") + "\n", "utf8");
    const manifest = {
      generatedAt: new Date().toISOString(),
      file: target,
      total: lines.length,
      rotationBucket: rotate,
      rotationBuckets: ROTATION_BUCKETS,
      nextRotation: new Date((Math.floor(Date.now() / 3_600_000) + 1) * 3_600_000).toISOString(),
      poolSize: pool.size,
      perTransport: lines.reduce((acc, line) => {
        const parsed = parse(line);
        acc[parsed.transport] = (acc[parsed.transport] ?? 0) + 1;
        return acc;
      }, {}),
      top: ordered.slice(0, 10).map((candidate) => ({
        line: candidate.parsed.line,
        score: candidate.score,
        bucket: candidate.bucket,
        why: candidate.why.slice(0, 4),
      })),
    };
    await writeFile(path.join(ROOT, "export/orbot/orbot_rotation_plan.json"), JSON.stringify(manifest, null, 2) + "\n", "utf8");
    report.dynamic = { target, written: lines.length, poolSize: pool.size, rotationBucket: rotate, perTransport: manifest.perTransport };
    report.actions.push({ kind: "dynamic", file: target, written: lines.length, applied: true });

    // Objective-specific profiles from the same AI-scored pool (all Orbot-valid, hourly rotation):
    //   stealth : maximum DPI resistance (HTTPS-mimicking / fronted / CDN-shielded, timing-randomised)
    //   fast    : least overhead (direct obfs4 / vanilla, iat-mode kept at the bridge default, RTT when probed)
    const profiles = {
      "export/orbot/orbot_iran_stealth.txt": (candidate) =>
        candidate.score +
        (candidate.parsed.transport === "webtunnel" ? 14 : 0) +
        (candidate.parsed.params.front || candidate.parsed.params.fronts ? 6 : 0) +
        (candidate.parsed.port === 443 ? 6 : 0) +
        (/iat-mode=[12]/.test(candidate.parsed.line) ? 4 : 0),
      "export/orbot/orbot_iran_fast.txt": (candidate) =>
        candidate.score +
        (candidate.parsed.transport === "obfs4" || candidate.parsed.transport === "vanilla" ? 10 : -12) +
        (candidate.parsed.port === 443 ? 3 : 0) -
        (candidate.parsed.isIpv6 ? 10 : 0) +
        (typeof candidate.rtt === "number" ? Math.max(-6, 12 - candidate.rtt / 40) : 0),
    };
    for (const [profileFile, adjust] of Object.entries(profiles)) {
      const adjusted = [...pool.values()].map((candidate) => {
        const evidence = harvestEvidence.get(candidate.parsed.identity);
        return { ...candidate, rtt: evidence?.rtt, score: adjust({ ...candidate, rtt: evidence?.rtt }) };
      });
      const chosen = selectDiverse(adjusted, Math.min(MODE.top, 40), rotate).sort((a, b) => b.score - a.score);
      const profileLines = chosen.map((candidate) => (profileFile.includes("stealth") ? hardenObfs4(candidate.parsed.line) : candidate.parsed.line));
      if (profileLines.length > 0 && profileLines.every((line) => ORBOT_LINE.test(line))) {
        await writeFile(path.join(ROOT, profileFile), profileLines.join("\n") + "\n", "utf8");
        report.actions.push({ kind: "dynamic-profile", file: profileFile, written: profileLines.length, applied: true });
      }
    }
  }

  // Transparency: lines that Orbot cannot paste are reported, never deleted.
  const rejectedReport = [];
  for (const entry of inventory.values()) {
    for (const item of entry.rejected ?? []) rejectedReport.push(item);
  }
  if (rejectedReport.length > 0) {
    const target = "export/orbot_rejected_report.tsv";
    const body = [
      "file\treason\tline",
      ...rejectedReport.map((item) => `${item.file}\t${item.reason}\t${item.line}`),
    ].join("\n");
    await writeFile(path.join(ROOT, target), body + "\n", "utf8");
    report.actions.push({ kind: "rejected-report", file: target, written: rejectedReport.length, applied: true });
  }

  // torrc files are documented torrc syntax; expose validated copies for Orbot.
  const torrcFiles = (await listFiles("export")).filter((file) => file.endsWith(".torrc"));
  const torrcLines = new Map();
  for (const file of torrcFiles) {
    const info = inventory.get(file);
    if (!info) continue;
    for (const line of await readLines(path.join(ROOT, file))) {
      const fixed = normalise(line);
      if (!fixed || fixed.startsWith("#")) continue;
      const parsed = parse(fixed);
      if (!parsed || !parsed.valid || parsed.placeholder) continue;
      if (!torrcLines.has(parsed.identity)) torrcLines.set(parsed.identity, parsed.line);
    }
  }
  if (torrcLines.size > 0) {
    const target = "export/orbot/orbot_from_torrc.txt";
    const values = [...torrcLines.values()];
    await writeFile(path.join(ROOT, target), values.join("\n") + "\n", "utf8");
    report.actions.push({ kind: "torrc", file: target, written: values.length, applied: true });
  }
}

/* -------------------------------------------------------------------- output */

if (MODE.check && report.hard.length > 0) {
  for (const problem of report.hard) console.error("[bridge-autofill] HARD: " + problem);
  if (MODE.json) await writeFile(path.resolve(ROOT, MODE.json), JSON.stringify(report, null, 2) + "\n", "utf8");
  process.exit(1);
}

const totals = report.files.reduce(
  (acc, file) => {
    acc.lines += file.lines;
    acc.valid += file.valid;
    acc.invalid += file.invalid;
    acc.dupes += file.dupes;
    acc.placeholders += file.placeholders;
    acc.conjure += file.conjure;
    if (file.status === "empty") acc.empty += 1;
    return acc;
  },
  { lines: 0, valid: 0, invalid: 0, dupes: 0, placeholders: 0, conjure: 0, empty: 0 },
);

console.log("[bridge-autofill] mode=%s root=%s", JSON.stringify(MODE), ROOT);
console.log(
  "[bridge-autofill] files=%d lines=%d valid=%d invalid=%d empty=%d dupes=%d placeholders=%d conjure=%d",
  report.files.length, totals.lines, totals.valid, totals.invalid, totals.empty, totals.dupes, totals.placeholders, totals.conjure,
);
for (const file of report.files) {
  if (file.status === "ok" && file.placeholders === 0) continue;
  console.log(
    "  %s lines=%d valid=%d dupes=%d placeholders=%d status=%s",
    file.file.padEnd(48), file.lines, file.valid, file.dupes, file.placeholders, file.status,
  );
}
for (const action of report.actions.slice(0, 25)) {
  console.log("  → %s %s %s", action.kind, action.file, action.written ? `written=${action.written}` : action.add !== undefined ? `add=${action.add} applied=${action.applied}` : "");
}
if (report.dynamic) {
  console.log("[bridge-autofill] dynamic: %s written=%d pool=%d bucket=%d/%d", report.dynamic.target, report.dynamic.written, report.dynamic.poolSize, report.dynamic.rotationBucket, ROTATION_BUCKETS);
}
for (const warning of report.warnings.slice(0, 12)) console.log("[bridge-autofill] note: " + warning);
for (const hard of report.hard) console.error("[bridge-autofill] HARD: " + hard);

if (MODE.json) {
  await writeFile(path.resolve(ROOT, MODE.json), JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log("[bridge-autofill] report: " + MODE.json);
}

console.log(report.hard.length === 0 ? "[bridge-autofill] OK" : "[bridge-autofill] FAIL");
