#!/usr/bin/env node
/**
 * iran_antidpi_adaptive.mjs — hourly adaptive anti-DPI list for Iran (offline, dependency-free).
 *
 *   node scripts/iran_antidpi_adaptive.mjs [--root <dir>] [--total 90] [--json <report>] [--seed <n>]
 *
 * Reads the Iran evidence the repository already collects (blocked vs likely-working lists),
 * lets scripts/lib/iran_antidpi_adaptive.mjs pick this hour's Thompson-sampled transport mix,
 * shapes and diversifies the result and writes
 *
 *   export/orbot/orbot_iran_adaptive.txt   paste-ready (every line re-validated for Orbot)
 *   data/iran_adaptive_profile.json        mix, posteriors, counts, hour — explains every choice
 *
 * Never fatal: with no candidates it leaves the previous list untouched. conjure never enters.
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { parseLite, loadModel } from "./lib/iran_antidpi_learn.mjs";
import { buildAdaptiveList, hourSeed, MIX_TRANSPORTS } from "./lib/iran_antidpi_adaptive.mjs";
import { isOrbotValid } from "./lib/orbot_format.mjs";

const argv = process.argv.slice(2);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
};
const ROOT = path.resolve(opt("--root", process.cwd()));
const TOTAL = Math.max(20, Number(opt("--total", "90")) || 90);
const SEED = opt("--seed", null) !== null ? Number(opt("--seed")) : hourSeed();
const OUT_LIST = "export/orbot/orbot_iran_adaptive.txt";
const OUT_PROFILE = "data/iran_adaptive_profile.json";

const readList = async (rel) => {
  try {
    return (await readFile(path.join(ROOT, rel), "utf8")).split(/\r?\n/);
  } catch {
    return [];
  }
};

const BLOCKED = ["bridge/iran_blocked.txt", "bridge/iran_blocked_ipv4_ipv6_all.txt"];
const WORKING = [
  "bridge/iran_likely_working_obfs4.txt", "bridge/iran_likely_working_webtunnel.txt",
  "bridge/iran_likely_working_vanilla.txt", "bridge/iran_likely_working_snowflake.txt",
  "bridge/iran_likely_working_all.txt",
];
const CANDIDATES = [
  "export/orbot/orbot_extended.txt", "export/orbot/orbot_all.txt", "export/orbot/orbot_harvest_live.txt",
  "export/orbot/orbot_snowflake.txt", "export/orbot/orbot_meek.txt", "export/orbot/orbot_webtunnel.txt",
  "export/orbot/orbot_obfs4.txt", "export/orbot/orbot_vanilla.txt",
];

async function evidenceByTransport() {
  const positive = new Map();
  const negative = new Map();
  for (const rel of WORKING) for (const raw of await readList(rel)) {
    const parsed = parseLite(raw);
    if (parsed) positive.set(`${parsed.transport}|${parsed.host}|${parsed.port}`, parsed.transport);
  }
  for (const rel of BLOCKED) for (const raw of await readList(rel)) {
    const parsed = parseLite(raw);
    if (!parsed) continue;
    const key = `${parsed.transport}|${parsed.host}|${parsed.port}`;
    if (!positive.has(key)) negative.set(key, parsed.transport);
  }
  const evidence = Object.fromEntries(MIX_TRANSPORTS.map((t) => [t, { positive: 0, negative: 0 }]));
  for (const transport of positive.values()) if (evidence[transport]) evidence[transport].positive += 1;
  for (const transport of negative.values()) if (evidence[transport]) evidence[transport].negative += 1;
  // cap the weight of the evidence so one huge list can never freeze the posterior
  for (const e of Object.values(evidence)) {
    const n = e.positive + e.negative;
    if (n > 400) {
      e.positive = Math.round((e.positive * 400) / n);
      e.negative = Math.round((e.negative * 400) / n);
    }
  }
  return evidence;
}

const lines = [];
for (const rel of CANDIDATES) lines.push(...(await readList(rel)));
const evidence = await evidenceByTransport();
const model = await loadModel(ROOT);

const density = new Map();
for (const raw of lines) {
  const parsed = parseLite(raw);
  if (parsed?.isIpv4) {
    const key = parsed.host.split(".").slice(0, 3).join(".");
    density.set(key, (density.get(key) ?? 0) + 1);
  }
}
const ctxFor = (parsed) => ({ density: parsed.isIpv4 ? density.get(parsed.host.split(".").slice(0, 3).join(".")) ?? 1 : 1 });

const result = buildAdaptiveList(lines, { evidence, model, seed: SEED, total: TOTAL, ctxFor });
const profile = {
  generatedAt: new Date().toISOString(),
  hour: SEED,
  total: result.lines.length,
  evidence,
  modelConfidence: model?.confidence ?? null,
  thompsonDraws: Object.fromEntries(Object.entries(result.draws).map(([k, v]) => [k, Math.round(v * 1000) / 1000])),
  shares: Object.fromEntries(Object.entries(result.shares).map(([k, v]) => [k, Math.round(v * 1000) / 1000])),
  slots: result.slots,
  counts: result.counts,
  candidates: result.candidates,
  note: "Mix is re-sampled every hour from Iran evidence; meek_lite gets a rotating uTLS profile, obfs4 iat-mode 1|2.",
};

const bad = result.lines.filter((line) => !isOrbotValid(line) || /^conjure\b/i.test(line));
if (bad.length > 0) {
  console.error(`[iran-adaptive] FATAL: ${bad.length} generated lines are not Orbot-valid, e.g. ${bad[0]}`);
  process.exit(1);
}
if (result.lines.length === 0) {
  console.log("[iran-adaptive] no candidates — previous list kept");
} else {
  await mkdir(path.join(ROOT, "export/orbot"), { recursive: true });
  await mkdir(path.join(ROOT, "data"), { recursive: true });
  await writeFile(path.join(ROOT, OUT_LIST), result.lines.join("\n") + "\n", "utf8");
  await writeFile(path.join(ROOT, OUT_PROFILE), JSON.stringify(profile, null, 1) + "\n", "utf8");
  console.log("[iran-adaptive] hour=%d wrote %d lines mix=%s", SEED, result.lines.length, JSON.stringify(result.counts));
}
const jsonOut = opt("--json", null);
if (jsonOut) await writeFile(jsonOut, JSON.stringify(profile, null, 1) + "\n", "utf8");
