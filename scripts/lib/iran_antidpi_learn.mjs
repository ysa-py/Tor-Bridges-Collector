/**
 * iran_antidpi_learn.mjs — the repository's INTERNAL, self-training anti-filtering model.
 *
 * No API key, no network, no dependency: it learns offline, every hour, from the Iran
 * evidence this repository already collects:
 *
 *   negatives : bridge/iran_blocked.txt            (measured blocked from Iran)
 *   positives : bridge/iran_likely_working_*.txt   (evidence-backed likely working)
 *
 * Two cooperating learners (both explainable, both persisted in
 * data/iran_antidpi_weights.json so a failed hour never loses what was learnt):
 *
 *   1. logistic regression (SGD + L2, seeded => deterministic) over *static* features:
 *      port class, specific port, IP family, CDN shield, iat-mode, fronting, fingerprint.
 *      The transport itself is deliberately NOT a learnt feature: the hand-tuned prior in
 *      iran_antidpi_model.mjs already encodes it and the label files are skewed by transport.
 *   2. range reputation: smoothed positive-rate per IPv4 /16 (Iranian filters block by
 *      hosting range / ASN, so "this /16 was blocked 40 of 41 times" is the strongest
 *      single signal there is).
 *
 * The model reports its own hold-out AUC. Its influence on the final score is scaled by
 * that measured quality, so a bad or missing model degrades to the prior — never to noise.
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { iranScore, isCdnIpv4 } from "./iran_antidpi_model.mjs";
import { splitAddress, SUPPORTED_TRANSPORTS } from "./orbot_format.mjs";

export const MODEL_FILE = "data/iran_antidpi_weights.json";
const TLS_PORTS = new Set([443, 8443, 2053, 2083, 2087, 2096, 4443, 9443]);
const FLAGGED_PORTS = new Set([9001, 9030, 9050, 9051, 9150, 9151, 9101, 9002]);
const COMMON_PORTS = [80, 443, 8080, 8443, 9001, 9030, 9443, 993, 995, 465, 22, 21, 25, 53, 110, 143, 587, 2083, 4433, 7000];

export const FEATURES = [
  "port_443", "port_80", "port_tls", "port_flagged", "port_low", "port_mid", "port_high",
  ...COMMON_PORTS.filter((p) => ![80, 443].includes(p)).map((p) => `port_is_${p}`),
  "ipv6", "cdn", "has_fp", "iat_1", "iat_2", "fronted", "https_url",
];

/** Minimal tolerant parser for training lines (any of the repo's list layouts). */
export function parseLite(raw) {
  const text = String(raw).replace(/^\uFEFF/, "").replace(/^Bridge\s+/i, "").trim();
  if (!text || text.startsWith("#")) return null;
  const tokens = text.split(/\s+/);
  const transport = SUPPORTED_TRANSPORTS.includes(tokens[0]) ? tokens[0] : "vanilla";
  const address = splitAddress(transport === "vanilla" ? tokens[0] : tokens[1]);
  if (!address) return null;
  const rest = tokens.slice(transport === "vanilla" ? 1 : 2);
  const params = {};
  for (const token of rest) {
    const eq = token.indexOf("=");
    if (eq > 0) params[token.slice(0, eq).toLowerCase()] = token.slice(eq + 1);
  }
  const isIpv6 = address.host.includes(":");
  const fp = rest.find((token) => /^[0-9a-fA-F]{40}$/.test(token))?.toUpperCase() ?? null;
  return {
    line: text,
    transport,
    host: address.host,
    port: address.port ?? 0,
    isIpv4: !isIpv6,
    isIpv6,
    fp,
    params,
    identity: `${transport}|${address.host}|${address.port ?? 0}|${fp ?? ""}`,
  };
}

export const rangeKey = (parsed) => (parsed.isIpv4 ? parsed.host.split(".").slice(0, 2).join(".") : null);

export function featurize(parsed) {
  const port = parsed.port ?? 0;
  const params = parsed.params ?? {};
  const on = new Set();
  if (port === 443) on.add("port_443");
  if (port === 80) on.add("port_80");
  if (TLS_PORTS.has(port)) on.add("port_tls");
  if (FLAGGED_PORTS.has(port)) on.add("port_flagged");
  if (port > 0 && port < 1024) on.add("port_low");
  else if (port >= 1024 && port < 20000) on.add("port_mid");
  else if (port >= 20000) on.add("port_high");
  if (COMMON_PORTS.includes(port) && port !== 80 && port !== 443) on.add(`port_is_${port}`);
  if (parsed.isIpv6) on.add("ipv6");
  if (parsed.isIpv4 && isCdnIpv4(parsed.host)) on.add("cdn");
  if (parsed.fp) on.add("has_fp");
  if (params["iat-mode"] === "1") on.add("iat_1");
  if (params["iat-mode"] === "2") on.add("iat_2");
  if (params.front || params.fronts) on.add("fronted");
  if (params.url && /^https:\/\//i.test(params.url)) on.add("https_url");
  return on;
}

/* ------------------------------------------------------------------- maths */

const sigmoid = (z) => 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, z))));

function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

export function auc(scored) {
  const positives = scored.filter((item) => item.y === 1);
  const negatives = scored.filter((item) => item.y === 0);
  if (positives.length === 0 || negatives.length === 0) return 0.5;
  const ordered = [...scored].sort((a, b) => a.p - b.p);
  let rankSum = 0;
  let index = 0;
  while (index < ordered.length) {
    let end = index;
    while (end + 1 < ordered.length && ordered[end + 1].p === ordered[index].p) end += 1;
    const rank = (index + end) / 2 + 1;
    for (let k = index; k <= end; k += 1) if (ordered[k].y === 1) rankSum += rank;
    index = end + 1;
  }
  return (rankSum - (positives.length * (positives.length + 1)) / 2) / (positives.length * negatives.length);
}

function fitLogistic(samples, { epochs = 60, lr = 0.15, l2 = 1e-3 } = {}) {
  const weights = Object.fromEntries(FEATURES.map((name) => [name, 0]));
  let bias = 0;
  const positives = samples.filter((s) => s.y === 1).length;
  const negatives = samples.length - positives;
  const wPos = samples.length / (2 * Math.max(1, positives));
  const wNeg = samples.length / (2 * Math.max(1, negatives));
  const random = rng(20260101);
  const order = samples.map((_, i) => i);
  for (let epoch = 0; epoch < epochs; epoch += 1) {
    for (let i = order.length - 1; i > 0; i -= 1) {
      const j = Math.floor(random() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    const rate = lr / (1 + epoch * 0.08);
    for (const idx of order) {
      const sample = samples[idx];
      let z = bias;
      for (const name of sample.x) z += weights[name];
      const error = (sigmoid(z) - sample.y) * (sample.y === 1 ? wPos : wNeg);
      bias -= rate * error;
      for (const name of sample.x) weights[name] -= rate * (error + l2 * weights[name]);
    }
  }
  return { weights, bias };
}

function buildRanges(samples) {
  const table = {};
  for (const sample of samples) {
    if (!sample.range) continue;
    const slot = (table[sample.range] ??= [0, 0]);
    slot[sample.y === 1 ? 0 : 1] += 1;
  }
  return table;
}

const rangeProbability = (ranges, range, prior) => {
  const slot = ranges?.[range];
  if (!slot) return null;
  const n = slot[0] + slot[1];
  if (n < 3) return null;
  const alpha = 6;
  return (slot[0] + alpha * prior) / (n + alpha);
};

/* ---------------------------------------------------------------- training */

async function readList(root, rel) {
  try {
    return (await readFile(path.join(root, rel), "utf8")).split(/\r?\n/);
  } catch {
    return [];
  }
}

export async function buildTrainingSet(root) {
  const blocked = [];
  for (const rel of ["bridge/iran_blocked.txt", "bridge/iran_blocked_ipv4_ipv6_all.txt"]) blocked.push(...(await readList(root, rel)));
  const working = [];
  for (const rel of [
    "bridge/iran_likely_working_obfs4.txt", "bridge/iran_likely_working_webtunnel.txt",
    "bridge/iran_likely_working_vanilla.txt", "bridge/iran_likely_working_snowflake.txt",
    "bridge/iran_likely_working_nin.txt", "bridge/iran_likely_working_all.txt",
  ]) working.push(...(await readList(root, rel)));
  const negative = new Map();
  const positive = new Map();
  for (const raw of blocked) {
    const parsed = parseLite(raw);
    if (parsed && parsed.fp) negative.set(`${parsed.host}|${parsed.port}`, parsed);
  }
  for (const raw of working) {
    const parsed = parseLite(raw);
    if (parsed && parsed.fp) positive.set(`${parsed.host}|${parsed.port}`, parsed);
  }
  const samples = [];
  for (const [key, parsed] of positive) {
    if (negative.has(key)) continue; // conflicting evidence is not a label
    samples.push({ y: 1, x: featurize(parsed), range: rangeKey(parsed), key });
  }
  for (const [key, parsed] of negative) {
    if (positive.has(key)) continue;
    samples.push({ y: 0, x: featurize(parsed), range: rangeKey(parsed), key });
  }
  return samples;
}

function evaluate(model, samples) {
  const scored = samples.map((sample) => ({ y: sample.y, p: predictSet(model, sample.x, sample.range).p }));
  const hits = scored.filter((item) => (item.p >= model.prior ? 1 : 0) === item.y).length;
  return { auc: Math.round(auc(scored) * 1000) / 1000, accuracy: Math.round((hits / Math.max(1, scored.length)) * 1000) / 1000, n: scored.length };
}

export async function trainModel(root) {
  const samples = await buildTrainingSet(root);
  const pos = samples.filter((s) => s.y === 1).length;
  const neg = samples.length - pos;
  if (pos < 30 || neg < 30) return { ok: false, reason: `not enough labelled evidence (pos=${pos}, neg=${neg})` };
  const random = rng(42);
  const holdoutSet = [];
  const trainSet = [];
  for (const sample of samples) (random() < 0.2 ? holdoutSet : trainSet).push(sample);
  const prior = pos / samples.length;

  const partial = { prior, ...fitLogistic(trainSet), ranges: buildRanges(trainSet) };
  const holdout = evaluate(partial, holdoutSet);

  // final model: refit on everything (the hold-out number above stays the honest quality estimate)
  const fitted = fitLogistic(samples);
  const ranges = {};
  for (const [range, slot] of Object.entries(buildRanges(samples))) if (slot[0] + slot[1] >= 3) ranges[range] = slot;
  const model = {
    version: 1,
    trainedAt: new Date().toISOString(),
    samples: { positive: pos, negative: neg },
    prior: Math.round(prior * 1000) / 1000,
    holdout,
    bias: Math.round(fitted.bias * 10000) / 10000,
    weights: Object.fromEntries(Object.entries(fitted.weights).map(([k, v]) => [k, Math.round(v * 10000) / 10000])),
    ranges,
  };
  model.confidence = modelConfidence(model);
  return { ok: true, model };
}

export const modelConfidence = (model) => {
  if (!model?.holdout) return 0;
  const quality = Math.max(0, Math.min(1, (model.holdout.auc - 0.5) * 3.5));
  const volume = Math.min(1, (model.samples.positive + model.samples.negative) / 600);
  return Math.round(quality * volume * 1000) / 1000;
};

export async function loadModel(root) {
  try {
    const model = JSON.parse(await readFile(path.join(root, MODEL_FILE), "utf8"));
    return model?.weights ? model : null;
  } catch {
    return null;
  }
}

export async function saveModel(root, model) {
  await mkdir(path.join(root, "data"), { recursive: true });
  await writeFile(path.join(root, MODEL_FILE), JSON.stringify(model, null, 1) + "\n", "utf8");
}

/** Probability that a bridge is "likely working from Iran" (0..1) with explanation. */
export function predictSet(model, features, range) {
  let z = model.bias ?? 0;
  for (const name of features) z += model.weights?.[name] ?? 0;
  const logistic = sigmoid(z);
  const reputation = rangeProbability(model.ranges, range, model.prior ?? 0.5);
  // blend: the range reputation is the more specific signal when it exists
  const p = reputation === null ? logistic : 0.35 * logistic + 0.65 * reputation;
  return { p, logistic, reputation };
}

/**
 * Final AI score = hand-tuned prior (iranScore) + learnt adjustment (scaled by measured
 * quality) − density penalty (many candidates in one /24 are blocked together).
 * @param {object} parsed  parsed bridge (transport,host,port,isIpv4,isIpv6,fp,params,...)
 * @param {object} ctx     iranScore context + optional {density}
 * @param {object|null} model
 */
export function iranScoreAI(parsed, ctx = {}, model = null) {
  const base = iranScore(parsed, ctx);
  let score = base.score;
  const why = [...base.why];
  if (model && (model.confidence ?? modelConfidence(model)) > 0) {
    const confidence = model.confidence ?? modelConfidence(model);
    const { p, reputation } = predictSet(model, featurize(parsed), rangeKey(parsed));
    const adjust = Math.round((p - (model.prior ?? 0.5)) * 60 * confidence * 10) / 10;
    if (adjust !== 0) {
      score += adjust;
      why.push(`ai${adjust > 0 ? "+" : ""}${adjust}${reputation !== null ? "(range)" : ""}`);
    }
  }
  if ((ctx.density ?? 0) > 1) {
    const penalty = -Math.min(10, Math.round(Math.log2(ctx.density) * 2.5 * 10) / 10);
    score += penalty;
    why.push(`dense-/24${penalty}`);
  }
  return { score: Math.round(score * 10) / 10, why };
}
