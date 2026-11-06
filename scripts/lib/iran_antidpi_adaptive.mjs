/**
 * iran_antidpi_adaptive.mjs — hourly self-tuning anti-DPI selector (pure logic, no I/O).
 *
 * Complements the static prior (iran_antidpi_model.mjs) and the supervised learner
 * (iran_antidpi_learn.mjs) with three *online* mechanisms, all internal, offline and
 * deterministic for a given (evidence, hour):
 *
 *   1. Thompson-sampling transport mix. Every transport has a Beta(positive+1, negative+1)
 *      posterior built from the measured Iran evidence (likely-working vs blocked lists).
 *      Each hour one seeded draw per transport decides how many of the TOP slots it gets,
 *      so the mix exploits what works from Iran today yet keeps exploring the others: a
 *      DPI rule that suddenly burns one transport shifts the mix at the next evidence
 *      refresh with no human in the loop. A floor keeps every transport represented.
 *   2. Hourly client-side shaping that stays inside what Orbot / Tor accept:
 *        - meek_lite: rotating uTLS ClientHello (Chrome / Firefox / randomised) so the TLS
 *          fingerprint is not a stable signature across hours,
 *        - obfs4: iat-mode 1 or 2 chosen per bridge and hour (never 0): inter-arrival
 *          randomisation against flow-timing classifiers.
 *      A parameter already present in a line is NEVER overridden for meek_lite; obfs4
 *      iat-mode=0 is the only value that is raised.
 *   3. Burn-risk diversification. Dialled transports are capped per /16 and /24, tunnelled
 *      ones per front/url host, fingerprints are unique: one blocked range or one blocked
 *      CDN domain can never take the whole list with it.
 */
import { createHash } from "node:crypto";
import { repairForOrbot, splitAddress } from "./orbot_format.mjs";
import { iranScoreAI } from "./iran_antidpi_learn.mjs";

export const MIX_TRANSPORTS = ["webtunnel", "snowflake", "obfs4", "meek_lite", "vanilla"];
export const UTLS_PROFILES = ["HelloChrome_Auto", "HelloFirefox_Auto", "HelloRandomizedNoALPN", "HelloRandomizedALPN", "HelloSafari_Auto"];
const MIN_SHARE = { webtunnel: 0.1, snowflake: 0.08, obfs4: 0.1, meek_lite: 0.04, vanilla: 0.03 };

/** Deterministic PRNG (mulberry32). */
export function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const hashInt = (text) => createHash("sha1").update(String(text)).digest().readUInt32BE(0);
export const hourSeed = (date = new Date()) => Math.floor(date.getTime() / 3_600_000);

/** Standard normal via Box-Muller on the seeded PRNG. */
function gaussian(rand) {
  const u = Math.max(1e-12, rand());
  const v = rand();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/** Gamma(shape>=1) sampler (Marsaglia-Tsang). */
function gammaSample(shape, rand) {
  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (let i = 0; i < 64; i++) {
    const x = gaussian(rand);
    const v = (1 + c * x) ** 3;
    if (v <= 0) continue;
    const u = rand();
    if (Math.log(Math.max(u, 1e-12)) < 0.5 * x * x + d - d * v + d * Math.log(v)) return d * v;
  }
  return shape; // astronomically unlikely fall-back: the mean
}

export function betaSample(alpha, beta, rand) {
  const x = gammaSample(Math.max(1, alpha), rand);
  const y = gammaSample(Math.max(1, beta), rand);
  return x / (x + y);
}

/**
 * @param {Record<string,{positive:number,negative:number}>} evidence per transport
 * @returns {{shares: Record<string,number>, draws: Record<string,number>}}
 */
export function thompsonMix(evidence, seed) {
  const rand = prng(seed ^ 0x9e3779b9);
  const draws = {};
  for (const transport of MIX_TRANSPORTS) {
    const e = evidence[transport] ?? { positive: 0, negative: 0 };
    draws[transport] = betaSample(e.positive + 1, e.negative + 1, rand);
  }
  const floorTotal = MIX_TRANSPORTS.reduce((sum, t) => sum + MIN_SHARE[t], 0);
  const drawTotal = MIX_TRANSPORTS.reduce((sum, t) => sum + draws[t], 0) || 1;
  const shares = {};
  for (const transport of MIX_TRANSPORTS) {
    shares[transport] = MIN_SHARE[transport] + (1 - floorTotal) * (draws[transport] / drawTotal);
  }
  return { shares, draws };
}

/** Largest-remainder rounding of shares into integer slot counts that sum to `total`. */
export function allocateSlots(shares, total) {
  const exact = MIX_TRANSPORTS.map((t) => ({ t, v: shares[t] * total }));
  const slots = Object.fromEntries(exact.map(({ t, v }) => [t, Math.floor(v)]));
  let left = total - Object.values(slots).reduce((a, b) => a + b, 0);
  exact.sort((a, b) => b.v - Math.floor(b.v) - (a.v - Math.floor(a.v)));
  for (const { t } of exact) {
    if (left <= 0) break;
    slots[t] += 1;
    left -= 1;
  }
  return slots;
}

/** Hourly client-side shaping of ONE paste-ready line (see header). Returns the new line. */
export function shapeLine(line, seed) {
  const tokens = line.split(" ");
  const transport = tokens[0];
  if (transport === "meek_lite" && !tokens.some((t) => /^utls=/i.test(t))) {
    const profile = UTLS_PROFILES[(hashInt(line) + seed) % UTLS_PROFILES.length];
    return `${line} utls=${profile}`;
  }
  if (transport === "obfs4") {
    const iat = 1 + ((hashInt(line) + seed) % 2);
    const index = tokens.findIndex((t) => /^iat-mode=/i.test(t));
    if (index === -1) return `${line} iat-mode=${iat}`;
    if (tokens[index] === "iat-mode=0") {
      tokens[index] = `iat-mode=${iat}`;
      return tokens.join(" ");
    }
  }
  return line;
}

/** Minimal parsed shape expected by the scoring models. */
export function toParsed(line, transport) {
  const tokens = line.split(" ");
  const address = splitAddress(transport === "vanilla" ? tokens[0] : tokens[1]);
  if (!address) return null;
  const rest = tokens.slice(transport === "vanilla" ? 1 : 2);
  const params = {};
  for (const token of rest) {
    const eq = token.indexOf("=");
    if (eq > 0) params[token.slice(0, eq).toLowerCase()] = token.slice(eq + 1);
  }
  const isIpv6 = address.host.includes(":");
  const dummy = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:0?db8:)/i.test(address.host);
  const tunnelled = transport !== "obfs4" && transport !== "vanilla" && Boolean(params.url || params.front || params.fronts);
  return {
    line,
    transport,
    host: address.host,
    port: address.port ?? 0,
    isIpv4: !isIpv6,
    isIpv6,
    fp: rest.find((t) => /^[0-9a-fA-F]{40}$/.test(t))?.toUpperCase() ?? null,
    params,
    valid: true,
    placeholder: dummy && !tunnelled,
  };
}

function diversityKeys(parsed) {
  if (parsed.transport === "webtunnel" || parsed.transport === "snowflake" || parsed.transport === "meek_lite") {
    const raw = parsed.params.url ?? parsed.params.front ?? parsed.params.fronts ?? "";
    let domain = null;
    try {
      domain = raw ? new URL(raw.includes("://") ? raw : `https://${raw.split(",")[0]}`).hostname : null;
    } catch {
      domain = null;
    }
    return { k16: domain ?? parsed.host, k24: domain ?? parsed.host, cap16: 2, cap24: 2 };
  }
  if (parsed.isIpv4) {
    const octets = parsed.host.split(".");
    return { k16: octets.slice(0, 2).join("."), k24: octets.slice(0, 3).join("."), cap16: 2, cap24: 1 };
  }
  const groups = parsed.host.split(":").slice(0, 3).join(":");
  return { k16: groups, k24: parsed.host, cap16: 2, cap24: 1 };
}

/**
 * Build the adaptive list.
 * @param {string[]} rawLines   candidate lines (any layout the repo uses)
 * @param {{evidence:Record<string,{positive:number,negative:number}>, model?:any, seed:number, total?:number,
 *          ctxFor?:(parsed:any)=>object}} options
 */
export function buildAdaptiveList(rawLines, { evidence, model = null, seed, total = 90, ctxFor = () => ({}) }) {
  const { shares, draws } = thompsonMix(evidence, seed);
  const slots = allocateSlots(shares, total);
  const pools = Object.fromEntries(MIX_TRANSPORTS.map((t) => [t, []]));
  const seen = new Set();
  for (const raw of rawLines) {
    const result = repairForOrbot(raw);
    if (!result.ok || seen.has(result.line)) continue;
    seen.add(result.line);
    const parsed = toParsed(result.line, result.transport);
    if (!parsed || parsed.placeholder) continue;
    const base = iranScoreAI(parsed, ctxFor(parsed), model).score;
    // hourly jitter (+-5): the list rotates every hour instead of freezing on the same top-N
    const jitter = ((hashInt(`${seed}|${parsed.transport}|${parsed.host}|${parsed.port}`) % 1000) / 1000 - 0.5) * 10;
    pools[parsed.transport]?.push({ parsed, score: base + jitter });
  }
  const chosen = [];
  const perKey16 = new Map();
  const perKey24 = new Map();
  const fps = new Set();
  const leftovers = [];
  for (const transport of MIX_TRANSPORTS) {
    const ranked = pools[transport].sort((a, b) => b.score - a.score);
    let taken = 0;
    for (const item of ranked) {
      if (taken >= slots[transport]) break;
      const keys = diversityKeys(item.parsed);
      if (item.parsed.fp && fps.has(`${transport}|${item.parsed.fp}`)) continue;
      if ((perKey16.get(keys.k16) ?? 0) >= keys.cap16 || (perKey24.get(keys.k24) ?? 0) >= keys.cap24) {
        leftovers.push(item);
        continue;
      }
      perKey16.set(keys.k16, (perKey16.get(keys.k16) ?? 0) + 1);
      perKey24.set(keys.k24, (perKey24.get(keys.k24) ?? 0) + 1);
      if (item.parsed.fp) fps.add(`${transport}|${item.parsed.fp}`);
      chosen.push(item);
      taken += 1;
    }
  }
  // transports with too few candidates donate their unused slots to the best remaining lines
  if (chosen.length < total) {
    const picked = new Set(chosen.map((c) => c.parsed.line));
    const rest = [...MIX_TRANSPORTS.flatMap((t) => pools[t]), ...leftovers]
      .filter((item) => !picked.has(item.parsed.line))
      .sort((a, b) => b.score - a.score);
    for (const item of rest) {
      if (chosen.length >= total) break;
      if (picked.has(item.parsed.line)) continue;
      const keys = diversityKeys(item.parsed);
      if ((perKey24.get(keys.k24) ?? 0) >= keys.cap24 + 1) continue;
      perKey24.set(keys.k24, (perKey24.get(keys.k24) ?? 0) + 1);
      picked.add(item.parsed.line);
      chosen.push(item);
    }
  }
  chosen.sort((a, b) => b.score - a.score);
  const lines = [];
  for (const item of chosen) {
    const shaped = shapeLine(item.parsed.line, seed);
    // the shaped line is re-validated: shaping must never be the thing that breaks a paste
    const check = repairForOrbot(shaped);
    lines.push(check.ok ? check.line : item.parsed.line);
  }
  const counts = {};
  for (const item of chosen) counts[item.parsed.transport] = (counts[item.parsed.transport] ?? 0) + 1;
  return { lines, shares, draws, slots, counts, candidates: Object.fromEntries(MIX_TRANSPORTS.map((t) => [t, pools[t].length])) };
}
