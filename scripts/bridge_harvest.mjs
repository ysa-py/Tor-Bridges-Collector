#!/usr/bin/env node
/**
 * bridge_harvest.mjs — fully automatic, self-extending bridge harvester.
 *
 * What it does on every run (hourly in CI, safe to run by hand):
 *   1. builds its source list: built-in community mirrors + every URL already known to
 *      the pipeline (data/ai_fusion_extra_sources.json) + sources it DISCOVERED itself
 *      through the GitHub search/tree API (new collector repos appear automatically),
 *   2. downloads them with retry/backoff, adaptive per-source health tracking and
 *      dead-source quarantine (a failing mirror never stops the run),
 *   3. keeps only lines that are real, Orbot-pasteable bridge lines (obfs4 / webtunnel /
 *      vanilla). Conjure is dropped, reserved/private/dummy endpoints are dropped,
 *      malformed certs / urls / fingerprints are dropped,
 *   4. TCP-probes candidates (round-robin, never-probed first) measuring RTT, so the
 *      pool carries "alive" + "speed" evidence; probing disables itself automatically
 *      when the environment cannot probe truthfully (egress proxy / no IPv6),
 *   5. persists a compact durable pool (data/bridge_harvest_pool.json) — the hourly
 *      collector may rewrite bridge/*.txt, the pool re-injects them on the next run,
 *   6. appends (never deletes) live bridges to the bridge/*.txt base lists and writes
 *      export/orbot/orbot_harvest_live.txt, a fastest-first, AI-ranked, Orbot-safe list.
 *
 * Network failure is never fatal: exit code is 0 unless --strict is given.
 *
 * Usage:
 *   node scripts/bridge_harvest.mjs [--discover] [--probe] [--no-fetch] [--dry]
 *        [--max-new 6000] [--probe-limit 3000] [--concurrency 160] [--timeout-ms 4000]
 *        [--pool-cap 14000] [--ttl-days 14] [--max-unverified 1500] [--json report.json]
 *        [--root <dir>] [--strict]
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import net from "node:net";
import dns from "node:dns/promises";
import path from "node:path";
import { iranScore, ipv4ToInt } from "./lib/iran_antidpi_model.mjs";
import { isPlaceholderUrl } from "./lib/orbot_format.mjs";

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[index + 1] : fallback;
};
const num = (flag, fallback) => Number(opt(flag, String(fallback))) || fallback;

const ROOT = path.resolve(opt("--root", process.cwd()));
const CFG = {
  discover: has("--discover"),
  probe: has("--probe"),
  fetch: !has("--no-fetch"),
  dry: has("--dry"),
  strict: has("--strict"),
  maxNew: num("--max-new", 6000),
  probeLimit: num("--probe-limit", 3000),
  concurrency: num("--concurrency", 160),
  timeoutMs: num("--timeout-ms", 4000),
  poolCap: num("--pool-cap", 14000),
  ttlDays: num("--ttl-days", 14),
  maxUnverified: num("--max-unverified", 4500),
  perFileAdd: num("--per-file-add", 2000),
  json: opt("--json", null),
};

const POOL_FILE = "data/bridge_harvest_pool.json";
const SOURCES_FILE = "data/bridge_harvest_sources.json";
const EXTRA_SOURCES_FILE = "data/ai_fusion_extra_sources.json";
const LIVE_FILE = "export/orbot/orbot_harvest_live.txt";
const NOW = new Date();
const NOW_ISO = NOW.toISOString();
const OWN_REPO = (process.env.GITHUB_REPOSITORY ?? "ysa-py/Tor-Bridges-Collector").toLowerCase();

const ORBOT_LINE = /^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$/;
const FP40 = /^[0-9a-fA-F]{40}$/;

const BUILTIN_SOURCES = [
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/obfs4.txt",
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/obfs4_ipv6.txt",
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/webtunnel.txt",
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/webtunnel_ipv6.txt",
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/vanilla.txt",
  "Delta-Kronecker/Tor-Bridges-Collector@main:bridge/vanilla_ipv6.txt",
  "center2055/OnionHop-Bridges-Collector@main:bridge/obfs4.txt",
  "center2055/OnionHop-Bridges-Collector@main:bridge/obfs4_ipv6.txt",
  "center2055/OnionHop-Bridges-Collector@main:bridge/webtunnel.txt",
  "center2055/OnionHop-Bridges-Collector@main:bridge/vanilla.txt",
  "scriptzteam/Tor-Bridges-Collector-v2@main:bridges/obfs4.txt",
  "scriptzteam/Tor-Bridges-Collector-v2@main:bridges/obfs4_ipv6.txt",
  "scriptzteam/Tor-Bridges-Collector-v2@main:bridges/webtunnel.txt",
  "scriptzteam/Tor-Bridges-Collector-v2@main:bridges/webtunnel_ipv6.txt",
  "scriptzteam/Tor-Bridges-Collector-v2@main:bridges/vanilla.txt",
  "scriptzteam/Tor-Bridges-Collector@main:bridges-obfs4",
  "scriptzteam/Tor-Bridges-Collector@main:bridges-obfs4-ipv6",
  "scriptzteam/Tor-Bridges-Collector@main:bridges-webtunnel",
  "scriptzteam/Tor-Bridges-Collector@main:bridges-vanilla",
  // Verified live sources added 2026-11 (each returns real bridge lines; dead ones are demoted
  // automatically by the per-source ok/fail statistics, never fatal).
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/obfs4.txt",
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/obfs4_72h.txt",
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/obfs4_ipv6_72h.txt",
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/webtunnel.txt",
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/webtunnel_72h.txt",
  "Delta-Kronecker/Delta-Tor@HEAD:Android/app/src/main/assets/bridges/vanilla.txt",
  "githubkdskkd/Tor-Bridges-List@HEAD:obfs4.txt",
  "githubkdskkd/Tor-Bridges-List@HEAD:webtunnel.txt",
  "maximusTIT/tor-bridges@HEAD:bridges.txt",
  "shahab7e/Gommage@HEAD:assets/bridges.txt",
].map((spec) => {
  const [repo, rest] = spec.split("@");
  const [branch, file] = rest.split(":");
  return { name: `builtin:${repo}/${file}`, url: `https://raw.githubusercontent.com/${repo}/${branch}/${file}` };
});

/* ------------------------------------------------------------------ helpers */

const log = (...args) => console.log("[bridge-harvest]", ...args);
const readJson = async (rel, fallback) => {
  try {
    return JSON.parse(await readFile(path.join(ROOT, rel), "utf8"));
  } catch {
    return fallback;
  }
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function pmap(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

async function fetchText(url, { timeout = 30000, retries = 2, headers = {} } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: { "user-agent": "torshield-ir-bridge-harvest/1", accept: "*/*", ...headers },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const text = await response.text();
      if (text.length > 80_000_000) throw new Error("payload too large");
      return text;
    } catch (error) {
      lastError = error;
      if (/HTTP 4(0[0-9]|1[0-9]|2[0-8])/.test(String(error.message))) break; // not retryable
      await sleep(600 * 2 ** attempt);
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError;
}

/* ------------------------------------------------------------- bridge parse */

function reservedV4(host) {
  const value = ipv4ToInt(host);
  if (value === null) return true;
  const a = Math.floor(value / 16777216);
  const b = Math.floor(value / 65536) % 256;
  const c = Math.floor(value / 256) % 256;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 192 && b === 0 && c <= 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  return false;
}

function reservedV6(host) {
  const h = host.toLowerCase();
  return (
    h === "::" || h === "::1" || h.startsWith("fc") || h.startsWith("fd") || /^fe[89ab]/.test(h) ||
    h.startsWith("ff") || h.startsWith("2001:db8") || h.startsWith("2001:0db8") || h.startsWith("::ffff:")
  );
}

/** Returns a canonical bridge record, or null (plus a reject reason via `stats`). */
function parseBridge(raw, stats) {
  let text = raw.replace(/^\uFEFF/, "").replace(/\u00A0/g, " ").trim();
  if (!text || text.startsWith("#") || text.startsWith("//")) return null;
  text = text.replace(/^Bridge\s+/i, "").replace(/\s+/g, " ");
  if (/^conjure\b/i.test(text)) {
    stats.conjure += 1;
    return null;
  }
  const tokens = text.split(" ");
  let transport = "vanilla";
  let rest = tokens;
  if (["obfs4", "webtunnel"].includes(tokens[0].toLowerCase())) {
    transport = tokens[0].toLowerCase();
    rest = tokens.slice(1);
  } else if (/^(snowflake|meek_lite|meek-lite|dnstt|scramblesuit|fte)$/i.test(tokens[0])) {
    stats.otherTransport += 1;
    return null;
  }
  const addr = /^(\[[0-9a-fA-F:.]+]|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(rest[0] ?? "");
  if (!addr) {
    stats.badFormat += 1;
    return null;
  }
  const host = addr[1].replace(/^\[|\]$/g, "");
  const port = Number(addr[2]);
  if (port < 1 || port > 65535) {
    stats.badFormat += 1;
    return null;
  }
  const isIpv6 = host.includes(":");
  const isIpv4 = !isIpv6;
  if (isIpv4 && ipv4ToInt(host) === null) {
    stats.badFormat += 1;
    return null;
  }
  const fp = rest[1] ?? "";
  if (!FP40.test(fp)) {
    stats.badFingerprint += 1;
    return null;
  }
  const params = {};
  const keep = [];
  for (const token of rest.slice(2)) {
    const eq = token.indexOf("=");
    if (eq <= 0) {
      stats.badFormat += 1;
      return null;
    }
    const key = token.slice(0, eq);
    if (key.toLowerCase() in params) continue; // duplicated parameter
    params[key.toLowerCase()] = token.slice(eq + 1);
    keep.push(token);
  }
  if (transport === "obfs4") {
    if (!/^[A-Za-z0-9+/]{40,90}$/.test(params.cert ?? "")) {
      stats.badCert += 1;
      return null;
    }
    if (params["iat-mode"] !== undefined && !/^[012]$/.test(params["iat-mode"])) {
      stats.badFormat += 1;
      return null;
    }
  }
  if (transport === "webtunnel") {
    try {
      const url = new URL(params.url ?? "");
      if (url.protocol !== "https:" || !url.hostname.includes(".") || isPlaceholderUrl(params.url) || /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)) throw new Error("url");
    } catch {
      stats.badUrl += 1;
      return null;
    }
    // webtunnel dials the url host: the literal address may be a documentation dummy
    // (that is how Tor itself writes webtunnel lines) but never private/loopback.
    const dummy = isIpv4 ? /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(host) : /^2001:0?db8/i.test(host);
    if (!dummy && (isIpv4 ? reservedV4(host) : reservedV6(host))) {
      stats.reserved += 1;
      return null;
    }
  } else if (isIpv4 ? reservedV4(host) : reservedV6(host)) {
    stats.reserved += 1;
    return null;
  }
  if (transport === "vanilla" && keep.length > 0) {
    stats.badFormat += 1;
    return null;
  }
  const upperFp = fp.toUpperCase();
  const line =
    transport === "vanilla"
      ? `${addr[1]}:${port} ${upperFp}`
      : `${transport} ${addr[1]}:${port} ${upperFp}${keep.length ? " " + keep.join(" ") : ""}`;
  if (!ORBOT_LINE.test(line)) {
    stats.orbotRegex += 1;
    return null;
  }
  return {
    line,
    transport,
    host,
    port,
    fp: upperFp,
    params,
    isIpv4,
    isIpv6,
    valid: true,
    placeholder: false,
    identity: `${transport}|${host}|${port}|${upperFp}`,
  };
}

const emptyStats = () => ({
  conjure: 0, otherTransport: 0, badFormat: 0, badFingerprint: 0, badCert: 0, badUrl: 0, reserved: 0, orbotRegex: 0,
});

/* ------------------------------------------------------------------ sources */

async function buildSourceList(state) {
  const sources = new Map();
  const add = (name, url, origin) => {
    if (!url || sources.has(url)) return;
    if (url.toLowerCase().includes(`/${OWN_REPO}/`)) return; // never re-ingest ourselves
    sources.set(url, { name, url, origin });
  };
  for (const source of BUILTIN_SOURCES) add(source.name, source.url, "builtin");
  const extra = await readJson(EXTRA_SOURCES_FILE, { urls: {} });
  for (const [url, meta] of Object.entries(extra.urls ?? {})) {
    if (!/\.(txt)$|bridges-/.test(url) || /pt_config\.json$/.test(url)) continue;
    add(meta.name ?? url, url, "pipeline");
  }
  for (const [url, meta] of Object.entries(state.sources)) add(meta.name ?? url, url, meta.origin ?? "state");
  return [...sources.values()];
}

async function discover(state, report) {
  const lastRun = state.lastDiscover ? new Date(state.lastDiscover).getTime() : 0;
  if (NOW.getTime() - lastRun < 2 * 3_600_000) {
    log("discovery: ran less than 2h ago — skipped");
    return;
  }
  const headers = { accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const queries = [
    "tor bridges collector in:name,description",
    "obfs4 bridges in:name,description",
    "webtunnel bridges in:name,description",
    "tor bridge list obfs4 snowflake in:readme",
    "topic:tor-bridges",
    "topic:obfs4",
    "topic:webtunnel",
    "topic:bridges topic:tor",
    "tor-bridges in:name",
    "bridge collector obfs4 webtunnel vanilla in:readme",
    "iran tor bridges in:name,description,readme",
    "orbot bridges in:name,description",
    // wider net (2026-11): app assets, Persian / Russian ecosystem, feeds and pools
    "tor bridges android assets obfs4 webtunnel in:readme",
    "bridge pool obfs4 webtunnel snowflake in:name,description",
    "tor bridges feed in:name,description",
    "topic:tor-bridge",
    "topic:snowflake topic:tor",
    "topic:censorship-circumvention topic:tor",
    "obfs4 iat-mode bridges list in:readme",
    "پل تور بریج",
    "tor bridges telegram bot obfs4 in:readme",
    "bridgedb mirror obfs4 in:name,description",
  ];
  const repos = new Map();
  for (const query of queries) {
    try {
      const body = JSON.parse(
        await fetchText(
          `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=updated&order=desc&per_page=30`,
          { headers, retries: 1 },
        ),
      );
      for (const item of body.items ?? []) {
        if (item.archived || item.disabled || item.size < 5) continue;
        if (item.full_name.toLowerCase() === OWN_REPO) continue;
        repos.set(item.full_name, item.default_branch ?? "main");
      }
    } catch (error) {
      report.warnings.push(`discovery search failed: ${error.message}`);
    }
    await sleep(2200); // search API: 30 req/min with a token, 10 without
  }
  let found = 0;

  // GitHub code search (needs a token): finds raw bridge files directly, even inside
  // repositories whose name/description never mention bridges.
  if (process.env.GITHUB_TOKEN) {
    const codeQueries = [
      "obfs4 cert= iat-mode= extension:txt",
      "webtunnel url=https ver=0.0.1 extension:txt",
      "obfs4 cert iat-mode filename:bridges",
      "obfs4 cert= iat-mode= filename:bridges.txt",
      "webtunnel url=https ver= filename:webtunnel",
      "obfs4 cert= iat-mode=0 extension:list",
    ];
    for (const query of codeQueries) {
      try {
        const body = JSON.parse(
          await fetchText(`https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=50`, { headers, retries: 1 }),
        );
        for (const item of body.items ?? []) {
          const full = item.repository?.full_name;
          if (!full || full.toLowerCase() === OWN_REPO) continue;
          if (/\.(md|json|zip|gz|py|js|ts|go|rs|yml|yaml|sh|html|toml)$/i.test(item.path)) continue;
          if (/readme|license|changelog|blocked|conjure/i.test(item.path)) continue;
          const url = `https://raw.githubusercontent.com/${full}/HEAD/${item.path.split("/").map(encodeURIComponent).join("/")}`;
          if (!state.sources[url]) {
            state.sources[url] = { name: `code-search:${full}/${item.path}`, origin: "discovered", added: NOW_ISO, ok: 0, fail: 0, miss: 0, yield: 0 };
            found += 1;
          }
        }
      } catch (error) {
        report.warnings.push(`code search failed: ${error.message}`);
      }
      await sleep(7000); // code search is limited to ~10 requests / minute
    }
  }

  for (const [full, branch] of [...repos.entries()].slice(0, 70)) {
    try {
      const tree = JSON.parse(
        await fetchText(`https://api.github.com/repos/${full}/git/trees/${encodeURIComponent(branch)}?recursive=1`, { headers, retries: 1 }),
      );
      const files = (tree.tree ?? [])
        .filter((node) => node.type === "blob" && node.size >= 300 && node.size <= 40_000_000)
        .filter((node) => /(^|\/)[^/]*(obfs4|webtunnel|vanilla|bridges?)[^/]*$/i.test(node.path))
        .filter((node) => !/\.(md|json|zip|gz|png|jpg|py|js|ts|go|rs|yml|yaml|sh|csv|html|toml|lock)$/i.test(node.path))
        .filter((node) => !/readme|license|changelog|manifest|blocked|snowflake|meek|conjure|dnstt/i.test(node.path))
        .sort((a, b) => b.size - a.size)
        .slice(0, 10);
      for (const node of files) {
        const url = `https://raw.githubusercontent.com/${full}/${branch}/${node.path}`;
        if (!state.sources[url]) {
          state.sources[url] = { name: `discovered:${full}/${node.path}`, origin: "discovered", added: NOW_ISO, ok: 0, fail: 0, miss: 0, yield: 0 };
          found += 1;
        }
      }
    } catch (error) {
      report.warnings.push(`discovery tree ${full}: ${error.message}`);
    }
    await sleep(400);
  }
  state.lastDiscover = NOW_ISO;
  report.discovered = found;
  log(`discovery: ${repos.size} candidate repos, ${found} new source files`);
}

/* ---------------------------------------------------------------- pool i/o */

async function loadPool() {
  const doc = await readJson(POOL_FILE, null);
  const pool = new Map();
  if (doc && Array.isArray(doc.bridges)) {
    for (const rec of doc.bridges) {
      const parsed = parseBridge(rec.l, emptyStats());
      if (!parsed) continue; // self-heal: anything that no longer validates is dropped from the pool
      pool.set(parsed.identity, { ...rec, l: parsed.line });
    }
  }
  return pool;
}

async function savePool(pool, meta) {
  const records = [...pool.values()].sort((a, b) => (a.l < b.l ? -1 : 1));
  const body =
    `{"version":1,"updated_at":${JSON.stringify(NOW_ISO)},"meta":${JSON.stringify(meta)},"bridges":[\n` +
    records.map((rec) => JSON.stringify(rec)).join(",\n") +
    "\n]}\n";
  await mkdir(path.join(ROOT, "data"), { recursive: true });
  await writeFile(path.join(ROOT, POOL_FILE), body, "utf8");
}

const recParsed = (rec) => parseBridge(rec.l, emptyStats());
const recCtx = (rec) => ({
  alive: (rec.as ?? 0) > 0,
  aliveStreak: rec.as ?? 0,
  failStreak: rec.fl ?? 0,
  rttMs: rec.rtt,
});
const recScore = (rec) => {
  const parsed = recParsed(rec);
  return parsed ? iranScore(parsed, recCtx(rec)).score : -999;
};

/* -------------------------------------------------------------------- probe */

function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const socket = net.connect({ host, port, timeout: timeoutMs });
    const done = (ok) => {
      socket.destroy();
      resolve(ok ? Number(process.hrtime.bigint() - started) / 1e6 : null);
    };
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

async function probeEnvironment() {
  const closed = await tcpProbe("203.0.113.1", 65000, 2500); // TEST-NET: must never answer
  const open4 = await tcpProbe("1.1.1.1", 443, 4000);
  const open6 = await tcpProbe("2606:4700:4700::1111", 443, 4000);
  return {
    truthful: closed === null && open4 !== null,
    ipv4: open4 !== null,
    ipv6: open6 !== null,
    reason: closed !== null ? "egress proxy answers for unroutable targets" : open4 === null ? "no outbound TCP" : "ok",
  };
}

async function probeRecord(rec, env) {
  const parsed = recParsed(rec);
  if (!parsed) return undefined;
  let host = parsed.host;
  let port = parsed.port;
  if (parsed.transport === "webtunnel") {
    const url = new URL(parsed.params.url);
    port = Number(url.port) || 443;
    try {
      host = (await dns.lookup(url.hostname)).address;
    } catch {
      return null;
    }
  } else if (parsed.isIpv6 && !env.ipv6) {
    return undefined; // cannot judge IPv6 from an IPv4-only runner
  }
  return tcpProbe(host, port, CFG.timeoutMs);
}

/* --------------------------------------------------------------------- main */

const report = {
  generatedAt: NOW_ISO,
  mode: CFG,
  sources: { total: 0, ok: 0, failed: 0, skipped: 0 },
  fetchedLines: 0,
  rejected: emptyStats(),
  newInPool: 0,
  pool: { before: 0, after: 0, alive: 0, dead: 0, unprobed: 0, pruned: 0 },
  probe: null,
  injected: {},
  live: 0,
  warnings: [],
  discovered: 0,
};

const state = await readJson(SOURCES_FILE, { version: 1, sources: {}, lastDiscover: null });
state.sources ??= {};
const pool = await loadPool();
report.pool.before = pool.size;

/* 1+2. discovery, fetch ------------------------------------------------- */
if (CFG.fetch) {
  if (CFG.discover) await discover(state, report);
  const list = await buildSourceList(state);
  report.sources.total = list.length;
  const candidates = new Map(); // identity -> parsed (best first)
  await pmap(list, 6, async (source) => {
    const meta = (state.sources[source.url] ??= { name: source.name, origin: source.origin, ok: 0, fail: 0, miss: 0, yield: 0 });
    meta.name = source.name;
    const lastTry = meta.lastTry ? new Date(meta.lastTry).getTime() : 0;
    if ((meta.miss ?? 0) >= 6 && NOW.getTime() - lastTry < Math.min(7, 2 ** (meta.miss - 5)) * 86_400_000) {
      report.sources.skipped += 1; // quarantined: exponential back-off, retried automatically later
      return;
    }
    meta.lastTry = NOW_ISO;
    try {
      const text = await fetchText(source.url);
      const stats = emptyStats();
      let valid = 0;
      const lines = text.split(/\r?\n/);
      for (const raw of lines.length > 400_000 ? lines.slice(-400_000) : lines) {
        const parsed = parseBridge(raw, stats);
        if (!parsed) continue;
        valid += 1;
        if (!candidates.has(parsed.identity)) candidates.set(parsed.identity, parsed);
      }
      for (const key of Object.keys(stats)) report.rejected[key] += stats[key];
      report.fetchedLines += lines.length;
      meta.ok = (meta.ok ?? 0) + 1;
      meta.miss = valid > 0 ? 0 : (meta.miss ?? 0) + 1;
      meta.lastOk = NOW_ISO;
      meta.yield = valid;
      report.sources.ok += 1;
    } catch (error) {
      meta.fail = (meta.fail ?? 0) + 1;
      meta.miss = (meta.miss ?? 0) + 1;
      meta.lastError = String(error.message).slice(0, 120);
      report.sources.failed += 1;
    }
  });

  // refresh lastSeen for known bridges, admit the best new ones (AI-ranked, transport-balanced)
  const fresh = [];
  for (const parsed of candidates.values()) {
    const known = pool.get(parsed.identity);
    if (known) known.ls = NOW_ISO;
    else fresh.push(parsed);
  }
  const ranked = fresh
    .map((parsed) => ({ parsed, score: iranScore(parsed).score }))
    .sort((a, b) => b.score - a.score || (a.parsed.line < b.parsed.line ? -1 : 1));
  const quota = { obfs4: Math.ceil(CFG.maxNew * 0.5), webtunnel: Math.ceil(CFG.maxNew * 0.3), vanilla: Math.ceil(CFG.maxNew * 0.3) };
  const taken = { obfs4: 0, webtunnel: 0, vanilla: 0 };
  for (const { parsed } of ranked) {
    if (report.newInPool >= CFG.maxNew) break;
    if (taken[parsed.transport] >= quota[parsed.transport]) continue;
    taken[parsed.transport] += 1;
    pool.set(parsed.identity, { l: parsed.line, fs: NOW_ISO, ls: NOW_ISO, la: null, as: 0, fl: 0, lp: null });
    report.newInPool += 1;
  }
  log(`sources ok=${report.sources.ok} failed=${report.sources.failed} skipped=${report.sources.skipped}; candidates=${candidates.size}; new=${report.newInPool}`);
}

/* 3. probe --------------------------------------------------------------- */
if (CFG.probe) {
  const env = await probeEnvironment();
  report.probe = { ...env, attempted: 0, alive: 0, dead: 0, skipped: 0 };
  if (!env.truthful) {
    report.warnings.push(`probing disabled: ${env.reason}`);
    log(`probe disabled (${env.reason}) — falling back to AI ranking only`);
  } else {
    const order = [...pool.entries()]
      .filter(([, rec]) => !rec.lp || NOW.getTime() - new Date(rec.lp).getTime() > 3 * 3_600_000)
      .sort(([, a], [, b]) => (a.lp ? 1 : 0) - (b.lp ? 1 : 0) || (a.lp ?? "") .localeCompare(b.lp ?? "") || recScore(b) - recScore(a))
      .slice(0, CFG.probeLimit);
    await pmap(order, CFG.concurrency, async ([, rec]) => {
      const rtt = await probeRecord(rec, env);
      if (rtt === undefined) {
        report.probe.skipped += 1;
        return;
      }
      report.probe.attempted += 1;
      rec.lp = NOW_ISO;
      if (rtt !== null) {
        rec.as = (rec.as ?? 0) + 1;
        rec.fl = 0;
        rec.la = NOW_ISO;
        rec.rtt = Math.round(rtt);
        report.probe.alive += 1;
      } else {
        rec.fl = (rec.fl ?? 0) + 1;
        rec.as = 0;
        report.probe.dead += 1;
      }
    });
    log(`probe attempted=${report.probe.attempted} alive=${report.probe.alive} dead=${report.probe.dead} skipped=${report.probe.skipped}`);
  }
}

/* 4. prune (pool only — bridge/ lists are never pruned here) ------------- */
const ttlMs = CFG.ttlDays * 86_400_000;
for (const [id, rec] of [...pool.entries()]) {
  const stale = NOW.getTime() - new Date(rec.ls).getTime() > ttlMs;
  const dead = (rec.fl ?? 0) >= 5 && !(rec.as > 0);
  if (stale || dead) {
    pool.delete(id);
    report.pool.pruned += 1;
  }
}
if (pool.size > CFG.poolCap) {
  const keep = [...pool.entries()].sort(([, a], [, b]) => recScore(b) - recScore(a)).slice(0, CFG.poolCap);
  report.pool.pruned += pool.size - keep.length;
  pool.clear();
  for (const [id, rec] of keep) pool.set(id, rec);
}
for (const rec of pool.values()) {
  if ((rec.as ?? 0) > 0) report.pool.alive += 1;
  else if ((rec.fl ?? 0) > 0) report.pool.dead += 1;
  else report.pool.unprobed += 1;
}
report.pool.after = pool.size;

/* 5. inject into bridge/*.txt (append-only) + live Orbot list ------------ */
const probeWorked = Boolean(report.probe?.truthful) && report.probe.attempted > 0;
const eligible = [...pool.values()].filter((rec) => (rec.as ?? 0) > 0);
let unverified = [];
if (!probeWorked) {
  // No truthful probing available: admit the best-ranked never-failed entries, capped.
  unverified = [...pool.values()]
    .filter((rec) => (rec.as ?? 0) === 0 && (rec.fl ?? 0) === 0)
    .sort((a, b) => recScore(b) - recScore(a))
    .slice(0, CFG.maxUnverified);
}
const toInject = [...eligible, ...unverified].sort((a, b) => recScore(b) - recScore(a));

const TARGETS = {
  obfs4: { 4: ["bridge/obfs4.txt", "bridge/obfs4_ipv4_ipv6_all.txt"], 6: ["bridge/obfs4_ipv6.txt", "bridge/obfs4_ipv4_ipv6_all.txt"] },
  webtunnel: { 4: ["bridge/webtunnel.txt", "bridge/webtunnel_ipv4_ipv6_all.txt"], 6: ["bridge/webtunnel_ipv6.txt", "bridge/webtunnel_ipv4_ipv6_all.txt"] },
  vanilla: { 4: ["bridge/vanilla.txt", "bridge/vanilla_ipv4_ipv6_all.txt"], 6: ["bridge/vanilla_ipv6.txt", "bridge/vanilla_ipv4_ipv6_all.txt"] },
};

const byFile = new Map();
for (const rec of toInject) {
  const parsed = recParsed(rec);
  if (!parsed) continue;
  for (const file of TARGETS[parsed.transport][parsed.isIpv6 ? 6 : 4]) {
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push(parsed);
  }
}

if (!CFG.dry) {
  for (const [file, entries] of byFile) {
    const absolute = path.join(ROOT, file);
    let existing = "";
    try {
      existing = await readFile(absolute, "utf8");
    } catch {
      /* new file */
    }
    const have = new Set();
    for (const raw of existing.split(/\r?\n/)) {
      const parsed = parseBridge(raw, emptyStats());
      if (parsed) have.add(parsed.identity);
    }
    const additions = [];
    for (const parsed of entries) {
      if (additions.length >= CFG.perFileAdd) break;
      if (!have.has(parsed.identity)) additions.push(parsed.line);
    }
    report.injected[file] = additions.length;
    if (additions.length === 0) continue;
    const base = existing.length === 0 || existing.endsWith("\n") ? existing : existing + "\n";
    await writeFile(absolute, base + additions.join("\n") + "\n", "utf8");
  }
}

// Orbot-safe "live & fastest" list: probe-verified only, one bridge per /24, AI + RTT ranked.
if (probeWorked && eligible.length > 0) {
  const ordered = eligible
    .map((rec) => ({ rec, parsed: recParsed(rec), score: recScore(rec) }))
    .filter((item) => item.parsed)
    .sort((a, b) => b.score - a.score);
  const seen24 = new Map();
  const live = [];
  for (const item of ordered) {
    const key = item.parsed.isIpv4 ? item.parsed.host.split(".").slice(0, 3).join(".") : item.parsed.params.url ?? item.parsed.host;
    if ((seen24.get(key) ?? 0) >= 1) continue;
    seen24.set(key, 1);
    live.push(item.parsed.line);
    if (live.length >= 150) break;
  }
  report.live = live.length;
  if (!CFG.dry && live.length > 0) {
    await mkdir(path.join(ROOT, "export/orbot"), { recursive: true });
    await writeFile(path.join(ROOT, LIVE_FILE), live.join("\n") + "\n", "utf8");
  }
}

if (!CFG.dry) {
  await savePool(pool, { alive: report.pool.alive, dead: report.pool.dead, unprobed: report.pool.unprobed });
  await mkdir(path.join(ROOT, "data"), { recursive: true });
  // keep the sources state compact: forget sources that never worked for 30+ tries
  for (const [url, meta] of Object.entries(state.sources)) {
    if ((meta.ok ?? 0) === 0 && (meta.fail ?? 0) >= 30 && meta.origin === "discovered") delete state.sources[url];
  }
  state.updatedAt = NOW_ISO;
  await writeFile(path.join(ROOT, SOURCES_FILE), JSON.stringify(state, null, 1) + "\n", "utf8");
}

const added = Object.values(report.injected).reduce((a, b) => a + b, 0);
log(`pool ${report.pool.before} -> ${report.pool.after} (alive=${report.pool.alive} dead=${report.pool.dead} unprobed=${report.pool.unprobed} pruned=${report.pool.pruned})`);
log(`injected ${added} line(s) into ${Object.keys(report.injected).length} list(s); live list=${report.live}`);
for (const [key, value] of Object.entries(report.rejected)) if (value > 0) log(`  rejected ${key}=${value}`);
for (const warning of report.warnings.slice(0, 10)) log("note: " + warning);
if (CFG.json) await writeFile(path.resolve(CFG.json), JSON.stringify(report, null, 2) + "\n", "utf8");

const totalFailure = CFG.fetch && report.sources.total > 0 && report.sources.ok === 0;
if (totalFailure) log("WARNING: every source failed (network?) — pool kept as is");
process.exit(CFG.strict && totalFailure ? 1 : 0);
