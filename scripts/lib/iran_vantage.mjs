// Pure logic for the check-host.net Iran-datacenter vantage stage.
//
// HONESTY BOUNDARY (do not weaken):
//   * A check-host "ir*" node is a datacenter host in Iran. It answers only
//     "can that host open a TCP connection / get an HTTPS response from that
//     endpoint?".  It is NOT a pluggable-transport handshake, NOT a meek tunnel,
//     NOT a WebTunnel upgrade, NOT a Snowflake WebRTC session and NOT a Tor
//     circuit.  Missing data is "inconclusive" - never "blocked" or "working".
//   * GitHub-hosted runners are outside Iran; nothing here is run "from Iran"
//     except the probe that check-host itself operates.
//   * Output classes are never copied into any working-bridge list.
//
// This module has no I/O: everything is unit-tested offline.

export const VANTAGE = "check-host-iran-datacenter";
export const USER_AGENT = "iran-tcp-vantage-measurement/1.0";
export const CLAIM_CEILING = {
  tcp: "tcp-from-iran-datacenter-only",
  https: "https-from-iran-datacenter-only",
};

/** Source buckets in processing order. `files` = first existing file wins. */
export const SOURCES = [
  { transport: "vanilla", files: ["bridge/vanilla_ipv4.txt", "bridge/vanilla.txt"], take: 4, unit: "calls" },
  { transport: "obfs4", files: ["bridge/obfs4_ipv4.txt", "bridge/obfs4.txt"], take: 4, unit: "calls" },
  { transport: "webtunnel", files: ["bridge/webtunnel_ipv4.txt", "bridge/webtunnel.txt"], take: 4, unit: "lines" },
  { transport: "meek_lite", files: ["bridge/meek_lite.txt"], take: 2, unit: "calls" },
  { transport: "meek-azure", files: ["bridge/meek-azure.txt"], take: 2, unit: "calls" },
  { transport: "snowflake", files: ["bridge/snowflake.txt"], take: 2, unit: "calls" },
  { transport: "conjure", files: ["bridge/conjure.txt"], take: 2, unit: "calls" },
  { transport: "scramblesuit", files: ["bridge/scramblesuit.txt"], take: 2, unit: "calls" },
  { transport: "obfs3", files: ["bridge/obfs3.txt"], take: 2, unit: "calls" },
  { transport: "fte", files: ["bridge/fte.txt"], take: 2, unit: "calls" },
];

export const MAX_CALLS_PER_RUN = 20;
export const MIN_START_GAP_MS = 3000;
export const POLL_INTERVAL_MS = 2000;
export const MAX_POLLS = 12;

// ───────────────────────── address helpers ─────────────────────────

export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s));
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.some((x) => x > 255) ? null : o;
}

/** Public = outside every reserved / private / documentation / multicast range. */
export function isPublicIPv4(s) {
  const o = parseIPv4(s);
  if (!o) return false;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127) return false; // 0/8 10/8 127/8
  if (a === 100 && b >= 64 && b <= 127) return false; // 100.64/10
  if (a === 169 && b === 254) return false; // link local
  if (a === 172 && b >= 16 && b <= 31) return false; // 172.16/12
  if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1 (repo placeholder)
  if (a === 192 && b === 168) return false;
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast, reserved, broadcast
  return true;
}

/** "ip:port" | "[v6]:port" | "host:port" -> {kind, host, port}. */
export function splitHostPort(addr) {
  const s = String(addr || "");
  if (s.startsWith("[")) return { kind: "ipv6" };
  const parts = s.split(":");
  if (parts.length > 2) return { kind: "ipv6" };
  if (parts.length !== 2) return { kind: "invalid" };
  const port = /^\d{1,5}$/.test(parts[1]) ? Number(parts[1]) : 0;
  if (port < 1 || port > 65535) return { kind: "invalid" };
  const host = parts[0];
  if (parseIPv4(host)) return { kind: "ipv4", host, port };
  return { kind: "hostname", host, port };
}

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

/** hostname (no scheme/path/port) -> {ok, host} | {ok:false, reason}. */
function checkHostName(host) {
  const h = String(host || "").toLowerCase();
  if (!h) return { ok: false, reason: "empty_host" };
  if (h.startsWith("[") || h.includes(":")) return { ok: false, reason: "ipv6_not_measured" };
  if (parseIPv4(h)) return isPublicIPv4(h) ? { ok: true, host: h } : { ok: false, reason: "non_public_address" };
  if (h === "localhost" || !HOSTNAME_RE.test(h)) return { ok: false, reason: "invalid_hostname" };
  return { ok: true, host: h };
}

/** url=... -> "https://host/" | "https://host:port/" (path/query/userinfo/fragment dropped). */
export function httpsOrigin(urlStr) {
  let u;
  try {
    u = new URL(String(urlStr));
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  if (u.protocol !== "https:") return { ok: false, reason: "not_https_url" };
  const h = checkHostName(u.hostname);
  if (!h.ok) return h;
  const port = u.port ? `:${u.port}` : ""; // WHATWG URL drops the default 443
  return { ok: true, target: `https://${h.host}${port}/` };
}

function frontOrigin(front) {
  const h = checkHostName(front);
  return h.ok ? { ok: true, target: `https://${h.host}/` } : h;
}

// ───────────────────────── line -> targets ─────────────────────────

const FRONTED = new Set(["meek_lite", "meek-azure", "snowflake", "conjure"]);
const VERB_BUCKETS = new Set(["obfs4", "scramblesuit", "obfs3", "fte"]);

function kv(tokens) {
  const out = {};
  for (const t of tokens) {
    const i = t.indexOf("=");
    if (i > 0) out[t.slice(0, i).toLowerCase()] = t.slice(i + 1);
  }
  return out;
}

/**
 * Turn one bridge-file line into check-host targets.
 * Returns {line_verb, targets:[{transport,line_verb,source_file,method,target}], skips:[reason]}.
 * Never stores fingerprints, certs, url paths or permanent links.
 */
export function buildTargets(rawLine, transport, sourceFile) {
  const res = { line_verb: null, targets: [], skips: [] };
  let line = String(rawLine || "").trim();
  if (!line || line.startsWith("#")) {
    res.skips.push("blank_or_comment");
    return res;
  }
  line = line.replace(/^bridge\s+/i, "");
  const tok = line.split(/\s+/);
  const add = (method, target, verb) =>
    res.targets.push({ transport, line_verb: verb, source_file: sourceFile, method, target });

  if (transport === "vanilla") {
    res.line_verb = "vanilla";
    const hp = splitHostPort(tok[0]);
    if (hp.kind === "ipv6") res.skips.push("ipv6_not_measured");
    else if (hp.kind !== "ipv4") res.skips.push("not_a_vanilla_ipv4_line");
    else if (!isPublicIPv4(hp.host)) res.skips.push("non_public_address");
    else add("tcp", `${hp.host}:${hp.port}`, "vanilla");
    return res;
  }

  const verb = (tok[0] || "").toLowerCase();
  res.line_verb = verb;
  const opts = kv(tok.slice(2));

  if (VERB_BUCKETS.has(transport)) {
    if (verb !== transport) {
      res.skips.push("verb_mismatch");
      return res;
    }
    const hp = splitHostPort(tok[1]);
    if (hp.kind === "ipv6") res.skips.push("ipv6_not_measured");
    else if (hp.kind !== "ipv4") res.skips.push("not_an_ipv4_endpoint");
    else if (!isPublicIPv4(hp.host)) res.skips.push("non_public_address");
    else add("tcp", `${hp.host}:${hp.port}`, verb);
    return res;
  }

  if (transport === "webtunnel") {
    if (verb !== "webtunnel") {
      res.skips.push("verb_mismatch");
      return res;
    }
    const hp = splitHostPort(tok[1]);
    if (hp.kind === "ipv4" && isPublicIPv4(hp.host)) add("tcp", `${hp.host}:${hp.port}`, verb);
    else if (hp.kind === "ipv6") res.skips.push("tcp:ipv6_not_measured");
    else if (hp.kind === "ipv4") res.skips.push("tcp:non_public_address");
    else res.skips.push("tcp:no_literal_ipv4");
    if (opts.url) {
      const o = httpsOrigin(opts.url);
      if (o.ok) add("https", o.target, verb);
      else res.skips.push(`https:${o.reason}`);
    } else {
      res.skips.push("https:no_url");
    }
    return res;
  }

  if (FRONTED.has(transport)) {
    // The written address is a placeholder: never tcp-probe it.
    let o = null;
    if (opts.front) o = frontOrigin(opts.front);
    if ((!o || !o.ok) && opts.url) {
      const u = httpsOrigin(opts.url);
      if (!o || u.ok) o = u;
    }
    if (!o) res.skips.push("no_front_or_url");
    else if (!o.ok) res.skips.push(o.reason);
    else add("https", o.target, verb);
    return res;
  }

  res.skips.push("unknown_transport");
  return res;
}

/**
 * Lazily plan one source file. Cursor semantics: advance only past considered
 * lines, wrapping to 0 at the end of the file.
 * seen: Set shared across the run (dedupe of transport|method|target).
 */
export function planSource({ transport, sourceFile, lines, cursor, take, unit, callsLeft, seen }) {
  const n = lines.length;
  const items = [];
  const skipLog = [];
  if (n === 0) return { items, skipLog, finalCursor: 0 };
  const start = Number.isInteger(cursor) && cursor >= 0 && cursor < n ? cursor : 0;
  let finalCursor = start;
  let taken = 0;
  let callsPlanned = 0;
  for (let k = 0; k < n; k++) {
    if (taken >= take || callsPlanned >= callsLeft) break;
    const idx = (start + k) % n;
    const b = buildTargets(lines[idx], transport, sourceFile);
    const fresh = [];
    for (const t of b.targets) {
      const key = `${t.transport}|${t.method}|${t.target}`;
      if (!seen.has(key)) fresh.push({ t, key });
    }
    if (callsPlanned + fresh.length > callsLeft) break; // cannot afford: do not consider the line
    for (const f of fresh) seen.add(f.key);
    for (const s of b.skips) if (s !== "blank_or_comment") skipLog.push(s);
    finalCursor = (idx + 1) % n;
    if (fresh.length) {
      callsPlanned += fresh.length;
      taken += unit === "lines" ? 1 : fresh.length;
      items.push({ targets: fresh.map((f) => f.t), cursorAfter: finalCursor });
    }
  }
  return { items, skipLog, finalCursor };
}

// ───────────────────────── check-host result parsing ─────────────────────────

const REFUSED_RE = /refused/i;
const UNREACH_RE = /timed out|timeout|no route|unreachable|failed/i;

function classifyMessage(msg) {
  if (typeof msg !== "string") return "inconclusive";
  if (REFUSED_RE.test(msg)) return "refused";
  if (UNREACH_RE.test(msg)) return "unreachable";
  return "inconclusive";
}

/**
 * One node's value from /check-result -> {state, code}.
 * state: pending | open | answered | refused | unreachable | inconclusive
 * method decides the positive label (tcp: open, https: answered); both shapes
 * are accepted for either method.
 */
export function parseNodeResult(value, method) {
  const positive = method === "https" ? "answered" : "open";
  if (value === null || value === undefined) return { state: "pending", code: null };
  let row = value;
  if (Array.isArray(value)) {
    if (value.length === 0) return { state: "inconclusive", code: null };
    const first = value[0];
    if (first === null) return { state: "pending", code: null };
    if (Array.isArray(first) || typeof first === "object") row = first;
  }
  if (row === null || typeof row !== "object") return { state: "inconclusive", code: null };
  if (!Array.isArray(row)) {
    // TCP object shape
    if (row.error !== undefined && row.error !== null) return { state: classifyMessage(String(row.error)), code: null };
    if (typeof row.time === "number" && Number.isFinite(row.time)) return { state: positive, code: null };
    return { state: "inconclusive", code: null };
  }
  // list shapes
  if (typeof row[0] === "string") {
    // legacy TCP array ["OK", seconds, ip]
    if (row[0] === "OK" && typeof row[1] === "number") return { state: positive, code: null };
    return { state: classifyMessage(row[0]), code: null };
  }
  if (row.length >= 3 && (row[0] === 1 || row[0] === 0)) {
    if (row[0] === 1) {
      const code = row[3] === undefined || row[3] === null ? null : String(row[3]);
      return { state: positive, code };
    }
    return { state: classifyMessage(row[2]), code: null };
  }
  return { state: "inconclusive", code: null };
}

const POSITIVE = new Set(["open", "answered"]);

/** Class decision from the two sides. Never maps missing data to blocked/working. */
export function classify(method, iran, control) {
  const kind = method === "https" ? "https" : "tcp";
  if (!iran || !control) return "inconclusive";
  if (iran === "inconclusive" || control === "inconclusive" || iran === "pending" || control === "pending") {
    return "inconclusive";
  }
  const cPos = POSITIVE.has(control);
  if (POSITIVE.has(iran) && cPos) return `iran_${kind}_open`;
  if (iran === "unreachable" && cPos) return `iran_${kind}_unreachable`;
  if (iran === "refused" && cPos) return "iran_node_refused";
  if (iran === "unreachable" && control === "unreachable") return "endpoint_down";
  if (iran === "refused" && control === "refused") return "endpoint_down";
  return "inconclusive";
}

// ───────────────────────── node discovery ─────────────────────────

const byName = (a, b) => a.name.localeCompare(b.name, "en", { numeric: true });

/** /nodes/hosts payload -> {iran:[...], control:node|null}. Rediscovered every run. */
export function discoverNodes(payload) {
  const raw = payload && typeof payload === "object" ? payload.nodes : null;
  const all = [];
  if (raw && typeof raw === "object") {
    for (const [name, info] of Object.entries(raw)) {
      const loc = info && Array.isArray(info.location) ? info.location : [];
      if (typeof loc[0] !== "string" || !/^[a-z0-9.-]+$/i.test(name)) continue;
      all.push({
        name,
        ip: typeof info.ip === "string" ? info.ip : null,
        asn: typeof info.asn === "string" ? info.asn.trim() : null,
        country: loc[0],
        city: typeof loc[2] === "string" ? loc[2] : null,
      });
    }
  }
  const iran = all.filter((n) => n.country === "ir").sort(byName);
  const pick = (cc) => all.filter((n) => n.country === cc).sort(byName)[0] || null;
  return { iran, control: pick("de") || pick("nl") };
}

// ───────────────────────── record ─────────────────────────

export function buildRecord({ target, iranNode, controlNode, requestId, testedAt, iran, control }) {
  const m = target.method;
  return {
    transport: target.transport,
    line_verb: target.line_verb,
    source_file: target.source_file,
    method: m,
    target: target.target,
    tested_at: testedAt,
    vantage: VANTAGE,
    iran_node: iranNode.name,
    iran_node_ip: iranNode.ip,
    iran_asn: iranNode.asn,
    iran_city: iranNode.city,
    control_node: controlNode.name,
    control_country: controlNode.country,
    request_id: requestId,
    iran: iran.state === "pending" ? "inconclusive" : iran.state,
    control: control.state === "pending" ? "inconclusive" : control.state,
    http_code_iran: m === "https" ? iran.code : null,
    http_code_control: m === "https" ? control.code : null,
    class: classify(m, iran.state, control.state),
    claim_ceiling: CLAIM_CEILING[m],
  };
}

// ───────────────────────── multi-node selection + aggregate (additive) ─────────────────────────

/**
 * Pick up to k distinct Iran nodes for ONE check-host call, rotating through
 * every node discovered this run (ir1..irN, never hard-coded). Different cities
 * are preferred first so the observations are as independent as the free node
 * set allows. Deterministic for a given (nodes, offset).
 */
export function pickIranNodes(iran, offset, k) {
  const n = iran.length;
  if (!n || k <= 0) return [];
  const rotated = [];
  for (let i = 0; i < n; i++) rotated.push(iran[(((offset + i) % n) + n) % n]);
  const picked = [];
  const cities = new Set();
  for (const node of rotated) {
    if (picked.length >= k) break;
    const c = (node.city || node.name).toLowerCase();
    if (!cities.has(c)) { cities.add(c); picked.push(node); }
  }
  for (const node of rotated) {
    if (picked.length >= k) break;
    if (!picked.includes(node)) picked.push(node);
  }
  return picked;
}

const NEG_CLASSES = new Set(["iran_tcp_unreachable", "iran_https_unreachable"]);
const POS_CLASSES = new Set(["iran_tcp_open", "iran_https_open"]);

/**
 * Aggregate per-target view over records inside a time window.
 * suspected_blocked_from_iran_datacenters is set ONLY when at least two DISTINCT
 * Iranian nodes failed while the foreign control answered AND no Iranian node
 * answered. It is a TCP/HTTPS datacenter signal; it never says anything about a
 * Tor, obfs4, WebTunnel, meek or Snowflake handshake and is never copied to a
 * working/blocked bridge list. Missing data stays "inconclusive".
 */
export function summarizeVantage(records, nowMs, windowMs = 24 * 3600 * 1000) {
  const per = new Map();
  for (const r of records) {
    if (!r || typeof r !== "object" || !r.target || !r.iran_node || !r.tested_at) continue;
    const t = Date.parse(r.tested_at);
    if (!Number.isFinite(t) || nowMs - t > windowMs) continue;
    const key = `${r.transport}|${r.method}|${r.target}`;
    let e = per.get(key);
    if (!e) {
      e = { transport: r.transport, method: r.method, target: r.target, open: new Set(), failed: new Set(), other: new Set(), latest: r.tested_at };
      per.set(key, e);
    }
    if (r.tested_at > e.latest) e.latest = r.tested_at;
    if (POS_CLASSES.has(r.class)) e.open.add(r.iran_node);
    else if (NEG_CLASSES.has(r.class)) e.failed.add(r.iran_node);
    else e.other.add(r.iran_node);
  }
  const targets = [];
  const counts = { reachable_from_iran_datacenter: 0, suspected_blocked_from_iran_datacenters: 0, inconclusive: 0 };
  for (const e of [...per.values()].sort((a, b) => (a.target < b.target ? -1 : 1))) {
    let verdict = "inconclusive";
    if (e.open.size > 0) verdict = "reachable_from_iran_datacenter";
    else if (e.failed.size >= 2) verdict = "suspected_blocked_from_iran_datacenters";
    counts[verdict] += 1;
    targets.push({
      transport: e.transport, method: e.method, target: e.target, verdict,
      iran_nodes_open: [...e.open].sort(), iran_nodes_failed: [...e.failed].sort(),
      latest_tested_at: e.latest,
    });
  }
  return {
    schema: "iran-vantage-summary/1",
    generated_at: new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, "Z"),
    window_hours: Math.round(windowMs / 3600000),
    claim_ceiling: "tcp-or-https-from-iran-datacenters-only; not a Tor/PT handshake; GitHub runners are not in Iran",
    counts, targets,
  };
}
