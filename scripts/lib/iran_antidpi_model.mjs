/**
 * iran_antidpi_model.mjs — internal, dependency-free, fully explainable ranking
 * model for bridges used from inside Iran (shared by bridge_autofill.mjs and
 * bridge_harvest.mjs).
 *
 * Hand-tuned additive (logistic-style) model: no network, no API key,
 * deterministic, every term returns a human-readable reason. The weights encode
 * what is publicly known about the Iranian filtering stack:
 *
 *   - DPI fingerprints the *protocol*: WebTunnel (real HTTPS to a real domain)
 *     and Snowflake (WebRTC) survive far better than bare obfs4 / vanilla.
 *   - obfs4 "iat-mode" is a CLIENT-side option: iat-mode=1/2 randomises packet
 *     timing, defeating flow-timing classifiers (costs some speed).
 *   - Port 443 / common TLS ports blend into normal traffic; the classic Tor
 *     ports 9001 / 9030 / 9050 / 9150 are matched first by blocklists.
 *   - Cloudflare / Fastly / Azure-fronted endpoints cannot be IP-blocked
 *     without collateral damage.
 *   - IPv6 is throttled / blocked more often than IPv4 on mobile networks.
 *   - Live, low-RTT bridges beat dead or slow ones (speed term).
 */

const TLS_PORTS = new Set([443, 8443, 2053, 2083, 2087, 2096, 4443, 9443]);
const FLAGGED_PORTS = new Set([9001, 9030, 9050, 9051, 9150, 9151, 9101, 9002]);

/** IPv4 CIDR blocks of big CDNs (collateral-damage shield). */
const CDN_V4 = [
  ["104.16.0.0", 13], ["104.24.0.0", 14], ["172.64.0.0", 13], ["162.158.0.0", 15],
  ["188.114.96.0", 20], ["141.101.64.0", 18], ["108.162.192.0", 18], ["198.41.128.0", 17],
  ["151.101.0.0", 16], ["199.232.0.0", 16], // Fastly
  ["13.107.246.0", 24], ["13.107.213.0", 24], // Azure Front Door
];

export function ipv4ToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return (parts[0] * 16777216) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function isCdnIpv4(ip) {
  const value = ipv4ToInt(ip);
  if (value === null) return false;
  return CDN_V4.some(([base, bits]) => {
    const start = ipv4ToInt(base);
    const size = 2 ** (32 - bits);
    return value >= start && value < start + size;
  });
}

/**
 * @param {{transport:string,host:string,port:number,isIpv4:boolean,isIpv6:boolean,
 *          fp?:string|null,params?:Record<string,string>,placeholder?:boolean,valid?:boolean}} parsed
 * @param {{freshHours?:number,alive?:boolean,aliveStreak?:number,failStreak?:number,rttMs?:number}} [ctx]
 */
export function iranScore(parsed, ctx = {}) {
  const why = [];
  let score = 40;
  const bump = (value, reason) => {
    score += value;
    if (value !== 0) why.push(`${reason}${value > 0 ? "+" : ""}${value}`);
  };
  const params = parsed.params ?? {};

  if (parsed.transport === "webtunnel") bump(24, "webtunnel(HTTPS mimics real traffic)");
  else if (parsed.transport === "snowflake") bump(18, "snowflake(volunteer proxies)");
  else if (parsed.transport === "obfs4") bump(15, "obfs4");
  else if (parsed.transport === "meek_lite") bump(4, "meek_slow");

  if (parsed.port === 443) bump(12, "port443");
  else if (TLS_PORTS.has(parsed.port)) bump(8, "tls-like-port");
  else if (parsed.port === 80) bump(3, "port80");
  else if (FLAGGED_PORTS.has(parsed.port)) bump(-6, "classic-tor-port(flagged)");
  else if (parsed.port > 1024 && parsed.port < 40000) bump(2, "mid-port");

  if (parsed.isIpv4) bump(6, "ipv4");
  if (parsed.isIpv6 && parsed.transport !== "webtunnel") bump(-10, "ipv6(blocked more often in IR)");
  if (parsed.isIpv4 && isCdnIpv4(parsed.host)) bump(10, "cdn-shielded");
  if (parsed.fp) bump(6, "pinned-fingerprint");

  const iat = params["iat-mode"];
  if (iat === "1") bump(9, "iat-mode=1");
  else if (iat === "2") bump(5, "iat-mode=2");
  if (params.front || params.fronts) bump(6, "domain-fronted");
  if (params.url && /^https:\/\//i.test(params.url)) bump(4, "https-url");

  if (parsed.placeholder) bump(-80, "dummy-endpoint(unreachable)");
  if (parsed.valid === false) bump(-100, "invalid-for-orbot");

  if (ctx.freshHours !== undefined) {
    const freshness = Math.max(-4, 6 - Math.min(6, ctx.freshHours / 12));
    if (freshness > 0) bump(Math.round(freshness), "fresh-source");
  }
  if (ctx.alive) bump(10 + Math.min(6, (ctx.aliveStreak ?? 1) - 1), "probe-alive");
  if ((ctx.failStreak ?? 0) > 0) bump(-Math.min(30, ctx.failStreak * 8), "probe-failing");
  if (typeof ctx.rttMs === "number" && ctx.rttMs > 0) {
    bump(Math.round(Math.max(-4, 8 - ctx.rttMs / 60)), `rtt${Math.round(ctx.rttMs)}ms`);
  }
  return { score: Math.round(score * 10) / 10, why };
}

/**
 * Client-side hardening for an obfs4 line: iat-mode=0 -> 1 randomises inter-arrival
 * timing (anti flow-timing DPI) at a small speed cost. Lines that already carry
 * iat-mode=1/2 are unchanged. Non-obfs4 lines are unchanged.
 */
export function hardenObfs4(line) {
  if (!/^obfs4\s/i.test(line)) return line;
  if (/\biat-mode=[12]\b/.test(line)) return line;
  if (/\biat-mode=0\b/.test(line)) return line.replace(/\biat-mode=0\b/, "iat-mode=1");
  return `${line} iat-mode=1`;
}
