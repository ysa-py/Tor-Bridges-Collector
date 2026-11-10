/**
 * orbot_format.mjs — single source of truth for "will Orbot accept this line?".
 *
 * Mirrors guardianproject/orbot-android CustomBridgeBottomSheet.kt (validBridgeRegex +
 * cleanBridgeLines). Orbot validates EVERY pasted line and rejects the WHOLE paste with
 * "Invalid bridge format" when one line fails, so this module is used to:
 *
 *   1. validate   — exact regex Orbot uses, after the same Unicode-space normalisation,
 *   2. check      — semantic problems Orbot's regex cannot see but Tor rejects after the
 *                   user taps Connect ("configuration is invalid"): octets > 255,
 *                   port 0 / > 65535, obfs4 without cert=, webtunnel without url=, ...
 *   3. repair     — turn the lines that circulate in the wild into paste-ready ones
 *                   WITHOUT changing their meaning:
 *                     "Bridge obfs4 ..."                -> prefix removed (torrc syntax)
 *                     "snowflake <FP> fingerprint=..."  -> dummy address inserted, exactly
 *                     "meek_lite <FP> url=..."             like Tor itself writes them
 *                     duplicated key=value tokens       -> first one kept
 *                     "%2F" style escapes               -> decoded when that makes it valid
 *                   Comments, bare domains, conjure and unsupported transports are
 *                   reported as non-bridge lines (never silently "fixed").
 *
 * Dependency-free, Node >= 20, no network.
 */

export const ORBOT_REGEX =
  /^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$/;

export const SUPPORTED_TRANSPORTS = ["obfs4", "webtunnel", "snowflake", "meek_lite", "dnstt"];
const UNSUPPORTED = /^(conjure|scramblesuit|fte|obfs3|obfs2|meek|meek-azure|meek-lite|lyrebird|shadow|hysteria)\b/i;
const FP40 = /^[0-9a-fA-F]{40}$/;

/** Addresses Tor itself writes for transports that connect through url=/front= instead of dialling. */
export const DUMMY_ADDRESS = {
  snowflake: "192.0.2.3:80",
  meek_lite: "192.0.2.18:80",
  webtunnel: "[2001:db8::1]:443",
};

/** Orbot's cleaning path: any Unicode space (NBSP, thin space, ...) becomes a plain space. */
export function normaliseSpaces(text) {
  return String(text).replace(/\uFEFF/g, "").replace(/\p{Zs}/gu, " ");
}

/** Same as Orbot's cleanBridgeLines(): split lines, normalise spaces, drop blanks. */
export function cleanBridgeLines(text) {
  return normaliseSpaces(text)
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);
}

export const isOrbotValid = (line) => ORBOT_REGEX.test(normaliseSpaces(line).replace(/\r$/, ""));

export function isDummyHost(host) {
  return /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:0?db8:)/i.test(host);
}

/** Split "addr[:port]" into parts; returns null when it is not an address token. */
export function splitAddress(token) {
  const match = /^(\[[0-9a-fA-F:.]+]|\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/.exec(token ?? "");
  if (!match) return null;
  return {
    host: match[1].replace(/^\[|\]$/g, ""),
    bracketed: match[1].startsWith("["),
    port: match[2] ? Number(match[2]) : null,
  };
}

/** Fingerprints of the public Snowflake bridges shipped with Tor Browser (used to heal corrupted copies). */
export const KNOWN_FINGERPRINTS = [
  "2B280B23E1107BB62ABFC40DDCC8824814F80A72",
  "8838024498816A039FCBBAB14E6F40A0843051FA",
];

/** Documentation / template hosts that appear in sample lines and can never be reached. */
const PLACEHOLDER_HOST =
  /^(?:yourdomain|your-domain|yourdomain\.\w+|example\.(?:com|org|net)|www\.example\.(?:com|org|net)|domain\.(?:tld|com)|localhost|[a-z0-9.-]+\.(?:example|invalid|test|localhost))$/i;

export function isPlaceholderUrl(value) {
  try {
    const url = new URL(String(value));
    return PLACEHOLDER_HOST.test(url.hostname);
  } catch {
    return /yourdomain|example\.(com|org|net)/i.test(String(value));
  }
}

function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    for (let j = 1; j <= b.length; j++) {
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = row;
  }
  return prev[b.length];
}

/**
 * Heal a hex token that is a damaged fingerprint (one or two characters lost / flipped).
 * Orbot's regex lets such a token through (it falls into the free-form tail) but Tor then
 * refuses the bridge ("Invalid fingerprint"), so the whole bridge is dead on arrival.
 * @returns {null | {fp: string | null, repaired: boolean}} null = not fingerprint-like;
 *          fp === null = fingerprint-like but unrecoverable.
 */
export function repairFingerprint(token) {
  if (FP40.test(token)) return { fp: token.toUpperCase(), repaired: token !== token.toUpperCase() };
  if (!/^[0-9a-fA-F]{34,46}$/.test(token)) return null;
  const upper = token.toUpperCase();
  const known = KNOWN_FINGERPRINTS.find((candidate) => editDistance(upper, candidate, 2) <= 2);
  return known ? { fp: known, repaired: true } : { fp: null, repaired: false };
}

/**
 * Token-wise scrub of one raw bridge line: heals damaged fingerprints and flags lines that
 * can never connect. Whitespace and every other byte of the line are preserved.
 * @returns {{drop: string | null, line: string, changed: boolean}}
 */
export function scrubLine(raw) {
  const parts = String(raw).split(/(\s+)/);
  let changed = false;
  for (let i = 0; i < parts.length; i++) {
    const token = parts[i];
    if (!token || /^\s+$/.test(token)) continue;
    const eq = token.indexOf("=");
    if (eq > 0) {
      const key = token.slice(0, eq).toLowerCase();
      const value = token.slice(eq + 1);
      if (key === "fingerprint") {
        const fixed = repairFingerprint(value);
        if (fixed && fixed.fp === null) return { drop: "bad-fingerprint", line: raw, changed: false };
        if (fixed && fixed.fp !== value) {
          parts[i] = `${token.slice(0, eq)}=${fixed.fp}`;
          changed = true;
        }
      } else if (key === "url" && isPlaceholderUrl(value)) {
        return { drop: "placeholder-url", line: raw, changed: false };
      }
    } else if (/^[0-9a-fA-F]{34,46}$/.test(token) && token.length !== 40) {
      const fixed = repairFingerprint(token);
      if (!fixed || fixed.fp === null) return { drop: "bad-fingerprint", line: raw, changed: false };
      parts[i] = fixed.fp;
      changed = true;
    }
  }
  return { drop: null, line: parts.join(""), changed };
}

/** Problems the regex cannot catch but Tor/Orbot reject at connect time. Empty array = fine. */
export function semanticProblems(line) {
  const problems = [];
  const tokens = normaliseSpaces(line).trim().split(/\s+/);
  const transport = SUPPORTED_TRANSPORTS.includes(tokens[0]) ? tokens[0] : "vanilla";
  const address = splitAddress(transport === "vanilla" ? tokens[0] : tokens[1]);
  if (!address) return ["no-address"];
  if (!address.bracketed && address.host.split(".").some((octet) => Number(octet) > 255)) problems.push("octet>255");
  if (address.port !== null && (address.port < 1 || address.port > 65535)) problems.push("port-range");
  if (address.port === null && transport !== "snowflake" && transport !== "meek_lite") problems.push("no-port");
  const rest = tokens.slice(transport === "vanilla" ? 1 : 2);
  const fp = rest.find((token) => FP40.test(token));
  const kv = Object.fromEntries(
    rest
      .filter((t) => t.includes("="))
      .map((t) => [t.slice(0, t.indexOf("=")).toLowerCase(), t.slice(t.indexOf("=") + 1)]),
  );
  if (rest.some((token) => /^[0-9a-fA-F]{34,46}$/.test(token) && token.length !== 40)) problems.push("bad-fingerprint");
  if (kv.fingerprint !== undefined && !FP40.test(kv.fingerprint)) problems.push("bad-fingerprint");
  if (kv.url && isPlaceholderUrl(kv.url)) problems.push("placeholder-url");
  if (transport === "obfs4" && !/^[A-Za-z0-9+/]{40,90}$/.test(kv.cert ?? "")) problems.push("obfs4-cert");
  if (transport === "obfs4" && kv["iat-mode"] !== undefined && !/^[012]$/.test(kv["iat-mode"])) problems.push("obfs4-iat");
  if (transport === "webtunnel" && !/^https?:\/\/[^/\s]+\.[^/\s]+/i.test(kv.url ?? "")) problems.push("webtunnel-url");
  if (transport === "meek_lite" && !kv.url) problems.push("meek-url");
  if (transport === "snowflake" && !(kv.url || kv.front || kv.fronts || kv.ice)) problems.push("snowflake-params");
  return problems;
}

/**
 * Repair one raw line.
 * @returns {{ok:boolean, line?:string, repaired?:boolean, reason?:string, transport?:string}}
 *  reason (when !ok): comment | blank | conjure | unsupported | not-a-bridge | charset | semantic:<why> | regex
 */
export function repairForOrbot(raw) {
  let text = normaliseSpaces(raw).replace(/\r$/, "").trim();
  if (!text) return { ok: false, reason: "blank" };
  if (text.startsWith("#") || text.startsWith("//") || text.startsWith(";")) return { ok: false, reason: "comment" };
  const original = text;
  text = text.replace(/^Bridge\s+/i, "").replace(/\s+/g, " ").trim();
  if (/^conjure\b/i.test(text)) return { ok: false, reason: "conjure" };
  if (UNSUPPORTED.test(text)) return { ok: false, reason: "unsupported" };
  const scrubbed = scrubLine(text);
  if (scrubbed.drop) return { ok: false, reason: scrubbed.drop };
  text = scrubbed.line;

  let tokens = text.split(" ");
  const first = tokens[0].toLowerCase();
  let transport = "vanilla";
  if (SUPPORTED_TRANSPORTS.includes(first)) {
    transport = first;
    tokens = tokens.slice(1);
  } else if (/^[a-z][a-z0-9_-]*$/i.test(tokens[0]) && !splitAddress(tokens[0])) {
    return { ok: false, reason: "not-a-bridge" };
  }

  // address-less "transport FP key=val ..." (snowflake / meek_lite / webtunnel in Tor's own bundles)
  if (tokens[0] && FP40.test(tokens[0]) && DUMMY_ADDRESS[transport]) {
    tokens = [DUMMY_ADDRESS[transport], ...tokens];
  } else if (tokens[0] && !splitAddress(tokens[0]) && DUMMY_ADDRESS[transport] && tokens[0].includes("=")) {
    tokens = [DUMMY_ADDRESS[transport], ...tokens]; // meek_lite url=... without fingerprint
  }
  const address = splitAddress(tokens[0]);
  if (!address) return { ok: false, reason: "not-a-bridge" };

  const head =
    address.port === null && transport !== "vanilla" && DUMMY_ADDRESS[transport]
      ? `${tokens[0]}:${DUMMY_ADDRESS[transport].split(":").pop()}`
      : tokens[0];

  const seen = new Set();
  const rest = [];
  for (let token of tokens.slice(1)) {
    if (token.includes("%")) {
      try {
        token = decodeURIComponent(token);
      } catch {
        /* keep as is -> charset check below rejects it */
      }
    }
    const eq = token.indexOf("=");
    if (eq > 0) {
      const key = token.slice(0, eq).toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
    }
    if (FP40.test(token)) token = token.toUpperCase();
    rest.push(token);
  }
  if (transport === "webtunnel" && !seen.has("ver")) {
    rest.push("ver=0.0.1");
  }
  const line = [transport === "vanilla" ? null : transport, head, ...rest].filter(Boolean).join(" ");

  if (!ORBOT_REGEX.test(line)) {
    return { ok: false, reason: /[^ \t\f\w\-/+:=.,\[\]]/.test(rest.join(" ")) ? "charset" : "regex" };
  }
  const problems = semanticProblems(line);
  if (problems.length > 0) return { ok: false, reason: `semantic:${problems[0]}`, transport };
  return { ok: true, line, transport, repaired: line !== original };
}

/** True when a repaired line dials its (documentation) address, i.e. can never connect. */
export function isDialPlaceholder(line, transport) {
  if (transport !== "obfs4" && transport !== "vanilla") return false;
  const tokens = line.split(" ");
  const address = splitAddress(transport === "vanilla" ? tokens[0] : tokens[1]);
  return Boolean(address && isDummyHost(address.host));
}

/** Convenience: repair a whole text, returning unique paste-ready lines + reasons for the rest. */
export function repairText(text, { dropDialPlaceholders = true } = {}) {
  const lines = [];
  const seen = new Set();
  const rejected = {};
  let repaired = 0;
  const count = (reason) => {
    rejected[reason] = (rejected[reason] ?? 0) + 1;
  };
  for (const raw of text.split(/\r?\n/)) {
    const result = repairForOrbot(raw);
    if (!result.ok) {
      if (result.reason !== "blank") count(result.reason);
      continue;
    }
    if (dropDialPlaceholders && isDialPlaceholder(result.line, result.transport)) {
      count("dial-placeholder");
      continue;
    }
    if (seen.has(result.line)) {
      count("duplicate");
      continue;
    }
    seen.add(result.line);
    if (result.repaired) repaired += 1;
    lines.push(result.line);
  }
  return { lines, rejected, repaired };
}
