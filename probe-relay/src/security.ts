export const MAX_REQUEST_BODY_BYTES = 64 * 1024;
export const MAX_BRIDGES_PER_REQUEST = 6;
export const MAX_HOST_BYTES = 253;

export type AllowedTransport =
  | "obfs4"
  | "webtunnel"
  | "vanilla"
  | "bridge"
  | "unknown"
  | "snowflake"
  | "meek"
  | "meek_lite"
  | "meek-azure"
  | "conjure"
  | "vless"
  | "vless+reality"
  | "shadowtls"
  | "anytls"
  | "http-upgrade"
  | "grpc";

export interface ValidatedBridge {
  id: string;
  transport: AllowedTransport;
  host: string;
  port: number;
  sni?: string;
  url?: string;
  path?: string;
  cert?: string;
  iat_mode?: string;
  fingerprint?: string;
}

export type JsonBodyResult =
  | { ok: true; value: unknown }
  | { ok: false; status: number; error: "request_timeout" | "body_too_large" | "bad_json_body" | "invalid_content_length" };

export type BridgeValidationResult =
  | { ok: true; bridges: ValidatedBridge[] }
  | { ok: false; status: 400 | 413; error: string; index?: number };

const ALLOWED_TRANSPORTS = new Set<AllowedTransport>([
  "obfs4",
  "webtunnel",
  "vanilla",
  "bridge",
  "unknown",
  "snowflake",
  "meek",
  "meek_lite",
  "meek-azure",
  "conjure",
  "vless",
  "vless+reality",
  "shadowtls",
  "anytls",
  "http-upgrade",
  "grpc",
]);

const ALLOWED_FIELDS = new Set([
  "id",
  "transport",
  "host",
  "port",
  "sni",
  "url",
  "path",
  "cert",
  "iat_mode",
  "fingerprint",
]);

class BodyReadFailure extends Error {
  constructor(readonly code: "request_timeout" | "body_too_large") {
    super(code);
  }
}

function isControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function parseCanonicalIpv4(host: string): number[] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return null;
  const parts = host.split(".").map((part) => {
    if ((part.length > 1 && part.startsWith("0")) || !/^\d{1,3}$/.test(part)) {
      return Number.NaN;
    }
    return Number(part);
  });
  if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts;
}

function ipv4IsPublic(parts: number[]): boolean {
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // shared address space
  if (a === 169 && b === 254) return false; // link local
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a === 255 && b === 255 && c === 255) return false;
  return true;
}

function parseIpv6(host: string): number[] | null {
  let value = host.toLowerCase();
  if (value.startsWith("[") && value.endsWith("]")) {
    value = value.slice(1, -1);
  }
  if (!value.includes(":" ) || value.includes("%")) return null;

  // Convert an IPv4 tail to the final two 16-bit groups.
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (tail.includes(".")) {
    const ipv4 = parseCanonicalIpv4(tail);
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    value = `${value.slice(0, lastColon + 1)}${high}:${low}`;
  }

  if ((value.match(/::/g) ?? []).length > 1) return null;
  const compressed = value.includes("::");
  const [leftText, rightText = ""] = compressed ? value.split("::") : [value, ""];
  const left = leftText ? leftText.split(":") : [];
  const right = rightText ? rightText.split(":") : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((compressed && missing < 1) || (!compressed && missing !== 0)) return null;
  const groups = [
    ...left.map((part) => Number.parseInt(part, 16)),
    ...Array(compressed ? missing : 0).fill(0),
    ...right.map((part) => Number.parseInt(part, 16)),
  ];
  return groups.length === 8 ? groups : null;
}

function isGloballyReachable2001Exception(groups: number[]): boolean {
  const second = groups[1];
  if (second === 0x0001) {
    // IANA assigns only these three individual anycast addresses as globally
    // reachable within 2001:1::/32; the rest of the parent /23 is not global.
    return groups.slice(2, 7).every((group) => group === 0) && [1, 2, 3].includes(groups[7]);
  }
  if (second === 0x0003) return true; // 2001:3::/32 AMT
  if (second === 0x0004 && groups[2] === 0x0112) return true; // 2001:4:112::/48 AS112-v6
  if (second >= 0x0020 && second <= 0x002f) return true; // 2001:20::/28 ORCHIDv2
  if (second >= 0x0030 && second <= 0x003f) return true; // 2001:30::/28 Drone Remote ID
  return false;
}

function ipv6IsPublic(groups: number[]): boolean {
  const first = groups[0];
  const second = groups[1];

  // IPv4-mapped addresses are a special-purpose block, not a public IPv6
  // destination, even when the embedded IPv4 address itself is globally routable.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) return false;

  // Permit global-unicast 2000::/3 only, excluding IANA special-purpose
  // blocks that are non-global, documentation, or transition mechanisms.
  if (first < 0x2000 || first > 0x3fff) return false;
  if (first === 0x2001 && second < 0x0200 && !isGloballyReachable2001Exception(groups)) return false;
  if (first === 0x2001 && second === 0x0db8) return false; // documentation 2001:db8::/32
  if (first === 0x2002) return false; // 6to4
  if (first === 0x3fff && second <= 0x0fff) return false; // documentation /20
  return true;
}

function isNumericAddressLike(host: string): boolean {
  return /^[0-9.]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host);
}

export function normalizeAndValidatePublicHost(input: unknown): string | null {
  if (typeof input !== "string" || input.length === 0 || input.length > MAX_HOST_BYTES + 2) return null;
  if (input !== input.trim() || isControlCharacter(input) || /[\\/@?#\s]/.test(input)) return null;

  const bracketed = input.startsWith("[") || input.endsWith("]");
  if (bracketed && !(input.startsWith("[") && input.endsWith("]"))) return null;
  const host = bracketed ? input.slice(1, -1) : input;
  if (!host || host.length > MAX_HOST_BYTES) return null;

  if (host.includes(":")) {
    const groups = parseIpv6(host);
    return groups && ipv6IsPublic(groups) ? (bracketed ? `[${host.toLowerCase()}]` : host.toLowerCase()) : null;
  }

  const ipv4 = parseCanonicalIpv4(host);
  if (ipv4) return ipv4IsPublic(ipv4) ? host : null;
  if (isNumericAddressLike(host)) return null;

  const normalized = host.toLowerCase().replace(/\.$/, "");
  if (normalized.length > MAX_HOST_BYTES || !normalized.includes(".")) return null;
  const labels = normalized.split(".");
  if (labels.some((label) =>
    label.length === 0 || label.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  )) return null;

  const blockedSuffixes = [
    ".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa",
    ".test", ".invalid", ".example", ".onion", ".arpa",
  ];
  if (normalized === "localhost" || blockedSuffixes.some((suffix) => normalized.endsWith(suffix))) return null;
  return normalized;
}

function validateOptionalString(
  object: Record<string, unknown>,
  key: string,
  maxLength: number,
): { ok: true; value?: string } | { ok: false } {
  if (!Object.prototype.hasOwnProperty.call(object, key)) return { ok: true };
  const value = object[key];
  if (typeof value !== "string" || value.length > maxLength || isControlCharacter(value)) return { ok: false };
  return { ok: true, value };
}

function validateDescriptor(value: unknown, index: number):
  | { ok: true; bridge: ValidatedBridge }
  | { ok: false; error: string; index: number } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, error: "descriptor_must_be_object", index };
  }
  const object = value as Record<string, unknown>;
  if (Object.keys(object).some((key) => !ALLOWED_FIELDS.has(key))) {
    return { ok: false, error: "unknown_descriptor_field", index };
  }

  const host = normalizeAndValidatePublicHost(object.host);
  if (!host) return { ok: false, error: "invalid_or_non_public_host", index };
  if (!Number.isInteger(object.port) || (object.port as number) < 1 || (object.port as number) > 65535) {
    return { ok: false, error: "invalid_port", index };
  }
  if (typeof object.transport !== "string" || object.transport.length > 40) {
    return { ok: false, error: "invalid_transport", index };
  }
  const transport = object.transport.toLowerCase() as AllowedTransport;
  if (!ALLOWED_TRANSPORTS.has(transport)) return { ok: false, error: "unsupported_transport", index };

  let id: string;
  if (Object.prototype.hasOwnProperty.call(object, "id")) {
    if (typeof object.id !== "string" || object.id.length === 0 || object.id.length > 128 || isControlCharacter(object.id)) {
      return { ok: false, error: "invalid_id", index };
    }
    id = object.id;
  } else {
    id = `${transport}-${host}-${object.port}`;
  }

  let sni: string | undefined;
  if (Object.prototype.hasOwnProperty.call(object, "sni")) {
    sni = normalizeAndValidatePublicHost(object.sni) ?? undefined;
    if (!sni) return { ok: false, error: "invalid_or_non_public_sni", index };
  }

  const path = validateOptionalString(object, "path", 2048);
  if (!path.ok || (path.value !== undefined && (
    !path.value.startsWith("/") || path.value.startsWith("//") ||
    path.value.includes("\\") || path.value.includes("#")
  ))) return { ok: false, error: "invalid_path", index };

  const cert = validateOptionalString(object, "cert", 2048);
  const iatMode = validateOptionalString(object, "iat_mode", 64);
  const fingerprint = validateOptionalString(object, "fingerprint", 128);
  const url = validateOptionalString(object, "url", 2048);
  if (!cert.ok) return { ok: false, error: "invalid_cert", index };
  if (!iatMode.ok) return { ok: false, error: "invalid_iat_mode", index };
  if (!fingerprint.ok) return { ok: false, error: "invalid_fingerprint", index };
  if (!url.ok) return { ok: false, error: "invalid_url", index };
  if (url.value !== undefined) {
    try {
      const parsed = new URL(url.value);
      if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
          !normalizeAndValidatePublicHost(parsed.hostname)) {
        return { ok: false, error: "invalid_url", index };
      }
    } catch {
      return { ok: false, error: "invalid_url", index };
    }
  }

  return {
    ok: true,
    bridge: {
      id,
      transport,
      host,
      port: object.port as number,
      ...(sni ? { sni } : {}),
      ...(url.value !== undefined ? { url: url.value } : {}),
      ...(path.value !== undefined ? { path: path.value } : {}),
      ...(cert.value !== undefined ? { cert: cert.value } : {}),
      ...(iatMode.value !== undefined ? { iat_mode: iatMode.value } : {}),
      ...(fingerprint.value !== undefined ? { fingerprint: fingerprint.value } : {}),
    },
  };
}

export async function readJsonRequestBody(
  request: Request,
  maxBytes = MAX_REQUEST_BODY_BYTES,
  timeoutMs = 5_000,
): Promise<JsonBodyResult> {
  const cancelBody = (): void => {
    try { void request.body?.cancel().catch(() => {}); } catch { /* already consumed or canceled */ }
  };
  const lengthHeader = request.headers.get("content-length");
  if (lengthHeader !== null) {
    if (!/^\d+$/.test(lengthHeader)) {
      cancelBody();
      return { ok: false, status: 400, error: "invalid_content_length" };
    }
    const declaredLength = Number(lengthHeader);
    if (!Number.isSafeInteger(declaredLength)) {
      cancelBody();
      return { ok: false, status: 400, error: "invalid_content_length" };
    }
    if (declaredLength > maxBytes) {
      cancelBody();
      return { ok: false, status: 413, error: "body_too_large" };
    }
  }

  if (!request.body) return { ok: false, status: 400, error: "bad_json_body" };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  const deadline = Date.now() + timeoutMs;

  try {
    for (;;) {
      if (request.signal.aborted) throw new BodyReadFailure("request_timeout");
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new BodyReadFailure("request_timeout");

      const read = reader.read();
      const result = await new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
        const timer = setTimeout(() => {
          cleanup();
          reject(new BodyReadFailure("request_timeout"));
        }, remaining);
        const onAbort = () => {
          cleanup();
          reject(new BodyReadFailure("request_timeout"));
        };
        const cleanup = () => {
          clearTimeout(timer);
          request.signal.removeEventListener("abort", onAbort);
        };
        request.signal.addEventListener("abort", onAbort, { once: true });
        read.then((value) => {
          cleanup();
          resolve(value);
        }, (error: unknown) => {
          cleanup();
          reject(error);
        });
      });

      if (result.done) break;
      totalBytes += result.value.byteLength;
      if (totalBytes > maxBytes) throw new BodyReadFailure("body_too_large");
      chunks.push(result.value);
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (error) {
    // Do not await a hostile stream's cancel algorithm: a stalled body must
    // not defeat the read deadline while cleanup is in progress.
    try { void reader.cancel(error).catch(() => {}); } catch { /* stream already canceled/closed */ }
    if (error instanceof BodyReadFailure) {
      return { ok: false, status: error.code === "body_too_large" ? 413 : 408, error: error.code };
    }
    return { ok: false, status: 400, error: "bad_json_body" };
  } finally {
    try { reader.releaseLock(); } catch { /* reader already released */ }
  }
}

export function validateBridgeList(value: unknown, maxBridges = MAX_BRIDGES_PER_REQUEST): BridgeValidationResult {
  if (!Array.isArray(value) || value.length === 0) {
    return { ok: false, status: 400, error: "bridge_array_required" };
  }
  if (value.length > maxBridges) {
    return { ok: false, status: 413, error: "too_many_bridges" };
  }

  const bridges: ValidatedBridge[] = [];
  for (let index = 0; index < value.length; index++) {
    const checked = validateDescriptor(value[index], index);
    if (!checked.ok) return { ok: false, status: 400, error: checked.error, index: checked.index };
    bridges.push(checked.bridge);
  }
  return { ok: true, bridges };
}

/** Compare token bytes without returning early when a content byte differs. */
export function constantTimeTokenEqual(actual: string | null, expected: string): boolean {
  const encoder = new TextEncoder();
  const actualBytes = encoder.encode(actual ?? "");
  const expectedBytes = encoder.encode(expected);
  const length = Math.max(actualBytes.length, expectedBytes.length);
  let difference = actualBytes.length ^ expectedBytes.length;
  for (let index = 0; index < length; index++) {
    difference |= (actualBytes[index] ?? 0) ^ (expectedBytes[index] ?? 0);
  }
  return difference === 0;
}

export function configuredInteger(
  raw: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number | null {
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum ? value : null;
}
