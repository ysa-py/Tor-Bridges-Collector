// @ts-ignore — cloudflare:sockets is an ambient Workers runtime module
import { connect } from "cloudflare:sockets";

// Local socket interface matching cloudflare:sockets Socket at runtime.
// Avoids import() type resolution issues in local tsc while preserving
// full type safety under wrangler's bundled Workers type-check.
interface WorkersSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): void;
}

/**
 * Tor Bridge Probe Relay — Cloudflare Worker (v2 — concurrency-safe)
 *
 * External always-on relay that performs real TCP/TLS/WebTunnel probes
 * against Tor bridge endpoints. GitHub Actions runners have restricted
 * outbound egress and cannot reliably complete raw TCP handshakes to
 * arbitrary IP:port pairs. This Worker uses the `cloudflare:sockets`
 * `connect()` API to perform those probes from Cloudflare's edge network.
 *
 * v2 CHANGES (2026-08-10):
 *   - Concurrency-limited probe queue (MAX_CONCURRENT_PROBES, default 5)
 *     replaces flat Promise.all — prevents Cloudflare's "stalled HTTP
 *     response was canceled" warnings caused by unreleased reader locks
 *     stacking up.
 *   - Every connect() response body is always consumed or explicitly
 *     released via the safeConnect() wrapper — the reader lock bug that
 *     caused silent probe cancellations is eliminated.
 *   - Per-probe AbortController timeout so a hung probe can never hold a
 *     concurrency slot indefinitely.
 *   - Structured per-chunk summary log: probes attempted, completed,
 *     timed-out/canceled, errored — visible in Cloudflare Observability
 *     and CI wrangler tail.
 *
 * Endpoint: POST /probe
 *   Auth:    X-Probe-Token header (shared secret)
 *   Body:    JSON array of bridge descriptors
 *   Returns: JSON array of probe results
 *
 * Free tier constraints:
 *   - 100,000 requests/day
 *   - 10ms CPU time per invocation (idle I/O wait does NOT count)
 *   - 50 subrequests (outbound sockets) per invocation
 *   - 30s wall-clock timeout
 *
 * Probe capabilities (per transport):
 *   - vanilla, obfs4 (prefilter): raw TCP connect
 *   - snowflake, meek, conjure, fronted: TLS handshake (offloaded)
 *   - webtunnel: TLS + HTTP WebSocket Upgrade (checks for 101)
 */

// ─── Types ──────────────────────────────────────────────────────────

interface BridgeDescriptor {
  id: string;
  transport: string;
  host: string;
  port: number;
  sni?: string;
  url?: string;
  path?: string;
  cert?: string;
  iat_mode?: string;
  fingerprint?: string;
}

interface ProbeResult {
  id: string;
  transport: string;
  host: string;
  port: number;
  success: boolean;
  latency_ms: number | null;
  probe_type: string;
  error: string | null;
}

interface Env {
  PROBE_RELAY_TOKEN?: string;
  MAX_BRIDGES_PER_REQUEST?: string;
  MAX_CONCURRENT_PROBES?: string;
  PROBE_TIMEOUT_SECS?: string;
}

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_PROBE_TIMEOUT_MS = 5000;
const DEFAULT_MAX_CONCURRENT_PROBES = 5;
const USER_AGENT = "TorShield-IR-ProbeRelay/2.0";

// ─── Entry Point ────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return corsResponse(new Response(null, { status: 204 }));
    }

    if (request.method !== "POST") {
      return jsonResponse(405, {
        error: "method_not_allowed",
        detail: "Only POST /probe is supported",
      });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/probe") {
      return jsonResponse(404, {
        error: "not_found",
        detail: "Only /probe endpoint exists",
      });
    }

    // Auth
    const token = request.headers.get("X-Probe-Token");
    const expectedToken = env.PROBE_RELAY_TOKEN;
    if (expectedToken && token !== expectedToken) {
      return jsonResponse(401, {
        error: "unauthorized",
        detail: "Invalid or missing X-Probe-Token header",
      });
    }

    // Parse body
    let bridges: BridgeDescriptor[];
    try {
      bridges = await request.json() as BridgeDescriptor[];
    } catch {
      return jsonResponse(400, {
        error: "bad_request",
        detail: "Request body must be a JSON array of bridge descriptors",
      });
    }

    if (!Array.isArray(bridges) || bridges.length === 0) {
      return jsonResponse(400, {
        error: "bad_request",
        detail: "Request body must be a non-empty JSON array",
      });
    }

    const maxBridges = parseInt(env.MAX_BRIDGES_PER_REQUEST || "50", 10);
    if (bridges.length > maxBridges) {
      return jsonResponse(413, {
        error: "too_many_bridges",
        detail: `Maximum ${maxBridges} bridges per request; got ${bridges.length}. Split into smaller chunks.`,
      });
    }

    // Validate schema
    for (const bridge of bridges) {
      if (!bridge.host || !bridge.port || !bridge.transport) {
        return jsonResponse(400, {
          error: "bad_request",
          detail: `Each bridge must have host, port, and transport fields. Offending: ${JSON.stringify(bridge)}`,
        });
      }
    }

    const maxConcurrent = parseInt(
      env.MAX_CONCURRENT_PROBES || String(DEFAULT_MAX_CONCURRENT_PROBES),
      10,
    );
    const probeTimeoutMs = parseInt(
      env.PROBE_TIMEOUT_SECS || String(DEFAULT_PROBE_TIMEOUT_MS / 1000),
      10,
    ) * 1000;

    console.log(
      `[probe-relay] batch_start bridges=${bridges.length} max_concurrent=${maxConcurrent} timeout_ms=${probeTimeoutMs}`,
    );

    const { results, stats } = await probeBridgesWithConcurrency(
      bridges,
      maxConcurrent,
      probeTimeoutMs,
    );

    console.log(
      `[probe-relay] batch_done attempted=${stats.attempted} completed=${stats.completed} ` +
        `timed_out=${stats.timedOut} errored=${stats.errored} success=${stats.success}`,
    );

    return corsResponse(jsonResponse(200, { results, stats }));
  },
};

// ─── Concurrency-Limited Probing Engine ─────────────────────────────

interface ProbeStats {
  attempted: number;
  completed: number;
  timedOut: number;
  errored: number;
  success: number;
}

// Exported for unit testing — not part of the Worker's public API.
export async function probeBridgesWithConcurrency(
  bridges: BridgeDescriptor[],
  maxConcurrent: number,
  timeoutMs: number,
): Promise<{ results: ProbeResult[]; stats: ProbeStats }> {
  const results: ProbeResult[] = new Array(bridges.length);
  const stats: ProbeStats = {
    attempted: bridges.length,
    completed: 0,
    timedOut: 0,
    errored: 0,
    success: 0,
  };

  let nextIndex = 0;

  // Worker function that pulls the next bridge from the queue
  async function worker(): Promise<void> {
    while (nextIndex < bridges.length) {
      const idx = nextIndex++;
      if (idx >= bridges.length) break;

      const bridge = bridges[idx];
      stats.attempted = Math.max(stats.attempted, idx + 1);

      try {
        const result = await probeOneWithTimeout(bridge, timeoutMs);
        results[idx] = result;
        stats.completed++;
        if (result.success) stats.success++;
      } catch (err) {
        const isTimeout =
          err instanceof Error &&
          (err.message.includes("timed out") || err.name === "TimeoutError");
        if (isTimeout) {
          stats.timedOut++;
        } else {
          stats.errored++;
        }
        results[idx] = {
          id: bridge.id,
          transport: bridge.transport,
          host: bridge.host,
          port: bridge.port,
          success: false,
          latency_ms: null,
          probe_type: classifyProbe(bridge),
          error: isTimeout ? "probe_timeout" : (err instanceof Error ? err.message : String(err)),
        };
      }
    }
  }

  // Launch maxConcurrent workers
  const workerCount = Math.min(maxConcurrent, bridges.length);
  const workers: Promise<void>[] = [];
  for (let i = 0; i < workerCount; i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  return { results, stats };
}

// ─── Timeout-Wrapped Probe ──────────────────────────────────────────

// Exported for unit testing.
export async function probeOneWithTimeout(
  bridge: BridgeDescriptor,
  timeoutMs: number,
): Promise<ProbeResult> {
  // Race the probe against a timeout using a simple setTimeout pattern.
  // This avoids AbortController event-listener promise patterns that
  // can produce unhandled rejections in test environments.
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const timeoutPromise = new Promise<ProbeResult>((resolve) => {
    timeoutId = setTimeout(() => {
      resolve({
        id: bridge.id,
        transport: bridge.transport,
        host: bridge.host,
        port: bridge.port,
        success: false,
        latency_ms: null,
        probe_type: classifyProbe(bridge),
        error: `probe timed out after ${timeoutMs}ms`,
      });
    }, timeoutMs);
  });

  try {
    const result = await Promise.race([
      probeOne(bridge),
      timeoutPromise,
    ]);
    return result;
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  }
}

// ─── Per-Bridge Probe ───────────────────────────────────────────────

async function probeOne(bridge: BridgeDescriptor): Promise<ProbeResult> {
  const start = Date.now();
  const probeType = classifyProbe(bridge);
  const sni = bridge.sni || bridge.host;
  const port = bridge.port;

  try {
    switch (probeType) {
      case "tcp":
        await safeTcpProbe(bridge.host, port);
        break;

      case "tls":
        await safeTlsProbe(bridge.host, port, sni);
        break;

      case "websocket-101":
        await safeWebsocketProbe(bridge);
        break;

      default:
        await safeTcpProbe(bridge.host, port);
    }

    const latencyMs = Date.now() - start;
    return {
      id: bridge.id,
      transport: bridge.transport,
      host: bridge.host,
      port: bridge.port,
      success: true,
      latency_ms: latencyMs,
      probe_type: probeType,
      error: null,
    };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      id: bridge.id,
      transport: bridge.transport,
      host: bridge.host,
      port: bridge.port,
      success: false,
      latency_ms: latencyMs,
      probe_type: probeType,
      error: errorMsg,
    };
  }
}

// Exported for unit testing.
export function classifyProbe(bridge: BridgeDescriptor): string {
  const t = bridge.transport.toLowerCase();

  if (t === "webtunnel") {
    return "websocket-101";
  }

  if (
    t === "snowflake" ||
    t === "meek" ||
    t === "meek_lite" ||
    t === "meek-azure" ||
    t === "conjure" ||
    t === "vless" ||
    t === "vless+reality" ||
    t === "shadowtls" ||
    t === "anytls" ||
    t === "http-upgrade" ||
    t === "grpc"
  ) {
    return "tls";
  }

  return "tcp";
}

// ─── Safe Probe Implementations (reader-lock-safe) ──────────────────
//
// CRITICAL: Cloudflare's Workers runtime enforces a limit on concurrent
// in-flight connect()/fetch() calls with unread response bodies. If a
// readable stream's reader lock is acquired (via getReader()) but never
// released, the runtime interprets this as a "stalled response" and
// force-cancels it — producing the "A stalled HTTP response was canceled
// to prevent deadlock" warning and silently dropping probe results.
//
// Every probe implementation below uses a try/finally pattern that
// guarantees the reader lock is always released, including in error and
// timeout paths. The safeConnect() wrapper is the single entry point for
// all socket connections — no code anywhere else in this file calls
// connect() directly.

interface ConnectOptions {
  secureTransport: "off" | "start";
  alpn?: string[];
}

/**
 * Safe connect wrapper. Guarantees the reader lock is always released
 * before the function returns, regardless of success/failure/timeout.
 * This is the ONLY function in the file that calls connect() directly.
 */
async function safeConnect(
  host: string,
  port: number,
  options: ConnectOptions,
  timeoutMs: number,
): Promise<WorkersSocket> {
  // @ts-ignore — cloudflare:sockets types are ambient in Workers
  const socket = connect(
    { hostname: host, port },
    {
      secureTransport: options.secureTransport,
      alpn: options.alpn,
    } as any,
  );

  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  try {
    // Acquire reader to detect connection establishment.
    // The `.closed` promise resolves when the connection succeeds or
    // the remote closes. We MUST release the lock after the race.
    reader = socket.readable.getReader();

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new Error(`TCP connect timed out after ${timeoutMs}ms`)),
        timeoutMs,
      );
    });

    await Promise.race([reader.closed, timeoutPromise]);
  } catch (err) {
    closeSocket(socket);
    throw err;
  } finally {
    // ALWAYS release the reader lock — this is the fix for the
    // "stalled HTTP response was canceled" bug.
    if (reader) {
      try {
        reader.releaseLock();
      } catch {
        // Best-effort; reader may already be released or stream closed
      }
    }
  }

  return socket;
}

async function safeTcpProbe(host: string, port: number): Promise<void> {
  const socket = await safeConnect(host, port, { secureTransport: "off" }, DEFAULT_PROBE_TIMEOUT_MS);
  // Connection established — success. Explicitly consume any pending data
  // then close to ensure the runtime sees a fully-consumed response.
  await drainAndClose(socket);
}

async function safeTlsProbe(host: string, port: number, sni: string): Promise<void> {
  const socket = await safeConnect(
    host,
    port,
    { secureTransport: "start", alpn: ["http/1.1"] },
    DEFAULT_PROBE_TIMEOUT_MS,
  );
  // TLS handshake completed by connect(). Consume any server greeting
  // data then close.
  await drainAndClose(socket);
}

async function safeWebsocketProbe(bridge: BridgeDescriptor): Promise<void> {
  const sni = bridge.sni || extractHostFromUrl(bridge.url) || bridge.host;
  const port = bridge.port || 443;
  const path = bridge.path || extractPathFromUrl(bridge.url) || "/";

  const socket = await safeConnect(
    sni,
    port,
    { secureTransport: "start", alpn: ["http/1.1"] },
    DEFAULT_PROBE_TIMEOUT_MS,
  );

  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  try {
    // Build WebSocket upgrade request
    const wsKey = generateWebSocketKey();
    const request = [
      `GET ${path} HTTP/1.1`,
      `Host: ${sni}`,
      `User-Agent: ${USER_AGENT}`,
      `Connection: Upgrade`,
      `Upgrade: websocket`,
      `Sec-WebSocket-Key: ${wsKey}`,
      `Sec-WebSocket-Version: 13`,
      "",
      "",
    ].join("\r\n");

    writer = socket.writable.getWriter();
    await writer.write(new TextEncoder().encode(request));

    // Read response — look for "101" status
    reader = socket.readable.getReader();
    let response = "";
    const deadline = Date.now() + DEFAULT_PROBE_TIMEOUT_MS;

    while (Date.now() < deadline && response.length < 2048) {
      const { value, done } = await reader.read();
      if (done) break;
      response += new TextDecoder().decode(value);
      if (response.includes("\r\n\r\n")) break;
    }

    const statusLine = response.split("\r\n")[0] || "";
    if (!statusLine.includes("101")) {
      throw new Error(
        `WebSocket upgrade rejected: ${statusLine || "no response"}`,
      );
    }
  } finally {
    // Always release writer and reader locks, then close the socket.
    // This guarantees no dangling locks regardless of which code path
    // (success, error, timeout) triggers the cleanup.
    const w = writer;
    const r = reader;
    if (w) {
      try { w.releaseLock(); } catch { /* best-effort */ }
    }
    if (r) {
      try { r.releaseLock(); } catch { /* best-effort */ }
    }
    closeSocket(socket);
  }
}

// ─── Drain-and-Close Helper ─────────────────────────────────────────
//
// Drains any pending data from the socket's readable side, then closes
// the socket. This tells the Workers runtime that the response body has
// been fully consumed — preventing "stalled response canceled" warnings.

async function drainAndClose(
  socket: WorkersSocket,
): Promise<void> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  try {
    reader = socket.readable.getReader();
    // Read up to 4KB of any greeting data the server might have sent.
    // We don't care about the content — we just need to consume the
    // readable stream so Cloudflare doesn't flag it as unread.
    const deadline = Date.now() + 1000; // 1s drain budget
    let drained = 0;
    while (Date.now() < deadline && drained < 4096) {
      const { done } = await reader.read();
      if (done) break;
      drained += 1; // approximate
    }
  } catch {
    // Socket already closed or errored — nothing to drain
  } finally {
    if (reader) {
      try { reader.releaseLock(); } catch { /* best-effort */ }
    }
    closeSocket(socket);
  }
}

// ─── Socket Helpers ─────────────────────────────────────────────────

function closeSocket(socket: WorkersSocket): void {
  try {
    socket.close();
  } catch {
    // Best-effort close — socket may already be closed
  }
}

// ─── URL Helpers ────────────────────────────────────────────────────

function extractHostFromUrl(urlStr: string | undefined): string | null {
  if (!urlStr) return null;
  try {
    return new URL(urlStr).hostname;
  } catch {
    return null;
  }
}

function extractPathFromUrl(urlStr: string | undefined): string | null {
  if (!urlStr) return null;
  try {
    const u = new URL(urlStr);
    return u.pathname + u.search || "/";
  } catch {
    return null;
  }
}

function generateWebSocketKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

// ─── HTTP Helpers ───────────────────────────────────────────────────

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Probe-Token",
    },
  });
}

function corsResponse(response: Response): Response {
  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, X-Probe-Token");
  return response;
}
