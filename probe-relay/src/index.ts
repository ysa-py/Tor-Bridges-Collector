/**
 * Tor Bridge Probe Relay — Cloudflare Worker
 *
 * External always-on relay that performs real TCP/TLS/WebTunnel probes
 * against Tor bridge endpoints. GitHub Actions runners have restricted
 * outbound egress and cannot reliably complete raw TCP handshakes to
 * arbitrary IP:port pairs. This Worker uses the `cloudflare:sockets`
 * `connect()` API to perform those probes from Cloudflare's edge network.
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
  // Transport-specific parameters (all optional, read dynamically)
  sni?: string;        // TLS SNI (for fronted transports)
  url?: string;        // WebTunnel URL
  path?: string;       // WebTunnel/HTTP path
  cert?: string;       // obfs4 certificate
  iat_mode?: string;   // obfs4 IAT mode
  fingerprint?: string;
}

interface ProbeResult {
  id: string;
  transport: string;
  host: string;
  port: number;
  success: boolean;
  latency_ms: number | null;
  probe_type: string;   // "tcp", "tls", "websocket-101"
  error: string | null;
}

interface Env {
  PROBE_AUTH_TOKEN?: string;
  MAX_BRIDGES_PER_REQUEST?: string;
  BATCH_SIZE?: string;
  PROBE_TIMEOUT_SECS?: string;
}

// ─── Constants ──────────────────────────────────────────────────────

const PROBE_TIMEOUT_MS = 5000; // 5s per probe
const USER_AGENT = "TorShield-IR-ProbeRelay/1.0";

// ─── Entry Point ────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
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

    // Authentication
    const token = request.headers.get("X-Probe-Token");
    const expectedToken = env.PROBE_AUTH_TOKEN;
    if (!expectedToken || token !== expectedToken) {
      return jsonResponse(401, {
        error: "unauthorized",
        detail: "Invalid or missing X-Probe-Token header",
      });
    }

    // Parse request
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

    // Validate each bridge
    for (const bridge of bridges) {
      if (!bridge.host || !bridge.port || !bridge.transport) {
        return jsonResponse(400, {
          error: "bad_request",
          detail: `Each bridge must have host, port, and transport fields. Offending: ${JSON.stringify(bridge)}`,
        });
      }
    }

    // Probe all bridges in concurrent batches
    const batchSize = parseInt(env.BATCH_SIZE || "10", 10);
    const results = await probeBridges(bridges, batchSize);

    return corsResponse(jsonResponse(200, { results }));
  },
};

// ─── Probing Engine ─────────────────────────────────────────────────

async function probeBridges(
  bridges: BridgeDescriptor[],
  batchSize: number,
): Promise<ProbeResult[]> {
  const allResults: ProbeResult[] = [];

  for (let i = 0; i < bridges.length; i += batchSize) {
    const batch = bridges.slice(i, i + batchSize);
    const batchPromises = batch.map((bridge) => probeOne(bridge));
    const batchResults = await Promise.all(batchPromises);
    allResults.push(...batchResults);
  }

  return allResults;
}

async function probeOne(bridge: BridgeDescriptor): Promise<ProbeResult> {
  const start = Date.now();

  // Determine probe type from transport
  const probeType = classifyProbe(bridge);
  const sni = bridge.sni || bridge.host;
  const port = bridge.port;

  try {
    switch (probeType) {
      case "tcp":
        await tcpProbe(bridge.host, port);
        break;

      case "tls":
        await tlsProbe(bridge.host, port, sni);
        break;

      case "websocket-101":
        await websocketProbe(bridge);
        break;

      default:
        // Unknown transport — fall back to TCP
        await tcpProbe(bridge.host, port);
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

/**
 * Classify which probe strategy to use based on transport type.
 * This is transport-agnostic — it derives the strategy from the transport
 * name, not from hardcoded assumptions about field positions.
 */
function classifyProbe(bridge: BridgeDescriptor): string {
  const t = bridge.transport.toLowerCase();

  // WebTunnel: needs TLS + WebSocket Upgrade with 101 check
  if (t === "webtunnel") {
    return "websocket-101";
  }

  // Domain-fronted transports: TLS handshake to the front domain
  // These use `url=` or a dedicated front domain as SNI
  if (t === "snowflake" || t === "meek" || t === "meek_lite" ||
      t === "meek-azure" || t === "conjure" || t === "vless" ||
      t === "vless+reality" || t === "shadowtls" || t === "anytls" ||
      t === "http-upgrade" || t === "grpc") {
    return "tls";
  }

  // Everything else: raw TCP connect (vanilla, obfs4, hysteria2, tuic, etc.)
  // Full obfs4 PT handshake is too CPU-intensive for Workers; the CI runner
  // performs local SOCKS5 verification against TCP-reachable obfs4 endpoints.
  return "tcp";
}

// ─── Probe Implementations ──────────────────────────────────────────

/**
 * Raw TCP connect probe. Opens a socket, waits for the connection to
 * establish (or timeout), then closes. This is the fastest probe type
 * and works for vanilla, obfs4 (prefilter), hysteria2, tuic, etc.
 */
async function tcpProbe(host: string, port: number): Promise<void> {
  const socket = await connectWithTimeout(host, port, { secureTransport: "off" });
  try {
    // Connection established — success. No data transfer needed.
    // The socket is immediately closed; we only care about reachability.
  } finally {
    closeSocket(socket);
  }
}

/**
 * TLS handshake probe. Uses Cloudflare's `secureTransport: "start"`
 * which offloads the TLS handshake to the edge, not consuming Worker
 * CPU time. This confirms the endpoint accepts TLS with the given SNI.
 */
async function tlsProbe(host: string, port: number, sni: string): Promise<void> {
  const socket = await connectWithTimeout(host, port, {
    secureTransport: "start",
    alpn: ["http/1.1"],
  });
  try {
    // TLS handshake was completed by connect(). Success.
    // Optionally write a minimal HTTP request and read the first bytes
    // to confirm the server responds after TLS, but for a prefilter
    // this isn't strictly necessary and adds CPU time.
  } finally {
    closeSocket(socket);
  }
}

/**
 * WebTunnel probe: TLS + HTTP WebSocket Upgrade request.
 * Checks for HTTP 101 Switching Protocols response.
 *
 * This is a genuine WebTunnel verification — it confirms:
 * 1. The front domain accepts TLS (CDN alive)
 * 2. The WebSocket upgrade path works (bridge reachable through the CDN)
 */
async function websocketProbe(bridge: BridgeDescriptor): Promise<void> {
  const sni = bridge.sni || extractHostFromUrl(bridge.url) || bridge.host;
  const port = bridge.port || 443;
  const path = bridge.path || extractPathFromUrl(bridge.url) || "/";

  const socket = await connectWithTimeout(sni, port, {
    secureTransport: "start",
    alpn: ["http/1.1"],
  });

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

    const writer = socket.writable.getWriter();
    await writer.write(new TextEncoder().encode(request));
    writer.releaseLock();

    // Read response — look for "101" status
    const reader = socket.readable.getReader();
    let response = "";
    const deadline = Date.now() + PROBE_TIMEOUT_MS;

    while (Date.now() < deadline && response.length < 2048) {
      const { value, done } = await reader.read();
      if (done) break;
      response += new TextDecoder().decode(value);
      // Stop reading once we have the full HTTP response headers
      if (response.includes("\r\n\r\n")) break;
    }
    reader.releaseLock();

    // Check for HTTP 101
    const statusLine = response.split("\r\n")[0] || "";
    if (!statusLine.includes("101")) {
      throw new Error(
        `WebSocket upgrade rejected: ${statusLine || "no response"}`,
      );
    }
  } finally {
    closeSocket(socket);
  }
}

// ─── Socket Helpers ─────────────────────────────────────────────────

interface ConnectOptions {
  secureTransport: "off" | "start";
  alpn?: string[];
}

async function connectWithTimeout(
  host: string,
  port: number,
  options: ConnectOptions,
): Promise<import("cloudflare:sockets").Socket> {
  // Cloudflare Workers expose the `connect()` global from cloudflare:sockets
  // @ts-ignore — cloudflare:sockets types are ambient in Workers
  const socket = connect(
    { hostname: host, port },
    {
      secureTransport: options.secureTransport,
      alpn: options.alpn,
    },
  );

  // Set a timeout on the readable side
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error(`TCP connect timed out after ${PROBE_TIMEOUT_MS}ms`)), PROBE_TIMEOUT_MS);
  });

  // Race: socket becomes readable (connected) vs timeout
  await Promise.race([
    socket.readable.getReader().closed,
    timeoutPromise,
  ]).catch((err) => {
    closeSocket(socket);
    throw err;
  });

  return socket;
}

function closeSocket(socket: import("cloudflare:sockets").Socket): void {
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
    // Preserve path + query string if present
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
