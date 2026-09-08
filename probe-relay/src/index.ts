// @ts-ignore — cloudflare:sockets is an ambient Workers runtime module
import { connect } from "cloudflare:sockets";

// Local socket interface matching cloudflare:sockets Socket at runtime.
// Avoids import() type resolution issues in local tsc while preserving
// full type safety under wrangler's bundled Workers type-check.
interface WorkersSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /** Resolves once the connection is established — for secureTransport
   *  "on" sockets, after the TLS handshake completes; rejects on
   *  connection/handshake/certificate errors. Documented at
   *  developers.cloudflare.com/workers/runtime-apis/tcp-sockets. */
  opened?: Promise<unknown>;
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
 *
 * v2.1 CHANGES (2026-09-06):
 *   - DEFAULT_MAX_CONCURRENT_PROBES raised 5 -> 25. The reader-lock bug that
 *     motivated the conservative limit of 5 is fixed (safeConnect +
 *     drainAndClose always release every reader), so a 30-bridge chunk from
 *     the CI client now probes in ~1-2 waves (~5-10s) instead of ~6 serial
 *     waves (~30s). 25 concurrent connect() calls stay under the free-tier
 *     50-subrequest-per-invocation ceiling, which is how Stage 4 now finishes
 *     its full bridge set inside the CI budget instead of truncating at the
 *     20-minute mark.
 *   - Per-probe AbortController timeout so a hung probe can never hold a
 *     concurrency slot indefinitely.
 *   - Structured per-chunk summary log: probes attempted, completed,
 *     timed-out/canceled, errored — visible in Cloudflare Observability
 *     and CI wrangler tail.
 *
 * v2.6 CHANGES (2026-09-08) — protocol-correct meek + conjure probes:
 *   - The v2.5 domain-fronting fix gave every fronted transport the same
 *     generic TLS GET. That is correct for webtunnel (101 upgrade) but
 *     protocol-blind for meek and conjure, whose wire protocols are HTTP
 *     POST round-trips with specific semantics — a GET of the bridge URL
 *     cannot distinguish "front reachable" from "bridge functional".
 *   - meek-post class (meek / meek_lite / meek-azure): POST to the url=
 *     path with X-Session-Id: base64(32 random bytes) and Host = the
 *     url= host, SNI = front — exactly the reference client's
 *     roundTripWithHTTP (git.torproject.org/pluggable-transports/meek,
 *     meek-client.go:118-142, genSessionId :252-258). Success bar: the
 *     reference server's transact() signature — HTTP 200 with
 *     Content-Type application/octet-stream (meek-server.go:150-176);
 *     other statuses fail but are surfaced verbatim (400 = session-id
 *     validation, 500 = ORPort dial failure) so CI evidence can classify
 *     the failure layer.
 *   - conjure-registration class (conjure): POST to the registrar's
 *     /api/register-bidirectional endpoint with Host = registrar host
 *     and SNI = front (the PT client's domain-fronting split,
 *     gitlab.tpo.org/anti-censorship/pluggable-transports/conjure
 *     registration.go). A full registration needs station-pubkey crypto
 *     a liveness probe cannot construct; the honest minimal signature —
 *     defined by the regserver's own validation ladder
 *     (refraction-networking/conjure apiregserver.go:105-135) — is
 *     400 "Payload too small" on an empty POST, proving the registrar
 *     (not the front's default page) is reachable and processing.
 *     Path derivation verified live 2026-09-08 against
 *     registration.refraction.network: /api/register-bidirectional
 *     exists (non-404, GET-rejected); /api/api/register-bidirectional
 *     is "404 page not found" — descriptor url= values already carry
 *     the /api prefix the Caddy layer strips, so the probe appends only
 *     /register-bidirectional when the url path ends in /api.
 *   - The tls GET path (httpsFrontProbe) and the websocket-101 path are
 *     byte-identical to v2.5 (now built by the shared rawTlsExchange
 *     core; the request construction and read loop are unchanged) —
 *     snowflake / vless / shadowtls / anytls / http-upgrade / grpc stay
 *     on "tls", webtunnel stays on "websocket-101".
 *
 * v2.7 CHANGES (2026-09-08) — connection-queue starvation fix (fronted
 * probes dying at exactly 15000ms in CI):
 *   - ROOT CAUSE (proven twice on the real edge, egress-diagnostic runs
 *     34177070080 + 34177799271): the Workers runtime allows only SIX
 *     simultaneous outgoing connections per invocation and QUEUES excess
 *     connect() calls (developers.cloudflare.com/workers/platform/
 *     limits). A probe's own deadline (5s tcp / 15s TLS) starts when
 *     THIS code calls connect(), not when the runtime actually begins
 *     the connection — so a fronted probe admitted behind a wave of
 *     5s-hanging dead-bridge tcp connects spends its whole 15s budget
 *     waiting in the runtime's connection queue and reports "TLS connect
 *     … timed out after 15000ms" for a target that answers in ~400ms
 *     whenever it gets a slot. The decisive experiment: the 7 CI meek/
 *     conjure descriptors behind 23 verified-hanging dead bridges ALL
 *     fail at exactly 15000ms (batch B, wall 50s); the same 30
 *     descriptors with the 7 admitted FIRST all settle in 8-485ms with
 *     conjure c1 answering HTTP 400 (the regserver "Payload too small"
 *     signature) — batches A/C/D. Order is the only variable.
 *   - FIX 1: DEFAULT_MAX_CONCURRENT_PROBES 25 -> 6 (and
 *     wrangler.toml [vars] MAX_CONCURRENT_PROBES "25" -> "6"), aligning
 *     the admission pool with the runtime's real simultaneous-connection
 *     limit so every admitted probe starts connecting immediately — its
 *     deadline then measures probe time, never queue time. Total
 *     throughput is unchanged: the runtime's 6-connection pool was
 *     ALWAYS the real cap (25 admissions still executed 6-at-a-time),
 *     so the 2026-09-06 truncation fix is preserved — only timer-start
 *     semantics change. (The slot-limit sweep in the same diagnostic
 *     runs measures the limit directly: first queue delay appears when
 *     a batch's 7th connect() is in flight.)
 *   - FIX 2: fronted (non-tcp) probe classes are now ADMITTED FIRST
 *     within each batch — the exact batch-C configuration measured
 *     green twice. A 30-descriptor chunk is built by input order
 *     (scripts/probe_relay.sh split -l 30), so fronted descriptors can
 *     sit behind ~19 hangers; admitting them first gives them the first
 *     connection slots. tcp-class probes are outcome-invariant to
 *     admission order (a dead bridge fails either way; its latency
 *     merely becomes more honest). The results[] array stays indexed by
 *     ORIGINAL input position, so the response is byte-identical to the
 *     previous admission order for every caller.
 *
 * v2.5 CHANGES (2026-09-07) — TRUE domain-fronted probing (the Host-header
 * fix), implemented on cloudflare:sockets:
 *   - ROOT CAUSE (confirmed against the real workerd runtime and CI probe
 *     evidence): the v2.2 fetch()-based front probes built
 *     `https://${sni||host}:${port}${path}` and let fetch() derive every
 *     header from that URL — so the TLS SNI and the HTTP Host header were
 *     ALWAYS identical (both the front domain). A domain-fronted request
 *     needs SNI = front (the CDN you dial) and Host = the true backend
 *     host (the service the CDN routes to). fetch() in the Workers
 *     runtime cannot do that: the Host header is derived from the URL and
 *     a caller-supplied Host header is silently discarded (verified
 *     empirically — see the raw-socket probe section below). The v2.2
 *     probes therefore only ever reached the front CDN's own default
 *     vhost and could never observe the bridge behind it, which is the
 *     0-success signature for webtunnel / meek_lite / meek-azure /
 *     conjure in every CI run.
 *   - FIX: the tls and websocket-101 probe classes now run over
 *     cloudflare:sockets with secureTransport "on" (immediate TLS — the
 *     CURRENT valid values per the Workers TCP-sockets documentation are
 *     "off" | "on" | "starttls"; the old code's "start" was never valid
 *     and the deployed runtime rejects it verbatim with "Unsupported
 *     value in secureTransport socket option: start"). The dial host
 *     (= TLS ServerName/SNI) is the descriptor's advertised front; the
 *     raw HTTP/1.1 request's Host header is the descriptor's true host —
 *     the exact technique of the proven runner-side probe in
 *     src/webtunnel_probe.rs::probe_sync (real TLS handshake + raw
 *     HTTP request with Host independent of the TLS ServerName). No ALPN
 *     is offered (the connect() options have no alpn field — the old
 *     code's alpn option never existed and was silently ignored), so the
 *     connection speaks HTTP/1.1, which is what a WebSocket-Upgrade
 *     handshake requires.
 *   - BridgeDB documentation-prefix IPv6 endpoints (2001:db8::/32) are
 *     skipped before any network I/O, mirroring the SkipDocIpv6 decision
 *     in webtunnel_probe.rs — they are anti-enumeration placeholders, and
 *     probing them only burned the chunk's wall-clock budget.
 *   - tcp class (obfs4, vanilla) — UNCHANGED raw connect()
 *     (secureTransport "off"); httpsFrontProbe / wsUpgradeFrontProbe keep
 *     their exported names, signatures, and JSON result schema
 *     (probe_type, success, http_status, error, latency_ms).
 *
 * v2.4 CHANGES (2026-09-07):
 *   - Fetch probes use the descriptor's optional `path` (from the bridge
 *     line's url=) instead of always "/" — webtunnel lines carry a
 *     per-bridge token path that real clients upgrade against, and conjure
 *     lines carry /api. Purely additive (descriptor field + request URL).
 *
 * v2.3 CHANGES (2026-09-07):
 *   - Fetch()-based probes moved from the 5s TCP budget to a 15s internal
 *     deadline (outer race is per-class), after the first-fix CI run showed
 *     every fetch probe hitting the 5s cap from the Cloudflare edge while
 *     runner-side probes reached the same fronts seconds later.
 *   - stats.https_controls: known-good HTTPS endpoints (example.com,
 *     1.1.1.1) probed through the same fetch path whenever a batch contains
 *     non-tcp descriptors, so all-timeout runs can distinguish worker fetch
 *     egress failure (controls fail) from front-specific unreachability
 *     (controls pass).
 *
 * v2.2 CHANGES (2026-09-07) — probe-method fix for fronted/rendezvous
 * transports (diagnosed from real CI per-descriptor evidence):
 *   - The tls and websocket-101 probe classes previously called
 *     connect({ secureTransport: "start" }). The deployed Workers runtime
 *     rejects that option ("Unsupported value in secureTransport socket
 *     option: start"), so every descriptor routed to those classes failed
 *     BEFORE any network I/O and reported exactly 0 success — snowflake,
 *     meek_lite, meek-azure, conjure and webtunnel all showed 0/… while the
 *     tcp-class transports (obfs4, Bridge/vanilla) showed real successes in
 *     the same batches. Both classes now run over fetch() from the runtime's
 *     real TLS stack instead of raw sockets:
 *       - tls class        -> HTTPS GET to the descriptor dial target
 *                             (front when sni is present, else host); ANY
 *                             HTTP response is evidence the fronted CDN
 *                             layer is reachable; the status is recorded
 *                             (http_status) for downstream interpretation.
 *       - websocket-101    -> HTTPS WebSocket-Upgrade request to the same
 *                             dial target; HTTP 101 Switching Protocols is
 *                             required for success (mirrors the proven
 *                             upgrade probe in src/webtunnel_probe.rs).
 *       - tcp class        -> UNCHANGED raw connect() (secureTransport:
 *                             "off") — the method that correctly probes
 *                             obfs4 and Bridge/vanilla endpoints.
 *   - ProbeResult gains two additive fields: `sni` (dial-target SNI used,
 *     when different from the descriptor host) and `http_status` (HTTP
 *     status received from a fetch-based probe, when one was received).
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
 *   - vanilla, obfs4, Bridge/vanilla bucket: raw TCP connect (unchanged)
 *   - snowflake, meek, meek_lite, meek-azure, conjure, fronted: raw-socket
 *     TLS GET with SNI = advertised front and Host = the true backend
 *   - webtunnel: raw-socket TLS WebSocket Upgrade (SNI = front/host,
 *     Host = true backend; requires HTTP 101)
 */

// ─── Types ──────────────────────────────────────────────────────────

interface BridgeDescriptor {
  id: string;
  transport: string;
  host: string;
  port: number;
  sni?: string;
  url?: string;
  /** v2.4: request path carried over from the bridge line's url= (e.g. a
   *  webtunnel per-bridge token path). Defaults to "/" when absent. */
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
  /** SNI / dial-target host actually used by fetch-based probes, when the
   *  descriptor carried a front distinct from its host field. */
  sni?: string | null;
  /** HTTP status received from a fetch-based (tls/websocket-101) probe. */
  http_status?: number | null;
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
// v2.3: fetch()-based TLS/WebSocket probes get a longer budget than raw TCP
// connects: real-CI evidence (run 34148197499) showed every fetch probe to
// the fronted transports timing out at exactly the 5s TCP cap while the same
// fronts answered the runner-side probe seconds later in the same run.
const FETCH_PROBE_TIMEOUT_MS = 15000;
// v2.7: 25 -> 6. The Workers runtime allows only 6 simultaneous outgoing
// connections per invocation and QUEUES excess connect() calls — and a
// probe's own deadline starts at admission (when this code calls
// connect()), so with 25 admissions the 7th..25th probes' 5s/15s budgets
// burn inside the runtime's connection queue (proven by egress-diagnostic
// runs 34177070080 + 34177799271: all seven fronted descriptors admitted
// behind 23 verified-hanging tcp connects fail at exactly 15000ms; the
// same descriptors admitted first settle in 8-485ms). 6 aligns admission
// with the runtime pool: every admitted probe starts connecting
// immediately. Throughput is unchanged — the runtime pool was always the
// real cap, so the 2026-09-06 truncation fix holds.
// Override at deploy time via wrangler.toml [vars] MAX_CONCURRENT_PROBES.
const DEFAULT_MAX_CONCURRENT_PROBES = 6;
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

    // v2.3: when a batch contains any fetch()-probed (non-tcp) descriptor,
    // probe two known-good public HTTPS endpoints through the same runtime
    // TLS path and attach the outcomes to stats. CI prints the chunk stats
    // verbatim, so a run where every fronted-transport probe times out can
    // be distinguished as "Worker fetch egress down/slow" (controls also
    // fail) versus "these particular fronts unreachable from Cloudflare"
    // (controls succeed). Diagnostics only — never counted as successes.
    const hasNonTcp = bridges.some((b) => classifyProbe(b) !== "tcp");
    if (hasNonTcp) {
      stats.https_controls = await runHttpsEgressControls();
    }

    console.log(
      `[probe-relay] batch_done attempted=${stats.attempted} completed=${stats.completed} ` +
        `timed_out=${stats.timedOut} errored=${stats.errored} success=${stats.success}` +
        (stats.https_controls
          ? ` controls=${JSON.stringify(stats.https_controls)}`
          : ""),
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
  /** v2.3: outcomes of known-good HTTPS egress controls, populated only
   *  when the batch contained fetch()-probed (non-tcp) descriptors. */
  https_controls?: HttpsControl[];
}

interface HttpsControl {
  target: string;
  ok: boolean;
  http_status: number | null;
  error: string | null;
}

/** v2.3: fetch()-based egress controls against known-good public HTTPS
 *  endpoints. Returns one outcome per target; never throws. */
export async function runHttpsEgressControls(
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
): Promise<HttpsControl[]> {
  const targets = ["https://example.com/", "https://1.1.1.1/"];
  const controls: HttpsControl[] = [];
  for (const target of targets) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(target, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT, Accept: "*/*" },
      });
      controls.push({ target, ok: true, http_status: res.status, error: null });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      controls.push({
        target,
        ok: false,
        http_status: null,
        error: controller.signal.aborted
          ? `timed out after ${timeoutMs}ms`
          : reason,
      });
    } finally {
      clearTimeout(timer);
    }
  }
  return controls;
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

  // v2.7: admission order — fronted (non-tcp) probe classes first, then
  // tcp-class probes, each stable in input order. The Workers runtime
  // queues connect() calls beyond 6 simultaneous connections per
  // invocation, and a probe's deadline starts at admission, so a fronted
  // probe admitted behind a wave of 5s-hanging dead-bridge tcp connects
  // can spend its whole 15s budget in the runtime queue (the exact CI
  // failure proven in egress-diagnostic runs 34177070080/34177799271:
  // 7-first ⇒ 8-485ms incl. conjure HTTP 400; same 30 descriptors with
  // 23 hangers first ⇒ all seven exactly 15000ms). Admitting fronted
  // classes first is the measured-green configuration. tcp-class probes
  // are outcome-invariant to admission order (a dead bridge fails either
  // way). results[] stays indexed by ORIGINAL input position, so the
  // response array is byte-identical to the previous admission order.
  const frontedFirst: number[] = [];
  const tcpLast: number[] = [];
  for (let i = 0; i < bridges.length; i++) {
    if (classifyProbe(bridges[i]) === "tcp") {
      tcpLast.push(i);
    } else {
      frontedFirst.push(i);
    }
  }
  const order = [...frontedFirst, ...tcpLast];

  let nextIndex = 0;

  // Worker function that pulls the next bridge from the queue
  async function worker(): Promise<void> {
    while (nextIndex < order.length) {
      const idx = order[nextIndex++];
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

  // v2.3: fetch()-based classes carry their own longer internal deadline
  // (FETCH_PROBE_TIMEOUT_MS) and produce results with full diagnostics
  // (sni / http_status / error). The outer race must outlast the inner
  // deadline so the inner result — not this generic fallback — wins.
  const probeType = classifyProbe(bridge);
  const raceMs =
    probeType === "tcp" ? timeoutMs : FETCH_PROBE_TIMEOUT_MS + 1000;

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
        error: `probe timed out after ${raceMs}ms`,
      });
    }, raceMs);
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
  const port = bridge.port;
  let httpStatus: number | null = null;

  try {
    switch (probeType) {
      case "tcp":
        await safeTcpProbe(bridge.host, port);
        break;

      case "tls":
        // v2.5: raw-socket domain-fronted HTTPS GET (real TLS with SNI =
        // the advertised front, Host = the descriptor's true host). The
        // fetch()-based v2.2 probe sent SNI = Host = front and could
        // never reach the bridge behind the CDN; the connect({
        // secureTransport: "start" }) path before that was rejected by
        // the deployed runtime before any network I/O.
        httpStatus = await httpsFrontProbe(bridge);
        break;

      case "websocket-101":
        // v2.5: raw-socket domain-fronted WebSocket Upgrade over
        // TLS/HTTP-1.1 (SNI = front/host, Host = the descriptor's true
        // host); only HTTP 101 counts as success.
        httpStatus = await wsUpgradeFrontProbe(bridge);
        break;

      case "meek-post":
        // v2.6: protocol-correct meek round-trip — POST with
        // X-Session-Id over fronted TLS (SNI = front, Host = the
        // descriptor's url= host); success requires the meek-server
        // transact signature (200 + application/octet-stream).
        httpStatus = await meekPostProbe(bridge);
        break;

      case "conjure-registration":
        // v2.6: conjure registrar reachability — POST to the
        // register-bidirectional endpoint over fronted TLS (SNI = front,
        // Host = the registrar); success = the regserver's 400
        // payload-validation signature (or a 2xx).
        httpStatus = await conjureRegistrationProbe(bridge);
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
      sni: bridge.sni ?? null,
      success: true,
      latency_ms: latencyMs,
      probe_type: probeType,
      http_status: httpStatus,
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
      sni: bridge.sni ?? null,
      success: false,
      latency_ms: latencyMs,
      probe_type: probeType,
      http_status: httpStatus,
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

  // v2.6: meek-family transports ride an HTTP POST round-trip over a
  // fronted TLS connection (meek-client.go roundTripWithHTTP), so a
  // protocol-correct probe is a POST with the X-Session-Id header — not
  // the generic TLS GET used since v2.5.
  if (t === "meek" || t === "meek_lite" || t === "meek-azure") {
    return "meek-post";
  }

  // v2.6: conjure bridges register via the bidirectional API rendezvous
  // (POST to the registrar's /api/register-bidirectional endpoint behind
  // an optional front), not a plain TLS GET of the bridge URL.
  if (t === "conjure") {
    return "conjure-registration";
  }

  if (
    t === "snowflake" ||
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
// timeout paths. safeConnect() (raw TCP class) and safeTlsConnect()
// (v2.5, TLS fronted classes) are the two entry points for socket
// connections — no other code in this file calls connect() directly.

// v2.5: the valid secureTransport values per the current Workers
// TCP-sockets documentation are "off" | "on" | "starttls". The old type
// allowed "start", which the deployed runtime rejects verbatim with
// "Unsupported value in secureTransport socket option: start" — it was
// never a valid value in the deployed runtime generation.
interface ConnectOptions {
  secureTransport: "off" | "on" | "starttls";
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
  // v2.5 FIX: this helper previously dialed with secureTransport "start"
  // (rejected verbatim by the deployed runtime: "Unsupported value in
  // secureTransport socket option: start") and passed a non-existent
  // `alpn` connect() option (silently ignored — the connect() options
  // only accept secureTransport and allowHalfOpen). It now performs a
  // real immediate-TLS connection (secureTransport "on") via
  // safeTlsConnect, dialing the SNI host with the documented
  // socket.opened handshake signal, then drains and closes.
  const dialHost = sni || host;
  const socket = await safeTlsConnect(dialHost, port, DEFAULT_PROBE_TIMEOUT_MS);
  // TLS handshake completed. Consume any server greeting data then close.
  await drainAndClose(socket);
}

async function safeWebsocketProbe(bridge: BridgeDescriptor): Promise<void> {
  // v2.5 FIX (legacy raw-socket WebSocket probe, previously dead in
  // production): it dialed with secureTransport "start" — rejected
  // verbatim by the deployed runtime before any network I/O — and sent
  // `Host: ${sni}` (the FRONT) instead of the true backend host, so even
  // where it ran it probed the front's own default vhost. It is now a
  // thin wrapper over the corrected raw-socket upgrade path used by
  // wsUpgradeFrontProbe: TLS with SNI = the advertised front and a raw
  // HTTP/1.1 WebSocket-Upgrade request whose Host header is the
  // descriptor's true host. Same name, same descriptor-in / void-out
  // shape (it was and remains an internal helper, not exported).
  const { status } = await rawTlsHttpProbe(bridge, true, DEFAULT_PROBE_TIMEOUT_MS);
  if (status !== 101) {
    throw new Error(`WebSocket upgrade rejected: HTTP ${status}`);
  }
}

// ─── Raw-socket domain-fronted TLS probes (v2.5) ─────────────────────
//
// WHY fetch() CANNOT PROBE A FRONTED TRANSPORT (root cause of the
// permanent 0-success rows, verified empirically inside the real workerd
// runtime): a fetch() to `https://front:443/path` sends TLS SNI = front
// AND HTTP Host = front, because the Workers runtime derives the Host
// header from the URL and SILENTLY DISCARDS a caller-supplied Host
// header. A domain-fronted request needs SNI = front (the CDN you dial)
// but Host = the true backend host (the service the CDN's vhost routing
// forwards to). The v2.2/v2.3 fetch probes therefore only ever reached
// the front CDN's own default vhost and could never observe the bridge
// behind it.
//
// THE FIX (ported from the proven runner-side pattern in
// src/webtunnel_probe.rs::probe_sync): a real TLS connection via
// cloudflare:sockets with secureTransport "on", where the TLS
// ServerName/SNI is the DIAL host (the advertised front), followed by a
// raw HTTP/1.1 request whose Host header is set INDEPENDENTLY to the
// descriptor's true host. No ALPN is offered (connect() has no alpn
// option), so both ends speak plain HTTP/1.1 — exactly what a
// WebSocket-Upgrade handshake requires and what the fetch()-based probe
// could not guarantee (the runtime's fetch stack may negotiate HTTP/2,
// where `Upgrade: websocket` is meaningless, which is why v2.4 saw
// "Server failed WebSocket handshake: missing Upgrade header" from
// otherwise-live webtunnel fronts).
//
// Descriptor field semantics (traced from the builder in
// scripts/probe_relay.sh v5.5, Format 4):
//   - URL-only descriptors (ALL webtunnel lines; snowflake / meek_lite /
//     meek-azure / conjure / meek lines without advertised fronts):
//       host = the url= host, sni absent
//     → direct TLS: SNI = host, Host = host.
//   - Fronted descriptors (v5.2: non-webtunnel lines advertising
//     front=/fronts= emit one extra descriptor per advertised front):
//       host = the url= host (the TRUE BACKEND the CDN routes to),
//       sni  = the advertised front (the domain to dial).
//     → domain-fronted TLS: SNI = sni (the front), Host = host (the true
//       backend).
// In BOTH cases the correct mapping is: TLS ServerName = (sni || host),
// HTTP Host = host. The bridge line's url= therefore only ever becomes
// the Host header / dial host when no front is advertised — a front
// domain is never used as the Host value (the v2.2 bug).
//
// Semantics (evidence tiers, unchanged from v2.2/v2.4):
//   - tls class: any HTTP response status proves the fronted layer is
//     reachable through TLS; the status itself is returned so callers
//     can distinguish a live transport endpoint (2xx/3xx) from a
//     reachable but refusing front (4xx/5xx).
//   - websocket-101 class: only HTTP 101 Switching Protocols counts as
//     success — the same bar as the proven webtunnel upgrade probe in
//     src/webtunnel_probe.rs. A non-101 response is a reachable front
//     without a live WebTunnel endpoint and is reported as a failure
//     with its status.

/** True when the host is an RFC 3849 documentation-prefix IPv6 address
 *  (2001:db8::/32), including the bracketed form used in bridge lines.
 *  BridgeDB substitutes these into webtunnel IPv6 lines as an
 *  anti-enumeration placeholder — they are not routable. Mirrors
 *  is_documentation_ipv6() in src/webtunnel_probe.rs. */
export function isDocumentationIpv6(host: string): boolean {
  const stripped = (host || "")
    .trim()
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
  return stripped === "2001:db8" || stripped.startsWith("2001:db8:");
}

/** Request path for a probe: the bridge line's url= path when it carries
 *  one (webtunnel token paths, conjure's /api), else "/". */
function frontProbePath(bridge: BridgeDescriptor): string {
  const p = (bridge.path || "").trim();
  return p.startsWith("/") && p.length > 1 ? p : "/";
}

/** Dial target for a fronted descriptor (see the section header for the
 *  per-transport field semantics): the TLS dial host / SNI is the
 *  advertised front when present, else the descriptor host; the HTTP
 *  Host header is ALWAYS the descriptor's true host. */
function frontDialTarget(bridge: BridgeDescriptor): {
  dialHost: string;
  hostHeader: string;
} {
  const sni = (bridge.sni || "").trim();
  return { dialHost: sni || bridge.host, hostHeader: bridge.host };
}

/** Host header value: the bare hostname on the default TLS port,
 *  host:port otherwise (what PT clients and the previous fetch() probes
 *  put on the wire). */
function hostHeaderValue(host: string, port: number): string {
  return port === 443 ? host : `${host}:${port}`;
}

/** v2.5: TLS connect for the fronted probe classes. Unlike safeConnect()
 *  — whose reader.closed race models endpoints that close on silence
 *  (the raw TCP class) — this awaits the documented `socket.opened`
 *  promise, which resolves once the TCP connection AND the TLS handshake
 *  are complete and rejects on connection / handshake / certificate
 *  errors. No reader lock is held while waiting, and every caller
 *  releases its locks in a finally block (the same discipline as the
 *  rest of this file). */
async function safeTlsConnect(
  dialHost: string,
  port: number,
  timeoutMs: number,
): Promise<WorkersSocket> {
  // @ts-ignore — cloudflare:sockets types are ambient in Workers
  const socket = connect(
    { hostname: dialHost, port },
    { secureTransport: "on" } as any,
  );

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const opened: Promise<unknown> = socket.opened ?? Promise.resolve(undefined);
    await Promise.race([
      opened,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error(
                `TLS connect to ${dialHost}:${port} timed out after ${timeoutMs}ms`,
              ),
            ),
          timeoutMs,
        );
      }),
    ]);
    return socket;
  } catch (err) {
    closeSocket(socket);
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`TLS connect to ${dialHost}:${port} failed: ${reason}`);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/** Shared raw-socket exchange used by every fronted probe class (v2.5
 *  core, v2.6 generalized): real TLS with ServerName = the dial host
 *  (the advertised front), a raw HTTP/1.1 request whose Host header is
 *  the descriptor's true host, then a response-head read and status-line
 *  parse. `method`/`path`/`extraHeaders` control the request; the Host /
 *  User-Agent / Accept lines are common to all probe classes. Throws on
 *  any failure. Returns the parsed status, the verbatim status line, and
 *  the full response head text (headers included) so callers can apply
 *  protocol-specific response signatures. */
async function rawTlsExchange(
  bridge: BridgeDescriptor,
  method: string,
  path: string,
  extraHeaders: string[],
  timeoutMs: number,
): Promise<{ status: number; statusLine: string; headText: string }> {
  // Fast-path skip: BridgeDB documentation-prefix IPv6 placeholders are
  // unroutable by design; probing them only burns the chunk's wall-clock
  // budget (251 of the 255 webtunnel lines in a typical CI input are
  // these). Mirrors the SkipDocIpv6 decision in webtunnel_probe.rs — the
  // runner-side probe skips them for the same reason.
  if (isDocumentationIpv6(bridge.host)) {
    throw new Error(
      `skipped: documentation-prefix IPv6 endpoint ${bridge.host} ` +
        `(BridgeDB anti-enumeration placeholder, not a routable bridge address)`,
    );
  }

  const { dialHost, hostHeader } = frontDialTarget(bridge);
  const port = bridge.port || 443;
  const label =
    `TLS front probe ${dialHost}:${port}${path} ` +
    `(SNI=${dialHost}, Host=${hostHeaderValue(hostHeader, port)})`;

  let socket: WorkersSocket | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let responseTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    socket = await safeTlsConnect(dialHost, port, timeoutMs);
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();

    const requestLines = [
      `${method} ${path} HTTP/1.1`,
      `Host: ${hostHeaderValue(hostHeader, port)}`,
      `User-Agent: ${USER_AGENT}`,
      `Accept: */*`,
    ];
    requestLines.push(...extraHeaders);
    const request = `${requestLines.join("\r\n")}\r\n\r\n`;
    await writer.write(new TextEncoder().encode(request));

    // Read the response head, racing the overall deadline so a server
    // that accepts the request but never responds cannot hold the probe
    // (the read loop itself would otherwise await forever).
    const responsePromise = (async () => {
      let response = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        response += new TextDecoder().decode(value);
        if (response.includes("\r\n\r\n")) break;
        if (response.length > 4096) break;
      }
      return response;
    })();
    const deadlinePromise = new Promise<"__probe_deadline__">((resolve) => {
      responseTimer = setTimeout(() => resolve("__probe_deadline__"), timeoutMs);
    });
    const response = await Promise.race([responsePromise, deadlinePromise]);
    if (response === "__probe_deadline__") {
      throw new Error(`timed out after ${timeoutMs}ms waiting for response head`);
    }

    const statusLine = (response.split("\r\n")[0] || "").trim();
    const match = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
    if (!match) {
      throw new Error(
        statusLine
          ? `no HTTP status line in response (first line: ${statusLine})`
          : `no response (connection closed before a status line was received)`,
      );
    }
    return { status: parseInt(match[1], 10), statusLine, headText: response };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`${label} failed: ${reason}`);
  } finally {
    if (responseTimer !== undefined) {
      clearTimeout(responseTimer);
    }
    // Always release writer and reader locks, then close the socket —
    // no dangling locks regardless of which code path (success, error,
    // timeout) triggers the cleanup.
    if (writer) {
      try { writer.releaseLock(); } catch { /* best-effort */ }
    }
    if (reader) {
      try { reader.releaseLock(); } catch { /* best-effort */ }
    }
    if (socket) {
      closeSocket(socket);
    }
  }
}

/** Core v2.5 probe: plain GET or WebSocket-Upgrade GET over the shared
 *  raw TLS exchange. Used by the tls and websocket-101 classes; the wire
 *  format is exactly the v2.5 construction (request line, Host, UA,
 *  Accept, then the upgrade headers when `websocketUpgrade`). Throws on
 *  any failure. */
async function rawTlsHttpProbe(
  bridge: BridgeDescriptor,
  websocketUpgrade: boolean,
  timeoutMs: number,
): Promise<{ status: number; statusLine: string; headText: string }> {
  const extraHeaders: string[] = [];
  if (websocketUpgrade) {
    extraHeaders.push(
      `Connection: Upgrade`,
      `Upgrade: websocket`,
      `Sec-WebSocket-Key: ${generateWebSocketKey()}`,
      `Sec-WebSocket-Version: 13`,
    );
  }
  return rawTlsExchange(bridge, "GET", frontProbePath(bridge), extraHeaders, timeoutMs);
}

/** HTTPS GET probe (tls class). Resolves to the HTTP status of any
 *  response; throws on DNS/TLS/connection errors or timeout. v2.5:
 *  domain-fronted via raw TLS socket (SNI = advertised front, Host =
 *  the descriptor's true host) — see the section header above. */
export async function httpsFrontProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
): Promise<number> {
  const { status } = await rawTlsHttpProbe(bridge, false, timeoutMs);
  return status;
}

/** WebSocket-Upgrade probe (websocket-101 class). Resolves to 101 when
 *  the front completes the upgrade; throws otherwise (including for
 *  non-101 HTTP responses, mirroring the webtunnel_probe.rs bar).
 *  v2.5: domain-fronted via raw TLS socket over HTTP/1.1 (SNI =
 *  advertised front, Host = the descriptor's true host). */
export async function wsUpgradeFrontProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
): Promise<number> {
  const { status, statusLine } = await rawTlsHttpProbe(bridge, true, timeoutMs);
  if (status !== 101) {
    throw new Error(`WebSocket upgrade rejected: ${statusLine || `HTTP ${status}`}`);
  }
  return status;
}

// ─── meek-post Probe (v2.6) ─────────────────────────────────────────
//
// Protocol-correct meek reachability check modeled on the reference
// implementation (git.torproject.org/pluggable-transports/meek, mirrored
// at github.com/arlolra/meek — meek-client.go roundTripWithHTTP +
// genSessionId; meek-server.go POST handler + transact + minSessionIdLength).

/** Generate a meek session id exactly like the reference client's
 *  genSessionId (meek-client.go:252-258): standard-base64 of 32 random
 *  bytes, i.e. 44 characters including the single pad '='. The server
 *  enforces minSessionIdLength = 32 (meek-server.go:38) with a 400
 *  otherwise, so a probe that wants to reach the session/transact layer
 *  must send a plausible id. */
function generateMeekSessionId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Response-head signature check: does the head contain the given header
 *  (field name case-insensitive per RFC 7230) whose value starts with
 *  `valuePrefix` (case-insensitive)? Used for the meek success bar
 *  (Content-Type: application/octet-stream). Only accepts the header at
 *  the start of a line so text inside other header values cannot match. */
function headHasHeaderValue(headText: string, name: string, valuePrefix: string): boolean {
  const lower = headText.toLowerCase();
  const needle = `${name.toLowerCase()}:`;
  const prefix = valuePrefix.toLowerCase();
  let idx = 0;
  while ((idx = lower.indexOf(needle, idx)) !== -1) {
    const atLineStart = idx === 0 || lower[idx - 1] === "\n";
    if (atLineStart) {
      const valueStart = idx + needle.length;
      const lineEnd = lower.indexOf("\n", valueStart);
      const line = lower.slice(valueStart, lineEnd === -1 ? undefined : lineEnd).trim();
      if (line.startsWith(prefix)) return true;
    }
    idx += needle.length;
  }
  return false;
}

/** meek-post class probe (v2.6): POST the meek round-trip over the
 *  shared raw TLS exchange, exactly like the reference client's
 *  roundTripWithHTTP (meek-client.go:118-142):
 *    - POST to the bridge url= path (the meek transport payload rides as
 *      the HTTP body; an empty body is protocol-shaped for a liveness
 *      probe: the server wraps it in a MaxBytesReader, forwards it to
 *      the ORPort, and the ORPort reply becomes the response body).
 *    - X-Session-Id: base64(32 random bytes) per genSessionId.
 *    - Host: the descriptor's true (backend) host; SNI/dial: the front —
 *      the client's fronting split (req.Host = backend, URL.Host = front).
 *  Success bar: HTTP 200 with Content-Type application/octet-stream —
 *  the server's transact() signature (meek-server.go:150-176), proving
 *  the front is reachable, the meek app routed the session, and the
 *  ORPort behind it answered within turnaroundTimeout (10ms). Any other
 *  status fails the probe but is surfaced verbatim in the error so CI
 *  evidence can classify the layer: 400 = session-id validation, 500 =
 *  ORPort dial failure (meek-server.go:179-189), 404/403 = the front's
 *  edge answered without reaching the meek app. Throws on failure;
 *  resolves with the HTTP status on success. */
export async function meekPostProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
): Promise<number> {
  const path = frontProbePath(bridge);
  const { status, statusLine, headText } = await rawTlsExchange(
    bridge,
    "POST",
    path,
    [`X-Session-Id: ${generateMeekSessionId()}`, `Content-Length: 0`],
    timeoutMs,
  );
  if (status === 200 && headHasHeaderValue(headText, "Content-Type", "application/octet-stream")) {
    return status;
  }
  const hasOctetStream = headHasHeaderValue(headText, "Content-Type", "application/octet-stream");
  throw new Error(
    `meek POST ${path} got ${statusLine}` +
      (status === 200 && !hasOctetStream
        ? ` (200 without meek's application/octet-stream transact signature — likely the front's default vhost, not the meek backend)`
        : ` (see meek-server.go status semantics: 400 = session-id validation, 500 = ORPort dial failure, 4xx = front edge)`),
  );
}

// ─── conjure-registration Probe (v2.6) ──────────────────────────────
//
// Registrar reachability check modeled on the conjure PT client's
// bidirectional API rendezvous (gitlab.tpo.org/anti-censorship/pluggable-
// transports/conjure registration.go Rendezvous.RoundTrip, default
// registrar "bdapi" → RegisterURL + /api/register-bidirectional) and the
// reference API regserver (refraction-networking/conjure
// pkg/regserver/apiregserver/apiregserver.go).

/** Derive the bidirectional-registration path from the descriptor's url=
 *  value. The PT client appends the literal "/api/register-bidirectional"
 *  to RegisterURL (registration.go, regConfig.Target); the production
 *  deployment (registration.refraction.network) serves a single /api
 *  prefix that Caddy strips before reverse-proxying to the regserver
 *  (cmd/registration-server/README.md). Descriptor url= values already
 *  carry the /api prefix, so appending the full literal would double it —
 *  verified live 2026-09-08: /api/register-bidirectional exists (non-404,
 *  rejects GET) while /api/api/register-bidirectional is "404 page not
 *  found". */
function conjureRegistrationPath(bridge: BridgeDescriptor): string {
  const base = (bridge.path || "").replace(/\/+$/, "");
  if (base.toLowerCase().endsWith("/api")) {
    return `${base}/register-bidirectional`;
  }
  return `${base}/api/register-bidirectional`;
}

/** conjure-registration class probe (v2.6): POST to the
 *  register-bidirectional endpoint with Host = the registrar host and
 *  SNI/dial = the advertised front — the client's domain-fronting split
 *  (registration.go: req.Host = registrar, req.URL.Host = front). A full
 *  registration requires the station public key and shared-secret crypto
 *  wrapping a ClientToStation protobuf, which a liveness probe cannot
 *  construct; the regserver's own validation ladder
 *  (apiregserver.go:105-135) defines the honest minimal signature: a
 *  POST that reaches the registrar with an empty body is answered
 *  400 "Payload too small" — proving the registrar (not the front's
 *  default page) is reachable and processing requests. Success bar: the
 *  400 payload-validation signature, or any 2xx (registration accepted —
 *  not expected from this probe). 404 (front default vhost / wrong
 *  path), 405, 5xx, and any TLS/transport error throw with the verbatim
 *  reason so CI evidence can classify dead front vs dead registrar vs
 *  Cloudflare-egress failure. Throws on failure; resolves with the
 *  HTTP status on success. */
export async function conjureRegistrationProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
): Promise<number> {
  const path = conjureRegistrationPath(bridge);
  const { status, statusLine } = await rawTlsExchange(
    bridge,
    "POST",
    path,
    [`Content-Length: 0`],
    timeoutMs,
  );
  if ((status >= 200 && status < 300) || status === 400) {
    return status;
  }
  throw new Error(
    `conjure registration POST ${path} got ${statusLine}` +
      ` (expected the 400 payload-validation signature or 2xx; 404 = front default vhost or wrong path)` +
      (status === 405 ? `; 405 is still method validation by the regserver itself` : ``),
  );
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
