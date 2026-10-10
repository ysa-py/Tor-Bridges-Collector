// @ts-ignore — cloudflare:sockets is an ambient Workers runtime module
import { connect } from "cloudflare:sockets";
import {
  MAX_BRIDGES_PER_REQUEST,
  constantTimeTokenEqual,
  configuredInteger,
  readJsonRequestBody,
  validateBridgeList,
} from "./security";

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
  path?: string;
  cert?: string;
  iat_mode?: string;
  fingerprint?: string;
}

type ProbeStatus = "connected" | "refused" | "timeout" | "inconclusive" | "error";
type VerificationStage = "S0" | "S1" | "S2" | "S3" | "S4";

interface ProbeVantage {
  type: "cloudflare_worker";
  colo: string | null;
}

interface ProbeResult {
  id: string;
  transport: string;
  host: string;
  port: number;
  /** Compatibility summary only; stage/status are the authoritative evidence. */
  success: boolean;
  status: ProbeStatus;
  stage: VerificationStage;
  vantage: ProbeVantage;
  observed_at: string;
  rtt_ms: number | null;
  latency_ms: number | null;
  probe_type: string;
  sni?: string | null;
  http_status?: number | null;
  detail: string;
  error_class: string | null;
  /** Redacted, machine-readable summary retained for legacy clients. */
  error: string | null;
}

interface Env {
  PROBE_RELAY_TOKEN?: string;
  MAX_BRIDGES_PER_REQUEST?: string;
  MAX_CONCURRENT_PROBES?: string;
  PROBE_TIMEOUT_SECS?: string;
  /** v2.8 (additive): deploy-version identity, injected by CI at deploy time
   *  via `wrangler deploy --var RELAY_GIT_SHA:<sha>` from the last commit that
   *  touched probe-relay/. Consumed by the version-safe deploy guard in
   *  torshield-ir.yml Stage 4-prep so an older checkout can never silently
   *  overwrite a newer deployment. Absent on pre-v2.8 deployments (null). */
  RELAY_GIT_SHA?: string;
  /** v2.8 (additive): committer timestamp (unix seconds) of the same commit. */
  RELAY_GIT_TS?: string;
}

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_PROBE_TIMEOUT_MS = 5000;
// v2.3: fetch()-based TLS/WebSocket probes get a longer budget than raw TCP
// connects: real-CI evidence (run 34148197499) showed every fetch probe to
// the fronted transports timing out at exactly the 5s TCP cap while the same
// fronts answered the runner-side probe seconds later in the same run.
const FETCH_PROBE_TIMEOUT_MS = 15000;
const WORKER_REQUEST_DEADLINE_MS = 22000;
const EGRESS_CONTROL_TIMEOUT_MS = 2500;
const MAX_OUTBOUND_SUBREQUESTS = 50;
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
    try {
      if (request.method !== "POST") {
        return jsonResponse(405, {
          error: "method_not_allowed",
          detail: "Only POST /probe is supported",
          version: {
            service: "tor-bridge-probe-relay",
            git_sha: env.RELAY_GIT_SHA ?? null,
            git_ts: env.RELAY_GIT_TS ?? null,
          },
        });
      }

      const url = new URL(request.url);
      if (url.pathname !== "/probe") {
        return jsonResponse(404, { error: "not_found" });
      }

      const expectedToken = env.PROBE_RELAY_TOKEN;
      if (typeof expectedToken !== "string" || expectedToken.trim() === "" ||
          expectedToken.length < 16 || expectedToken.length > 1024 ||
          /[\u0000-\u001f\u007f]/.test(expectedToken)) {
        return jsonResponse(503, {
          error: "service_unavailable",
          detail: "probe authentication is not configured or invalid",
        });
      }
      if (!constantTimeTokenEqual(request.headers.get("X-Probe-Token"), expectedToken)) {
        return jsonResponse(401, { error: "unauthorized" });
      }

      const mediaType = (request.headers.get("content-type") ?? "")
        .split(";", 1)[0]
        .trim()
        .toLowerCase();
      if (mediaType !== "application/json") {
        return jsonResponse(415, { error: "unsupported_media_type" });
      }

      const body = await readJsonRequestBody(request);
      if (!body.ok) return jsonResponse(body.status, { error: body.error });

      const maxBridges = configuredInteger(
        env.MAX_BRIDGES_PER_REQUEST,
        MAX_BRIDGES_PER_REQUEST,
        1,
        MAX_BRIDGES_PER_REQUEST,
      );
      const maxConcurrent = configuredInteger(
        env.MAX_CONCURRENT_PROBES,
        DEFAULT_MAX_CONCURRENT_PROBES,
        1,
        DEFAULT_MAX_CONCURRENT_PROBES,
      );
      const probeTimeoutSecs = configuredInteger(
        env.PROBE_TIMEOUT_SECS,
        DEFAULT_PROBE_TIMEOUT_MS / 1000,
        1,
        30,
      );
      if (maxBridges === null || maxConcurrent === null || probeTimeoutSecs === null) {
        return jsonResponse(503, { error: "invalid_worker_configuration" });
      }

      const checked = validateBridgeList(body.value, maxBridges);
      if (!checked.ok) {
        return jsonResponse(checked.status, {
          error: checked.error,
          ...(checked.index !== undefined ? { index: checked.index } : {}),
        });
      }
      const bridges = checked.bridges;
      const probeTimeoutMs = probeTimeoutSecs * 1000;
      const vantage = workerVantage(request);
      const batchController = new AbortController();
      const unlinkRequestSignal = linkAbortSignal(request.signal, batchController);
      const requestDeadline = setTimeout(
        () => batchController.abort(new ProbeFailure(
          "timeout",
          "request_deadline",
          "S0",
          "Worker request deadline reached",
        )),
        WORKER_REQUEST_DEADLINE_MS,
      );

      try {
        console.log(
          `[probe-relay] batch_start bridges=${bridges.length} max_concurrent=${maxConcurrent} timeout_ms=${probeTimeoutMs}`,
        );

        const { results, stats } = await probeBridgesWithConcurrency(
          bridges,
          maxConcurrent,
          probeTimeoutMs,
          batchController.signal,
          vantage,
        );

        // Keep the two diagnostic HTTPS checks bounded and within the 50
        // subrequest/invocation ceiling. They run only after the six-socket
        // bridge wave has closed, and each has a short, explicit deadline.
        const hasNonTcp = bridges.some((bridge) => classifyProbe(bridge) !== "tcp");
        if (hasNonTcp && bridges.length + 2 <= MAX_OUTBOUND_SUBREQUESTS && !batchController.signal.aborted) {
          stats.https_controls = await runHttpsEgressControls(
            EGRESS_CONTROL_TIMEOUT_MS,
            batchController.signal,
          );
        }

        console.log(
          `[probe-relay] batch_done attempted=${stats.attempted} completed=${stats.completed} ` +
            `connected=${stats.connected} refused=${stats.refused} timed_out=${stats.timedOut} ` +
            `inconclusive=${stats.inconclusive} errored=${stats.errored}`,
        );
        return jsonResponse(200, { results, stats });
      } finally {
        clearTimeout(requestDeadline);
        unlinkRequestSignal();
      }
    } catch {
      // Do not serialize raw exceptions: socket and HTTP clients can include
      // credential-bearing URLs or peer-controlled data in their messages.
      console.error("[probe-relay] request_failed error_class=internal");
      return jsonResponse(500, { error: "internal_error" });
    }
  },
};

// ─── Concurrency-Limited Probing Engine ─────────────────────────────

interface ProbeStats {
  attempted: number;
  completed: number;
  connected: number;
  refused: number;
  timedOut: number;
  inconclusive: number;
  errored: number;
  /** Backward-compatible alias for connected outcomes; stage is authoritative. */
  success: number;
  https_controls?: HttpsControl[];
}

interface HttpsControl {
  target: string;
  ok: boolean;
  http_status: number | null;
  error: string | null;
}

class ProbeFailure extends Error {
  constructor(
    readonly status: Exclude<ProbeStatus, "connected">,
    readonly errorClass: string,
    readonly stage: VerificationStage,
    readonly safeDetail: string,
    readonly httpStatus?: number | null,
  ) {
    super(safeDetail);
    this.name = "ProbeFailure";
  }
}

function workerVantage(request: Request): ProbeVantage {
  const cf = (request as Request & { cf?: { colo?: unknown } }).cf;
  return {
    type: "cloudflare_worker",
    colo: typeof cf?.colo === "string" ? cf.colo : null,
  };
}

function abortFailure(signal?: AbortSignal): ProbeFailure {
  const reason = signal?.reason;
  if (reason instanceof ProbeFailure) return reason;
  return new ProbeFailure("inconclusive", "caller_cancelled", "S0", "probe cancelled by caller");
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortFailure(signal);
}

function linkAbortSignal(parent: AbortSignal | undefined, controller: AbortController): () => void {
  if (!parent) return () => {};
  const onAbort = () => controller.abort(parent.reason);
  if (parent.aborted) onAbort();
  else parent.addEventListener("abort", onAbort, { once: true });
  return () => parent.removeEventListener("abort", onAbort);
}

function raceWithSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortFailure(signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(abortFailure(signal));
    };
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => { cleanup(); resolve(value); },
      (error: unknown) => { cleanup(); reject(error); },
    );
  });
}

function closeOnAbort(socket: WorkersSocket, signal?: AbortSignal): () => void {
  if (!signal) return () => {};
  const close = () => closeSocket(socket);
  if (signal.aborted) close();
  else signal.addEventListener("abort", close, { once: true });
  return () => signal.removeEventListener("abort", close);
}

function classifyFailure(error: unknown): ProbeFailure {
  if (error instanceof ProbeFailure) return error;
  const message = error instanceof Error ? error.message : String(error);
  const lower = message.toLowerCase();
  if (lower.includes("timed out") || lower.includes("timeout")) {
    return new ProbeFailure("timeout", "probe_timeout", "S0", "probe timed out");
  }
  if (lower.includes("econnrefused") || lower.includes("connection refused") || lower.includes("refused")) {
    return new ProbeFailure("refused", "connection_refused", "S0", "connection refused");
  }
  if (/(cloudflare|egress|private|reserved).*(block|deny|not allowed|unavailable)/i.test(message)) {
    return new ProbeFailure("error", "egress_policy", "S0", "egress policy prevented the probe");
  }
  if (/http|response|upgrade|protocol|signature/i.test(message)) {
    return new ProbeFailure("inconclusive", "protocol_response_unverified", "S1", "connection reached the endpoint but its protocol signature was not verified");
  }
  return new ProbeFailure("error", "probe_error", "S0", "probe failed before a positive connection stage was recorded");
}

function makeProbeResult(
  bridge: BridgeDescriptor,
  probeType: string,
  vantage: ProbeVantage,
  elapsedMs: number,
  outcome: {
    status: ProbeStatus;
    stage: VerificationStage;
    detail: string;
    errorClass?: string | null;
    httpStatus?: number | null;
  },
): ProbeResult {
  const connected = outcome.status === "connected";
  return {
    id: bridge.id,
    transport: bridge.transport,
    host: bridge.host,
    port: bridge.port,
    success: connected,
    status: outcome.status,
    stage: outcome.stage,
    vantage,
    observed_at: new Date().toISOString(),
    rtt_ms: elapsedMs,
    latency_ms: elapsedMs,
    probe_type: probeType,
    sni: bridge.sni ?? null,
    http_status: outcome.httpStatus ?? null,
    detail: outcome.detail,
    error_class: outcome.errorClass ?? null,
    error: connected ? null : outcome.detail,
  };
}

function cancelledResult(bridge: BridgeDescriptor, vantage: ProbeVantage): ProbeResult {
  return makeProbeResult(bridge, classifyProbe(bridge), vantage, 0, {
    status: "inconclusive",
    stage: "S0",
    detail: "probe cancelled by caller before network activity",
    errorClass: "caller_cancelled",
  });
}

/** Supplementary known-good HTTPS controls; outcomes are diagnostic only. */
export async function runHttpsEgressControls(
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
  parentSignal?: AbortSignal,
): Promise<HttpsControl[]> {
  const targets = ["https://example.com/", "https://1.1.1.1/"];
  return Promise.all(targets.map(async (target): Promise<HttpsControl> => {
    if (parentSignal?.aborted) {
      return { target, ok: false, http_status: null, error: "caller_cancelled" };
    }
    const controller = new AbortController();
    const unlink = linkAbortSignal(parentSignal, controller);
    const timer = setTimeout(
      () => controller.abort(new ProbeFailure("timeout", "control_timeout", "S0", "control timed out")),
      timeoutMs,
    );
    try {
      const response = await fetch(target, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT, Accept: "*/*" },
      });
      await response.body?.cancel();
      return { target, ok: true, http_status: response.status, error: null };
    } catch {
      const failure = controller.signal.aborted ? abortFailure(controller.signal) : null;
      return {
        target,
        ok: false,
        http_status: null,
        error: failure?.errorClass === "caller_cancelled" ? "caller_cancelled" :
          failure?.status === "timeout" ? "timed_out" : "fetch_failed",
      };
    } finally {
      clearTimeout(timer);
      unlink();
    }
  }));
}

/** Exported for hermetic Vitest coverage; preserves input result order. */
export async function probeBridgesWithConcurrency(
  bridges: BridgeDescriptor[],
  maxConcurrent: number,
  timeoutMs: number,
  signal?: AbortSignal,
  vantage: ProbeVantage = { type: "cloudflare_worker", colo: null },
): Promise<{ results: ProbeResult[]; stats: ProbeStats }> {
  const results: ProbeResult[] = new Array(bridges.length);
  const stats: ProbeStats = {
    attempted: 0,
    completed: 0,
    connected: 0,
    refused: 0,
    timedOut: 0,
    inconclusive: 0,
    errored: 0,
    success: 0,
  };

  // Preserve measured fronted-first admission and stable order within each class.
  const frontedFirst: number[] = [];
  const tcpLast: number[] = [];
  for (let index = 0; index < bridges.length; index++) {
    (classifyProbe(bridges[index]) === "tcp" ? tcpLast : frontedFirst).push(index);
  }
  const order = [...frontedFirst, ...tcpLast];
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < order.length) {
      const index = order[nextIndex++];
      const bridge = bridges[index];
      if (signal?.aborted) {
        results[index] = cancelledResult(bridge, vantage);
        stats.completed++;
        stats.inconclusive++;
        continue;
      }

      stats.attempted++;
      const result = await probeOneWithTimeout(bridge, timeoutMs, signal, vantage);
      results[index] = result;
      stats.completed++;
      switch (result.status) {
        case "connected": stats.connected++; stats.success++; break;
        case "refused": stats.refused++; break;
        case "timeout": stats.timedOut++; break;
        case "inconclusive": stats.inconclusive++; break;
        case "error": stats.errored++; break;
      }
    }
  }

  const workerCount = Math.min(Math.max(1, Math.min(maxConcurrent, 6)), bridges.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return { results, stats };
}

/** Exported for the handler's deterministic regression tests. */
export async function probeOneWithTimeout(
  bridge: BridgeDescriptor,
  timeoutMs: number,
  parentSignal?: AbortSignal,
  vantage: ProbeVantage = { type: "cloudflare_worker", colo: null },
): Promise<ProbeResult> {
  const started = Date.now();
  const probeType = classifyProbe(bridge);
  const operationTimeout = probeType === "tcp" ? timeoutMs : FETCH_PROBE_TIMEOUT_MS;
  const controller = new AbortController();
  const unlink = linkAbortSignal(parentSignal, controller);
  const timer = setTimeout(
    () => controller.abort(new ProbeFailure("timeout", "probe_timeout", "S0", "probe timed out")),
    operationTimeout + 250,
  );

  try {
    const outcome = await raceWithSignal(probeOne(bridge, operationTimeout, controller.signal), controller.signal);
    return makeProbeResult(bridge, probeType, vantage, Date.now() - started, outcome);
  } catch (error) {
    const failure = classifyFailure(error);
    return makeProbeResult(bridge, probeType, vantage, Date.now() - started, {
      status: failure.status,
      stage: failure.stage,
      detail: failure.safeDetail,
      errorClass: failure.errorClass,
      httpStatus: failure.httpStatus,
    });
  } finally {
    clearTimeout(timer);
    unlink();
  }
}

async function probeOne(
  bridge: BridgeDescriptor,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<{
  status: "connected";
  stage: "S1" | "S2";
  detail: string;
  httpStatus?: number | null;
}> {
  const probeType = classifyProbe(bridge);
  throwIfAborted(signal);
  switch (probeType) {
    case "tcp":
      await safeTcpProbe(bridge.host, bridge.port, timeoutMs, signal);
      return { status: "connected", stage: "S1", detail: "TCP connection established" };
    case "tls": {
      const httpStatus = await httpsFrontProbe(bridge, timeoutMs, signal);
      return { status: "connected", stage: "S1", detail: "TLS connection returned an HTTP response", httpStatus };
    }
    case "websocket-101": {
      const httpStatus = await wsUpgradeFrontProbe(bridge, timeoutMs, signal);
      return { status: "connected", stage: "S2", detail: "WebTunnel WebSocket upgrade signature verified", httpStatus };
    }
    case "meek-post": {
      const httpStatus = await meekPostProbe(bridge, timeoutMs, signal);
      return { status: "connected", stage: "S2", detail: "meek transact response signature verified", httpStatus };
    }
    case "conjure-registration": {
      const httpStatus = await conjureRegistrationProbe(bridge, timeoutMs, signal);
      return { status: "connected", stage: "S2", detail: "conjure registrar validation signature verified", httpStatus };
    }
    default:
      await safeTcpProbe(bridge.host, bridge.port, timeoutMs, signal);
      return { status: "connected", stage: "S1", detail: "TCP connection established" };
  }
}

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
  signal?: AbortSignal,
): Promise<WorkersSocket> {
  throwIfAborted(signal);
  // @ts-ignore — cloudflare:sockets types are ambient in Workers
  const socket = connect(
    { hostname: toSocketHost(host), port },
    { secureTransport: options.secureTransport } as any,
  ) as unknown as WorkersSocket;
  const removeAbort = closeOnAbort(socket, signal);
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    // `socket.opened` is the documented connection-establishment signal.
    // A quiet readable stream is not evidence of a failed TCP connection.
    if (!socket.opened || typeof socket.opened.then !== "function") {
      throw new ProbeFailure("error", "socket_opened_unavailable", "S0", "socket.opened is unavailable");
    }
    await raceWithSignal(Promise.race([
      socket.opened,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ProbeFailure("timeout", "tcp_connect_timeout", "S0", "TCP connection timed out")),
          timeoutMs,
        );
      }),
    ]), signal);
    return socket;
  } catch (error) {
    closeSocket(socket);
    throw classifyFailure(error);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    removeAbort();
  }
}

async function safeTcpProbe(
  host: string,
  port: number,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<void> {
  const socket = await safeConnect(host, port, { secureTransport: "off" }, timeoutMs, signal);
  // For a TCP liveness check, connection establishment is the full claim.
  // Do not wait for peer data or stream closure; close promptly and release
  // the runtime's outbound-connection slot.
  closeSocket(socket);
}

async function safeTlsProbe(
  host: string,
  port: number,
  sni: string,
  signal: AbortSignal = new AbortController().signal,
): Promise<void> {
  const socket = await safeTlsConnect(sni || host, port, DEFAULT_PROBE_TIMEOUT_MS, signal);
  closeSocket(socket);
}

async function safeWebsocketProbe(bridge: BridgeDescriptor): Promise<void> {
  await wsUpgradeFrontProbe(bridge, DEFAULT_PROBE_TIMEOUT_MS, new AbortController().signal);
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
function toSocketHost(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function hostHeaderValue(host: string, port: number): string {
  const bareHost = toSocketHost(host);
  const headerHost = bareHost.includes(":") ? `[${bareHost}]` : bareHost;
  return port === 443 ? headerHost : `${headerHost}:${port}`;
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
  signal: AbortSignal,
): Promise<WorkersSocket> {
  throwIfAborted(signal);
  // @ts-ignore — cloudflare:sockets types are ambient in Workers
  const socket = connect(
    { hostname: toSocketHost(dialHost), port },
    { secureTransport: "on" } as any,
  ) as unknown as WorkersSocket;
  const removeAbort = closeOnAbort(socket, signal);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (!socket.opened || typeof socket.opened.then !== "function") {
      throw new ProbeFailure("error", "socket_opened_unavailable", "S0", "socket.opened is unavailable");
    }
    await raceWithSignal(Promise.race([
      socket.opened,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ProbeFailure("timeout", "tls_connect_timeout", "S0", "TLS connection timed out")),
          timeoutMs,
        );
      }),
    ]), signal);
    return socket;
  } catch (error) {
    closeSocket(socket);
    throw classifyFailure(error);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    removeAbort();
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
  signal: AbortSignal,
  minimumBodyBytes = 0,
): Promise<{ status: number; statusLine: string; headText: string; bodyText: string }> {
  if (isDocumentationIpv6(bridge.host)) {
    throw new ProbeFailure("inconclusive", "placeholder_target", "S0", "skipped: documentation-prefix IPv6 endpoint placeholder was not probed");
  }

  const started = Date.now();
  const deadline = started + timeoutMs;
  const { dialHost, hostHeader } = frontDialTarget(bridge);
  const port = bridge.port || 443;
  let socket: WorkersSocket | null = null;
  let connectionEstablished = false;
  let removeAbort = () => {};
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  try {
    socket = await safeTlsConnect(dialHost, port, timeoutMs, signal);
    connectionEstablished = true;
    removeAbort = closeOnAbort(socket, signal);
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();

    const requestLines = [
      `${method} ${path} HTTP/1.1`,
      `Host: ${hostHeaderValue(hostHeader, port)}`,
      `User-Agent: ${USER_AGENT}`,
      `Accept: */*`,
      ...extraHeaders,
    ];
    const request = `${requestLines.join("\r\n")}\r\n\r\n`;
    await raceWithSignal(writer.write(new TextEncoder().encode(request)), signal);

    let response = "";
    for (;;) {
      throwIfAborted(signal);
      const headerEnd = response.indexOf("\r\n\r\n");
      if (headerEnd >= 0) {
        const bodyText = response.slice(headerEnd + 4);
        const headerText = response.slice(0, headerEnd);
        const statusCode = Number.parseInt((headerText.split("\r\n")[0] || "").match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i)?.[1] ?? "0", 10);
        const lengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
        const contentLength = lengthMatch ? Number(lengthMatch[1]) : null;
        const needConjureErrorBody = minimumBodyBytes > 0 && statusCode === 400;
        if (!needConjureErrorBody || bodyText.length >= minimumBodyBytes ||
            (contentLength !== null && bodyText.length >= contentLength)) {
          break;
        }
      }
      if (response.length >= 4608) break;
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new ProbeFailure("timeout", "response_timeout", "S1", "connected endpoint did not complete its response before the deadline");
      }
      let readTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        const read = reader.read();
        const result = await raceWithSignal(Promise.race([
          read,
          new Promise<never>((_, reject) => {
            readTimer = setTimeout(
              () => reject(new ProbeFailure("timeout", "response_timeout", "S1", "connected endpoint did not complete its response before the deadline")),
              remaining,
            );
          }),
        ]), signal);
        if (result.done) break;
        response += new TextDecoder("latin1").decode(result.value);
      } finally {
        if (readTimer !== undefined) clearTimeout(readTimer);
      }
    }

    const boundary = response.indexOf("\r\n\r\n");
    if (boundary < 0) {
      throw new ProbeFailure("inconclusive", "http_response_missing", "S1", "connection reached the endpoint but no complete HTTP response head was received");
    }
    const headerText = response.slice(0, boundary);
    const statusLine = (headerText.split("\r\n")[0] || "").trim();
    const match = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
    if (!match) {
      throw new ProbeFailure("inconclusive", "http_status_missing", "S1", "connection reached the endpoint but no valid HTTP status was received");
    }
    return {
      status: Number.parseInt(match[1], 10),
      statusLine,
      headText: `${headerText}\r\n\r\n`,
      bodyText: response.slice(boundary + 4),
    };
  } catch (error) {
    const failure = classifyFailure(error);
    // Preserve the positive TCP-connect stage if cancellation/timeout occurs
    // after socket.opened resolved but before a protocol response completed.
    if (connectionEstablished && failure.stage === "S0") {
      throw new ProbeFailure(
        failure.status,
        failure.errorClass,
        "S1",
        failure.safeDetail,
        failure.httpStatus,
      );
    }
    throw failure;
  } finally {
    removeAbort();
    if (writer) {
      try { writer.releaseLock(); } catch { /* best-effort */ }
    }
    if (reader) {
      try { reader.releaseLock(); } catch { /* best-effort */ }
    }
    if (socket) closeSocket(socket);
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
  signal: AbortSignal,
  websocketKey?: string,
): Promise<{ status: number; statusLine: string; headText: string; bodyText: string }> {
  const extraHeaders: string[] = [];
  if (websocketUpgrade && websocketKey) {
    extraHeaders.push(
      "Connection: Upgrade",
      "Upgrade: websocket",
      `Sec-WebSocket-Key: ${websocketKey}`,
      "Sec-WebSocket-Version: 13",
    );
  }
  return rawTlsExchange(bridge, "GET", frontProbePath(bridge), extraHeaders, timeoutMs, signal);
}

function responseHeaders(headText: string, name: string): string[] {
  const prefix = `${name.toLowerCase()}:`;
  const values: string[] = [];
  for (const line of headText.split("\r\n").slice(1)) {
    if (line.toLowerCase().startsWith(prefix)) values.push(line.slice(prefix.length).trim());
  }
  return values;
}

function uniqueResponseHeader(headText: string, name: string): string | null {
  const values = responseHeaders(headText, name);
  return values.length === 1 ? values[0] : null;
}

async function websocketAcceptForKey(key: string): Promise<string> {
  const input = new TextEncoder().encode(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`);
  const digest = await crypto.subtle.digest("SHA-1", input);
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

/** HTTPS GET is connection/TLS reachability only (S1), never a transport handshake. */
export async function httpsFrontProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
  signal: AbortSignal = new AbortController().signal,
): Promise<number> {
  const { status } = await rawTlsHttpProbe(bridge, false, timeoutMs, signal);
  return status;
}

/** Verify a complete WebSocket upgrade signature, not just a generic 101. */
export async function wsUpgradeFrontProbe(
  bridge: BridgeDescriptor,
  timeoutMs: number = FETCH_PROBE_TIMEOUT_MS,
  signal: AbortSignal = new AbortController().signal,
): Promise<number> {
  const key = generateWebSocketKey();
  const { status, statusLine, headText } = await rawTlsHttpProbe(bridge, true, timeoutMs, signal, key);
  // RFC 6455 opening handshake is HTTP/1.1 101 plus a unique accept signature.
  if (!/^HTTP\/1\.1\s+101\b/i.test(statusLine) || status !== 101) {
    throw new ProbeFailure("inconclusive", "websocket_upgrade_rejected", "S1", "WebTunnel endpoint did not return HTTP 101", status);
  }
  const upgrade = uniqueResponseHeader(headText, "upgrade")?.toLowerCase();
  const connection = uniqueResponseHeader(headText, "connection")?.toLowerCase()
    .split(",").map((value) => value.trim()) ?? [];
  const receivedAccept = uniqueResponseHeader(headText, "sec-websocket-accept");
  const expectedAccept = await websocketAcceptForKey(key);
  if (upgrade !== "websocket" || !connection.includes("upgrade") || receivedAccept !== expectedAccept) {
    throw new ProbeFailure("inconclusive", "websocket_signature_invalid", "S1", "HTTP 101 was returned without a valid WebSocket upgrade signature", status);
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
  signal: AbortSignal = new AbortController().signal,
): Promise<number> {
  const { status, headText } = await rawTlsExchange(
    bridge,
    "POST",
    frontProbePath(bridge),
    [`X-Session-Id: ${generateMeekSessionId()}`, "Content-Length: 0"],
    timeoutMs,
    signal,
  );
  if (status === 200 && headHasHeaderValue(headText, "Content-Type", "application/octet-stream")) {
    return status;
  }
  throw new ProbeFailure(
    "inconclusive",
    "meek_signature_unverified",
    "S1",
    "meek transact response signature was not verified",
    status,
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
  signal: AbortSignal = new AbortController().signal,
): Promise<number> {
  const { status, bodyText } = await rawTlsExchange(
    bridge,
    "POST",
    conjureRegistrationPath(bridge),
    ["Content-Length: 0"],
    timeoutMs,
    signal,
    17,
  );
  if ((status >= 200 && status < 300) || (status === 400 && /payload too small/i.test(bodyText))) {
    return status;
  }
  throw new ProbeFailure(
    "inconclusive",
    "conjure_signature_unverified",
    "S1",
    "conjure registrar validation signature was not verified",
    status,
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
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
