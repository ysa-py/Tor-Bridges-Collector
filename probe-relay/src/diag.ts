// @ts-ignore — cloudflare:sockets is an ambient Workers runtime module
import { connect } from "cloudflare:sockets";
import {
  constantTimeTokenEqual,
  normalizeAndValidatePublicHost,
  readJsonRequestBody,
} from "./security";

/**
 * Temporary egress-diagnostic Worker. It is deployed only by
 * .github/workflows/egress-diagnostic.yml under a separate Worker name and is
 * deleted at the end of that workflow. Every operation is authenticated,
 * bounded, limited to validated public targets, and returns redacted details.
 */

type DiagMode = "dns" | "tcp" | "tls" | "starttls" | "http" | "fetch";
interface DiagRequest {
  host: string;
  port: number;
  mode: DiagMode;
  timeout_ms?: number;
}
interface DiagResult {
  input: DiagRequest;
  ok: boolean;
  ms: number;
  detail: string;
}
interface Env {
  DIAG_TOKEN?: string;
}
interface DiagSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened?: Promise<unknown>;
  startTls?(): unknown;
  close(): void | Promise<void>;
}

const MAX_BODY_BYTES = 4096;
const BODY_TIMEOUT_MS = 5000;
const REQUEST_DEADLINE_MS = 60000;
const ALLOWED_MODES = new Set<DiagMode>(["dns", "tcp", "tls", "starttls", "http", "fetch"]);
const ALLOWED_FIELDS = new Set(["host", "port", "mode", "timeout_ms"]);

function closeSocket(socket: DiagSocket | null | undefined): void {
  try {
    if (socket) void Promise.resolve(socket.close()).catch(() => {});
  } catch { /* best effort */ }
}

function socketHost(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function urlHost(host: string): string {
  const bare = socketHost(host);
  return bare.includes(":") ? `[${bare}]` : bare;
}

function classifyError(error: unknown): string {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (message.includes("timeout") || message.includes("timed out")) return "timed_out";
  if (message.includes("refused") || message.includes("econnrefused")) return "connection_refused";
  if (/(cloudflare|egress|private|reserved).*(block|deny|restrict|not allowed|unavailable)/i.test(message)) return "egress_policy";
  if (message.includes("dns") || message.includes("enotfound") || message.includes("nxdomain")) return "dns_resolution_failed";
  if (message.includes("tls") || message.includes("certificate") || message.includes("handshake")) return "tls_handshake_failed";
  if (message === "caller_cancelled") return "caller_cancelled";
  return "network_error";
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error && signal.reason.message === "operation_timeout"
    ? new Error("operation_timeout")
    : new Error("caller_cancelled");
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(abortError(signal));
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => finish(() => reject(new Error("operation_timeout"))), timeoutMs);
    const onAbort = () => finish(() => reject(abortError(signal)));
    const finish = (action: () => void) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      action();
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => finish(() => resolve(value)),
      () => finish(() => reject(new Error("network_error"))),
    );
  });
}

function closeOnAbort(socket: DiagSocket, signal: AbortSignal): () => void {
  const close = () => closeSocket(socket);
  if (signal.aborted) close();
  else signal.addEventListener("abort", close, { once: true });
  return () => signal.removeEventListener("abort", close);
}

function makeSocket(host: string, port: number, secureTransport: "off" | "on" | "starttls"): DiagSocket {
  return connect(
    { hostname: socketHost(host), port },
    { secureTransport } as any,
  ) as unknown as DiagSocket;
}

async function waitForOpened(socket: DiagSocket, timeoutMs: number, signal: AbortSignal): Promise<void> {
  if (!socket.opened || typeof socket.opened.then !== "function") {
    throw new Error("socket_opened_unavailable");
  }
  await withTimeout(socket.opened, timeoutMs, signal);
}

function buildResult(req: DiagRequest, started: number, ok: boolean, detail: string): DiagResult {
  return { input: req, ok, ms: Math.max(0, Date.now() - started), detail: detail.slice(0, 512) };
}

async function diagDns(req: DiagRequest, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  const targets: Array<[string, string]> = [
    ["cloudflare-1.1.1.1", "https://1.1.1.1/dns-query"],
    ["google-dns.google", "https://dns.google/resolve"],
  ];
  const results = await Promise.all(targets.map(async ([label, endpoint]) => {
    const query = new URL(endpoint);
    query.searchParams.set("name", req.host);
    query.searchParams.set("type", "A");
    let response: Response | null = null;
    try {
      response = await withTimeout(fetch(query, {
        headers: { accept: "application/dns-json" },
        signal,
      }), Math.min(req.timeout_ms ?? 10000, 10000), signal);
      const body = await withTimeout(response.json() as Promise<Record<string, unknown>>, 3000, signal);
      const status = Number.isInteger(body.Status) ? body.Status : null;
      const answers = Array.isArray(body.Answer)
        ? body.Answer.slice(0, 8).map((answer) => {
          if (answer === null || typeof answer !== "object") return "invalid";
          const record = answer as Record<string, unknown>;
          const type = typeof record.type === "number" && Number.isInteger(record.type) ? record.type : "?";
          const data = typeof record.data === "string" && /^[0-9a-fA-F:.]{1,64}$/.test(record.data) ? record.data : "non-address";
          return `${type}:${data}`;
        })
        : [];
      return { ok: response.ok, detail: `${label} http=${response.status} dns_status=${status ?? "unknown"} answers=[${answers.join(",")}]` };
    } catch (error) {
      try { void response?.body?.cancel().catch(() => {}); } catch { /* already consumed */ }
      return { ok: false, detail: `${label} error=${classifyError(error)}` };
    }
  }));
  return buildResult(req, started, results.some((result) => result.ok), results.map((result) => result.detail).join(" | "));
}

async function diagTcp(req: DiagRequest, timeoutMs: number, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  let socket: DiagSocket | null = null;
  let unlink = () => {};
  try {
    socket = makeSocket(req.host, req.port, "off");
    unlink = closeOnAbort(socket, signal);
    await waitForOpened(socket, timeoutMs, signal);
    return buildResult(req, started, true, "TCP connection established");
  } catch (error) {
    return buildResult(req, started, false, `TCP connect failed: ${classifyError(error)}`);
  } finally {
    unlink();
    closeSocket(socket);
  }
}

async function diagTls(req: DiagRequest, timeoutMs: number, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  let socket: DiagSocket | null = null;
  let unlink = () => {};
  try {
    socket = makeSocket(req.host, req.port, "on");
    unlink = closeOnAbort(socket, signal);
    await waitForOpened(socket, timeoutMs, signal);
    return buildResult(req, started, true, 'TLS handshake completed (secureTransport "on")');
  } catch (error) {
    return buildResult(req, started, false, `TLS connect failed: ${classifyError(error)}`);
  } finally {
    unlink();
    closeSocket(socket);
  }
}

async function diagStarttls(req: DiagRequest, timeoutMs: number, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  let socket: DiagSocket | null = null;
  let upgradedSocket: DiagSocket | null = null;
  let unlinkSocket = () => {};
  let unlinkUpgrade = () => {};
  try {
    socket = makeSocket(req.host, req.port, "starttls");
    unlinkSocket = closeOnAbort(socket, signal);
    await waitForOpened(socket, timeoutMs, signal);
    const tcpMs = Date.now() - started;
    if (typeof socket.startTls !== "function") {
      return buildResult(req, started, false, `TCP connected in ${tcpMs}ms; startTls unavailable`);
    }
    const upgraded = await withTimeout(Promise.resolve(socket.startTls()), timeoutMs, signal);
    upgradedSocket = upgraded as DiagSocket;
    if (!upgradedSocket || typeof upgradedSocket.close !== "function") {
      return buildResult(req, started, false, "startTls returned an invalid socket");
    }
    unlinkUpgrade = closeOnAbort(upgradedSocket, signal);
    await waitForOpened(upgradedSocket, timeoutMs, signal);
    const totalMs = Date.now() - started;
    return buildResult(req, started, true, `TCP ${tcpMs}ms + TLS ${totalMs - tcpMs}ms (startTls split)`);
  } catch (error) {
    return buildResult(req, started, false, `startTls failed: ${classifyError(error)}`);
  } finally {
    unlinkUpgrade();
    unlinkSocket();
    closeSocket(upgradedSocket);
    closeSocket(socket);
  }
}

async function diagHttp(req: DiagRequest, timeoutMs: number, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  let socket: DiagSocket | null = null;
  let unlink = () => {};
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let tcpMs = 0;
  try {
    socket = makeSocket(req.host, req.port, "off");
    unlink = closeOnAbort(socket, signal);
    await waitForOpened(socket, timeoutMs, signal);
    tcpMs = Date.now() - started;

    writer = socket.writable.getWriter();
    const host = urlHost(req.host);
    await withTimeout(writer.write(new TextEncoder().encode(
      `GET / HTTP/1.0\r\nHost: ${hostHeader(host, req.port)}\r\n\r\n`,
    )), timeoutMs, signal);
    writer.releaseLock();
    writer = null;

    reader = socket.readable.getReader();
    let received = 0;
    let status = "no_status_line";
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("operation_timeout");
      const result = await withTimeout(reader.read(), remaining, signal);
      if (result.done) break;
      received += result.value.byteLength;
      if (status === "no_status_line") {
        const prefix = new TextDecoder("latin1").decode(result.value.slice(0, 128));
        const match = prefix.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
        if (match) status = `http_status=${match[1]}`;
      }
      if (received >= 512) break;
    }
    return buildResult(req, started, true, `TCP ${tcpMs}ms; plaintext probe received ${received} bytes; ${status}`);
  } catch (error) {
    return buildResult(req, started, false, `plaintext probe failed: ${classifyError(error)}`);
  } finally {
    if (writer) {
      try { writer.releaseLock(); } catch { /* already released */ }
    }
    if (reader) {
      try { await reader.cancel().catch(() => {}); } catch { /* socket already closed */ }
      try { reader.releaseLock(); } catch { /* already released */ }
    }
    unlink();
    closeSocket(socket);
  }
}

function hostHeader(host: string, port: number): string {
  const formatted = urlHost(host);
  return port === 443 ? formatted : `${formatted}:${port}`;
}

async function diagFetch(req: DiagRequest, timeoutMs: number, signal: AbortSignal): Promise<DiagResult> {
  const started = Date.now();
  let response: Response | null = null;
  try {
    const target = `https://${urlHost(req.host)}:${req.port}/`;
    response = await withTimeout(fetch(target, { redirect: "manual", signal }), timeoutMs, signal);
    const result = buildResult(req, started, true, `fetch egress returned HTTP ${response.status}`);
    await response.body?.cancel().catch(() => {});
    return result;
  } catch (error) {
    try { await response?.body?.cancel(); } catch { /* already canceled */ }
    return buildResult(req, started, false, `fetch failed: ${classifyError(error)}`);
  }
}

function badRequest(error: string, status = 400): Response {
  return Response.json({ error }, { status });
}

function normalizeDiagHost(value: unknown, mode: DiagMode): string | null {
  const publicHost = normalizeAndValidatePublicHost(value);
  if (publicHost) return publicHost;
  // .invalid is a reserved DNS test suffix. Permit it only for DNS-over-HTTPS
  // queries, which are sent to fixed public resolvers; never dial it as a target.
  if (mode !== "dns" || typeof value !== "string" || value.length > 253 ||
      value !== value.trim() || /[\\/@?#\s\u0000-\u001f\u007f]/.test(value)) return null;
  const name = value.toLowerCase().replace(/\.$/, "");
  const labels = name.split(".");
  if (!name.endsWith(".invalid") || labels.length < 2 || labels.some((label) =>
    label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  )) return null;
  return name;
}

function validateDiagRequest(value: unknown): { ok: true; request: DiagRequest } | { ok: false; error: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return { ok: false, error: "request_must_be_object" };
  const object = value as Record<string, unknown>;
  if (Object.keys(object).some((key) => !ALLOWED_FIELDS.has(key))) return { ok: false, error: "unknown_request_field" };
  if (typeof object.mode !== "string" || !ALLOWED_MODES.has(object.mode as DiagMode)) {
    return { ok: false, error: "invalid_mode" };
  }
  const mode = object.mode as DiagMode;
  const host = normalizeDiagHost(object.host, mode);
  if (!host) return { ok: false, error: "invalid_or_non_public_host" };
  if (!Number.isInteger(object.port) || (object.port as number) < 1 || (object.port as number) > 65535) {
    return { ok: false, error: "invalid_port" };
  }
  const timeoutMs = object.timeout_ms ?? 10000;
  if (!Number.isInteger(timeoutMs) || (timeoutMs as number) < 1000 || (timeoutMs as number) > REQUEST_DEADLINE_MS) {
    return { ok: false, error: "invalid_timeout_ms" };
  }
  return {
    ok: true,
    request: {
      host,
      port: object.port as number,
      mode: object.mode as DiagMode,
      timeout_ms: timeoutMs as number,
    },
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method !== "POST") return badRequest("method_not_allowed", 405);
      if (new URL(request.url).pathname !== "/diag") return badRequest("not_found", 404);

      const expected = env.DIAG_TOKEN;
      if (typeof expected !== "string" || expected.trim() === "" || expected.length < 16 || expected.length > 1024 ||
          /[\u0000-\u001f\u007f]/.test(expected)) {
        return badRequest("service_unavailable", 503);
      }
      if (!constantTimeTokenEqual(request.headers.get("X-Diag-Token"), expected)) {
        return badRequest("unauthorized", 401);
      }
      const mediaType = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
      if (mediaType !== "application/json") return badRequest("unsupported_media_type", 415);

      const body = await readJsonRequestBody(request, MAX_BODY_BYTES, BODY_TIMEOUT_MS);
      if (!body.ok) return badRequest(body.error, body.status);
      const checked = validateDiagRequest(body.value);
      if (!checked.ok) return badRequest(checked.error);
      const diagRequest = checked.request;
      const timeoutMs = diagRequest.timeout_ms ?? 10000;

      const controller = new AbortController();
      const onCallerAbort = () => controller.abort(new Error("caller_cancelled"));
      if (request.signal.aborted) onCallerAbort();
      else request.signal.addEventListener("abort", onCallerAbort, { once: true });
      const deadline = setTimeout(() => controller.abort(new Error("operation_timeout")), REQUEST_DEADLINE_MS);
      try {
        let result: DiagResult;
        switch (diagRequest.mode) {
          case "dns": result = await diagDns(diagRequest, controller.signal); break;
          case "tcp": result = await diagTcp(diagRequest, timeoutMs, controller.signal); break;
          case "tls": result = await diagTls(diagRequest, timeoutMs, controller.signal); break;
          case "starttls": result = await diagStarttls(diagRequest, timeoutMs, controller.signal); break;
          case "http": result = await diagHttp(diagRequest, timeoutMs, controller.signal); break;
          case "fetch": result = await diagFetch(diagRequest, timeoutMs, controller.signal); break;
        }
        return Response.json(result);
      } finally {
        clearTimeout(deadline);
        request.signal.removeEventListener("abort", onCallerAbort);
      }
    } catch {
      // Do not serialize raw exceptions or peer-controlled strings.
      return badRequest("internal_error", 500);
    }
  },
};
