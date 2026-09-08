// @ts-ignore — cloudflare:sockets is an ambient Workers runtime module
import { connect } from "cloudflare:sockets";

/**
 * Egress Diagnostic Worker — temporary, evidence-gathering companion to the
 * probe relay (NOT part of the probe pipeline; deployed only on demand by
 * .github/workflows/egress-diagnostic.yml under the name
 * "tor-bridge-probe-relay-diag" and deleted at the end of the same run).
 *
 * Purpose (2026-09-08 session): isolate WHERE the meek_lite / conjure
 * TLS-connect timeouts observed in CI run 34172542990 actually happen —
 * DNS resolution, TCP connect (SYN), TLS handshake (ClientHello), or
 * "not at all / just slow" — by running ONE primitive network operation
 * per request from the real Cloudflare Workers edge and returning the
 * raw timing + verbatim error, with nothing else layered on top.
 *
 * The production relay's probe classes wrap connect() inside protocol
 * exchanges (meek POST, conjure POST), so their errors cannot split the
 * TCP and TLS phases. This worker exposes the primitives directly:
 *
 *   mode "dns"      — DoH A/AAAA lookups for `host` against 1.1.1.1 and
 *                     dns.google from inside the Workers runtime (the
 *                     closest observable proxy for the resolver connect()
 *                     uses; workerd does not expose connect()'s own
 *                     resolution result).
 *   mode "tcp"      — bare TCP connect (secureTransport "off"), no bytes
 *                     sent. Timeout = timeout_ms (default 10000).
 *   mode "tls"      — immediate-TLS connect (secureTransport "on"), the
 *                     exact call the production relay's safeTlsConnect
 *                     makes. Timeout = timeout_ms (default 15000).
 *   mode "starttls" — TCP connect first (timed), then startTls() upgrade
 *                     (timed separately). Splits the TCP and TLS phases.
 *   mode "http"     — bare TCP connect, then a plaintext "GET / HTTP/1.0"
 *                     over the insecure socket. Reports how many response
 *                     bytes (if any) the endpoint answers on :443 without
 *                     TLS — a healthy TLS-only server typically closes
 *                     with 0 bytes, so this distinguishes "something is
 *                     listening" from "connection blackholes".
 *   mode "fetch"    — plain fetch("https://<host>/") — Cloudflare's other
 *                    egress path (edge proxy) for comparison with the
 *                    connect() path.
 *
 * Auth: X-Diag-Token header must match env.DIAG_TOKEN (set per-deploy via
 * `wrangler deploy --var DIAG_TOKEN:...`; the diagnostic workflow
 * generates a fresh random token each run and the worker is deleted when
 * the run ends).
 */

interface DiagRequest {
  host: string;
  port: number;
  mode: "dns" | "tcp" | "tls" | "starttls" | "http" | "fetch";
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

// Local socket interface matching cloudflare:sockets Socket at runtime.
interface DiagSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened?: Promise<unknown>;
  startTls?(): unknown;
  close(): void;
}

function nowMs(): number {
  return Date.now();
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function closeSocket(socket: DiagSocket): void {
  try {
    socket.close();
  } catch {
    // already closed
  }
}

/** Race a promise against a deadline; rejects with `label ... timed out
 *  after Nms` on expiry. Used for every phase so a hang can never wedge a
 *  diagnostic request. */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
        timeoutMs,
      );
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  }) as Promise<T>;
}

async function diagDns(req: DiagRequest): Promise<DiagResult> {
  const t0 = nowMs();
  const resolvers: Array<[string, string]> = [
    ["cloudflare-1.1.1.1", `https://1.1.1.1/dns-query?name=${req.host}&type=A`],
    ["google-dns.google", `https://dns.google/resolve?name=${req.host}&type=A`],
  ];
  const lines: string[] = [];
  let allOk = true;
  for (const [label, url] of resolvers) {
    try {
      const r = await withTimeout(
        fetch(url, { headers: { accept: "application/dns-json" } }),
        10000,
        `DoH ${label}`,
      );
      const body: any = await r.json();
      const answers = (body.Answer ?? []).map((a: any) => `${a.type}:${a.data}`);
      lines.push(
        `${label} status=${body.Status ?? "?"} answers=[${answers.join(", ")}]`,
      );
      if (body.Status !== 0) allOk = allOk && true; // status itself is the finding
    } catch (err) {
      allOk = false;
      lines.push(`${label} error=${errText(err)}`);
    }
  }
  return {
    input: req,
    ok: allOk,
    ms: nowMs() - t0,
    detail: lines.join(" | "),
  };
}

async function diagTcp(req: DiagRequest, timeoutMs: number): Promise<DiagResult> {
  const t0 = nowMs();
  let socket: DiagSocket | null = null;
  try {
    socket = connect(
      { hostname: req.host, port: req.port },
      { secureTransport: "off" } as any,
    ) as unknown as DiagSocket;
    const opened: Promise<unknown> = socket.opened ?? Promise.resolve(undefined);
    await withTimeout(opened, timeoutMs, `TCP connect to ${req.host}:${req.port}`);
    closeSocket(socket);
    return {
      input: req,
      ok: true,
      ms: nowMs() - t0,
      detail: `TCP connect established`,
    };
  } catch (err) {
    if (socket) closeSocket(socket);
    return {
      input: req,
      ok: false,
      ms: nowMs() - t0,
      detail: `TCP connect to ${req.host}:${req.port} failed: ${errText(err)}`,
    };
  }
}

async function diagTls(req: DiagRequest, timeoutMs: number): Promise<DiagResult> {
  const t0 = nowMs();
  let socket: DiagSocket | null = null;
  try {
    socket = connect(
      { hostname: req.host, port: req.port },
      { secureTransport: "on" } as any,
    ) as unknown as DiagSocket;
    const opened: Promise<unknown> = socket.opened ?? Promise.resolve(undefined);
    await withTimeout(
      opened,
      timeoutMs,
      `TLS connect to ${req.host}:${req.port}`,
    );
    closeSocket(socket);
    return {
      input: req,
      ok: true,
      ms: nowMs() - t0,
      detail: `TLS handshake completed (secureTransport "on", same call as production safeTlsConnect)`,
    };
  } catch (err) {
    if (socket) closeSocket(socket);
    return {
      input: req,
      ok: false,
      ms: nowMs() - t0,
      detail: `TLS connect to ${req.host}:${req.port} failed: ${errText(err)}`,
    };
  }
}

async function diagStarttls(req: DiagRequest, timeoutMs: number): Promise<DiagResult> {
  const t0 = nowMs();
  let socket: DiagSocket | null = null;
  try {
    socket = connect(
      { hostname: req.host, port: req.port },
      { secureTransport: "starttls" } as any,
    ) as unknown as DiagSocket;
    const opened: Promise<unknown> = socket.opened ?? Promise.resolve(undefined);
    await withTimeout(opened, timeoutMs, `TCP connect to ${req.host}:${req.port}`);
    const tcpMs = nowMs() - t0;
    if (typeof socket.startTls !== "function") {
      closeSocket(socket);
      return {
        input: req,
        ok: false,
        ms: tcpMs,
        detail: `TCP connected in ${tcpMs}ms but startTls() is not available on this runtime generation`,
      };
    }
    const upgraded: unknown = await withTimeout(
      Promise.resolve(socket.startTls()),
      timeoutMs,
      `startTls() upgrade on ${req.host}:${req.port}`,
    );
    const up = upgraded as DiagSocket;
    const upOpened: Promise<unknown> = up?.opened ?? Promise.resolve(undefined);
    await withTimeout(upOpened, timeoutMs, `TLS handshake (startTls) on ${req.host}:${req.port}`);
    const totalMs = nowMs() - t0;
    if (up && up !== socket) closeSocket(up);
    closeSocket(socket);
    return {
      input: req,
      ok: true,
      ms: totalMs,
      detail: `TCP ${tcpMs}ms + TLS ${totalMs - tcpMs}ms (startTls split)`,
    };
  } catch (err) {
    if (socket) closeSocket(socket);
    return {
      input: req,
      ok: false,
      ms: nowMs() - t0,
      detail: `startTls diag on ${req.host}:${req.port} failed: ${errText(err)}`,
    };
  }
}

async function diagHttp(req: DiagRequest, timeoutMs: number): Promise<DiagResult> {
  const t0 = nowMs();
  let socket: DiagSocket | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  try {
    socket = connect(
      { hostname: req.host, port: req.port },
      { secureTransport: "off" } as any,
    ) as unknown as DiagSocket;
    const opened: Promise<unknown> = socket.opened ?? Promise.resolve(undefined);
    await withTimeout(opened, timeoutMs, `TCP connect to ${req.host}:${req.port}`);
    const tcpMs = nowMs() - t0;

    const writer = socket.writable.getWriter();
    await writer.write(
      new TextEncoder().encode(
        `GET / HTTP/1.0\r\nHost: ${req.host}\r\n\r\n`,
      ),
    );
    writer.releaseLock();

    reader = socket.readable.getReader();
    let received = 0;
    let firstChunk = "";
    const deadline = nowMs() + timeoutMs;
    for (;;) {
      const remaining = deadline - nowMs();
      if (remaining <= 0) {
        throw new Error(`plaintext read timed out after ${timeoutMs}ms`);
      }
      const { value, done } = await withTimeout(
        reader.read(),
        remaining,
        `plaintext read`,
      );
      if (done) break;
      received += value.length;
      if (!firstChunk) {
        firstChunk = new TextDecoder("latin1").decode(value.slice(0, 120));
      }
      if (received > 512) break;
    }
    try {
      reader.releaseLock();
    } catch {
      // already released
    }
    reader = null;
    closeSocket(socket);
    return {
      input: req,
      ok: true,
      ms: nowMs() - t0,
      detail: `TCP ${tcpMs}ms; plaintext GET over :443 received ${received} bytes${firstChunk ? ` first="${firstChunk.replace(/[\r\n]+/g, " | ")}"` : " (connection closed with no bytes — expected for a TLS-only listener)"}`,
    };
  } catch (err) {
    if (reader) {
      try {
        reader.releaseLock();
      } catch {
        // already released
      }
    }
    if (socket) closeSocket(socket);
    return {
      input: req,
      ok: false,
      ms: nowMs() - t0,
      detail: `plaintext-http diag on ${req.host}:${req.port} failed: ${errText(err)}`,
    };
  }
}

async function diagFetch(req: DiagRequest, timeoutMs: number): Promise<DiagResult> {
  const t0 = nowMs();
  try {
    const r = await withTimeout(
      fetch(`https://${req.host}:${req.port}/`, { redirect: "manual" }),
      timeoutMs,
      `fetch https://${req.host}/`,
    );
    return {
      input: req,
      ok: true,
      ms: nowMs() - t0,
      detail: `fetch() (edge-proxy egress path) HTTP ${r.status} ${r.statusText}`,
    };
  } catch (err) {
    return {
      input: req,
      ok: false,
      ms: nowMs() - t0,
      detail: `fetch https://${req.host}/ failed: ${errText(err)}`,
    };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return Response.json({ error: "method_not_allowed" }, { status: 405 });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/diag") {
      return Response.json({ error: "not_found" }, { status: 404 });
    }
    const expected = env.DIAG_TOKEN;
    if (expected && request.headers.get("X-Diag-Token") !== expected) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }

    let req: DiagRequest;
    try {
      req = (await request.json()) as DiagRequest;
    } catch {
      return Response.json({ error: "bad_json_body" }, { status: 400 });
    }
    if (!req || typeof req.host !== "string" || typeof req.port !== "number" || !req.mode) {
      return Response.json({ error: "bad_request" }, { status: 400 });
    }
    const timeoutMs = Math.min(Math.max(req.timeout_ms ?? 10000, 1000), 60000);

    let result: DiagResult;
    switch (req.mode) {
      case "dns":
        result = await diagDns(req);
        break;
      case "tcp":
        result = await diagTcp(req, timeoutMs);
        break;
      case "tls":
        result = await diagTls(req, timeoutMs);
        break;
      case "starttls":
        result = await diagStarttls(req, timeoutMs);
        break;
      case "http":
        result = await diagHttp(req, timeoutMs);
        break;
      case "fetch":
        result = await diagFetch(req, timeoutMs);
        break;
      default:
        return Response.json({ error: `unknown_mode_${req.mode}` }, { status: 400 });
    }
    return Response.json(result);
  },
};
