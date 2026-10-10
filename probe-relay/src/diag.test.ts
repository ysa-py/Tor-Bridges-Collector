import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import diagWorker from "./diag";
import { connect as mockConnect, makeFakeSocket } from "./__mocks__/cloudflare-sockets";

const TOKEN = "diagnostic-test-secret-value";

function request(
  body: string,
  token: string | null = TOKEN,
  contentType = "application/json",
  signal?: AbortSignal,
): Request {
  const headers = new Headers({ "Content-Type": contentType });
  if (token !== null) headers.set("X-Diag-Token", token);
  return new Request("https://diag.example/diag", { method: "POST", headers, body, signal });
}

describe("protected diagnostic Worker", () => {
  beforeEach(() => mockConnect.mockReset());
  afterEach(() => vi.restoreAllMocks());

  it("fails closed with 503 when DIAG_TOKEN is missing, blank, or invalid", async () => {
    for (const env of [{}, { DIAG_TOKEN: "   " }, { DIAG_TOKEN: "short" }]) {
      const response = await diagWorker.fetch(request("{}"), env);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "service_unavailable" });
    }
    expect(mockConnect).not.toHaveBeenCalled();
  });

  it("requires a constant-time-matched token before reading or probing the body", async () => {
    for (const token of [null, "wrong-diagnostic-secret"]) {
      const response = await diagWorker.fetch(request("not-json", token), { DIAG_TOKEN: TOKEN });
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "unauthorized" });
    }
    expect(mockConnect).not.toHaveBeenCalled();
  });

  it("returns structured errors for media type, malformed JSON, and oversized bodies", async () => {
    const wrongType = await diagWorker.fetch(request("{}", TOKEN, "text/plain"), { DIAG_TOKEN: TOKEN });
    expect(wrongType.status).toBe(415);
    expect(await wrongType.json()).toEqual({ error: "unsupported_media_type" });

    const malformed = await diagWorker.fetch(request("{"), { DIAG_TOKEN: TOKEN });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: "bad_json_body" });

    // Exercise the explicit declared-size path without allocating a large body.
    const declaredOversize = new Request("https://diag.example/diag", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": "4097", "X-Diag-Token": TOKEN },
      body: "{}",
    });
    const large = await diagWorker.fetch(declaredOversize, { DIAG_TOKEN: TOKEN });
    expect(large.status).toBe(413);
    expect(await large.json()).toEqual({ error: "body_too_large" });
  });

  it("rejects invalid targets, ranges, modes, and extra fields before connect()", async () => {
    const cases = [
      { host: "127.0.0.1", port: 443, mode: "tcp" },
      { host: "10.0.0.1", port: 443, mode: "tcp" },
      { host: "definitely-not-real.invalid", port: 443, mode: "tcp" },
      { host: "example.com\r\nHost: evil", port: 443, mode: "tcp" },
      { host: "example.com", port: 0, mode: "tcp" },
      { host: "example.com", port: 65536, mode: "tcp" },
      { host: "example.com", port: "443", mode: "tcp" },
      { host: "example.com", port: 443, mode: "connect" },
      { host: "example.com", port: 443, mode: "tcp", extra: "bad" },
      { host: "example.com", port: 443, mode: "tcp", timeout_ms: "1000" },
      { host: "example.com", port: 443, mode: "tcp", timeout_ms: 60001 },
    ];
    for (const item of cases) {
      const response = await diagWorker.fetch(request(JSON.stringify(item)), { DIAG_TOKEN: TOKEN });
      expect(response.status).toBe(400);
      expect(await response.json()).toHaveProperty("error");
    }
    expect(mockConnect).not.toHaveBeenCalled();
  });

  it("allows the reserved .invalid name only as a DNS question, never as a socket target", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ Status: 3, Answer: [] }), { status: 200 }),
    );
    const response = await diagWorker.fetch(
      request(JSON.stringify({ host: "definitely-not-real.invalid", port: 443, mode: "dns" })),
      { DIAG_TOKEN: TOKEN },
    );
    expect(response.status).toBe(200);
    const body: any = await response.json();
    expect(body.input.host).toBe("definitely-not-real.invalid");
    expect(body.detail).toContain("dns_status=3");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(mockConnect).not.toHaveBeenCalled();
  });

  it("returns a structured, redacted TCP observation for a valid public target", async () => {
    mockConnect.mockReturnValue(makeFakeSocket(0, false, true));
    const response = await diagWorker.fetch(
      request(JSON.stringify({ host: "example.com", port: 443, mode: "tcp", timeout_ms: 1000 })),
      { DIAG_TOKEN: TOKEN },
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const body: any = await response.json();
    expect(body).toMatchObject({
      input: { host: "example.com", port: 443, mode: "tcp", timeout_ms: 1000 },
      ok: true,
      detail: "TCP connection established",
    });
    expect(body.ms).toEqual(expect.any(Number));
  });

  it("closes a socket when the caller cancels a probe", async () => {
    const socket = makeFakeSocket(0, false, true);
    socket.opened = new Promise(() => {});
    const close = socket.close.bind(socket);
    let closed = false;
    socket.close = () => { closed = true; close(); };
    mockConnect.mockReturnValue(socket);

    const controller = new AbortController();
    const pending = diagWorker.fetch(
      request(JSON.stringify({ host: "example.com", port: 443, mode: "tcp", timeout_ms: 60000 }), TOKEN, "application/json", controller.signal),
      { DIAG_TOKEN: TOKEN },
    );
    for (let attempt = 0; attempt < 10 && !mockConnect.mock.calls.length; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(mockConnect).toHaveBeenCalledTimes(1);
    controller.abort();
    const response = await pending;
    expect(response.status).toBe(200);
    expect(closed).toBe(true);
    const body: any = await response.json();
    expect(body.ok).toBe(false);
    expect(body.detail).toContain("caller_cancelled");
  });
});
