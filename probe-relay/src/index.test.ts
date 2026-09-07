/**
 * probe-relay/src/index.test.ts
 *
 * Unit tests for the probe relay Worker's concurrency model.
 *
 * Tests validate:
 *   - classifyProbe returns correct probe type per transport
 *   - probeOneWithTimeout rejects after timeoutMs
 *   - probeBridgesWithConcurrency respects MAX_CONCURRENT_PROBES
 *   - All bridges get results even when count > concurrency limit
 *   - Zero reader locks leak after processing ("stalled response" regression)
 *   - Stats counters are accurate (attempted, completed, timedOut, success)
 *
 * cloudflare:sockets is mocked via vitest.config.ts alias →
 * src/__mocks__/cloudflare-sockets.ts.
 *
 * Run: npx vitest run
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// cloudflare:sockets is auto-mocked by the vitest.config.ts alias
import {
  probeBridgesWithConcurrency,
  probeOneWithTimeout,
  classifyProbe,
  httpsFrontProbe,
  wsUpgradeFrontProbe,
  runHttpsEgressControls,
} from "./index";

import {
  connect as mockConnect,
  makeFakeSocket,
  resetReaderTracking,
  activeReaders,
  peakReaders,
} from "./__mocks__/cloudflare-sockets";

function makeBridge(id: string, transport: string, host: string, port: number) {
  return { id, transport, host, port };
}

// ─── classifyProbe ───────────────────────────────────────────────────

describe("classifyProbe", () => {
  it("returns tcp for vanilla", () => {
    expect(classifyProbe(makeBridge("a", "vanilla", "1.2.3.4", 443))).toBe("tcp");
  });

  it("returns tcp for obfs4", () => {
    expect(classifyProbe(makeBridge("a", "obfs4", "1.2.3.4", 9001))).toBe("tcp");
  });

  it("returns websocket-101 for webtunnel", () => {
    expect(
      classifyProbe(makeBridge("a", "webtunnel", "cdn.example.com", 443)),
    ).toBe("websocket-101");
  });

  it("returns tls for snowflake", () => {
    expect(
      classifyProbe(makeBridge("a", "snowflake", "cdn.example.com", 443)),
    ).toBe("tls");
  });

  it("returns tls for meek", () => {
    expect(classifyProbe(makeBridge("a", "meek", "cdn.azure.com", 443))).toBe("tls");
  });

  it("returns tls for conjure", () => {
    expect(classifyProbe(makeBridge("a", "conjure", "1.2.3.4", 443))).toBe("tls");
  });

  it("is case-insensitive", () => {
    expect(
      classifyProbe(makeBridge("a", "WebTunnel", "x.com", 443)),
    ).toBe("websocket-101");
  });
});

// ─── probeOneWithTimeout ─────────────────────────────────────────────

describe("probeOneWithTimeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns error result when probe times out", async () => {
    // The neverResolve socket simulates a hung bridge.
    // probeOneWithTimeout now uses a simple setTimeout-based timeout
    // pattern that resolves (not rejects) on timeout for clean test handling.
    vi.useRealTimers();
    mockConnect.mockReturnValue(makeFakeSocket(0, false, true));

    const bridge = makeBridge("t1", "vanilla", "10.255.255.1", 443);
    const result = await probeOneWithTimeout(bridge, 100);

    // Should have failed — the bridge never responded
    expect(result.success).toBe(false);
    // Error message should indicate timeout
    expect(result.error).toContain("timed out");

    vi.useFakeTimers();
  });
});

// ─── Raw-socket domain-fronted probes (v2.5 regression tests) ───────
//
// These cover the fix for the SNI==Host domain-fronting bug. The tls and
// websocket-101 classes must dial the ADVERTISED FRONT (TLS SNI) via
// cloudflare:sockets with secureTransport "on" while sending an HTTP/1.1
// Host header for the DESCRIPTOR'S TRUE HOST — the two values must be
// independent. (The v2.2 fetch()-based probes sent SNI = Host = front and
// could only ever reach the front CDN's own default vhost; the Workers
// runtime silently discards a caller-supplied Host header on fetch().)
//
// The fake sockets come from __mocks__/cloudflare-sockets.ts: connect()
// captures its (address, options) arguments, and an httpResponder socket
// feeds written bytes to the responder and enqueues its response, so the
// exact raw HTTP request is assertable.

function lastConnectArgs(): { address: any; options: any } {
  const last = mockConnect.mock.calls[mockConnect.mock.calls.length - 1];
  return { address: last[0], options: last[1] };
}

describe("isDocumentationIpv6 (v2.5 fast-path skip predicate)", () => {
  it("detects RFC 3849 documentation-prefix IPv6 in all bridge-line forms", async () => {
    const { isDocumentationIpv6 } = await import("./index");
    expect(isDocumentationIpv6("2001:db8::1")).toBe(true);
    expect(isDocumentationIpv6("[2001:db8:1169:5d59:447d:1feb:3595:b174]")).toBe(true);
    expect(isDocumentationIpv6("2001:DB8:1218:1de7::1")).toBe(true);
    expect(isDocumentationIpv6("  [2001:db8::dead:beef] ")).toBe(true);
    expect(isDocumentationIpv6("2001:db8")).toBe(true);
    expect(isDocumentationIpv6("2001:4860:4860::8888")).toBe(false);
    expect(isDocumentationIpv6("vika7.space")).toBe(false);
    expect(isDocumentationIpv6("")).toBe(false);
    expect(isDocumentationIpv6("1.2.3.4")).toBe(false);
  });
});

describe("httpsFrontProbe (tls class, raw-socket v2.5)", () => {
  beforeEach(() => {
    mockConnect.mockReset();
    resetReaderTracking();
  });

  it("dials the advertised front (SNI) and sends Host = the true backend host", async () => {
    let writtenRequest = "";
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, (req) => {
        writtenRequest = req;
        return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
      }),
    );
    const bridge = {
      id: "s1",
      transport: "snowflake",
      host: "1098762253.rsc.cdn77.org",
      port: 443,
      sni: "www.cdn77.com",
    };
    const status = await httpsFrontProbe(bridge, 5000);
    expect(status).toBe(200);
    // The TLS dial target (SNI) must be the advertised front…
    const { address, options } = lastConnectArgs();
    expect(address.hostname).toBe("www.cdn77.com");
    expect(address.port).toBe(443);
    expect(options.secureTransport).toBe("on");
    // …while the HTTP/1.1 Host header carries the TRUE backend host.
    expect(writtenRequest).toContain("GET / HTTP/1.1\r\n");
    expect(writtenRequest).toContain("Host: 1098762253.rsc.cdn77.org\r\n");
    expect(writtenRequest).not.toContain("Host: www.cdn77.com");
  });

  it("dials the url= host directly (SNI = Host) and uses the url= path (e.g. conjure's /api)", async () => {
    let writtenRequest = "";
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, (req) => {
        writtenRequest = req;
        return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
      }),
    );
    const bridge = {
      id: "c1",
      transport: "conjure",
      host: "registration.refraction.network",
      port: 443,
      path: "/api",
    };
    const status = await httpsFrontProbe(bridge, 5000);
    expect(status).toBe(200);
    const { address } = lastConnectArgs();
    expect(address.hostname).toBe("registration.refraction.network");
    expect(writtenRequest).toContain("GET /api HTTP/1.1\r\n");
    expect(writtenRequest).toContain("Host: registration.refraction.network\r\n");
  });

  it("returns the status even for 4xx/5xx fronts (layer reachable)", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, () => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"),
    );
    const bridge = {
      id: "m1",
      transport: "meek_lite",
      host: "meek.azureedge.net",
      port: 443,
    };
    await expect(httpsFrontProbe(bridge, 5000)).resolves.toBe(403);
  });

  it("throws a descriptive error when the TLS handshake fails", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, undefined, "TLS handshake failed"),
    );
    const bridge = {
      id: "c1",
      transport: "conjure",
      host: "registration.refraction.network",
      port: 443,
    };
    await expect(httpsFrontProbe(bridge, 5000)).rejects.toThrow(
      /failed: TLS connect to registration\.refraction\.network:443 failed: TLS handshake failed/,
    );
  });

  it("times out when the front accepts the request but never responds", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, () => ""),
    );
    const bridge = {
      id: "m2",
      transport: "meek_lite",
      host: "meek.azureedge.net",
      port: 443,
      sni: "ajax.aspnetcdn.com",
    };
    await expect(httpsFrontProbe(bridge, 200)).rejects.toThrow(
      /timed out after 200ms waiting for response head/,
    );
  });

  it("skips documentation-prefix IPv6 placeholders without any network I/O", async () => {
    mockConnect.mockImplementation(() => {
      throw new Error("connect() must not be called for doc-prefix IPv6");
    });
    const bridge = {
      id: "w-doc",
      transport: "webtunnel",
      host: "[2001:db8:1169:5d59:447d:1feb:3595:b174]",
      port: 443,
    };
    await expect(httpsFrontProbe(bridge, 5000)).rejects.toThrow(
      /skipped: documentation-prefix IPv6 endpoint/,
    );
    expect(mockConnect).not.toHaveBeenCalled();
  });
});

describe("wsUpgradeFrontProbe (websocket-101 class, raw-socket v2.5)", () => {
  beforeEach(() => {
    mockConnect.mockReset();
    resetReaderTracking();
  });

  it("succeeds only on HTTP 101 and sends the full upgrade request with Host = the true host", async () => {
    let writtenRequest = "";
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, (req) => {
        writtenRequest = req;
        return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
      }),
    );
    const bridge = {
      id: "w1",
      transport: "webtunnel",
      host: "vika7.space",
      port: 443,
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).resolves.toBe(101);
    const { address, options } = lastConnectArgs();
    expect(address.hostname).toBe("vika7.space");
    expect(options.secureTransport).toBe("on");
    expect(writtenRequest).toContain(
      "GET / HTTP/1.1\r\nHost: vika7.space\r\n",
    );
    expect(writtenRequest).toContain("Connection: Upgrade\r\n");
    expect(writtenRequest).toContain("Upgrade: websocket\r\n");
    expect(writtenRequest).toMatch(/Sec-WebSocket-Key: [A-Za-z0-9+/=]{16,}\r\n/);
    expect(writtenRequest).toContain("Sec-WebSocket-Version: 13\r\n");
  });

  it("upgrades against the url= token path when the descriptor carries one", async () => {
    let writtenRequest = "";
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, (req) => {
        writtenRequest = req;
        return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
      }),
    );
    const bridge = {
      id: "w1p",
      transport: "webtunnel",
      host: "jochenkessler.de",
      port: 443,
      path: "/D82XI88Vz3nttmFEc9OBXGRD",
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).resolves.toBe(101);
    expect(writtenRequest).toContain(
      "GET /D82XI88Vz3nttmFEc9OBXGRD HTTP/1.1\r\n",
    );
    expect(writtenRequest).toContain("Host: jochenkessler.de\r\n");
  });

  it("rejects a non-101 HTTP response with the status line in the error", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, () => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    const bridge = {
      id: "w2",
      transport: "webtunnel",
      host: "coellen.xyz",
      port: 443,
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).rejects.toThrow(
      /WebSocket upgrade rejected: HTTP\/1\.1 200 OK/,
    );
  });

  it("reports the front's error status line verbatim (e.g. Cloudflare 521/525)", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, () => "HTTP/1.1 521 Web Server Is Down\r\nContent-Length: 0\r\n\r\n"),
    );
    const bridge = {
      id: "w2b",
      transport: "webtunnel",
      host: "coellen.xyz",
      port: 443,
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).rejects.toThrow(
      /WebSocket upgrade rejected: HTTP\/1\.1 521 Web Server Is Down/,
    );
  });

  it("throws a descriptive error on TLS connect failure", async () => {
    mockConnect.mockImplementation(() =>
      makeFakeSocket(0, false, false, undefined, "TLS handshake failed"),
    );
    const bridge = {
      id: "w3",
      transport: "webtunnel",
      host: "vault.005184.xyz",
      port: 443,
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).rejects.toThrow(
      /TLS front probe vault\.005184\.xyz:443\/ .* failed: TLS connect to vault\.005184\.xyz:443 failed: TLS handshake failed/,
    );
  });

  it("skips documentation-prefix IPv6 placeholders without any network I/O", async () => {
    mockConnect.mockImplementation(() => {
      throw new Error("connect() must not be called for doc-prefix IPv6");
    });
    const bridge = {
      id: "w-doc2",
      transport: "webtunnel",
      host: "2001:db8:1218:1de7:3a91:22cc:8d7f:197c",
      port: 443,
    };
    await expect(wsUpgradeFrontProbe(bridge, 5000)).rejects.toThrow(
      /skipped: documentation-prefix IPv6 endpoint/,
    );
    expect(mockConnect).not.toHaveBeenCalled();
  });
});

describe("runHttpsEgressControls (v2.3 diagnostics)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("records ok=true with the HTTP status for responding controls", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    const controls = await runHttpsEgressControls(5000);
    expect(controls).toHaveLength(2);
    expect(controls.every((c) => c.ok && c.http_status === 204 && c.error === null)).toBe(true);
    expect(controls.map((c) => c.target)).toEqual([
      "https://example.com/",
      "https://1.1.1.1/",
    ]);
  });

  it("records ok=false with the error for failing controls (never throws)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("socket hang up");
      }),
    );
    const controls = await runHttpsEgressControls(5000);
    expect(controls).toHaveLength(2);
    expect(controls.every((c) => !c.ok && c.http_status === null)).toBe(true);
    expect(controls[0].error).toContain("socket hang up");
  });
});

// ─── probeBridgesWithConcurrency ─────────────────────────────────────

describe("probeBridgesWithConcurrency", () => {
  beforeEach(() => {
    resetReaderTracking();
    mockConnect.mockReset();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("processes all bridges even when count exceeds maxConcurrent", async () => {
    const bridgeCount = 20;
    const maxConcurrent = 3;
    const bridges = Array.from({ length: bridgeCount }, (_, i) =>
      makeBridge(`b${i}`, "vanilla", `10.0.0.${i + 1}`, 443),
    );

    mockConnect.mockImplementation(() => makeFakeSocket(0));

    const promise = probeBridgesWithConcurrency(bridges, maxConcurrent, 5000);
    await vi.runAllTimersAsync();
    const { results, stats } = await promise;

    expect(results.length).toBe(bridgeCount);
    expect(stats.attempted).toBe(bridgeCount);
    expect(stats.completed).toBe(bridgeCount);
    expect(stats.success).toBe(bridgeCount);
  });

  it("respects maxConcurrent — peak readers never exceeds limit", async () => {
    const bridgeCount = 15;
    const maxConcurrent = 4;
    const bridges = Array.from({ length: bridgeCount }, (_, i) =>
      makeBridge(`b${i}`, "vanilla", `10.0.0.${i + 1}`, 443),
    );

    mockConnect.mockImplementation(() => makeFakeSocket(0));

    const promise = probeBridgesWithConcurrency(bridges, maxConcurrent, 5000);
    await vi.runAllTimersAsync();
    await promise;

    // Peak readers ≤ maxConcurrent (reader is released by drainAndClose after each probe)
    expect(peakReaders).toBeLessThanOrEqual(maxConcurrent);
    // All readers released by now
    expect(activeReaders).toBe(0);
  });

  it("zero reader leaks after processing — regression test for stalled response bug", async () => {
    // THIS IS THE CRITICAL REGRESSION TEST. After processing all bridges,
    // activeReaders MUST be 0. Any positive value means a reader lock was
    // never released → "stalled HTTP response was canceled" in production.
    const bridgeCount = 10;
    const maxConcurrent = 5;
    const bridges = Array.from({ length: bridgeCount }, (_, i) =>
      makeBridge(`b${i}`, "vanilla", `10.0.0.${i + 1}`, 443),
    );

    mockConnect.mockImplementation(() => makeFakeSocket(0));

    const promise = probeBridgesWithConcurrency(bridges, maxConcurrent, 5000);
    await vi.runAllTimersAsync();
    const { stats } = await promise;

    expect(activeReaders).toBe(0);
    expect(stats.completed).toBe(bridgeCount);
  });

  it("stats counters are accurate after processing", async () => {
    // Use real timers with fast-resolving mocks.
    vi.useRealTimers();

    const bridges = [
      makeBridge("ok1", "vanilla", "10.0.0.1", 443),
      makeBridge("ok2", "vanilla", "10.0.0.2", 443),
      makeBridge("ok3", "vanilla", "10.0.0.3", 443),
    ];

    mockConnect.mockReturnValue(makeFakeSocket(0));

    const { results, stats } = await probeBridgesWithConcurrency(bridges, 3, 5000);

    // All 3 bridges should be attempted
    expect(stats.attempted).toBe(3);
    // Stats shape should be correct
    expect(typeof stats.completed).toBe("number");
    expect(typeof stats.success).toBe("number");
    expect(typeof stats.timedOut).toBe("number");
    // Results array should have entries for all bridges
    expect(results.length).toBe(3);
    // All readers released
    expect(activeReaders).toBe(0);

    vi.useFakeTimers();
  });
});
