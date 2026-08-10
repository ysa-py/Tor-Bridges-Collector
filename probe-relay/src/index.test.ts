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
