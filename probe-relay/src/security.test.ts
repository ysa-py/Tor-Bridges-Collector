import { describe, expect, it } from "vitest";
import {
  MAX_BRIDGES_PER_REQUEST,
  constantTimeTokenEqual,
  configuredInteger,
  normalizeAndValidatePublicHost,
  readJsonRequestBody,
  validateBridgeList,
} from "./security";

function descriptor(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "unit-1", host: "example.com", port: 443, transport: "obfs4", ...overrides };
}

describe("public target validation", () => {
  it("accepts public DNS, IPv4, global-unicast IPv6, and IANA global exceptions", () => {
    expect(normalizeAndValidatePublicHost("example.com")).toBe("example.com");
    expect(normalizeAndValidatePublicHost("93.184.216.34")).toBe("93.184.216.34");
    expect(normalizeAndValidatePublicHost("2001:4860:4860::8888")).toBe("2001:4860:4860::8888");
    for (const address of [
      "2001:1::1",
      "2001:1::2",
      "2001:1::3",
      "2001:3::1",
      "2001:4:112::1",
      "2001:20::1",
      "2001:31::1",
    ]) {
      expect(normalizeAndValidatePublicHost(address)).toBe(address);
    }
  });

  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.5",
    "169.254.1.1",
    "100.64.0.1",
    "100.127.255.254",
    "198.18.0.1",
    "198.19.255.254",
    "192.0.0.1",
    "192.88.99.1",
    "192.0.2.10",
    "198.51.100.2",
    "203.0.113.4",
    "0.0.0.0",
    "255.255.255.255",
    "0177.0.0.1",
    "2130706433",
    "0x7f000001",
    "localhost",
    "service.internal",
    "service.example",
    "::",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001::1",
    "2001:0:1::1",
    "2001:2::1",
    "2001:10::1",
    "2001:1::4",
    "2001:100::1",
    "2001:40::1",
    "2001:db8::1",
    "2002:1::1",
    "3fff::1",
    "::ffff:127.0.0.1",
    "::ffff:93.184.216.34",
    "[::1]",
  ])("rejects private, reserved, or ambiguous target %s", (host) => {
    expect(normalizeAndValidatePublicHost(host)).toBeNull();
  });

  it("rejects CR/LF, whitespace, URL syntax, malformed IPv6, and a zone identifier", () => {
    for (const host of ["example.com\r\nHost: evil", " example.com", "https://example.com", "2001:::1", "fe80::1%eth0"]) {
      expect(normalizeAndValidatePublicHost(host)).toBeNull();
    }
  });
});

describe("bridge-list validation", () => {
  it("normalizes allowed transport case and creates a stable id when omitted", () => {
    const input = descriptor({ transport: "WEBTUNNEL" });
    delete input.id;
    const result = validateBridgeList([input]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.bridges[0].transport).toBe("webtunnel");
      expect(result.bridges[0].id).toBe("webtunnel-example.com-443");
    }
  });

  it.each([
    [descriptor({ transport: "unknown-protocol" }), "unsupported_transport"],
    [descriptor({ port: 0 }), "invalid_port"],
    [descriptor({ port: 65536 }), "invalid_port"],
    [descriptor({ port: "443" }), "invalid_port"],
    [descriptor({ host: "127.0.0.1" }), "invalid_or_non_public_host"],
    [descriptor({ sni: "10.0.0.1" }), "invalid_or_non_public_sni"],
    [descriptor({ path: "//evil.example/path" }), "invalid_path"],
    [descriptor({ path: "/safe\r\nHost: evil" }), "invalid_path"],
    [descriptor({ id: "bad\nline" }), "invalid_id"],
    [descriptor({ extra: "unexpected" }), "unknown_descriptor_field"],
    [null, "descriptor_must_be_object"],
  ])("rejects a descriptor before probing", (input, expectedError) => {
    const result = validateBridgeList([input]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe(expectedError);
  });

  it("caps a Worker request at one six-connection wave", () => {
    const result = validateBridgeList(Array.from({ length: MAX_BRIDGES_PER_REQUEST + 1 }, () => descriptor()));
    expect(result).toEqual({ ok: false, status: 413, error: "too_many_bridges" });
  });

  it("does not echo a malformed descriptor or its path in validation errors", () => {
    const result = validateBridgeList([descriptor({ path: "/secret-token\r\nInjected: value" })]);
    expect(JSON.stringify(result)).not.toContain("secret-token");
    expect(JSON.stringify(result)).not.toContain("Injected");
  });
});

describe("bounded JSON request reader", () => {
  it("rejects an oversized declared body before parsing", async () => {
    const request = new Request("https://relay.example/probe", {
      method: "POST",
      headers: { "content-length": "65537", "content-type": "application/json" },
      body: "[]",
    });
    expect(await readJsonRequestBody(request)).toEqual({
      ok: false,
      status: 413,
      error: "body_too_large",
    });
  });

  it("reads valid JSON and returns a structured error for malformed JSON", async () => {
    const valid = new Request("https://relay.example/probe", { method: "POST", body: "[{\"a\":1}]" });
    expect(await readJsonRequestBody(valid)).toEqual({ ok: true, value: [{ a: 1 }] });
    const invalid = new Request("https://relay.example/probe", { method: "POST", body: "{" });
    expect(await readJsonRequestBody(invalid)).toEqual({ ok: false, status: 400, error: "bad_json_body" });
  });
});

describe("constant-time token comparison and config bounds", () => {
  it("compares all content while requiring equal lengths", () => {
    expect(constantTimeTokenEqual("secret", "secret")).toBe(true);
    expect(constantTimeTokenEqual("secreu", "secret")).toBe(false);
    expect(constantTimeTokenEqual("short", "secret")).toBe(false);
    expect(constantTimeTokenEqual(null, "secret")).toBe(false);
  });

  it("rejects invalid configuration rather than accepting NaN or values above the hard cap", () => {
    expect(configuredInteger(undefined, 6, 1, 6)).toBe(6);
    expect(configuredInteger("6", 6, 1, 6)).toBe(6);
    expect(configuredInteger("25", 6, 1, 6)).toBeNull();
    expect(configuredInteger("NaN", 6, 1, 6)).toBeNull();
    expect(configuredInteger("0", 6, 1, 6)).toBeNull();
  });
});
