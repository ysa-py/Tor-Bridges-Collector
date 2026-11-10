#!/usr/bin/env node
// Offline tests for the check-host Iran-datacenter vantage stage. No network.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import {
  buildTargets, classify, parseNodeResult, discoverNodes, isPublicIPv4, planSource, buildRecord,
  pickIranNodes, summarizeVantage,
} from "./lib/iran_vantage.mjs";

let n = 0;
const ok = (name, fn) => { fn(); n += 1; console.log(`  ok  ${name}`); };
const sha = (f) => (fs.existsSync(f) ? crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex") : "absent");
const WORKING = "bridge/iran_likely_working_all.txt";
const before = sha(WORKING);

console.log("fixtures (emitted targets / skip reasons):");
const FIX = [
  ["1 vanilla", "185.220.101.195:443 AABBCCDDEEFF00112233445566778899AABBCCDD", "vanilla", "bridge/vanilla_ipv4.txt"],
  ["2 obfs4 private", "obfs4 10.1.2.3:443 FINGERPRINT cert=abc iat-mode=0", "obfs4", "bridge/obfs4.txt"],
  ["3 meek-azure", "meek_lite 192.0.2.47:80 url=https://reflector.example/path front=ajax.aspnetcdn.com utls=HelloFirefox_Auto", "meek-azure", "bridge/meek-azure.txt"],
  ["4 meek_lite", "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org/secret front=www.phpmyadmin.net", "meek_lite", "bridge/meek_lite.txt"],
  ["5 webtunnel", "webtunnel 85.215.163.16:443 FINGERPRINT url=https://pod.example:8443/jLoIafiPpOBk ver=0.0.3", "webtunnel", "bridge/webtunnel_ipv4.txt"],
  ["6 webtunnel v6", "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://front.example/secret", "webtunnel", "bridge/webtunnel.txt"],
  ["7 snowflake front", "snowflake 10.0.3.2:8080 FINGERPRINT url=https://broker.example/ front=www.gstatic.com", "snowflake", "bridge/snowflake.txt"],
  ["8 snowflake nofront", "snowflake 192.0.2.3:80 FINGERPRINT url=https://broker.example/dns", "snowflake", "bridge/snowflake.txt"],
];
const R = {};
for (const [label, line, tr, file] of FIX) {
  const r = buildTargets(line, tr, file);
  R[label[0]] = r;
  console.log(`  ${label}: targets=${JSON.stringify(r.targets.map((t) => `${t.method} ${t.target}`))} skips=${JSON.stringify(r.skips)}`);
}
const tg = (r) => r.targets.map((t) => `${t.method} ${t.target}`);

ok("1 vanilla -> one tcp target", () => assert.deepEqual(tg(R[1]), ["tcp 185.220.101.195:443"]));
ok("2 private obfs4 -> skipped non_public_address", () => {
  assert.deepEqual(R[2].targets, []);
  assert.deepEqual(R[2].skips, ["non_public_address"]);
});
ok("3 meek-azure keeps transport + line_verb, https front only, no path", () => {
  assert.deepEqual(tg(R[3]), ["https https://ajax.aspnetcdn.com/"]);
  assert.equal(R[3].targets[0].transport, "meek-azure");
  assert.equal(R[3].targets[0].line_verb, "meek_lite");
  assert.ok(!JSON.stringify(R[3]).includes("path"));
});
ok("4 meek_lite.txt -> front https, never tcp", () => assert.deepEqual(tg(R[4]), ["https https://www.phpmyadmin.net/"]));
ok("5 webtunnel -> tcp + https origin, path absent", () => {
  assert.deepEqual(tg(R[5]), ["tcp 85.215.163.16:443", "https https://pod.example:8443/"]);
  assert.ok(!JSON.stringify(R[5]).includes("jLoIaf"));
});
ok("6 webtunnel IPv6 -> no tcp, https origin only", () => {
  assert.deepEqual(tg(R[6]), ["https https://front.example/"]);
  assert.ok(R[6].skips.includes("tcp:ipv6_not_measured"));
});
ok("7 snowflake with front -> front only", () => assert.deepEqual(tg(R[7]), ["https https://www.gstatic.com/"]));
ok("8 snowflake without front -> url origin only", () => assert.deepEqual(tg(R[8]), ["https https://broker.example/"]));

ok("vanilla/obfs4 IPv6 are never measured", () => {
  assert.deepEqual(buildTargets("[2001:db8::2]:9001 AABB", "vanilla", "f").skips, ["ipv6_not_measured"]);
  assert.deepEqual(buildTargets("obfs4 [2001:db8::2]:9001 AABB cert=x", "obfs4", "f").skips, ["ipv6_not_measured"]);
});
ok("leading 'Bridge' is stripped once", () =>
  assert.deepEqual(tg(buildTargets("Bridge obfs4 8.8.8.8:443 FP cert=x", "obfs4", "f")), ["tcp 8.8.8.8:443"]));
ok("reserved ranges are not public", () => {
  for (const a of ["0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.1", "192.0.2.9", "192.168.1.1", "198.51.100.1", "203.0.113.10", "224.0.0.1", "255.255.255.255"]) {
    assert.equal(isPublicIPv4(a), false, a);
  }
  for (const a of ["1.1.1.1", "172.32.0.1", "100.63.0.1", "85.215.163.16"]) assert.equal(isPublicIPv4(a), true, a);
});
ok("placeholders never become tcp targets for fronted transports", () => {
  for (const t of ["meek_lite", "meek-azure", "snowflake", "conjure"]) {
    const r = buildTargets(`${t === "meek-azure" ? "meek_lite" : t} 192.0.2.1:80 FP url=https://a.example/x front=b.example`, t, "f");
    assert.ok(r.targets.every((x) => x.method === "https"));
  }
});

console.log("class decisions:");
const dec = [
  ["tcp", "open", "open"], ["https", "answered", "answered"], ["tcp", "unreachable", "open"],
  ["tcp", "refused", "open"], ["tcp", "unreachable", "unreachable"],
];
for (const [m, i, c] of dec) console.log(`  ${m} iran=${i} control=${c} -> ${classify(m, i, c)}`);
ok("class table", () => {
  assert.equal(classify("tcp", "open", "open"), "iran_tcp_open");
  assert.equal(classify("https", "answered", "answered"), "iran_https_open");
  assert.equal(classify("tcp", "unreachable", "open"), "iran_tcp_unreachable");
  assert.equal(classify("https", "unreachable", "answered"), "iran_https_unreachable");
  assert.equal(classify("tcp", "refused", "open"), "iran_node_refused");
  assert.equal(classify("tcp", "unreachable", "unreachable"), "endpoint_down");
  assert.equal(classify("tcp", "refused", "refused"), "endpoint_down");
  assert.equal(classify("tcp", "open", "unreachable"), "inconclusive");
  assert.equal(classify("tcp", "inconclusive", "open"), "inconclusive");
  assert.equal(classify("tcp", "open", "pending"), "inconclusive");
});
ok("HTTP 403 with flag 1 counts as iran_https_open (string and int codes)", () => {
  const a = parseNodeResult([[1, 0.2, "Forbidden", 403, "1.2.3.4"]], "https");
  const b = parseNodeResult([[1, 0.2, "OK", "200", "1.2.3.4"]], "https");
  assert.deepEqual([a.state, a.code, b.state, b.code], ["answered", "403", "answered", "200"]);
  assert.equal(classify("https", a.state, parseNodeResult([[1, 0.1, "OK", 200, "x"]], "https").state), "iran_https_open");
});
ok("tcp rows: recorded open / timeout / refused / pending / odd shapes", () => {
  assert.equal(parseNodeResult([{ address: "1.1.1.1", time: 0.083 }], "tcp").state, "open");
  assert.equal(parseNodeResult([{ error: "Connection timed out" }], "tcp").state, "unreachable");
  assert.equal(parseNodeResult([{ error: "Connection refused" }], "tcp").state, "refused");
  assert.equal(parseNodeResult(null, "tcp").state, "pending");
  assert.equal(parseNodeResult([null], "tcp").state, "pending");
  assert.equal(parseNodeResult([{ error: "weird" }], "tcp").state, "inconclusive");
  assert.equal(parseNodeResult(["OK", 0.1, "1.1.1.1"], "tcp").state, "open");
  assert.equal(parseNodeResult([[1, 0.1, "OK", 200, "x"]], "tcp").state, "open"); // other shape accepted
  assert.equal(parseNodeResult([{ time: 0.1, address: "x" }], "https").state, "answered");
});
ok("https failures: refused / unreachable / unknown", () => {
  assert.equal(parseNodeResult([[0, 1, "Connection refused", null, null]], "https").state, "refused");
  assert.equal(parseNodeResult([[0, 10, "Connection timed out", null, null]], "https").state, "unreachable");
  assert.equal(parseNodeResult([[0, 1, "???", null, null]], "https").state, "inconclusive");
});
ok("node discovery is dynamic; no Iran node or no control -> unusable", () => {
  const mk = (o) => ({ nodes: Object.fromEntries(Object.entries(o).map(([k, c]) => [`${k}.node.check-host.net`, { asn: " AS1", ip: "9.9.9.9", location: [c, "X", "Y"] }])) });
  const d = discoverNodes(mk({ ir2: "ir", ir1: "ir", nl1: "nl", fr2: "fr" }));
  assert.deepEqual(d.iran.map((x) => x.name.split(".")[0]), ["ir1", "ir2"]);
  assert.equal(d.control.name.startsWith("nl1"), true); // de absent -> nl
  assert.equal(d.iran[0].asn, "AS1");
  assert.equal(discoverNodes(mk({ de1: "de" })).iran.length, 0);
  assert.equal(discoverNodes(mk({ ir1: "ir" })).control, null);
  assert.equal(discoverNodes(mk({ de1: "de", ir1: "IR" })).iran.length, 0); // exact "ir" only
  assert.equal(discoverNodes(null).iran.length, 0);
  assert.equal(discoverNodes(mk({ de1: "de", nl1: "nl" })).control.name.startsWith("de1"), true);
});
ok("planner: cursor advances only past considered lines, wraps, dedupes, respects budget", () => {
  const lines = ["1.1.1.1:443 A", "10.0.0.1:443 B", "2.2.2.2:443 C", "2.2.2.2:443 D", "3.3.3.3:443 E"];
  const seen = new Set();
  let p = planSource({ transport: "vanilla", sourceFile: "f", lines, cursor: 0, take: 2, unit: "calls", callsLeft: 20, seen });
  assert.deepEqual(p.items.map((i) => i.targets[0].target), ["1.1.1.1:443", "2.2.2.2:443"]);
  assert.equal(p.finalCursor, 3); // stopped right after the 2nd taken line (index 2)
  p = planSource({ transport: "vanilla", sourceFile: "f", lines, cursor: 3, take: 2, unit: "calls", callsLeft: 20, seen: new Set() });
  assert.deepEqual(p.items.map((i) => i.targets[0].target), ["2.2.2.2:443", "3.3.3.3:443"]);
  assert.equal(p.finalCursor, 0); // wrapped at the end of the file
  const wt = ["webtunnel 8.8.8.8:443 F url=https://a.example/p"];
  p = planSource({ transport: "webtunnel", sourceFile: "f", lines: wt, cursor: 0, take: 4, unit: "lines", callsLeft: 1, seen: new Set() });
  assert.equal(p.items.length, 0); // two calls needed, one left: line not considered
  assert.equal(p.finalCursor, 0);
  p = planSource({ transport: "webtunnel", sourceFile: "f", lines: wt, cursor: 0, take: 4, unit: "lines", callsLeft: 2, seen: new Set() });
  assert.equal(p.items[0].targets.length, 2);
});
ok("record has the contract keys and no fingerprint/path; class never lands in a list", () => {
  const rec = buildRecord({
    target: R[5].targets[1],
    iranNode: { name: "ir1.node.check-host.net", ip: "185.105.238.209", asn: "AS47430", city: "Tehran" },
    controlNode: { name: "de1.node.check-host.net", country: "de" },
    requestId: "abc", testedAt: "2026-01-01T00:00:00Z",
    iran: { state: "answered", code: "403" }, control: { state: "answered", code: "200" },
  });
  assert.deepEqual(Object.keys(rec), ["transport", "line_verb", "source_file", "method", "target", "tested_at", "vantage", "iran_node", "iran_node_ip", "iran_asn", "iran_city", "control_node", "control_country", "request_id", "iran", "control", "http_code_iran", "http_code_control", "class", "claim_ceiling"]);
  assert.equal(rec.class, "iran_https_open");
  assert.equal(rec.claim_ceiling, "https-from-iran-datacenter-only");
  assert.ok(!/jLoIaf|FINGERPRINT|permanent/.test(JSON.stringify(rec)));
});

// ── multi-node (ir1..irN) selection + aggregate; all fixtures are simulated, never live ──
const IRN = [
  ["ir1", "Tehran"], ["ir2", "Tehran"], ["ir3", "Isfahan"], ["ir4", "Shiraz"], ["ir5", "Qom"],
  ["ir6", "Tehran"], ["ir7", "Shiraz"], ["ir8", "Tehran"], ["ir9", "Tehran"],
].map(([k, city]) => ({ name: `${k}.node.check-host.net`, ip: "x", asn: "AS1", country: "ir", city }));
ok("pickIranNodes: distinct nodes, different cities first, rotates over all 9", () => {
  const a = pickIranNodes(IRN, 0, 3);
  assert.equal(new Set(a.map((x) => x.name)).size, 3);
  assert.equal(new Set(a.map((x) => x.city)).size, 3);
  const seen = new Set();
  for (let o = 0; o < 9; o++) for (const x of pickIranNodes(IRN, o, 3)) seen.add(x.name);
  assert.equal(seen.size, 9);
  assert.deepEqual(pickIranNodes([], 5, 3), []);
  assert.equal(pickIranNodes(IRN.slice(0, 2), 0, 3).length, 2);
});
const rec = (node, cls, t = "2026-11-06T10:00:00Z") => ({
  transport: "obfs4", method: "tcp", target: "8.8.8.8:443", iran_node: node, class: cls, tested_at: t,
});
const NOW = Date.parse("2026-11-06T12:00:00Z");
ok("summary: one failing Iran node is NOT suspected_blocked", () => {
  const s = summarizeVantage([rec("ir1", "iran_tcp_unreachable"), rec("ir2", "inconclusive")], NOW);
  assert.equal(s.targets[0].verdict, "inconclusive");
});
ok("summary: >=2 distinct Iran nodes fail and none opens -> suspected_blocked (datacenter signal only)", () => {
  const s = summarizeVantage([rec("ir1", "iran_tcp_unreachable"), rec("ir3", "iran_tcp_unreachable"), rec("ir1", "iran_tcp_unreachable")], NOW);
  assert.equal(s.targets[0].verdict, "suspected_blocked_from_iran_datacenters");
  assert.match(s.claim_ceiling, /not a Tor/);
});
ok("summary: any Iranian open wins; the same node failing twice counts once; stale rows ignored", () => {
  assert.equal(summarizeVantage([rec("ir1", "iran_tcp_unreachable"), rec("ir2", "iran_tcp_unreachable"), rec("ir3", "iran_tcp_open")], NOW).targets[0].verdict, "reachable_from_iran_datacenter");
  assert.equal(summarizeVantage([rec("ir1", "iran_tcp_unreachable"), rec("ir1", "iran_tcp_unreachable")], NOW).targets[0].verdict, "inconclusive");
  assert.equal(summarizeVantage([rec("ir1", "iran_tcp_unreachable", "2026-11-01T00:00:00Z")], NOW).targets.length, 0);
});
ok("summary: endpoint_down / node_refused never count as a block", () => {
  const s = summarizeVantage([rec("ir1", "endpoint_down"), rec("ir2", "endpoint_down"), rec("ir3", "iran_node_refused")], NOW);
  assert.equal(s.targets[0].verdict, "inconclusive");
});
ok("none of the decisions touched iran_likely_working_all.txt", () => assert.equal(sha(WORKING), before));

console.log(`\niran vantage tests passed: ${n}`);
