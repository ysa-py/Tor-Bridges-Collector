#!/usr/bin/env node
/**
 * Self-test for scripts/lib/orbot_format.mjs and scripts/lib/iran_antidpi_learn.mjs.
 * Offline, deterministic, exit 1 on the first failed expectation.
 *   node scripts/test_orbot_format.mjs
 */
import assert from "node:assert/strict";
import { repairForOrbot, repairText, isOrbotValid, semanticProblems, cleanBridgeLines } from "./lib/orbot_format.mjs";
import { auc, featurize, parseLite, iranScoreAI } from "./lib/iran_antidpi_learn.mjs";

const FP = "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
const CERT = "p9L6+25s8bnfkye1ZxFeAE4mAGY7DH4Gaj7dxngIIzP9BtqrHHwZXdjMK0RVIQ34C7aqZw";
let passed = 0;
const ok = (name, fn) => {
  fn();
  passed += 1;
  console.log(`  ok  ${name}`);
};

ok("strips the torrc `Bridge ` prefix", () => {
  const r = repairForOrbot(`Bridge obfs4 1.2.3.4:443 ${FP} cert=${CERT} iat-mode=0`);
  assert.equal(r.ok, true);
  assert.equal(r.line.startsWith("obfs4 "), true);
  assert.equal(isOrbotValid(r.line), true);
});
ok("address-less snowflake gets Tor's own dummy address", () => {
  const r = repairForOrbot(`snowflake ${FP} fingerprint=${FP} fingerprint=${FP} url=https://b.example.org/ fronts=a.com,b.net ice=stun:s.example.org:19302`);
  assert.equal(r.ok, true);
  assert.match(r.line, /^snowflake 192\.0\.2\.3:80 [0-9A-F]{40} /);
  assert.equal(r.line.match(/fingerprint=/g).length, 1);
});
ok("address-less meek_lite without fingerprint is repaired", () => {
  const r = repairForOrbot("meek_lite url=https://meek.example.net/ front=ajax.aspnetcdn.com");
  assert.equal(r.ok, true);
  assert.match(r.line, /^meek_lite 192\.0\.2\.18:80 /);
});
ok("unicode spaces are normalised like Orbot does", () => {
  assert.deepEqual(cleanBridgeLines(`1.2.3.4:443\u00a0${FP}\u2009`), [`1.2.3.4:443 ${FP} `]);
  assert.equal(isOrbotValid(`1.2.3.4:443\u00a0${FP}`), true);
});
ok("conjure, comments, bare domains and torrc directives are never passed off as bridges", () => {
  assert.equal(repairForOrbot(`conjure 1.2.3.4:80 ${FP} url=https://x/`).reason, "conjure");
  assert.equal(repairForOrbot("# header").reason, "comment");
  assert.equal(repairForOrbot("azurefd.net").reason, "not-a-bridge");
  assert.equal(repairForOrbot("UseBridges 1").reason, "not-a-bridge");
});
ok("semantic problems Orbot's regex cannot see are caught", () => {
  assert.deepEqual(semanticProblems(`obfs4 1.2.3.999:443 ${FP} cert=${CERT}`), ["octet>255"]);
  assert.deepEqual(semanticProblems(`obfs4 1.2.3.4:70000 ${FP} cert=${CERT}`), ["port-range"]);
  assert.deepEqual(semanticProblems(`obfs4 1.2.3.4:443 ${FP}`), ["obfs4-cert"]);
  assert.deepEqual(semanticProblems(`obfs4 1.2.3.4:443 ${FP} cert=${CERT} iat-mode=1`), []);
});
ok("repairText dedupes and drops dial placeholders but keeps tunnelled dummy addresses", () => {
  const text = [
    `obfs4 192.0.2.10:443 ${FP} cert=${CERT}`,
    `obfs4 5.6.7.8:443 ${FP} cert=${CERT}`,
    `Bridge obfs4 5.6.7.8:443 ${FP} cert=${CERT}`,
    `webtunnel [2001:db8::1]:443 ${FP} url=https://w.example.org/x ver=0.0.1`,
  ].join("\n");
  const { lines, rejected } = repairText(text);
  assert.equal(lines.length, 2);
  assert.equal(rejected["dial-placeholder"], 1);
  assert.equal(rejected.duplicate, 1);
});
ok("AUC helper is exact on trivial cases", () => {
  assert.equal(auc([{ y: 1, p: 0.9 }, { y: 0, p: 0.1 }]), 1);
  assert.equal(auc([{ y: 1, p: 0.1 }, { y: 0, p: 0.9 }]), 0);
  assert.equal(auc([{ y: 1, p: 0.5 }, { y: 0, p: 0.5 }]), 0.5);
});
ok("AI score is a pure prior when no model exists and penalises dense /24s", () => {
  const parsed = parseLite(`obfs4 5.6.7.8:443 ${FP} cert=${CERT} iat-mode=1`);
  const alone = iranScoreAI(parsed, {}, null);
  const crowded = iranScoreAI(parsed, { density: 16 }, null);
  assert.ok(crowded.score < alone.score);
  assert.ok(featurize(parsed).has("port_443"));
});

console.log(`[test-orbot-format] ${passed} checks passed`);
