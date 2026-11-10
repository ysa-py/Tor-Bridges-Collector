#!/usr/bin/env node
import assert from "node:assert/strict";
import { thompsonMix, allocateSlots, shapeLine, buildAdaptiveList, MIX_TRANSPORTS, UTLS_PROFILES } from "./lib/iran_antidpi_adaptive.mjs";
import { isOrbotValid, repairForOrbot, scrubLine } from "./lib/orbot_format.mjs";

let n = 0;
const ok = (name, fn) => { fn(); n += 1; console.log(`  ok  ${name}`); };
const cert = "A".repeat(44);

ok("thompson mix is deterministic per seed, sums to 1 and honours the floor", () => {
  const ev = { webtunnel: { positive: 80, negative: 5 }, obfs4: { positive: 3, negative: 90 } };
  const a = thompsonMix(ev, 42), b = thompsonMix(ev, 42), c = thompsonMix(ev, 43);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a.shares, c.shares);
  assert.ok(Math.abs(Object.values(a.shares).reduce((x, y) => x + y, 0) - 1) < 1e-9);
  for (const t of MIX_TRANSPORTS) assert.ok(a.shares[t] >= 0.03);
});
ok("a transport with strong evidence wins most hours against a burnt one", () => {
  const ev = { webtunnel: { positive: 120, negative: 4 }, obfs4: { positive: 2, negative: 120 } };
  let wins = 0;
  for (let seed = 0; seed < 50; seed++) { const m = thompsonMix(ev, seed).shares; if (m.webtunnel > m.obfs4) wins++; }
  assert.ok(wins >= 45, `webtunnel won only ${wins}/50`);
});
ok("allocateSlots sums exactly to total", () => {
  const s = allocateSlots(thompsonMix({}, 7).shares, 90);
  assert.equal(Object.values(s).reduce((x, y) => x + y, 0), 90);
});
ok("shapeLine: uTLS added to meek_lite only when absent, iat-mode raised from 0, never lowered", () => {
  const meek = "meek_lite 192.0.2.18:80 url=https://x.example.org/ front=a.b";
  assert.match(shapeLine(meek, 5), new RegExp(`utls=(${UTLS_PROFILES.join("|")})$`));
  const keep = `${meek} utls=HelloChrome_Auto`;
  assert.equal(shapeLine(keep, 5), keep);
  const o = `obfs4 1.2.3.4:443 ${"A".repeat(40)} cert=${cert}`;
  assert.match(shapeLine(o, 1), /iat-mode=[12]$/);
  assert.match(shapeLine(`${o} iat-mode=0`, 1), /iat-mode=[12]$/);
  assert.ok(shapeLine(`${o} iat-mode=2`, 1).endsWith("iat-mode=2"));
});
ok("buildAdaptiveList yields only Orbot-valid, unique, conjure-free lines", () => {
  const lines = [];
  for (let i = 1; i <= 200; i++) lines.push(`obfs4 ${10 + (i % 90)}.${i}.7.${i % 250 + 1}:${i % 3 ? 443 : 9001} ${i.toString(16).padStart(40, "0").toUpperCase()} cert=${cert} iat-mode=0`);
  for (let i = 1; i <= 60; i++) lines.push(`webtunnel [2001:db8::1]:443 ${(i + 5000).toString(16).padStart(40, "A").toUpperCase()} url=https://h${i % 25}.real-site.com/p${i} ver=0.0.1`);
  lines.push("conjure 1.2.3.4:80 url=https://x.org/", "Bridge obfs4 8.8.8.8:1 NOT", "# comment");
  const r = buildAdaptiveList(lines, { evidence: {}, seed: 99, total: 60 });
  assert.ok(r.lines.length > 20);
  assert.equal(new Set(r.lines).size, r.lines.length);
  for (const l of r.lines) { assert.ok(isOrbotValid(l), l); assert.ok(!/^conjure/i.test(l)); assert.ok(repairForOrbot(l).ok, l); }
});
ok("scrubLine heals damaged snowflake fingerprints and drops template webtunnel lines", () => {
  const healed = scrubLine("snowflake 192.0.2.3:80 8838024498816A039FCBBA14E6F40A0843051FA url=https://b.net/");
  assert.equal(healed.drop, null);
  assert.ok(healed.line.includes("8838024498816A039FCBBAB14E6F40A0843051FA"));
  assert.equal(scrubLine("webtunnel [2001:db8::1]:443 " + "A".repeat(40) + " url=https://yourdomain/and/path ver=0.0.1").drop, "placeholder-url");
  assert.equal(scrubLine("snowflake 192.0.2.3:80 " + "A".repeat(37) + " url=https://b.net/").drop, "bad-fingerprint");
  assert.equal(scrubLine("obfs4 1.2.3.4:443 " + "A".repeat(40) + " cert=" + cert).changed, false);
});
console.log(`[test-iran-adaptive] ${n} checks passed`);
