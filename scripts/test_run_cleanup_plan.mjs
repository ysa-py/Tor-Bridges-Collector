#!/usr/bin/env node
import assert from "node:assert/strict";
import { planCleanup } from "./lib/run_cleanup_plan.mjs";
let n = 0;
const ok = (name, fn) => { fn(); n += 1; console.log(`  ok  ${name}`); };
const NOW = Date.parse("2026-01-02T00:00:00Z");
let id = 0;
const mk = (wf, status, conclusion, hoursAgo) => ({ id: ++id, workflow_id: wf, status, conclusion, created_at: new Date(NOW - hoursAgo * 3_600_000).toISOString() });

ok("keeps newest success + newest failure per workflow, deletes the rest", () => {
  const runs = [mk(1, "completed", "success", 1), mk(1, "completed", "failure", 2), mk(1, "completed", "success", 3), mk(1, "completed", "failure", 4), mk(1, "completed", "cancelled", 0.5)];
  const p = planCleanup(runs, { now: NOW });
  assert.deepEqual(p.keep.map((r) => r.id).sort(), [1, 2]);
  assert.equal(p.remove.length, 3);
});
ok("only successes: keeps the newest two", () => {
  const runs = [mk(2, "completed", "success", 1), mk(2, "completed", "success", 2), mk(2, "completed", "success", 3)];
  const p = planCleanup(runs, { now: NOW });
  assert.equal(p.keep.length, 2);
  assert.equal(p.remove.length, 1);
});
ok("a workflow with a single run keeps it; cancelled-only history keeps one", () => {
  assert.equal(planCleanup([mk(3, "completed", "success", 1)], { now: NOW }).remove.length, 0);
  const p = planCleanup([mk(4, "completed", "cancelled", 1), mk(4, "completed", "skipped", 2), mk(4, "completed", "cancelled", 3)], { now: NOW });
  assert.equal(p.keep.length, 2);
  assert.equal(p.remove.length, 1);
});
ok("fresh active runs are kept, stuck ones are cancelled, current run is never removed", () => {
  const fresh = mk(5, "in_progress", null, 1);
  const stuck = mk(5, "in_progress", null, 20);
  const cur = mk(5, "completed", "success", 0);
  const filler = [mk(5, "completed", "success", 5), mk(5, "completed", "success", 6)];
  const p = planCleanup([fresh, stuck, cur, ...filler], { now: NOW, currentRunId: cur.id });
  assert.ok(p.keep.some((r) => r.id === fresh.id));
  assert.ok(p.cancel.some((r) => r.id === stuck.id));
  assert.ok(p.keep.some((r) => r.id === cur.id));
  assert.ok(!p.remove.some((r) => r.id === stuck.id || r.id === fresh.id || r.id === cur.id));
});
ok("2500 runs collapse to at most 2 per workflow", () => {
  const runs = [];
  for (let i = 0; i < 2500; i++) runs.push(mk(i % 3, "completed", i % 7 === 0 ? "failure" : "success", i / 10));
  const p = planCleanup(runs, { now: NOW });
  assert.ok(p.keep.length <= 6);
  assert.equal(p.keep.length + p.remove.length, 2500);
});
console.log(`[test-run-cleanup-plan] ${n} checks passed`);
