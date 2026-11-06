/**
 * run_cleanup_plan.mjs — pure planner for GitHub Actions run clean-up (no I/O).
 *
 * Policy (per workflow, "keep the two runs that matter when debugging"):
 *   keep  newest SUCCESS            (the known-good reference)
 *   keep  newest FAILURE            (failure / timed_out / startup_failure — what you debug)
 *   if one of them does not exist, the next newest meaningful completed run fills the slot
 *   (cancelled / skipped / neutral runs only fill when nothing else exists), so every workflow
 *   keeps at most 2 completed runs and at least 1 when it has any history.
 *   keep  active runs younger than `staleHours` (never touch something that is still running)
 *   cancel active runs older than `staleHours` (stuck); they are deleted on a later pass
 *   delete everything else.
 * The run that is executing the clean-up (`currentRunId`) is always kept.
 */
const ACTIVE = new Set(["queued", "in_progress", "waiting", "pending", "requested"]);
const FAILED = new Set(["failure", "timed_out", "startup_failure"]);
const MEANINGLESS = new Set(["cancelled", "skipped", "neutral", "stale", "action_required"]);

const time = (run) => new Date(run.created_at ?? run.run_started_at ?? 0).getTime();

/**
 * @param {Array<{id:number,workflow_id:number,status:string,conclusion:string|null,created_at:string}>} runs
 * @param {{now?:number, staleHours?:number, currentRunId?:number|string|null}} [options]
 * @returns {{keep:Array, remove:Array, cancel:Array, perWorkflow:Record<string,{kept:number,removed:number}>}}
 */
export function planCleanup(runs, { now = Date.now(), staleHours = 6, currentRunId = null } = {}) {
  const byWorkflow = new Map();
  for (const run of runs) {
    if (!byWorkflow.has(run.workflow_id)) byWorkflow.set(run.workflow_id, []);
    byWorkflow.get(run.workflow_id).push(run);
  }
  const keep = [];
  const remove = [];
  const cancel = [];
  const perWorkflow = {};
  for (const [workflowId, list] of byWorkflow) {
    const sorted = [...list].sort((a, b) => time(b) - time(a) || b.id - a.id);
    const kept = new Set();
    const completed = sorted.filter((run) => !ACTIVE.has(run.status));
    const pick = (predicate) => completed.find((run) => predicate(run) && !kept.has(run.id));
    const success = pick((run) => run.conclusion === "success");
    if (success) kept.add(success.id);
    const failure = pick((run) => FAILED.has(run.conclusion));
    if (failure) kept.add(failure.id);
    for (const predicate of [(run) => !MEANINGLESS.has(run.conclusion), () => true]) {
      while (kept.size < 2) {
        const extra = pick(predicate);
        if (!extra) break;
        kept.add(extra.id);
      }
    }
    // a workflow with a healthy success AND a failure keeps exactly those two; with only one
    // kind it keeps that one plus the next newest completed run as a second data point
    let removed = 0;
    for (const run of sorted) {
      if (String(run.id) === String(currentRunId)) {
        keep.push(run);
        continue;
      }
      if (ACTIVE.has(run.status)) {
        const ageHours = (now - time(run)) / 3_600_000;
        if (ageHours > staleHours) cancel.push(run);
        else keep.push(run);
        continue;
      }
      if (kept.has(run.id)) {
        keep.push(run);
        continue;
      }
      remove.push(run);
      removed += 1;
    }
    perWorkflow[workflowId] = { kept: sorted.length - removed - cancel.filter((r) => r.workflow_id === workflowId).length, removed };
  }
  return { keep, remove, cancel, perWorkflow };
}
