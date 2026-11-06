#!/usr/bin/env node
/**
 * cleanup_workflow_runs.mjs — keep GitHub Actions history small and debuggable.
 *
 *   GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo node scripts/cleanup_workflow_runs.mjs
 *        [--dry] [--max-delete 800] [--stale-hours 6] [--concurrency 6] [--json out.json]
 *
 * Policy lives in scripts/lib/run_cleanup_plan.mjs (newest success + newest failure per workflow,
 * active runs untouched, stuck runs cancelled). Rate-limit aware: stops cleanly when the token
 * budget runs low and simply continues on the next scheduled pass. Never fails the pipeline
 * because of API hiccups (exit 0), only on programming errors.
 */
import { writeFile, appendFile } from "node:fs/promises";
import { planCleanup } from "./lib/run_cleanup_plan.mjs";

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const opt = (flag, fallback) => {
  const index = argv.indexOf(flag);
  return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
};
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const REPO = process.env.GITHUB_REPOSITORY || opt("--repo", "");
const DRY = has("--dry");
const MAX_DELETE = Number(opt("--max-delete", "800"));
const STALE_HOURS = Number(opt("--stale-hours", "6"));
const CONCURRENCY = Math.max(1, Number(opt("--concurrency", "6")));
const MIN_REMAINING = 30;
const CURRENT = process.env.GITHUB_RUN_ID ?? null;
const log = (...a) => console.log("[run-janitor]", ...a);

if (!TOKEN || !REPO) {
  log("GITHUB_TOKEN / GITHUB_REPOSITORY missing — nothing to do");
  process.exit(0);
}
let remaining = Infinity;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, { retries = 3 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const res = await fetch(`https://api.github.com/repos/${REPO}${path}`, {
      method,
      headers: { authorization: `Bearer ${TOKEN}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "run-janitor" },
    });
    const left = Number(res.headers.get("x-ratelimit-remaining"));
    if (Number.isFinite(left)) remaining = left;
    if (res.status === 403 || res.status === 429) {
      const wait = Number(res.headers.get("retry-after")) || 0;
      if (remaining <= 0 && !wait) return { status: res.status, rateLimited: true };
      await sleep((wait || 5 * (attempt + 1)) * 1000);
      continue;
    }
    const body = res.status === 204 ? null : await res.json().catch(() => null);
    return { status: res.status, body };
  }
  return { status: 429, rateLimited: true };
}

async function listAllRuns() {
  const runs = [];
  let total = Infinity;
  for (let page = 1; runs.length < total && page <= 120; page++) {
    const { status, body, rateLimited } = await api("GET", `/actions/runs?per_page=100&page=${page}`);
    if (rateLimited || status !== 200 || !body) {
      log(`listing stopped at page ${page} (status ${status}) — partial history, still safe to act on`);
      break;
    }
    total = body.total_count;
    for (const r of body.workflow_runs ?? []) {
      runs.push({ id: r.id, workflow_id: r.workflow_id, name: r.name, status: r.status, conclusion: r.conclusion, created_at: r.created_at });
    }
    if ((body.workflow_runs ?? []).length < 100) break;
    if (remaining < MIN_REMAINING + MAX_DELETE / 4) {
      log(`rate budget low while listing (${remaining}) — stopping the listing`);
      break;
    }
  }
  return { runs, total };
}

const started = Date.now();
const { runs, total } = await listAllRuns();
const plan = planCleanup(runs, { staleHours: STALE_HOURS, currentRunId: CURRENT });
log(`runs seen ${runs.length}/${total}; keep ${plan.keep.length}; delete ${plan.remove.length}; cancel-stuck ${plan.cancel.length}${DRY ? " [dry-run]" : ""}`);

const result = { repo: REPO, dry: DRY, total, seen: runs.length, keep: plan.keep.length, candidates: plan.remove.length, deleted: 0, cancelled: 0, failed: 0, stoppedByBudget: false };

if (!DRY) {
  for (const run of plan.cancel.slice(0, 40)) {
    if (remaining < MIN_REMAINING) break;
    const r = await api("POST", `/actions/runs/${run.id}/force-cancel`);
    if (r.status === 202) result.cancelled += 1;
  }
  const queue = plan.remove.slice(0, MAX_DELETE);
  let index = 0;
  const worker = async () => {
    while (index < queue.length) {
      if (remaining < MIN_REMAINING) {
        result.stoppedByBudget = true;
        return;
      }
      const run = queue[index++];
      const r = await api("DELETE", `/actions/runs/${run.id}`);
      if (r.status === 204 || r.status === 404) result.deleted += 1;
      else if (r.rateLimited) {
        result.stoppedByBudget = true;
        return;
      } else result.failed += 1;
      if (result.deleted % 200 === 0 && result.deleted > 0) log(`deleted ${result.deleted}/${queue.length} (rate left ${remaining})`);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
}
result.remainingCandidates = Math.max(0, plan.remove.length - result.deleted);
result.seconds = Math.round((Date.now() - started) / 1000);
log(JSON.stringify(result));

if (process.env.GITHUB_STEP_SUMMARY) {
  await appendFile(
    process.env.GITHUB_STEP_SUMMARY,
    `### Workflow-run janitor\n\n| metric | value |\n|---|---|\n${Object.entries(result).map(([k, v]) => `| ${k} | ${v} |`).join("\n")}\n`,
  ).catch(() => {});
}
const out = opt("--json", null);
if (out) await writeFile(out, JSON.stringify(result, null, 1) + "\n");
