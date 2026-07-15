'use strict';

const ACTIVE_STATUSES = new Set(['in_progress', 'queued', 'requested', 'waiting', 'pending']);

function parsePositiveInteger(value, fallback = 2, minimum = 2) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
}

function isTruthy(value) {
  return ['1', 'true', 'yes', 'y', 'on'].includes(String(value ?? '').trim().toLowerCase());
}

function currentRunIdFrom(context = {}, env = process.env) {
  const raw = context.runId ?? env.GITHUB_RUN_ID;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

function classifyRun(run, protectedIds, currentRunId) {
  const runId = Number(run.id);
  if (currentRunId !== null && runId === currentRunId) return 'current_run';
  if (protectedIds.has(runId)) return 'keep_last_n';
  if (ACTIVE_STATUSES.has(String(run.status || '').toLowerCase())) return 'active';
  return 'delete';
}

async function cleanupWorkflowRuns({ github, context, core = console, env = process.env, dryRun = false, keepLastN, strictCleanup } = {}) {
  if (!github?.rest?.actions || !github.paginate) throw new TypeError('cleanupWorkflowRuns requires a GitHub client with rest.actions and paginate.');
  const { owner, repo } = context?.repo || {};
  if (!owner || !repo) throw new TypeError('cleanupWorkflowRuns requires context.repo.owner and context.repo.repo.');

  const effectiveKeepLastN = parsePositiveInteger(keepLastN ?? env.KEEP_LAST_N, 2, 2);
  const strict = strictCleanup ?? isTruthy(env.STRICT_CLEANUP);
  const currentRunId = currentRunIdFrom(context, env);
  const result = { deletedRuns: [], skippedRuns: [], failedRuns: [], listFailed: [], scannedRuns: 0, keptRuns: 0, dryRun: Boolean(dryRun), strictCleanup: strict };

  let workflows;
  try {
    workflows = await github.paginate(github.rest.actions.listRepoWorkflows, { owner, repo, per_page: 100 });
  } catch (error) {
    result.listFailed.push({ scope: 'workflows', error: error.message || String(error) });
    core.warning?.(`Cleanup skipped: cannot list workflows: ${error.message || error}`);
    if (strict) throw error;
    return result;
  }

  for (const workflow of workflows) {
    let runs;
    try {
      runs = await github.paginate(github.rest.actions.listWorkflowRuns, { owner, repo, workflow_id: workflow.id, per_page: 100 });
    } catch (error) {
      result.listFailed.push({ scope: 'workflow', workflowId: workflow.id, workflowName: workflow.name, error: error.message || String(error) });
      core.warning?.(`Cannot list runs for ${workflow.name || workflow.id}: ${error.message || error}`);
      if (strict) throw error;
      continue;
    }

    const sortedRuns = [...runs].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    result.scannedRuns += sortedRuns.length;
    const protectedIds = new Set(sortedRuns.slice(0, effectiveKeepLastN).map(run => Number(run.id)));
    result.keptRuns += protectedIds.size;

    for (const run of sortedRuns) {
      const reason = classifyRun(run, protectedIds, currentRunId);
      const entry = { id: run.id, runNumber: run.run_number, status: run.status, workflowId: workflow.id, workflowName: workflow.name, reason };
      if (reason !== 'delete') {
        result.skippedRuns.push(entry);
        continue;
      }
      if (dryRun) {
        result.deletedRuns.push({ ...entry, dryRun: true });
        continue;
      }
      try {
        await github.rest.actions.deleteWorkflowRun({ owner, repo, run_id: run.id });
        result.deletedRuns.push(entry);
      } catch (error) {
        const failure = { ...entry, error: error.message || String(error), statusCode: error.status };
        if (error.status === 404) result.skippedRuns.push({ ...failure, reason: 'not_found' });
        else if (error.status === 409 || (error.status === 403 && /Cannot delete/i.test(failure.error))) result.skippedRuns.push({ ...failure, reason: 'active_or_protected' });
        else {
          result.failedRuns.push(failure);
          core.warning?.(`Failed to delete run ${run.id}: ${failure.error}`);
          if (strict) throw error;
        }
      }
    }
  }

  if ((result.failedRuns.length || result.listFailed.length) && !strict) {
    core.warning?.(`Cleanup completed with warnings: ${result.failedRuns.length} delete failure(s), ${result.listFailed.length} list failure(s).`);
  }
  return result;
}

async function runSelfTest() {
  const calls = { deleted: [] };
  const github = {
    rest: { actions: {
      listRepoWorkflows: Symbol('listRepoWorkflows'),
      listWorkflowRuns: Symbol('listWorkflowRuns'),
      async deleteWorkflowRun({ run_id }) { calls.deleted.push(run_id); if (run_id === 6) throw Object.assign(new Error('boom'), { status: 500 }); }
    } },
    async paginate(endpoint, params) {
      if (endpoint === this.rest.actions.listRepoWorkflows) return [{ id: 10, name: 'ci' }];
      if (params.workflow_id === 10) return [
        { id: 1, run_number: 1, status: 'completed', created_at: '2026-01-06' },
        { id: 2, run_number: 2, status: 'completed', created_at: '2026-01-05' },
        { id: 3, run_number: 3, status: 'in_progress', created_at: '2026-01-04' },
        { id: 4, run_number: 4, status: 'completed', created_at: '2026-01-03' },
        { id: 5, run_number: 5, status: 'completed', created_at: '2026-01-02' },
        { id: 6, run_number: 6, status: 'completed', created_at: '2026-01-01' }
      ];
      return [];
    }
  };
  const warnings = [];
  const result = await cleanupWorkflowRuns({ github, context: { repo: { owner: 'o', repo: 'r' }, runId: 4 }, core: { warning: msg => warnings.push(msg) }, keepLastN: 2 });
  if (calls.deleted.includes(3) || calls.deleted.includes(4)) throw new Error('active/current run was deleted');
  if (!calls.deleted.includes(5) || !calls.deleted.includes(6)) throw new Error('eligible runs were not attempted');
  if (!result.failedRuns.some(run => run.id === 6)) throw new Error('failedRuns did not capture deletion failure');
  if (!result.skippedRuns.some(run => run.reason === 'current_run') || !result.skippedRuns.some(run => run.reason === 'active')) throw new Error('skippedRuns missing protected entries');
}

if (require.main === module) {
  runSelfTest().then(() => console.log('cleanup regression checks passed')).catch(error => { console.error(error); process.exitCode = 1; });
}

module.exports = { ACTIVE_STATUSES, cleanupWorkflowRuns, classifyRun, currentRunIdFrom, parsePositiveInteger };
