import cleanupModule from './cleanup-workflow-runs.js';

export const ACTIVE_STATUSES = cleanupModule.ACTIVE_STATUSES;
export const cleanupWorkflowRuns = cleanupModule.cleanupWorkflowRuns;
export const classifyRun = cleanupModule.classifyRun;
export const currentRunIdFrom = cleanupModule.currentRunIdFrom;
export const parsePositiveInteger = cleanupModule.parsePositiveInteger;
export default cleanupWorkflowRuns;
