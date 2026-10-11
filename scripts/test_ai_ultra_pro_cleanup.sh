#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/ai-ultra-pro-cleanup.yml"

fail() {
  echo "test_ai_ultra_pro_cleanup: FAIL: $*" >&2
  exit 1
}

grep -Fq 'group: ai-ultra-pro-cleanup-${{ github.repository }}-' "$WORKFLOW" ||
  fail "cleanup concurrency group must be repository + branch/main scoped"
grep -Fq "github.ref == 'refs/heads/main' && 'main' || github.ref" "$WORKFLOW" ||
  fail "main cleanup must have a concurrency group separate from non-main refs"
grep -Fq "cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}" "$WORKFLOW" ||
  fail "non-main runs may be cancelled but main cleanup must be protected"

noop_line="$(grep -nF 'Non-main validation run: cleanup is a safe no-op (no history scan, no deletions).' "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
list_line="$(grep -nF 'github.rest.actions.listWorkflowRuns' "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
[ -n "$noop_line" ] || fail "non-main early-return guard is missing"
[ -n "$list_line" ] || fail "workflow-run listing call is missing"
[ "$noop_line" -lt "$list_line" ] ||
  fail "non-main early return must run before any workflow-history scan"

grep -Fq "core.setOutput('scanned_runs', '0')" "$WORKFLOW" ||
  fail "safe no-op should explicitly report zero scanned runs"
grep -Fq "core.setOutput('deleted', '0')" "$WORKFLOW" ||
  fail "safe no-op should explicitly report zero deletions"
grep -Fq "MAX_PAGES_PER_WORKFLOW = 2" "$WORKFLOW" ||
  fail "main cleanup must have a bounded scan page count"
grep -Fq "MAX_CANDIDATES_PER_INVOCATION = 200" "$WORKFLOW" ||
  fail "main cleanup must bound candidates per invocation"
grep -Fq "MAX_DELETIONS_PER_INVOCATION = 100" "$WORKFLOW" ||
  fail "main cleanup must bound deletions per invocation"

echo "test_ai_ultra_pro_cleanup: PASS (main isolated, branch no-op, bounded cleanup batches)"
