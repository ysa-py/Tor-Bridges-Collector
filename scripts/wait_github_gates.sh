#!/usr/bin/env bash
# wait_github_gates.sh — Wait for real cargo/go CI on the current SHA.
#
# Local sandboxes may lack rustc/go. GitHub-hosted runners do not. This helper
# watches rust-parity-tests and go-quality-gate for HEAD and refuses to call a
# missing local toolchain green.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v gh >/dev/null 2>&1; then
  echo "::error::gh is required to wait on GitHub-hosted cargo/go gates"
  exit 1
fi

SHA="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo "Waiting for GitHub-hosted cargo/go gates on ${BRANCH} @ ${SHA}"

deadline=$((SECONDS + 1500))
run_id=""
while (( SECONDS < deadline )); do
  run_id="$(
    gh run list --branch "${BRANCH}" --limit 30 \
      --json databaseId,headSha \
      --jq ".[] | select(.headSha==\"${SHA}\") | .databaseId" \
      | head -n1 || true
  )"
  if [[ -n "${run_id}" ]]; then
    break
  fi
  sleep 10
done

if [[ -z "${run_id}" ]]; then
  echo "::error::no GitHub Actions run found for ${SHA}; cargo/go not verified"
  exit 1
fi

echo "Watching run ${run_id}"
gh run watch "${run_id}" --exit-status

python3 - "${run_id}" <<'PY'
import json
import subprocess
import sys

run_id = sys.argv[1]
raw = subprocess.check_output(
    ["gh", "run", "view", run_id, "--json", "jobs,conclusion,url"],
    text=True,
)
data = json.loads(raw)
jobs = data.get("jobs") or []
required = ("rust-parity-tests", "go-quality-gate")
failed = False
for name in required:
    matches = [job for job in jobs if name in (job.get("name") or "")]
    if not matches:
        print(f"::error::{name} did not run on {data.get('url')}")
        failed = True
        continue
    job = matches[0]
    conclusion = job.get("conclusion")
    print(f"  {job.get('name')}: {conclusion}")
    if conclusion != "success":
        print(f"::error::{name} conclusion={conclusion} (not claimed green)")
        failed = True
if failed:
    sys.exit(1)
print(f"GitHub-hosted cargo/go gates passed: {data.get('url')}")
PY
