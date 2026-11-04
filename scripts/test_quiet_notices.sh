#!/usr/bin/env bash
# Self-test for scripts/quiet_notices.sh (offline, no network).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export GITHUB_STEP_SUMMARY="$tmp/summary.md"
: > "$GITHUB_STEP_SUMMARY"

out="$(bash "$here/quiet_notices.sh" bash -c '
  echo "::notice title=FUNNEL::relay_unobserved=89"
  echo "::notice::plain notice"
  echo "::warning::real warning stays"
  echo "::error::real error stays"
  echo normal line
')"

grep -Fq '[notice] FUNNEL relay_unobserved=89' <<<"$out"
grep -Fq '[notice] plain notice' <<<"$out"
grep -Fq '::warning::real warning stays' <<<"$out"
grep -Fq '::error::real error stays' <<<"$out"
grep -Fq 'normal line' <<<"$out"
if grep -q '^::notice' <<<"$out"; then
  echo "FAIL: ::notice leaked through" >&2; exit 1
fi
grep -Fq 'FUNNEL relay_unobserved=89' "$GITHUB_STEP_SUMMARY"

set +e
bash "$here/quiet_notices.sh" bash -c 'echo "::notice::x"; exit 7' >/dev/null
rc=$?
set -e
[ "$rc" -eq 7 ] || { echo "FAIL: exit code $rc != 7" >&2; exit 1; }

raw="$(QUIET_NOTICES=0 bash "$here/quiet_notices.sh" echo '::notice::raw')"
grep -Fq '::notice::raw' <<<"$raw"

echo "quiet_notices self-test passed"
