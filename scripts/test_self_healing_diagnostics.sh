#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
HELPER="$ROOT/scripts/summarize_self_heal_diagnostics.sh"

cat > "$TMP/failed.json" <<'JSON'
{
  "diagnostics": {
    "status": "failed",
    "errors": 639,
    "warnings": 810,
    "failsafe_triggers": 0,
    "unresolved": 1449,
    "total_lines": 43460
  }
}
JSON
: > "$TMP/failed.outputs"
summary="$(GITHUB_OUTPUT="$TMP/failed.outputs" bash "$HELPER" "$TMP/failed.json")"
[ "$summary" = "status=failed errors=639 warnings=810 failsafe_triggers=0 unresolved=1449 total_lines=43460" ] || {
  echo "FAIL: unexpected summary: $summary" >&2
  exit 1
}
grep -qx 'diagnostics_status=failed' "$TMP/failed.outputs"
grep -qx 'diagnostics_errors=639' "$TMP/failed.outputs"
grep -qx 'diagnostics_unresolved=1449' "$TMP/failed.outputs"

cat > "$TMP/healthy.json" <<'JSON'
{"diagnostics":{"status":"ok","errors":0,"warnings":2,"failsafe_triggers":1,"unresolved":0,"total_lines":20}}
JSON
: > "$TMP/healthy.outputs"
summary="$(GITHUB_OUTPUT="$TMP/healthy.outputs" bash "$HELPER" "$TMP/healthy.json")"
[ "$summary" = "status=ok errors=0 warnings=2 failsafe_triggers=1 unresolved=0 total_lines=20" ] || {
  echo "FAIL: unexpected healthy summary: $summary" >&2
  exit 1
}
grep -qx 'diagnostics_status=ok' "$TMP/healthy.outputs"
grep -qx 'diagnostics_errors=0' "$TMP/healthy.outputs"

summary="$(bash "$HELPER" "$TMP/missing.json")"
[ "$summary" = "status=unavailable errors=0 warnings=0 failsafe_triggers=0 unresolved=0 total_lines=0" ] || {
  echo "FAIL: missing file must yield an explicit unavailable status: $summary" >&2
  exit 1
}

NORMALIZER="$ROOT/scripts/normalize_self_heal_conclusion.sh"
[ "$(bash "$NORMALIZER" success failed 639 1449)" = "failure" ] || {
  echo "FAIL: failed diagnostics must override a successful parent conclusion" >&2
  exit 1
}
[ "$(bash "$NORMALIZER" success ok 0 0)" = "success" ] || {
  echo "FAIL: healthy diagnostics must preserve a successful parent conclusion" >&2
  exit 1
}
# GATE RECALIBRATION (2026-10-14, PR #265): a failed diagnostics STATUS is
# still an error-severity signal and must override a green parent, even with
# zero explicitly counted errors (belt-and-braces parity with the Rust
# classifier, whose status=failed <=> errors>0 by construction).
[ "$(bash "$NORMALIZER" success failed 0 1)" = "failure" ] || {
  echo "FAIL: failed-status findings must prevent false success" >&2
  exit 1
}
# The old gate also flipped on `unresolved > 0` — i.e. on ANY diagnostic
# event, including the typed by-design advisories every healthy run
# legitimately prints (probe timeout evidence, failsafe self-heal lines,
# MOAT empty windows). That re-labelled every green pipeline run
# "failure" (measured: 1975 advisory events on a 15/15-jobs-successful
# run, warning annotation on every self-heal trigger). Advisory-only
# findings now stay visible in the step summary and the uploaded
# whole_run_diagnostics.json artifact WITHOUT flipping the parent
# conclusion; only Error-severity findings (status=failed or errors>0)
# normalize a green parent to failure.
[ "$(bash "$NORMALIZER" success ok 0 1)" = "success" ] || {
  echo "FAIL: advisory-only findings must not flip a successful parent conclusion" >&2
  exit 1
}
[ "$(bash "$NORMALIZER" success degraded 0 1975)" = "success" ] || {
  echo "FAIL: degraded-with-zero-errors (advisory) diagnostics must preserve success" >&2
  exit 1
}
[ "$(bash "$NORMALIZER" success degraded 3 1975)" = "failure" ] || {
  echo "FAIL: error-severity findings must flip a successful parent conclusion" >&2
  exit 1
}
[ "$(bash "$NORMALIZER" failure ok 0 0)" = "failure" ] || {
  echo "FAIL: a failed parent conclusion must remain failed" >&2
  exit 1
}

echo "test_self_healing_diagnostics: PASS"
