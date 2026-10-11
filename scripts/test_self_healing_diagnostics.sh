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

echo "test_self_healing_diagnostics: PASS"
