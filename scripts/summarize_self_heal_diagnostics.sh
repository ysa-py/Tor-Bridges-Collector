#!/usr/bin/env bash
# Summarize whole-run self-heal JSON safely and export normalized fields for
# downstream failure categorization. Missing/malformed counters default to 0,
# but an unavailable status is preserved rather than presented as success.
set -euo pipefail

input="${1:-data/whole_run_diagnostics.json}"
status="unavailable"
errors=0
warnings=0
failsafe_triggers=0
unresolved=0
total_lines=0

if [ -s "$input" ] && command -v jq >/dev/null 2>&1; then
  status="$(jq -er '(.diagnostics.status // .status // "unavailable") | tostring' "$input" 2>/dev/null)" || status="unavailable"
  normalize_count() {
    local expression="$1" value
    value="$(jq -er "$expression | if type == \"number\" and . >= 0 then floor elif type == \"string\" and test(\"^[0-9]+$\") then tonumber else 0 end" "$input" 2>/dev/null)" || value=0
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    printf '%s' "$value"
  }
  errors="$(normalize_count '.diagnostics.errors // .errors // 0')"
  warnings="$(normalize_count '.diagnostics.warnings // .warnings // 0')"
  failsafe_triggers="$(normalize_count '.diagnostics.failsafe_triggers // .failsafe_triggers // 0')"
  unresolved="$(normalize_count '.diagnostics.unresolved // .unresolved // 0')"
  total_lines="$(normalize_count '.diagnostics.total_lines // .total_lines // 0')"
fi

printf 'status=%s errors=%s warnings=%s failsafe_triggers=%s unresolved=%s total_lines=%s\n' \
  "$status" "$errors" "$warnings" "$failsafe_triggers" "$unresolved" "$total_lines"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'diagnostics_status=%s\n' "$status"
    printf 'diagnostics_errors=%s\n' "$errors"
    printf 'diagnostics_warnings=%s\n' "$warnings"
    printf 'diagnostics_failsafe_triggers=%s\n' "$failsafe_triggers"
    printf 'diagnostics_unresolved=%s\n' "$unresolved"
    printf 'diagnostics_total_lines=%s\n' "$total_lines"
  } >> "$GITHUB_OUTPUT"
fi
