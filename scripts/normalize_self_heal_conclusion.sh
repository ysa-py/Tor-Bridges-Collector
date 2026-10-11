#!/usr/bin/env bash
# Normalize the parent conclusion without allowing failed whole-run diagnostics
# to be hidden by an otherwise successful workflow_run conclusion.
set -euo pipefail

parent="${1:-manual}"
status="${2:-unavailable}"
errors="${3:-0}"
unresolved="${4:-0}"

normalize_count() {
  local value="${1:-0}"
  [[ "$value" =~ ^[0-9]+$ ]] || value=0
  printf '%s' "$value"
}
errors="$(normalize_count "$errors")"
unresolved="$(normalize_count "$unresolved")"

if [ "$parent" != "failure" ] && {
  [ "$status" = "failed" ] ||
  [ "$errors" -gt 0 ] ||
  [ "$unresolved" -gt 0 ]
}; then
  printf 'failure\n'
else
  printf '%s\n' "$parent"
fi
