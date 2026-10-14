#!/usr/bin/env bash
# Normalize the parent conclusion without allowing failed whole-run diagnostics
# to be hidden by an otherwise successful workflow_run conclusion.
#
# GATE RECALIBRATION (2026-10-14, evidence run 38579293985):
# The previous gate also flipped success -> failure when `unresolved > 0`.
# `unresolved` counts EVERY diagnostic event — including the typed by-design
# advisories a healthy run legitimately prints (probe timeout evidence,
# failsafe self-heal lines, MOAT empty windows, source-gap warnings). With
# that condition every GREEN pipeline run was re-labelled "failure"
# (1975 advisory events on a 15/15-jobs-successful run), producing the
# "Whole-run diagnostics failed despite parent conclusion=success" warning
# on every single self-heal trigger.
#
# The flip is now driven by real Error-severity diagnostics only:
#   * status=failed   — the classifier found Error-severity events, or
#   * errors > 0      — the same, counted explicitly.
# Advisory-only diagnostics (warnings > 0, status=degraded) keep the parent
# conclusion untouched; they remain visible in the step summary and the
# uploaded whole_run_diagnostics.json artifact.
set -euo pipefail

parent="${1:-manual}"
status="${2:-unavailable}"
errors="${3:-0}"
unresolved="${4:-0}" # retained for interface compatibility; advisory-only.

normalize_count() {
  local value="${1:-0}"
  [[ "$value" =~ ^[0-9]+$ ]] || value=0
  printf '%s' "$value"
}
errors="$(normalize_count "$errors")"
unresolved="$(normalize_count "$unresolved")"

if [ "$parent" != "failure" ] && {
  [ "$status" = "failed" ] ||
  [ "$errors" -gt 0 ]
}; then
  printf 'failure\n'
else
  printf '%s\n' "$parent"
fi
