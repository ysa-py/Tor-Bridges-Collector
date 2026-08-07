#!/usr/bin/env bash
# retry_cmd.sh — Transient-error auto-retry wrapper with exponential backoff.
#
# Usage:  scripts/retry_cmd.sh <command...>
#
# Retries the command on transient failures (HTTP 502/503 or timeout) using
# exponential backoff: 2^attempt seconds, capped at 60s, up to 3 attempts.
# Deterministic errors (compilation, syntax, test failures) are NEVER retried.
#
# Matches the backoff policy in src/retry_engine.rs and
# src/bin/sync_bridge_outputs.rs.
set -euo pipefail

MAX_ATTEMPTS="${RETRY_MAX_ATTEMPTS:-3}"
BACKOFF_CAP_SECS="${RETRY_BACKOFF_CAP_SECS:-60}"

attempt=1
while true; do
  exit_code=0
  output=""
  output=$( "$@" 2>&1 ) || exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    printf '%s\n' "$output"
    exit 0
  fi

  # Only retry on HTTP 502/503 or runner timeouts.
  # grep -qE checks stderr+stdout for transient patterns.
  transient=false
  if echo "$output" | grep -qE '(502 Bad Gateway|503 Service Unavailable|curl:.*timed out|wget:.*timed out|gh:.*timeout|runner.*timeout)'; then
    transient=true
  fi

  if [ "$transient" != true ] || [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    printf '%s\n' "$output" >&2
    exit "$exit_code"
  fi

  delay=$(( 2 ** attempt ))
  if [ "$delay" -gt "$BACKOFF_CAP_SECS" ]; then
    delay="$BACKOFF_CAP_SECS"
  fi

  printf 'retry_cmd: attempt %d/%d failed (exit %d) — retrying in %ds\n' \
    "$attempt" "$MAX_ATTEMPTS" "$exit_code" "$delay" >&2
  sleep "$delay"
  attempt=$(( attempt + 1 ))
done
