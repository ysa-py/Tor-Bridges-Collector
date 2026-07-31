#!/usr/bin/env bash
# ci_ai_provider_helpers.sh
# --------------------------------------------------------------------------
# Shared CI helpers for AI provider API calls.
#
# Provides two shell functions used by the GitHub Actions workflows:
#
#   with_ai_retry <max-attempts> <command...>
#       Retry a command with exponential backoff. Designed to wrap AI
#       provider `curl` calls. 4xx HTTP responses (auth failure, bad
#       request, model not found) abort immediately — those errors never
#       fix themselves on retry. Network errors / 5xx / rate-limit statuses
#       back off: attempt n waits 2^n seconds starting at 2 s.
#
#   select_cf_slot <n-preferred>
#       Emits a Cloudflare slot index (1..11) whose account/token/gateway
#       trio is non-empty. The preferred index is tried first so CI
#       debugging stays stable; if it's empty (or only partially
#       configured), slots are walked round-robin starting from the
#       preferred index. Exits non-zero if NO usable slot exists.
#
# Usage (from a workflow `run:` step after sourcing this file):
#   source scripts/ci_ai_provider_helpers.sh
#   SLOT=$(select_cf_slot 1) || exit 1
#   with_ai_retry 3 curl -sS -X POST "${CF_AI_GATEWAY_URL_x}/workers-ai/run/@hf/..." \
#       -H "Authorization: Bearer ${CF_API_TOKEN_x}" \
#       -H "Content-Type: application/json" \
#       --data @payload.json
#
# Secrets are NOT read here; the caller must map them into env vars before
# invoking the helpers. This is shell-only and has no third-party deps.
# --------------------------------------------------------------------------
set -euo pipefail

: "${AI_RETRY_BASE_WAIT:=2}"

with_ai_retry() {
  local max_attempts="${1:-3}"
  shift
  local attempt=1
  local wait_s="${AI_RETRY_BASE_WAIT}"
  local output rc http_code
  while [ "$attempt" -le "$max_attempts" ]; do
    output=""
    rc=0
    http_code=0
    tmp_body="$(mktemp)"
    tmp_headers="$(mktemp)"
    # Run the command; capture stdout/stderr into body; curl writes HTTP status into headers file when using -D
    if "$@" >"$tmp_body" 2>"$tmp_headers"; then
      rc=0
    else
      rc=$?
    fi
    # If the wrapped command was curl, we can surface HTTP status
    if [[ "$1" == "curl" ]]; then
      http_code=$(grep -iE '^HTTP/' "$tmp_headers" | tail -1 | awk '{print $2}' || true)
      http_code="${http_code:-0}"
    fi
    # 4xx class: auth/bad request/model not found — do not retry.
    if [[ "$http_code" =~ ^4[0-9][0-9]$ ]]; then
      cat "$tmp_body" >&2 || true
      rm -f "$tmp_body" "$tmp_headers"
      echo "::error::AI provider returned HTTP ${http_code} (non-retryable, aborting)" >&2
      return 22
    fi
    # 2xx success
    if [ "$rc" -eq 0 ] && { [ "$http_code" = "0" ] || [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; }; then
      cat "$tmp_body"
      rm -f "$tmp_body" "$tmp_headers"
      return 0
    fi
    echo "::warning::AI provider call failed (rc=$rc, http=${http_code}); attempt ${attempt}/${max_attempts}; retrying in ${wait_s}s" >&2
    cat "$tmp_body" >&2 || true
    rm -f "$tmp_body" "$tmp_headers"
    sleep "$wait_s"
    attempt=$((attempt + 1))
    wait_s=$((wait_s * 2))
  done
  echo "::error::AI provider call failed after ${max_attempts} attempts" >&2
  return 1
}

select_cf_slot() {
  local preferred="${1:-1}"
  local i slot
  local account_var token_var gw_var
  # Walk from preferred..11, then 1..preferred-1
  for i in $(seq "$preferred" 11) $(seq 1 $((preferred - 1))); do
    account_var="CF_ACCOUNT_ID_${i}"
    token_var="CF_API_TOKEN_${i}"
    gw_var="CF_AI_GATEWAY_URL_${i}"
    if [ -n "${!account_var:-}" ] && [ -n "${!token_var:-}" ]; then
      # gateway URL is optional (some setups use the global worker); treat
      # present-but-empty as "use default", absent is fine.
      echo "$i"
      return 0
    fi
  done
  echo "::error::No usable Cloudflare slot (CF_ACCOUNT_ID_x + CF_API_TOKEN_x) is configured" >&2
  return 1
}
