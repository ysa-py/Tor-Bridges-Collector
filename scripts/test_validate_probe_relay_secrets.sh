#!/usr/bin/env bash
# Hermetic tests for Stage 4 secret presence, format checks, and log redaction.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validator="$repo_root/scripts/validate_probe_relay_secrets.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
output_file="$tmp_dir/github-output"
log_file="$tmp_dir/validator.log"

fail() {
  echo "FAIL: $*" >&2
  if [[ -f "$log_file" ]]; then
    cat "$log_file" >&2
  fi
  exit 1
}

assert_redacted() {
  local marker
  for marker in \
    'url-secret-marker' \
    'token-secret-marker' \
    'account-secret-marker' \
    'api-secret-marker'; do
    if grep -Fq "$marker" "$log_file"; then
      fail 'secret validation diagnostics leaked a configured value'
    fi
  done
}

run_validator() {
  GITHUB_OUTPUT="$output_file" \
  HAS_PROBE_RELAY_URL="${HAS_PROBE_RELAY_URL:-true}" \
  HAS_PROBE_RELAY_TOKEN="${HAS_PROBE_RELAY_TOKEN:-true}" \
  HAS_CF_WORKER_ACCOUNT_ID="${HAS_CF_WORKER_ACCOUNT_ID:-true}" \
  HAS_CF_WORKER_API_TOKEN="${HAS_CF_WORKER_API_TOKEN:-true}" \
  PROBE_RELAY_URL="${PROBE_RELAY_URL:-https://relay.example/private-path}" \
  PROBE_RELAY_TOKEN="${PROBE_RELAY_TOKEN:-a-fake-but-long-enough-token}" \
  CF_WORKER_ACCOUNT_ID="${CF_WORKER_ACCOUNT_ID:-0123456789abcdef0123456789abcdef}" \
  CF_WORKER_API_TOKEN="${CF_WORKER_API_TOKEN:-a-fake-cloudflare-api-token-for-tests}" \
    bash "$validator"
}

assert_skip() {
  [[ "$(tail -n 1 "$output_file")" == 'PROBE_RELAY_SKIP=true' ]] || fail 'expected Stage 4 skip output'
}
assert_proceed() {
  [[ ! -s "$output_file" ]] || fail 'valid credentials should leave the Stage 4 skip output unset until the live canary passes'
}

# All configured secrets with valid formats allow Stage 4.
: > "$output_file"
if run_validator > "$log_file" 2>&1; then
  :
else
  fail 'valid test credentials should pass validation'
fi
assert_proceed
assert_redacted

# GitHub-provided presence flags distinguish missing env secrets from "set".
: > "$output_file"
if HAS_PROBE_RELAY_URL=false HAS_PROBE_RELAY_TOKEN=false \
   HAS_CF_WORKER_ACCOUNT_ID=false HAS_CF_WORKER_API_TOKEN=false \
   PROBE_RELAY_URL='' PROBE_RELAY_TOKEN='' CF_WORKER_ACCOUNT_ID='' CF_WORKER_API_TOKEN='' \
   run_validator > "$log_file" 2>&1; then
  :
else
  fail 'missing secrets should be a non-fatal Stage 4 skip'
fi
assert_skip
grep -Fq "secret 'PROBE_RELAY_URL' is not configured" "$log_file" || fail 'missing-secret branch was not exercised'
assert_redacted

# A configured-but-whitespace-only secret is recognized as blank, not valid.
: > "$output_file"
if PROBE_RELAY_URL=$' \t\n' run_validator > "$log_file" 2>&1; then
  :
else
  fail 'blank secrets should be a non-fatal Stage 4 skip'
fi
assert_skip
grep -Fq "secret 'PROBE_RELAY_URL' is configured but blank" "$log_file" || fail 'blank-secret branch was not exercised'
assert_redacted

# Invalid values are never interpolated into diagnostics.
: > "$output_file"
if PROBE_RELAY_URL='http://url-secret-marker.invalid' \
   PROBE_RELAY_TOKEN='token-secret-marker' \
   CF_WORKER_ACCOUNT_ID='account-secret-marker' \
   CF_WORKER_API_TOKEN='api-secret-marker' \
   run_validator > "$log_file" 2>&1; then
  :
else
  fail 'invalid secrets should be a non-fatal Stage 4 skip'
fi
assert_skip
grep -Fq 'not a valid HTTPS endpoint' "$log_file" || fail 'invalid endpoint branch was not exercised'
assert_redacted

# Query-string credentials are rejected before they can enter curl arguments.
: > "$output_file"
if PROBE_RELAY_URL='https://relay.example/path?token=url-secret-marker' \
   run_validator > "$log_file" 2>&1; then
  :
else
  fail 'query-bearing endpoint should be a non-fatal Stage 4 skip'
fi
assert_skip
grep -Fq 'queries, fragments, and user-info are not allowed' "$log_file" || fail 'query URL validation branch was not exercised'
assert_redacted

echo 'All probe relay secret validation tests passed.'
