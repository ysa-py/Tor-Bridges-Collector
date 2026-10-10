#!/usr/bin/env bash
# Hermetic tests for mandatory relay auth, optional deployment auth, and redaction.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validator="$repo_root/scripts/validate_probe_relay_secrets.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
output_file="$tmp_dir/github-output"
log_file="$tmp_dir/validator.log"

fail() {
  echo "FAIL: $*" >&2
  if [[ -f "$log_file" ]]; then cat "$log_file" >&2; fi
  exit 1
}

assert_redacted() {
  local marker
  for marker in \
    'url-secret-marker' \
    'token-secret-marker' \
    'account-secret-marker' \
    'api-secret-marker' \
    'password-secret-marker' \
    'query-secret-marker' \
    'path-secret-marker'; do
    if grep -Fq "$marker" "$log_file"; then
      fail 'secret validation diagnostics leaked a configured value'
    fi
  done
}

run_validator() {
  GITHUB_OUTPUT="$output_file" \
  HAS_PROBE_RELAY_URL="${HAS_PROBE_RELAY_URL-true}" \
  HAS_PROBE_RELAY_TOKEN="${HAS_PROBE_RELAY_TOKEN-true}" \
  HAS_CF_WORKER_ACCOUNT_ID="${HAS_CF_WORKER_ACCOUNT_ID-true}" \
  HAS_CF_WORKER_API_TOKEN="${HAS_CF_WORKER_API_TOKEN-true}" \
  PROBE_RELAY_URL="${PROBE_RELAY_URL-https://relay.example/private-path}" \
  PROBE_RELAY_TOKEN="${PROBE_RELAY_TOKEN-a-fake-but-long-enough-token}" \
  CF_WORKER_ACCOUNT_ID="${CF_WORKER_ACCOUNT_ID-0123456789abcdef0123456789abcdef}" \
  CF_WORKER_API_TOKEN="${CF_WORKER_API_TOKEN-a-fake-cloudflare-api-token-for-tests}" \
    bash "$validator"
}

assert_relay_proceeds() {
  if grep -Fqx 'PROBE_RELAY_SKIP=true' "$output_file"; then fail 'valid authenticated relay credentials were marked skipped'; fi
}
assert_relay_skips() {
  grep -Fqx 'PROBE_RELAY_SKIP=true' "$output_file" || fail 'required relay credential failure did not skip Stage 4'
}
assert_deploy_skips() {
  grep -Fqx 'PROBE_RELAY_DEPLOY_SKIP=true' "$output_file" || fail 'optional deploy credential failure did not skip deployment'
}
assert_deploy_proceeds() {
  if grep -Fqx 'PROBE_RELAY_DEPLOY_SKIP=true' "$output_file"; then fail 'valid deployment credentials were marked skipped'; fi
}

# All four configured secrets with valid formats allow deployment and the live canary.
: > "$output_file"
if run_validator > "$log_file" 2>&1; then :; else fail 'valid test credentials should pass validation'; fi
assert_relay_proceeds
assert_deploy_proceeds
assert_redacted

# Relay URL/token are mandatory and fail closed; optional deploy values cannot rescue them.
: > "$output_file"
if HAS_PROBE_RELAY_URL=false HAS_PROBE_RELAY_TOKEN=false \
   PROBE_RELAY_URL='' PROBE_RELAY_TOKEN='' \
   run_validator > "$log_file" 2>&1; then :; else fail 'missing credentials should be a non-fatal Stage 4 skip'; fi
assert_relay_skips
assert_deploy_skips
grep -Fq "secret 'PROBE_RELAY_URL' is not configured" "$log_file" || fail 'missing-endpoint branch was not exercised'
grep -Fq "secret 'PROBE_RELAY_TOKEN' is not configured" "$log_file" || fail 'missing-token branch was not exercised'
assert_redacted

# Missing optional Cloudflare deploy credentials do not disable an authenticated smoke test.
: > "$output_file"
if HAS_CF_WORKER_ACCOUNT_ID=false HAS_CF_WORKER_API_TOKEN=false \
   CF_WORKER_ACCOUNT_ID='' CF_WORKER_API_TOKEN='' \
   run_validator > "$log_file" 2>&1; then :; else fail 'missing deploy credentials should remain non-fatal'; fi
assert_relay_proceeds
assert_deploy_skips
grep -Fq 'authenticated live canary still runs' "$log_file" || fail 'optional deploy skip was not distinguished from Stage 4'
assert_redacted

# Configured-but-whitespace-only relay secret is invalid.
: > "$output_file"
if PROBE_RELAY_TOKEN=$' \t\n' run_validator > "$log_file" 2>&1; then :; else fail 'blank relay token should produce a non-fatal skip'; fi
assert_relay_skips
assert_redacted

# Relay tokens need a printable 16-1024 character value, with no line breaks.
for invalid_token in 'too-short' $'token-secret-marker-123\nInjected: value' "$(printf 't%.0s' {1..1025})"; do
  : > "$output_file"
  if PROBE_RELAY_TOKEN="$invalid_token" run_validator > "$log_file" 2>&1; then :; else fail 'invalid token should be a non-fatal Stage 4 skip'; fi
  assert_relay_skips
  assert_redacted
done

# Invalid endpoint forms are rejected without echoing endpoint or embedded credentials.
for unsafe_url in \
  'http://url-secret-marker.invalid' \
  'https://user:password-secret-marker@relay.example/path' \
  'https://relay.example/path?token=query-secret-marker' \
  'https://relay.example/path#fragment-secret-marker' \
  'https://relay.example/path\\credential' \
  'https://relay.example/path"secret' \
  $'https://relay.example/path\r\nInjected: path-secret-marker' \
  'https://relay.example/a b'; do
  : > "$output_file"
  if PROBE_RELAY_URL="$unsafe_url" run_validator > "$log_file" 2>&1; then :; else fail 'unsafe endpoint should produce a non-fatal Stage 4 skip'; fi
  assert_relay_skips
  if grep -Fq "$unsafe_url" "$log_file"; then fail 'invalid endpoint was included in diagnostics'; fi
  assert_redacted
done

# Invalid deployment values skip deployment only, never the authenticated live canary.
: > "$output_file"
if CF_WORKER_ACCOUNT_ID='account-secret-marker' CF_WORKER_API_TOKEN='api-secret-marker' \
   run_validator > "$log_file" 2>&1; then :; else fail 'invalid optional deploy secrets should remain non-fatal'; fi
assert_relay_proceeds
assert_deploy_skips
assert_redacted

echo 'All probe relay secret validation tests passed.'
