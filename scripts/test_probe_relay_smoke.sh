#!/usr/bin/env bash
# Hermetic tests for relay smoke retries, redaction, and IPv6 canary payloads.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_script="$repo_root/scripts/probe_relay_smoke.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
sequence_file="$tmp_dir/curl-sequence"
count_file="$tmp_dir/curl-count"
log_file="$tmp_dir/smoke.log"

cat > "$fake_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

output_file=''
header_file=''
request_body=''
request_url=''
while (($#)); do
  case "$1" in
    --output|-o)
      output_file="$2"
      shift 2
      ;;
    --header|-H)
      if [[ "$2" == @* ]]; then
        header_file="${2#@}"
      fi
      shift 2
      ;;
    --data|--data-raw|-d)
      request_body="$2"
      shift 2
      ;;
    --write-out|-w|--request|-X|--connect-timeout|--max-time)
      shift 2
      ;;
    --silent|--show-error)
      shift
      ;;
    https://*)
      request_url="$1"
      shift
      ;;
    *)
      echo 'fake curl received an unexpected argument' >&2
      exit 97
      ;;
  esac
done

if [[ "$request_url" != "${FAKE_CURL_EXPECT_URL:?}" ]]; then
  echo 'fake curl did not receive the expected endpoint' >&2
  exit 98
fi
if [[ -n "${FAKE_CURL_EXPECT_TOKEN:-}" ]]; then
  if [[ -z "$header_file" ]] || ! grep -Fxq "X-Probe-Token: ${FAKE_CURL_EXPECT_TOKEN}" "$header_file"; then
    echo 'fake curl did not receive the auth header file' >&2
    exit 99
  fi
fi
if [[ -n "${FAKE_CURL_EXPECT_HOST:-}" && "$request_body" != *"\"host\":\"${FAKE_CURL_EXPECT_HOST}\""* ]]; then
  echo 'fake curl did not receive the expected loopback host' >&2
  exit 100
fi

count=0
if [[ -s "${FAKE_CURL_COUNT_FILE:?}" ]]; then
  read -r count < "$FAKE_CURL_COUNT_FILE"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_CURL_COUNT_FILE"
result="$(sed -n "${count}p" "${FAKE_CURL_SEQUENCE_FILE:?}")"
if [[ -z "$result" ]]; then
  echo 'fake curl test sequence ran out of entries' >&2
  exit 101
fi
read -r http_code curl_exit <<< "$result"
printf '{"body":"response-body-secret-must-not-be-logged"}\n' > "$output_file"
printf '%s' "$http_code"
exit "$curl_exit"
FAKE_CURL
chmod +x "$fake_bin/curl"

fail() {
  echo "FAIL: $*" >&2
  if [[ -f "$log_file" ]]; then
    cat "$log_file" >&2
  fi
  exit 1
}

run_smoke() {
  PATH="$fake_bin:$PATH" \
  PROBE_RELAY_URL="${PROBE_RELAY_URL:-https://relay.example/private-path}" \
  PROBE_RELAY_TOKEN="${PROBE_RELAY_TOKEN:-header-secret-must-not-be-logged}" \
  PROBE_RELAY_SMOKE_HOST="${PROBE_RELAY_SMOKE_HOST:-127.0.0.1}" \
  PROBE_RELAY_SMOKE_MAX_ATTEMPTS="${PROBE_RELAY_SMOKE_MAX_ATTEMPTS:-3}" \
  PROBE_RELAY_SMOKE_RETRY_DELAY_SECS=0 \
  FAKE_CURL_SEQUENCE_FILE="$sequence_file" \
  FAKE_CURL_COUNT_FILE="$count_file" \
  FAKE_CURL_EXPECT_URL="https://relay.example/private-path/probe" \
  FAKE_CURL_EXPECT_TOKEN="${FAKE_CURL_EXPECT_TOKEN:-header-secret-must-not-be-logged}" \
  FAKE_CURL_EXPECT_HOST="${FAKE_CURL_EXPECT_HOST:-}" \
    bash "$smoke_script"
}

assert_redacted() {
  if grep -Eq 'https://relay\.example|header-secret-must-not-be-logged|response-body-secret-must-not-be-logged' "$log_file"; then
    fail 'smoke diagnostics leaked an endpoint, token, or response body'
  fi
}

# A transient transport error is retried, and a later HTTP 200 succeeds.
printf '000 28\n200 0\n' > "$sequence_file"
: > "$count_file"
if run_smoke > "$log_file" 2>&1; then
  :
else
  fail 'expected transport retry followed by HTTP 200 to succeed'
fi
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected exactly two curl attempts after recovery'
grep -Fq 'retrying' "$log_file" || fail 'missing safe retry diagnostic'
grep -Fq 'passed (HTTP 200' "$log_file" || fail 'missing success diagnostic'
assert_redacted

# Retryable HTTP 5xx responses are retried, not mistaken for permanent 4xxs.
printf '503 0\n200 0\n' > "$sequence_file"
: > "$count_file"
if run_smoke > "$log_file" 2>&1; then
  :
else
  fail 'expected HTTP 503 retry followed by HTTP 200 to succeed'
fi
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected HTTP 503 to be retried once'
assert_redacted

# IPv6 canary bodies must serialize ::1 safely and still use the same gate.
printf '200 0\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_HOST='::1' FAKE_CURL_EXPECT_HOST='::1' run_smoke > "$log_file" 2>&1; then
  :
else
  fail 'expected IPv6 loopback smoke test to succeed'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'expected one IPv6 curl attempt'
assert_redacted

# Optional IPv6 failure remains informational and never claims Stage 4 is skipped.
printf '000 7\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_HOST='::1' PROBE_RELAY_SMOKE_MAX_ATTEMPTS=1 \
   PROBE_RELAY_SMOKE_FAILURE_MODE=informational run_smoke > "$log_file" 2>&1; then
  fail 'expected an unavailable optional IPv6 canary to return non-zero'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'optional IPv6 check must remain bounded to one attempt'
grep -Fq 'Informational only' "$log_file" || fail 'missing informational IPv6 diagnostic'
if grep -Fq 'Stage 4 will be skipped' "$log_file"; then
  fail 'optional IPv6 diagnostic incorrectly claimed Stage 4 would be skipped'
fi
assert_redacted

# DNS/transport failure exhausts the bounded retry budget and returns non-zero.
printf '000 6\n000 6\n000 6\n' > "$sequence_file"
: > "$count_file"
if run_smoke > "$log_file" 2>&1; then
  fail 'expected exhausted transport retries to fail'
fi
[[ "$(cat "$count_file")" == 3 ]] || fail 'expected exactly three bounded curl attempts'
grep -Fq 'DNS resolution failed' "$log_file" || fail 'missing classified transport diagnostic'
grep -Fq 'Stage 4 will be skipped' "$log_file" || fail 'missing explicit Stage 4 skip diagnostic'
if grep -Fq '000000' "$log_file"; then
  fail 'transport error status was duplicated as HTTP 000000'
fi
assert_redacted

# Permanent 4xx responses are not retried.
printf '401 0\n' > "$sequence_file"
: > "$count_file"
if run_smoke > "$log_file" 2>&1; then
  fail 'expected HTTP 401 to fail'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'permanent HTTP 401 must not be retried'
grep -Fq 'HTTP 401' "$log_file" || fail 'missing HTTP 401 diagnostic'
assert_redacted

# Credentials embedded in endpoint user-info/query/fragment are rejected before curl.
for unsafe_url in \
  'https://user:password@relay.example/private-path' \
  'https://relay.example/private-path?token=query-secret' \
  'https://relay.example/private-path#fragment-secret'; do
  : > "$count_file"
  if PROBE_RELAY_URL="$unsafe_url" run_smoke > "$log_file" 2>&1; then
    fail 'expected endpoint containing user-info/query/fragment to be rejected'
  fi
  [[ ! -s "$count_file" ]] || fail 'unsafe endpoint reached curl before validation'
  if grep -Fq "$unsafe_url" "$log_file"; then
    fail 'rejected endpoint was included in diagnostics'
  fi
done

echo 'All probe relay smoke tests passed.'
