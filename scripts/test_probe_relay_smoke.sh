#!/usr/bin/env bash
# Hermetic tests for live-control selection, typed content checks, redaction,
# bounded retries, evidence-report minimization, and fail-closed preconditions.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_script="$repo_root/scripts/probe_relay_smoke.sh"
selector="$repo_root/scripts/select_probe_relay_timeout_controls.py"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
sequence_file="$tmp_dir/curl-sequence"
count_file="$tmp_dir/curl-count"
log_file="$tmp_dir/smoke.log"
deaddata_file="$tmp_dir/historical-timeouts.json"
multi_control_file="$tmp_dir/multi-timeouts.json"
report_file="$tmp_dir/redacted-live-report.json"
printf '[{"host":"93.184.216.34","port":8443,"success":false,"error":"probe timed out after 5000ms"}]\n' > "$deaddata_file"
cat > "$multi_control_file" <<'JSON'
[
  {"host":"10.0.0.2","port":443,"success":false,"error":"timeout"},
  {"host":"192.0.2.7","port":443,"success":false,"error":"timed out"},
  {"host":"93.184.216.34","port":8443,"success":false,"error":"timed out"},
  {"host":"93.184.216.35","port":9443,"success":false,"error":"timed out"},
  {"host":"8.8.8.8","port":443,"success":false,"error":"timeout"},
  {"host":"1.1.1.1","port":53,"success":false,"error":"connection timed out"},
  {"host":"9.9.9.9","port":80,"success":false,"error":"timed out"},
  {"host":"example.com","port":443,"success":false,"error":"timed out"},
  {"host":"203.0.113.12","port":443,"success":false,"error":"timed out"},
  {"host":"8.8.4.4","port":true,"success":false,"error":"timed out"},
  {"host":"8.8.4.4","port":65536,"success":false,"error":"timed out"},
  {"host":"8.8.4.4","port":443,"success":true,"error":"timed out"}
]
JSON

cat > "$fake_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

output_file=''
config_file=''
header_file=''
request_file=''
while (($#)); do
  case "$1" in
    --output|-o)
      output_file="$2"
      shift 2
      ;;
    --config|-K)
      config_file="$2"
      shift 2
      ;;
    --header|-H)
      if [[ "$2" == @* ]]; then header_file="${2#@}"; fi
      shift 2
      ;;
    --data-binary)
      [[ "$2" == @* ]] || exit 90
      request_file="${2#@}"
      shift 2
      ;;
    --write-out|-w|--request|-X|--connect-timeout|--max-time|--max-filesize)
      shift 2
      ;;
    --silent|--show-error)
      shift
      ;;
    *)
      echo 'fake curl received an unexpected argument' >&2
      exit 97
      ;;
  esac
done

[[ -n "$config_file" && -n "$header_file" && -n "$request_file" && -n "$output_file" ]] || exit 91
[[ "$(stat -c '%a' "$config_file")" == 600 ]] || exit 92
[[ "$(stat -c '%a' "$header_file")" == 600 ]] || exit 93
[[ "$(stat -c '%a' "$request_file")" == 600 ]] || exit 94
url="$(sed -n 's/^url = "\(.*\)"$/\1/p' "$config_file")"
[[ "$url" == "${FAKE_CURL_EXPECT_URL:?}" ]] || exit 98
grep -Fxq "X-Probe-Token: ${FAKE_CURL_EXPECT_TOKEN:?}" "$header_file" || exit 99

# Verify exact target correlation in the request without printing target values.
jq -e --argjson controls "${FAKE_CURL_EXPECT_CONTROLS_JSON:?}" '
  type == "array" and length == ($controls|length) + 2 and
  .[0].id == "silent-live" and .[0].host == "example.com" and .[0].port == 443 and
  .[1].id == "refused-port" and .[1].host == "example.com" and .[1].port == 1 and
  .[2:] == $controls and all(.[]; .transport == "vanilla")
' "$request_file" >/dev/null || exit 100

count=0
if [[ -s "${FAKE_CURL_COUNT_FILE:?}" ]]; then read -r count < "$FAKE_CURL_COUNT_FILE"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_CURL_COUNT_FILE"
read -r http_code curl_exit body_mode < <(sed -n "${count}p" "${FAKE_CURL_SEQUENCE_FILE:?}")
[[ -n "$body_mode" ]] || exit 101

if [[ "$body_mode" == transport-error ]]; then
  printf 'curl-error-secret-must-not-be-logged\n' >&2
  printf '{"error":"response-body-secret-must-not-be-logged"}\n' > "$output_file"
  printf '%s' "$http_code"
  exit "$curl_exit"
fi

jq -c --arg mode "$body_mode" --arg observed_at "$(date -u +'%Y-%m-%dT%H:%M:%S.123Z')" '
  [ .[] | . as $b | {
      id: $b.id,
      transport: $b.transport,
      host: $b.host,
      port: $b.port,
      success: ($b.id == "silent-live" or ($mode == "no-timeout" and ($b.id | startswith("timeout-control-")))),
      status: (if $b.id == "silent-live" then "connected"
               elif $b.id == "refused-port" then "refused"
               elif $mode == "no-timeout" then "connected"
               else "timeout" end),
      stage: (if $b.id == "silent-live" or ($mode == "no-timeout" and ($b.id | startswith("timeout-control-"))) then "S1" else "S0" end),
      vantage: {type:"cloudflare_worker",colo:"TEST"},
      observed_at: (if $mode == "stale" then "2020-01-01T00:00:00Z" else $observed_at end),
      rtt_ms: (if $b.id == "timeout-control-1" then null else 3 end),
      detail: (if $b.id == "silent-live" then "TCP connection established" elif $b.id == "refused-port" then "connection refused" else "probe timed out" end),
      error_class: (if $b.id == "silent-live" or ($mode == "no-timeout" and ($b.id | startswith("timeout-control-"))) then null elif $b.id == "refused-port" then "connection_refused" else "tcp_connect_timeout" end),
      error: (if $b.id == "silent-live" or ($mode == "no-timeout" and ($b.id | startswith("timeout-control-"))) then null elif $b.id == "refused-port" then "connection refused" else "probe timed out" end)
    } ] as $results |
  {results:$results,
   stats:{attempted:($results|length),completed:($results|length),
     connected:([$results[]|select(.status=="connected")]|length),
     refused:([$results[]|select(.status=="refused")]|length),
     timedOut:([$results[]|select(.status=="timeout")]|length),
     inconclusive:([$results[]|select(.status=="inconclusive")]|length),
     errored:([$results[]|select(.status=="error")]|length),
     success:([$results[]|select(.status=="connected")]|length)},
   marker:"response-body-secret-must-not-be-logged"}
' "$request_file" > "$output_file"
if [[ "$body_mode" == wrong-content ]]; then
  jq '(.results[] | select(.id == "refused-port") | .status) = "connected"' "$output_file" > "${output_file}.tmp"
  mv "${output_file}.tmp" "$output_file"
elif [[ "$body_mode" == wrong-target ]]; then
  jq '(.results[] | select(.id == "timeout-control-1") | .host) = "203.0.113.99"' "$output_file" > "${output_file}.tmp"
  mv "${output_file}.tmp" "$output_file"
fi
printf '%s' "$http_code"
exit "$curl_exit"
FAKE_CURL
chmod +x "$fake_bin/curl"

fail() {
  echo "FAIL: $*" >&2
  if [[ -f "$log_file" ]]; then cat "$log_file" >&2; fi
  exit 1
}

single_controls='[{"id":"timeout-control-1","host":"93.184.216.34","port":8443,"transport":"vanilla"}]'
run_smoke() {
  PATH="$fake_bin:$PATH" \
  PROBE_RELAY_URL="${PROBE_RELAY_URL-https://relay.example/private-path}" \
  PROBE_RELAY_TOKEN="${PROBE_RELAY_TOKEN-header-secret-must-not-be-logged}" \
  PROBE_RELAY_SMOKE_DEAD_CONTROL_FILE="${PROBE_RELAY_SMOKE_DEAD_CONTROL_FILE-$deaddata_file}" \
  PROBE_RELAY_SMOKE_REPORT_PATH="${PROBE_RELAY_SMOKE_REPORT_PATH-}" \
  PROBE_RELAY_SMOKE_EVIDENCE_LABEL="${PROBE_RELAY_SMOKE_EVIDENCE_LABEL-mock}" \
  GITHUB_STEP_SUMMARY='' GITHUB_RUN_ID='' GITHUB_SHA='' \
  PROBE_RELAY_SMOKE_MAX_ATTEMPTS="${PROBE_RELAY_SMOKE_MAX_ATTEMPTS:-3}" \
  PROBE_RELAY_SMOKE_RETRY_DELAY_SECS=0 \
  FAKE_CURL_SEQUENCE_FILE="$sequence_file" \
  FAKE_CURL_COUNT_FILE="$count_file" \
  FAKE_CURL_EXPECT_URL="https://relay.example/private-path/probe" \
  FAKE_CURL_EXPECT_TOKEN="header-secret-must-not-be-logged" \
  FAKE_CURL_EXPECT_CONTROLS_JSON="${FAKE_CURL_EXPECT_CONTROLS_JSON-$single_controls}" \
    bash "$smoke_script"
}

assert_redacted() {
  local marker
  for marker in \
    'https://relay.example' \
    'header-secret-must-not-be-logged' \
    'response-body-secret-must-not-be-logged' \
    'curl-error-secret-must-not-be-logged' \
    '93.184.216.34' \
    '8.8.8.8' \
    '1.1.1.1' \
    '9.9.9.9' \
    'valid-token-marker-123'; do
    if grep -Fq "$marker" "$log_file"; then
      fail 'smoke diagnostics leaked a URL, token, response body, curl stderr, or bridge endpoint'
    fi
  done
}

# Selector rejects private/reserved/malformed targets, de-duplicates, and prefers
# four independent /24s. The smoke still requires a fresh, worker-observed timeout.
selected="$(python3 "$selector" "$multi_control_file" 2>/dev/null)" || fail 'timeout-control selection failed'
[[ "$(jq 'length' <<< "$selected")" == 4 ]] || fail 'selector did not choose four bounded controls'
jq -e '
  map(.id) == ["timeout-control-1","timeout-control-2","timeout-control-3","timeout-control-4"] and
  map(.host) == ["93.184.216.34","8.8.8.8","1.1.1.1","9.9.9.9"] and
  all(.[]; .transport == "vanilla" and (.port|type=="number" and .>=1 and .<=65535))
' <<< "$selected" >/dev/null || fail 'selector diversity/order/public-address contract failed'

# A transient transport error is retried; the redacted report records only typed live-style fields.
printf '000 28 transport-error\n200 0 valid\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_REPORT_PATH="$report_file" run_smoke > "$log_file" 2>&1; then :; else fail 'expected safe retry followed by valid typed controls'; fi
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected exactly two curl attempts after recovery'
grep -Fq 'retrying' "$log_file" || fail 'missing safe retry diagnostic'
grep -Fq 'silent-live S1, refused-port S0, 1 freshly timed-out public control(s) S0' "$log_file" || fail 'smoke failed to name the observed outcome classes'
jq -e '.schema_version == 1 and .kind == "probe_relay_smoke" and .evidence_class == "mock" and
  .result == "passed" and .stats.attempted == 3 and .stats.current_timeout_controls == 1 and
  ([.controls[]|select(.id == "silent-live" and .status == "connected" and .stage == "S1" and .vantage.type == "cloudflare_worker")]|length)==1 and
  ([.controls[]|select(.id == "refused-port" and .status == "refused" and .stage == "S0")]|length)==1 and
  ([.controls[]|select(.id == "timeout-control-1" and .status == "timeout" and .stage == "S0" and .rtt_ms == null)]|length)==1 and
  all(.controls[]; (has("host")|not) and (has("port")|not) and (has("detail")|not) and (has("error")|not))
' "$report_file" >/dev/null || fail 'redacted evidence report did not preserve measured status/stage/vantage/RTT'
for marker in '93.184.216.34' 'example.com' 'https://relay.example' 'header-secret-must-not-be-logged' 'response-body-secret-must-not-be-logged'; do
  if grep -Fq "$marker" "$report_file"; then fail 'redacted report leaked target, URL, or response marker'; fi
done
assert_redacted

# A successful relay response is not accepted if required evidence cannot be saved.
printf '200 0 valid\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_REPORT_PATH=/dev/null/blocked-report.json run_smoke > "$log_file" 2>&1; then
  fail 'a passed canary without its required redacted report was accepted'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'evidence-report failure should not trigger network retries'
grep -Fq 'redacted evidence report could not be written' "$log_file" || fail 'missing fail-closed report-write diagnostic'
assert_redacted

# Retryable HTTP 503 responses are retried; response bodies remain private.
printf '503 0 transport-error\n200 0 valid\n' > "$sequence_file"
: > "$count_file"
if run_smoke > "$log_file" 2>&1; then :; else fail 'expected HTTP 503 retry followed by valid typed controls'; fi
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected HTTP 503 to be retried once'
assert_redacted

# Multiple current timeout controls are safely correlated to the submitted endpoints.
multi_expected="$(python3 "$selector" "$multi_control_file" 2>/dev/null)" || fail 'multi-control selector failed'
printf '200 0 valid\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_DEAD_CONTROL_FILE="$multi_control_file" \
   FAKE_CURL_EXPECT_CONTROLS_JSON="$multi_expected" run_smoke > "$log_file" 2>&1; then :; else fail 'multi-control live response should match'; fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'expected one request for the bounded multi-control batch'
grep -Fq '4 freshly timed-out public control(s)' "$log_file" || fail 'multi-control run did not confirm timeout outcomes'
assert_redacted

# HTTP 200 without any fresh timeout is not accepted as the known-dead control.
printf '200 0 no-timeout\n200 0 no-timeout\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_MAX_ATTEMPTS=2 run_smoke > "$log_file" 2>&1; then
  fail 'a batch without a current timeout control must fail closed'
fi
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected bounded retries for a missing timeout control'
grep -Fq 'content did not match the typed control contract' "$log_file" || fail 'missing timeout-control failure diagnostic'
assert_redacted

# HTTP 200 with a target/response mismatch is rejected (not just status checked).
printf '200 0 wrong-target\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_MAX_ATTEMPTS=1 run_smoke > "$log_file" 2>&1; then
  fail 'response with a mismatched echoed target was accepted'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'wrong-target control should not be retried beyond configured limit'
assert_redacted

# Server timestamps must be recent; replayed/historical responses cannot pass.
printf '200 0 stale\\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_MAX_ATTEMPTS=1 run_smoke > "$log_file" 2>&1; then
  fail 'a stale response timestamp was accepted as fresh live evidence'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'stale timestamp control should use one request'
assert_redacted

# HTTP 200 with invalid statuses/stats is a failure, never a canary pass.
printf '200 0 wrong-content\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_MAX_ATTEMPTS=1 run_smoke > "$log_file" 2>&1; then
  fail 'expected invalid typed outcomes to fail the smoke test'
fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'wrong typed outcomes should be bounded by configured attempts'
assert_redacted

# Permanent HTTP 401 is not retried.
printf '401 0 transport-error\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_SMOKE_MAX_ATTEMPTS=3 run_smoke > "$log_file" 2>&1; then fail 'expected HTTP 401 to fail'; fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'permanent HTTP 401 must not be retried'
grep -Fq 'HTTP 401' "$log_file" || fail 'missing HTTP 401 diagnostic'
assert_redacted

# Missing endpoint/token and malformed secrets fail closed before curl.
for env_case in missing_endpoint missing_token short_token newline_token; do
  : > "$count_file"
  case "$env_case" in
    missing_endpoint) if PROBE_RELAY_URL='' run_smoke > "$log_file" 2>&1; then fail 'missing endpoint was accepted'; fi ;;
    missing_token) if PROBE_RELAY_TOKEN='' run_smoke > "$log_file" 2>&1; then fail 'missing token was accepted'; fi ;;
    short_token) if PROBE_RELAY_TOKEN='short-token' run_smoke > "$log_file" 2>&1; then fail 'short token was accepted'; fi ;;
    newline_token) if PROBE_RELAY_TOKEN=$'valid-token-marker-123\nInjected: secret' run_smoke > "$log_file" 2>&1; then fail 'newline token was accepted'; fi ;;
  esac
  [[ ! -s "$count_file" ]] || fail "$env_case reached curl before validation"
  assert_redacted
done

# Credential-bearing/unsafe endpoint forms are rejected before curl and never echoed.
for unsafe_url in \
  'https://user:password@relay.example/private-path' \
  'https://relay.example/private-path?token=query-secret' \
  'https://relay.example/private-path#fragment-secret' \
  'https://relay.example/private\\path' \
  $'https://relay.example/path\r\nInjected: url-secret'; do
  : > "$count_file"
  if PROBE_RELAY_URL="$unsafe_url" run_smoke > "$log_file" 2>&1; then fail 'unsafe endpoint was accepted'; fi
  [[ ! -s "$count_file" ]] || fail 'unsafe endpoint reached curl before validation'
  if grep -Fq "$unsafe_url" "$log_file"; then fail 'rejected endpoint was included in diagnostics'; fi
  assert_redacted
done

# Missing or wholly invalid historical candidate data never falls back to a guessed target.
private_control_file="$tmp_dir/private-only.json"
printf '[{"host":"10.0.0.1","port":443,"success":false,"error":"timeout"}]\\n' > "$private_control_file"
for bad_control_file in "$tmp_dir/missing.json" "$private_control_file"; do
  : > "$count_file"
  if PROBE_RELAY_SMOKE_DEAD_CONTROL_FILE="$bad_control_file" run_smoke > "$log_file" 2>&1; then
    fail 'missing/non-public timeout-control data was accepted'
  fi
  [[ ! -s "$count_file" ]] || fail 'invalid timeout-control precondition reached curl'
  assert_redacted
done

echo 'All probe relay smoke tests passed.'
