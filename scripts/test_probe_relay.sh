#!/usr/bin/env bash
# Hermetic tests for authenticated relay batching, typed content validation, and redaction.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_script="$repo_root/scripts/probe_relay.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
input_file="$tmp_dir/input.json"
output_file="$tmp_dir/results.json"
sequence_file="$tmp_dir/curl-sequence"
count_file="$tmp_dir/curl-count"
log_file="$tmp_dir/relay.log"

cat > "$input_file" <<'JSON'
[
  "vanilla 93.184.216.34:443 fingerprint",
  "webtunnel fingerprint url=https://example.com/private-token-path",
  "conjure fingerprint url=https://registration.example.com/api fronts=front.example.com",
  "unsupported-format"
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
    --output|-o) output_file="$2"; shift 2 ;;
    --config|-K) config_file="$2"; shift 2 ;;
    --header|-H)
      if [[ "$2" == @* ]]; then header_file="${2#@}"; fi
      shift 2
      ;;
    --data-binary)
      [[ "$2" == @* ]] || exit 90
      request_file="${2#@}"
      shift 2
      ;;
    --write-out|-w|--request|-X|--connect-timeout|--max-time|--max-filesize) shift 2 ;;
    --silent|--show-error) shift ;;
    *) echo 'fake curl unexpected argument' >&2; exit 97 ;;
  esac
done
[[ -n "$output_file" && -n "$config_file" && -n "$header_file" && -n "$request_file" ]] || exit 91
[[ "$(stat -c '%a' "$config_file")" == 600 ]] || exit 92
[[ "$(stat -c '%a' "$header_file")" == 600 ]] || exit 93
[[ "$(stat -c '%a' "$request_file")" == 600 ]] || exit 94
url="$(sed -n 's/^url = "\(.*\)"$/\1/p' "$config_file")"
[[ "$url" == "${FAKE_RELAY_EXPECT_URL:?}" ]] || exit 98
grep -Fxq "X-Probe-Token: ${FAKE_RELAY_EXPECT_TOKEN:?}" "$header_file" || exit 99

jq -e '
  type == "array" and length == 4 and
  any(.[]; .id == "line-vanilla-93.184.216.34-443" and .host == "93.184.216.34" and .port == 443 and .transport == "vanilla") and
  any(.[]; .transport == "webtunnel" and .host == "example.com" and .path == "/private-token-path") and
  (map(select(.transport == "conjure")) | length == 2) and
  all(.[]; (.host | type == "string") and (.port | type == "number"))
' "$request_file" >/dev/null || exit 100

count=0
if [[ -s "${FAKE_RELAY_COUNT_FILE:?}" ]]; then read -r count < "$FAKE_RELAY_COUNT_FILE"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_RELAY_COUNT_FILE"
read -r http_code curl_exit response_mode < <(sed -n "${count}p" "${FAKE_RELAY_SEQUENCE_FILE:?}")
[[ -n "$response_mode" ]] || exit 101

if [[ "$response_mode" == slow ]]; then
  sleep 10
  exit 28
fi
if [[ "$response_mode" == invalid ]]; then
  printf '{"results":[{"body_marker":"relay-response-secret-must-not-be-logged"}],"stats":{}}\n' > "$output_file"
  printf '%s' "$http_code"
  exit "$curl_exit"
fi

jq -c '
  [ .[] | . as $b | {
      id:$b.id,
      transport:$b.transport,
      host:$b.host,
      port:$b.port,
      success:($b.transport == "vanilla" or $b.transport == "webtunnel"),
      status:(if $b.transport == "vanilla" or $b.transport == "webtunnel" then "connected" else "inconclusive" end),
      stage:(if $b.transport == "webtunnel" then "S2" elif $b.transport == "vanilla" then "S1" else "S1" end),
      vantage:{type:"cloudflare_worker",colo:"TEST"},
      observed_at:"2026-10-10T00:00:00Z",
      rtt_ms:17,
      probe_type:(if $b.transport == "webtunnel" then "websocket-101" else "tcp" end),
      detail:(if $b.transport == "webtunnel" then "WebSocket upgrade signature verified" elif $b.transport == "vanilla" then "TCP connection established" else "protocol signature not verified" end),
      error_class:(if $b.transport == "vanilla" or $b.transport == "webtunnel" then null else "protocol_response_unverified" end),
      error:(if $b.transport == "vanilla" or $b.transport == "webtunnel" then null else "protocol signature not verified" end)
    } ] as $results |
  {results:$results,
   stats:{attempted:($results|length),completed:($results|length),
     connected:([$results[]|select(.status=="connected")]|length),
     refused:([$results[]|select(.status=="refused")]|length),
     timedOut:([$results[]|select(.status=="timeout")]|length),
     inconclusive:([$results[]|select(.status=="inconclusive")]|length),
     errored:([$results[]|select(.status=="error")]|length),
     success:([$results[]|select(.status=="connected")]|length)},
   marker:"relay-response-secret-must-not-be-logged"}
' "$request_file" > "$output_file"
printf '%s' "$http_code"
exit "$curl_exit"
FAKE_CURL
chmod +x "$fake_bin/curl"

fail() {
  echo "FAIL: $*" >&2
  if [[ -f "$log_file" ]]; then cat "$log_file" >&2; fi
  exit 1
}

run_relay_for_paths() {
  local relay_input="$1"
  local relay_output="$2"
  PATH="$fake_bin:$PATH" \
  PROBE_RELAY_URL="${PROBE_RELAY_URL-https://relay.example/credential-path-secret}" \
  PROBE_RELAY_TOKEN="${PROBE_RELAY_TOKEN-relay-token-secret-marker-123456}" \
  PROBE_RELAY_CHUNK_SIZE="${PROBE_RELAY_CHUNK_SIZE-6}" \
  PROBE_RELAY_MAX_RETRIES="${PROBE_RELAY_MAX_RETRIES-2}" \
  PROBE_RELAY_PARALLELISM="${PROBE_RELAY_PARALLELISM-2}" \
  FAKE_RELAY_SEQUENCE_FILE="$sequence_file" \
  FAKE_RELAY_COUNT_FILE="$count_file" \
  FAKE_RELAY_EXPECT_URL="https://relay.example/credential-path-secret/probe" \
  FAKE_RELAY_EXPECT_TOKEN="relay-token-secret-marker-123456" \
    bash "$relay_script" "$relay_input" "$relay_output"
}

run_relay() {
  run_relay_for_paths "$input_file" "$output_file"
}

assert_redacted() {
  local marker
  for marker in \
    'https://relay.example' \
    'credential-path-secret' \
    'relay-token-secret-marker-123456' \
    'relay-response-secret-must-not-be-logged' \
    'private-token-path' \
    'registration.example.com' \
    'front.example.com'; do
    if grep -Fq "$marker" "$log_file"; then fail 'relay client diagnostics leaked URL credentials, bridge data, or response content'; fi
  done
}

# A valid authenticated Worker response with mixed S1/S2/inconclusive outcomes is retained.
printf '200 0 valid\n' > "$sequence_file"
: > "$count_file"
if run_relay > "$log_file" 2>&1; then :; else fail 'valid typed response should pass'; fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'expected exactly one authenticated request'
jq -e 'length == 4 and
  ([.[] | select(.status == "connected" and .stage == "S1")] | length) == 1 and
  ([.[] | select(.status == "connected" and .stage == "S2")] | length) == 1 and
  ([.[] | select(.status == "inconclusive" and .stage == "S1")] | length) == 2 and
  all(.[]; (.observed_at | type == "string") and (.vantage.type == "cloudflare_worker") and (.line | type == "string")) and
  any(.[]; .transport == "webtunnel" and .line == "webtunnel fingerprint url=https://example.com/private-token-path")' "$output_file" >/dev/null || fail 'typed outcomes, timestamp, or vantage were not preserved'
grep -Fq 'worker_connected=2' "$log_file" || fail 'connected stats were not aggregated'
grep -Fq 'result_stage_S2=1' "$log_file" || fail 'S2 count was not aggregated'
grep -Fq 'result_status_inconclusive=2' "$log_file" || fail 'inconclusive results were not counted neutrally'
grep -Fq 'S2+=1' "$log_file" || fail 'per-transport S2+ breakdown is missing'
assert_redacted

# A malformed HTTP-200 contract is rejected; only typed S0 inconclusive fallback rows are written.
printf '200 0 invalid\n' > "$sequence_file"
: > "$count_file"
if PROBE_RELAY_MAX_RETRIES=0 run_relay > "$log_file" 2>&1; then :; else fail 'bounded malformed-response fallback should remain non-fatal'; fi
[[ "$(cat "$count_file")" == 1 ]] || fail 'invalid response should not be retried when configured for zero retries'
jq -e 'length == 4 and all(.[]; (.line | type == "string") and .status == "inconclusive" and .stage == "S0" and .success == false and .vantage == null and (.observed_at | type == "string"))' "$output_file" >/dev/null || fail 'malformed relay body was used or fallback outcomes were not typed'
grep -Fq 'result_status_inconclusive=4' "$log_file" || fail 'fallback outcomes were omitted from the result funnel'
assert_redacted

# Missing auth is rejected before curl and writes no false positive rows.
: > "$count_file"
if PROBE_RELAY_TOKEN='' run_relay > "$log_file" 2>&1; then fail 'missing relay token should fail closed'; fi
[[ ! -s "$count_file" ]] || fail 'unauthenticated request reached curl'
[[ "$(cat "$output_file")" == '[]' ]] || fail 'missing-auth guard should leave an empty result array'
assert_redacted

# Unsafe URLs and malformed tokens are rejected before curl; no value is echoed.
for unsafe_url in \
  'http://relay.example/path' \
  'https://user:password@relay.example/path' \
  'https://relay.example/path?token=secret' \
  'https://relay.example/path#fragment' \
  'https://relay.example/path\\credential'; do
  : > "$count_file"
  if PROBE_RELAY_URL="$unsafe_url" run_relay > "$log_file" 2>&1; then fail 'unsafe relay URL was accepted'; fi
  [[ ! -s "$count_file" ]] || fail 'unsafe relay URL reached curl'
  if grep -Fq "$unsafe_url" "$log_file"; then fail 'unsafe URL was logged'; fi
  assert_redacted
done
: > "$count_file"
if PROBE_RELAY_TOKEN='short' run_relay > "$log_file" 2>&1; then fail 'short relay token was accepted'; fi
[[ ! -s "$count_file" ]] || fail 'invalid token reached curl'
assert_redacted

# Chunk-size and retry caps fail closed before network activity.
for guard_case in chunk_size retries; do
  : > "$count_file"
  if [[ "$guard_case" == chunk_size ]]; then
    if PROBE_RELAY_CHUNK_SIZE=7 run_relay > "$log_file" 2>&1; then fail 'oversized chunk size was accepted'; fi
  else
    if PROBE_RELAY_MAX_RETRIES=6 run_relay > "$log_file" 2>&1; then fail 'unbounded retry count was accepted'; fi
  fi
  [[ ! -s "$count_file" ]] || fail "$guard_case validation reached curl"
  assert_redacted
done

# A timed-out later group must leave the prior completed group's typed results,
# not a stale output file or an empty replacement.
partial_input="$tmp_dir/partial-input.json"
partial_output="$tmp_dir/partial-results.json"
jq -s '.[0] + .[0]' "$input_file" > "$partial_input"
printf '200 0 valid\n200 28 slow\n' > "$sequence_file"
: > "$count_file"
set +e
PATH="$fake_bin:$PATH" \
PROBE_RELAY_URL='https://relay.example/credential-path-secret' \
PROBE_RELAY_TOKEN='relay-token-secret-marker-123456' \
PROBE_RELAY_CHUNK_SIZE=4 \
PROBE_RELAY_MAX_RETRIES=0 \
PROBE_RELAY_PARALLELISM=1 \
FAKE_RELAY_SEQUENCE_FILE="$sequence_file" \
FAKE_RELAY_COUNT_FILE="$count_file" \
FAKE_RELAY_EXPECT_URL='https://relay.example/credential-path-secret/probe' \
FAKE_RELAY_EXPECT_TOKEN='relay-token-secret-marker-123456' \
timeout --signal=TERM --kill-after=1s 2s bash "$relay_script" "$partial_input" "$partial_output" > "$log_file" 2>&1
partial_exit=$?
set -e
[[ "$partial_exit" == 124 || "$partial_exit" == 137 ]] || fail 'expected the test deadline to interrupt the second chunk'
[[ "$(cat "$count_file")" == 2 ]] || fail 'expected one completed and one interrupted chunk'
jq -e 'length == 4 and all(.[]; (.status == "connected" or .status == "inconclusive") and (.observed_at | type == "string"))' "$partial_output" >/dev/null || fail 'interrupted run did not preserve exactly the completed chunk results'
assert_redacted

echo 'All probe relay client tests passed.'
