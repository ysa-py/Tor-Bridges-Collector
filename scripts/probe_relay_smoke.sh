#!/usr/bin/env bash
# Authenticated, content-checking deployed-edge canary for the probe relay.
# Never prints the relay endpoint/token, request/response bodies, raw curl stderr,
# or any candidate bridge address.
set -euo pipefail
export LC_ALL=C
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_url="${PROBE_RELAY_URL:-}"
relay_token="${PROBE_RELAY_TOKEN:-}"
dead_control_file="${PROBE_RELAY_SMOKE_DEAD_CONTROL_FILE:-$repo_root/data/pt_results.json}"
report_path="${PROBE_RELAY_SMOKE_REPORT_PATH:-}"
evidence_label="${PROBE_RELAY_SMOKE_EVIDENCE_LABEL:-unclassified}"
max_attempts="${PROBE_RELAY_SMOKE_MAX_ATTEMPTS:-3}"
retry_delay="${PROBE_RELAY_SMOKE_RETRY_DELAY_SECS:-2}"

write_failure_report() {
  local result="$1" attempts="$2" http_code="$3" failure_class="$4"
  [[ -n "$report_path" ]] || return 0
  case "$result:$failure_class" in
    not_run:preflight|failed:transport|failed:http|failed:content|failed:report) ;;
    *) return 1 ;;
  esac
  local report_tmp="${report_path}.tmp.$$"
  if ! mkdir -p "$(dirname "$report_path")" || \
     ! jq -n \
       --arg evidence_class "$evidence_label" \
       --arg result "$result" \
       --arg failure_class "$failure_class" \
       --arg http_code "$http_code" \
       --arg attempts "$attempts" \
       --arg run_id "${GITHUB_RUN_ID:-}" \
       --arg commit "${GITHUB_SHA:-}" \
       '{schema_version:1,kind:"probe_relay_smoke",evidence_class:$evidence_class,result:$result,
         run_id:(if $run_id=="" then null else $run_id end),
         commit:(if $commit=="" then null else $commit end),
         attempts:($attempts|tonumber),http_status:$http_code,failure_class:$failure_class,
         controls:[],stats:null}' > "$report_tmp"; then
    rm -f -- "$report_tmp"
    return 1
  fi
  chmod 600 "$report_tmp" && mv -f -- "$report_tmp" "$report_path"
}

fail_config() {
  write_failure_report not_run 0 000 preflight || true
  echo "::warning::$1"
  exit 1
}

if [[ "$evidence_label" != live_edge && "$evidence_label" != mock && "$evidence_label" != unclassified ]]; then
  evidence_label=unclassified
  fail_config 'Probe relay smoke test rejected an unsupported evidence label.'
fi
if [[ -z "$relay_url" || -z "$relay_token" ]]; then
  fail_config 'Authenticated probe relay smoke test requires PROBE_RELAY_URL and PROBE_RELAY_TOKEN; unauthenticated mode is disabled (values redacted).'
fi
if [[ "$relay_url" != https://* || "$relay_url" == *'?'* || "$relay_url" == *'#'* || "$relay_url" == *'@'* || "$relay_url" == *'"'* || "$relay_url" == *\\* || "$relay_url" == *$'\r'* || "$relay_url" == *$'\n'* || "$relay_url" == *[[:space:]]* || "$relay_url" == *[[:cntrl:]]* ]]; then
  fail_config 'Probe relay smoke test rejected an invalid HTTPS endpoint (URL redacted; user-info, queries, fragments, backslashes, and whitespace are disallowed).'
fi
if [[ ${#relay_token} -lt 16 || ${#relay_token} -gt 1024 || "$relay_token" == *$'\r'* || "$relay_token" == *$'\n'* || "$relay_token" == *[[:cntrl:]]* ]]; then
  fail_config 'Probe relay smoke test rejected an invalid authentication token (value redacted; 16-1024 printable characters are required).'
fi
if [[ ! "$max_attempts" =~ ^[1-5]$ ]]; then
  fail_config 'PROBE_RELAY_SMOKE_MAX_ATTEMPTS must be an integer from 1 to 5.'
fi
if [[ ! "$retry_delay" =~ ^([0-9]|10)$ ]]; then
  fail_config 'PROBE_RELAY_SMOKE_RETRY_DELAY_SECS must be an integer from 0 to 10.'
fi
if [[ ! -r "$dead_control_file" ]]; then
  fail_config 'Probe relay smoke test cannot load repository timeout-control candidates; no live call was made.'
fi

# Historical records are target candidates only. Filter out malformed, private,
# reserved, and non-timeout entries; the live response below must independently
# confirm at least one current timeout from the Cloudflare Worker vantage.
timeout_controls_json="$(python3 "$repo_root/scripts/select_probe_relay_timeout_controls.py" "$dead_control_file" 2>/dev/null)" || \
  fail_config 'Probe relay smoke test found no valid public timeout-control candidates; no live call was made.'
timeout_control_count="$(jq -er 'length' <<< "$timeout_controls_json" 2>/dev/null)" || \
  fail_config 'Probe relay smoke test could not validate its timeout-control candidate set; no live call was made.'
if [[ ! "$timeout_control_count" =~ ^[1-4]$ ]]; then
  fail_config 'Probe relay smoke test requires one to four public timeout-control candidates; no live call was made.'
fi
expected_count=$((timeout_control_count + 2))

base_url="${relay_url%/}"
base_url="${base_url%/probe}"
smoke_url="${base_url}/probe"

tmp_dir="$(mktemp -d)"
request_body="$tmp_dir/request.json"
trap 'rm -rf "$tmp_dir"' EXIT
response_file="$tmp_dir/response.json"
curl_stderr_file="$tmp_dir/curl.stderr"
curl_config="$tmp_dir/curl.conf"
header_file="$tmp_dir/auth.header"

jq -cn --argjson timeout_controls "$timeout_controls_json" '
  [{id:"silent-live",host:"example.com",port:443,transport:"vanilla"},
   {id:"refused-port",host:"example.com",port:1,transport:"vanilla"}] + $timeout_controls
' > "$request_body"
printf 'url = "%s"\n' "$smoke_url" > "$curl_config"
printf 'X-Probe-Token: %s\n' "$relay_token" > "$header_file"
chmod 600 "$request_body" "$curl_config" "$header_file"

validate_smoke_response() {
  jq -e --argjson timeout_controls "$timeout_controls_json" \
    --argjson expected_count "$expected_count" --argjson now "$(date -u +%s)" '
    def valid_observed_at:
      (.observed_at | type == "string" and
        test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,9})?Z$") and
        (try ((sub("[.][0-9]+Z$"; "Z") | fromdateiso8601) as $seen |
          $seen >= $now - 600 and $seen <= $now + 120) catch false));
    def valid_common:
      (.transport == "vanilla") and
      (.vantage | type == "object" and .type == "cloudflare_worker" and (.colo == null or (.colo | type == "string" and length <= 8))) and
      (.rtt_ms == null or (.rtt_ms | type == "number" and . >= 0)) and
      valid_observed_at and
      (.detail | type == "string" and length <= 256) and
      (.status | type == "string" and IN("connected","refused","timeout","inconclusive","error")) and
      (.stage | type == "string" and IN("S0","S1")) and
      (.success == (.status == "connected")) and
      (.stage == (if .status == "connected" then "S1" else "S0" end));
    def counts_match:
      (.stats.attempted == $expected_count and .stats.completed == $expected_count) and
      (.stats.connected == ([.results[] | select(.status == "connected")] | length)) and
      (.stats.refused == ([.results[] | select(.status == "refused")] | length)) and
      (.stats.timedOut == ([.results[] | select(.status == "timeout")] | length)) and
      (.stats.inconclusive == ([.results[] | select(.status == "inconclusive")] | length)) and
      (.stats.errored == ([.results[] | select(.status == "error")] | length)) and
      (.stats.success == .stats.connected);
    . as $response |
    type == "object" and
    (.results | type == "array" and length == $expected_count) and
    (.stats | type == "object") and counts_match and
    ([.results[] | select(.id == "silent-live" and .host == "example.com" and .port == 443 and
       .status == "connected" and .stage == "S1" and valid_common)] | length == 1) and
    ([.results[] | select(.id == "refused-port" and .host == "example.com" and .port == 1 and
       .status == "refused" and .stage == "S0" and valid_common)] | length == 1) and
    all($timeout_controls[];
      . as $control |
      ([$response.results[] | select(.id == $control.id and .host == $control.host and .port == $control.port and
        valid_common and
        ((.status == "timeout" and .stage == "S0") or
         (.status == "connected" and .stage == "S1") or
         (.status == "refused" and .stage == "S0") or
         ((.status == "inconclusive" or .status == "error") and .stage == "S0")))] | length == 1)
    ) and
    ([.results[] | select((.id | startswith("timeout-control-")) and .status == "timeout" and .stage == "S0" and valid_common)] | length >= 1)
  ' "$response_file" >/dev/null 2>&1
}

write_success_report() {
  [[ -n "$report_path" ]] || return 0
  local report_tmp="${report_path}.tmp.$$"
  if ! mkdir -p "$(dirname "$report_path")" || \
     ! jq --arg evidence_class "$evidence_label" \
       --arg run_id "${GITHUB_RUN_ID:-}" \
       --arg commit "${GITHUB_SHA:-}" \
       '{schema_version:1,kind:"probe_relay_smoke",evidence_class:$evidence_class,result:"passed",
         run_id:(if $run_id=="" then null else $run_id end),
         commit:(if $commit=="" then null else $commit end),
         controls:[.results[]|{id,status,stage,
           vantage:{type:.vantage.type,colo:(.vantage.colo // null)},observed_at,rtt_ms}],
         stats:{attempted:.stats.attempted,completed:.stats.completed,connected:.stats.connected,
           refused:.stats.refused,timed_out:.stats.timedOut,inconclusive:.stats.inconclusive,
           errored:.stats.errored,success:.stats.success,
           current_timeout_controls:([.results[]|select((.id|startswith("timeout-control-")) and .status=="timeout")]|length)}}' \
       "$response_file" > "$report_tmp"; then
    rm -f -- "$report_tmp"
    return 1
  fi
  chmod 600 "$report_tmp" && mv -f -- "$report_tmp" "$report_path"
}

classify_failure() {
  local curl_exit="$1"
  local http_code="$2"
  if (( curl_exit != 0 )); then
    case "$curl_exit" in
      6) printf 'DNS resolution failed (curl exit 6)' ;;
      7) printf 'connection failed (curl exit 7)' ;;
      28) printf 'request timed out (curl exit 28)' ;;
      35|51|58|60) printf 'TLS negotiation or certificate validation failed (curl exit %s)' "$curl_exit" ;;
      *) printf 'transport request failed (curl exit %s)' "$curl_exit" ;;
    esac
  else
    printf 'relay returned HTTP %s' "$http_code"
  fi
}

last_http_code=000
last_curl_exit=0
last_failure='no response'
attempt=0
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : > "$response_file"
  : > "$curl_stderr_file"
  curl_exit=0
  if http_code="$(curl --config "$curl_config" --silent --show-error \
      --output "$response_file" --write-out '%{http_code}' \
      --request POST --header 'Content-Type: application/json' \
      --header "@${header_file}" --data-binary "@${request_body}" \
      --connect-timeout 15 --max-time 30 --max-filesize 65536 2>"$curl_stderr_file")"; then
    curl_exit=0
  else
    curl_exit=$?
    http_code=000
  fi
  if [[ ! "$http_code" =~ ^[0-9]{3}$ ]]; then http_code=000; fi

  if (( curl_exit == 0 )) && [[ "$http_code" == 200 ]] && validate_smoke_response "$response_file"; then
    if ! write_success_report; then
      write_failure_report failed "$attempt" "$http_code" report || true
      echo '::warning::Probe relay content canary passed, but the redacted evidence report could not be written; failing closed.'
      exit 1
    fi
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      {
        echo '### Probe relay smoke evidence'
        echo "- Evidence class: \\`${evidence_label}\\`"
        echo "- Result: passed; authenticated live content controls matched the typed contract."
        echo "- Attempt: ${attempt}/${max_attempts}; target details and credentials redacted."
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    timeout_count="$(jq '[.results[]|select((.id|startswith("timeout-control-")) and .status=="timeout")]|length' "$response_file")"
    echo "Probe relay content canaries passed: silent-live S1, refused-port S0, ${timeout_count} freshly timed-out public control(s) S0 (HTTP 200; authenticated; targets and credentials redacted)."
    exit 0
  fi

  last_http_code="$http_code"
  last_curl_exit="$curl_exit"
  if (( curl_exit != 0 )); then
    last_failure="$(classify_failure "$curl_exit" "$http_code")"
  elif [[ "$http_code" == 200 ]]; then
    last_failure='relay response content did not match the typed control contract'
  else
    last_failure="$(classify_failure "$curl_exit" "$http_code")"
  fi

  retryable=false
  if (( curl_exit != 0 )); then
    retryable=true
  elif [[ "$http_code" == 408 || "$http_code" == 425 || "$http_code" == 429 || "$http_code" =~ ^5[0-9][0-9]$ ]]; then
    retryable=true
  elif [[ "$http_code" == 200 ]]; then
    retryable=true
  fi
  if [[ "$retryable" == true && "$attempt" -lt "$max_attempts" ]]; then
    echo "::warning::Probe relay canary attempt ${attempt}/${max_attempts} failed: ${last_failure}; retrying (endpoint, credentials, target details, and response body redacted)."
    if (( retry_delay > 0 )); then sleep "$((retry_delay * attempt))"; fi
  else
    break
  fi
done

if (( last_curl_exit != 0 )); then
  failure_class=transport
elif [[ "$last_http_code" == 200 ]]; then
  failure_class=content
else
  failure_class=http
fi
write_failure_report failed "$attempt" "$last_http_code" "$failure_class" || true
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo '### Probe relay smoke evidence'
    echo "- Evidence class: \\`${evidence_label}\\`"
    echo "- Result: failed closed; no bridge outcome was promoted."
    echo "- Attempts: ${attempt}/${max_attempts}; response details and credentials redacted."
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [[ "${PROBE_RELAY_SMOKE_FAILURE_MODE:-stage4}" == informational ]]; then
  echo "::notice::Probe relay canary unavailable after ${attempt} attempt(s): ${last_failure} (HTTP ${last_http_code}, curl exit ${last_curl_exit}). Informational only; required production controls are not changed by this optional check."
else
  echo "::warning::Probe relay canary unavailable after ${attempt} attempt(s): ${last_failure} (HTTP ${last_http_code}, curl exit ${last_curl_exit}). Stage 4 will be skipped for this run; collection and publication continue."
fi
exit 1
