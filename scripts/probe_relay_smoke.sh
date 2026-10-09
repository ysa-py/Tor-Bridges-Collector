#!/usr/bin/env bash
# Safe, retrying live canary for the optional Cloudflare probe relay.
# Never prints the configured relay URL, auth token, response body, or curl stderr.
set -euo pipefail

relay_url="${PROBE_RELAY_URL:-}"
relay_token="${PROBE_RELAY_TOKEN:-}"
smoke_host="${PROBE_RELAY_SMOKE_HOST:-127.0.0.1}"
max_attempts="${PROBE_RELAY_SMOKE_MAX_ATTEMPTS:-3}"
retry_delay="${PROBE_RELAY_SMOKE_RETRY_DELAY_SECS:-2}"

if [[ ! "$relay_url" =~ ^https://[^[:space:]]+$ || "$relay_url" == *'?'* || "$relay_url" == *'#'* || "$relay_url" == *'@'* ]]; then
  echo '::warning::Probe relay smoke test skipped: no valid HTTPS endpoint is configured (URL redacted; user-info, queries, and fragments are disallowed).'
  exit 1
fi
case "$smoke_host" in
  127.0.0.1|::1) ;;
  *)
    echo '::warning::Probe relay smoke test rejected an unsupported canary host.'
    exit 1
    ;;
esac
if [[ ! "$max_attempts" =~ ^[1-5]$ ]]; then
  echo '::warning::PROBE_RELAY_SMOKE_MAX_ATTEMPTS must be an integer from 1 to 5; Stage 4 canary will be skipped.'
  exit 2
fi
if [[ ! "$retry_delay" =~ ^([0-9]|10)$ ]]; then
  echo '::warning::PROBE_RELAY_SMOKE_RETRY_DELAY_SECS must be an integer from 0 to 10; Stage 4 canary will be skipped.'
  exit 2
fi
if [[ "$relay_token" == *$'\r'* || "$relay_token" == *$'\n'* ]]; then
  echo '::warning::Probe relay smoke test skipped: auth token contains an invalid line break (value redacted).'
  exit 1
fi

base_url="${relay_url%/}"
base_url="${base_url%/probe}"
smoke_url="${base_url}/probe"
request_body="[{\"host\":\"${smoke_host}\",\"port\":9999,\"transport\":\"obfs4\"}]"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
response_file="$tmp_dir/response.json"
header_file="$tmp_dir/headers.txt"
curl_stderr_file="$tmp_dir/curl.stderr"
: > "$header_file"
if [[ -n "$relay_token" ]]; then
  printf 'X-Probe-Token: %s\n' "$relay_token" > "$header_file"
  chmod 600 "$header_file"
fi

curl_args=(
  --silent --show-error
  --output "$response_file"
  --write-out '%{http_code}'
  --request POST
  --header 'Content-Type: application/json'
  --data "$request_body"
  --connect-timeout 15
  --max-time 30
)
if [[ -s "$header_file" ]]; then
  curl_args+=(--header "@$header_file")
fi
curl_args+=("$smoke_url")

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
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : > "$response_file"
  : > "$curl_stderr_file"
  curl_exit=0
  if http_code="$(curl "${curl_args[@]}" 2>"$curl_stderr_file")"; then
    curl_exit=0
  else
    curl_exit=$?
  fi
  if [[ ! "$http_code" =~ ^[0-9]{3}$ ]]; then
    http_code=000
  fi

  if (( curl_exit == 0 )) && [[ "$http_code" == 200 ]]; then
    echo "Probe relay canary passed (HTTP 200; host ${smoke_host}; endpoint and credentials redacted)."
    exit 0
  fi

  last_http_code="$http_code"
  last_curl_exit="$curl_exit"
  last_failure="$(classify_failure "$curl_exit" "$http_code")"

  retryable=false
  if (( curl_exit != 0 )); then
    retryable=true
  elif [[ "$http_code" == 408 || "$http_code" == 425 || "$http_code" == 429 || "$http_code" =~ ^5[0-9][0-9]$ ]]; then
    retryable=true
  fi
  if [[ "$retryable" == true && "$attempt" -lt "$max_attempts" ]]; then
    echo "::warning::Probe relay canary attempt ${attempt}/${max_attempts} failed: ${last_failure}; retrying (endpoint and credentials redacted)."
    if (( retry_delay > 0 )); then
      sleep "$((retry_delay * attempt))"
    fi
  else
    break
  fi
done

if [[ "${PROBE_RELAY_SMOKE_FAILURE_MODE:-stage4}" == informational ]]; then
  echo "::notice::Probe relay canary unavailable after ${attempt} attempt(s): ${last_failure} (HTTP ${last_http_code}, curl exit ${last_curl_exit}). Informational only; the required IPv4 canary already passed."
else
  echo "::warning::Probe relay canary unavailable after ${attempt} attempt(s): ${last_failure} (HTTP ${last_http_code}, curl exit ${last_curl_exit}). Stage 4 will be skipped for this run; collection and publication continue."
fi
exit 1
