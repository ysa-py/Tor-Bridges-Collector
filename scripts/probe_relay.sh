#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# probe_relay.sh — authenticated External Probe Relay client
#
# Delegates bounded TCP/TLS/transport observations to the Cloudflare Worker
# relay. TCP connect is S1 reachability; only a verified transport signature
# may be S2. Every response must satisfy the typed-result contract before it
# is accepted or aggregated. Secrets, raw response bodies, and peer errors
# are never written to the job log.
#
# v5.5 CHANGES (2026-09-07) — strictly additive:
#   - Format-4 descriptors now carry the url= path (e.g. a webtunnel line's
#     per-bridge token path /83c1327e…, or conjure's /api) in a new optional
#     `path` field (defaults to "/"). The Worker's fetch probes use it, so
#     the WebSocket-Upgrade request targets the actual per-bridge endpoint
#     real clients connect to instead of always the site root — without
#     changing any descriptor id/host/port/transport or counter.
#
# v5.4 CHANGES (2026-09-07) — strictly additive:
#   - Chunk stats now echo the Worker's https_controls array (when present):
#     known-good HTTPS endpoints (example.com, 1.1.1.1) probed through the
#     same Worker fetch path on every chunk that contains a non-tcp probe.
#     If all fronted-transport probes time out while the controls succeed,
#     the fronts themselves are unreachable from Cloudflare's network; if
#     the controls fail too, the Worker's fetch egress is the problem.
#     Diagnostics only.
#
# v5.3 CHANGES (2026-09-07) — strictly additive:
#   - Retains the original SNI/Host split and per-transport parsing while
#     requiring authenticated, typed Worker outcomes and redacting diagnostics.
#
# v5.2 CHANGES (2026-09-07) — strictly additive:
#   - URL-only lines that advertise front=/fronts= hosts (snowflake /
#     meek_lite / conjure / meek) now also emit one extra descriptor per
#     advertised front (host = url= CDN host, SNI = the front) so every
#     advertised front is relay-probed before a bridge is concluded
#     unreachable. Webtunnel output remains byte-identical to v5/v5.1.
#
# v5.1 CHANGES (2026-09-07) — strictly additive:
#   - URL-only parsing (Format 4) generalised from webtunnel-only to every
#     recognised transport that BridgeDB can distribute without a literal
#     endpoint (snowflake / meek_lite / meek-azure / conjure / meek): those
#     candidates previously fell through every arm (0% parsed). The branch
#     body is parameterised on $transport, so existing webtunnel output is
#     byte-identical to v5.
#   - Per-candidate parse audit trace ([stage=audit]): prints the raw line
#     and parse outcome for every snowflake/meek_lite/meek-azure/conjure/meek
#     candidate plus a bounded sample of 'other'-bucket lines.
#   - Bucket reconciliation rows after the fixed per-transport table:
#     counters whose bucket name is outside the fixed display list (e.g.
#     "unknown", where IP:PORT-only lines parsed by Formats 2/3 are counted)
#     are printed explicitly so parsed/sent totals reconcile with the table.
#
# v5 CHANGES (2026-08-11):
#   - Per-transport breakdown in the final summary
#     (obfs4/webtunnel/vanilla/snowflake/meek_lite/etc.) so regressions
#     in any single transport are immediately visible in every run's log.
#   - URL-only webtunnel bridges are now recognised: the real CDN domain
#     is extracted from the `url=` parameter (e.g. `vika7.space`) and sent
#     as {host, port, transport:"webtunnel"} for TCP reachability probing.
#     The downstream webtunnel_probe.rs module does deeper TLS+WebSocket
#     Upgrade checks where TCP probing alone is insufficient.
#   - Dropped lines are now counted per-transport in the summary.
#
# v4 CHANGES (2026-08-10):
#   - Parses IP:PORT-only bridge lines (without transport prefix) — the
#     previous parser silently dropped ~28% of bridge lines (465/1673).
#   - Per-chunk diagnostics: bridges_in_file vs bridges_parsed vs
#     bridges_sent. Detects parse failures before they become silent drops.
#   - Final structured summary uses typed connected/refused/timeout/
#     inconclusive/error counts; a TCP connection is never labelled working.
#
# Usage:
#   bash scripts/probe_relay.sh <input_json> <output_json>
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

INPUT="${1:-bridge/bridge_list_for_testing.json}"
OUTPUT="${2:-data/pt_results.json}"
CHUNK_SIZE="${PROBE_RELAY_CHUNK_SIZE:-6}"
MAX_RETRIES="${PROBE_RELAY_MAX_RETRIES:-2}"
RELAY_URL="${PROBE_RELAY_URL:-}"
RELAY_TOKEN="${PROBE_RELAY_TOKEN:-}"

echo "——— External Probe Relay — CI Egress Fix v5 ———"
if [[ -n "$RELAY_URL" && -n "$RELAY_TOKEN" ]]; then
  echo "Relay:     configured (URL and credentials redacted)"
else
  echo "Relay:     missing configuration (URL and credentials redacted)"
fi
echo "Input:     configured (path redacted)"
echo "Output:    configured (path redacted)"
echo "Chunk size: $CHUNK_SIZE"
echo "Max retries: $MAX_RETRIES"

mkdir -p "$(dirname "$OUTPUT")"
# Never let an auth/config/input failure or a later timeout leave evidence from
# an earlier run masquerading as this run's observation set.
printf '[]\\n' > "$OUTPUT"

# ── Guard: relay URL and authentication are both mandatory ────────────────────
if [[ -z "$RELAY_URL" || -z "$RELAY_TOKEN" ]]; then
  echo "::error::PROBE_RELAY_URL and PROBE_RELAY_TOKEN are both required; unauthenticated relay mode is disabled."
  echo '[]' > "$OUTPUT"
  exit 2
fi
if [[ "$RELAY_URL" != https://* || "$RELAY_URL" == *'?'* || "$RELAY_URL" == *'#'* || "$RELAY_URL" == *'@'* || "$RELAY_URL" == *'"'* || "$RELAY_URL" == *\\* || "$RELAY_URL" == *$'\r'* || "$RELAY_URL" == *$'\n'* || "$RELAY_URL" == *[[:space:]]* || "$RELAY_URL" == *[[:cntrl:]]* ]]; then
  echo "::error::PROBE_RELAY_URL is invalid (endpoint redacted; HTTPS without user-info, query, fragment, or whitespace is required)."
  echo '[]' > "$OUTPUT"
  exit 2
fi
if [[ ${#RELAY_TOKEN} -lt 16 || ${#RELAY_TOKEN} -gt 1024 || "$RELAY_TOKEN" == *$'\r'* || "$RELAY_TOKEN" == *$'\n'* || "$RELAY_TOKEN" == *[[:cntrl:]]* ]]; then
  echo "::error::PROBE_RELAY_TOKEN is invalid (value redacted; 16-1024 printable characters are required)."
  echo '[]' > "$OUTPUT"
  exit 2
fi
if [[ ! "$CHUNK_SIZE" =~ ^[1-9][0-9]*$ ]] || (( CHUNK_SIZE > 6 )); then
  echo "::error::PROBE_RELAY_CHUNK_SIZE must be an integer from 1 to 6."
  echo '[]' > "$OUTPUT"
  exit 2
fi
if [[ ! "$MAX_RETRIES" =~ ^[0-5]$ ]]; then
  echo "::error::PROBE_RELAY_MAX_RETRIES must be an integer from 0 to 5."
  echo '[]' > "$OUTPUT"
  exit 2
fi

# ── Validate input file exists ───────────────────────────────────────────────
if [ ! -f "$INPUT" ]; then
  echo "[stage=guard] WARNING: Input file is unavailable — writing empty results"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Extract bridge lines from the JSON array ─────────────────────────────────
EXTRACT_ERR=$(mktemp)
if BRIDGE_LINES=$(jq -r '
  if type == "array" then
    .[] | select(type == "string")
  else
    empty
  end
' "$INPUT" 2>"$EXTRACT_ERR"); then
  EXTRACT_EC=0
else
  EXTRACT_EC=$?
  BRIDGE_LINES=""
fi

if [ "$EXTRACT_EC" -ne 0 ] && [ -s "$EXTRACT_ERR" ]; then
  echo "[stage=extract] input JSON could not be decoded (details redacted)."
fi
rm -f "$EXTRACT_ERR"

if [ -z "$BRIDGE_LINES" ]; then
  FALLBACK_ERR=$(mktemp)
  BRIDGE_LINES=$(jq -r '
    if type == "array" then
      .[] | if type == "object" then .fingerprint // .bridge_line // .line // empty
            elif type == "string" then .
            else empty end
    elif type == "object" and has("bridges") then
      .bridges[] | if type == "object" then .fingerprint // .bridge_line // .line // empty
                   elif type == "string" then .
                   else empty end
    else empty
    end
  ' "$INPUT" 2>"$FALLBACK_ERR" || true)
  if [ -s "$FALLBACK_ERR" ]; then
    echo "[stage=extract] fallback input shape could not be decoded (details redacted)."
  fi
  rm -f "$FALLBACK_ERR"
fi

LINE_COUNT=$(echo "$BRIDGE_LINES" | grep -c . || echo 0)
LINE_COUNT=${LINE_COUNT//[$'\t\r\n ']/}
LINE_COUNT=${LINE_COUNT:-0}

if [ "$LINE_COUNT" -eq 0 ]; then
  echo "[stage=extract] WARNING: No bridge lines extracted — writing empty results"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Per-transport input counts (before parsing) ──────────────────────────────
echo ""
echo "[stage=extract] Per-transport input counts:"
echo "$BRIDGE_LINES" | while IFS= read -r line; do
  t=$(echo "$line" | awk '{print $1}')
  case "$t" in
    obfs4|webtunnel|vanilla|snowflake|meek_lite|meek-azure|conjure|meek) echo "$t" ;;
    *) echo "other" ;;
  esac
done | sort | uniq -c | sort -rn | while read -r count transport; do
  echo "  ${transport}: ${count}"
done
echo "  total: ${LINE_COUNT}"
echo ""

echo "[stage=extract] extracted=${LINE_COUNT}"

# ── Shared jq expression for parsing bridge lines into BridgeDescriptor ──────
# v5: handles FOUR formats:
#   1. "transport IP:PORT ..."     — standard bridge line
#   2. "IP:PORT fingerprint..."    — IP:PORT-only (no transport prefix)
#   3. "[IPv6]:PORT ..."           — IPv6 IP:PORT-only (no transport prefix)
#   4. "webtunnel FINGERPRINT url=https://..." — URL-only webtunnel (no IP:port)
# All other formats are dropped with a per-transport count.
read -r -d '' PARSE_BRIDGE_JQ <<'JQEOF' || true
def parse_bridge:
  # Detect transport from the first token
  (split(" ") | .[0]) as $first
  | (if $first == "obfs4" or $first == "webtunnel" or $first == "vanilla"
        or $first == "snowflake" or $first == "meek_lite" or $first == "meek-azure"
        or $first == "conjure" or $first == "meek"
     then $first else "unknown" end) as $transport
  |
  # Format 1: "transport IP:PORT ..." or "transport [IPv6]:PORT ..."
  if test("^[a-zA-Z][a-zA-Z0-9_-]* +[0-9a-fA-F.:\\[\\]]+:[0-9]+ ") then
    split(" ") as $parts
    | ($parts[1] | split(":")) as $addr
    | { host: (if ($addr | length) > 2 then ($addr[:-1] | join(":")) else $addr[0] end),
        port: ($addr[-1] | tonumber),
        transport: $parts[0],
        id: ("line-" + $parts[0] + "-" + (if ($addr | length) > 2 then ($addr[:-1] | join("_")) else $addr[0] end) + "-" + ($addr[-1])) }
  # Format 4: "transport FINGERPRINT url=https://cdn.example.com/path ..."
  # URL-only bridge lines (no literal IP:port) for every transport BridgeDB
  # can distribute without a literal endpoint — webtunnel, snowflake,
  # meek_lite, meek-azure, conjure, meek. The real CDN/front domain is
  # extracted from the `url=` parameter for relay probing.
  #
  # v5.1 (ADDITIVE): v5 recognised ONLY webtunnel URL-only lines; snowflake /
  # meek_lite / meek-azure / conjure / meek candidates of the same shape were
  # dropped by every arm (structural gap, 0/5 parsed in live runs). The gate
  # is now any recognised transport carrying url=, and the branch body is
  # parameterised on $transport — so the existing webtunnel output stays
  # byte-identical (transport == $transport == "webtunnel" and the id prefix
  # "$transport-url-" == "webtunnel-url-"), while the other transports parse
  # into their own buckets and are relay-probed per their class (TLS for
  # snowflake/meek/conjure — see probe-relay/src/index.ts classifyProbe).
  elif $transport != "unknown" and test("url=";"i") then
    # v5.5 (ADDITIVE): the url= capture also extracts the request path
    # (webtunnel per-bridge token paths, conjure's /api, …); descriptors
    # carry it in an optional `path` field so the relay's fetch probes hit
    # the real endpoint instead of always the site root. Defaults to "/".
    (capture("(?i)https?://(?<host>[^/:\\s]+)(?::(?<port>\\d+))?(?<path>/[^\\s]*)?") //
     {host: "webtunnel-cdn", port: "443"}) as $raw
    | ((($raw.path // "/") | if . == "" then "/" else . end) // "/") as $path
    | (capture("(?i)fronts?=(?<frontlist>[^ ]+)")? // {frontlist: ""}) as $fr
    | (($fr.frontlist | split(",")) | map(select(length > 0 and . != $raw.host)) | unique) as $fronts
    | ( { host: $raw.host,
          port: (($raw.port // "443") | tonumber),
          transport: $transport,
          path: $path,
          id: ($transport + "-url-" + $raw.host + "-" + ($raw.port // "443")) },
        # v5.2 (ADDITIVE): when a non-webtunnel line advertises front=
        # / fronts= hosts, emit one extra descriptor per front (host stays
        # the url= CDN host, SNI is the advertised front) so every
        # advertised front is relay-probed before a bridge is concluded
        # unreachable. Webtunnel output stays byte-identical to v5/v5.1.
        (if $transport != "webtunnel" then
           $fronts[] | { host: $raw.host,
                         port: (($raw.port // "443") | tonumber),
                         transport: $transport,
                         path: $path,
                         sni: .,
                         id: ($transport + "-url-" + $raw.host + "-front-" + .) }
         else empty end) )
  # Format 2: "IPv4:PORT ..." (no transport prefix)
  # (Note: an obfs4/vanilla line never carries url=, so Format 4 cannot
  # misfire on IP:port forms — Format 1 already matched those above.)
  elif test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+ ") then
    split(" ") as $parts
    | ($parts[0] | split(":")) as $addr
    | { host: $addr[0],
        port: ($addr[1] | tonumber),
        transport: "unknown",
        id: ("line-unknown-" + $addr[0] + "-" + $addr[1]) }
  # Format 3: "[IPv6]:PORT ..." (no transport prefix)
  elif test("^\\[[0-9a-fA-F:]+\\]:[0-9]+ ") then
    split(" ") as $parts
    | ($parts[0] | split(":")) as $addr
    | { host: ($addr[:-1] | join(":")),
        port: ($addr[-1] | tonumber),
        transport: "unknown",
        id: ("line-unknown-" + ($addr[:-1] | join("_")) + "-" + $addr[-1]) }
  else
    empty
  end;
split("\n") | map(select(length > 0) | parse_bridge)
JQEOF

# ── Per-candidate parse audit (ADDITIVE v5.1) ─────────────────────────────────
# Pure diagnostics. Emits bounded, sanitized transport/host/port parse outcomes
# for fronted transports plus a bounded sample of unrecognized first-token
# buckets. Raw bridge lines, tokens, and peer-provided text are never logged.
echo ""
echo "[stage=audit] Per-candidate parse audit (additive diagnostics):"
AUDIT_TRACED=0
AUDIT_OTHER_SHOWN=0
AUDIT_OTHER_CAP=10
while IFS= read -r audit_raw; do
  [ -z "$audit_raw" ] && continue
  audit_first=$(printf '%s\n' "$audit_raw" | awk '{print $1}')
  audit_token_safe=$(printf '%s' "$audit_first" | LC_ALL=C tr -cd '[:alnum:]_.+-' | cut -c1-32)
  audit_trace=0
  case "$audit_first" in
    snowflake|meek_lite|meek-azure|conjure|meek) audit_trace=1 ;;
    obfs4|webtunnel|vanilla) audit_trace=0 ;;
    *)
      # 'other'-bucket line: trace only a bounded sample.
      if [ "$AUDIT_OTHER_SHOWN" -lt "$AUDIT_OTHER_CAP" ]; then
        audit_trace=1
        AUDIT_OTHER_SHOWN=$((AUDIT_OTHER_SHOWN + 1))
      fi
      ;;
  esac
  [ "$audit_trace" -ne 1 ] && continue
  AUDIT_ERR=$(mktemp)
  audit_json=$(printf '%s\n' "$audit_raw" | jq -R -s "$PARSE_BRIDGE_JQ" 2>"$AUDIT_ERR" || echo '[]')
  if [ -s "$AUDIT_ERR" ]; then
    echo "[stage=audit] candidate parse failed (details redacted)."
  fi
  rm -f "$AUDIT_ERR"
  audit_count=$(printf '%s\n' "$audit_json" | jq 'length' 2>/dev/null || echo 0)
  audit_count=${audit_count//[$'\t\r\n ']/}
  audit_outcome="unparsed"
  audit_detail="-"
  if [ "${audit_count:-0}" != "0" ]; then
    audit_outcome="parsed"
    audit_detail=$(printf '%s\n' "$audit_json" | jq -r '.[0] | .transport + " port=" + (.port|tostring)' 2>/dev/null || echo "-")
  fi
  echo "[stage=audit] token=${audit_token_safe:-unknown} outcome=${audit_outcome} ${audit_detail} raw=<redacted>"
  AUDIT_TRACED=$((AUDIT_TRACED + 1))
done <<< "$BRIDGE_LINES"
echo "[stage=audit] traced=${AUDIT_TRACED} (every snowflake/meek_lite/meek-azure/conjure/meek candidate; first ${AUDIT_OTHER_SHOWN} 'other'-bucket lines sampled)"

# ── Chunked relay submission ─────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
OUTPUT_TMP="$(mktemp "${OUTPUT}.tmp.XXXXXX")"
cleanup_probe_relay() {
  rm -rf "$TMP_DIR"
  rm -f "$OUTPUT_TMP"
}
trap cleanup_probe_relay EXIT

# Normalize URL
RELAY_URL="${RELAY_URL%/}"
RELAY_URL="${RELAY_URL%/probe}"
RELAY_URL="${RELAY_URL}/probe"

# Keep both the endpoint (which may contain a secret path) and the bearer
# token out of process arguments and logs. The restrictive URL validator
# above excludes quotes/backslashes before this curl config is written.
CURL_CONFIG="$TMP_DIR/relay.curl.conf"
TOKEN_HEADER_FILE="$TMP_DIR/probe-token.header"
printf 'url = "%s"\n' "$RELAY_URL" > "$CURL_CONFIG"
printf 'X-Probe-Token: %s\n' "$RELAY_TOKEN" > "$TOKEN_HEADER_FILE"
chmod 600 "$CURL_CONFIG" "$TOKEN_HEADER_FILE"
AUTH_HEADER=(--header "@${TOKEN_HEADER_FILE}")

CHUNK_IDX=0
echo "$BRIDGE_LINES" | split -l "$CHUNK_SIZE" - "$TMP_DIR/chunk_"

ALL_RESULTS="$TMP_DIR/all_results.json"
echo '[]' > "$ALL_RESULTS"

# Publish each fully completed parallel group atomically. If the outer Actions
# timeout stops the next group, downstream stages still see this run's typed
# partial outcomes rather than a stale file from a prior workflow.
write_results_snapshot() {
  local completed_chunks="$1"
  local merge_file="$TMP_DIR/merge_snapshot.jsonl"
  : > "$merge_file"
  if (( completed_chunks > 0 )); then
    for idx in $(seq 1 "$completed_chunks"); do
      if [ -f "$TMP_DIR/res_${idx}.json" ]; then
        cat "$TMP_DIR/res_${idx}.json" >> "$merge_file"
        printf '\n' >> "$merge_file"
      fi
    done
  fi
  if jq -s 'add // []' "$merge_file" > "$OUTPUT_TMP" && mv -f "$OUTPUT_TMP" "$OUTPUT"; then
    return 0
  fi
  echo "[stage=merge] Could not atomically update the typed partial-result snapshot."
  return 1
}

# ── Parallel, deterministic chunk submission ───────────────────────────────
# Each chunk is processed by its own worker. Every worker writes a per-chunk
# result array, a numeric per-chunk stats object, and a per-chunk log file.
# After all workers finish, the parent merges the per-chunk results IN CHUNK
# ORDER and recomputes the per-transport counters from the on-disk chunk/result
# files, so the final result array and summary are byte-identical to a
# sequential run (only wall-clock changes: chunks run concurrently).
PROBE_RELAY_PARALLELISM="${PROBE_RELAY_PARALLELISM:-8}"
if [[ ! "$PROBE_RELAY_PARALLELISM" =~ ^[1-8]$ ]]; then
  echo "::error::PROBE_RELAY_PARALLELISM must be an integer from 1 to 8."
  echo '[]' > "$OUTPUT"
  exit 2
fi

validate_relay_response() {
  local response_file="$1"
  local expected_count="$2"
  local request_file="$3"
  jq -e --argjson expected_count "$expected_count" --slurpfile request "$request_file" '
    def nonnegative_integer: type == "number" and floor == . and . >= 0;
    type == "object" and
    (.results | type == "array") and
    ((.results | length) == $expected_count) and
    ($request[0] | type == "array" and length == $expected_count) and
    (.stats | type == "object") and
    (.stats.attempted | nonnegative_integer) and
    (.stats.completed | nonnegative_integer) and
    (.stats.connected | nonnegative_integer) and
    (.stats.refused | nonnegative_integer) and
    (.stats.timedOut | nonnegative_integer) and
    (.stats.inconclusive | nonnegative_integer) and
    (.stats.errored | nonnegative_integer) and
    (.stats.success == .stats.connected) and
    (.stats.completed == $expected_count) and
    (.stats.attempted <= $expected_count) and
    ((.stats.connected + .stats.refused + .stats.timedOut + .stats.inconclusive + .stats.errored) == .stats.completed) and
    ([range(0; $expected_count) as $index | select(
      .results[$index].id == $request[0][$index].id and
      (.results[$index].transport | ascii_downcase) == ($request[0][$index].transport | ascii_downcase) and
      (.results[$index].host | ascii_downcase | sub("\\.$"; "")) == ($request[0][$index].host | ascii_downcase | sub("\\.$"; "")) and
      .results[$index].port == $request[0][$index].port
    )] | length) == $expected_count and
    ([.results[] | select(
      (.id | type == "string") and
      (.transport | type == "string") and
      (.host | type == "string") and
      (.port | type == "number" and floor == . and . >= 1 and . <= 65535) and
      (.status == "connected" or .status == "refused" or .status == "timeout" or .status == "inconclusive" or .status == "error") and
      (.stage == "S0" or .stage == "S1" or .stage == "S2" or .stage == "S3" or .stage == "S4") and
      (.vantage | type == "object" and .type == "cloudflare_worker" and (.colo == null or (.colo | type == "string"))) and
      (.rtt_ms | type == "number" and . >= 0) and
      (.observed_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\\r\\n]+Z$")) and
      (.probe_type | type == "string" and length <= 64) and
      (.detail | type == "string" and length <= 256) and
      (.error_class == null or (.error_class | type == "string" and length <= 64)) and
      (.error == null or (.error | type == "string" and length <= 256)) and
      (.http_status == null or (.http_status | type == "number" and floor == . and . >= 100 and . <= 599)) and
      (.success == (.status == "connected")) and
      (if .status == "connected" then (.stage == "S1" or .stage == "S2" or .stage == "S3" or .stage == "S4") else true end)
    )] | length) == $expected_count
  ' "$response_file" >/dev/null 2>&1
}

curl_failure_class() {
  case "$1" in
    6) printf 'DNS resolution failed' ;;
    7) printf 'connection failed' ;;
    28) printf 'request timed out' ;;
    35|51|58|60) printf 'TLS negotiation or certificate validation failed' ;;
    *) printf 'transport request failed' ;;
  esac
}

process_chunk() {
  local chunk_file="$1"
  local idx="$2"
  local log="$TMP_DIR/log_${idx}.txt"
  local res="$TMP_DIR/res_${idx}.json"
  local stat="$TMP_DIR/stat_${idx}.json"
  local request_file="$TMP_DIR/request_${idx}.json"
  local source_lines_file="$TMP_DIR/source_lines_${idx}.json"
  exec >"$log" 2>&1

  local BRIDGES_IN_FILE BRIDGES_PARSED
  BRIDGES_IN_FILE=$(grep -c . "$chunk_file" 2>/dev/null || echo 0)
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE//[$'\t\r\n ']/}
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE:-0}

  local PARSE_ERR CHUNK_JSON
  PARSE_ERR=$(mktemp)
  CHUNK_JSON=$(jq -R -s "$PARSE_BRIDGE_JQ" "$chunk_file" 2>"$PARSE_ERR") || CHUNK_JSON='[]'
  if [ -s "$PARSE_ERR" ]; then
    echo "[stage=parse] Chunk $idx parser rejected malformed input (details redacted)."
  fi
  rm -f "$PARSE_ERR"

  BRIDGES_PARSED=$(echo "$CHUNK_JSON" | jq 'length' 2>/dev/null || echo 0)
  BRIDGES_PARSED=${BRIDGES_PARSED//[$'\t\r\n ']/}
  BRIDGES_PARSED=${BRIDGES_PARSED:-0}
  if [ "$BRIDGES_PARSED" -lt "$BRIDGES_IN_FILE" ]; then
    DROPPED=$((BRIDGES_IN_FILE - BRIDGES_PARSED))
    echo "[stage=parse] Chunk $idx: ${BRIDGES_PARSED}/${BRIDGES_IN_FILE} lines parsed (${DROPPED} dropped — malformed or unsupported)."
  fi

  local CHUNK_FAILURES=0 MERGE_FAILURES=0 SENT=0 ATTEMPTED=0 COMPLETED=0
  local CONNECTED=0 REFUSED=0 TIMEDOUT=0 INCONCLUSIVE=0 ERRORED=0 CURL_SUCCESS=0
  local SUCCESS=false RETRY=0 HTTP_CODE CURL_EXIT=0
  if [ "$BRIDGES_PARSED" -eq 0 ]; then
    echo "[stage=parse] Chunk $idx: no valid descriptors; skipping network activity."
    echo '[]' > "$res"
    printf '{"parsed":0,"sent":0,"attempted":0,"completed":0,"connected":0,"refused":0,"timedout":0,"inconclusive":0,"errored":0,"chunk_failures":0,"merge_failures":0,"curl_success":0}\n' > "$stat"
    return
  fi
  printf '%s\n' "$CHUNK_JSON" > "$request_file"
  chmod 600 "$request_file"

  # Preserve an input-line mapping locally without sending bridge credentials
  # or fingerprints to the Worker. The response contract already guarantees
  # descriptor order and identity, including multiple front descriptors per line.
  local SOURCE_LINES=()
  local bridge_line descriptor_count
  while IFS= read -r bridge_line; do
    [ -z "$bridge_line" ] && continue
    descriptor_count=$(printf '%s\n' "$bridge_line" | jq -R "$PARSE_BRIDGE_JQ" 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
    descriptor_count=${descriptor_count//[$'\t\r\n ']/}
    if [[ "$descriptor_count" =~ ^[1-9][0-9]*$ ]]; then
      for ((descriptor_index = 0; descriptor_index < descriptor_count; descriptor_index++)); do
        SOURCE_LINES+=("$bridge_line")
      done
    fi
  done < "$chunk_file"
  if [ "${#SOURCE_LINES[@]}" -ne "$BRIDGES_PARSED" ]; then
    echo "[stage=merge] Chunk $idx could not map every descriptor to its source bridge line."
    echo '[]' > "$res"
    printf '{"parsed":%s,"sent":0,"attempted":0,"completed":0,"connected":0,"refused":0,"timedout":0,"inconclusive":0,"errored":0,"chunk_failures":0,"merge_failures":1,"curl_success":0}\n' "$BRIDGES_PARSED" > "$stat"
    return
  fi
  printf '%s\n' "${SOURCE_LINES[@]}" | jq -R . | jq -s . > "$source_lines_file"
  chmod 600 "$source_lines_file"

  while [ "$RETRY" -le "$MAX_RETRIES" ]; do
    echo "[stage=probe] Chunk $idx — sending ${BRIDGES_PARSED} descriptors (attempt $((RETRY + 1))/$((MAX_RETRIES + 1)))..."
    local CURL_ERR
    CURL_ERR=$(mktemp)
    CURL_EXIT=0
    if HTTP_CODE="$(curl --config "$CURL_CONFIG" --silent \
      --output "$TMP_DIR/resp_${idx}.json" --write-out '%{http_code}' \
      --request POST --header 'Content-Type: application/json' \
      "${AUTH_HEADER[@]}" --data-binary "@${request_file}" \
      --connect-timeout 15 --max-time 120 --max-filesize 65536 2>"$CURL_ERR")"; then
      :
    else
      CURL_EXIT=$?
      HTTP_CODE=000
    fi
    rm -f "$CURL_ERR"

    if [[ ! "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then HTTP_CODE=000; fi
    if [[ "$HTTP_CODE" == 200 ]]; then
      if validate_relay_response "$TMP_DIR/resp_${idx}.json" "$BRIDGES_PARSED" "$request_file"; then
        echo "[stage=probe] Chunk $idx: HTTP 200 with ${BRIDGES_PARSED} typed outcomes."
        SUCCESS=true
        CURL_SUCCESS=1
        break
      fi
      echo "[stage=probe] Chunk $idx: HTTP 200 response failed typed-result contract (body redacted)."
      HTTP_CODE=502
    elif (( CURL_EXIT != 0 )); then
      echo "[stage=probe] Chunk $idx: $(curl_failure_class "$CURL_EXIT") (curl exit ${CURL_EXIT}; endpoint and diagnostics redacted)."
    else
      echo "[stage=probe] Chunk $idx: HTTP ${HTTP_CODE} (response body redacted)."
    fi
    RETRY=$((RETRY + 1))
    if (( RETRY <= MAX_RETRIES )); then sleep $((RETRY * 2)); fi
  done

  local CHUNK_STATS='{}'
  if [ "$SUCCESS" = true ] && [ -s "$TMP_DIR/resp_${idx}.json" ]; then
    SENT=$BRIDGES_PARSED
    CHUNK_STATS=$(jq '{attempted: .stats.attempted, completed: .stats.completed, connected: .stats.connected, refused: .stats.refused, timedOut: .stats.timedOut, inconclusive: .stats.inconclusive, errored: .stats.errored}' "$TMP_DIR/resp_${idx}.json" 2>/dev/null || echo '{}')
    if [ "$CHUNK_STATS" != "{}" ]; then
      echo "[stage=stats] Chunk $idx Worker outcomes: $CHUNK_STATS"
      ATTEMPTED=$(echo "$CHUNK_STATS" | jq -r '.attempted // 0' 2>/dev/null || echo 0)
      COMPLETED=$(echo "$CHUNK_STATS" | jq -r '.completed // 0' 2>/dev/null || echo 0)
      CONNECTED=$(echo "$CHUNK_STATS" | jq -r '.connected // 0' 2>/dev/null || echo 0)
      REFUSED=$(echo "$CHUNK_STATS" | jq -r '.refused // 0' 2>/dev/null || echo 0)
      TIMEDOUT=$(echo "$CHUNK_STATS" | jq -r '.timedOut // 0' 2>/dev/null || echo 0)
      INCONCLUSIVE=$(echo "$CHUNK_STATS" | jq -r '.inconclusive // 0' 2>/dev/null || echo 0)
      ERRORED=$(echo "$CHUNK_STATS" | jq -r '.errored // 0' 2>/dev/null || echo 0)
    fi

    local MERGE_ERR
    MERGE_ERR=$(mktemp)
    if jq --slurpfile source_lines "$source_lines_file" '
      .results as $results | $source_lines[0] as $lines |
      if ($results | length) == ($lines | length) then
        [range(0; ($results | length)) as $index | $results[$index] + {line: $lines[$index]}]
      else error("descriptor/source-line count mismatch") end
    ' "$TMP_DIR/resp_${idx}.json" > "$res" 2>"$MERGE_ERR"; then
      :
    else
      MERGE_FAILURES=1
      echo "[stage=merge] Chunk $idx result merge failed (details and body redacted)."
      echo '[]' > "$res"
    fi
    rm -f "$MERGE_ERR"
  else
    CHUNK_FAILURES=1
    echo "[stage=probe] WARNING: Chunk $idx failed after $((MAX_RETRIES + 1)) attempts; recording inconclusive outcomes only."
    local ALL_RES=()
    local SKIPPED_UNPARSED=0
    local OBSERVED_AT
    OBSERVED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    while IFS= read -r bridge_line; do
      [ -z "$bridge_line" ] && continue
      local PARSED WITH_ERR PARSED_COUNT
      PARSED=$(printf '%s\n' "$bridge_line" | jq -R "$PARSE_BRIDGE_JQ" 2>/dev/null || echo '[]')
      PARSED_COUNT=$(echo "$PARSED" | jq 'length' 2>/dev/null || echo 0)
      PARSED_COUNT=${PARSED_COUNT//[$'\t\r\n ']/}
      if [[ "$PARSED_COUNT" =~ ^[1-9][0-9]*$ ]]; then
        while IFS= read -r WITH_ERR; do
          [ -n "$WITH_ERR" ] && ALL_RES+=("$WITH_ERR")
        done < <(echo "$PARSED" | jq -c --arg line "$bridge_line" --arg observed_at "$OBSERVED_AT" '
          map(. + {line:$line,success:false,status:"inconclusive",stage:"S0",vantage:null,rtt_ms:null,latency_ms:null,observed_at:$observed_at,error:"relay_unreachable",error_class:"relay_unreachable",detail:"relay unavailable; no probe result"})[]
        ' 2>/dev/null)
      else
        # Unparseable inputs are source candidates, not relay observations.
        SKIPPED_UNPARSED=$((SKIPPED_UNPARSED + 1))
      fi
    done < "$chunk_file"
    if [ "${#ALL_RES[@]}" -gt 0 ]; then
      printf '[%s]\n' "$(IFS=,; echo "${ALL_RES[*]}")" > "$res"
    else
      printf '[]\n' > "$res"
    fi
    if [ "$SKIPPED_UNPARSED" -gt 0 ]; then
      echo "[stage=probe] Chunk $idx omitted ${SKIPPED_UNPARSED} unparsed source candidate(s) from relay observations."
    fi
  fi

  printf '{"parsed":%s,"sent":%s,"attempted":%s,"completed":%s,"connected":%s,"refused":%s,"timedout":%s,"inconclusive":%s,"errored":%s,"chunk_failures":%s,"merge_failures":%s,"curl_success":%s}\n' \
    "$BRIDGES_PARSED" "$SENT" "$ATTEMPTED" "$COMPLETED" "$CONNECTED" "$REFUSED" "$TIMEDOUT" "$INCONCLUSIVE" "$ERRORED" "$CHUNK_FAILURES" "$MERGE_FAILURES" "$CURL_SUCCESS" > "$stat"
}

# Gather chunk files (sorted for deterministic order).
mapfile -t CHUNK_FILES < <(printf '%s\n' "$TMP_DIR"/chunk_* | sort)
for chunk_file in "${CHUNK_FILES[@]}"; do
  CHUNK_IDX=$((CHUNK_IDX + 1))
  process_chunk "$chunk_file" "$CHUNK_IDX" &
  if (( CHUNK_IDX % PROBE_RELAY_PARALLELISM == 0 )); then
    if ! wait; then
      echo "[stage=probe] A relay worker exited unexpectedly; preserving every completed chunk."
    fi
    if ! write_results_snapshot "$CHUNK_IDX"; then
      echo "::warning::partial-result snapshot update failed; keeping the last valid output file"
    fi
  fi
done
if ! wait; then
  echo "[stage=probe] A relay worker exited unexpectedly; preserving every completed chunk."
fi
if ! write_results_snapshot "$CHUNK_IDX"; then
  echo "::error::could not finalize the typed relay result snapshot"
  exit 2
fi

# Replay per-chunk logs in order so the step log stays deterministic.
for idx in $(seq 1 "$CHUNK_IDX"); do
  [ -f "$TMP_DIR/log_${idx}.txt" ] && cat "$TMP_DIR/log_${idx}.txt"
done

# Aggregate numeric stats across chunks.
TOTAL_PARSED=0
TOTAL_SENT=0
TOTAL_ATTEMPTED=0
TOTAL_COMPLETED=0
TOTAL_CONNECTED=0
TOTAL_REFUSED=0
TOTAL_TIMEDOUT=0
TOTAL_INCONCLUSIVE=0
TOTAL_ERRORED=0
TOTAL_MERGE_FAILURES=0
TOTAL_CHUNK_FAILURES=0
for stat_file in "$TMP_DIR"/stat_*.json; do
  [ -f "$stat_file" ] || continue
  TOTAL_PARSED=$((TOTAL_PARSED + $(jq -r '.parsed // 0' "$stat_file")))
  TOTAL_SENT=$((TOTAL_SENT + $(jq -r '.sent // 0' "$stat_file")))
  TOTAL_ATTEMPTED=$((TOTAL_ATTEMPTED + $(jq -r '.attempted // 0' "$stat_file")))
  TOTAL_COMPLETED=$((TOTAL_COMPLETED + $(jq -r '.completed // 0' "$stat_file")))
  TOTAL_CONNECTED=$((TOTAL_CONNECTED + $(jq -r '.connected // 0' "$stat_file")))
  TOTAL_REFUSED=$((TOTAL_REFUSED + $(jq -r '.refused // 0' "$stat_file")))
  TOTAL_TIMEDOUT=$((TOTAL_TIMEDOUT + $(jq -r '.timedout // 0' "$stat_file")))
  TOTAL_INCONCLUSIVE=$((TOTAL_INCONCLUSIVE + $(jq -r '.inconclusive // 0' "$stat_file")))
  TOTAL_ERRORED=$((TOTAL_ERRORED + $(jq -r '.errored // 0' "$stat_file")))
  TOTAL_MERGE_FAILURES=$((TOTAL_MERGE_FAILURES + $(jq -r '.merge_failures // 0' "$stat_file")))
  TOTAL_CHUNK_FAILURES=$((TOTAL_CHUNK_FAILURES + $(jq -r '.chunk_failures // 0' "$stat_file")))
done

# Recompute per-transport counters deterministically from disk (chunk files +
# result files) — identical to the sequential per-chunk accounting.
declare -A PT_EXTRACTED
declare -A PT_PARSED
declare -A PT_SENT
declare -A PT_DROPPED
for idx in $(seq 1 "$CHUNK_IDX"); do
  chunk_file="${CHUNK_FILES[$((idx-1))]}"
  BRIDGES_IN_FILE=$(grep -c . "$chunk_file" 2>/dev/null || echo 0)
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE//[$'\t\r\n ']/}
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE:-0}
  while IFS= read -r raw_line; do
    [ -z "$raw_line" ] && continue
    t=$(echo "$raw_line" | awk '{print $1}')
    case "$t" in
      obfs4|webtunnel|vanilla|snowflake|meek_lite|meek-azure|conjure|meek) ;;
      *) t="other" ;;
    esac
    PT_EXTRACTED[$t]=$((${PT_EXTRACTED[$t]:-0} + 1))
  done < "$chunk_file"
  chunk_file="${CHUNK_FILES[$((idx-1))]}"
  CHUNK_JSON=$(jq -R -s "$PARSE_BRIDGE_JQ" "$chunk_file" 2>/dev/null || echo '[]')
  BRIDGES_PARSED=$(echo "$CHUNK_JSON" | jq 'length' 2>/dev/null || echo 0)
  BRIDGES_PARSED=${BRIDGES_PARSED//[$'\t\r\n ']/}
  BRIDGES_PARSED=${BRIDGES_PARSED:-0}
  if [ "$BRIDGES_PARSED" -gt 0 ]; then
    while IFS= read -r pt; do
      [ -z "$pt" ] && continue
      PT_PARSED[$pt]=$((${PT_PARSED[$pt]:-0} + 1))
    done < <(echo "$CHUNK_JSON" | jq -r '.[].transport // "unknown"' 2>/dev/null || true)
  fi
  CURL_SUCCESS=$(jq -r '.curl_success // 0' "$TMP_DIR/stat_${idx}.json" 2>/dev/null || echo 0)
  if [ "${CURL_SUCCESS//[$'\t\r\n ']/}" = "1" ] && [ "$BRIDGES_PARSED" -gt 0 ]; then
    while IFS= read -r pt; do
      [ -z "$pt" ] && continue
      PT_SENT[$pt]=$((${PT_SENT[$pt]:-0} + 1))
    done < <(echo "$CHUNK_JSON" | jq -r '.[].transport // "unknown"' 2>/dev/null || true)
  fi
  # Dropped approximation (raw per-transport minus parsed) -- same as original.
  if [ "$BRIDGES_PARSED" -lt "$BRIDGES_IN_FILE" ]; then
    while IFS= read -r raw_line; do
      [ -z "$raw_line" ] && continue
      t=$(echo "$raw_line" | awk '{print $1}')
      case "$t" in
        obfs4|webtunnel|vanilla|snowflake|meek_lite|meek-azure|conjure|meek) ;;
        *) t="other" ;;
      esac
      PT_DROPPED[$t]=$((${PT_DROPPED[$t]:-0} + 1))
    done < "$chunk_file"
  fi
done

# Merge per-chunk results IN CHUNK ORDER (deterministic).
: > "$TMP_DIR/merge_input.jsonl"
for idx in $(seq 1 "$CHUNK_IDX"); do
  if [ -f "$TMP_DIR/res_${idx}.json" ]; then
    cat "$TMP_DIR/res_${idx}.json" >> "$TMP_DIR/merge_input.jsonl"
    printf '\n' >> "$TMP_DIR/merge_input.jsonl"
  fi
done
jq -s 'add // []' "$TMP_DIR/merge_input.jsonl" > "$TMP_DIR/all_results_tmp.json"
mv "$TMP_DIR/all_results_tmp.json" "$ALL_RESULTS"


# ── Per-descriptor typed outcomes for fronted/rendezvous probe classes ───────
# Diagnostics only. Emit typed status/stage/vantage and bounded error class;
# never print raw response text, paths, or peer-provided error messages.
echo ""
echo "[stage=results] Fronted/rendezvous probe outcomes (probe classes other than tcp), per descriptor:"
NON_TCP_ROWS=$(jq -r '[.[] | select((.probe_type // "tcp") != "tcp")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
NON_TCP_ROWS=${NON_TCP_ROWS//[$'\t\r\n ']/}
if [ "${NON_TCP_ROWS:-0}" != "0" ]; then
  jq -r '.[] | select((.probe_type // "tcp") != "tcp") |
    "\(.transport) probe=\(.probe_type // "?") status=\(.status // "unknown") stage=\(.stage // "S0")"
    + " vantage=\(.vantage.type // "none") rtt_ms=\(.rtt_ms // "null")"
    + (if .http_status then " http_status=\(.http_status|tostring)" else "" end)
    + " error_class=" + (.error_class // "none")' "$ALL_RESULTS" 2>/dev/null | sed 's/^/[stage=results] /' || true
else
  echo "[stage=results] none (every relay probe used the tcp class)"
fi

# ── Per-transport typed outcome counts ───────────────────────────────────────
declare -A PT_RESULT_CONNECTED
declare -A PT_RESULT_S2PLUS
if [ -s "$ALL_RESULTS" ]; then
  while IFS= read -r pt; do
    [ -z "$pt" ] && continue
    PT_RESULT_CONNECTED[$pt]=$((${PT_RESULT_CONNECTED[$pt]:-0} + 1))
  done < <(jq -r '.[] | select(.status == "connected") | .transport // "unknown"' "$ALL_RESULTS" 2>/dev/null || true)
  while IFS= read -r pt; do
    [ -z "$pt" ] && continue
    PT_RESULT_S2PLUS[$pt]=$((${PT_RESULT_S2PLUS[$pt]:-0} + 1))
  done < <(jq -r '.[] | select(.status == "connected" and (.stage == "S2" or .stage == "S3" or .stage == "S4")) | .transport // "unknown"' "$ALL_RESULTS" 2>/dev/null || true)
fi

# ── Final write + structured summary ─────────────────────────────────────────
RESULT_COUNT=$(jq 'length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_CONNECTED=$(jq '[.[] | select(.status == "connected")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_REFUSED=$(jq '[.[] | select(.status == "refused")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_TIMEDOUT=$(jq '[.[] | select(.status == "timeout")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_INCONCLUSIVE=$(jq '[.[] | select(.status == "inconclusive")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_ERRORED=$(jq '[.[] | select(.status == "error")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_S0=$(jq '[.[] | select(.stage == "S0")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_S1=$(jq '[.[] | select(.stage == "S1")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_S2=$(jq '[.[] | select(.stage == "S2")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_S3=$(jq '[.[] | select(.stage == "S3")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
RESULT_S4=$(jq '[.[] | select(.stage == "S4")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
cp "$ALL_RESULTS" "$OUTPUT"

echo ""
echo "═══ PROBE RELAY SUMMARY ═══"
echo "[stage=summary] chunks_processed=${CHUNK_IDX}"
echo "[stage=summary] bridge_lines_extracted=${LINE_COUNT}"
echo "[stage=summary] bridges_parsed_total=${TOTAL_PARSED}"
echo "[stage=summary] bridges_sent_to_worker=${TOTAL_SENT}"
echo "[stage=summary] worker_attempted=${TOTAL_ATTEMPTED}"
echo "[stage=summary] worker_completed=${TOTAL_COMPLETED}"
echo "[stage=summary] worker_connected=${TOTAL_CONNECTED}"
echo "[stage=summary] worker_refused=${TOTAL_REFUSED}"
echo "[stage=summary] worker_timed_out=${TOTAL_TIMEDOUT}"
echo "[stage=summary] worker_inconclusive=${TOTAL_INCONCLUSIVE}"
echo "[stage=summary] worker_errored=${TOTAL_ERRORED}"
echo "[stage=summary] result_status_connected=${RESULT_CONNECTED}"
echo "[stage=summary] result_status_refused=${RESULT_REFUSED}"
echo "[stage=summary] result_status_timeout=${RESULT_TIMEDOUT}"
echo "[stage=summary] result_status_inconclusive=${RESULT_INCONCLUSIVE}"
echo "[stage=summary] result_status_error=${RESULT_ERRORED}"
echo "[stage=summary] result_stage_S0=${RESULT_S0}"
echo "[stage=summary] result_stage_S1=${RESULT_S1}"
echo "[stage=summary] result_stage_S2=${RESULT_S2}"
echo "[stage=summary] result_stage_S3=${RESULT_S3}"
echo "[stage=summary] result_stage_S4=${RESULT_S4}"
echo "[stage=summary] chunk_failures=${TOTAL_CHUNK_FAILURES}"
echo "[stage=summary] merge_failures=${TOTAL_MERGE_FAILURES}"
echo "[stage=summary] results_written=${RESULT_COUNT}"
echo "[stage=summary] output_written=true (path redacted)"
echo ""
echo "═══ PER-TRANSPORT BREAKDOWN ═══"
for pt in obfs4 webtunnel vanilla snowflake meek_lite meek-azure conjure meek other; do
  extracted=${PT_EXTRACTED[$pt]:-0}
  parsed=${PT_PARSED[$pt]:-0}
  sent=${PT_SENT[$pt]:-0}
  connected=${PT_RESULT_CONNECTED[$pt]:-0}
  s2plus=${PT_RESULT_S2PLUS[$pt]:-0}
  if [ "$extracted" -gt 0 ] || [ "$parsed" -gt 0 ] || [ "$sent" -gt 0 ]; then
    printf "  %-12s  extracted=%-5s  parsed=%-5s  sent=%-5s  connected=%-5s  S2+=%-5s\n" \
      "$pt" "$extracted" "$parsed" "$sent" "$connected" "$s2plus"
  fi
done
# ── Bucket reconciliation (ADDITIVE v5.1) ─────────────────────────────────────
# The fixed display list above covers only the named transport buckets.
# Parsed lines whose first token is NOT a known transport (IP:PORT-only
# lines, Formats 2/3) are counted under their parsed `.transport` value
# ("unknown"), so the fixed "other" row can read parsed=0 even though those
# lines WERE parsed and sent — which makes the summary's two consecutive
# sections appear inconsistent. This additive block prints every counter
# bucket outside the fixed list, making the parsed/sent accounting complete
# and auditable.
for pt in $(printf '%s\n' "${!PT_EXTRACTED[@]}" "${!PT_PARSED[@]}" "${!PT_SENT[@]}" "${!PT_RESULT_CONNECTED[@]}" "${!PT_RESULT_S2PLUS[@]}" | sort -u); do
  case "$pt" in
    obfs4|webtunnel|vanilla|snowflake|meek_lite|meek-azure|conjure|meek|other) continue ;;
  esac
  extracted=${PT_EXTRACTED[$pt]:-0}
  parsed=${PT_PARSED[$pt]:-0}
  sent=${PT_SENT[$pt]:-0}
  connected=${PT_RESULT_CONNECTED[$pt]:-0}
  s2plus=${PT_RESULT_S2PLUS[$pt]:-0}
  if [ "$extracted" -gt 0 ] || [ "$parsed" -gt 0 ] || [ "$sent" -gt 0 ]; then
    printf '  %-12s  extracted=%-5s  parsed=%-5s  sent=%-5s  connected=%-5s  S2+=%-5s  [bucket "%s" is outside the fixed display list]\n' \
      "$pt" "$extracted" "$parsed" "$sent" "$connected" "$s2plus" "$pt"
  fi
done
echo "═══════════════════════════════"
echo "[stage=summary] reconciliation: named buckets + \"unknown\" above sum to parsed_total=${TOTAL_PARSED}; relay observations written=${RESULT_COUNT}"

# ── Structured diagnostics for zero results ──────────────────────────────────
if [ "$RESULT_COUNT" -eq 0 ]; then
  echo ""
  echo "═══ ZERO-RESULTS DIAGNOSTIC ═══"
  echo "Reason analysis:"
  if [ "$TOTAL_CHUNK_FAILURES" -eq "$CHUNK_IDX" ]; then
    echo "  ❌ ALL ${CHUNK_IDX} chunks failed — Worker is unreachable or auth is wrong"
  elif [ "$TOTAL_MERGE_FAILURES" -gt 0 ]; then
    echo "  ❌ ${TOTAL_MERGE_FAILURES} merge failures — Worker response format may have changed"
  elif [ "$TOTAL_PARSED" -eq 0 ]; then
    echo "  ❌ 0 bridges parsed from ${LINE_COUNT} lines — all lines in non-parseable format"
  elif [ "$TOTAL_CONNECTED" -eq 0 ] && [ "$TOTAL_SENT" -gt 0 ]; then
    echo "  ⚠️  Worker recorded 0 connected outcomes across ${TOTAL_SENT} descriptors; inspect typed status counts, egress policy, and targets."
  else
    echo "  ⚠️  PARSED=${TOTAL_PARSED} SENT=${TOTAL_SENT} CONNECTED=${TOTAL_CONNECTED} but RESULT_COUNT=0"
    echo "  This is a BUG — successful probes were dropped between Worker response and final merge"
  fi
  echo "═══════════════════════════════"
fi

# ── Successful completion ────────────────────────────────────────────────────
exit 0
