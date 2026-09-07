#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# probe_relay.sh — External Probe Relay client (CI egress fix) — v5.3
#
# Delegates TCP/TLS/WebSocket handshake verification to an external
# always-on Cloudflare Worker relay that has real outbound network access
# via the cloudflare:sockets connect() API (TCP class) and fetch()-based
# HTTPS/WebSocket probes (fronted-transport classes).
#
# v5.3 CHANGES (2026-09-07) — strictly additive:
#   - New per-descriptor "[stage=results]" block prints every relay result
#     whose probe class is NOT tcp (snowflake/meek_lite/meek-azure/conjure/
#     webtunnel descriptors) with its dial target (sni when a front was
#     advertised), probe class, success flag, http_status when the front
#     answered, and the exact error otherwise — so a transport-wide 0-success
#     row is auditable per descriptor in the job log. Diagnostics only: adds
#     no counters and changes no existing log line.
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
#   - Every error suppression (2>/dev/null, || true) replaced with
#     captured-stderr diagnostic logging.
#   - Final structured summary: attempted/completed/timedOut/errored/success
#     across ALL chunks, with per-stage breakdown.
#
# Usage:
#   bash scripts/probe_relay.sh <input_json> <output_json>
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

INPUT="${1:-bridge/bridge_list_for_testing.json}"
OUTPUT="${2:-data/pt_results.json}"
CHUNK_SIZE="${PROBE_RELAY_CHUNK_SIZE:-30}"
MAX_RETRIES="${PROBE_RELAY_MAX_RETRIES:-2}"
RELAY_URL="${PROBE_RELAY_URL:-}"
RELAY_TOKEN="${PROBE_RELAY_TOKEN:-}"

echo "——— External Probe Relay — CI Egress Fix v5 ———"
echo "Relay URL: ${RELAY_URL:-<not configured — skipping relay, local fallback>}"
echo "Input:     $INPUT"
echo "Output:    $OUTPUT"
echo "Chunk size: $CHUNK_SIZE"
echo "Max retries: $MAX_RETRIES"

mkdir -p "$(dirname "$OUTPUT")"

# ── Guard: no relay URL → skip cleanly ───────────────────────────────────────
if [ -z "$RELAY_URL" ]; then
  echo "[stage=guard] PROBE_RELAY_URL is not set — writing empty pt_results.json and exiting 0"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Validate input file exists ───────────────────────────────────────────────
if [ ! -f "$INPUT" ]; then
  echo "[stage=guard] WARNING: Input file $INPUT does not exist — writing empty results"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Extract bridge lines from the JSON array ─────────────────────────────────
EXTRACT_ERR=$(mktemp)
BRIDGE_LINES=$(jq -r '
  if type == "array" then
    .[] | select(type == "string")
  else
    empty
  end
' "$INPUT" 2>"$EXTRACT_ERR" || true)
EXTRACT_EC=$?

if [ "$EXTRACT_EC" -ne 0 ] && [ -s "$EXTRACT_ERR" ]; then
  echo "[stage=extract] jq stderr: $(tr '\n' ' ' < "$EXTRACT_ERR")"
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
    echo "[stage=extract] fallback jq stderr: $(tr '\n' ' ' < "$FALLBACK_ERR")"
  fi
  rm -f "$FALLBACK_ERR"
fi

LINE_COUNT=$(echo "$BRIDGE_LINES" | grep -c . || echo 0)
LINE_COUNT=${LINE_COUNT//[$'\t\r\n ']/}
LINE_COUNT=${LINE_COUNT:-0}

if [ "$LINE_COUNT" -eq 0 ]; then
  echo "[stage=extract] WARNING: No bridge lines extracted from $INPUT — writing empty results"
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

echo "[stage=extract] extracted=${LINE_COUNT} file=${INPUT}"

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
    (capture("(?i)https?://(?<host>[^/:\\s]+)(?::(?<port>\\d+))?") //
     {host: "webtunnel-cdn", port: "443"}) as $raw
    | (capture("(?i)fronts?=(?<frontlist>[^ ]+)")? // {frontlist: ""}) as $fr
    | (($fr.frontlist | split(",")) | map(select(length > 0 and . != $raw.host)) | unique) as $fronts
    | ( { host: $raw.host,
          port: (($raw.port // "443") | tonumber),
          transport: $transport,
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
# Pure diagnostics. Prints the raw line and the exact parse outcome for every
# snowflake / meek_lite / meek-azure / conjure / meek candidate plus a bounded
# sample of 'other'-bucket (unrecognised first-token) lines, so a transport-
# wide 0-parsed result is auditable line-by-line in the job log. Adds no
# counters, changes no existing log line, sends no request.
echo ""
echo "[stage=audit] Per-candidate parse audit (additive diagnostics):"
AUDIT_TRACED=0
AUDIT_OTHER_SHOWN=0
AUDIT_OTHER_CAP=10
while IFS= read -r audit_raw; do
  [ -z "$audit_raw" ] && continue
  audit_first=$(printf '%s\n' "$audit_raw" | awk '{print $1}')
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
    echo "[stage=audit] jq stderr: $(tr '\n' ' ' < "$AUDIT_ERR")"
  fi
  rm -f "$AUDIT_ERR"
  audit_count=$(printf '%s\n' "$audit_json" | jq 'length' 2>/dev/null || echo 0)
  audit_count=${audit_count//[$'\t\r\n ']/}
  audit_outcome="unparsed"
  audit_detail="-"
  if [ "${audit_count:-0}" != "0" ]; then
    audit_outcome="parsed"
    audit_detail=$(printf '%s\n' "$audit_json" | jq -r '.[0] | .transport + " host=" + .host + " port=" + (.port|tostring)' 2>/dev/null || echo "-")
  fi
  echo "[stage=audit] token=${audit_first} outcome=${audit_outcome} ${audit_detail} raw=${audit_raw}"
  AUDIT_TRACED=$((AUDIT_TRACED + 1))
done <<< "$BRIDGE_LINES"
echo "[stage=audit] traced=${AUDIT_TRACED} (every snowflake/meek_lite/meek-azure/conjure/meek candidate; first ${AUDIT_OTHER_SHOWN} 'other'-bucket lines sampled)"

# ── Chunked relay submission ─────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Normalize URL
RELAY_URL="${RELAY_URL%/}"
RELAY_URL="${RELAY_URL%/probe}"
RELAY_URL="${RELAY_URL}/probe"

CHUNK_IDX=0
echo "$BRIDGE_LINES" | split -l "$CHUNK_SIZE" - "$TMP_DIR/chunk_"

AUTH_HEADER=()
if [ -n "$RELAY_TOKEN" ]; then
  AUTH_HEADER=(-H "X-Probe-Token: $RELAY_TOKEN")
fi

ALL_RESULTS="$TMP_DIR/all_results.json"
echo '[]' > "$ALL_RESULTS"

# ── Parallel, deterministic chunk submission ───────────────────────────────
# Each chunk is processed by its own worker. Every worker writes a per-chunk
# result array, a numeric per-chunk stats object, and a per-chunk log file.
# After all workers finish, the parent merges the per-chunk results IN CHUNK
# ORDER and recomputes the per-transport counters from the on-disk chunk/result
# files, so the final result array and summary are byte-identical to a
# sequential run (only wall-clock changes: chunks run concurrently).
PROBE_RELAY_PARALLELISM="${PROBE_RELAY_PARALLELISM:-8}"

process_chunk() {
  local chunk_file="$1"
  local idx="$2"
  local log="$TMP_DIR/log_${idx}.txt"
  local res="$TMP_DIR/res_${idx}.json"
  local stat="$TMP_DIR/stat_${idx}.json"

  exec >"$log" 2>&1

  local BRIDGES_IN_FILE BRIDGES_PARSED
  BRIDGES_IN_FILE=$(grep -c . "$chunk_file" 2>/dev/null || echo 0)
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE//[$'\t\r\n ']/}
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE:-0}

  PARSE_ERR=$(mktemp)
  local CHUNK_JSON
  CHUNK_JSON=$(jq -R -s "$PARSE_BRIDGE_JQ" "$chunk_file" 2>"$PARSE_ERR") || true
  if [ -s "$PARSE_ERR" ]; then
    echo "[stage=parse] Chunk $idx jq stderr: $(tr '\n' ' ' < "$PARSE_ERR")"
  fi
  rm -f "$PARSE_ERR"

  BRIDGES_PARSED=$(echo "$CHUNK_JSON" | jq 'length' 2>/dev/null || echo 0)
  BRIDGES_PARSED=${BRIDGES_PARSED//[$'\t\r\n ']/}
  BRIDGES_PARSED=${BRIDGES_PARSED:-0}

  if [ "$BRIDGES_PARSED" -lt "$BRIDGES_IN_FILE" ]; then
    DROPPED=$((BRIDGES_IN_FILE - BRIDGES_PARSED))
    echo "[stage=parse] Chunk $idx: ${BRIDGES_PARSED}/${BRIDGES_IN_FILE} bridges parsed (${DROPPED} dropped — likely URL-only or malformed lines)"
  fi

  local CHUNK_FAILURES=0 MERGE_FAILURES=0 SENT=0 ATTEMPTED=0 COMPLETED=0 SUCC=0 TIMEDOUT=0 ERRORED=0 CURL_SUCCESS=0
  local SUCCESS=false RETRY=0 HTTP_CODE

  if [ "$BRIDGES_PARSED" -eq 0 ]; then
    echo "[stage=parse] Chunk $idx: 0 bridges parsed from ${BRIDGES_IN_FILE} lines — skipping (all lines in non-parseable format)"
    echo '[]' > "$res"
    printf '{"parsed":0,"sent":0,"attempted":0,"completed":0,"success":0,"timedout":0,"errored":0,"chunk_failures":0,"merge_failures":0,"curl_success":0}\n' > "$stat"
    return
  fi

  while [ "$RETRY" -le "$MAX_RETRIES" ]; do
    echo "[stage=probe] Chunk $idx — sending ${BRIDGES_PARSED} bridges (attempt $((RETRY + 1))/$((MAX_RETRIES + 1)))..."

    CURL_ERR=$(mktemp)
    HTTP_CODE=$(curl -s -o "$TMP_DIR/resp_${idx}.json" \
      -w "%{http_code}" \
      -X POST "$RELAY_URL" \
      -H "Content-Type: application/json" \
      "${AUTH_HEADER[@]}" \
      -d "$CHUNK_JSON" \
      --connect-timeout 15 --max-time 120 2>"$CURL_ERR" || echo "000")

    if [ "$HTTP_CODE" = "000" ] && [ -s "$CURL_ERR" ]; then
      echo "[stage=probe] Chunk $idx curl error: $(tr '\n' ' ' < "$CURL_ERR")"
    fi
    rm -f "$CURL_ERR"

    if [ "$HTTP_CODE" = "200" ]; then
      echo "[stage=probe] Chunk $idx: HTTP 200 OK"
      SUCCESS=true
      CURL_SUCCESS=1
      break
    else
      echo "[stage=probe] Chunk $idx: HTTP ${HTTP_CODE} (retry $RETRY/$MAX_RETRIES)"
      RETRY=$((RETRY + 1))
      sleep $((RETRY * 2))
    fi
  done

  local CHUNK_STATS='{}'
  if [ "$SUCCESS" = true ] && [ -s "$TMP_DIR/resp_${idx}.json" ]; then
    SENT=$BRIDGES_PARSED
    CHUNK_STATS=$(jq '{attempted: .stats.attempted, completed: .stats.completed, success: .stats.success, timedOut: .stats.timedOut, errored: .stats.errored}' "$TMP_DIR/resp_${idx}.json" 2>/dev/null || echo '{}')
    if [ "$CHUNK_STATS" != "{}" ]; then
      echo "[stage=stats] Chunk $idx Worker stats: $CHUNK_STATS"
      ATTEMPTED=$(echo "$CHUNK_STATS" | jq -r '.attempted // 0' 2>/dev/null || echo 0)
      COMPLETED=$(echo "$CHUNK_STATS" | jq -r '.completed // 0' 2>/dev/null || echo 0)
      SUCC=$(echo "$CHUNK_STATS" | jq -r '.success // 0' 2>/dev/null || echo 0)
      TIMEDOUT=$(echo "$CHUNK_STATS" | jq -r '.timedOut // 0' 2>/dev/null || echo 0)
      ERRORED=$(echo "$CHUNK_STATS" | jq -r '.errored // 0' 2>/dev/null || echo 0)
    fi

    MERGE_ERR=$(mktemp)
    if jq -r 'if type == "object" and has("results") then (.results // []) elif type == "array" then . else [] end' "$TMP_DIR/resp_${idx}.json" > "$res" 2>"$MERGE_ERR"; then
      :
    else
      MERGE_FAILURES=1
      echo "[stage=merge] ERROR: Chunk $idx merge FAILED — jq: $(tr '\n' ' ' < "$MERGE_ERR")"
      echo "[stage=merge] Response body (first 300 chars): $(head -c 300 "$TMP_DIR/resp_${idx}.json")"
      echo '[]' > "$res"
    fi
    rm -f "$MERGE_ERR"
  else
    CHUNK_FAILURES=1
    echo "[stage=probe] WARNING: Chunk $idx failed after $((MAX_RETRIES + 1)) attempts"

    local ALL_RES=()
    while IFS= read -r bridge_line; do
      [ -z "$bridge_line" ] && continue
      FALLBACK_ERR=$(mktemp)
      PARSED=$(echo "$bridge_line" | jq -R "$PARSE_BRIDGE_JQ" 2>"$FALLBACK_ERR" || echo '[]')
      if [ -s "$FALLBACK_ERR" ]; then
        echo "[stage=fallback] Chunk $idx parse stderr: $(tr '\n' ' ' < "$FALLBACK_ERR")"
      fi
      rm -f "$FALLBACK_ERR"

      PARSED_COUNT=$(echo "$PARSED" | jq 'length' 2>/dev/null || echo 0)
      if [ "${PARSED_COUNT//[$'\t\r\n ']/}" != "0" ] && [ "$PARSED_COUNT" != "0" ]; then
        WITH_ERR=$(echo "$PARSED" | jq '.[0] + {success: false, latency_ms: null, error: "relay_unreachable"}' 2>/dev/null || echo '{"success":false,"error":"relay_unreachable"}')
      else
        WITH_ERR='{"success":false,"error":"relay_unreachable:unparseable","host":"unknown","port":0,"transport":"unknown"}'
      fi
      ALL_RES+=("$WITH_ERR")
    done < "$chunk_file"
    if [ "${#ALL_RES[@]}" -gt 0 ]; then
      printf '[%s]\n' "$(IFS=,; echo "${ALL_RES[*]}")" > "$res"
    else
      printf '[]\n' > "$res"
    fi
  fi

  printf '{"parsed":%s,"sent":%s,"attempted":%s,"completed":%s,"success":%s,"timedout":%s,"errored":%s,"chunk_failures":%s,"merge_failures":%s,"curl_success":%s}\n' \
    "$BRIDGES_PARSED" "$SENT" "$ATTEMPTED" "$COMPLETED" "$SUCC" "$TIMEDOUT" "$ERRORED" "$CHUNK_FAILURES" "$MERGE_FAILURES" "$CURL_SUCCESS" > "$stat"
}

# Gather chunk files (sorted for deterministic order).
mapfile -t CHUNK_FILES < <(printf '%s\n' "$TMP_DIR"/chunk_* | sort)
for chunk_file in "${CHUNK_FILES[@]}"; do
  CHUNK_IDX=$((CHUNK_IDX + 1))
  process_chunk "$chunk_file" "$CHUNK_IDX" &
  if (( CHUNK_IDX % PROBE_RELAY_PARALLELISM == 0 )); then
    wait
  fi
done
wait

# Replay per-chunk logs in order so the step log stays deterministic.
for idx in $(seq 1 "$CHUNK_IDX"); do
  [ -f "$TMP_DIR/log_${idx}.txt" ] && cat "$TMP_DIR/log_${idx}.txt"
done

# Aggregate numeric stats across chunks.
TOTAL_PARSED=0
TOTAL_SENT=0
TOTAL_ATTEMPTED=0
TOTAL_COMPLETED=0
TOTAL_SUCCESS=0
TOTAL_TIMEDOUT=0
TOTAL_ERRORED=0
TOTAL_MERGE_FAILURES=0
TOTAL_CHUNK_FAILURES=0
for stat_file in "$TMP_DIR"/stat_*.json; do
  [ -f "$stat_file" ] || continue
  TOTAL_PARSED=$((TOTAL_PARSED + $(jq -r '.parsed // 0' "$stat_file")))
  TOTAL_SENT=$((TOTAL_SENT + $(jq -r '.sent // 0' "$stat_file")))
  TOTAL_ATTEMPTED=$((TOTAL_ATTEMPTED + $(jq -r '.attempted // 0' "$stat_file")))
  TOTAL_COMPLETED=$((TOTAL_COMPLETED + $(jq -r '.completed // 0' "$stat_file")))
  TOTAL_SUCCESS=$((TOTAL_SUCCESS + $(jq -r '.success // 0' "$stat_file")))
  TOTAL_TIMEDOUT=$((TOTAL_TIMEDOUT + $(jq -r '.timedout // 0' "$stat_file")))
  TOTAL_ERRORED=$((TOTAL_ERRORED + $(jq -r '.errored // 0' "$stat_file")))
  TOTAL_MERGE_FAILURES=$((TOTAL_MERGE_FAILURES + $(jq -r '.merge_failures // 0' "$stat_file")))
  TOTAL_CHUNK_FAILURES=$((TOTAL_CHUNK_FAILURES + $(jq -r '.chunk_failures // 0' "$stat_file")))
done

# Recompute per-transport counters deterministically from disk (chunk files +
# result files) — identical to the sequential per-chunk accounting.
declare -A PT_EXTRACTED
declare -A PT_PARSED
declare -A PT_SENT
declare -A PT_SUCCESS
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

# Per-transport successes from final merged results.
declare -A PT_RESULT_SUCCESS
if [ -s "$ALL_RESULTS" ]; then
  while IFS= read -r pt; do
    [ -z "$pt" ] && continue
    PT_SUCCESS[$pt]=$((${PT_SUCCESS[$pt]:-0} + 1))
  done < <(jq -r '.[] | select(.success == true) | .transport // "unknown"' "$ALL_RESULTS" 2>/dev/null || true)
fi

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
cp "$ALL_RESULTS" "$OUTPUT"


# ── Per-descriptor outcomes for fronted/rendezvous probe classes ─────────────
# (ADDITIVE v5.3, diagnostics only) Relay probes in the tls / websocket-101
# classes (snowflake / meek_lite / meek-azure / conjure / webtunnel) run the
# Worker's fetch()-based HTTPS / WebSocket probes. Print every such result
# verbatim — dial target, probe class, success flag, http_status when the
# front answered, and the exact error otherwise — so a 0-success transport
# row is auditable per descriptor in the job log.
echo ""
echo "[stage=results] Fronted/rendezvous probe outcomes (probe classes other than tcp), per descriptor:"
NON_TCP_ROWS=$(jq -r '[.[] | select((.probe_type // "tcp") != "tcp")] | length' "$ALL_RESULTS" 2>/dev/null || echo 0)
NON_TCP_ROWS=${NON_TCP_ROWS//[$'\t\r\n ']/}
if [ "${NON_TCP_ROWS:-0}" != "0" ]; then
  jq -r '.[] | select((.probe_type // "tcp") != "tcp") |
    "\(.transport) host=\(.host) port=\(.port)"
    + (if .sni and (.sni != .host) then " dial_target=\(.sni)" else "" end)
    + " probe=\(.probe_type // "?") success=\(.success)"
    + (if .http_status then " http_status=\(.http_status|tostring)" else "" end)
    + " error=" + (.error // "none")' "$ALL_RESULTS" 2>/dev/null | sed 's/^/[stage=results] /' || true
else
  echo "[stage=results] none (every relay probe used the tcp class)"
fi

# ── Per-transport summary ────────────────────────────────────────────────────
# Count per-transport successes from final results
declare -A PT_RESULT_SUCCESS
if [ -s "$ALL_RESULTS" ]; then
  while IFS= read -r pt; do
    [ -z "$pt" ] && continue
    PT_RESULT_SUCCESS[$pt]=$((${PT_RESULT_SUCCESS[$pt]:-0} + 1))
  done < <(jq -r '.[] | select(.success == true) | .transport // "unknown"' "$ALL_RESULTS" 2>/dev/null || true)
fi

# ── Final write + structured summary ─────────────────────────────────────────
RESULT_COUNT=$(jq 'length' "$ALL_RESULTS" 2>/dev/null || echo 0)
cp "$ALL_RESULTS" "$OUTPUT"

echo ""
echo "═══ PROBE RELAY SUMMARY ═══"
echo "[stage=summary] chunks_processed=${CHUNK_IDX}"
echo "[stage=summary] bridge_lines_extracted=${LINE_COUNT}"
echo "[stage=summary] bridges_parsed_total=${TOTAL_PARSED}"
echo "[stage=summary] bridges_sent_to_worker=${TOTAL_SENT}"
echo "[stage=summary] worker_attempted=${TOTAL_ATTEMPTED}"
echo "[stage=summary] worker_completed=${TOTAL_COMPLETED}"
echo "[stage=summary] worker_success=${TOTAL_SUCCESS}"
echo "[stage=summary] worker_timed_out=${TOTAL_TIMEDOUT}"
echo "[stage=summary] worker_errored=${TOTAL_ERRORED}"
echo "[stage=summary] chunk_failures=${TOTAL_CHUNK_FAILURES}"
echo "[stage=summary] merge_failures=${TOTAL_MERGE_FAILURES}"
echo "[stage=summary] results_written=${RESULT_COUNT}"
echo "[stage=summary] output_file=${OUTPUT}"
echo ""
echo "═══ PER-TRANSPORT BREAKDOWN ═══"
for pt in obfs4 webtunnel vanilla snowflake meek_lite meek-azure conjure meek other; do
  extracted=${PT_EXTRACTED[$pt]:-0}
  parsed=${PT_PARSED[$pt]:-0}
  sent=${PT_SENT[$pt]:-0}
  success=${PT_RESULT_SUCCESS[$pt]:-0}
  if [ "$extracted" -gt 0 ] || [ "$parsed" -gt 0 ] || [ "$sent" -gt 0 ]; then
    printf "  %-12s  extracted=%-5s  parsed=%-5s  sent=%-5s  success=%-5s\n" \
      "$pt" "$extracted" "$parsed" "$sent" "$success"
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
for pt in $(printf '%s\n' "${!PT_EXTRACTED[@]}" "${!PT_PARSED[@]}" "${!PT_SENT[@]}" "${!PT_RESULT_SUCCESS[@]}" | sort -u); do
  case "$pt" in
    obfs4|webtunnel|vanilla|snowflake|meek_lite|meek-azure|conjure|meek|other) continue ;;
  esac
  extracted=${PT_EXTRACTED[$pt]:-0}
  parsed=${PT_PARSED[$pt]:-0}
  sent=${PT_SENT[$pt]:-0}
  success=${PT_RESULT_SUCCESS[$pt]:-0}
  if [ "$extracted" -gt 0 ] || [ "$parsed" -gt 0 ] || [ "$sent" -gt 0 ]; then
    printf '  %-12s  extracted=%-5s  parsed=%-5s  sent=%-5s  success=%-5s  [bucket "%s" is outside the fixed display list]\n' \
      "$pt" "$extracted" "$parsed" "$sent" "$success" "$pt"
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
  elif [ "$TOTAL_SUCCESS" -eq 0 ] && [ "$TOTAL_SENT" -gt 0 ]; then
    echo "  ⚠️  Worker probed ${TOTAL_SENT} bridges but found 0 reachable — PTs may be blocked or endpoints dead"
  else
    echo "  ⚠️  PARSED=${TOTAL_PARSED} SENT=${TOTAL_SENT} SUCCESS=${TOTAL_SUCCESS} but RESULT_COUNT=0"
    echo "  This is a BUG — successful probes were dropped between Worker response and final merge"
  fi
  echo "═══════════════════════════════"
fi

# ── Always exit 0 — the relay is supplementary; local fallback exists ────────
exit 0
