#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# probe_relay.sh — External Probe Relay client (CI egress fix) — v4
#
# Delegates TCP/TLS/WebSocket handshake verification to an external
# always-on Cloudflare Worker relay that has real outbound network access
# via the cloudflare:sockets connect() API.
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
#   - If final results are 0, the zero-results diagnostic distinguishes
#     between "Worker returned empty results" and "merge/drop bug".
#
# v3 CHANGES (2026-08-10):
#   - 30-bridge chunks, incremental writes, 25min Stage 4 limit.
#   - Worker returns {results:[],stats:{}} — jq extracts .results.
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

echo "——— External Probe Relay — CI Egress Fix v4 ———"
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
# v4: capture jq stderr instead of swallowing it with 2>/dev/null.
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
  # Try object-array fallback
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

echo "[stage=extract] extracted=${LINE_COUNT} file=${INPUT}"

# ── Shared jq expression for parsing bridge lines into BridgeDescriptor ──────
# v4: handles THREE formats:
#   1. "transport IP:PORT ..."  — standard bridge line
#   2. "IP:PORT fingerprint..." — IP:PORT-only (no transport prefix, ~28% of lines)
#   3. "[IPv6]:PORT ..."        — IPv6 IP:PORT-only (no transport prefix)
# All other formats (URL-only webtunnel, etc.) are dropped with a count.
read -r -d '' PARSE_BRIDGE_JQ <<'JQEOF' || true
def parse_bridge:
  # Format 1: "transport IP:PORT ..." or "transport [IPv6]:PORT ..."
  if test("^[a-zA-Z][a-zA-Z0-9_-]* +[0-9a-fA-F.:\\[\\]]+:[0-9]+ ") then
    split(" ") as $parts
    | ($parts[1] | split(":")) as $addr
    | { host: (if ($addr | length) > 2 then ($addr[:-1] | join(":")) else $addr[0] end),
        port: ($addr[-1] | tonumber),
        transport: $parts[0],
        id: ("line-" + ($parts[0]) + "-" + (if ($addr | length) > 2 then ($addr[:-1] | join("_")) else $addr[0] end) + "-" + ($addr[-1])) }
  # Format 2: "IPv4:PORT ..." (no transport prefix)
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

# Aggregate stats across all chunks
TOTAL_PARSED=0
TOTAL_SENT=0
TOTAL_ATTEMPTED=0
TOTAL_COMPLETED=0
TOTAL_SUCCESS=0
TOTAL_TIMEDOUT=0
TOTAL_ERRORED=0
TOTAL_MERGE_FAILURES=0
TOTAL_CHUNK_FAILURES=0

for chunk_file in "$TMP_DIR"/chunk_*; do
  CHUNK_IDX=$((CHUNK_IDX + 1))
  BRIDGES_IN_FILE=$(grep -c . "$chunk_file" 2>/dev/null || echo 0)
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE//[$'\t\r\n ']/}
  BRIDGES_IN_FILE=${BRIDGES_IN_FILE:-0}

  # Build JSON. Capture stderr for diagnostics.
  PARSE_ERR=$(mktemp)
  CHUNK_JSON=$(jq -R -s "$PARSE_BRIDGE_JQ" "$chunk_file" 2>"$PARSE_ERR") || true
  if [ -s "$PARSE_ERR" ]; then
    echo "[stage=parse] Chunk $CHUNK_IDX jq stderr: $(tr '\n' ' ' < "$PARSE_ERR")"
  fi
  rm -f "$PARSE_ERR"

  BRIDGES_PARSED=$(echo "$CHUNK_JSON" | jq 'length' 2>/dev/null || echo 0)
  BRIDGES_PARSED=${BRIDGES_PARSED//[$'\t\r\n ']/}
  BRIDGES_PARSED=${BRIDGES_PARSED:-0}
  TOTAL_PARSED=$((TOTAL_PARSED + BRIDGES_PARSED))

  # Diagnose parse gaps: if fewer bridges parsed than in file, log the delta
  if [ "$BRIDGES_PARSED" -lt "$BRIDGES_IN_FILE" ]; then
    DROPPED=$((BRIDGES_IN_FILE - BRIDGES_PARSED))
    echo "[stage=parse] Chunk $CHUNK_IDX: ${BRIDGES_PARSED}/${BRIDGES_IN_FILE} bridges parsed (${DROPPED} dropped — likely URL-only or malformed lines)"
  fi

  if [ "$BRIDGES_PARSED" -eq 0 ]; then
    echo "[stage=parse] Chunk $CHUNK_IDX: 0 bridges parsed from ${BRIDGES_IN_FILE} lines — skipping (all lines in non-parseable format)"
    continue
  fi

  RETRY=0
  SUCCESS=false
  while [ "$RETRY" -le "$MAX_RETRIES" ]; do
    echo "[stage=probe] Chunk $CHUNK_IDX — sending ${BRIDGES_PARSED} bridges (attempt $((RETRY + 1))/$((MAX_RETRIES + 1)))..."

    CURL_ERR=$(mktemp)
    HTTP_CODE=$(curl -s -o "$TMP_DIR/resp_${CHUNK_IDX}.json" \
      -w "%{http_code}" \
      -X POST "$RELAY_URL" \
      -H "Content-Type: application/json" \
      "${AUTH_HEADER[@]}" \
      -d "$CHUNK_JSON" \
      --connect-timeout 15 --max-time 120 2>"$CURL_ERR" || echo "000")

    if [ "$HTTP_CODE" = "000" ] && [ -s "$CURL_ERR" ]; then
      echo "[stage=probe] Chunk $CHUNK_IDX curl error: $(tr '\n' ' ' < "$CURL_ERR")"
    fi
    rm -f "$CURL_ERR"

    if [ "$HTTP_CODE" = "200" ]; then
      echo "[stage=probe] Chunk $CHUNK_IDX: HTTP 200 OK"
      SUCCESS=true
      break
    else
      echo "[stage=probe] Chunk $CHUNK_IDX: HTTP ${HTTP_CODE} (retry $RETRY/$MAX_RETRIES)"
      RETRY=$((RETRY + 1))
      sleep $((RETRY * 2))
    fi
  done

  if [ "$SUCCESS" = true ] && [ -s "$TMP_DIR/resp_${CHUNK_IDX}.json" ]; then
    TOTAL_SENT=$((TOTAL_SENT + BRIDGES_PARSED))

    # Extract per-chunk stats from Worker response for aggregate reporting
    CHUNK_STATS=$(jq '{attempted: .stats.attempted, completed: .stats.completed, success: .stats.success, timedOut: .stats.timedOut, errored: .stats.errored}' "$TMP_DIR/resp_${CHUNK_IDX}.json" 2>/dev/null || echo '{}')
    if [ "$CHUNK_STATS" != "{}" ]; then
      echo "[stage=stats] Chunk $CHUNK_IDX Worker stats: $CHUNK_STATS"
      c_attempted=$(echo "$CHUNK_STATS" | jq -r '.attempted // 0' 2>/dev/null || echo 0)
      c_completed=$(echo "$CHUNK_STATS" | jq -r '.completed // 0' 2>/dev/null || echo 0)
      c_success=$(echo "$CHUNK_STATS" | jq -r '.success // 0' 2>/dev/null || echo 0)
      c_timedout=$(echo "$CHUNK_STATS" | jq -r '.timedOut // 0' 2>/dev/null || echo 0)
      c_errored=$(echo "$CHUNK_STATS" | jq -r '.errored // 0' 2>/dev/null || echo 0)
      TOTAL_ATTEMPTED=$((TOTAL_ATTEMPTED + ${c_attempted//[$'\t\r\n ']/}))
      TOTAL_COMPLETED=$((TOTAL_COMPLETED + ${c_completed//[$'\t\r\n ']/}))
      TOTAL_SUCCESS=$((TOTAL_SUCCESS + ${c_success//[$'\t\r\n ']/}))
      TOTAL_TIMEDOUT=$((TOTAL_TIMEDOUT + ${c_timedout//[$'\t\r\n ']/}))
      TOTAL_ERRORED=$((TOTAL_ERRORED + ${c_errored//[$'\t\r\n ']/}))
    fi

    # Merge: extract .results from Worker response {results:[],stats:{}}
    # The // .[1] fallback handles legacy raw-array responses.
    MERGE_ERR=$(mktemp)
    if jq -s '.[0] + (.[1].results // .[1])' "$ALL_RESULTS" "$TMP_DIR/resp_${CHUNK_IDX}.json" > "$TMP_DIR/merged.json" 2>"$MERGE_ERR"; then
      if [ -s "$TMP_DIR/merged.json" ]; then
        mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
        cp "$ALL_RESULTS" "$OUTPUT"
      else
        echo "[stage=merge] WARNING: Chunk $CHUNK_IDX merge produced empty file — check Worker response format"
      fi
    else
      TOTAL_MERGE_FAILURES=$((TOTAL_MERGE_FAILURES + 1))
      echo "[stage=merge] ERROR: Chunk $CHUNK_IDX merge FAILED — jq: $(tr '\n' ' ' < "$MERGE_ERR")"
      echo "[stage=merge] Response body (first 300 chars): $(head -c 300 "$TMP_DIR/resp_${CHUNK_IDX}.json")"
    fi
    rm -f "$MERGE_ERR"
  else
    TOTAL_CHUNK_FAILURES=$((TOTAL_CHUNK_FAILURES + 1))
    echo "[stage=probe] WARNING: Chunk $CHUNK_IDX failed after $((MAX_RETRIES + 1)) attempts"

    # Mark each bridge in this chunk as unreachable
    while IFS= read -r bridge_line; do
      [ -z "$bridge_line" ] && continue
      FALLBACK_ERR=$(mktemp)
      PARSED=$(echo "$bridge_line" | jq -R "$PARSE_BRIDGE_JQ" 2>"$FALLBACK_ERR" || echo '[]')
      if [ -s "$FALLBACK_ERR" ]; then
        echo "[stage=fallback] Chunk $CHUNK_IDX parse stderr: $(tr '\n' ' ' < "$FALLBACK_ERR")"
      fi
      rm -f "$FALLBACK_ERR"

      # If jq produced results, add error field; otherwise create a minimal record
      PARSED_COUNT=$(echo "$PARSED" | jq 'length' 2>/dev/null || echo 0)
      if [ "${PARSED_COUNT//[$'\t\r\n ']/}" != "0" ] && [ "$PARSED_COUNT" != "0" ]; then
        # Add error field to each parsed result
        WITH_ERR=$(echo "$PARSED" | jq '.[0] + {success: false, latency_ms: null, error: "relay_unreachable"}' 2>/dev/null || echo '{"success":false,"error":"relay_unreachable"}')
      else
        WITH_ERR='{"success":false,"error":"relay_unreachable:unparseable","host":"unknown","port":0,"transport":"unknown"}'
      fi

      APPEND_ERR=$(mktemp)
      jq --argjson parsed "$WITH_ERR" '. + [$parsed]' "$ALL_RESULTS" > "$TMP_DIR/merged.json" 2>"$APPEND_ERR" || true
      if [ -s "$APPEND_ERR" ]; then
        echo "[stage=fallback] Chunk $CHUNK_IDX append stderr: $(tr '\n' ' ' < "$APPEND_ERR")"
      fi
      rm -f "$APPEND_ERR"

      if [ -s "$TMP_DIR/merged.json" ]; then
        mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
      fi
    done < "$chunk_file"
    cp "$ALL_RESULTS" "$OUTPUT"
  fi
done

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
echo "════════════════════════════"

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
