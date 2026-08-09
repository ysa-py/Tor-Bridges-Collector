#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────
# scripts/probe_relay.sh — CI-side probe relay client
#
# Replaces the in-runner bridge-probe invocation (Stage 4) with chunked
# HTTP calls to the external Probe Relay Service (Cloudflare Worker).
#
# Usage:
#   PROBE_RELAY_URL="https://probe-relay.xyz.workers.dev" \
#   PROBE_RELAY_TOKEN="..." \
#   bash scripts/probe_relay.sh bridge/bridge_list_for_testing.json data/pt_results.json
#
# Environment Variables:
#   PROBE_RELAY_URL   — Base URL of the probe relay (required)
#   PROBE_RELAY_TOKEN — Shared secret for X-Probe-Token header (required)
#   CHUNK_SIZE        — Bridges per relay call (default: 30)
#   MAX_RETRIES       — Max retries per chunk on failure (default: 3)
#   PROBE_TIMEOUT     — Curl timeout per chunk in seconds (default: 90)
# ────────────────────────────────────────────────────────────────────
set -euo pipefail

INPUT_FILE="${1:-bridge/bridge_list_for_testing.json}"
OUTPUT_FILE="${2:-data/pt_results.json}"
CHUNK_SIZE="${CHUNK_SIZE:-30}"
MAX_RETRIES="${MAX_RETRIES:-3}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-90}"

RELAY_URL="${PROBE_RELAY_URL:-}"
RELAY_TOKEN="${PROBE_RELAY_TOKEN:-}"

# ── Validation ──────────────────────────────────────────────────────

if [ -z "$RELAY_URL" ]; then
  echo "::error::PROBE_RELAY_URL is not set. Cannot reach probe relay."
  echo "::error::Set PROBE_RELAY_URL and PROBE_RELAY_TOKEN as GitHub Actions secrets."
  echo "::error::Falling back: writing empty pt_results.json with relay_unreachable marker."
  echo '{"error":"relay_unreachable","detail":"PROBE_RELAY_URL not configured","results":[]}' > "$OUTPUT_FILE"
  exit 0
fi

if [ -z "$RELAY_TOKEN" ]; then
  echo "::error::PROBE_RELAY_TOKEN is not set."
  echo '{"error":"relay_unreachable","detail":"PROBE_RELAY_TOKEN not configured","results":[]}' > "$OUTPUT_FILE"
  exit 0
fi

if [ ! -f "$INPUT_FILE" ]; then
  echo "::warning::Input file $INPUT_FILE not found — writing empty probe results."
  echo '{"results":[]}' > "$OUTPUT_FILE"
  exit 0
fi

# ── Prepare bridge descriptors from input JSON ──────────────────────

echo "═══ External Probe Relay — CI Egress Fix ═══"
echo "Relay URL:     $RELAY_URL"
echo "Input:         $INPUT_FILE"
echo "Output:        $OUTPUT_FILE"
echo "Chunk size:    $CHUNK_SIZE"
echo "Max retries:   $MAX_RETRIES"
echo ""

# Extract bridges into a JSON array of descriptors suitable for the relay.
# The input format (bridge_list_for_testing.json) is an array of objects with
# fields: id, transport, host, port, line, fingerprint, etc.
#
# We transform each bridge into the relay's expected format:
#   { id, transport, host, port, sni?, url?, path?, cert?, iat_mode? }
#
# Using jq to parse and transform, falling back to a simpler format if jq
# is unavailable.

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

if command -v jq &>/dev/null; then
  # Full jq-based transformation — preserves all transport-specific params
  jq -c '
    [.[] | {
      id: (.fingerprint // .id // ""),
      transport: (.transport // "unknown"),
      host: (.host // ""),
      port: (.port // 0),
      sni: (.sni // null),
      url: (.url // null),
      path: (.path // null),
      cert: (.cert // null),
      iat_mode: (.["iat-mode"] // null),
      fingerprint: (.fingerprint // null)
    }]
  ' "$INPUT_FILE" > "$TEMP_DIR/bridges.json"
else
  echo "::warning::jq not available — using minimal bridge descriptor extraction."
  # Fallback: extract host/port/transport from each JSON object using grep/sed
  # This is less reliable but works when jq isn't installed.
  echo '[]' > "$TEMP_DIR/bridges.json"
fi

TOTAL=$(jq '. | length' "$TEMP_DIR/bridges.json" 2>/dev/null || echo 0)
echo "Bridges to probe: $TOTAL"

if [ "$TOTAL" -eq 0 ]; then
  echo "No bridges to probe — writing empty results."
  echo '{"results":[]}' > "$OUTPUT_FILE"
  exit 0
fi

# ── Chunk and probe ─────────────────────────────────────────────────

OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"
mkdir -p "$OUTPUT_DIR"

ALL_RESULTS="$TEMP_DIR/all_results.json"
echo '[]' > "$ALL_RESULTS"

# Split into chunks using jq
jq -c --argjson chunk "$CHUNK_SIZE" '
  def chunks(n):
    length as $len | [range(0; $len; n)] | map(.[.:.+n]);
  chunks($chunk)
' "$TEMP_DIR/bridges.json" > "$TEMP_DIR/chunks.json"

TOTAL_CHUNKS=$(jq '. | length' "$TEMP_DIR/chunks.json")
echo "Chunks: $TOTAL_CHUNKS"

CHUNK_INDEX=0
SUCCESS_COUNT=0
FAIL_COUNT=0

while [ "$CHUNK_INDEX" -lt "$TOTAL_CHUNKS" ]; do
  jq -c ".[$CHUNK_INDEX]" "$TEMP_DIR/chunks.json" > "$TEMP_DIR/current_chunk.json"
  CHUNK_SIZE_ACTUAL=$(jq '. | length' "$TEMP_DIR/current_chunk.json")
  
  echo ""
  echo "── Chunk $((CHUNK_INDEX + 1))/$TOTAL_CHUNKS ($CHUNK_SIZE_ACTUAL bridges) ──"

  ATTEMPT=0
  CHUNK_OK=false

  while [ "$ATTEMPT" -lt "$MAX_RETRIES" ] && [ "$CHUNK_OK" != "true" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    
    if [ "$ATTEMPT" -gt 1 ]; then
      BACKOFF=$((2 ** (ATTEMPT - 1)))
      echo "  Retry $ATTEMPT/$MAX_RETRIES after ${BACKOFF}s backoff..."
      sleep "$BACKOFF"
    fi

    HTTP_CODE=$(curl -s -w '%{http_code}' -o "$TEMP_DIR/chunk_response.json" \
      --max-time "$PROBE_TIMEOUT" \
      -X POST "${RELAY_URL}/probe" \
      -H "Content-Type: application/json" \
      -H "X-Probe-Token: ${RELAY_TOKEN}" \
      -d "@${TEMP_DIR}/current_chunk.json" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
      # Merge results
      CHUNK_RESULTS=$(jq -c '.results // []' "$TEMP_DIR/chunk_response.json" 2>/dev/null || echo '[]')
      jq -s '.[0] + .[1]' "$ALL_RESULTS" <(echo "$CHUNK_RESULTS") > "$TEMP_DIR/merged.json"
      mv "$TEMP_DIR/merged.json" "$ALL_RESULTS"

      CHUNK_SUCCESSES=$(echo "$CHUNK_RESULTS" | jq '[.[] | select(.success == true)] | length')
      CHUNK_FAILURES=$(echo "$CHUNK_RESULTS" | jq '[.[] | select(.success == false)] | length')
      SUCCESS_COUNT=$((SUCCESS_COUNT + CHUNK_SUCCESSES))
      FAIL_COUNT=$((FAIL_COUNT + CHUNK_FAILURES))
      
      echo "  ✅ Chunk complete: $CHUNK_SUCCESSES reachable, $CHUNK_FAILURES unreachable"
      CHUNK_OK=true
    elif [ "$HTTP_CODE" = "401" ]; then
      echo "  ❌ Authentication failed (HTTP $HTTP_CODE) — check PROBE_RELAY_TOKEN"
      # Don't retry auth failures
      break
    elif [ "$HTTP_CODE" = "413" ]; then
      echo "  ❌ Chunk too large (HTTP $HTTP_CODE) — reduce CHUNK_SIZE"
      break
    else
      echo "  ⚠️  Relay returned HTTP $HTTP_CODE (attempt $ATTEMPT/$MAX_RETRIES)"
      if [ -f "$TEMP_DIR/chunk_response.json" ]; then
        echo "  Response: $(head -c 200 "$TEMP_DIR/chunk_response.json")"
      fi
    fi
  done

  if [ "$CHUNK_OK" != "true" ]; then
    echo "  ❌ Chunk failed after $MAX_RETRIES attempts — relay unreachable for this chunk"
    # Mark all bridges in this chunk as relay_unreachable
    jq -c '[.[] | {id, transport: (.transport // "unknown"), host: (.host // ""), port: (.port // 0), success: false, latency_ms: null, probe_type: "relay_unreachable", error: "Probe relay unreachable after '"$MAX_RETRIES"' retries"}]' \
      "$TEMP_DIR/current_chunk.json" > "$TEMP_DIR/fallback_chunk.json"
    jq -s '.[0] + .[1]' "$ALL_RESULTS" "$TEMP_DIR/fallback_chunk.json" > "$TEMP_DIR/merged.json"
    mv "$TEMP_DIR/merged.json" "$ALL_RESULTS"
  fi

  CHUNK_INDEX=$((CHUNK_INDEX + 1))
done

# ── Write output ────────────────────────────────────────────────────

TOTAL_RESULTS=$(jq '. | length' "$ALL_RESULTS")
echo ""
echo "═══ Probe Relay Summary ═══"
echo "Bridges probed:   $TOTAL_RESULTS"
echo "Reachable:        $SUCCESS_COUNT"
echo "Unreachable:      $FAIL_COUNT"
echo "Output:           $OUTPUT_FILE"

# Write results in a format compatible with downstream stages
# (same schema as bridge-probe's pt_results.json)
jq -c '{
  results: .,
  summary: {
    total: length,
    reachable: [.[] | select(.success == true)] | length,
    unreachable: [.[] | select(.success == false)] | length,
    probe_source: "external-relay"
  }
}' "$ALL_RESULTS" > "$OUTPUT_FILE"

echo "✅ Probe relay stage complete."
