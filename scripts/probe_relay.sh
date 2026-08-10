#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# probe_relay.sh — External Probe Relay client (CI egress fix)
#
# Delegates TCP/TLS/WebSocket handshake verification to an external
# always-on Cloudflare Worker relay that has real outbound network access
# via the cloudflare:sockets connect() API.
#
# The bridge_list_for_testing.json file produced by the upstream scraper
# stages is an array of bridge-line STRINGS (e.g. "obfs4 1.2.3.4:9001 ...").
# Earlier versions of this script assumed every element was an OBJECT with
# a .fingerprint field, which caused a jq crash (exit 5) on every run.
#
# This version handles both:
#   1. Arrays of strings (the common case) — passes the string directly.
#   2. Arrays of objects with .fingerprint / .bridge_line — extracts the
#      needed field.
#
# Non-object / non-string elements are skipped with a logged warning.
#
# Usage:
#   bash scripts/probe_relay.sh <input_json> <output_json>
#
# Environment (required when PROBE_RELAY_URL is not empty):
#   PROBE_RELAY_URL   — Cloudflare Worker endpoint
#   PROBE_RELAY_TOKEN — Bearer token (optional; the Worker checks it if set)
#
# When PROBE_RELAY_URL is unset or empty the script skips gracefully and
# writes an empty-but-valid pt_results.json array; the pipeline then falls
# back to the local bridge-probe binary.
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

INPUT="${1:-bridge/bridge_list_for_testing.json}"
OUTPUT="${2:-data/pt_results.json}"
CHUNK_SIZE="${PROBE_RELAY_CHUNK_SIZE:-30}"
MAX_RETRIES="${PROBE_RELAY_MAX_RETRIES:-2}"
RELAY_URL="${PROBE_RELAY_URL:-}"
RELAY_TOKEN="${PROBE_RELAY_TOKEN:-}"

echo "——— External Probe Relay — CI Egress Fix ———"
echo "Relay URL: ${RELAY_URL:-<not configured — skipping relay, local fallback>}"
echo "Input:     $INPUT"
echo "Output:    $OUTPUT"
echo "Chunk size: $CHUNK_SIZE"
echo "Max retries: $MAX_RETRIES"

mkdir -p "$(dirname "$OUTPUT")"

# ── Guard: no relay URL → skip cleanly ───────────────────────────────────────
if [ -z "$RELAY_URL" ]; then
  echo "PROBE_RELAY_URL is not set — writing empty pt_results.json and exiting 0"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Validate input file exists ───────────────────────────────────────────────
if [ ! -f "$INPUT" ]; then
  echo "::warning::Input file $INPUT does not exist — writing empty results"
  echo '[]' > "$OUTPUT"
  exit 0
fi

# ── Extract bridge lines from the JSON array ─────────────────────────────────
# The input is an array of strings (bridge lines). We use jq to flatten it.
# select(type == "string") defensively skips any non-string entries (objects,
# numbers, etc.) so a single malformed entry never crashes the pipeline.
# Objects with a "fingerprint" or "bridge_line" key are also extracted if
# present, but the prevailing upstream format is a flat array of strings.
BRIDGE_LINES=$(jq -r '
  if type == "array" then
    .[] | select(type == "string")
  else
    empty
  end
' "$INPUT" 2>/dev/null || true)

if [ -z "$BRIDGE_LINES" ]; then
  # Try object-array fallback: { "bridges": [...] } or array of {fingerprint, ...}
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
  ' "$INPUT" 2>/dev/null || true)
fi

LINE_COUNT=$(echo "$BRIDGE_LINES" | grep -c . || echo 0)
LINE_COUNT=${LINE_COUNT//[$'\t\r\n ']/}
LINE_COUNT=${LINE_COUNT:-0}

if [ "$LINE_COUNT" -eq 0 ]; then
  echo "::warning::No bridge lines extracted from $INPUT — writing empty results"
  echo '[]' > "$OUTPUT"
  exit 0
fi

echo "Extracted $LINE_COUNT bridge lines from $INPUT"

# ── Chunked relay submission ─────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Ensure URL ends with /probe (Worker only handles POST /probe, not root).
# Normalize: strip trailing slash, strip /probe suffix if present, then append /probe.
# This makes the system format-tolerant regardless of whether the owner sets:
#   https://foo.workers.dev         → https://foo.workers.dev/probe
#   https://foo.workers.dev/        → https://foo.workers.dev/probe
#   https://foo.workers.dev/probe   → https://foo.workers.dev/probe
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

for chunk_file in "$TMP_DIR"/chunk_*; do
  CHUNK_IDX=$((CHUNK_IDX + 1))
  BRIDGES_IN_CHUNK=$(grep -c . "$chunk_file" 2>/dev/null || echo 0)
  BRIDGES_IN_CHUNK=${BRIDGES_IN_CHUNK//[$'\t\r\n ']/}
  BRIDGES_IN_CHUNK=${BRIDGES_IN_CHUNK:-0}

  # Build a JSON array of strings from this chunk's lines
  CHUNK_JSON=$(jq -R -s 'split("\n") | map(select(length > 0))' "$chunk_file")

  RETRY=0
  SUCCESS=false
  while [ "$RETRY" -le "$MAX_RETRIES" ]; do
    echo "Chunk $CHUNK_IDX (${BRIDGES_IN_CHUNK} bridges, attempt $((RETRY + 1))/${MAX_RETRIES}0)..."
    HTTP_CODE=$(curl -s -o "$TMP_DIR/resp_${CHUNK_IDX}.json" \
      -w "%{http_code}" \
      -X POST "$RELAY_URL" \
      -H "Content-Type: application/json" \
      "${AUTH_HEADER[@]}" \
      -d "$CHUNK_JSON" \
      --connect-timeout 15 --max-time 120 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
      echo "Chunk $CHUNK_IDX: 200 OK"
      SUCCESS=true
      break
    else
      echo "Chunk $CHUNK_IDX: HTTP $HTTP_CODE (retry $RETRY/$MAX_RETRIES)"
      RETRY=$((RETRY + 1))
      sleep $((RETRY * 2))
    fi
  done

  if [ "$SUCCESS" = true ] && [ -s "$TMP_DIR/resp_${CHUNK_IDX}.json" ]; then
    # Merge chunk results into the aggregate array
    jq -s '.[0] + .[1]' "$ALL_RESULTS" "$TMP_DIR/resp_${CHUNK_IDX}.json" > "$TMP_DIR/merged.json" 2>/dev/null || true
    if [ -s "$TMP_DIR/merged.json" ]; then
      mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
    fi
  else
    echo "::warning::Chunk $CHUNK_IDX failed after $((MAX_RETRIES + 1)) attempts"
    # Mark each bridge in this chunk as unreachable in the output
    while IFS= read -r bridge_line; do
      [ -z "$bridge_line" ] && continue
      jq --arg line "$bridge_line" \
        '. + [{"bridge": $line, "status": "relay_unreachable", "latency_ms": 0, "pt_type": "unknown"}]' \
        "$ALL_RESULTS" > "$TMP_DIR/merged.json" 2>/dev/null
      mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
    done < "$chunk_file"
  fi
done

# ── Write final output ───────────────────────────────────────────────────────
RESULT_COUNT=$(jq 'length' "$ALL_RESULTS" 2>/dev/null || echo 0)
cp "$ALL_RESULTS" "$OUTPUT"
echo "Probe relay complete: $RESULT_COUNT results written to $OUTPUT"

# ── Always exit 0 — the relay is supplementary; local fallback exists ────────
exit 0
