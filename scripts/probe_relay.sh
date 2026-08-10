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
#
# This script parses every bridge line into a structured BridgeDescriptor
# object {host, port, transport, id} matching the Worker schema
# (probe-relay/src/index.ts) before POSTing to the relay endpoint.
# Raw bridge-line strings are NEVER sent directly — the Worker requires
# host/port/transport fields, not bare strings or "address"-keyed objects.
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
# v3: default 30 bridges per chunk matches the Worker's MAX_CONCURRENT_PROBES=5
# with 6× headroom for per-probe timeouts. The Worker drains all reader
# locks after each probe, so 30 bridges × 5s timeout ≈ 150s worst-case.
# With ~1450 bridges: 1450/30 ≈ 49 chunks × ~15s avg ≈ 12.5 min total.
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

  # Build a JSON array of BridgeDescriptor objects from this chunk's bridge lines.
  # The Worker expects {"host","port","transport"} — NOT raw bridge-line strings
  # and NOT {"address",...}. Schema: probe-relay/src/index.ts BridgeDescriptor.
  #
  # Bridge line formats handled:
  #   "transport IP:PORT ..."  → {"host":"IP","port":PORT,"transport":"transport"}
  #   "transport [IPv6]:PORT ..." → {"host":"[IPv6]","port":PORT,"transport":"transport"}
  CHUNK_JSON=$(jq -R -s '
    def parse_bridge:
      if test("^[a-zA-Z][a-zA-Z0-9_-]* +[0-9a-fA-F.:\\[\\]]+:[0-9]+ ") then
        split(" ") as $parts
        | ($parts[1] | split(":")) as $addr
        | { host: (if ($addr | length) > 2 then ($addr[:-1] | join(":")) else $addr[0] end),
            port: ($addr[-1] | tonumber),
            transport: $parts[0],
            id: ("line-" + ($parts[0]) + "-" + (if ($addr | length) > 2 then ($addr[:-1] | join("_")) else $addr[0] end) + "-" + ($addr[-1])) }
      else
        empty
      end;
    split("\n") | map(select(length > 0) | parse_bridge)
  ' "$chunk_file")

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
    # Merge chunk results into the aggregate array.
    # The Worker returns {"results":[...],"stats":{...}} — we extract .results.
    # The // .[1] fallback handles legacy raw-array responses gracefully.
    #
    # DIAGNOSTIC: if jq merge fails (e.g. malformed response), capture stderr
    # so the failure reason is visible in CI logs — no more silent drops.
    MERGE_ERR=$(mktemp)
    if jq -s '.[0] + (.[1].results // .[1])' "$ALL_RESULTS" "$TMP_DIR/resp_${CHUNK_IDX}.json" > "$TMP_DIR/merged.json" 2>"$MERGE_ERR"; then
      if [ -s "$TMP_DIR/merged.json" ]; then
        mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
        # Incremental write: persist after EVERY chunk so partial results
        # survive a step timeout. The previous write-at-end-only approach
        # lost ALL results when Stage 4 exceeded its 20-min timeout.
        cp "$ALL_RESULTS" "$OUTPUT"
      fi
    else
      echo "::warning::Chunk $CHUNK_IDX merge FAILED — jq error: $(tr '\n' ' ' < "$MERGE_ERR")"
      echo "::warning::Response body (first 200 chars): $(head -c 200 "$TMP_DIR/resp_${CHUNK_IDX}.json")"
    fi
    rm -f "$MERGE_ERR"
  else
    echo "::warning::Chunk $CHUNK_IDX failed after $((MAX_RETRIES + 1)) attempts"
    # Mark each bridge in this chunk as unreachable in the output.
    # Output schema matches the Worker's ProbeResult: {id,host,port,transport,success,latency_ms,error}
    while IFS= read -r bridge_line; do
      [ -z "$bridge_line" ] && continue
      PARSED=$(echo "$bridge_line" | jq -R '
        if test("^[a-zA-Z][a-zA-Z0-9_-]* +[0-9a-fA-F.:\\[\\]]+:[0-9]+ ") then
          split(" ") as $parts
          | ($parts[1] | split(":")) as $addr
          | { id: ("line-" + $parts[0] + "-" + (if ($addr | length) > 2 then ($addr[:-1] | join("_")) else $addr[0] end) + "-" + $addr[-1]),
              host: (if ($addr | length) > 2 then ($addr[:-1] | join(":")) else $addr[0] end),
              port: ($addr[-1] | tonumber),
              transport: $parts[0],
              success: false,
              latency_ms: null,
              error: "relay_unreachable" }
        else
          { id: ("unknown-" + (now | tostring)), host: "unknown", port: 0, transport: "unknown", success: false, latency_ms: null, error: "relay_unreachable:unparseable" }
        end
      ' 2>/dev/null || echo '{"success":false,"error":"relay_unreachable"}')
      jq --argjson parsed "$PARSED" '. + [$parsed]' "$ALL_RESULTS" > "$TMP_DIR/merged.json" 2>/dev/null
      mv "$TMP_DIR/merged.json" "$ALL_RESULTS"
    done < "$chunk_file"
    # Incremental write for failed chunk too — partial results survive timeout
    cp "$ALL_RESULTS" "$OUTPUT"
  fi
done

# ── Write final output ───────────────────────────────────────────────────────
RESULT_COUNT=$(jq 'length' "$ALL_RESULTS" 2>/dev/null || echo 0)
cp "$ALL_RESULTS" "$OUTPUT"
echo "Probe relay complete: $RESULT_COUNT results written to $OUTPUT"

# ── Structured diagnostics: zero results is a critical signal ────────────────
if [ "$RESULT_COUNT" -eq 0 ]; then
  echo ""
  echo "═══ ZERO-RESULTS DIAGNOSTIC ═══"
  echo "Chunks attempted:  $CHUNK_IDX"
  echo "Input bridge lines: $LINE_COUNT"
  echo ""
  echo "Possible causes (check CI logs above):"
  echo "  1. All jq merge steps failed — look for 'merge FAILED' warnings above"
  echo "  2. Worker returned empty .results arrays — check Cloudflare Observability for probe errors"
  echo "  3. Worker response format mismatch — the fix in this script extracts .results from {results,stats}"
  echo "  4. PROBE_RELAY_URL missing or misconfigured"
  echo "  5. Bridge lines could not be parsed into {host,port,transport} by jq — check chunk JSON above"
  echo ""
  echo "Next step: verify the Worker is deployed (wrangler deploy) and reachable (curl smoke test)."
  echo "If the Worker IS healthy, check Cloudflare Observability for per-probe failure reasons."
  echo "═══════════════════════════════"
fi

# ── Always exit 0 — the relay is supplementary; local fallback exists ────────
exit 0
