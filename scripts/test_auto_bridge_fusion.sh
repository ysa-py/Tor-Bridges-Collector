#!/usr/bin/env bash
# Offline regression test for scripts/auto_bridge_fusion.sh.
#
# Runs the engine against a scratch copy of bridge/ + data/ (no network, no
# attestation) and asserts the invariants the hourly workflow relies on:
#   * history never shrinks and stays valid JSON
#   * every required bridge/*.txt that has a real data source is non-empty
#   * NO projection may stay empty — the IPv6 vanilla projections (no public source
#     publishes vanilla IPv6 bridges) are back-filled by the documented, reported
#     dual-stack fallback and superseded automatically when real IPv6 data appears
#   * the Iran hourly mix / anti-DPI profile / torrc are produced
#   * the engine is idempotent (second run changes no projection)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bridge" "$TMP/data" "$TMP/export"
cp -R "$ROOT/bridge/." "$TMP/bridge/"
cp -R "$ROOT/data/." "$TMP/data/"

before="$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$TMP/bridge/bridge_history.json")"

run() {
  FUSION_OFFLINE=1 FUSION_SKIP_ATTEST=1 BRIDGE_DIR="$TMP/bridge" DATA_DIR="$TMP/data" EXPORT_DIR="$TMP/export" \
    bash "$ROOT/scripts/auto_bridge_fusion.sh" >/dev/null
}

run
sums1="$(cd "$TMP/bridge" && find . -name '*.txt' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
run
sums2="$(cd "$TMP/bridge" && find . -name '*.txt' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
if [ "$sums1" != "$sums2" ]; then
  echo "FAIL: fusion is not idempotent" >&2
  exit 1
fi

TMP="$TMP" BEFORE="$before" python3 - <<'PY'
import json
import os
import sys

tmp = os.environ["TMP"]
bridge = os.path.join(tmp, "bridge")
history = json.load(open(os.path.join(bridge, "bridge_history.json")))
if len(history) < int(os.environ["BEFORE"]):
    sys.exit("FAIL: history shrank")

allowed_empty = set()
manifest = json.load(open(os.path.join(tmp, "data", "run_manifest.json")))["files"]
empty = [n for n in manifest
         if n.endswith(".txt") or n == "snowflake_ipv6_tested"
         if os.path.isfile(os.path.join(bridge, n)) and os.path.getsize(os.path.join(bridge, n)) == 0]
unexpected = sorted(set(empty) - allowed_empty)
if unexpected:
    sys.exit(f"FAIL: unexpected empty projections: {unexpected}")

for rel in ("data/iran_hourly_mix.json", "data/iran_anti_dpi_profile.json", "data/ai_fusion_model.json",
            "data/ai_fusion_report.json", "data/iran_anti_dpi_ultra.json", "data/bridge_freshness.json",
            "data/ai_fusion_fallbacks.json"):
    json.load(open(os.path.join(tmp, rel)))
mix = json.load(open(os.path.join(tmp, "data", "iran_hourly_mix.json")))
if mix["count"] < 1:
    sys.exit("FAIL: hourly mix is empty")
torrc = open(os.path.join(tmp, "export", "iran_hourly_mix.torrc")).read()
if "UseBridges 1" not in torrc or "\nBridge " not in torrc:
    sys.exit("FAIL: torrc export malformed")
if not os.path.isfile(os.path.join(tmp, "export", "iran_fastest.torrc")):
    sys.exit("FAIL: fastest-first torrc missing")
fresh = json.load(open(os.path.join(tmp, "data", "bridge_freshness.json")))
if fresh["empty_files"]:
    sys.exit(f"FAIL: freshness manifest reports empty files: {fresh['empty_files']}")
print(f"OK: history={len(history)} empty_allowed={sorted(set(empty))} mix={mix['count']}")
PY
echo "test_auto_bridge_fusion: PASS"
