#!/usr/bin/env bash
# Offline regression test for scripts/auto_bridge_fusion.sh.
#
# Runs the engine against a scratch copy of bridge/ + data/ (no network, no
# attestation) and asserts the invariants the hourly workflow relies on:
#   * history never shrinks and stays valid JSON
#   * EVERY required bridge/*.txt file is non-empty (0 empty files, including IPv6 vanilla)
#   * the Iran hourly mix / anti-DPI profile / torrc are produced
#   * the engine is idempotent within the same hour seed (second run changes no projection)
#   * advancing the hour seed dynamically re-combines and rotates projections
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bridge" "$TMP/data" "$TMP/export"
cp -R "$ROOT/bridge/." "$TMP/bridge/"
cp -R "$ROOT/data/." "$TMP/data/"

before="$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$TMP/bridge/bridge_history.json")"

run_with_seed() {
  local seed="$1"
  FUSION_HOUR_SEED="$seed" FUSION_OFFLINE=1 FUSION_SKIP_ATTEST=1 \
    BRIDGE_DIR="$TMP/bridge" DATA_DIR="$TMP/data" EXPORT_DIR="$TMP/export" \
    bash "$ROOT/scripts/auto_bridge_fusion.sh" >/dev/null
}

run_with_seed 500000
sums1="$(cd "$TMP/bridge" && find . -name '*.txt' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
run_with_seed 500000
sums2="$(cd "$TMP/bridge" && find . -name '*.txt' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
if [ "$sums1" != "$sums2" ]; then
  echo "FAIL: fusion is not idempotent within the same hour seed" >&2
  exit 1
fi

run_with_seed 500001
sums3="$(cd "$TMP/bridge" && find . -name '*.txt' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
if [ "$sums1" = "$sums3" ]; then
  echo "FAIL: fusion did not dynamically rotate projections on new hour seed" >&2
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

manifest = json.load(open(os.path.join(tmp, "data", "run_manifest.json")))["files"]
empty = [n for n in manifest
         if n.endswith(".txt") or n == "snowflake_ipv6_tested"
         if os.path.isfile(os.path.join(bridge, n)) and os.path.getsize(os.path.join(bridge, n)) == 0]
if empty:
    sys.exit(f"FAIL: unexpected empty projections: {empty}")

for rel in ("data/iran_hourly_mix.json", "data/iran_anti_dpi_profile.json", "data/ai_fusion_model.json",
            "data/ai_fusion_report.json"):
    json.load(open(os.path.join(tmp, rel)))
mix = json.load(open(os.path.join(tmp, "data", "iran_hourly_mix.json")))
if mix["count"] < 1:
    sys.exit("FAIL: hourly mix is empty")
torrc = open(os.path.join(tmp, "export", "iran_hourly_mix.torrc")).read()
if "UseBridges 1" not in torrc or "\nBridge " not in torrc:
    sys.exit("FAIL: torrc export malformed")
print(f"OK: history={len(history)} empty={empty} mix={mix['count']}")
PY
echo "test_auto_bridge_fusion: PASS"
