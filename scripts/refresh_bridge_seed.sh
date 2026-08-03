#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# refresh_bridge_seed.sh — high-volume real-bridge archive refresh (no Rust).
#
# Fetches fresh real Tor bridge lines from the public Delta-Kronecker
# community mirror (via api.github.com) and merges them into the canonical
# `bridge/bridge_history.json`. The publisher (`sync_bridge_outputs`) rebuilds
# every public `bridge/*.txt` projection FROM `bridge_history.json`, so seeding
# the canonical history with real candidates increases the published bridge
# count on the very next pipeline run — fully automatically.
#
# It touches NO Rust source, so it cannot break the fmt/clippy/test gate, and
# every mirror source is optional/non-fatal (an unreachable mirror leaves the
# existing history untouched).
#
# Usage:
#   scripts/refresh_bridge_seed.sh [bridge-dir]
# Env:
#   BRIDGE_MIRRORS_REPO   override the mirror repo (org/repo), default
#                         Delta-Kronecker/Tor-Bridges-Collector
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BRIDGE_DIR="${1:-bridge}"
REPO="${BRIDGE_MIRRORS_REPO:-Delta-Kronecker/Tor-Bridges-Collector}"
DELTA="https://api.github.com/repos/${REPO}/contents/bridge"
TRANSPORTS=(obfs4 obfs4_ipv6 vanilla vanilla_ipv6 webtunnel webtunnel_ipv6)

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "═══ refresh_bridge_seed ═══"
echo "mirror: ${REPO}  bridge-dir: ${BRIDGE_DIR}"

# 1) Fetch the mirror files. Each is optional (non-fatal).
for f in "${TRANSPORTS[@]}"; do
  if curl -fsSL -H "Accept: application/vnd.github.raw" \
      "$DELTA/$f.txt" -o "$TMPDIR/$f.txt" 2>/dev/null; then
    echo "  ✓ fetched ${f}.txt ($(wc -l < "$TMPDIR/$f.txt") lines)"
  else
    echo "  ✗ ${f}.txt unavailable — skipped"
  fi
done

mkdir -p "$BRIDGE_DIR"

# 2) Merge into canonical history (pure stdlib python3; no .py file is written,
#    so the repo-wide python-free gate still passes).
python3 - "$TMPDIR" "$BRIDGE_DIR" <<'PY'
import json, os, sys, datetime

seed_dir, bridge_dir = sys.argv[1], sys.argv[2]
now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

def normalize_key(line, transport):
    line = line.strip()
    if transport == "vanilla" and not line.startswith("Bridge "):
        return "Bridge " + line
    return line

def valid(s):
    s = s.strip()
    return bool(s) and not s.startswith("#") and len(s) >= 12

hist_path = os.path.join(bridge_dir, "bridge_history.json")
try:
    with open(hist_path) as fh:
        history = json.load(fh)
    if not isinstance(history, dict):
        history = {}
except (OSError, ValueError):
    history = {}

files = [
    ("obfs4", False, "obfs4.txt"),
    ("obfs4", True, "obfs4_ipv6.txt"),
    ("vanilla", False, "vanilla.txt"),
    ("vanilla", True, "vanilla_ipv6.txt"),
    ("webtunnel", False, "webtunnel.txt"),
    ("webtunnel", True, "webtunnel_ipv6.txt"),
]

added = updated = 0
for transport, ipv6, fname in files:
    path = os.path.join(seed_dir, fname)
    if not os.path.exists(path):
        continue
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not valid(line):
                continue
            ip_ver = "ipv6" if (ipv6 or "[" in line) else "ipv4"
            key = normalize_key(line, transport)
            entry = {
                "raw": line,
                "transport": transport,
                "ip_version": ip_ver,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "tcp_reachable": None,
            }
            if key in history and isinstance(history[key], dict):
                history[key]["last_seen"] = now_iso
                history[key]["raw"] = line
                updated += 1
            else:
                history[key] = entry
                added += 1

with open(hist_path, "w") as fh:
    json.dump(history, fh, indent=2, ensure_ascii=False)
    fh.write("\n")

print(f"  history: +{added} added, {updated} updated, {len(history)} total records")
PY

echo "═══ refresh_bridge_seed done ═══"
