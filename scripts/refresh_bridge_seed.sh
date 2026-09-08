#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# refresh_bridge_seed.sh — high-volume real-bridge archive refresh (no Rust).
#
# Fetches fresh real Tor bridge lines from MULTIPLE public community mirrors
# (via api.github.com) and merges them into the canonical
# `bridge/bridge_history.json`. The publisher (`sync_bridge_outputs`) rebuilds
# every public `bridge/*.txt` projection FROM `bridge_history.json`, so seeding
# the canonical history with more real candidates increases the published
# bridge count on the very next pipeline run — fully automatically and
# dynamically (the pool grows as mirrors publish new bridges; the projection
# count is derived from the deduplicated history, never a fixed cap).
#
# Mirroring is additive and redundancy-first: every configured mirror is
# polled, all unique lines are merged (keyed by canonical transport line), and
# `last_seen` is refreshed for already-known bridges so healthy candidates stay
# hot. A single unreachable mirror is never fatal — the loop simply continues
# with the next source and leaves existing history untouched.
#
# It touches NO Rust source, so it cannot break the fmt/clippy/test gate.
#
# Usage:
#   scripts/refresh_bridge_seed.sh [bridge-dir]
# Env:
#   BRIDGE_MIRRORS_REPO     space-separated list of mirror repos (org/repo)
#                           PREPENDED to the built-in mirror list, so an
#                           operator can extend the pool at any time.
#                           Built-in default: Delta-Kronecker/Tor-Bridges-Collector
#                           (verified to serve bridge/<transport>.txt via the
#                           GitHub contents API). Any listed repo that does not
#                           serve the expected files is skipped non-fatally.
#   SEED_STRICT_IP_GUARD    OPTIONAL (default: false). When set to a truthy
#                           value (1/true/yes/on), mirror lines whose endpoint
#                           falls in a documentation/reserved range (RFC 3849
#                           2001:db8::/32, RFC 5737 TEST-NETs, loopback,
#                           RFC 1918, link-local, ... — the same table
#                           src/ip_guard.rs enforces for every scraper source)
#                           are SKIPPED instead of merged, and the skip counts
#                           are printed. This closes the gap found in the
#                           2026-09-08 funnel audit, where 252 non-routable
#                           2001:db8 webtunnel lines were re-seeded into the
#                           history every run through this script (which
#                           historically only checked length >= 12). OFF by
#                           default so merge behaviour is unchanged until the
#                           owner opts in.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BRIDGE_DIR="${1:-bridge}"

# Built-in mirror list (each org/repo must serve bridge/<transport>.txt via the
# GitHub contents API to contribute). A user-provided override is PREPENDED so
# it takes priority without disabling the redundancy pool.
FALLBACK_MIRRORS=(
  "Delta-Kronecker/Tor-Bridges-Collector"
)

MIRRORS=()
if [ -n "${BRIDGE_MIRRORS_REPO:-}" ]; then
  read -r -a _override <<<"${BRIDGE_MIRRORS_REPO}"
  MIRRORS+=("${_override[@]}")
fi
MIRRORS+=("${FALLBACK_MIRRORS[@]}")

# Every transport projection published by the pipeline. Each entry is fetched
# from each mirror when present; ipv6 projections are handled separately.
TRANSPORTS=(obfs4 obfs4_ipv6 vanilla vanilla_ipv6 webtunnel webtunnel_ipv6 \
            snowflake snowflake_ipv6 meek meek-azure conjure)

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "═══ refresh_bridge_seed ═══"
echo "bridge-dir: ${BRIDGE_DIR}"
echo "mirrors: ${MIRRORS[*]}"

mkdir -p "$BRIDGE_DIR"

FETCHED=0
# 1) Fetch transport projections from every mirror into per-mirror dirs.
#    Each mirror/file is optional (non-fatal).
for idx in "${!MIRRORS[@]}"; do
  REPO="${MIRRORS[$idx]}"
  MIRDIR="$TMPDIR/mirror_${idx}"
  mkdir -p "$MIRDIR"
  echo "── mirror ${idx}: ${REPO}"
  for f in "${TRANSPORTS[@]}"; do
    if curl -fsSL -H "Accept: application/vnd.github.raw" \
        "https://api.github.com/repos/${REPO}/contents/bridge/${f}.txt" \
        -o "$MIRDIR/$f.txt" 2>/dev/null && [ -s "$MIRDIR/$f.txt" ]; then
      echo "  ✓ ${REPO}/bridge/${f}.txt ($(wc -l < "$MIRDIR/$f.txt") lines)"
      FETCHED=$((FETCHED + 1))
    else
      rm -f "$MIRDIR/$f.txt"
    fi
  done
done

echo "═══ merge: fetched ${FETCHED} projection file(s) ═══"

# 2) Merge everything into canonical history (pure stdlib python3; no .py file
#    is written, so the repo-wide python-free gate still passes).
python3 - "$TMPDIR" "$BRIDGE_DIR" <<'PY'
import ipaddress
import json, os, sys, datetime

seed_root, bridge_dir = sys.argv[1], sys.argv[2]
now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

# SEED_STRICT_IP_GUARD (default off): when enabled, mirror lines whose
# endpoint sits in a documentation/reserved range are skipped before the
# merge, mirroring the table src/ip_guard.rs applies to every scraper
# source. OFF by default so the historical merge behaviour is unchanged.
seed_strict_ip_guard = os.environ.get("SEED_STRICT_IP_GUARD", "").strip().lower() in (
    "1", "true", "yes", "on",
)

# Reserved ranges mirrored from src/ip_guard.rs (RESERVED_CIDR_V4/_V6).
RESERVED_V4 = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32",
    )
]
RESERVED_V6 = [
    ipaddress.ip_network(n)
    for n in (
        "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
        "2001::/32", "2001:2::/48", "2001:db8::/32", "2001:10::/28",
        "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]


def endpoint_is_reserved(line):
    """Best-effort endpoint extraction + reserved-range check (std lib only)."""
    for token in line.split():
        # Bracketed IPv6 endpoint form: [2001:db8::1]:443
        if token.startswith("[") and "]" in token:
            host = token[1 : token.index("]")]
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                continue
            table = RESERVED_V4 if addr.version == 4 else RESERVED_V6
            if any(addr in net for net in table):
                return True
            continue
        candidate = token.strip("[]\"',;")
        if "=" in candidate:
            continue
        host = candidate.rsplit(":", 1)[0] if candidate.count(":") == 1 else candidate
        host = host.strip("[]")
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue
        table = RESERVED_V4 if addr.version == 4 else RESERVED_V6
        if any(addr in net for net in table):
            return True
    return False


# filename -> (transport, force_ipv6)
TRANSPORT_FILES = {
    "obfs4.txt": ("obfs4", False),
    "obfs4_ipv6.txt": ("obfs4", True),
    "vanilla.txt": ("vanilla", False),
    "vanilla_ipv6.txt": ("vanilla", True),
    "webtunnel.txt": ("webtunnel", False),
    "webtunnel_ipv6.txt": ("webtunnel", True),
    "snowflake.txt": ("snowflake", False),
    "snowflake_ipv6.txt": ("snowflake", True),
    "meek.txt": ("meek", False),
    "meek-azure.txt": ("meek-azure", False),
    "conjure.txt": ("conjure", False),
}


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

added = updated = 0
skipped_reserved = 0
total_files = 0
# Walk every per-mirror directory in seed_root.
for dirpath, _dirs, filenames in os.walk(seed_root):
    for fname in filenames:
        if fname not in TRANSPORT_FILES:
            continue
        transport, force_ipv6 = TRANSPORT_FILES[fname]
        path = os.path.join(dirpath, fname)
        total_files += 1
        with open(path) as fh:
            for raw in fh:
                line = raw.strip()
                if not valid(line):
                    continue
                if seed_strict_ip_guard and endpoint_is_reserved(line):
                    skipped_reserved += 1
                    continue
                ip_ver = "ipv6" if (force_ipv6 or "[" in line) else "ipv4"
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

by_transport = {}
for entry in history.values():
    if isinstance(entry, dict):
        by_transport[entry.get("transport", "?")] = by_transport.get(entry.get("transport", "?"), 0) + 1

print(f"  history: +{added} added, {updated} updated, {len(history)} total records")
if seed_strict_ip_guard:
    print(f"  SEED_STRICT_IP_GUARD: skipped {skipped_reserved} documentation/reserved-endpoint line(s)")
else:
    print("  SEED_STRICT_IP_GUARD: off (set SEED_STRICT_IP_GUARD=true to enable the ip_guard-equivalent filter)")
print("  per-transport:", ", ".join(f"{k}={v}" for k, v in sorted(by_transport.items())))
print(f"  merged projection files: {total_files}")
PY

echo "═══ refresh_bridge_seed done ═══"
