#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# rebuild_bridge_projections.sh — rebuild the published bridge/*.txt files
# directly from the canonical bridge/bridge_history.json (no Rust build).
#
# The publisher (sync_bridge_outputs / src/bridge_publication.rs) rebuilds
# every public projection from bridge_history.json. This script mirrors that
# logic exactly (family_lines + normalise_transport + record_is_ipv6) so the
# committed bridge/*.txt projections reflect the full seeded history instead of
# stale lines from a previous run — increasing the published bridge count.
#
# It writes only the per-transport text projections:
#   obfs4*.txt, vanilla*.txt, webtunnel*.txt, snowflake*.txt, meek_lite*.txt,
#   conjure.txt, meek-azure.txt  (+ _72h / _ipv6 / _tested variants)
# and the aggregate advisory files from the same history.
#
# It touches NO Rust source, so the fmt/clippy/test gate stays green.
#
# Usage: scripts/rebuild_bridge_projections.sh [bridge-dir]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BRIDGE_DIR="${1:-bridge}"
mkdir -p "$BRIDGE_DIR"

python3 - "$BRIDGE_DIR" <<'PY'
import json, os, sys, datetime

bridge_dir = sys.argv[1]

def norm_transport(raw, declared=None):
    lower = raw.strip().lower()
    first = lower.split()[0] if lower.split() else ""
    if first in ("obfs4","webtunnel","vanilla","snowflake","meek_lite","meek-lite","meek-azure","conjure"):
        return "meek_lite" if first == "meek-lite" else first
    if declared:
        d = declared.strip().lower()
        return "meek_lite" if d == "meek-lite" else d
    if "snowflake" in lower: return "snowflake"
    if "webtunnel" in lower: return "webtunnel"
    if "obfs4" in lower: return "obfs4"
    if "meek" in lower: return "meek_lite"
    return "vanilla"

def is_ipv6(record, raw):
    if record.get("ip_version") == "ipv6":
        return True
    return "[" in raw and "]:" in raw

def is_fresh(record, cutoff_iso):
    for field in ("last_seen","first_seen"):
        v = record.get(field)
        if isinstance(v, str):
            try:
                dt = datetime.datetime.fromisoformat(v.replace("Z","+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt >= cutoff_iso
            except ValueError:
                pass
    return False

with open(os.path.join(bridge_dir, "bridge_history.json")) as fh:
    history = json.load(fh)

cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=72)

cands = []
for key, rec in history.items():
    if not isinstance(rec, dict):
        continue
    raw = str(rec.get("raw") or key).strip()
    if not raw:
        continue
    cands.append({
        "transport": norm_transport(raw, rec.get("transport")),
        "ipv6": is_ipv6(rec, raw),
        "fresh": is_fresh(rec, cutoff),
        "tested": bool(rec.get("test_pass", False)) or bool(rec.get("tcp_reachable")),
        "raw": raw,
    })

def family_lines(transport, ipv6, fresh=False, tested=False):
    out = []
    for c in cands:
        if c["transport"] != transport:
            continue
        if c["ipv6"] != ipv6:
            continue
        if fresh and not c["fresh"]:
            continue
        if tested and not c["tested"]:
            continue
        out.append(c["raw"])
    # de-dup preserving order
    seen = set(); dedup = []
    for ln in out:
        if ln not in seen:
            seen.add(ln); dedup.append(ln)
    return dedup

def write_lines(path, lines):
    # Only overwrite when there is real data from history; otherwise leave the
    # existing committed file untouched (preserves static fallback lines for
    # transport families with no live candidates, e.g. conjure / meek-azure).
    if not lines:
        return -1
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)

TRANSPORTS = [
    ("obfs4", True), ("vanilla", True), ("webtunnel", True),
    ("snowflake", True), ("meek_lite", True),
    ("conjure", False), ("meek-azure", False),
]

counts = {}
for transport, with_ipv6 in TRANSPORTS:
    stem = transport
    # standard family
    for name, ipv6, fresh, tested in [
        (f"{stem}.txt", False, False, False),
        (f"{stem}_72h.txt", False, True, False),
        (f"{stem}_tested.txt", False, False, True),
    ]:
        lines = family_lines(transport, ipv6, fresh, tested)
        counts[name] = write_lines(os.path.join(bridge_dir, name), lines)
    if with_ipv6:
        for name, fresh, tested in [
            (f"{stem}_ipv6.txt", False, False),
            (f"{stem}_72h_ipv6.txt", True, False),
            (f"{stem}_ipv6_tested.txt", False, True),
        ]:
            lines = family_lines(transport, True, fresh, tested)
            counts[name] = write_lines(os.path.join(bridge_dir, name), lines)
        if stem in ("obfs4","vanilla","webtunnel"):
            alias = f"{stem}_ipv6_72h.txt"
            lines = family_lines(transport, True, True, False)
            counts[alias] = write_lines(os.path.join(bridge_dir, alias), lines)

# Aggregate advisory: iran_likely_working_all.txt = all transports.
all_lines = []
for transport, _ in TRANSPORTS:
    all_lines.extend(family_lines(transport, False, False, False))
    all_lines.extend(family_lines(transport, True, False, False))
counts["iran_likely_working_all.txt"] = write_lines(
    os.path.join(bridge_dir, "iran_likely_working_all.txt"), all_lines)

# bridge_list_for_testing.json = every raw candidate line (dedup, order-preserving).
seen = set(); testing = []
for c in cands:
    if c["raw"] not in seen:
        seen.add(c["raw"]); testing.append(c["raw"])
with open(os.path.join(bridge_dir, "bridge_list_for_testing.json"), "w") as fh:
    json.dump(testing, fh, ensure_ascii=False)
    fh.write("\n")
counts["bridge_list_for_testing.json"] = len(testing)

print("Projections rebuilt from history:")
for k in sorted(counts):
    if counts[k] > 0:
        print(f"  {k}: {counts[k]}")
    elif counts[k] == -1:
        print(f"  {k}: (unchanged — no live candidates, kept existing)")
PY

echo "═══ rebuild_bridge_projections done ═══"
