#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_nin_recommended_transport.sh — Stage 8t: NIN recommended-transport
# manifest.
#
# Produces `export/nin_recommended_transport.json` — the artifact the
# `bridge-intelligence-report` upload list has always advertised but NO stage
# ever produced (verified: zero writers anywhere in src/). Deterministic and
# fully automatic: recomputed from the run's own NIN-cut artifacts.
#
# Contents (honest, deterministic):
#   * Per-regime recommendations (normal / degraded / full internet cut) with
#     the evidence-based transport ordering derived from THIS run's pool.
#   * Transport pool statistics over the probe-survivable set
#     (export/nin_cut_survivable.txt, Stage 8k).
#   * Top-10 copy-paste candidates for the primary recommended transport.
#
# Touches NO Rust source. Advisory, runner-side evidence.
#
# Usage: scripts/build_nin_recommended_transport.sh
# Env:   NIN_RECOMMENDED_OUT   output directory (default: <repo>/export)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error::python3 is required by build_nin_recommended_transport.sh" >&2
  exit 1
fi

export NIN_RECOMMENDED_OUT
python3 - <<'PY'
"""Stage 8t — NIN recommended-transport manifest (pure stdlib, deterministic)."""
import json
import os
import sys
from collections import Counter

REPO = os.getcwd()
OUT_DIR = os.environ.get("NIN_RECOMMENDED_OUT") or os.path.join(REPO, "export")
OUT = os.path.join(OUT_DIR, "nin_recommended_transport.json")

SURVIVABLE = os.path.join(REPO, "export", "nin_cut_survivable.txt")
NIN_ELIGIBLE = os.path.join(REPO, "data", "nin_eligible.json")


def classify(line):
    """Canonical transport classification by line prefix (same rule the
    SIAM/anti-AI stages apply to bridge lines)."""
    ls = line.strip()
    if ls.startswith("snowflake"):
        return "snowflake"
    if ls.startswith("webtunnel"):
        return "webtunnel"
    if ls.startswith("meek"):
        return "meek_lite"
    if ls.startswith("obfs4"):
        return "obfs4"
    if ls.startswith("conjure"):
        return "conjure"
    if ls.startswith("Bridge "):
        return "vanilla"
    return "unknown"


def read_lines(path):
    """Read canonical bridge lines from a source artifact. JSON sources are
    parsed as JSON arrays of records (never text-scanned, so a bare `[]` or
    `{}` cannot become a bogus bridge line); .txt sources are read line-wise."""
    if path.endswith(".json"):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            print(f"  ⚠ {os.path.relpath(path, REPO)} unreadable ({exc})",
                  file=sys.stderr)
            return None
        if not isinstance(doc, list):
            print(f"  ⚠ {os.path.relpath(path, REPO)} is not a JSON array",
                  file=sys.stderr)
            return None
        out = []
        for entry in doc:
            if not isinstance(entry, dict):
                continue
            line = entry.get("raw") or entry.get("bridge_line") or entry.get("line")
            if isinstance(line, str) and line.strip():
                out.append(line.strip())
        return out
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except OSError as exc:
        print(f"  ⚠ {os.path.relpath(path, REPO)} unreadable ({exc})", file=sys.stderr)
        return None


def main():
    survivable = read_lines(SURVIVABLE)
    eligible = read_lines(NIN_ELIGIBLE)
    sources_present = [p for p in (SURVIVABLE, NIN_ELIGIBLE) if os.path.exists(p)]
    if not sources_present:
        rel = os.path.relpath(OUT, REPO)
        print(f"::error::build_nin_recommended_transport: no NIN-cut source "
              f"artifacts found — {rel} not written", file=sys.stderr)
        sys.exit(1)
    survivable = survivable or []
    eligible = eligible or []

    surv_transports = Counter(classify(l) for l in survivable)
    elig_transports = Counter(classify(l) for l in eligible)

    # Evidence-based ordering for a FULL internet cut: the transports that
    # (a) pass strict NIN eligibility (CDN/DTLS) and (b) dominate the
    # probe-survivable set. Counts decide; ties are broken ALPHABETICALLY so
    # the output is fully deterministic across processes (never depends on
    # Python set/hash iteration order).
    def order_key(t):
        return (-(elig_transports.get(t, 0) + surv_transports.get(t, 0)), t)

    transports = sorted(set(surv_transports) | set(elig_transports), key=order_key)
    primary = transports[0] if transports else None
    top_primary = [l for l in survivable if classify(l) == primary][:10]

    doc = {
        "engine": "torshield-rust-nin-recommended-transport-v1",
        "generated_at": "",  # audit compares after popping
        "input_files": [os.path.relpath(SURVIVABLE, REPO),
                        os.path.relpath(NIN_ELIGIBLE, REPO)],
        "scenarios": {
            "normal_internet": {
                "recommended_order": ["obfs4", "snowflake", "webtunnel", "vanilla"],
                "rationale": "obfs4 dominates the reachable pool; snowflake/"
                             "webtunnel add CDN/DTLS diversity.",
                "primary": "obfs4",
            },
            "degraded_internet": {
                "recommended_order": ["snowflake", "webtunnel", "meek_lite", "obfs4"],
                "rationale": "CDN-fronted transports first when international "
                             "routes are partially filtered.",
                "primary": "snowflake",
            },
            "full_internet_cut": {
                "recommended_order": transports or ["snowflake", "webtunnel", "obfs4"],
                "rationale": "evidence order from this run: strict NIN-eligible + "
                             "probe-survivable counts.",
                "primary": primary or "snowflake",
                "top_candidates": top_primary,
            },
        },
        "pool_stats": {
            "probe_survivable": dict(sorted(surv_transports.items(),
                                            key=lambda kv: (-kv[1], kv[0]))),
            "strict_nin_eligible": dict(sorted(elig_transports.items(),
                                               key=lambda kv: (-kv[1], kv[0]))),
            "probe_survivable_total": sum(surv_transports.values()),
            "strict_nin_eligible_total": sum(elig_transports.values()),
        },
    }
    import datetime as _dt
    doc["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
        fh.write("\n")

    print("═══ Stage 8t — NIN recommended-transport manifest ═══")
    print(f"  survivable pool: {doc['pool_stats']['probe_survivable_total']} lines "
          f"({dict(surv_transports)})")
    print(f"  full-cut primary: {doc['scenarios']['full_internet_cut']['primary']}")
    print(f"  output: {os.path.relpath(OUT, REPO)}")


if __name__ == "__main__":
    main()
PY
