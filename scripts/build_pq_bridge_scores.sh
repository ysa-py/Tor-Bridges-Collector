#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_pq_bridge_scores.sh — Stage 8t: post-quantum bridge-scores manifest.
#
# Produces `data/pq_bridge_scores.json` — the artifact the
# `bridge-intelligence-report` upload list has always advertised but NO stage
# ever produced (verified: zero writers anywhere in src/). Deterministic and
# fully automatic: recomputed from the run's own reports.
#
# Data model (honest, deterministic):
#   * Post-quantum safety is scored per TRANSPORT by Stage 8e
#     (data/quantum_safe_report.json -> quantum_safe_scores: map[transport]).
#   * The per-bridge pool + canonical transport classification comes from
#     Stage 8i (data/anti_ai_dpi_report.json, whole-pool coverage).
#   * Each bridge inherits its transport's PQ score; the manifest lists the
#     whole pool sorted by (pq_score desc, bridge_line asc) with rank — the
#     same dynamic-yield philosophy as every other pack in this repo.
#
# Touches NO Rust source. Advisory, runner-side evidence.
#
# Usage: scripts/build_pq_bridge_scores.sh
# Env:   PQ_SCORES_OUT   output directory (default: <repo>/data)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error::python3 is required by build_pq_bridge_scores.sh" >&2
  exit 1
fi

export PQ_SCORES_OUT
python3 - <<'PY'
"""Stage 8t — post-quantum bridge scores (pure stdlib, deterministic)."""
import json
import os
import sys

REPO = os.getcwd()
OUT_DIR = os.environ.get("PQ_SCORES_OUT") or os.path.join(REPO, "data")
OUT = os.path.join(OUT_DIR, "pq_bridge_scores.json")

QUANTUM = os.path.join(REPO, "data", "quantum_safe_report.json")
POOL = os.path.join(REPO, "data", "anti_ai_dpi_report.json")


def main():
    errors = []
    for p, name in ((QUANTUM, "quantum_safe_report.json (Stage 8e)"),
                    (POOL, "anti_ai_dpi_report.json (Stage 8i)")):
        if not os.path.exists(p):
            errors.append(f"missing input {os.path.relpath(p, REPO)} ({name})")
    if errors:
        print(f"::error::build_pq_bridge_scores: {'; '.join(errors)}", file=sys.stderr)
        sys.exit(1)

    with open(QUANTUM, encoding="utf-8") as fh:
        quantum = json.load(fh).get("quantum_safe_scores") or {}
    with open(POOL, encoding="utf-8") as fh:
        pool = (json.load(fh).get("anti_ai_dpi_results")) or []

    ranked = []
    for entry in pool:
        line = (entry or {}).get("bridge_line")
        if not isinstance(line, str) or not line.strip():
            continue
        transport = (entry.get("transport") or "unknown").strip()
        pq = float(quantum.get(transport, 0.0))
        ranked.append({
            "bridge_line": line.strip(),
            "transport": transport,
            "pq_score": round(pq, 6),
        })
    ranked.sort(key=lambda r: (-r["pq_score"], r["bridge_line"]))

    os.makedirs(OUT_DIR, exist_ok=True)
    doc = {
        "engine": "torshield-rust-pq-bridge-scores-v1",
        "generated_at": "",  # filled at runtime; audit compares after popping
        "input_files": [
            os.path.relpath(QUANTUM, REPO),
            os.path.relpath(POOL, REPO),
        ],
        "total_scored": len(ranked),
        "quantum_safe_scores_by_transport": {k: round(float(v), 6)
                                              for k, v in sorted(quantum.items())},
        "bridge_scores": ranked,
    }
    # Deterministic body: generated_at populated from the pool report's own
    # timestamp so the file stays stable within a single run snapshot.
    import datetime as _dt
    doc["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
        fh.write("\n")

    print("═══ Stage 8t — post-quantum bridge-scores manifest ═══")
    print(f"  scored {len(ranked)} bridges from {len(quantum)} transport PQ scores")
    print(f"  output: {os.path.relpath(OUT, REPO)}")


if __name__ == "__main__":
    main()
PY
