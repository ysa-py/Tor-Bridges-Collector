#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_iran_anti_dpi_elite.sh — Stage 8s: Iran Anti-DPI Elite fusion (no Rust).
#
# Fuses the per-run Iran intelligence reports into one deduplicated,
# DPI-hardened, priority-ordered bridge list for Iranian users:
#
#   data/anti_ai_dpi_report.json   (Stage 8i  — anti-AI-DPI scoring)
#   data/iran_siam_report.json     (Stage 8r  — 8-layer SIAM/NGFW evasion tier)
#   data/smart_iran_results.json   (Stage 8i-smart — Smart-Iran AI score)
#
# Outputs:
#   export/iran_anti_dpi_elite.txt   — one canonical bridge line per entry,
#                                      PHANTOM → STEALTH → COVERT priority,
#                                      composite score descending within tier.
#   export/iran_anti_dpi_elite.json  — machine-readable summary (counts, tiers,
#                                      top-50 detail, input provenance).
#
# Semantics (deterministic, advisory, honest):
#   * A bridge flagged DETECTED by the 8-layer SIAM analysis is EXCLUDED: the
#     pack is "DPI-hardened", and SIAM's verdict is the strongest per-bridge
#     signal the pipeline has.
#   * The whole surviving, deduplicated pool is emitted (dynamic yield) unless
#     AI_ANTI_DPI_TOP_N (>0) caps the list at the top-N entries.
#   * Composite score = weighted mean of the signals present per bridge
#     (0.40 anti-AI-DPI, 0.35 SIAM evasion, 0.25 Smart-Iran; weights are
#     renormalized over whichever signals exist for a given bridge so a bridge
#     seen by only one stage is not zero-padded).
#   * Evidence remains advisory: runner-side scoring, NOT Iranian-side
#     measurement (consistent with the README's honesty contract).
#
# Touches NO Rust source, so it cannot break the fmt/clippy/test gate.
#
# Usage:   scripts/build_iran_anti_dpi_elite.sh
# Env:     AI_ANTI_DPI_TOP_N   integer cap (default 0 = whole surviving pool)
#          ELITE_OUT_DIR       output directory (default: <repo>/export)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error::python3 is required by build_iran_anti_dpi_elite.sh" >&2
  exit 1
fi

export AI_ANTI_DPI_TOP_N
export ELITE_OUT_DIR
python3 - <<'PY'
"""Stage 8s — Iran Anti-DPI Elite fusion (pure stdlib, deterministic)."""
import datetime as _dt
import json
import os
import sys
from collections import Counter, OrderedDict

REPO = os.getcwd()
OUT_DIR = os.environ.get("ELITE_OUT_DIR") or os.path.join(REPO, "export")
TOP_N = int(os.environ.get("AI_ANTI_DPI_TOP_N", "0") or "0")

INPUTS = {
    "anti_ai_dpi": os.path.join(REPO, "data", "anti_ai_dpi_report.json"),
    "iran_siam": os.path.join(REPO, "data", "iran_siam_report.json"),
    "smart_iran": os.path.join(REPO, "data", "smart_iran_results.json"),
}

TIER_PRIORITY = {"PHANTOM": 3, "STEALTH": 2, "COVERT": 1, "DETECTED": 0}
TIER_ORDER = ["PHANTOM", "STEALTH", "COVERT"]
TIER_RANK = {name: rank for rank, name in enumerate(TIER_ORDER, start=1)}

# Composite weights (renormalized per-bridge over present signals).
W_ANTI_AI, W_SIAM, W_SMART = 0.40, 0.35, 0.25


def load(path: str, required: bool = False):
    """Load one input report; missing/corrupt inputs are non-fatal except when
    every input is absent (loud failure rather than a silent empty pack)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001 - report-generator tolerance
        msg = f"  ⚠ cannot read {os.path.relpath(path, REPO)}: {exc}"
        print(msg, file=sys.stderr)
        if required:
            print("::error::all Stage 8s input reports are unreadable" + str(exc),
                  file=sys.stderr)
            raise SystemExit(1) from exc
        return None


def entries_of(doc, key):
    if not isinstance(doc, dict):
        return []
    val = doc.get(key)
    return val if isinstance(val, list) else []


def build_records():
    anti_ai = load(INPUTS["anti_ai_dpi"])
    siam = load(INPUTS["iran_siam"])
    smart = load(INPUTS["smart_iran"])

    if anti_ai is None and siam is None and smart is None:
        load(INPUTS["iran_siam"], required=True)  # loud, documented exit
        return {}

    # signal_lists: line -> {"anti_ai": [...], "siam": [...], "smart": [...]}
    signals = {}

    for entry in entries_of(anti_ai, "anti_ai_dpi_results"):
        line = (entry or {}).get("bridge_line")
        if line:
            signals.setdefault(line, {}).setdefault("anti_ai", []).append(entry)

    for entry in entries_of(siam, "results"):
        line = (entry or {}).get("bridge_line")
        if line:
            signals.setdefault(line, {}).setdefault("siam", []).append(entry)

    for entry in entries_of(smart, "bridges"):
        line = (entry or {}).get("raw") or (entry or {}).get("bridge_id")
        if line:
            signals.setdefault(line, {}).setdefault("smart", []).append(entry)

    records = {}
    for line, groups in signals.items():
        line = (line or "").strip()
        if not line:
            continue
        anti_entries = groups.get("anti_ai", [])
        siam_entries = groups.get("siam", [])
        smart_entries = groups.get("smart", [])

        tier = None
        tier_priority = -1
        for e in siam_entries:
            t = (e.get("bypass_tier") or "").upper()
            p = TIER_PRIORITY.get(t, 0)
            if p > tier_priority:
                tier, tier_priority = t, p
        if tier == "DETECTED":
            continue  # DPI-hardened pack: detected bridges are excluded

        anti_score = max((e.get("anti_ai_dpi_score") or 0.0) for e in anti_entries) \
            if anti_entries else None
        siam_score = max((e.get("iran_siam_score") or 0.0) for e in siam_entries) \
            if siam_entries else None
        smart_raw = max(
            (e.get("final_score") or e.get("dpi_score") or 0.0) for e in smart_entries
        ) if smart_entries else None
        smart_score = max(0.0, min(1.0, smart_raw / 100.0)) if smart_raw is not None \
            else None

        present = [(w, s) for w, s in (
            (W_ANTI_AI, anti_score), (W_SIAM, siam_score), (W_SMART, smart_score),
        ) if s is not None]
        composite = sum(w * s for w, s in present) / sum(w for w, _ in present) \
            if present else 0.0
        if anti_score is None and siam_score is None and smart_score is None:
            composite = 0.0

        # A Smart-Iran "tier" (e.g. good) does not override the SIAM verdict.
        smart_tier = None
        for e in smart_entries:
            if (e.get("tier") or "").strip():
                smart_tier = (e.get("tier") or "").strip().lower()
                break

        records[line] = {
            "bridge_line": line,
            "transport": next(
                (
                    e.get("transport")
                    for lst in (anti_entries, siam_entries, smart_entries)
                    for e in lst
                    if (e.get("transport") or "").strip()
                ),
                "unknown",
            ),
            "tier": tier or ("smart:" + smart_tier if smart_tier else "UNRANKED"),
            "tier_priority": tier_priority,
            "composite": round(composite, 6),
            "signals": {
                "anti_ai_dpi_score": round(anti_score, 6) if anti_score is not None else None,
                "iran_siam_score": round(siam_score, 6) if siam_score is not None else None,
                "smart_score": round(smart_raw, 6) if smart_raw is not None else None,
            },
        }
    return records


def main():
    records = build_records()
    pool = sorted(
        records.values(),
        key=lambda r: (-r["tier_priority"], -r["composite"], r["bridge_line"]),
    )
    if TOP_N and TOP_N > 0:
        pool = pool[:TOP_N]

    tier_counts = Counter(r["tier"].split(":")[0] for r in pool)
    transport_counts = Counter(r["transport"] for r in pool)

    os.makedirs(OUT_DIR, exist_ok=True)
    txt_path = os.path.join(OUT_DIR, "iran_anti_dpi_elite.txt")
    json_path = os.path.join(OUT_DIR, "iran_anti_dpi_elite.json")

    with open(txt_path, "w", encoding="utf-8") as fh:
        for r in pool:
            fh.write(r["bridge_line"] + "\n")

    summary = OrderedDict()
    summary["engine"] = "torshield-rust-anti-dpi-elite-fusion-v1"
    summary["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    summary["input_files"] = {k: os.path.relpath(p, REPO) for k, p in INPUTS.items()}
    summary["top_n_cap"] = TOP_N
    summary["tier_priority"] = TIER_ORDER
    summary["totals"] = {
        "elite_bridges": len(pool),
        "tiers": {t: tier_counts.get(t, 0) for t in TIER_ORDER},
        "transports": dict(sorted(transport_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
    summary["top"] = [
        {
            "rank": i + 1,
            "tier": r["tier"],
            "composite_score": r["composite"],
            "signals": r["signals"],
            "bridge_line": r["bridge_line"],
        }
        for i, r in enumerate(pool[:50])
    ]
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print("═══ Stage 8s — Iran Anti-DPI Elite fusion ═══")
    print(f"  inputs : {', '.join(summary['input_files'].values())}")
    print(f"  pool   : {len(pool)} elite bridges "
          f"(PHANTOM={tier_counts.get('PHANTOM', 0)}, "
          f"STEALTH={tier_counts.get('STEALTH', 0)}, "
          f"COVERT={tier_counts.get('COVERT', 0)}, "
          f"UNRANKED={tier_counts.get('UNRANKED', 0)})")
    print(f"  output : {os.path.relpath(txt_path, REPO)} "
          f"+ {os.path.relpath(json_path, REPO)}")


if __name__ == "__main__":
    main()
PY
