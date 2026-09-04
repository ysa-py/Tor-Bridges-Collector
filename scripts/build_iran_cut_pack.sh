#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_iran_cut_pack.sh — Stage 8p2: NIN internet-cut pack finalizer.
#
# Rebuilds the USER-FACING `export/iran_cut_pack.txt` (the file README.md
# points Iranian users to during a "شبکه ملی / national internet cut") from
# every NIN-cut intelligence artifact produced earlier in the run, so the pack
# is never silently empty when real survivable candidates exist.
#
# Sources merged, in priority order (keep-first dedup by canonical line):
#   1. data/nin_eligible.json            Stage 8d  (nin_selector — strict NIN
#                                        CDN/DTLS eligibility; often 0 because
#                                        the CI runner cannot reach them)
#   2. bridge/iran_likely_working_nin.txt Stage 8p  (nin_internet_cut_classifier
#                                        combined output; also in the 55-file
#                                        bridge/ publication contract)
#   3. export/nin_cut_bridges.txt        Stage 8p  (classifier GREEN pack)
#   4. export/iran_nin_pack.txt          Stage 8d2 (iran_nin_bypass NIN pack)
#   5. export/nin_cut_survivable.txt     Stage 8k  (nin_cut_tester — probe-based
#                                        survivability under simulated cut:
#                                        Iranian-domestic obfs4 + CDN-fronted,
#                                        the transports that actually survive a
#                                        real national-internet cut)
#
# Behaviour:
#   * Deterministic: stable source order, keep-first dedup, header WITHOUT a
#     timestamp, so a regeneration is byte-identical (the invariant audit
#     compares committed vs regenerated).
#   * Honest: the header reports the real merged count and each source's
#     contribution. If every source is empty/missing the pack still states
#     "Bridges: 0" loudly (::error::) instead of pretending.
#   * Advisory: runner-side evidence, consistent with the README honesty
#     contract — never presented as Iranian-side measurement.
#   * Touches NO Rust source, so it cannot break the fmt/clippy/test gate.
#
# Usage: scripts/build_iran_cut_pack.sh
# Env:   NIN_CUT_PACK_OUT   output directory (default: <repo>/export)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error::python3 is required by build_iran_cut_pack.sh" >&2
  exit 1
fi

export NIN_CUT_PACK_OUT
python3 - <<'PY'
"""Stage 8p2 — NIN cut-pack finalizer (pure stdlib, deterministic)."""
import json
import os
import sys

REPO = os.getcwd()
OUT_DIR = os.environ.get("NIN_CUT_PACK_OUT") or os.path.join(REPO, "export")
OUT = os.path.join(OUT_DIR, "iran_cut_pack.txt")

# Source, (display name, required-at-least-one flag). Keep-first priority.
def lines_of_json_array(path):
    """Return non-empty canonical bridge lines from a JSON array of records."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"  ⚠ {os.path.relpath(path, REPO)} unreadable ({exc}) — skipping",
              file=sys.stderr)
        return [], 0
    if not isinstance(doc, list):
        print(f"  ⚠ {os.path.relpath(path, REPO)} is not a JSON array — skipping",
              file=sys.stderr)
        return [], 0
    out = []
    for entry in doc:
        if not isinstance(entry, dict):
            continue
        line = entry.get("raw") or entry.get("bridge_line") or entry.get("line")
        if isinstance(line, str):
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out, len(out)


def lines_of_txt(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except OSError as exc:
        print(f"  ⚠ {os.path.relpath(path, REPO)} unreadable ({exc}) — skipping",
              file=sys.stderr)
        return []


SOURCES = [
    (os.path.join(REPO, "data", "nin_eligible.json"), "data/nin_eligible.json (Stage 8d, strict)", True),
    (os.path.join(REPO, "bridge", "iran_likely_working_nin.txt"), "bridge/iran_likely_working_nin.txt (Stage 8p)", False),
    (os.path.join(REPO, "export", "nin_cut_bridges.txt"), "export/nin_cut_bridges.txt (Stage 8p)", False),
    (os.path.join(REPO, "export", "iran_nin_pack.txt"), "export/iran_nin_pack.txt (Stage 8d2)", False),
    (os.path.join(REPO, "export", "nin_cut_survivable.txt"), "export/nin_cut_survivable.txt (Stage 8k, probe-based)", False),
]


def main():
    seen = set()
    merged = []
    contributions = []
    present_any = False
    for path, label, is_json in SOURCES:
        if not os.path.exists(path):
            continue
        present_any = True
        if is_json:
            raw, total = lines_of_json_array(path)
        else:
            raw = lines_of_txt(path)
            total = len(raw)
        before = len(merged)
        for line in raw:
            if line not in seen:
                seen.add(line)
                merged.append(line)
        contributions.append(f"{os.path.relpath(path, REPO)}={total} lines "
                             f"(+{len(merged) - before} unique)")
    if not present_any:
        rel = os.path.relpath(OUT, REPO)
        print(f"::error::build_iran_cut_pack: no NIN-cut source artifacts found "
              f"— {rel} not written", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    body = [
        "# TorShield-IR — Internet Cut Pack (شبکه ملی / NIN Mode)",
        f"# Bridges: {len(merged)}  (survivable during full international internet cut)",
        "# Order: source priority — strict NIN-eligible, classifier packs, then",
        "# probe-survivable domestic/CDN set (each stage's own internal order).",
        "#",
        "# Merged automatically (Stage 8p2) from every NIN-cut intelligence artifact:",
    ]
    body += [f"#   {c}" for c in contributions]
    body.append("#")
    body.append("# Advisory: runner-side evidence, not Iranian-side measurement.")
    body.append("# Usage: Tor Browser -> Settings -> Connection -> Bridges -> paste lines.")
    body.append("")
    for line in merged:
        body.append(line)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body) + "\n")

    print("═══ Stage 8p2 — NIN cut-pack finalizer ═══")
    for c in contributions:
        print(f"  {c}")
    print(f"  {os.path.relpath(OUT, REPO)} : {len(merged)} unique bridges")
    if not merged:
        print("::error::build_iran_cut_pack: merged pack is EMPTY — every source "
              "reported zero survivable candidates", file=sys.stderr)


if __name__ == "__main__":
    main()
PY
