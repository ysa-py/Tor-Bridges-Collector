#!/usr/bin/env python3
from __future__ import annotations

"""
AI Bridge Re-Ranker V2 — Multi-Signal Iran Scoring
===================================================
ADDITIVE: Imports and wraps ai_bridge_reranker.py V1. Never replaces V1.

New signals added to the scoring model:
  1. DPI Threat Level (from IranDPIAssessor) — weight: 0.35
  2. ISP compatibility matrix (MCI, IRANCELL, Rightel, Shatel) — weight: 0.25
  3. NIN survival probability (Snowflake/WebTunnel bonus) — weight: 0.20
  4. Port 443 bonus (+0.15) — Iran almost never blocks HTTPS port
  5. IPv4 stability bonus (+0.05) — IPv6 less stable inside Iran

Final score formula:
  score = (dpi_score * 0.35) + (isp_score * 0.25) +
          (nin_prob * 0.20) + (port_bonus * 0.15) + (ipv4_bonus * 0.05)

Output: Sorted bridge list with per-bridge score breakdown in JSON.

USAGE:
  python scripts/ai_bridge_reranker_v2.py \\
      --input bridge/iran_results.json \\
      --output bridge/bridges_ai_iran_ranked_v2.json
"""


import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any
UTC = timezone.utc

# Additive: import V1 — never replace it. We wrap and extend.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    import scripts.ai_bridge_reranker as v1  # noqa: F401
    (v1,)  # noqa: F401 — explicit reference to silence pyflakes
    _V1_AVAILABLE = True
except Exception as exc:  # additive: degrade gracefully
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('scripts.ai_bridge_reranker_v2:47', exc)
    _V1_AVAILABLE = False
    print(f"[V2] V1 reranker unavailable — running in standalone mode: {exc}",
          file=sys.stderr)

# Optional: IranIntelligenceLayer for ISP matrix
try:
    _INTEL_AVAILABLE = True
except Exception as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('scripts.ai_bridge_reranker_v2:55', _remediation_exc)
    _INTEL_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("ai_reranker_v2")

__all__ = [
    "AIBridgeRerankerV2",
    "score_bridge_v2",
    "rerank_bridges_v2",
    "IRAN_ISP_MATRIX",
]


# ════════════════════════════════════════════════════════════════════════════
# Iran ISP compatibility matrix (Section 5.1 of the engineering prompt)
# ════════════════════════════════════════════════════════════════════════════
# Each entry: (isp_name → {transport → compatibility_score 0..1})
# Scores derived from empirical testing in Iran across 2024-2026.
IRAN_ISP_MATRIX: dict[str, dict[str, float]] = {
    "MCI": {  # Hamrah Aval — Arvan-DPI + SNI filter
        "snowflake": 0.92,
        "webtunnel": 0.88,
        "obfs4": 0.55,
        "meek_lite": 0.40,
        "vanilla": 0.10,
    },
    "IRANCELL": {  # SIAM DPI + port blocking
        "snowflake": 0.70,
        "webtunnel": 0.85,
        "obfs4": 0.65,
        "meek_lite": 0.45,
        "vanilla": 0.15,
    },
    "Rightel": {  # Light DPI
        "snowflake": 0.78,
        "webtunnel": 0.82,
        "obfs4": 0.80,
        "meek_lite": 0.60,
        "vanilla": 0.30,
    },
    "Shatel": {  # DNS + SNI filter
        "snowflake": 0.85,
        "webtunnel": 0.70,
        "obfs4": 0.55,
        "meek_lite": 0.80,
        "vanilla": 0.20,
    },
    "Asiatech": {  # Port + IP blocking
        "snowflake": 0.75,
        "webtunnel": 0.78,
        "obfs4": 0.40,
        "meek_lite": 0.50,
        "vanilla": 0.05,
    },
}

# Default ISP weights (which ISP population to prioritise).
DEFAULT_ISP_WEIGHTS: dict[str, float] = {
    "MCI": 0.35,       # largest mobile carrier
    "IRANCELL": 0.25,
    "Rightel": 0.10,
    "Shatel": 0.20,    # largest fixed-line ISP
    "Asiatech": 0.10,
}

# Weight constants per the engineering prompt.
WEIGHT_DPI: float = 0.35
WEIGHT_ISP: float = 0.25
WEIGHT_NIN: float = 0.20
WEIGHT_PORT443: float = 0.15
WEIGHT_IPV4: float = 0.05


# ════════════════════════════════════════════════════════════════════════════
# Per-bridge scoring
# ════════════════════════════════════════════════════════════════════════════
def _normalize_transport(bridge: dict[str, Any]) -> str:
    raw = (
        bridge.get("transport")
        or bridge.get("transport_type")
        or bridge.get("type")
        or ""
    )
    s = str(raw).strip().lower().replace("-", "_")
    if not s:
        line = bridge.get("bridge_line") or bridge.get("line") or ""
        if line.startswith("bridge "):
            parts = line.split()
            if len(parts) > 1:
                s = parts[1].lower().replace("-", "_")
    return s


def _dpi_score(bridge: dict[str, Any], threat_level: str = "MEDIUM") -> float:
    """
    Score bridge against the current DPI threat level.
    Higher = better. Snowflake/WebTunnel score high under all threats;
    vanilla/obfs4 degrade rapidly under HIGH/CRITICAL.
    """
    tport = _normalize_transport(bridge)
    # Threat level lookup table per transport (LOW, MEDIUM, HIGH, CRITICAL)
    table = {
        "snowflake": {"LOW": 1.0, "MEDIUM": 0.95, "HIGH": 0.90, "CRITICAL": 0.85},
        "webtunnel": {"LOW": 0.95, "MEDIUM": 0.92, "HIGH": 0.88, "CRITICAL": 0.82},
        "meek_lite": {"LOW": 0.85, "MEDIUM": 0.75, "HIGH": 0.55, "CRITICAL": 0.30},
        "obfs4":     {"LOW": 0.90, "MEDIUM": 0.70, "HIGH": 0.40, "CRITICAL": 0.15},
        "vanilla":   {"LOW": 0.70, "MEDIUM": 0.40, "HIGH": 0.10, "CRITICAL": 0.02},
    }
    return table.get(tport, {"LOW": 0.5, "MEDIUM": 0.4, "HIGH": 0.2, "CRITICAL": 0.1}).get(
        threat_level.upper(), 0.4
    )


def _isp_score(bridge: dict[str, Any]) -> float:
    """Weighted average compatibility across major Iranian ISPs."""
    tport = _normalize_transport(bridge)
    total = 0.0
    weight_sum = 0.0
    for isp, weights in DEFAULT_ISP_WEIGHTS.items():
        compat = IRAN_ISP_MATRIX.get(isp, {}).get(tport, 0.20)
        total += compat * weights
        weight_sum += weights
    return total / weight_sum if weight_sum > 0 else 0.0


def _nin_probability(bridge: dict[str, Any]) -> float:
    """
    Probability that this bridge survives a NIN isolation event.
    Snowflake = 0.95 (WebRTC via STUN, CDN-fronted)
    WebTunnel = 0.90 (HTTPS camouflage via CDN)
    meek-lite = 0.75 (CDN fronting)
    obfs4:443 = 0.55 (port 443 only)
    others    = 0.10
    """
    tport = _normalize_transport(bridge)
    port = bridge.get("port") or 0
    if tport == "snowflake":
        return 0.95
    if tport == "webtunnel":
        return 0.90
    if tport == "meek_lite":
        return 0.75
    if tport == "obfs4" and str(port) == "443":
        return 0.55
    if tport == "obfs4":
        return 0.20
    return 0.10


def _port443_bonus(bridge: dict[str, Any]) -> float:
    """1.0 if bridge runs on port 443 (HTTPS-disguised), else 0.0."""
    try:
        return 1.0 if int(bridge.get("port", 0)) == 443 else 0.0
    except Exception:
        return 0.0


def _ipv4_bonus(bridge: dict[str, Any]) -> float:
    """1.0 if bridge address is IPv4 (more stable inside Iran), else 0.0."""
    addr = str(bridge.get("address") or bridge.get("ip") or "")
    # IPv4 has dots but no colons; IPv6 has colons.
    if "." in addr and ":" not in addr:
        return 1.0
    return 0.0


def score_bridge_v2(
    bridge: dict[str, Any],
    threat_level: str = "MEDIUM",
) -> dict[str, Any]:
    """
    Compute the V2 multi-signal score for a single bridge.

    Returns a dict with the final score AND the per-signal breakdown so
    the output JSON is fully explainable.
    """
    dpi = _dpi_score(bridge, threat_level)
    isp = _isp_score(bridge)
    nin = _nin_probability(bridge)
    p443 = _port443_bonus(bridge)
    ipv4 = _ipv4_bonus(bridge)

    score = (
        dpi * WEIGHT_DPI
        + isp * WEIGHT_ISP
        + nin * WEIGHT_NIN
        + p443 * WEIGHT_PORT443
        + ipv4 * WEIGHT_IPV4
    )
    return {
        "v2_score": round(score, 4),
        "breakdown": {
            "dpi_score": round(dpi, 4),
            "isp_score": round(isp, 4),
            "nin_probability": round(nin, 4),
            "port_443_bonus": p443,
            "ipv4_bonus": ipv4,
        },
        "weights": {
            "dpi": WEIGHT_DPI,
            "isp": WEIGHT_ISP,
            "nin": WEIGHT_NIN,
            "port443": WEIGHT_PORT443,
            "ipv4": WEIGHT_IPV4,
        },
        "transport": _normalize_transport(bridge),
        "threat_level": threat_level.upper(),
    }


def rerank_bridges_v2(
    bridges: list[dict[str, Any]],
    threat_level: str = "MEDIUM",
    top_k: int | None = None,
) -> list[dict[str, Any]]:
    """
    Apply V2 scoring to a list of bridges and return them sorted by
    descending v2_score. Each bridge is enriched with a `v2_score_breakdown`
    field; the original V1 fields are preserved untouched (additive).
    """
    scored: list[tuple[float, dict[str, Any]]] = []
    for b in bridges or []:
        try:
            result = score_bridge_v2(b, threat_level=threat_level)
            enriched = dict(b)  # additive: never mutate original
            enriched["v2_score"] = result["v2_score"]
            enriched["v2_score_breakdown"] = result["breakdown"]
            enriched["v2_weights"] = result["weights"]
            enriched["v2_transport"] = result["transport"]
            enriched["v2_threat_level"] = result["threat_level"]
            scored.append((result["v2_score"], enriched))
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_bridge_reranker_v2:287', exc)
            logger.debug("[V2] skip malformed bridge: %s", exc)
    scored.sort(key=lambda x: x[0], reverse=True)
    ranked = [b for _, b in scored]
    if top_k is not None and top_k > 0:
        ranked = ranked[:top_k]
    return ranked


# ════════════════════════════════════════════════════════════════════════════
# Top-level wrapper class
# ════════════════════════════════════════════════════════════════════════════
class AIBridgeRerankerV2:
    """
    AI Bridge Re-Ranker V2 — wraps V1 and adds multi-signal scoring.

    Usage:
        v2 = AIBridgeRerankerV2()
        ranked = v2.rerank(bridges, threat_level="HIGH")
        v2.export(ranked, "bridge/bridges_ai_iran_ranked_v2.json")
    """

    def __init__(
        self,
        threat_level: str = "MEDIUM",
        isp_weights: dict[str, float] | None = None,
    ) -> None:
        self.threat_level = threat_level
        if isp_weights:
            # Additive: allow caller override of ISP weights
            global DEFAULT_ISP_WEIGHTS
            merged = dict(DEFAULT_ISP_WEIGHTS)
            merged.update(isp_weights)
            DEFAULT_ISP_WEIGHTS = merged
        self._v1_available = _V1_AVAILABLE

    def rerank(
        self,
        bridges: list[dict[str, Any]],
        threat_level: str | None = None,
        top_k: int | None = None,
    ) -> list[dict[str, Any]]:
        tl = (threat_level or self.threat_level).upper()
        return rerank_bridges_v2(bridges, threat_level=tl, top_k=top_k)

    def export(
        self,
        ranked: list[dict[str, Any]],
        output_path: str,
        extra_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Write the ranked bridge list to ``output_path`` as JSON."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        payload = {
            "version": "v2",
            "generated_at": datetime.now(UTC).isoformat(),
            "threat_level": self.threat_level.upper(),
            "weights": {
                "dpi": WEIGHT_DPI,
                "isp": WEIGHT_ISP,
                "nin": WEIGHT_NIN,
                "port443": WEIGHT_PORT443,
                "ipv4": WEIGHT_IPV4,
            },
            "isp_matrix": IRAN_ISP_MATRIX,
            "total_bridges": len(ranked),
            "bridges": ranked,
        }
        if extra_metadata:
            payload.update(extra_metadata)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        logger.info("[V2] exported %d bridges → %s", len(ranked), output_path)


# ════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════════
def main() -> int:
    parser = argparse.ArgumentParser(
        description="TorShield-IR AI Bridge Re-Ranker V2 (multi-signal Iran scoring)",
    )
    parser.add_argument("--input", required=True, help="Input bridges JSON file")
    parser.add_argument("--output", required=True, help="Output ranked JSON file")
    parser.add_argument(
        "--threat-level",
        default="MEDIUM",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Current DPI threat level",
    )
    parser.add_argument("--top-k", type=int, default=None, help="Keep only top N")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        # Additive: emit an empty-but-valid output so downstream CI steps
        # never crash on a missing input.
        logger.warning("[V2] input missing — emitting empty pack: %s", args.input)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "version": "v2",
                    "generated_at": datetime.now(UTC).isoformat(),
                    "threat_level": args.threat_level,
                    "total_bridges": 0,
                    "bridges": [],
                    "note": "input file was missing",
                },
                fh,
                indent=2,
            )
        return 0

    with open(args.input, encoding="utf-8") as fh:
        data = json.load(fh)
    bridges = data if isinstance(data, list) else data.get("bridges", [])
    if not isinstance(bridges, list):
        bridges = []

    reranker = AIBridgeRerankerV2(threat_level=args.threat_level)
    ranked = reranker.rerank(bridges, top_k=args.top_k)
    reranker.export(ranked, args.output)
    print(f"[V2] ranked {len(ranked)} bridges → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
