from __future__ import annotations

"""Non-destructive Iran-aware bridge prioritization.

This module only scores and reorders existing bridge records. It never drops
records, mutates input records in-place, or removes existing fields.
"""

import copy
import re
from collections.abc import Iterable
from datetime import timedelta, timezone
from typing import Any

import config
from core.dt_utils import coerce_utc_dt, utc_now

_SUPPORTED_TRANSPORTS = {"snowflake", "webtunnel", "obfs4", "meek_lite", "vanilla"}
_TRANSPORT_SCORES = {
    "snowflake": 1.0,
    "webtunnel": 0.92,
    "meek_lite": 0.84,
    "obfs4": 0.76,
    "vanilla": 0.18,
    "unknown": 0.30,
}
_ENDPOINT_RE = re.compile(
    r"(?P<host>\[[^\]]+\]|[^\s:]+):(?P<port>\d{2,5})"
)


def _enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _raw_line(record: dict[str, Any]) -> str:
    for key in ("raw", "line", "bridge_line"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _extract_port(record: dict[str, Any]) -> int:
    value = record.get("port")
    try:
        if value not in (None, ""):
            port = int(value)
            if 0 < port <= 65535:
                return port
    except (TypeError, ValueError) as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('core.iran_bridge_prioritizer:60', _remediation_exc)
        pass

    match = _ENDPOINT_RE.search(_raw_line(record))
    if not match:
        return 0
    try:
        return int(match.group("port"))
    except (TypeError, ValueError):
        return 0


def _extract_transport(record: dict[str, Any]) -> str:
    value = record.get("transport")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    raw = _raw_line(record).lower()
    for transport in _SUPPORTED_TRANSPORTS:
        if re.search(rf"\b{re.escape(transport)}\b", raw):
            return transport
    return "unknown"


def _recency_score(record: dict[str, Any], now=None) -> float:
    now = now or utc_now()
    value = record.get("last_seen") or record.get("tested_at") or record.get("first_seen")
    if not value:
        return 0.0
    age = now - coerce_utc_dt(value)
    if age <= timedelta(hours=24):
        return 1.0
    if age <= timedelta(hours=72):
        return 0.75
    if age <= timedelta(days=7):
        return 0.50
    if age <= timedelta(days=30):
        return 0.25
    return 0.05


def _reachability_score(record: dict[str, Any]) -> float:
    for key in ("reachable", "test_pass", "success", "is_reachable"):
        if record.get(key) is True:
            return 1.0
        if record.get(key) is False:
            return 0.0

    metadata = record.get("reachability") or record.get("reachability_metadata")
    if isinstance(metadata, dict):
        for key in ("success", "reachable", "ok"):
            if metadata.get(key) is True:
                return 1.0
            if metadata.get(key) is False:
                return 0.0
        score = metadata.get("score")
        if isinstance(score, (int, float)):
            return max(0.0, min(1.0, float(score)))

    if record.get("ripe_atlas_reachable") is True or record.get("atlas_success") is True:
        return 1.0
    return 0.0


def _within_window(hour: int, start: int, end: int) -> bool:
    if start == end:
        return True
    if start < end:
        return start <= hour <= end
    return hour >= start or hour <= end


def _context_multiplier(now=None) -> float:
    multiplier = 1.0
    for flag in ("UTLS_EVASION_MODE", "NIN_MODE"):
        if _enabled(getattr(config, flag, False)):
            multiplier += 0.05
    iran_now = (now or utc_now()).astimezone(
        timezone(timedelta(hours=3, minutes=30))
    )
    iran_hour = iran_now.hour
    if _within_window(
        iran_hour,
        int(getattr(config, "IRST_HIGH_CENSORSHIP_START", 18)),
        int(getattr(config, "IRST_HIGH_CENSORSHIP_END", 1)),
    ):
        multiplier += 0.05
    if _within_window(
        iran_hour,
        int(getattr(config, "IRST_ULTRA_STEALTH_START", 20)),
        int(getattr(config, "IRST_ULTRA_STEALTH_END", 23)),
    ):
        multiplier += 0.05
    if getattr(config, "RIPE_ATLAS_API_KEY", ""):
        multiplier += 0.05
    return multiplier


def score_bridge(record: dict[str, Any], *, now=None) -> dict[str, Any]:
    """Return an annotated copy of one bridge record with prioritization data."""
    port = _extract_port(record)
    transport = _extract_transport(record)
    preferred_ports = set(getattr(config, "IRAN_PREFERRED_PORTS", []))

    weights = {
        "port": _number(
            getattr(config, "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", 1.0), 1.0
        ),
        "transport": _number(
            getattr(config, "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT", 1.0), 1.0
        ),
        "recency": _number(
            getattr(config, "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", 1.0), 1.0
        ),
        "reachability": _number(
            getattr(config, "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY", 1.0),
            1.0,
        ),
    }
    signals = {
        "port": 1.0 if port in preferred_ports else 0.0,
        "transport": _TRANSPORT_SCORES.get(transport, _TRANSPORT_SCORES["unknown"]),
        "recency": _recency_score(record, now=now),
        "reachability": _reachability_score(record),
    }
    total_weight = sum(max(0.0, weight) for weight in weights.values()) or 1.0
    score = sum(signals[key] * max(0.0, weights[key]) for key in signals) / total_weight
    score *= _context_multiplier(now=now)

    annotated = copy.deepcopy(record)
    annotated["iran_prioritization"] = {
        "score": round(max(0.0, min(1.0, score)), 4),
        "signals": signals,
        "weights": weights,
        "port": port,
        "transport": transport,
    }
    return annotated


def prioritize_bridges(
    records: Iterable[dict[str, Any]], *, annotate: bool = True, now=None
) -> list[dict[str, Any]]:
    """Return all bridge records in Iran-aware priority order when enabled.

    With IRAN_BRIDGE_PRIORITIZATION_ENABLED=false, this returns a shallow copy
    of the original iterable in its original order and without annotations.
    """
    bridges = list(records)
    if not _enabled(getattr(config, "IRAN_BRIDGE_PRIORITIZATION_ENABLED", False)):
        return list(bridges)

    scored = [(idx, score_bridge(record, now=now)) for idx, record in enumerate(bridges)]
    scored.sort(
        key=lambda item: (item[1]["iran_prioritization"]["score"], -item[0]),
        reverse=True,
    )
    ranked = [record for _, record in scored]
    if annotate:
        return ranked
    return [
        {k: v for k, v in record.items() if k != "iran_prioritization"}
        for record in ranked
    ]
