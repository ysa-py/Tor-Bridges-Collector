from __future__ import annotations

"""Adaptive, additive bridge scoring for Iran conditions.

The scorer is intentionally non-destructive: it only returns a numeric score
and human-readable reasons for a bridge that has already been collected and
probed.  Callers can persist the optional annotations without skipping or
removing any existing bridge records.
"""

import json
import re
from pathlib import Path
from typing import Any

from sources.history_utils import parse_history_dt

_HIGH_RISK_PORTS = {2053, 9001, 9030}
_DOMAIN_FRONT_HINTS = (
    "front=", "url=", "cdn", "cloudfront.net", "fastly.net", "azureedge.net",
    "aspnetcdn.com", "arvancloud", "gstatic.com", "googlevideo.com",
)
_ENDPOINT_RE = re.compile(r"(?P<host>\[[^\]]+\]|[^\s:]+):(?P<port>\d{2,5})")


def _load_json(path: str | Path) -> Any:
    try:
        p = Path(path)
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_telemetry(path: str | Path = "data/telemetry_state.json") -> dict[str, Any]:
    data = _load_json(path)
    return data if isinstance(data, dict) else {}


def load_scheduler_results(path: str | Path = "data/scheduler_results.json") -> dict[str, Any]:
    data = _load_json(path)
    return data if isinstance(data, dict) else {}


def _raw_line(record: dict[str, Any]) -> str:
    for key in ("raw", "line", "bridge_line"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _transport(record: dict[str, Any]) -> str:
    value = record.get("transport")
    if isinstance(value, str) and value.strip():
        return value.strip().lower().replace("-", "_")
    raw = _raw_line(record).lower()
    for name in ("snowflake", "webtunnel", "meek_lite", "meek-azure", "obfs4", "vanilla"):
        if name in raw:
            return "meek_lite" if name == "meek-azure" else name
    return "unknown"


def _coerce_port(value: Any) -> int:
    """Return a valid TCP/UDP port number, or ``0`` when unavailable.

    Bridge history can contain partially-normalized records where ``port`` is
    present but set to ``None`` or an empty string.  Those values are expected
    for legacy/imported records and should not be recorded as scorer failures;
    callers can still recover the port from the raw bridge line below.
    """
    if value in (None, ""):
        return 0
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port <= 65535 else 0


def _port(record: dict[str, Any]) -> int:
    value = _coerce_port(record.get("port"))
    if value:
        return value
    match = _ENDPOINT_RE.search(_raw_line(record))
    if not match:
        return 0
    try:
        return int(match.group("port"))
    except (TypeError, ValueError):
        return 0


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "reachable", "ok", "up"}:
            return True
        if lowered in {"false", "no", "0", "blocked", "down", "failed"}:
            return False
    return None


def _scheduler_for(record: dict[str, Any], scheduler_results: Any) -> dict[str, Any]:
    if not isinstance(scheduler_results, dict):
        return {}
    raw = _raw_line(record)
    candidates = scheduler_results.get("results", [])
    if isinstance(candidates, dict):
        candidates = candidates.values()
    if not isinstance(candidates, list):
        return {}
    key_values = {raw, record.get("raw"), record.get("line"), record.get("bridge_line")}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        if any(item.get(k) in key_values for k in ("raw", "line", "bridge_line", "bridge")):
            return item
    return {}


def _telemetry_pressure(telemetry: Any) -> tuple[bool, list[str]]:
    if not isinstance(telemetry, dict):
        return False, ["telemetry unavailable or invalid"]
    counters = telemetry.get("counters") if isinstance(telemetry.get("counters"), dict) else {}
    dpi_total = int(counters.get("dpi_total", 0) or 0)
    blocked = int(counters.get("dpi_blocked", 0) or 0)
    camouflaged = int(counters.get("dpi_camouflaged", 0) or 0)
    heals = int(counters.get("self_heal_total", 0) or 0)
    recent = telemetry.get("recent_dpi_events") if isinstance(telemetry.get("recent_dpi_events"), list) else []
    recent_blocked = sum(1 for e in recent if isinstance(e, dict) and e.get("action") in {"blocked", "detected"})
    high = (dpi_total + recent_blocked) >= 3 or blocked > 0 or camouflaged >= 2
    reasons: list[str] = []
    if high:
        reasons.append("high DPI telemetry state detected")
    if heals:
        reasons.append(f"self-heal telemetry active ({heals} events)")
    return high, reasons


def _freshness_points(record: dict[str, Any], now_utc: Any, reasons: list[str]) -> float:
    value = record.get("last_seen") or record.get("test_time") or record.get("first_seen")
    if not value:
        reasons.append("missing freshness timestamp")
        return 4.0
    try:
        age = parse_history_dt(now_utc) - parse_history_dt(value)
    except Exception:
        reasons.append("invalid freshness timestamp")
        return 4.0
    hours = age.total_seconds() / 3600
    if hours <= 24:
        reasons.append("fresh bridge timestamp (<=24h)")
        return 12.0
    if hours <= 72:
        reasons.append("recent bridge timestamp (<=72h)")
        return 9.0
    if hours <= 24 * 7:
        reasons.append("week-old bridge timestamp")
        return 5.0
    reasons.append("stale bridge timestamp")
    return 1.0


def _latency_points(latency: Any, reasons: list[str]) -> float:
    try:
        ms = float(latency)
    except (TypeError, ValueError):
        reasons.append("latency unavailable")
        return 5.0
    if ms <= 250:
        reasons.append(f"low latency ({ms:.0f}ms)")
        return 12.0
    if ms <= 800:
        reasons.append(f"moderate latency ({ms:.0f}ms)")
        return 8.0
    reasons.append(f"high latency ({ms:.0f}ms)")
    return 2.0


def recommended_priority(score: float) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def score_bridge(
    record: dict[str, Any],
    telemetry: Any | None = None,
    now_utc: Any | None = None,
    scheduler_results: Any | None = None,
) -> tuple[float, list[str]]:
    """Return ``(score, reasons)`` for an already collected/probed bridge."""
    from core.dt_utils import utc_now

    now_utc = now_utc or utc_now()
    telemetry = {} if telemetry is None else telemetry
    scheduler = _scheduler_for(record, scheduler_results) if scheduler_results is not None else {}
    merged = {**record, **scheduler}
    reasons: list[str] = []
    score = 40.0

    high_dpi, telemetry_reasons = _telemetry_pressure(telemetry)
    reasons.extend(telemetry_reasons)

    transport = _transport(merged)
    domain_fronted = transport in {"webtunnel", "meek_lite"} or any(h in _raw_line(merged).lower() for h in _DOMAIN_FRONT_HINTS)
    if high_dpi:
        if transport == "snowflake":
            score += 24; reasons.append("snowflake resilience credit under high DPI")
        elif transport == "webtunnel":
            score += 22; reasons.append("webtunnel prioritized under high DPI")
        elif domain_fronted:
            score += 18; reasons.append("domain-fronted transport prioritized under high DPI")
        elif transport == "obfs4":
            score += 8; reasons.append("obfs4 receives limited DPI resilience credit")
        else:
            score -= 6; reasons.append("transport has low DPI resilience")
    else:
        score += {"snowflake": 18, "webtunnel": 17, "meek_lite": 13, "obfs4": 10, "vanilla": 0}.get(transport, 4)
        reasons.append(f"transport preference applied: {transport}")

    reachable = _bool_value(merged.get("RIPEReachable", merged.get("ripe_reachable")))
    ripe_tested = _bool_value(merged.get("RIPETested", merged.get("ripe_tested")))
    if reachable is True:
        score += 12; reasons.append("RIPE reachable")
    elif reachable is False and ripe_tested is True:
        score -= 10; reasons.append("RIPE tested unreachable")
    elif ripe_tested is True:
        reasons.append("RIPE tested without definitive reachability")

    pt_status = str(merged.get("pt_status") or merged.get("PTStatus") or "").lower()
    if pt_status in {"ok", "running", "reachable", "success"}:
        score += 8; reasons.append(f"PT status positive ({pt_status})")
    elif pt_status in {"failed", "blocked", "down", "error"}:
        score -= 10; reasons.append(f"PT status negative ({pt_status})")

    test_pass = _bool_value(merged.get("test_pass", merged.get("tcp_reachable")))
    if test_pass is True:
        score += 12; reasons.append("recent probe succeeded")
    elif test_pass is False:
        score -= 18; reasons.append("recent probe failed; penalized but retained")

    score += _latency_points(merged.get("latency_ms", merged.get("latency")), reasons)
    score += _freshness_points(merged, now_utc, reasons)

    port = _port(merged)
    if port in _HIGH_RISK_PORTS:
        score -= 12; reasons.append(f"high-risk Iran tester port ({port})")
    elif port in {443, 80, 8080, 8443, 2083, 2087, 2096}:
        score += 5; reasons.append(f"Iran-preferred port ({port})")

    return round(max(0.0, min(100.0, score)), 2), reasons
