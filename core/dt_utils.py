from __future__ import annotations

"""
core/dt_utils.py — Timezone-safe datetime utilities for TorShield-IR.

Root cause of the TypeError:
  datetime.utcnow()         → naive  datetime (no tzinfo)
  datetime.fromisoformat()  → aware  datetime when the ISO string has "+00:00"
  Python raises TypeError when comparing naive vs aware datetimes.

Fix applied everywhere: always work in UTC-aware datetimes.
  utc_now()    replaces  datetime.utcnow()
  parse_dt()   replaces  datetime.fromisoformat() in comparisons
"""

from datetime import datetime, timezone
from typing import Any
UTC = timezone.utc


def utc_now() -> datetime:
    """Return the current time as a UTC-aware datetime."""
    return datetime.now(UTC)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with +00:00 suffix."""
    return utc_now().isoformat()


def coerce_utc_dt(value: Any, fallback: str = "2000-01-01T00:00:00+00:00") -> datetime:
    """Coerce a history timestamp to a UTC-aware datetime.

    Bridge history may contain legacy naive timestamps from older runs. Treat
    those naive values as UTC, and normalize aware values to UTC so every
    history comparison uses UTC-aware datetimes.
    """
    try:
        fallback_dt = (
            fallback
            if isinstance(fallback, datetime)
            else datetime.fromisoformat(str(fallback).replace("Z", "+00:00"))
        )
    except ValueError as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('core.dt_utils:43', _remediation_exc)
        fallback_dt = datetime(1970, 1, 1, tzinfo=UTC)
    if fallback_dt.tzinfo is None:
        fallback_dt = fallback_dt.replace(tzinfo=UTC)
    else:
        fallback_dt = fallback_dt.astimezone(UTC)

    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            return fallback_dt
    except (TypeError, ValueError):
        return fallback_dt

    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_dt(s: str) -> datetime:
    """
    Parse an ISO-8601 datetime string and always return an aware datetime.

    Handles both formats stored in bridge_history.json:
      • Naive   — "2026-06-05T07:45:38"        (old records, assume UTC)
      • Aware   — "2026-06-05T07:45:38+03:30"  (preserve existing offset)

    Backward compatible behavior: malformed strings return the Unix epoch.
    """
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=UTC)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
