from __future__ import annotations

from datetime import datetime, timezone

from core.dt_utils import coerce_utc_dt, parse_dt
UTC = timezone.utc


def test_parse_dt_preserves_aware_offsets_for_backward_compatibility() -> None:
    parsed = parse_dt("2026-06-05T08:45:38+03:30")

    assert parsed.isoformat() == "2026-06-05T08:45:38+03:30"


def test_coerce_utc_dt_normalizes_aware_and_naive_history_values_to_utc() -> None:
    assert coerce_utc_dt("2026-06-05T08:45:38+03:30").isoformat() == "2026-06-05T05:15:38+00:00"
    assert coerce_utc_dt("2026-06-05T07:45:38").isoformat() == "2026-06-05T07:45:38+00:00"
    assert coerce_utc_dt(datetime(2026, 6, 5, 7, 45, 38)).tzinfo is UTC


def test_coerce_utc_dt_uses_explicit_fallback_for_invalid_values() -> None:
    assert coerce_utc_dt(None).isoformat() == "2000-01-01T00:00:00+00:00"
    assert coerce_utc_dt("not-a-date", "1999-01-01T00:00:00+00:00").isoformat() == "1999-01-01T00:00:00+00:00"
