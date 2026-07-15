from __future__ import annotations

from datetime import datetime, timedelta, timezone

import onionhop_collector
from sources import direct_scraper, history_utils, legacy_scraper
UTC = timezone.utc


def _sample_history() -> dict[str, object]:
    return {
        "legacy-bridge": "2026-06-05T07:45:38",
        "dict-bridge": {
            "raw": "obfs4 203.0.113.1:443 cert=abc iat-mode=2",
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": "2026-06-05T07:45:38",
            "last_seen": "2026-06-05T08:45:38+03:30",
            "tcp_reachable": True,
            "capabilities": {"kept": True, "nested": {"score": 10}},
        },
    }


def _assert_normalized(history: dict[str, object]) -> None:
    assert history["legacy-bridge"] == "2026-06-05T07:45:38+00:00"

    entry = history["dict-bridge"]
    assert isinstance(entry, dict)
    assert entry["first_seen"] == "2026-06-05T07:45:38+00:00"
    assert entry["last_seen"] == "2026-06-05T05:15:38+00:00"
    assert entry["raw"] == "obfs4 203.0.113.1:443 cert=abc iat-mode=2"
    assert entry["transport"] == "obfs4"
    assert entry["ip_version"] == "ipv4"
    assert entry["tcp_reachable"] is True
    assert entry["capabilities"] == {"kept": True, "nested": {"score": 10}}


def test_parse_history_dt_accepts_naive_and_aware_iso_timestamps() -> None:
    values = [
        "2026-06-05T07:45:38",
        "2026-06-05T07:45:38+00:00",
        datetime(2026, 6, 5, 7, 45, 38),
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
    ]

    now = datetime.now(UTC)
    parsed = [history_utils.parse_history_dt(value) for value in values]

    assert all(dt.tzinfo is not None for dt in parsed)
    assert all(dt <= now for dt in parsed)
    assert parsed == [
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
    ]


def test_normalize_history_timestamps_handles_mixed_naive_and_aware_entries() -> None:
    history = {
        "legacy-naive": "2026-06-05T07:45:38",
        "legacy-aware": "2026-06-05T07:45:38+00:00",
        "dict-mixed": {
            "raw": "obfs4 203.0.113.3:443 cert=ghi iat-mode=2",
            "first_seen": "2026-06-05T07:45:38",
            "last_seen": "2026-06-05T07:45:38+00:00",
        },
    }

    history_utils.normalize_history_timestamps(history)

    assert history == {
        "legacy-naive": "2026-06-05T07:45:38+00:00",
        "legacy-aware": "2026-06-05T07:45:38+00:00",
        "dict-mixed": {
            "raw": "obfs4 203.0.113.3:443 cert=ghi iat-mode=2",
            "first_seen": "2026-06-05T07:45:38+00:00",
            "last_seen": "2026-06-05T07:45:38+00:00",
        },
    }
    parsed_values = [
        history_utils.parse_history_dt(history["legacy-naive"]),
        history_utils.parse_history_dt(history["legacy-aware"]),
        history_utils.parse_history_dt(history["dict-mixed"]["first_seen"]),
        history_utils.parse_history_dt(history["dict-mixed"]["last_seen"]),
    ]
    assert all(dt.tzinfo is not None for dt in parsed_values)
    assert all(dt < datetime.now(UTC) for dt in parsed_values)


def test_cleanup_history_handles_mixed_naive_and_aware_entries(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "old-naive-string": "2026-05-01T07:45:38",
        "fresh-aware-string": "2026-06-05T07:45:38+00:00",
        "fresh-dict-mixed": {
            "first_seen": "2026-05-01T07:45:38",
            "last_seen": "2026-06-05T07:45:38+00:00",
        },
        "old-dict-mixed": {
            "first_seen": "2026-05-01T07:45:38+00:00",
            "last_seen": "2026-05-02T07:45:38",
        },
    }

    assert history_utils.cleanup_history(history, 30) == {
        "fresh-aware-string": "2026-06-05T07:45:38+00:00",
        "fresh-dict-mixed": {
            "first_seen": "2026-05-01T07:45:38",
            "last_seen": "2026-06-05T07:45:38+00:00",
        },
    }


def test_recent_bridge_filtering_comparison_accepts_naive_and_aware_history_entries() -> None:
    cutoff = datetime(2026, 6, 5, 7, 45, 37, tzinfo=UTC)
    history = {
        "legacy-naive": "2026-06-05T07:45:38",
        "legacy-aware": "2026-06-05T07:45:38+00:00",
        "dict-naive": {"first_seen": "2026-06-05T07:45:38"},
        "dict-aware": {"first_seen": "2026-06-05T07:45:38+00:00"},
    }

    recent: list[str] = []
    for bridge, entry in history.items():
        if isinstance(entry, str):
            ts_value = entry
        elif isinstance(entry, dict):
            ts_value = entry.get("first_seen")
        else:
            ts_value = None
        parsed = history_utils.parse_history_dt(ts_value)
        assert parsed.tzinfo is not None
        assert parsed > cutoff
        if parsed > cutoff:
            recent.append(bridge)

    assert recent == ["legacy-naive", "legacy-aware", "dict-naive", "dict-aware"]


def test_shared_history_timestamp_migration_normalizes_without_dropping_fields() -> None:
    history = _sample_history()

    assert history_utils.normalize_history_timestamps(history) is history

    _assert_normalized(history)


def test_direct_history_timestamp_migration_normalizes_without_dropping_fields() -> None:
    history = _sample_history()

    assert direct_scraper.normalize_history_timestamps(history) is history

    _assert_normalized(history)


def test_legacy_history_timestamp_migration_normalizes_without_dropping_fields() -> None:
    history = _sample_history()

    assert legacy_scraper.normalize_history_timestamps(history) is history

    _assert_normalized(history)


def test_direct_and_legacy_cleanup_use_same_last_seen_behavior(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "stale": "2026-05-01T00:00:00",
        "fresh": "2026-06-23T00:00:00",
        "old-first-new-last": {
            "raw": "obfs4 203.0.113.2:443 cert=def iat-mode=2",
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00+00:00",
            "tcp_reachable": False,
            "capabilities": {"transport_options": {"iat-mode": "0"}},
        },
    }

    direct_cleaned = direct_scraper.cleanup_history(history.copy(), 30)
    legacy_cleaned = legacy_scraper.cleanup_history(history.copy(), 30)

    assert direct_cleaned == legacy_cleaned
    assert "stale" not in direct_cleaned
    assert "fresh" in direct_cleaned
    assert "old-first-new-last" in direct_cleaned
    entry = direct_cleaned["old-first-new-last"]
    assert isinstance(entry, dict)
    assert entry["raw"] == "obfs4 203.0.113.2:443 cert=def iat-mode=2"
    assert entry["transport"] == "obfs4"
    assert entry["ip_version"] == "ipv4"
    assert entry["first_seen"] == "2026-05-01T00:00:00+00:00"
    assert entry["last_seen"] == "2026-06-23T00:00:00+00:00"
    assert entry["tcp_reachable"] is False
    assert entry["capabilities"] == {"transport_options": {"iat-mode": "0"}}


def test_cleanup_retains_dict_entry_when_last_seen_is_within_retention(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "kept-by-last-seen": {
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00+00:00",
        },
    }

    assert history_utils.cleanup_history(history, 30) == {
        "kept-by-last-seen": {
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00+00:00",
        },
    }


def test_cleanup_can_prefer_first_seen_when_requested(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "old-first-new-last": {
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00+00:00",
        },
    }

    assert history_utils.cleanup_history(history, 30, prefer_last_seen=False) == {}

def test_onionhop_parse_iso_safe_normalizes_naive_history_timestamp_to_utc() -> None:
    parsed = onionhop_collector._parse_iso_safe("2026-06-05T07:45:38")

    assert parsed == datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC)
    assert parsed.tzinfo is UTC


def test_onionhop_parse_iso_safe_converts_aware_history_timestamp_to_utc() -> None:
    parsed = onionhop_collector._parse_iso_safe("2026-06-05T08:45:38+03:30")

    assert parsed == datetime(2026, 6, 5, 5, 15, 38, tzinfo=UTC)
    assert parsed.tzinfo is UTC


def test_onionhop_entry_last_seen_returns_aware_utc_for_legacy_values() -> None:
    values = [
        "2026-06-05T07:45:38",
        {"last_seen": "2026-06-05T08:45:38+03:30"},
    ]

    parsed = [onionhop_collector._entry_last_seen(value) for value in values]

    assert parsed == [
        datetime(2026, 6, 5, 7, 45, 38, tzinfo=UTC),
        datetime(2026, 6, 5, 5, 15, 38, tzinfo=UTC),
    ]
    assert all(value is not None and value.tzinfo is UTC for value in parsed)
    assert onionhop_collector._entry_last_seen({"last_seen": "not-a-date"}) is None


def test_onionhop_cleanup_history_and_recent_filter_accept_legacy_naive_values(monkeypatch) -> None:
    fixed_now = datetime(2026, 6, 24, 12, 0, tzinfo=UTC)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            if tz is None:
                return fixed_now.replace(tzinfo=None)
            return fixed_now.astimezone(tz)

    monkeypatch.setattr(onionhop_collector, "datetime", FixedDateTime)
    monkeypatch.setattr(onionhop_collector, "HISTORY_RETENTION_DAYS", 30)
    monkeypatch.setattr(onionhop_collector, "RECENT_HOURS", 72)

    history = {
        "stale-naive": "2026-05-01T00:00:00",
        "recent-naive": "2026-06-23T00:00:00",
        "recent-aware-offset": {"last_seen": "2026-06-23T03:30:00+03:30"},
    }

    cleaned = onionhop_collector._cleanup_history(history)
    recent_cutoff = fixed_now - timedelta(hours=onionhop_collector.RECENT_HOURS)
    recent = [
        bridge
        for bridge, entry in cleaned.items()
        if (ts := onionhop_collector._entry_last_seen(entry)) and ts > recent_cutoff
    ]

    assert cleaned == {
        "recent-naive": "2026-06-23T00:00:00",
        "recent-aware-offset": {"last_seen": "2026-06-23T03:30:00+03:30"},
    }
    assert recent == ["recent-naive", "recent-aware-offset"]


def test_direct_cleanup_comparison_handles_mixed_naive_and_aware_values(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "old-naive-string": "2026-05-01T00:00:00",
        "fresh-aware-string": "2026-06-23T00:00:00+00:00",
        "fresh-dict-naive-last": {
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00",
        },
        "old-dict-aware-last": {
            "first_seen": "2026-06-23T00:00:00",
            "last_seen": "2026-05-01T00:00:00+00:00",
        },
    }

    cleaned = direct_scraper.cleanup_history(history, 30)

    assert list(cleaned) == ["fresh-aware-string", "fresh-dict-naive-last"]


def test_legacy_cleanup_comparison_handles_mixed_naive_and_aware_values(monkeypatch) -> None:
    monkeypatch.setattr(history_utils, "utc_now", lambda: datetime(2026, 6, 24, tzinfo=UTC))
    history = {
        "old-naive-string": "2026-05-01T00:00:00",
        "fresh-aware-string": "2026-06-23T00:00:00+00:00",
        "fresh-dict-naive-last": {
            "first_seen": "2026-05-01T00:00:00+00:00",
            "last_seen": "2026-06-23T00:00:00",
        },
        "old-dict-aware-last": {
            "first_seen": "2026-06-23T00:00:00",
            "last_seen": "2026-05-01T00:00:00+00:00",
        },
    }

    cleaned = legacy_scraper.cleanup_history(history, 30)

    assert list(cleaned) == ["fresh-aware-string", "fresh-dict-naive-last"]


def test_direct_recent_filter_first_seen_comparison_handles_mixed_values() -> None:
    cutoff = datetime(2026, 6, 20, tzinfo=UTC)
    entries = {
        "legacy-naive": "2026-06-23T00:00:00",
        "legacy-aware": "2026-06-23T03:30:00+03:30",
        "dict-naive": {"first_seen": "2026-06-23T00:00:00"},
        "dict-aware": {"first_seen": "2026-06-23T03:30:00+03:30"},
        "old": {"first_seen": "2026-05-01T00:00:00"},
    }

    recent = [
        bridge
        for bridge, entry in entries.items()
        if direct_scraper._history_first_seen_dt(entry) > cutoff
    ]

    assert recent == ["legacy-naive", "legacy-aware", "dict-naive", "dict-aware"]


def test_legacy_recent_filter_first_seen_comparison_handles_mixed_values() -> None:
    cutoff = datetime(2026, 6, 20, tzinfo=UTC)
    entries = {
        "legacy-naive": "2026-06-23T00:00:00",
        "legacy-aware": "2026-06-23T03:30:00+03:30",
        "dict-naive": {"first_seen": "2026-06-23T00:00:00"},
        "dict-aware": {"first_seen": "2026-06-23T03:30:00+03:30"},
        "old": {"first_seen": "2026-05-01T00:00:00"},
    }

    recent = [
        bridge
        for bridge, entry in entries.items()
        if legacy_scraper._history_first_seen_dt(entry) > cutoff
    ]

    assert recent == ["legacy-naive", "legacy-aware", "dict-naive", "dict-aware"]
