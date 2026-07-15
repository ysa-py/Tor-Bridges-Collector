from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.iran_bridge_prioritizer import prioritize_bridges, score_bridge
UTC = timezone.utc

NOW = datetime(2026, 6, 24, tzinfo=UTC)


def _set_enabled(monkeypatch, enabled=True):
    monkeypatch.setattr("config.IRAN_BRIDGE_PRIORITIZATION_ENABLED", enabled)
    monkeypatch.setattr("config.IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", 1.0)
    monkeypatch.setattr("config.IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT", 1.0)
    monkeypatch.setattr("config.IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", 1.0)
    monkeypatch.setattr("config.IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY", 1.0)
    monkeypatch.setattr("config.UTLS_EVASION_MODE", False)
    monkeypatch.setattr("config.NIN_MODE", False)
    monkeypatch.setattr("config.RIPE_ATLAS_API_KEY", "")


def test_prioritization_preserves_all_input_bridge_entries(monkeypatch):
    _set_enabled(monkeypatch, True)
    bridges = [
        {"id": "a", "transport": "obfs4", "port": 9001},
        {"id": "b", "transport": "obfs4", "port": 443},
        {"id": "c", "transport": "snowflake", "port": 80},
    ]

    ranked = prioritize_bridges(bridges, now=NOW)

    assert len(ranked) == len(bridges)
    assert sorted(item["id"] for item in ranked) == ["a", "b", "c"]


def test_no_fields_are_removed(monkeypatch):
    _set_enabled(monkeypatch, True)
    bridge = {
        "id": "keep-me",
        "transport": "obfs4",
        "port": 443,
        "custom": {"nested": True},
    }

    ranked = prioritize_bridges([bridge], now=NOW)

    assert bridge.items() <= ranked[0].items()
    assert ranked[0]["custom"] == {"nested": True}


def test_preferred_ports_score_higher(monkeypatch):
    _set_enabled(monkeypatch, True)
    preferred = {"transport": "obfs4", "port": 443}
    non_preferred = {"transport": "obfs4", "port": 9001}

    assert score_bridge(preferred, now=NOW)["iran_prioritization"]["score"] > score_bridge(
        non_preferred, now=NOW
    )["iran_prioritization"]["score"]


def test_recent_last_seen_scores_higher(monkeypatch):
    _set_enabled(monkeypatch, True)
    recent = {"transport": "obfs4", "port": 443, "last_seen": (NOW - timedelta(hours=2)).isoformat()}
    old = {"transport": "obfs4", "port": 443, "last_seen": (NOW - timedelta(days=45)).isoformat()}

    assert score_bridge(recent, now=NOW)["iran_prioritization"]["score"] > score_bridge(
        old, now=NOW
    )["iran_prioritization"]["score"]


def test_feature_flag_disabled_keeps_original_ordering(monkeypatch):
    _set_enabled(monkeypatch, False)
    bridges = [
        {"id": "first", "transport": "vanilla", "port": 9001},
        {"id": "second", "transport": "snowflake", "port": 443},
    ]

    ranked = prioritize_bridges(bridges, now=NOW)

    assert [item["id"] for item in ranked] == ["first", "second"]
    assert all("iran_prioritization" not in item for item in ranked)
