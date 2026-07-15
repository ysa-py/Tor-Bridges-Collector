from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = timezone.utc

from sources.bridge_scoring import recommended_priority, score_bridge

NOW = datetime(2026, 6, 25, tzinfo=UTC)
HIGH_DPI = {"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}}


def test_reachable_low_latency_webtunnel_ranks_above_stale_failed_obfs4():
    webtunnel = {
        "raw": "webtunnel 198.51.100.10:443 url=https://cdn.fastly.net/bridge",
        "transport": "webtunnel",
        "port": 443,
        "test_pass": True,
        "latency_ms": 120,
        "last_seen": (NOW - timedelta(hours=2)).isoformat(),
        "RIPEReachable": True,
        "RIPETested": True,
        "pt_status": "ok",
    }
    obfs4 = {
        "raw": "obfs4 198.51.100.11:9001 FINGERPRINT cert=x iat-mode=2",
        "transport": "obfs4",
        "port": 9001,
        "test_pass": False,
        "latency_ms": 1400,
        "last_seen": (NOW - timedelta(days=30)).isoformat(),
        "RIPEReachable": False,
        "RIPETested": True,
        "pt_status": "failed",
    }

    web_score, _ = score_bridge(webtunnel, HIGH_DPI, NOW)
    obfs_score, reasons = score_bridge(obfs4, HIGH_DPI, NOW)

    assert web_score > obfs_score
    assert any("penalized but retained" in reason for reason in reasons)


def test_invalid_missing_telemetry_does_not_crash_scoring():
    score, reasons = score_bridge({"transport": "snowflake", "last_seen": NOW.isoformat()}, telemetry="bad", now_utc=NOW)

    assert isinstance(score, float)
    assert recommended_priority(score) in {"high", "medium", "low"}
    assert "telemetry unavailable or invalid" in reasons


def test_snowflake_receives_resilience_credit_under_high_dpi_state():
    snowflake = {"transport": "snowflake", "last_seen": NOW.isoformat(), "test_pass": True}
    calm_score, calm_reasons = score_bridge(snowflake, {"counters": {}}, NOW)
    high_score, high_reasons = score_bridge(snowflake, HIGH_DPI, NOW)

    assert high_score > calm_score
    assert any("snowflake resilience credit" in reason for reason in high_reasons)
    assert not any("snowflake resilience credit" in reason for reason in calm_reasons)


def test_recently_failed_bridges_are_penalized_but_not_deleted():
    failed = {
        "raw": "obfs4 203.0.113.10:443 FINGERPRINT cert=x iat-mode=2",
        "transport": "obfs4",
        "test_pass": False,
        "last_seen": (NOW - timedelta(hours=1)).isoformat(),
    }

    score, reasons = score_bridge(failed, HIGH_DPI, NOW)

    assert score > 0
    assert any("recent probe failed; penalized but retained" == reason for reason in reasons)


def test_missing_port_falls_back_to_raw_line_without_failure_log(capsys):
    bridge = {
        "raw": "snowflake 198.51.100.20:443 fingerprint=x",
        "transport": "snowflake",
        "port": None,
        "last_seen": NOW.isoformat(),
    }

    score, reasons = score_bridge(bridge, {"counters": {}}, NOW)
    captured = capsys.readouterr()

    assert score >= 80
    assert "Iran-preferred port (443)" in reasons
    assert "int() argument" not in captured.err
