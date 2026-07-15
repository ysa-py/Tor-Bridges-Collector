from datetime import datetime, timedelta, timezone

from telemetry_watcher import DPIEvent, SelfHealEvent, SlotEvent, TelemetryWatcher
UTC = timezone.utc


def test_24h_summary_accepts_naive_and_aware_event_timestamps():
    watcher = TelemetryWatcher()
    watcher._dpi_events.clear()
    watcher._slot_events.clear()
    watcher._self_heal_events.clear()
    watcher._save_daily_report = lambda aggregation: None

    now = datetime.now(UTC)
    naive_recent = (now - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    aware_recent = (now - timedelta(hours=2)).astimezone(timezone(timedelta(hours=3))).isoformat()

    watcher._dpi_events.extend([
        DPIEvent(timestamp=naive_recent, dpi_system="sni_inspector", action="blocked"),
        DPIEvent(timestamp=aware_recent, dpi_system="ja3_fingerprinter", action="evaded"),
    ])
    watcher._slot_events.extend([
        SlotEvent(timestamp=naive_recent, slot_index=1, env_var="CF_API_TOKEN_1", error_type="HTTP 403"),
        SlotEvent(timestamp=aware_recent, slot_index=2, env_var="CF_API_TOKEN_2", error_type="Timeout", recovered=True),
    ])
    watcher._self_heal_events.extend([
        SelfHealEvent(timestamp=naive_recent, action_type="reset_circuit"),
        SelfHealEvent(timestamp=aware_recent, action_type="auto_switch_provider"),
    ])

    summary = watcher.get_24h_summary()

    assert summary.total_dpi_events == 2
    assert summary.total_slot_failures == 2
    assert summary.total_self_heal_events == 2


def test_parse_ts_normalizes_to_utc_for_naive_and_aware_timestamps():
    naive = TelemetryWatcher._parse_ts("2026-06-24T12:00:00")
    aware = TelemetryWatcher._parse_ts("2026-06-24T15:30:00+03:30")

    assert naive == datetime(2026, 6, 24, 12, 0, tzinfo=UTC)
    assert aware == datetime(2026, 6, 24, 12, 0, tzinfo=UTC)


def test_24h_summary_excludes_invalid_timestamps_from_recent_events(monkeypatch):
    recorded_failures = []

    def fake_record_silent_failure(site, exc, **context):
        recorded_failures.append((site, exc, context))

    monkeypatch.setattr(
        "monitoring.structured_logger.record_silent_failure",
        fake_record_silent_failure,
    )

    watcher = TelemetryWatcher()
    watcher._dpi_events.clear()
    watcher._slot_events.clear()
    watcher._self_heal_events.clear()
    watcher._save_daily_report = lambda aggregation: None

    now = datetime.now(UTC)
    invalid_timestamp = "not-a-timestamp"
    empty_timestamp = ""
    naive_recent = (now - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    aware_recent = (now - timedelta(hours=2)).astimezone(timezone(timedelta(hours=3))).isoformat()

    watcher._dpi_events.extend([
        DPIEvent(timestamp=invalid_timestamp, dpi_system="sni_inspector", action="blocked"),
        DPIEvent(timestamp=empty_timestamp, dpi_system="ja3_fingerprinter", action="blocked"),
        DPIEvent(timestamp=naive_recent, dpi_system="packet_timing", action="evaded"),
        DPIEvent(timestamp=aware_recent, dpi_system="http2_fingerprint", action="camouflaged"),
    ])
    watcher._slot_events.extend([
        SlotEvent(timestamp=invalid_timestamp, slot_index=1, env_var="CF_API_TOKEN_1", error_type="HTTP 403"),
        SlotEvent(timestamp=empty_timestamp, slot_index=2, env_var="CF_API_TOKEN_2", error_type="Timeout"),
        SlotEvent(timestamp=naive_recent, slot_index=3, env_var="CF_API_TOKEN_3", error_type="HTTP 429"),
        SlotEvent(timestamp=aware_recent, slot_index=4, env_var="CF_API_TOKEN_4", error_type="Timeout", recovered=True),
    ])
    watcher._self_heal_events.extend([
        SelfHealEvent(timestamp=invalid_timestamp, action_type="reset_circuit"),
        SelfHealEvent(timestamp=empty_timestamp, action_type="switch_model"),
        SelfHealEvent(timestamp=naive_recent, action_type="auto_switch_provider"),
        SelfHealEvent(timestamp=aware_recent, action_type="health_check_recovery"),
    ])

    summary = watcher.get_24h_summary()

    assert summary.total_dpi_events == 2
    assert summary.dpi_events_blocked == 0
    assert summary.dpi_events_evaded == 2
    assert summary.total_slot_failures == 2
    assert summary.slots_poisoned == [3]
    assert summary.slots_recovered == [4]
    assert summary.total_self_heal_events == 2
    assert summary.self_heal_by_type == {
        "auto_switch_provider": 1,
        "health_check_recovery": 1,
    }
    assert [context["timestamp"] for _, _, context in recorded_failures] == [
        invalid_timestamp,
        empty_timestamp,
        invalid_timestamp,
        empty_timestamp,
        invalid_timestamp,
        empty_timestamp,
    ]


def test_parse_ts_invalid_timestamp_records_failure_and_returns_old_fallback(monkeypatch):
    recorded_failures = []

    def fake_record_silent_failure(site, exc, **context):
        recorded_failures.append((site, exc, context))

    monkeypatch.setattr(
        "monitoring.structured_logger.record_silent_failure",
        fake_record_silent_failure,
    )

    parsed = TelemetryWatcher._parse_ts("not-a-timestamp")

    assert parsed == datetime.min.replace(tzinfo=UTC)
    assert len(recorded_failures) == 1
    assert recorded_failures[0][0] == "telemetry_watcher._parse_ts"
    assert recorded_failures[0][2] == {"timestamp": "not-a-timestamp"}
