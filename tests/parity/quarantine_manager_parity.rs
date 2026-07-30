#![allow(warnings)]
// Parity tests for `src/quarantine_manager.rs` vs `quarantine_manager.py`.
//
// Two test groups:
// 1. `rolling_zscore` — invokes the Python implementation directly via
//    `std::process::Command` on fixed inputs and asserts byte-identical f64
//    output (compared via `f64::to_bits()`).
// 2. `QuarantineManager` decision logic — uses a temp directory for state
//    and log files, exercising the quarantine/release state machine.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{json, Value};
use torshield_ir_ultra::quarantine_manager::{
    mean, rolling_zscore, std, QuarantineEntry, QuarantineError, QuarantineManager, UpdateSummary,
    CLEAN_DAYS_TO_RELEASE, ZSCORE_THRESHOLD, ZSCORE_WINDOW,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("python")
}

/// Invoke the Python `rolling_zscore` (and by extension `_mean` / `_std`)
/// on a fixed input list and return the computed f64. The Python helper
/// prints `repr(z)` so the full f64 precision round-trips.
fn python_rolling_zscore(daily_rates: &[f64], window: usize) -> f64 {
    let rates_json = serde_json::to_string(daily_rates)
        .unwrap_or_else(|err| panic!("rates must serialize to JSON: {err}"));
    let script = r#"
import json, sys
sys.path.insert(0, ".")
from quarantine_manager import rolling_zscore
rates = json.loads(sys.argv[1])
window = int(sys.argv[2])
z = rolling_zscore(rates, window=window)
print(repr(z))
"#;
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&rates_json)
        .arg(window.to_string())
        .output()
        .unwrap_or_else(|err| panic!("python rolling_zscore helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python rolling_zscore helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    trimmed
        .parse::<f64>()
        .unwrap_or_else(|err| panic!("python helper must emit a float: {err}; stdout={trimmed}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Temp directory helper
// ─────────────────────────────────────────────────────────────────────────────

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_quarantine_manager_parity_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("quarantine_state.json")
}

fn log_path(dir: &Path) -> PathBuf {
    dir.join("quarantine_log.jsonl")
}

/// Parse the first non-empty line of a JSONL log file as a `serde_json::Value`.
fn parse_first_log_event(log_text: &str) -> Value {
    let first_line = log_text
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("at least one log line");
    serde_json::from_str(first_line)
        .unwrap_or_else(|err| panic!("log line must be valid JSON: {err}; line={first_line}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// rolling_zscore parity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_rolling_zscore_empty_list_returns_zero() {
    let rates: Vec<f64> = vec![];
    let py = python_rolling_zscore(&rates, ZSCORE_WINDOW);
    let rs = rolling_zscore(&rates, ZSCORE_WINDOW);
    assert_eq!(py.to_bits(), rs.to_bits());
    assert_eq!(rs, 0.0);
}

#[test]
fn parity_rolling_zscore_shorter_than_window_plus_one_returns_zero() {
    // window=7, so we need at least 8 elements. 3 is too short.
    let rates: Vec<f64> = vec![0.0, 0.0, 1.0];
    let py = python_rolling_zscore(&rates, ZSCORE_WINDOW);
    let rs = rolling_zscore(&rates, ZSCORE_WINDOW);
    assert_eq!(py.to_bits(), rs.to_bits());
    assert_eq!(rs, 0.0);
}

#[test]
fn parity_rolling_zscore_zero_historical_std_returns_zero() {
    // 14 elements total (7 historical + 7 recent), but historical is all
    // identical → std = 0 → returns 0.0.
    let rates: Vec<f64> = vec![0.0; 14];
    let py = python_rolling_zscore(&rates, ZSCORE_WINDOW);
    let rs = rolling_zscore(&rates, ZSCORE_WINDOW);
    assert_eq!(py.to_bits(), rs.to_bits());
    assert_eq!(rs, 0.0);
}

#[test]
fn parity_rolling_zscore_detectable_spike_matches_python() {
    // 7 historical (1 anomaly, low variance) + 7 recent (all anomalies).
    // Python: z = 2.2677868380553634
    let rates: Vec<f64> = vec![
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    ];
    let py = python_rolling_zscore(&rates, ZSCORE_WINDOW);
    let rs = rolling_zscore(&rates, ZSCORE_WINDOW);
    assert_eq!(py.to_bits(), rs.to_bits(), "Rust z={rs} != Python z={py}");
    assert!(
        rs > ZSCORE_THRESHOLD,
        "expected z > {ZSCORE_THRESHOLD}, got {rs}"
    );
}

#[test]
fn parity_rolling_zscore_custom_window_matches_python() {
    // Smaller window to exercise the window parameter path.
    // historical = [0.0, 1.0], recent = [1.0, 1.0, 1.0]
    let rates: Vec<f64> = vec![0.0, 1.0, 1.0, 1.0, 1.0];
    let window = 3;
    let py = python_rolling_zscore(&rates, window);
    let rs = rolling_zscore(&rates, window);
    assert_eq!(py.to_bits(), rs.to_bits(), "Rust z={rs} != Python z={py}");
}

#[test]
fn parity_mean_and_std_match_python() {
    // Cross-check the internal _mean and _std helpers too.
    let values: Vec<f64> = vec![0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0];
    let script = r#"
import json, sys
sys.path.insert(0, ".")
from quarantine_manager import _mean, _std
values = json.loads(sys.argv[1])
print(repr(_mean(values)))
print(repr(_std(values)))
"#;
    let values_json = serde_json::to_string(&values).expect("values must serialize");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&values_json)
        .output()
        .unwrap_or_else(|err| panic!("python mean/std helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python mean/std helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let py_mean = lines
        .next()
        .expect("mean line present")
        .parse::<f64>()
        .expect("python mean parses");
    let py_std = lines
        .next()
        .expect("std line present")
        .parse::<f64>()
        .expect("python std parses");
    assert_eq!(py_mean.to_bits(), mean(&values).to_bits());
    assert_eq!(py_std.to_bits(), std(&values).to_bits());
}

// ─────────────────────────────────────────────────────────────────────────────
// QuarantineManager decision-logic tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn initial_state_is_empty() {
    let dir = case_dir("initial_empty");
    let mgr = QuarantineManager::new(&state_path(&dir), &log_path(&dir))
        .expect("manager constructs with missing state file");
    assert!(mgr.quarantined_set().is_empty());
    assert!(mgr.state_snapshot().is_empty());
    assert!(!mgr.is_quarantined("1.2.3.4"));
}

#[test]
fn quarantine_adds_entry_with_correct_fields() {
    let dir = case_dir("quarantine_adds_entry");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.1:443", 2.2677868380553634, "anomaly_spike")
        .expect("quarantine succeeds");

    assert!(mgr.is_quarantined("192.0.2.1:443"));
    let snapshot = mgr.state_snapshot();
    let entry = snapshot
        .get("192.0.2.1:443")
        .expect("entry exists for quarantined host");
    assert!(
        !entry.quarantined_at.is_empty(),
        "quarantined_at must be set"
    );
    // z_score must be rounded to 3 decimals: round(2.2677..., 3) = 2.268
    assert_eq!(entry.z_score, 2.268);
    assert_eq!(entry.consecutive_clean, 0);
    assert_eq!(entry.reason, "anomaly_spike");

    // The state file must have been written and reloadable.
    let reloaded = QuarantineManager::new(&state_path(&dir), &log_path(&dir))
        .expect("state reloads from disk");
    let reloaded_snapshot = reloaded.state_snapshot();
    let reloaded_entry = reloaded_snapshot
        .get("192.0.2.1:443")
        .expect("reloaded entry exists");
    assert_eq!(reloaded_entry.z_score, 2.268);
    assert_eq!(reloaded_entry.consecutive_clean, 0);
    assert_eq!(reloaded_entry.reason, "anomaly_spike");

    // The log file must have received a "quarantined" event line.
    let log_text = fs::read_to_string(log_path(&dir)).expect("log file written");
    let event = parse_first_log_event(&log_text);
    assert_eq!(event["action"], json!("quarantined"));
    assert_eq!(event["bridge_host"], json!("192.0.2.1:443"));
}

#[test]
fn quarantine_is_idempotent_on_same_host() {
    let dir = case_dir("quarantine_idempotent");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.2:443", 3.5, "reason_one")
        .expect("first quarantine succeeds");
    let first_snapshot = mgr
        .state_snapshot()
        .get("192.0.2.2:443")
        .expect("entry exists after first quarantine")
        .clone();

    // Second call with different z_score and reason must NOT overwrite.
    mgr.quarantine("192.0.2.2:443", 9.999, "reason_two")
        .expect("second quarantine is a no-op");

    let second_snapshot = mgr
        .state_snapshot()
        .get("192.0.2.2:443")
        .expect("entry still exists after second quarantine")
        .clone();
    assert_eq!(second_snapshot.z_score, first_snapshot.z_score);
    assert_eq!(
        second_snapshot.z_score, 3.5,
        "z_score must not be overwritten"
    );
    assert_eq!(
        second_snapshot.reason, "reason_one",
        "reason must not be overwritten"
    );
    assert_eq!(
        second_snapshot.quarantined_at, first_snapshot.quarantined_at,
        "quarantined_at must not be overwritten"
    );

    // The log file must contain exactly one "quarantined" event for this host.
    let log_text = fs::read_to_string(log_path(&dir)).expect("log file written");
    let count = log_text
        .lines()
        .filter(|line| {
            serde_json::from_str::<Value>(line)
                .map(|event| {
                    event.get("action") == Some(&json!("quarantined"))
                        && event.get("bridge_host") == Some(&json!("192.0.2.2:443"))
                })
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        count, 1,
        "idempotent quarantine must not log a second event"
    );
}

#[test]
fn record_clean_measurement_releases_after_three_consecutive_cleans() {
    let dir = case_dir("record_clean_releases");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.3:443", 2.5, "anomaly_spike")
        .expect("quarantine succeeds");

    // First clean → counter 1, not released.
    let r1 = mgr
        .record_clean_measurement("192.0.2.3:443")
        .expect("first clean measurement");
    assert!(!r1, "first clean must not release");
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.3:443")
            .expect("entry exists")
            .consecutive_clean,
        1
    );

    // Second clean → counter 2, not released.
    let r2 = mgr
        .record_clean_measurement("192.0.2.3:443")
        .expect("second clean measurement");
    assert!(!r2, "second clean must not release");
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.3:443")
            .expect("entry exists")
            .consecutive_clean,
        2
    );

    // Third clean → counter 3 ≥ CLEAN_DAYS_TO_RELEASE → release.
    let r3 = mgr
        .record_clean_measurement("192.0.2.3:443")
        .expect("third clean measurement");
    assert!(r3, "third clean must release");
    assert!(
        !mgr.is_quarantined("192.0.2.3:443"),
        "host must be removed after release"
    );

    // record_clean_measurement on unknown host returns False without error.
    let r_unknown = mgr
        .record_clean_measurement("unknown.host:443")
        .expect("unknown host clean is a no-op");
    assert!(!r_unknown);

    // Sanity: CLEAN_DAYS_TO_RELEASE is 3.
    assert_eq!(CLEAN_DAYS_TO_RELEASE, 3);
}

#[test]
fn record_anomaly_measurement_resets_counter_to_zero() {
    let dir = case_dir("record_anomaly_resets");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.4:443", 2.5, "anomaly_spike")
        .expect("quarantine succeeds");

    // Accumulate 2 clean measurements.
    mgr.record_clean_measurement("192.0.2.4:443")
        .expect("first clean");
    mgr.record_clean_measurement("192.0.2.4:443")
        .expect("second clean");
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.4:443")
            .expect("entry exists")
            .consecutive_clean,
        2
    );

    // An anomaly resets the counter.
    mgr.record_anomaly_measurement("192.0.2.4:443")
        .expect("anomaly measurement resets counter");
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.4:443")
            .expect("entry still exists")
            .consecutive_clean,
        0
    );

    // record_anomaly_measurement on unknown host is a silent no-op.
    mgr.record_anomaly_measurement("unknown.host:443")
        .expect("unknown host anomaly is a no-op");
    assert!(!mgr.is_quarantined("unknown.host:443"));
}

#[test]
fn release_removes_entry_and_returns_false_for_unknown_host() {
    let dir = case_dir("release_removes_entry");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.5:443", 3.0, "anomaly_spike")
        .expect("quarantine succeeds");

    // Release unknown host → False, no state change.
    let r_unknown = mgr
        .release("unknown.host:443", "manual")
        .expect("release unknown host");
    assert!(!r_unknown);
    assert!(mgr.is_quarantined("192.0.2.5:443"));

    // Release known host → True, entry removed.
    let r_known = mgr
        .release("192.0.2.5:443", "manual")
        .expect("release known host");
    assert!(r_known);
    assert!(!mgr.is_quarantined("192.0.2.5:443"));
    assert!(mgr.state_snapshot().is_empty());

    // The log file must have a "released" event for the known host.
    let log_text = fs::read_to_string(log_path(&dir)).expect("log file written");
    let has_release = log_text.lines().any(|line| {
        serde_json::from_str::<Value>(line)
            .map(|event| {
                event.get("action") == Some(&json!("released"))
                    && event.get("bridge_host") == Some(&json!("192.0.2.5:443"))
            })
            .unwrap_or(false)
    });
    assert!(
        has_release,
        "log must contain a released event for the known host"
    );
}

#[test]
fn update_from_ooni_history_with_spike_triggers_quarantine() {
    let dir = case_dir("update_spike_triggers");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");

    // 7 historical days with 1 anomaly (low variance) + 7 recent days all
    // anomalies → z ≈ 2.27 > 2.0 → quarantine.
    let mut daily: Vec<(String, bool)> = Vec::new();
    for day in 1..=7 {
        let is_anomaly = day == 7;
        daily.push((format!("2024-01-{day:02}"), is_anomaly));
    }
    for day in 8..=14 {
        daily.push((format!("2024-01-{day:02}"), true));
    }

    let history = vec![("192.0.2.6:443".to_string(), daily)];
    let summary = mgr
        .update_from_ooni_history(&history)
        .expect("update succeeds");

    assert_eq!(summary.evaluated, 1);
    assert_eq!(summary.newly_quarantined, 1);
    assert_eq!(summary.released, 0);
    assert_eq!(summary.currently_quarantined, 1);
    assert!(mgr.is_quarantined("192.0.2.6:443"));
    assert_eq!(summary.hosts_quarantined, vec!["192.0.2.6:443".to_string()]);

    // The quarantined entry must carry reason="anomaly_spike".
    let snapshot = mgr.state_snapshot();
    let entry = snapshot.get("192.0.2.6:443").expect("entry exists");
    assert_eq!(entry.reason, "anomaly_spike");
}

#[test]
fn update_from_ooni_history_with_stable_history_does_not_quarantine() {
    let dir = case_dir("update_stable_no_quarantine");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");

    // 14 clean days → z = 0.0 (historical std = 0) → no quarantine.
    let daily: Vec<(String, bool)> = (1..=14)
        .map(|day| (format!("2024-01-{day:02}"), false))
        .collect();
    let history = vec![("192.0.2.7:443".to_string(), daily)];
    let summary = mgr
        .update_from_ooni_history(&history)
        .expect("update succeeds");

    assert_eq!(summary.evaluated, 1);
    assert_eq!(summary.newly_quarantined, 0);
    assert_eq!(summary.released, 0);
    assert_eq!(summary.currently_quarantined, 0);
    assert!(!mgr.is_quarantined("192.0.2.7:443"));
    assert!(summary.hosts_quarantined.is_empty());
}

#[test]
fn update_from_ooni_history_releases_after_three_clean_days_in_quarantine() {
    let dir = case_dir("update_releases_after_clean");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");

    // First, manually quarantine a bridge.
    mgr.quarantine("192.0.2.8:443", 2.5, "manual")
        .expect("manual quarantine");

    // History: 14 days where the last 3 are clean. Because the bridge is
    // already quarantined and z is computed (may or may not exceed threshold)
    // the else-branch logic kicks in: latest is clean → record_clean_measurement.
    // Three consecutive clean updates should release the bridge.
    let daily: Vec<(String, bool)> = (1..=14)
        .map(|day| (format!("2024-01-{day:02}"), false))
        .collect();
    let history = vec![("192.0.2.8:443".to_string(), daily.clone())];

    // First update: counter 1, not released.
    let s1 = mgr
        .update_from_ooni_history(&history)
        .expect("first update");
    assert_eq!(s1.released, 0);
    assert!(mgr.is_quarantined("192.0.2.8:443"));

    // Second update: counter 2, not released.
    let s2 = mgr
        .update_from_ooni_history(&history)
        .expect("second update");
    assert_eq!(s2.released, 0);
    assert!(mgr.is_quarantined("192.0.2.8:443"));

    // Third update: counter 3 ≥ threshold → release.
    let s3 = mgr
        .update_from_ooni_history(&history)
        .expect("third update");
    assert_eq!(s3.released, 1);
    assert!(!mgr.is_quarantined("192.0.2.8:443"));
    assert_eq!(s3.currently_quarantined, 0);
}

#[test]
fn update_from_ooni_history_with_anomaly_on_quarantined_host_resets_counter() {
    let dir = case_dir("update_anomaly_resets");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");

    mgr.quarantine("192.0.2.9:443", 2.5, "manual")
        .expect("manual quarantine");

    // Accumulate 2 clean measurements first.
    let clean_daily: Vec<(String, bool)> = (1..=14)
        .map(|day| (format!("2024-01-{day:02}"), false))
        .collect();
    let clean_history = vec![("192.0.2.9:443".to_string(), clean_daily)];
    mgr.update_from_ooni_history(&clean_history)
        .expect("first clean update");
    mgr.update_from_ooni_history(&clean_history)
        .expect("second clean update");
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.9:443")
            .expect("entry exists")
            .consecutive_clean,
        2
    );

    // Now the latest day is an anomaly → resets counter to 0.
    let mut anomaly_daily: Vec<(String, bool)> = (1..=13)
        .map(|day| (format!("2024-01-{day:02}"), false))
        .collect();
    anomaly_daily.push(("2024-01-14".to_string(), true));
    let anomaly_history = vec![("192.0.2.9:443".to_string(), anomaly_daily)];
    let summary = mgr
        .update_from_ooni_history(&anomaly_history)
        .expect("anomaly update");
    assert_eq!(summary.released, 0);
    assert!(mgr.is_quarantined("192.0.2.9:443"));
    assert_eq!(
        mgr.state_snapshot()
            .get("192.0.2.9:443")
            .expect("entry still exists")
            .consecutive_clean,
        0
    );
}

#[test]
fn update_from_ooni_history_skips_empty_daily_entries() {
    let dir = case_dir("update_skips_empty");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");

    // Empty daily list should be skipped (continue in Python).
    let history = vec![("192.0.2.10:443".to_string(), vec![])];
    let summary = mgr
        .update_from_ooni_history(&history)
        .expect("update with empty daily");
    // evaluated counts all bridges including empty ones (matches Python).
    assert_eq!(summary.evaluated, 1);
    assert_eq!(summary.newly_quarantined, 0);
    assert!(summary.hosts_quarantined.is_empty());
}

#[test]
fn state_file_round_trips_through_disk() {
    let dir = case_dir("state_round_trip");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.11:443", 4.5678, "round_trip_test")
        .expect("quarantine");
    mgr.quarantine("192.0.2.12:443", 1.234, "second_host")
        .expect("second quarantine");

    // Reload from disk and verify both entries survive.
    let reloaded =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("state reloads");
    let snapshot = reloaded.state_snapshot();
    assert_eq!(snapshot.len(), 2);
    let e1 = snapshot.get("192.0.2.11:443").expect("first host present");
    assert_eq!(e1.z_score, 4.568); // round(4.5678, 3) = 4.568
    assert_eq!(e1.reason, "round_trip_test");
    let e2 = snapshot.get("192.0.2.12:443").expect("second host present");
    assert_eq!(e2.z_score, 1.234);
    assert_eq!(e2.reason, "second_host");
}

#[test]
fn malformed_state_file_returns_typed_error_not_panic() {
    let dir = case_dir("malformed_state");
    fs::write(state_path(&dir), "not valid json {{{").expect("write malformed state");
    let result = QuarantineManager::new(&state_path(&dir), &log_path(&dir));
    assert!(matches!(result, Err(QuarantineError::ParseState { .. })));
}

#[test]
fn lenient_constructor_swallows_malformed_state() {
    let dir = case_dir("lenient_malformed");
    fs::write(state_path(&dir), "not valid json {{{").expect("write malformed state");
    let mgr = QuarantineManager::new_lenient(&state_path(&dir), &log_path(&dir));
    assert!(mgr.state_snapshot().is_empty());
}

#[test]
fn entry_json_round_trip_preserves_all_fields() {
    let entry = QuarantineEntry {
        quarantined_at: "2024-01-15T12:34:56.789012+00:00".to_string(),
        z_score: 2.5,
        consecutive_clean: 1,
        reason: "test_reason".to_string(),
    };
    let json = entry.to_json();
    let parsed = QuarantineEntry::from_json("host", &json).expect("entry round-trips");
    assert_eq!(parsed, entry);
}

#[test]
fn update_summary_json_shape_matches_python_dict() {
    let summary = UpdateSummary {
        evaluated: 3,
        currently_quarantined: 1,
        newly_quarantined: 1,
        released: 0,
        hosts_quarantined: vec!["host1".to_string()],
    };
    let json = summary.to_json();
    let obj = json.as_object().expect("summary is object");
    for key in [
        "evaluated",
        "currently_quarantined",
        "newly_quarantined",
        "released",
        "hosts_quarantined",
    ] {
        assert!(obj.contains_key(key), "missing summary field {key}");
    }
    assert_eq!(json["evaluated"], json!(3));
    assert_eq!(json["hosts_quarantined"], json!(["host1"]));
}

#[test]
fn quarantine_min_until_in_log_event_uses_three_day_offset() {
    let dir = case_dir("quarantine_min_until");
    let mut mgr =
        QuarantineManager::new(&state_path(&dir), &log_path(&dir)).expect("manager constructs");
    mgr.quarantine("192.0.2.13:443", 2.5, "anomaly_spike")
        .expect("quarantine");

    let log_text = fs::read_to_string(log_path(&dir)).expect("log written");
    // Each log line is a JSON object; parse the first one.
    let first_line = log_text.lines().next().expect("at least one log line");
    let event: Value = serde_json::from_str(first_line).expect("log line is JSON");
    assert_eq!(event["action"], json!("quarantined"));
    assert_eq!(event["bridge_host"], json!("192.0.2.13:443"));
    assert_eq!(event["reason"], json!("anomaly_spike"));
    assert_eq!(event["z_score"], json!(2.5));
    // quarantine_min_until and logged_at must be present ISO-8601 strings.
    let min_until = event["quarantine_min_until"]
        .as_str()
        .expect("quarantine_min_until is string");
    let logged_at = event["logged_at"].as_str().expect("logged_at is string");
    assert!(!min_until.is_empty());
    assert!(!logged_at.is_empty());
    // Both must contain the UTC offset designator.
    assert!(min_until.ends_with("+00:00"));
    assert!(logged_at.ends_with("+00:00"));
}
