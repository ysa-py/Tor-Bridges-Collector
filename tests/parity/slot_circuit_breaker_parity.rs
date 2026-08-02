// Parity tests for `src/slot_circuit_breaker.rs` vs
// `circuit_breaker/slot_circuit_breaker.py`.
//
// Two test groups:
// 1. State-machine logic — uses an injectable clock to exercise the
//    CLOSED → OPEN → HALF_OPEN → CLOSED/OPEN cycle deterministically.
// 2. Python subprocess parity — invokes the Python `SlotCircuitBreaker`
//    directly via `std::process::Command` on fixed scenarios and asserts
//    identical JSON output (state strings, booleans, status dict).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use torshield_ir_ultra::slot_circuit_breaker::{
    default_clock, CircuitState, Clock, EnvMap, SlotCircuitBreaker, SlotCircuitBreakerError,
    DEFAULT_COOLDOWN_SECS, DEFAULT_FAILURE_THRESHOLD, DEFAULT_HALF_OPEN_MAX_PROBES, SLOT_COUNT,
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

/// Invoke the Python `SlotCircuitBreaker` on a fixed scenario and return the
/// parsed JSON output. The Python helper mocks `time.time()` so cooldown
/// behavior is deterministic.
fn python_scenario(scenario: &str) -> Value {
    let script = format!(
        r#"
import os, sys, json, time

# Set credentials before import (slot 1 and 2 are valid; 3-11 are skipped).
os.environ['CF_ACCOUNT_ID_1'] = 'a' * 32
os.environ['CF_API_TOKEN_1'] = 't' * 40
os.environ['CF_ACCOUNT_ID_2'] = 'b' * 32
os.environ['CF_API_TOKEN_2'] = 'u' * 40

# Mock time.time() to control cooldown deterministically.
_mock_time = [1000.0]
time.time = lambda: _mock_time[0]

def advance(t):
    _mock_time[0] = t

from circuit_breaker.slot_circuit_breaker import SlotCircuitBreaker

b = SlotCircuitBreaker()
scenario = {scenario:?}

if scenario == 'fresh':
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'allow': b.allow_request(1),
    }}))
elif scenario == 'below_threshold':
    b.record_failure(1, error_type='HTTP_500')
    b.record_failure(1, error_type='HTTP_500')
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'consecutive_failures': b._slots[1].consecutive_failures,
        'allow': b.allow_request(1),
    }}))
elif scenario == 'at_threshold':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'allow': b.allow_request(1),
    }}))
elif scenario == 'cooldown_half_open':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    advance(1000.0 + 61.0)
    allow = b.allow_request(1)
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'allow': allow,
    }}))
elif scenario == 'half_open_success':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    advance(1000.0 + 61.0)
    b.allow_request(1)
    b.record_success(1, latency_ms=200.0)
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'consecutive_failures': b._slots[1].consecutive_failures,
        'total_successes': b._slots[1].total_successes,
        'allow': b.allow_request(1),
    }}))
elif scenario == 'half_open_failure':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    advance(1000.0 + 61.0)
    b.allow_request(1)
    advance(1000.0 + 62.0)
    b.record_failure(1, error_type='HTTP_500')
    print(json.dumps({{
        'state': b._slots[1].state.value,
        'last_failure_time': b._slots[1].last_failure_time,
        'allow': b.allow_request(1),
    }}))
elif scenario == 'multi_slot':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    print(json.dumps({{
        'slot1_state': b._slots[1].state.value,
        'slot1_allow': b.allow_request(1),
        'slot2_state': b._slots[2].state.value,
        'slot2_allow': b.allow_request(2),
    }}))
elif scenario == 'status':
    for _ in range(3):
        b.record_failure(1, error_type='HTTP_500')
    print(json.dumps(b.get_status(), sort_keys=True))
else:
    print(json.dumps({{'error': 'unknown scenario'}}))
"#,
        scenario = scenario
    );
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python slot_circuit_breaker helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_env() -> EnvMap {
    let mut env = EnvMap::new();
    env.insert("CF_ACCOUNT_ID_1".to_string(), "a".repeat(32));
    env.insert("CF_API_TOKEN_1".to_string(), "t".repeat(40));
    env.insert("CF_ACCOUNT_ID_2".to_string(), "b".repeat(32));
    env.insert("CF_API_TOKEN_2".to_string(), "u".repeat(40));
    env
}

fn fixed_clock(t: f64) -> Clock {
    Arc::new(move || t)
}

/// Create an injectable clock backed by a shared mutable f64. Returns the
/// clock and a handle that tests can advance via `*handle.lock().unwrap() = t`.
fn test_clock(initial: f64) -> (Clock, Arc<Mutex<f64>>) {
    let state = Arc::new(Mutex::new(initial));
    let state_clone = Arc::clone(&state);
    let clock: Clock = Arc::new(move || *state_clone.lock().unwrap());
    (clock, state)
}

/// Reproduce the same scenario as `python_scenario` in Rust and return the
/// JSON value for comparison.
fn rust_scenario(scenario: &str) -> Value {
    let (clock, state) = test_clock(1000.0);
    let env = test_env();
    let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();

    let advance = |t: f64| *state.lock().unwrap() = t;

    match scenario {
        "fresh" => json!({
            "state": b.state(1).unwrap(),
            "allow": b.allow_request(1),
        }),
        "below_threshold" => {
            b.record_failure_with_details(1, "HTTP_500", "");
            b.record_failure_with_details(1, "HTTP_500", "");
            json!({
                "state": b.state(1).unwrap(),
                "consecutive_failures": b.slot(1).unwrap().consecutive_failures,
                "allow": b.allow_request(1),
            })
        }
        "at_threshold" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            json!({
                "state": b.state(1).unwrap(),
                "allow": b.allow_request(1),
            })
        }
        "cooldown_half_open" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            advance(1000.0 + 61.0);
            let allow = b.allow_request(1);
            json!({
                "state": b.state(1).unwrap(),
                "allow": allow,
            })
        }
        "half_open_success" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            advance(1000.0 + 61.0);
            b.allow_request(1);
            b.record_success_with_latency(1, 200.0);
            json!({
                "state": b.state(1).unwrap(),
                "consecutive_failures": b.slot(1).unwrap().consecutive_failures,
                "total_successes": b.slot(1).unwrap().total_successes,
                "allow": b.allow_request(1),
            })
        }
        "half_open_failure" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            advance(1000.0 + 61.0);
            b.allow_request(1);
            advance(1000.0 + 62.0);
            b.record_failure_with_details(1, "HTTP_500", "");
            json!({
                "state": b.state(1).unwrap(),
                "last_failure_time": b.slot(1).unwrap().last_failure_time,
                "allow": b.allow_request(1),
            })
        }
        "multi_slot" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            json!({
                "slot1_state": b.state(1).unwrap(),
                "slot1_allow": b.allow_request(1),
                "slot2_state": b.state(2).unwrap(),
                "slot2_allow": b.allow_request(2),
            })
        }
        "status" => {
            for _ in 0..3 {
                b.record_failure_with_details(1, "HTTP_500", "");
            }
            // `serde_json::Value` object equality is order-independent, so the
            // Rust Value compares directly to the Python-parsed Value.
            b.get_status()
        }
        _ => json!({"error": "unknown scenario"}),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure state-machine tests (no Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fresh_breaker_state_is_closed_and_allows_requests() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    assert_eq!(b.state(1), Some("closed"));
    assert!(b.allow_request(1));
    assert_eq!(b.state(2), Some("closed"));
    assert!(b.allow_request(2));
}

#[test]
fn below_threshold_stays_closed() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    b.record_failure_with_details(1, "HTTP_500", "");
    b.record_failure_with_details(1, "HTTP_500", "");
    assert_eq!(b.state(1), Some("closed"));
    assert_eq!(b.slot(1).unwrap().consecutive_failures, 2);
    assert!(b.allow_request(1));
}

#[test]
fn at_threshold_opens_circuit() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    for _ in 0..DEFAULT_FAILURE_THRESHOLD {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    assert_eq!(b.state(1), Some("open"));
    assert!(!b.allow_request(1));
}

#[test]
fn cooldown_elapses_to_half_open_with_probe_budget() {
    let (clock, state) = test_clock(1000.0);
    let env = test_env();
    let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    assert_eq!(b.state(1), Some("open"));
    // Just before cooldown: still open.
    *state.lock().unwrap() = 1000.0 + 59.0;
    assert!(!b.allow_request(1));
    assert_eq!(b.state(1), Some("open"));
    // After cooldown: transitions to HALF_OPEN and allows the probe.
    *state.lock().unwrap() = 1000.0 + 61.0;
    assert!(b.allow_request(1));
    assert_eq!(b.state(1), Some("half_open"));
    // HALF_OPEN continues to allow requests (parity with Python — probes_sent
    // is never incremented; see MIGRATION_NOTES).
    assert!(b.allow_request(1));
}

#[test]
fn half_open_success_transitions_to_closed() {
    let (clock, state) = test_clock(1000.0);
    let env = test_env();
    let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    *state.lock().unwrap() = 1000.0 + 61.0;
    b.allow_request(1); // OPEN → HALF_OPEN
    b.record_success_with_latency(1, 200.0);
    assert_eq!(b.state(1), Some("closed"));
    assert_eq!(b.slot(1).unwrap().consecutive_failures, 0);
    assert_eq!(b.slot(1).unwrap().total_successes, 1);
    assert!(b.allow_request(1));
}

#[test]
fn half_open_failure_reopens_with_reset_cooldown() {
    let (clock, state) = test_clock(1000.0);
    let env = test_env();
    let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    let first_failure_time = b.slot(1).unwrap().last_failure_time;
    *state.lock().unwrap() = 1000.0 + 61.0;
    b.allow_request(1); // OPEN → HALF_OPEN
    *state.lock().unwrap() = 1000.0 + 62.0;
    b.record_failure_with_details(1, "HTTP_500", "");
    assert_eq!(b.state(1), Some("open"));
    let second_failure_time = b.slot(1).unwrap().last_failure_time;
    assert!(
        second_failure_time > first_failure_time,
        "cooldown timer should reset: {second_failure_time} > {first_failure_time}"
    );
    // Cooldown has not elapsed since the new failure.
    assert!(!b.allow_request(1));
    // After a fresh cooldown from the new failure time, transitions again.
    *state.lock().unwrap() = 1000.0 + 62.0 + 61.0;
    assert!(b.allow_request(1));
    assert_eq!(b.state(1), Some("half_open"));
}

#[test]
fn different_slots_have_independent_state() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    // Drive slot 1 to OPEN.
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    // Slot 2: record 2 failures (below threshold) then a success.
    b.record_failure_with_details(2, "HTTP_429", "");
    b.record_failure_with_details(2, "HTTP_429", "");
    assert_eq!(b.state(2), Some("closed"));
    b.record_success_with_latency(2, 150.0);
    assert_eq!(b.state(2), Some("closed"));
    assert_eq!(b.slot(2).unwrap().consecutive_failures, 0);

    // Slot 1 is still OPEN, slot 2 is CLOSED.
    assert_eq!(b.state(1), Some("open"));
    assert_eq!(b.state(2), Some("closed"));
    assert!(!b.allow_request(1));
    assert!(b.allow_request(2));
}

#[test]
fn skipped_slots_block_requests_and_retain_closed_state() {
    let env = EnvMap::new();
    let mut b = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap();
    for i in 1..=(SLOT_COUNT as i32) {
        assert!(!b.allow_request(i), "slot {i} should be blocked");
        assert_eq!(b.state(i), Some("closed"));
        assert!(b.slot(i).unwrap().is_skipped);
        assert_eq!(b.slot(i).unwrap().skip_reason, "missing credentials");
    }
}

#[test]
fn available_slots_excludes_open_and_skipped() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    let avail = b.get_available_slots();
    assert_eq!(avail, vec![2]);
}

#[test]
fn get_slot_for_rotation_picks_best_health() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    // Both slots CLOSED with equal health; either is valid.
    let slot = b.get_slot_for_rotation(None);
    assert!(slot.is_some());
    let s = slot.unwrap();
    assert!(s == 1 || s == 2, "expected slot 1 or 2, got {s}");

    // Exclude slot 1 → must return slot 2.
    let mut exclude = BTreeSet::new();
    exclude.insert(1);
    let slot = b.get_slot_for_rotation(Some(&exclude));
    assert_eq!(slot, Some(2));

    // Drive slot 1 to OPEN and exclude slot 2 → no slots available.
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    let mut exclude2 = BTreeSet::new();
    exclude2.insert(2);
    let slot = b.get_slot_for_rotation(Some(&exclude2));
    assert_eq!(slot, None);
}

#[test]
fn record_success_updates_latency_ema() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    // EMA: 0.25 * 100 + 0.75 * 200 = 175
    b.record_success_with_latency(1, 100.0);
    assert_eq!(b.slot(1).unwrap().avg_latency_ms, 175.0);
    // Next: 0.25 * 50 + 0.75 * 175 = 12.5 + 131.25 = 143.75
    b.record_success_with_latency(1, 50.0);
    assert_eq!(b.slot(1).unwrap().avg_latency_ms, 143.75);
}

#[test]
fn failure_by_type_tracks_error_counts() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    b.record_failure_with_details(1, "HTTP_500", "");
    b.record_failure_with_details(1, "HTTP_500", "");
    b.record_failure_with_details(1, "HTTP_429", "");
    let slot = b.slot(1).unwrap();
    assert_eq!(slot.failure_by_type.get("HTTP_500"), Some(&2));
    assert_eq!(slot.failure_by_type.get("HTTP_429"), Some(&1));
}

#[test]
fn invalid_env_returns_typed_error() {
    let mut env = test_env();
    env.insert(
        "CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
        "abc".to_string(),
    );
    let err = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap_err();
    assert!(matches!(
        err,
        SlotCircuitBreakerError::InvalidInt { name, .. }
            if name == "CIRCUIT_BREAKER_FAILURE_THRESHOLD"
    ));
}

#[test]
fn invalid_float_env_returns_typed_error() {
    let mut env = test_env();
    env.insert(
        "CIRCUIT_BREAKER_COOLDOWN_SECS".to_string(),
        "not-a-float".to_string(),
    );
    let err = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap_err();
    assert!(matches!(
        err,
        SlotCircuitBreakerError::InvalidFloat { name, .. }
            if name == "CIRCUIT_BREAKER_COOLDOWN_SECS"
    ));
}

#[test]
fn env_overrides_apply() {
    let mut env = test_env();
    env.insert(
        "CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
        "5".to_string(),
    );
    env.insert(
        "CIRCUIT_BREAKER_COOLDOWN_SECS".to_string(),
        "30".to_string(),
    );
    env.insert(
        "CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES".to_string(),
        "2".to_string(),
    );
    let b = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap();
    assert_eq!(b.failure_threshold(), 5);
    assert_eq!(b.cooldown_secs(), 30.0);
    assert_eq!(b.half_open_max_probes(), 2);
}

#[test]
fn can_proceed_and_is_available_are_aliases() {
    let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
    assert!(b.can_proceed(1));
    assert!(b.is_available(1));
    for _ in 0..3 {
        b.record_failure_with_details(1, "HTTP_500", "");
    }
    assert!(!b.can_proceed(1));
    assert!(!b.is_available(1));
}

#[test]
fn default_clock_returns_positive_epoch() {
    let clock = default_clock();
    let t = clock();
    assert!(
        t > 1_700_000_000.0,
        "default clock should return a recent epoch: {t}"
    );
}

#[test]
fn circuit_state_value_matches_python_enum() {
    assert_eq!(CircuitState::Closed.value(), "closed");
    assert_eq!(CircuitState::Open.value(), "open");
    assert_eq!(CircuitState::HalfOpen.value(), "half_open");
}

// ─────────────────────────────────────────────────────────────────────────────
// Python subprocess parity tests (at least 3 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_fresh_state() {
    assert_eq!(rust_scenario("fresh"), python_scenario("fresh"));
}

#[test]
fn parity_below_threshold() {
    assert_eq!(
        rust_scenario("below_threshold"),
        python_scenario("below_threshold")
    );
}

#[test]
fn parity_at_threshold() {
    assert_eq!(
        rust_scenario("at_threshold"),
        python_scenario("at_threshold")
    );
}

#[test]
fn parity_cooldown_half_open() {
    assert_eq!(
        rust_scenario("cooldown_half_open"),
        python_scenario("cooldown_half_open")
    );
}

#[test]
fn parity_half_open_success() {
    assert_eq!(
        rust_scenario("half_open_success"),
        python_scenario("half_open_success")
    );
}

#[test]
fn parity_half_open_failure() {
    assert_eq!(
        rust_scenario("half_open_failure"),
        python_scenario("half_open_failure")
    );
}

#[test]
fn parity_multi_slot_isolation() {
    assert_eq!(rust_scenario("multi_slot"), python_scenario("multi_slot"));
}

#[test]
fn parity_get_status_full_dict() {
    // This is the most comprehensive parity check: compares the full
    // get_status() dict including all 11 slots, health scores, success rates,
    // recovery times, and aggregate counts.
    assert_eq!(rust_scenario("status"), python_scenario("status"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanity: confirm the default constants match config/feature_flags.py
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn defaults_match_feature_flags() {
    assert_eq!(DEFAULT_FAILURE_THRESHOLD, 3);
    assert_eq!(DEFAULT_COOLDOWN_SECS, 60.0);
    assert_eq!(DEFAULT_HALF_OPEN_MAX_PROBES, 1);
    assert_eq!(SLOT_COUNT, 11);
}
