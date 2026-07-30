#![allow(warnings)]
// Parity tests for `src/circuit_breaker_11slot.rs` vs
// `circuit_breaker_11slot.py`.
//
// Two test groups:
// 1. State-machine logic — uses an injectable clock to exercise the
//    blacklist / circuit-open / backoff / recovery cycle deterministically.
// 2. Python subprocess parity — invokes the Python `CircuitBreaker11Slot`
//    directly via `std::process::Command` on fixed scenarios (mocking
//    `time.time()` and forcing `cb._registry = None`/`cb._telemetry = None`
//    so the comparison is deterministic) and asserts identical JSON output.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use torshield_ir_ultra::circuit_breaker_11slot::{
    is_critical_error, CircuitBreaker11Slot, Clock, EliteRegistry, EnvMap, ModelSelector,
    Telemetry, DEFAULT_AVG_LATENCY_MS, LATENCY_EMA_ALPHA, MAX_CONSECUTIVE_FAILURES, NUM_SLOTS,
    SESSION_BLACKLIST_DURATION, ULTIMATE_FALLBACK_MODEL,
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

/// Invoke the Python `CircuitBreaker11Slot` on a fixed scenario and return
/// the parsed JSON output. The Python helper mocks `time.time()` and forces
/// `cb._registry = None` / `cb._telemetry = None` so the comparison is
/// deterministic and does not depend on the elite_registry or
/// telemetry_watcher modules.
fn python_scenario(scenario: &str) -> Value {
    let script = format!(
        r#"
import os, sys, json, time

# Set credentials before import (slot 1 and 2 are configured; 3-11 are not).
os.environ['CF_ACCOUNT_ID_1'] = 'a' * 32
os.environ['CF_API_TOKEN_1'] = 't' * 40
os.environ['CF_AI_GATEWAY_URL_1'] = 'https://gw1.example'
os.environ['CF_ACCOUNT_ID_2'] = 'b' * 32
os.environ['CF_API_TOKEN_2'] = 'u' * 40

# Mock time.time() to control cooldown/blacklist deterministically.
_mock_time = [1000.0]
time.time = lambda: _mock_time[0]

def advance(t):
    _mock_time[0] = t

# Block imports of telemetry_watcher so the breaker falls back to the
# no-integration path (mirrors the Rust port's None trait). The
# elite_registry module is left importable so STATIC_BASELINE is accessible
# in get_next_model Step 3 (matching the Rust port's hardcoded list).
sys.modules['telemetry_watcher'] = None

# Pre-create the torshield_ai_gateway.model_selector module with a
# None-returning best_cf_model so Step 2 of get_next_model falls through to
# STATIC_BASELINE (matching the Rust port's lack of a model_selector).
sys.modules['torshield_ai_gateway'] = type(sys)('torshield_ai_gateway')
_model_selector_mod = type(sys)('torshield_ai_gateway.model_selector')
_model_selector_mod.best_cf_model = lambda: None
sys.modules['torshield_ai_gateway.model_selector'] = _model_selector_mod

from circuit_breaker_11slot import CircuitBreaker11Slot

cb = CircuitBreaker11Slot()
scenario = {scenario:?}

if scenario == 'fresh_status':
    print(json.dumps(cb.get_status(), sort_keys=True))
elif scenario == 'mark_critical':
    cb.mark_slot_failed(1, 'HTTP 403 Forbidden', 'model-1')
    print(json.dumps({{
        'slot1_blacklisted': cb._slots[1].session_blacklisted,
        'slot1_circuit_open': cb._slots[1].circuit_open,
        'slot1_consecutive_failures': cb._slots[1].consecutive_failures,
        'slot1_total_failures': cb._slots[1].total_failures,
        'slot1_model_errors': cb._slots[1].model_errors,
        'slot1_last_failure_error': cb._slots[1].last_failure_error,
        'blacklisted_slots': cb.get_blacklisted_slots(),
    }}, sort_keys=True))
elif scenario == 'mark_circuit_error_at_threshold':
    for _ in range(3):
        cb.mark_slot_failed(1, 'HTTP 500', 'm1')
    print(json.dumps({{
        'slot1_blacklisted': cb._slots[1].session_blacklisted,
        'slot1_circuit_open': cb._slots[1].circuit_open,
        'slot1_consecutive_failures': cb._slots[1].consecutive_failures,
    }}, sort_keys=True))
elif scenario == 'mark_success':
    cb.mark_slot_failed(1, 'HTTP 500', 'm1')
    cb.mark_slot_success(1, 100.0, 'm1')
    print(json.dumps({{
        'slot1_consecutive_failures': cb._slots[1].consecutive_failures,
        'slot1_total_successes': cb._slots[1].total_successes,
        'slot1_avg_latency_ms': cb._slots[1].avg_latency_ms,
        'slot1_current_model': cb._slots[1].current_model,
    }}, sort_keys=True))
elif scenario == 'mark_request':
    cb.mark_slot_request(1)
    cb.mark_slot_request(1)
    print(json.dumps({{
        'slot1_total_requests': cb._slots[1].total_requests,
        'slot1_total_successes': cb._slots[1].total_successes,
    }}, sort_keys=True))
elif scenario == 'get_next_slot_round_robin':
    s1 = cb.get_next_slot()
    s2 = cb.get_next_slot()
    s3 = cb.get_next_slot()
    print(json.dumps({{
        's1': s1.index if s1 else None,
        's2': s2.index if s2 else None,
        's3': s3.index if s3 else None,
    }}, sort_keys=True))
elif scenario == 'get_next_model_no_deps':
    # Block best_cf_model so Step 2 fails too.
    sys.modules['torshield_ai_gateway.model_selector'].best_cf_model = lambda: None
    print(json.dumps({{
        'model': cb.get_next_model('general'),
    }}, sort_keys=True))
elif scenario == 'reset_all':
    cb.mark_slot_failed(1, 'HTTP 403', 'm1')
    for _ in range(3):
        cb.mark_slot_failed(2, 'HTTP 500', 'm2')
    cb.reset_all_circuits()
    print(json.dumps({{
        'slot1_blacklisted': cb._slots[1].session_blacklisted,
        'slot1_circuit_open': cb._slots[1].circuit_open,
        'slot1_consecutive_failures': cb._slots[1].consecutive_failures,
        'slot2_circuit_open': cb._slots[2].circuit_open,
    }}, sort_keys=True))
elif scenario == 'reset_slot':
    success = cb.reset_slot(1)
    not_found = cb.reset_slot(99)
    print(json.dumps({{
        'reset_1': success,
        'reset_99': not_found,
    }}, sort_keys=True))
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
        .unwrap_or_else(|err| panic!("python circuit_breaker_11slot helper must execute: {err}"));
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
    env.insert(
        "CF_AI_GATEWAY_URL_1".to_string(),
        "https://gw1.example".to_string(),
    );
    env.insert("CF_ACCOUNT_ID_2".to_string(), "b".repeat(32));
    env.insert("CF_API_TOKEN_2".to_string(), "u".repeat(40));
    env
}

fn fixed_clock(t: f64) -> Clock {
    Arc::new(move || t)
}

/// Create an injectable clock backed by a shared mutable f64.
fn test_clock(initial: f64) -> (Clock, Arc<Mutex<f64>>) {
    let state = Arc::new(Mutex::new(initial));
    let state_clone = Arc::clone(&state);
    let clock: Clock = Arc::new(move || *state_clone.lock().unwrap());
    (clock, state)
}

/// Reproduce the same scenario as `python_scenario` in Rust and return the
/// JSON value for comparison. Uses no integrations (matching the Python
/// helper that blocks telemetry_watcher / elite_registry imports).
fn rust_scenario(scenario: &str) -> Value {
    let (clock, _state) = test_clock(1000.0);
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);

    match scenario {
        "fresh_status" => {
            let mut status = cb.get_status();
            // Sort the slots object by key for stable comparison.
            if let Value::Object(ref mut map) = status {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                for k in keys {
                    let v = map.remove(&k).unwrap();
                    sorted.insert(k, v);
                }
                *map = sorted;
            }
            status
        }
        "mark_critical" => {
            cb.mark_slot_failed(1, "HTTP 403 Forbidden", "model-1");
            let s = cb.slot(1).unwrap();
            json!({
                "slot1_blacklisted": s.session_blacklisted,
                "slot1_circuit_open": s.circuit_open,
                "slot1_consecutive_failures": s.consecutive_failures,
                "slot1_total_failures": s.total_failures,
                "slot1_model_errors": s.model_errors,
                "slot1_last_failure_error": s.last_failure_error,
                "blacklisted_slots": cb.get_blacklisted_slots(),
            })
        }
        "mark_circuit_error_at_threshold" => {
            for _ in 0..3 {
                cb.mark_slot_failed(1, "HTTP 500", "m1");
            }
            let s = cb.slot(1).unwrap();
            json!({
                "slot1_blacklisted": s.session_blacklisted,
                "slot1_circuit_open": s.circuit_open,
                "slot1_consecutive_failures": s.consecutive_failures,
            })
        }
        "mark_success" => {
            cb.mark_slot_failed(1, "HTTP 500", "m1");
            cb.mark_slot_success(1, 100.0, "m1");
            let s = cb.slot(1).unwrap();
            json!({
                "slot1_consecutive_failures": s.consecutive_failures,
                "slot1_total_successes": s.total_successes,
                "slot1_avg_latency_ms": s.avg_latency_ms,
                "slot1_current_model": s.current_model,
            })
        }
        "mark_request" => {
            cb.mark_slot_request(1);
            cb.mark_slot_request(1);
            let s = cb.slot(1).unwrap();
            json!({
                "slot1_total_requests": s.total_requests,
                "slot1_total_successes": s.total_successes,
            })
        }
        "get_next_slot_round_robin" => {
            let s1 = cb.get_next_slot();
            let s2 = cb.get_next_slot();
            let s3 = cb.get_next_slot();
            json!({
                "s1": s1,
                "s2": s2,
                "s3": s3,
            })
        }
        "get_next_model_no_deps" => {
            // The Rust port already has no model_selector injected.
            json!({
                "model": cb.get_next_model("general"),
            })
        }
        "reset_all" => {
            cb.mark_slot_failed(1, "HTTP 403", "m1");
            for _ in 0..3 {
                cb.mark_slot_failed(2, "HTTP 500", "m2");
            }
            cb.reset_all_circuits();
            let s1 = cb.slot(1).unwrap();
            let s2 = cb.slot(2).unwrap();
            json!({
                "slot1_blacklisted": s1.session_blacklisted,
                "slot1_circuit_open": s1.circuit_open,
                "slot1_consecutive_failures": s1.consecutive_failures,
                "slot2_circuit_open": s2.circuit_open,
            })
        }
        "reset_slot" => {
            let r1 = cb.reset_slot(1);
            let r99 = cb.reset_slot(99);
            json!({
                "reset_1": r1,
                "reset_99": r99,
            })
        }
        _ => json!({"error": "unknown scenario"}),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure state-machine tests (no Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fresh_breaker_initializes_all_slots() {
    let env = test_env();
    let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    assert_eq!(cb.slot(1).unwrap().index, 1);
    assert!(cb.slot(1).unwrap().is_configured);
    assert!(cb.slot(2).unwrap().is_configured);
    for i in 3..=NUM_SLOTS {
        assert!(
            !cb.slot(i).unwrap().is_configured,
            "slot {i} should be unconfigured"
        );
    }
}

#[test]
fn fresh_health_score_is_0_98_for_default_latency() {
    let env = test_env();
    let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    // success_rate(1.0) * (1 - 200/10000) = 0.98
    assert_eq!(cb.slot(1).unwrap().health_score(), 0.98);
    assert_eq!(cb.slot(1).unwrap().success_rate(), 1.0);
}

#[test]
fn critical_error_blacklists_slot_immediately() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    cb.mark_slot_failed(1, "HTTP 403 Forbidden", "model-1");
    let s = cb.slot(1).unwrap();
    assert!(s.session_blacklisted);
    assert!(!s.circuit_open); // below threshold
    assert_eq!(s.consecutive_failures, 1);
    assert_eq!(s.total_failures, 1);
    assert_eq!(s.model_errors.get("model-1"), Some(&1));
}

#[test]
fn circuit_error_at_threshold_opens_circuit_without_blacklist() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        cb.mark_slot_failed(1, "HTTP 500", "m1");
    }
    let s = cb.slot(1).unwrap();
    assert!(!s.session_blacklisted); // not a critical error
    assert!(s.circuit_open);
    assert_eq!(s.consecutive_failures, MAX_CONSECUTIVE_FAILURES);
}

#[test]
fn mark_slot_success_resets_and_updates_ema() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    cb.mark_slot_failed(1, "HTTP 500", "m1");
    cb.mark_slot_failed(1, "HTTP 500", "m1");
    cb.mark_slot_success(1, 100.0, "m1");
    let s = cb.slot(1).unwrap();
    assert_eq!(s.consecutive_failures, 0);
    assert_eq!(s.total_successes, 1);
    // EMA: 0.25 * 100 + 0.75 * 200 = 175
    assert_eq!(s.avg_latency_ms, 175.0);
    assert_eq!(s.current_model, "m1");
}

#[test]
fn mark_slot_request_increments_only_total_requests() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    cb.mark_slot_request(1);
    cb.mark_slot_request(1);
    let s = cb.slot(1).unwrap();
    assert_eq!(s.total_requests, 2);
    assert_eq!(s.total_successes, 0);
    assert_eq!(s.total_failures, 0);
}

#[test]
fn is_available_respects_blacklist_expiry() {
    let env = test_env();
    let (clock, state) = test_clock(1000.0);
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
    cb.mark_slot_failed(1, "HTTP 403", "m1");
    assert!(cb.slot(1).unwrap().session_blacklisted);
    // Before expiry.
    *state.lock().unwrap() = 1000.0 + SESSION_BLACKLIST_DURATION - 1.0;
    assert!(!cb.get_available_slots().contains(&1));
    // After expiry: blacklist cleared.
    *state.lock().unwrap() = 1000.0 + SESSION_BLACKLIST_DURATION + 1.0;
    assert!(cb.get_available_slots().contains(&1));
    assert!(!cb.slot(1).unwrap().session_blacklisted);
}

#[test]
fn is_available_respects_circuit_reset() {
    let env = test_env();
    let (clock, state) = test_clock(1000.0);
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        cb.mark_slot_failed(1, "HTTP 500", "m1");
    }
    assert!(cb.slot(1).unwrap().circuit_open);
    // Before reset.
    *state.lock().unwrap() = 1000.0 + 299.0;
    assert!(!cb.get_available_slots().contains(&1));
    // After reset: circuit cleared.
    *state.lock().unwrap() = 1000.0 + 301.0;
    assert!(cb.get_available_slots().contains(&1));
    assert!(!cb.slot(1).unwrap().circuit_open);
}

#[test]
fn is_available_respects_backoff_window() {
    let env = test_env();
    let (clock, state) = test_clock(1000.0);
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
    // 1 failure: below circuit threshold, but within backoff window.
    cb.mark_slot_failed(1, "HTTP 500", "m1");
    *state.lock().unwrap() = 1000.0 + 89.0;
    assert!(!cb.get_available_slots().contains(&1));
    *state.lock().unwrap() = 1000.0 + 91.0;
    assert!(cb.get_available_slots().contains(&1));
}

#[test]
fn get_next_slot_round_robin() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    // First call: starts at 0, advances to 1.
    assert_eq!(cb.get_next_slot(), Some(1));
    // Second call: advances to 2.
    assert_eq!(cb.get_next_slot(), Some(2));
    // Third call: 3..11 are unconfigured; wraps to 1.
    assert_eq!(cb.get_next_slot(), Some(1));
}

#[test]
fn get_next_slot_with_gateway_prefers_gateway_slots() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    // Slot 1 has a gateway URL; slot 2 does not.
    let s = cb.get_next_slot_with_gateway().unwrap();
    assert_eq!(s, 1);
}

#[test]
fn get_status_dict_shape_matches_python() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    let status = cb.get_status();
    assert_eq!(status["total_slots"], json!(NUM_SLOTS));
    assert_eq!(status["configured_slots"], json!(2));
    assert_eq!(status["available_slots"], json!(2));
    assert_eq!(status["blacklisted_slots"], json!(0));
    assert_eq!(status["circuit_open_slots"], json!(0));
    assert_eq!(status["rotation_counter"], json!(0));
    assert_eq!(status["fallback_mode"], json!(false));
    assert_eq!(status["slots"]["1"]["configured"], json!(true));
    assert_eq!(status["slots"]["1"]["has_gateway"], json!(true));
    assert_eq!(status["slots"]["2"]["has_gateway"], json!(false));
    assert_eq!(status["slots"]["3"]["configured"], json!(false));
}

#[test]
fn get_blacklisted_slots_returns_indices() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    cb.mark_slot_failed(1, "HTTP 403", "m1");
    cb.mark_slot_failed(2, "HTTP 401", "m2");
    let mut bl = cb.get_blacklisted_slots();
    bl.sort();
    assert_eq!(bl, vec![1, 2]);
}

#[test]
fn reset_all_circuits_clears_state() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    cb.mark_slot_failed(1, "HTTP 403", "m1");
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        cb.mark_slot_failed(2, "HTTP 500", "m2");
    }
    cb.reset_all_circuits();
    for s in cb.slot(1).iter().chain(cb.slot(2).iter()) {
        assert!(!s.circuit_open);
        assert!(!s.session_blacklisted);
        assert_eq!(s.consecutive_failures, 0);
    }
}

#[test]
fn reset_slot_returns_false_for_unknown_index() {
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    assert!(!cb.reset_slot(99));
    assert!(cb.reset_slot(1));
}

#[test]
fn get_next_model_no_deps_returns_first_static_baseline() {
    let env = test_env();
    let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
    assert_eq!(
        cb.get_next_model("general"),
        "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    );
}

#[test]
fn get_next_model_ultimate_fallback_when_baseline_unavailable() {
    struct AllUnavailable;
    impl EliteRegistry for AllUnavailable {
        fn get_best_model(&self, _task: &str) -> Option<String> {
            None
        }
        fn mark_model_error(&self, _model_id: &str) {}
        fn mark_model_success(&self, _model_id: &str, _latency_ms: f64) {}
        fn is_model_available(&self, _model_id: &str) -> bool {
            false
        }
    }
    let env = test_env();
    let cb = CircuitBreaker11Slot::new(
        &env,
        fixed_clock(1000.0),
        None,
        Some(Arc::new(AllUnavailable)),
        None,
    );
    assert_eq!(cb.get_next_model("general"), ULTIMATE_FALLBACK_MODEL);
}

#[test]
fn get_next_model_uses_registry_when_available() {
    struct StubRegistry;
    impl EliteRegistry for StubRegistry {
        fn get_best_model(&self, _task: &str) -> Option<String> {
            Some("custom-model".to_string())
        }
        fn mark_model_error(&self, _model_id: &str) {}
        fn mark_model_success(&self, _model_id: &str, _latency_ms: f64) {}
    }
    let env = test_env();
    let cb = CircuitBreaker11Slot::new(
        &env,
        fixed_clock(1000.0),
        None,
        Some(Arc::new(StubRegistry)),
        None,
    );
    assert_eq!(cb.get_next_model("general"), "custom-model");
}

#[test]
fn get_next_model_uses_model_selector_when_no_registry() {
    struct StubSelector;
    impl ModelSelector for StubSelector {
        fn best_cf_model(&self) -> Option<String> {
            Some("selector-model".to_string())
        }
    }
    let env = test_env();
    let cb = CircuitBreaker11Slot::new(
        &env,
        fixed_clock(1000.0),
        None,
        None,
        Some(Arc::new(StubSelector)),
    );
    assert_eq!(cb.get_next_model("general"), "selector-model");
}

#[test]
fn is_critical_error_matches_python_set() {
    assert!(is_critical_error("HTTP 403 Forbidden"));
    assert!(is_critical_error("HTTP 401 Unauthorized"));
    assert!(is_critical_error("HTTP 1010 Access Denied"));
    assert!(is_critical_error("Circuit Open: slot 3"));
    assert!(!is_critical_error("HTTP 500"));
    assert!(!is_critical_error("HTTP 400"));
    assert!(!is_critical_error(""));
}

#[test]
fn telemetry_hooks_are_invoked() {
    use std::sync::Mutex as StdMutex;
    struct Recording {
        log_slot_failure_calls: StdMutex<Vec<(i32, String, String, String)>>,
        log_request_calls: StdMutex<Vec<bool>>,
        #[allow(clippy::type_complexity)]
        log_self_heal_calls: StdMutex<Vec<(String, Value, bool, Option<f64>)>>,
    }
    impl Telemetry for Recording {
        fn log_slot_failure(
            &self,
            slot_index: i32,
            env_var: &str,
            error_type: &str,
            error_detail: &str,
        ) {
            self.log_slot_failure_calls.lock().unwrap().push((
                slot_index,
                env_var.to_string(),
                error_type.to_string(),
                error_detail.to_string(),
            ));
        }
        fn log_request(&self, success: bool) {
            self.log_request_calls.lock().unwrap().push(success);
        }
        fn log_self_heal(
            &self,
            action: &str,
            data: Value,
            success: bool,
            recovery_time_ms: Option<f64>,
        ) {
            self.log_self_heal_calls.lock().unwrap().push((
                action.to_string(),
                data,
                success,
                recovery_time_ms,
            ));
        }
    }
    let recording = Arc::new(Recording {
        log_slot_failure_calls: StdMutex::new(Vec::new()),
        log_request_calls: StdMutex::new(Vec::new()),
        log_self_heal_calls: StdMutex::new(Vec::new()),
    });
    let env = test_env();
    let mut cb = CircuitBreaker11Slot::new(
        &env,
        fixed_clock(1000.0),
        Some(recording.clone()),
        None,
        None,
    );
    cb.mark_slot_failed(1, "HTTP 500", "m1");
    cb.mark_slot_success(1, 100.0, "m1");
    // mark_slot_failed logs log_slot_failure + log_self_heal(slot_failover)
    assert_eq!(recording.log_slot_failure_calls.lock().unwrap().len(), 1);
    assert_eq!(recording.log_self_heal_calls.lock().unwrap().len(), 1);
    // mark_slot_success logs log_request(true)
    assert_eq!(recording.log_request_calls.lock().unwrap().len(), 1);
}

#[test]
fn default_constants_match_python_module() {
    assert_eq!(NUM_SLOTS, 11);
    assert_eq!(MAX_CONSECUTIVE_FAILURES, 3);
    assert_eq!(SESSION_BLACKLIST_DURATION, 3600.0);
    assert_eq!(DEFAULT_AVG_LATENCY_MS, 200.0);
    assert_eq!(LATENCY_EMA_ALPHA, 0.25);
}

// ─────────────────────────────────────────────────────────────────────────────
// Python subprocess parity tests (8 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_fresh_status() {
    assert_eq!(
        rust_scenario("fresh_status"),
        python_scenario("fresh_status")
    );
}

#[test]
fn parity_mark_critical_blacklists() {
    assert_eq!(
        rust_scenario("mark_critical"),
        python_scenario("mark_critical")
    );
}

#[test]
fn parity_mark_circuit_error_at_threshold() {
    assert_eq!(
        rust_scenario("mark_circuit_error_at_threshold"),
        python_scenario("mark_circuit_error_at_threshold")
    );
}

#[test]
fn parity_mark_success_resets_and_ema() {
    assert_eq!(
        rust_scenario("mark_success"),
        python_scenario("mark_success")
    );
}

#[test]
fn parity_mark_request_tracks_total() {
    assert_eq!(
        rust_scenario("mark_request"),
        python_scenario("mark_request")
    );
}

#[test]
fn parity_get_next_slot_round_robin() {
    assert_eq!(
        rust_scenario("get_next_slot_round_robin"),
        python_scenario("get_next_slot_round_robin")
    );
}

#[test]
fn parity_get_next_model_no_deps() {
    assert_eq!(
        rust_scenario("get_next_model_no_deps"),
        python_scenario("get_next_model_no_deps")
    );
}

#[test]
fn parity_reset_all_circuits() {
    assert_eq!(rust_scenario("reset_all"), python_scenario("reset_all"));
}

#[test]
fn parity_reset_slot_returns_bool() {
    assert_eq!(rust_scenario("reset_slot"), python_scenario("reset_slot"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-threaded smoke test
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn breaker_is_send_sync_across_threads() {
    use std::sync::Arc;
    let env = Arc::new(test_env());
    let env_clone = Arc::clone(&env);
    let handle = std::thread::spawn(move || {
        let cb = CircuitBreaker11Slot::new_without_integrations(&env_clone, fixed_clock(1000.0));
        cb.slot(1).unwrap().health_score()
    });
    let h = handle.join().unwrap();
    assert_eq!(h, 0.98);
}
