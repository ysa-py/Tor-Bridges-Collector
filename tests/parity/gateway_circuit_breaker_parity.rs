// Live-Python differential parity test for
// `torshield_ai_gateway/circuit_breaker.py` vs the Rust port
// `src/torshield_ai_gateway/circuit_breaker.rs`.
//
// An identical scripted sequence of operations is replayed against BOTH the
// real CPython `IranAwareCircuitBreaker` (spawned as a subprocess oracle, with
// `time.time()` monkeypatched to a controlled clock) and the Rust port. The
// `can_attempt` results at each step and the final `get_status()` snapshot are
// compared for exact equality.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::circuit_breaker::IranAwareCircuitBreaker;

fn python_executable() -> &'static str {
    if Command::new("python")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        "python"
    } else {
        "python3"
    }
}

const ORACLE: &str = r#"
import sys, json, os, time
# Clean any persisted state so construction is deterministic.
try:
    os.remove("/tmp/torshield_cb_state.json")
except OSError:
    pass
import torshield_ai_gateway.circuit_breaker as cb

clock = {"t": 0.0}
cb.time.time = lambda: clock["t"]           # controlled monotonic-ish clock

b = cb.IranAwareCircuitBreaker()
ops = json.loads(sys.argv[1])
results = []
for op in ops:
    kind = op[0]
    if kind == "set_threat":
        b.set_threat_level(op[1])
    elif kind == "set_time":
        clock["t"] = op[1]
    elif kind == "can_attempt":
        results.append([op[1], bool(b.can_attempt(op[1]))])
    elif kind == "record_failure":
        b.record_failure(op[1], op[2], op[3])
    elif kind == "record_success":
        b.record_success(op[1], op[2])
    else:
        sys.exit("bad op " + kind)

print(json.dumps({"results": results, "status": b.get_status()}, sort_keys=True))
"#;

fn oracle(ops: &Value) -> (Value, Value) {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(ORACLE)
        .arg(serde_json::to_string(ops).unwrap())
        .output()
        .expect("python circuit_breaker oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).expect("oracle JSON");
    (v["results"].clone(), v["status"].clone())
}

/// Replay the same op-script against the Rust port; return (results, status).
fn replay_rust(ops: &Value) -> (Value, Value) {
    let mut b = IranAwareCircuitBreaker::new();
    let mut clock = 0.0_f64;
    let mut results: Vec<Value> = Vec::new();
    for op in ops.as_array().unwrap() {
        let op = op.as_array().unwrap();
        match op[0].as_str().unwrap() {
            "set_threat" => b.set_threat_level(op[1].as_str().unwrap()),
            "set_time" => clock = op[1].as_f64().unwrap(),
            "can_attempt" => {
                let p = op[1].as_str().unwrap();
                results.push(json!([p, b.can_attempt(p, clock)]));
            }
            "record_failure" => {
                let http = if op[3].is_null() {
                    None
                } else {
                    Some(op[3].as_i64().unwrap())
                };
                b.record_failure(op[1].as_str().unwrap(), op[2].as_str().unwrap(), http, clock);
            }
            "record_success" => {
                b.record_success(op[1].as_str().unwrap(), op[2].as_f64().unwrap(), clock);
            }
            other => panic!("bad op {other}"),
        }
    }
    (Value::Array(results), b.get_status())
}

fn check(ops: Value) {
    let (py_results, py_status) = oracle(&ops);
    let (r_results, r_status) = replay_rust(&ops);
    assert_eq!(py_results, r_results, "can_attempt results diverged");
    assert_eq!(py_status, r_status, "get_status snapshot diverged");
}

#[test]
fn parity_iran_provider_opens_after_two() {
    check(json!([
        ["set_threat", "high"],
        ["set_time", 100.0],
        ["can_attempt", "cerebras"],
        ["record_failure", "cerebras", "connection refused", 403],
        ["can_attempt", "cerebras"],
        ["record_failure", "cerebras", "boom", null],
        ["can_attempt", "cerebras"]
    ]));
}

#[test]
fn parity_standard_provider_five_failures() {
    check(json!([
        ["set_time", 10.0],
        ["record_failure", "openai", "err", 500],
        ["record_failure", "openai", "err", 500],
        ["record_failure", "openai", "err", 500],
        ["record_failure", "openai", "err", 500],
        ["can_attempt", "openai"],
        ["record_failure", "openai", "err", 500],
        ["can_attempt", "openai"]
    ]));
}

#[test]
fn parity_recovery_open_halfopen_closed() {
    check(json!([
        ["set_threat", "none"],
        ["set_time", 0.0],
        ["record_failure", "portkey", "x", null],
        ["record_failure", "portkey", "x", null],
        ["set_time", 10.0],
        ["can_attempt", "portkey"],
        ["set_time", 31.0],
        ["can_attempt", "portkey"],
        ["record_success", "portkey", 5.5],
        ["can_attempt", "portkey"]
    ]));
}

#[test]
fn parity_threat_level_recovery_timeouts() {
    // critical => 600s: at t=500 still OPEN, at t=601 half-open.
    check(json!([
        ["set_threat", "critical"],
        ["set_time", 0.0],
        ["record_failure", "cerebras", "dns poisoning", null],
        ["record_failure", "cerebras", "dns poisoning", null],
        ["set_time", 500.0],
        ["can_attempt", "cerebras"],
        ["set_time", 601.0],
        ["can_attempt", "cerebras"]
    ]));
}

#[test]
fn parity_mixed_providers_and_latency_stats() {
    check(json!([
        ["set_time", 50.0],
        ["record_success", "cloudflare", 12.5],
        ["record_success", "cloudflare", 7.5],
        ["record_failure", "cloudflare", "transient", 500],
        ["record_success", "cloudflare", 20.0],
        ["record_failure", "cerebras", "timed out", null],
        ["record_failure", "cerebras", "timed out", null],
        ["can_attempt", "cerebras"],
        ["can_attempt", "cloudflare"]
    ]));
}
