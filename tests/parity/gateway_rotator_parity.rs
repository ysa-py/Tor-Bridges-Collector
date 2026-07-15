// Live-Python differential parity test for `torshield_ai_gateway/rotator.py`.
//
// Pure-math behaviour (success_rate, health_score, latency EMA, status_report,
// fallback ordering) is asserted for exact equality. The env-seeded
// deterministic `run_seed`/`get_primary` selection is exercised under a fixed
// `GITHUB_RUN_ID`/`GITHUB_RUN_ATTEMPT` on both sides. All env-dependent checks
// live in a single test so process-global env mutation cannot race.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::rotator::{AccountRotator, AccountSlot};

fn oracle(script: &str, args: &[&str], env: &[(&str, &str)]) -> Value {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("python");
    cmd.current_dir(repo_root).arg("-c").arg(script).args(args);
    cmd.env_remove("GITHUB_RUN_ID");
    cmd.env_remove("GITHUB_RUN_ATTEMPT");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("python parity oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python oracle must emit JSON")
}

// Build identical slot sets on both sides. Each spec:
// (index, total_requests, total_successes, avg_latency_ms)
type SlotSpec = (i64, i64, i64, f64);

fn make_rust_slots(specs: &[SlotSpec]) -> Vec<AccountSlot> {
    specs
        .iter()
        .map(|&(index, req, ok, lat)| {
            let mut s = AccountSlot::new(index, format!("acc{index}"), format!("key{index}"));
            s.total_requests = req;
            s.total_successes = ok;
            s.avg_latency_ms = lat;
            s
        })
        .collect()
}

fn specs_json(specs: &[SlotSpec]) -> String {
    let arr: Vec<Value> = specs
        .iter()
        .map(|&(i, req, ok, lat)| json!([i, req, ok, lat]))
        .collect();
    serde_json::to_string(&arr).expect("serialize specs")
}

const PY_BUILD: &str = r#"
from torshield_ai_gateway.rotator import AccountRotator, AccountSlot
def build(specs):
    slots = []
    for index, req, ok, lat in specs:
        s = AccountSlot(index=index, account_id="acc%d" % index, api_key="key%d" % index)
        s.total_requests = req
        s.total_successes = ok
        s.avg_latency_ms = lat
        slots.append(s)
    return AccountRotator("cf", slots)
"#;

#[test]
fn parity_status_report_and_scores() {
    let script = format!(
        r#"
import json, sys
{PY_BUILD}
specs = json.loads(sys.argv[1])
r = build(specs)
print(json.dumps({{
    "status": r.status_report(),
    "scores": [s.health_score for s in r.slots],
    "rates": [s.success_rate for s in r.slots],
}}, separators=(",", ":")))
"#
    );
    let specs: Vec<SlotSpec> = vec![
        (1, 0, 0, 200.0),
        (2, 10, 9, 500.0),
        (3, 4, 1, 8000.0),
        (4, 100, 100, 50.0),
    ];
    let py = oracle(&script, &[&specs_json(&specs)], &[]);

    let r = AccountRotator::new("cf", make_rust_slots(&specs)).unwrap();
    let rust_status = Value::Array(r.status_report());
    let rust_scores: Vec<f64> = r.slots.iter().map(|s| s.health_score()).collect();
    let rust_rates: Vec<f64> = r.slots.iter().map(|s| s.success_rate()).collect();

    assert_eq!(py["status"], rust_status, "status_report mismatch");
    assert_eq!(py["scores"], json!(rust_scores), "health_score mismatch");
    assert_eq!(py["rates"], json!(rust_rates), "success_rate mismatch");
}

#[test]
fn parity_fallback_chain_order() {
    let script = format!(
        r#"
import json, sys
{PY_BUILD}
specs = json.loads(sys.argv[1])
exclude = int(sys.argv[2])
r = build(specs)
chain = r.get_fallback_chain(exclude)
print(json.dumps({{"order": [s.index for s in chain]}}, separators=(",", ":")))
"#
    );
    let specs: Vec<SlotSpec> = vec![
        (1, 10, 5, 300.0),
        (2, 10, 9, 300.0),
        (3, 10, 9, 300.0),
        (4, 10, 2, 300.0),
    ];
    let py = oracle(&script, &[&specs_json(&specs), "2"], &[]);

    let mut r = AccountRotator::new("cf", make_rust_slots(&specs)).unwrap();
    let rust_order: Vec<i64> = r
        .get_fallback_chain(2)
        .into_iter()
        .map(|i| r.slots[i].index)
        .collect();
    assert_eq!(py["order"], json!(rust_order), "fallback order mismatch");
}

// Only this test mutates GITHUB_RUN_ID/ATTEMPT — no race with the others.
#[test]
fn parity_run_seed_and_primary_selection() {
    // 1) run seed mod parity across several moduli and run ids.
    let seed_script = r#"
import json, sys, os, hashlib
run_id = os.environ.get("GITHUB_RUN_ID", "0")
attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
seed = int(hashlib.sha256(("%s:%s" % (run_id, attempt)).encode()).hexdigest(), 16)
mods = json.loads(sys.argv[1])
print(json.dumps({"mods": {str(m): seed % m for m in mods}}, separators=(",", ":")))
"#;
    for (run_id, attempt) in [("12345", "1"), ("999999", "2"), ("abcRUN", "3")] {
        let py = oracle(
            seed_script,
            &["[10000,7,1000000,97]"],
            &[("GITHUB_RUN_ID", run_id), ("GITHUB_RUN_ATTEMPT", attempt)],
        );
        std::env::set_var("GITHUB_RUN_ID", run_id);
        std::env::set_var("GITHUB_RUN_ATTEMPT", attempt);
        for m in [10000_u64, 7, 1_000_000, 97] {
            assert_eq!(
                py["mods"][m.to_string()],
                json!(AccountRotator::run_seed_mod(m)),
                "seed mod {m} mismatch for run_id {run_id}"
            );
        }
    }

    // 2) get_primary deterministic selection under fixed seed, fresh slots.
    let primary_script = format!(
        r#"
import json, sys
{PY_BUILD}
specs = json.loads(sys.argv[1])
r = build(specs)
print(json.dumps({{"primary": r.get_primary().index}}, separators=(",", ":")))
"#
    );
    let specs: Vec<SlotSpec> = vec![
        (1, 10, 2, 400.0),
        (2, 10, 9, 200.0),
        (3, 10, 7, 900.0),
        (4, 10, 10, 100.0),
    ];
    for (run_id, attempt) in [("12345", "1"), ("777", "1"), ("iranrun", "5")] {
        let py = oracle(
            &primary_script,
            &[&specs_json(&specs)],
            &[("GITHUB_RUN_ID", run_id), ("GITHUB_RUN_ATTEMPT", attempt)],
        );
        std::env::set_var("GITHUB_RUN_ID", run_id);
        std::env::set_var("GITHUB_RUN_ATTEMPT", attempt);
        let mut r = AccountRotator::new("cf", make_rust_slots(&specs)).unwrap();
        let primary_idx = r.get_primary();
        let chosen = r.slots[primary_idx].index;
        assert_eq!(py["primary"], json!(chosen), "primary mismatch for {run_id}");
    }

    std::env::remove_var("GITHUB_RUN_ID");
    std::env::remove_var("GITHUB_RUN_ATTEMPT");
}
