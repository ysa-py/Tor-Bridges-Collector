// Parity tests for `src/censorship_monitor.rs` vs `core/censorship_monitor.py`.
//
// See `src/censorship_monitor.rs`'s module doc comment ("This sandbox
// cannot reach any of the real probe targets") before changing the
// network-touching tests below: they deliberately probe local TCP
// listeners this test suite starts and controls, never the real
// `_CAT_A`..`_CAT_F` targets, which are unreachable from this
// environment's sandboxed egress by design.

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;

use serde_json::{json, Value};

use torshield_ir_ultra::censorship_monitor::{
    best_transports_for_level, decide_level, get_last_state, isp_tier_info, level_recommendations,
    measure_censorship_level_with_categories, probe_category, probe_tcp, should_use_nin_pack,
};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        return Box::leak(path.into_boxed_str());
    }
    "python3"
}

struct PythonResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_python_script(script: &str, payload: &Value) -> PythonResult {
    let payload_json = serde_json::to_string(payload).expect("payload must serialize");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&payload_json)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    PythonResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn run_python_json(script: &str, payload: &Value) -> Value {
    let result = run_python_script(script, payload);
    assert!(result.success, "python helper failed: {}", result.stderr);
    serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "python helper must emit JSON: {err}; stdout={}",
            result.stdout
        )
    })
}

/// Starts a local listener that accepts and immediately drops
/// connections (a stand-in "reachable" target), returning its port and
/// a guard that keeps it alive until dropped.
fn start_reachable_listener() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut s) => {
                    let mut buf = [0u8; 1];
                    let _ = s.read(&mut buf);
                }
                Err(_) => break,
            }
        }
    });
    (port, handle)
}

/// Returns a port with nothing listening on it (bind-then-drop), a
/// stand-in "refused" target.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// ─────────────────────────────────────────────────────────────────────────────
// decide_level — pure function, no network, exact parity expected
// ─────────────────────────────────────────────────────────────────────────────

const DECIDE_LEVEL_SCRIPT: &str = r##"
import json, sys
from core.censorship_monitor import _decide_level

p = json.loads(sys.argv[1])
level, conf = _decide_level(
    p["a_ok"], p["a_tot"], p["b_ok"], p["b_tot"],
    p["c_ok"], p["c_tot"], p["d_ok"], p["d_tot"],
    p["e_ok"], p["e_tot"], p["f_ok"], p["f_tot"],
)
print(json.dumps({"level": level, "confidence": conf}))
"##;

macro_rules! parity_decide_level {
    ($name:ident, $a_ok:expr, $a_tot:expr, $b_ok:expr, $b_tot:expr, $c_ok:expr, $c_tot:expr, $d_ok:expr, $d_tot:expr, $e_ok:expr, $e_tot:expr, $f_ok:expr, $f_tot:expr) => {
        #[test]
        fn $name() {
            let payload = json!({
                "a_ok": $a_ok, "a_tot": $a_tot, "b_ok": $b_ok, "b_tot": $b_tot,
                "c_ok": $c_ok, "c_tot": $c_tot, "d_ok": $d_ok, "d_tot": $d_tot,
                "e_ok": $e_ok, "e_tot": $e_tot, "f_ok": $f_ok, "f_tot": $f_tot,
            });
            let py = run_python_json(DECIDE_LEVEL_SCRIPT, &payload);
            let (level, conf) = decide_level(
                $a_ok, $a_tot, $b_ok, $b_tot, $c_ok, $c_tot, $d_ok, $d_tot, $e_ok, $e_tot, $f_ok, $f_tot,
            );
            assert_eq!(py["level"], json!(level));
            assert_eq!(py["confidence"], json!(conf));
        }
    };
}

parity_decide_level!(decide_l5_nin_active, 0, 4, 4, 4, 3, 4, 3, 3, 1, 3, 3, 3);
parity_decide_level!(decide_l5_fallback, 0, 4, 0, 4, 0, 4, 0, 3, 0, 3, 0, 3);
parity_decide_level!(decide_l4_dpi_active, 1, 4, 4, 4, 0, 4, 0, 3, 0, 3, 3, 3);
parity_decide_level!(decide_l4_strong_signal, 2, 4, 4, 4, 0, 4, 0, 4, 2, 3, 3, 4);
parity_decide_level!(decide_l3_tor_blocked, 4, 4, 4, 4, 1, 4, 2, 4, 2, 3, 3, 4);
parity_decide_level!(decide_l2_f_low, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 1, 4);
parity_decide_level!(decide_l2_f_mid, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 4);
parity_decide_level!(
    decide_l2_falls_through_to_l1,
    4,
    4,
    4,
    4,
    4,
    4,
    3,
    3,
    3,
    3,
    4,
    4
);
parity_decide_level!(
    decide_l2_falls_through_to_default,
    4,
    4,
    1,
    4,
    1,
    3,
    3,
    3,
    3,
    3,
    4,
    4
);
parity_decide_level!(decide_true_default, 2, 4, 1, 4, 0, 4, 1, 3, 1, 3, 2, 4);
parity_decide_level!(decide_all_zero_totals, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

// ─────────────────────────────────────────────────────────────────────────────
// Static data
// ─────────────────────────────────────────────────────────────────────────────

const LEVEL_RECS_SCRIPT: &str = r##"
import json, sys
from core.censorship_monitor import LEVEL_RECOMMENDATIONS
p = json.loads(sys.argv[1])
print(json.dumps(LEVEL_RECOMMENDATIONS[p["level"]]))
"##;

macro_rules! parity_level_recommendations {
    ($name:ident, $level:expr) => {
        #[test]
        fn $name() {
            let payload = json!({ "level": $level });
            let py = run_python_json(LEVEL_RECS_SCRIPT, &payload);
            let rs = level_recommendations($level);
            assert_eq!(py, rs);
        }
    };
}

parity_level_recommendations!(level_recs_1, 1);
parity_level_recommendations!(level_recs_2, 2);
parity_level_recommendations!(level_recs_3, 3);
parity_level_recommendations!(level_recs_4, 4);
parity_level_recommendations!(level_recs_5, 5);

const ISP_TIER_SCRIPT: &str = r##"
import json, sys
from core.censorship_monitor import ISP_TIERS
p = json.loads(sys.argv[1])
print(json.dumps(ISP_TIERS.get(p["key"])))
"##;

macro_rules! parity_isp_tier {
    ($name:ident, $key:expr) => {
        #[test]
        fn $name() {
            let payload = json!({ "key": $key });
            let py = run_python_json(ISP_TIER_SCRIPT, &payload);
            let rs = isp_tier_info($key);
            assert_eq!(py, rs);
        }
    };
}

parity_isp_tier!(isp_tier_mci, "mci");
parity_isp_tier!(isp_tier_shatel, "shatel");
parity_isp_tier!(isp_tier_unknown, "unknown");

const CAT_TABLES_SCRIPT: &str = r##"
import json
from core.censorship_monitor import _CAT_A, _CAT_B, _CAT_C, _CAT_D, _CAT_E, _CAT_F
print(json.dumps({
    "a": _CAT_A, "b": _CAT_B, "c": _CAT_C, "d": _CAT_D, "e": _CAT_E, "f": _CAT_F,
}))
"##;

#[test]
fn parity_category_tables_match() {
    let py = run_python_json(CAT_TABLES_SCRIPT, &json!({}));
    use torshield_ir_ultra::censorship_monitor::{CAT_A, CAT_B, CAT_C, CAT_D, CAT_E, CAT_F};
    let as_json = |cat: &[(&str, u16)]| -> Value {
        json!(cat.iter().map(|(h, p)| json!([h, p])).collect::<Vec<_>>())
    };
    assert_eq!(py["a"], as_json(CAT_A));
    assert_eq!(py["b"], as_json(CAT_B));
    assert_eq!(py["c"], as_json(CAT_C));
    assert_eq!(py["d"], as_json(CAT_D));
    assert_eq!(py["e"], as_json(CAT_E));
    assert_eq!(py["f"], as_json(CAT_F));
}

const TIMEOUTS_SCRIPT: &str = r##"
import json
from core.censorship_monitor import _PROBE_TIMEOUT, _FAST_TIMEOUT
print(json.dumps({"probe": _PROBE_TIMEOUT, "fast": _FAST_TIMEOUT}))
"##;

#[test]
fn parity_timeout_constants_match() {
    let py = run_python_json(TIMEOUTS_SCRIPT, &json!({}));
    use torshield_ir_ultra::censorship_monitor::{FAST_TIMEOUT, PROBE_TIMEOUT};
    assert_eq!(py["probe"], json!(PROBE_TIMEOUT));
    assert_eq!(py["fast"], json!(FAST_TIMEOUT));
}

// ─────────────────────────────────────────────────────────────────────────────
// best_transports_for_level / should_use_nin_pack
// ─────────────────────────────────────────────────────────────────────────────

const BEST_TRANSPORTS_SCRIPT: &str = r##"
import json, sys
from core.censorship_monitor import best_transports_for_level
p = json.loads(sys.argv[1])
print(json.dumps(best_transports_for_level(p["level"])))
"##;

macro_rules! parity_best_transports {
    ($name:ident, $level:expr) => {
        #[test]
        fn $name() {
            let payload = json!({ "level": $level });
            let py = run_python_json(BEST_TRANSPORTS_SCRIPT, &payload);
            let rs = best_transports_for_level($level);
            assert_eq!(py, json!(rs));
        }
    };
}

parity_best_transports!(best_transports_level_2, 2);
parity_best_transports!(best_transports_level_5, 5);
parity_best_transports!(best_transports_out_of_range, 42);

const SHOULD_USE_NIN_SCRIPT: &str = r##"
import json, sys
from core.censorship_monitor import should_use_nin_pack
p = json.loads(sys.argv[1])
print(json.dumps(should_use_nin_pack(p["level"])))
"##;

macro_rules! parity_should_use_nin {
    ($name:ident, $level:expr) => {
        #[test]
        fn $name() {
            let payload = json!({ "level": $level });
            let py = run_python_json(SHOULD_USE_NIN_SCRIPT, &payload);
            let rs = should_use_nin_pack($level);
            assert_eq!(py, json!(rs));
        }
    };
}

parity_should_use_nin!(should_use_nin_level_3, 3);
parity_should_use_nin!(should_use_nin_level_4, 4);
parity_should_use_nin!(should_use_nin_level_5, 5);

// ─────────────────────────────────────────────────────────────────────────────
// probe_tcp / probe_category — against local listeners, not real targets
// ─────────────────────────────────────────────────────────────────────────────

const PROBE_TCP_SCRIPT: &str = r##"
import asyncio, json, sys
from core.censorship_monitor import _probe_tcp

p = json.loads(sys.argv[1])

async def main():
    ok, latency_ms = await _probe_tcp(p["host"], p["port"], p["timeout"])
    print(json.dumps({"ok": ok}))

asyncio.run(main())
"##;

#[tokio::test]
async fn parity_probe_tcp_reachable() {
    let (port, _handle) = start_reachable_listener();
    let payload = json!({ "host": "127.0.0.1", "port": port, "timeout": 2.0 });
    let py = run_python_json(PROBE_TCP_SCRIPT, &payload);
    let (ok, _lat) = probe_tcp("127.0.0.1", port, 2.0).await;
    assert_eq!(py["ok"], json!(ok));
    assert!(ok, "expected the local listener to be reachable");
}

#[tokio::test]
async fn parity_probe_tcp_refused() {
    let port = closed_port();
    let payload = json!({ "host": "127.0.0.1", "port": port, "timeout": 2.0 });
    let py = run_python_json(PROBE_TCP_SCRIPT, &payload);
    let (ok, _lat) = probe_tcp("127.0.0.1", port, 2.0).await;
    assert_eq!(py["ok"], json!(ok));
    assert!(!ok, "expected a closed local port to be unreachable");
}

#[tokio::test]
async fn parity_probe_tcp_times_out_on_blocked_egress() {
    // HARNESS PORTABILITY FIX (Session 10): the original target 1.1.1.1:53
    // assumed the sandbox black-holes public egress, but this environment's
    // network layer transparently proxies arbitrary *public* IPs (including
    // RFC5737 TEST-NET ranges) to a fast "connected" result, so 1.1.1.1 and
    // 192.0.2.1 report reachable and the "must time out" assertion was
    // environment-dependent and false here. 10.255.255.1 is an unrouted
    // RFC1918 (private, non-proxied) address that produces a genuine connect
    // timeout in both proxied and bare environments — a portable, real
    // "unreachable via timeout" path. The primary cross-language parity
    // assertion (Rust probe agrees with the Python oracle) is unchanged.
    let payload = json!({ "host": "10.255.255.1", "port": 53, "timeout": 1.2 });
    let py = run_python_json(PROBE_TCP_SCRIPT, &payload);
    let (ok, _lat) = probe_tcp("10.255.255.1", 53, 1.2).await;
    assert_eq!(py["ok"], json!(ok));
    assert!(
        !ok,
        "expected the unroutable target to time out as unreachable"
    );
}

const PROBE_CATEGORY_SCRIPT: &str = r##"
import asyncio, json, sys
from core.censorship_monitor import _probe_category

p = json.loads(sys.argv[1])
targets = [(t[0], t[1]) for t in p["targets"]]

async def main():
    ok, total, results = await _probe_category(p["category"], targets, p["timeout"])
    print(json.dumps({"ok": ok, "total": total}))

asyncio.run(main())
"##;

#[tokio::test]
async fn parity_probe_category_mixed_reachability() {
    let (reachable_port, _handle) = start_reachable_listener();
    let closed1 = closed_port();
    let closed2 = closed_port();
    let targets = vec![
        json!(["127.0.0.1", reachable_port]),
        json!(["127.0.0.1", closed1]),
        json!(["127.0.0.1", closed2]),
    ];
    let payload = json!({ "category": "test_cat", "targets": targets, "timeout": 2.0 });
    let py = run_python_json(PROBE_CATEGORY_SCRIPT, &payload);

    let targets_rs: Vec<(&str, u16)> = vec![
        ("127.0.0.1", reachable_port),
        ("127.0.0.1", closed1),
        ("127.0.0.1", closed2),
    ];
    let (ok, total, _results) = probe_category("test_cat", &targets_rs, 2.0).await;

    assert_eq!(py["ok"], json!(ok));
    assert_eq!(py["total"], json!(total));
    assert_eq!(ok, 1);
    assert_eq!(total, 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// measure_censorship_level — full pipeline against local, controlled targets
// ─────────────────────────────────────────────────────────────────────────────

const MEASURE_WITH_PATCHED_CATEGORIES_SCRIPT: &str = r##"
import asyncio, json, sys
import core.censorship_monitor as cm

p = json.loads(sys.argv[1])

def as_tuples(lst):
    return [(t[0], t[1]) for t in lst]

# Monkeypatch the module-level category tables — this session's
# established technique for injecting controlled, local, deterministic
# targets into a function that doesn't accept them as parameters. See
# src/censorship_monitor.rs module doc comment.
cm._CAT_A = as_tuples(p["cat_a"])
cm._CAT_B = as_tuples(p["cat_b"])
cm._CAT_C = as_tuples(p["cat_c"])
cm._CAT_D = as_tuples(p["cat_d"])
cm._CAT_E = as_tuples(p["cat_e"])
cm._CAT_F = as_tuples(p["cat_f"])

async def main():
    state = await cm.measure_censorship_level(write_state=False)
    d = state.to_dict()
    d.pop("detected_at")  # wall-clock, not comparable
    print(json.dumps(d))

asyncio.run(main())
"##;

fn pair_json(pairs: &[(&str, u16)]) -> Vec<Value> {
    pairs.iter().map(|(h, p)| json!([h, p])).collect()
}

#[tokio::test]
async fn parity_measure_censorship_level_reproduces_a_specific_decision() {
    // Controlled scenario: category A (dns_intl) and B (cdn_https) fully
    // reachable, C/D/E/F all unreachable (closed local ports).
    // a_frac=1.0, c_frac=0.0, d_frac=0.0 satisfies decide_level's THIRD
    // condition (a>=0.25 and c<=0 and d<=0) before ever reaching the
    // c<=0.25 condition further down — verified against live Python
    // after an initial guess of "level 3" here turned out wrong (that
    // guess assumed execution would fall through further than it
    // actually does; c_frac and d_frac both being *exactly* zero, not
    // just low, is what trips the earlier condition). Real answer: 4.
    let (reach_a, _h1) = start_reachable_listener();
    let (reach_b, _h2) = start_reachable_listener();
    let closed_targets: Vec<u16> = (0..12).map(|_| closed_port()).collect();

    let cat_a: Vec<(&str, u16)> = vec![("127.0.0.1", reach_a)];
    let cat_b: Vec<(&str, u16)> = vec![("127.0.0.1", reach_b)];
    let cat_c: Vec<(&str, u16)> = vec![("127.0.0.1", closed_targets[0])];
    let cat_d: Vec<(&str, u16)> = vec![("127.0.0.1", closed_targets[1])];
    let cat_e: Vec<(&str, u16)> = vec![("127.0.0.1", closed_targets[2])];
    let cat_f: Vec<(&str, u16)> = vec![("127.0.0.1", closed_targets[3])];

    let payload = json!({
        "cat_a": pair_json(&cat_a), "cat_b": pair_json(&cat_b),
        "cat_c": pair_json(&cat_c), "cat_d": pair_json(&cat_d),
        "cat_e": pair_json(&cat_e), "cat_f": pair_json(&cat_f),
    });
    let py = run_python_json(MEASURE_WITH_PATCHED_CATEGORIES_SCRIPT, &payload);

    let rs_state = measure_censorship_level_with_categories(
        false,
        &cat_a,
        &cat_b,
        &cat_c,
        &cat_d,
        &cat_e,
        &cat_f,
        std::path::Path::new("/tmp/unused_censorship_state_parity.json"),
    )
    .await
    .unwrap();
    let mut rs_json = rs_state.to_json();
    rs_json.as_object_mut().unwrap().remove("detected_at");

    assert_eq!(py, rs_json);
    assert_eq!(py["level"], json!(4));
}

#[tokio::test]
async fn parity_measure_censorship_level_writes_state_file() {
    let (reach_a, _h1) = start_reachable_listener();
    let cat_a: Vec<(&str, u16)> = vec![("127.0.0.1", reach_a)];
    let closed_targets: Vec<u16> = (0..8).map(|_| closed_port()).collect();
    let empty_cat =
        |i: usize| -> Vec<(&'static str, u16)> { vec![("127.0.0.1", closed_targets[i])] };

    let dir =
        std::env::temp_dir().join(format!("censorship_monitor_parity_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state_path = dir.join("state.json");

    let rs_state = measure_censorship_level_with_categories(
        true,
        &cat_a,
        &empty_cat(0),
        &empty_cat(1),
        &empty_cat(2),
        &empty_cat(3),
        &empty_cat(4),
        &state_path,
    )
    .await
    .unwrap();

    assert!(state_path.exists());
    let loaded = get_last_state(&state_path).unwrap();
    assert_eq!(loaded.level, rs_state.level);
    assert_eq!(loaded.best_pack, rs_state.best_pack);
    let _ = std::fs::remove_dir_all(&dir);
}
