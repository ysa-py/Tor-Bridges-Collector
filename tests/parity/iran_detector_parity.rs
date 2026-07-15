// Parity tests for `src/iran_detector.rs` vs `core/iran_detector.py`.
//
// See `src/iran_detector.rs`'s module doc comment ("This sandbox cannot
// reach any of the real probe targets") before changing the
// network-touching tests below: they deliberately probe local TCP
// listeners this test suite starts and controls, never the real
// `_INTERNATIONAL_PROBES`/`_NIN_PROBES` targets. Both hardcoded NIN IPs
// return an instant, meaningless "reachable" from inside this sandbox
// (one is an RFC 1918 address that can only resolve within this
// sandbox's own container network); neither language's real-target path
// is exercised end-to-end here for that reason.
//
// One Python subtlety worth flagging up front: `_probe_tcp`'s `timeout`
// parameter defaults to `_PROBE_TIMEOUT` evaluated *once, at function
// definition time* (an ordinary Python late-binding gotcha for mutable
// module state used as a default argument). `check_connectivity()` calls
// `_probe_tcp(h, p)` without passing `timeout` explicitly, so
// monkeypatching `_PROBE_TIMEOUT` after import has no effect on it — only
// `_INTERNATIONAL_PROBES`/`_NIN_PROBES` are actually read fresh per call
// and are what the differential tests below patch. Every scenario here
// only needs "connects" vs. "refused", both near-instant against local
// listeners, so this doesn't need working around further.

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use torshield_ir_ultra::iran_detector::{
    check_connectivity_with_targets, probe_tcp, recommend_strategy, NinDetector,
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
    serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|err| panic!("python helper must emit JSON: {err}; stdout={}", result.stdout))
}

/// Starts a local listener that accepts and immediately drops connections
/// (a stand-in "reachable" target), returning its port and a guard that
/// keeps it alive until dropped. Mirrors `censorship_monitor_parity.rs`.
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
// recommend_strategy — pure function, exact parity expected
// ─────────────────────────────────────────────────────────────────────────────

const RECOMMEND_STRATEGY_SCRIPT: &str = r##"
import json, sys
from core._iran_detector_legacy import recommend_strategy

p = json.loads(sys.argv[1])
print(json.dumps({"result": recommend_strategy(p["nin_active"])}))
"##;

#[test]
fn recommend_strategy_nin_active_matches_python() {
    let payload = json!({ "nin_active": true });
    let py = run_python_json(RECOMMEND_STRATEGY_SCRIPT, &payload);
    assert_eq!(py["result"], json!(recommend_strategy(true)));
}

#[test]
fn recommend_strategy_reachable_matches_python() {
    let payload = json!({ "nin_active": false });
    let py = run_python_json(RECOMMEND_STRATEGY_SCRIPT, &payload);
    assert_eq!(py["result"], json!(recommend_strategy(false)));
}

// ─────────────────────────────────────────────────────────────────────────────
// probe_tcp — local listeners only, see header comment
// ─────────────────────────────────────────────────────────────────────────────

const PROBE_TCP_SCRIPT: &str = r##"
import asyncio, json, sys
from core._iran_detector_legacy import _probe_tcp

p = json.loads(sys.argv[1])
ok = asyncio.run(_probe_tcp(p["host"], p["port"], p["timeout"]))
print(json.dumps({"result": ok}))
"##;

#[tokio::test]
async fn probe_tcp_reachable_true() {
    let (port, _guard) = start_reachable_listener();
    assert!(probe_tcp("127.0.0.1", port, 2.0).await);
}

#[tokio::test]
async fn probe_tcp_refused_false() {
    let port = closed_port();
    assert!(!probe_tcp("127.0.0.1", port, 2.0).await);
}

#[tokio::test]
async fn probe_tcp_reachable_matches_python() {
    let (port, _guard) = start_reachable_listener();
    let payload = json!({ "host": "127.0.0.1", "port": port, "timeout": 2.0 });
    let py = run_python_json(PROBE_TCP_SCRIPT, &payload);
    let rust_result = probe_tcp("127.0.0.1", port, 2.0).await;
    assert_eq!(py["result"], json!(rust_result));
    assert!(rust_result);
}

#[tokio::test]
async fn probe_tcp_refused_matches_python() {
    let port = closed_port();
    let payload = json!({ "host": "127.0.0.1", "port": port, "timeout": 2.0 });
    let py = run_python_json(PROBE_TCP_SCRIPT, &payload);
    let rust_result = probe_tcp("127.0.0.1", port, 2.0).await;
    assert_eq!(py["result"], json!(rust_result));
    assert!(!rust_result);
}

// ─────────────────────────────────────────────────────────────────────────────
// check_connectivity_with_targets — aggregation logic, all four branches
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn both_reachable_is_not_nin_active() {
    let (int_port, _g1) = start_reachable_listener();
    let (nin_port, _g2) = start_reachable_listener();
    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;
    assert!(international_ok);
    assert!(!nin_active);
}

#[tokio::test]
async fn only_nin_reachable_is_nin_active() {
    let int_port = closed_port();
    let (nin_port, _g) = start_reachable_listener();
    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;
    assert!(!international_ok);
    assert!(nin_active);
}

#[tokio::test]
async fn only_international_reachable_is_not_nin_active() {
    let (int_port, _g) = start_reachable_listener();
    let nin_port = closed_port();
    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;
    assert!(international_ok);
    assert!(!nin_active);
}

#[tokio::test]
async fn neither_reachable_is_not_nin_active() {
    let int_port = closed_port();
    let nin_port = closed_port();
    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;
    assert!(!international_ok);
    assert!(!nin_active);
}

// ─────────────────────────────────────────────────────────────────────────────
// check_connectivity — full end-to-end differential via Python monkeypatch,
// both languages pointed at the same local listeners (never real targets)
// ─────────────────────────────────────────────────────────────────────────────

const CHECK_CONNECTIVITY_SCRIPT: &str = r##"
import asyncio, json, sys
import core._iran_detector_legacy as m

p = json.loads(sys.argv[1])
m._INTERNATIONAL_PROBES = [tuple(x) for x in p["international"]]
m._NIN_PROBES = [tuple(x) for x in p["nin"]]
international_ok, nin_active = asyncio.run(m.check_connectivity())
print(json.dumps({"international_ok": international_ok, "nin_active": nin_active}))
"##;

#[tokio::test]
async fn check_connectivity_matches_python_when_only_nin_reachable() {
    let int_port = closed_port();
    let (nin_port, _g) = start_reachable_listener();
    let payload = json!({
        "international": [["127.0.0.1", int_port]],
        "nin": [["127.0.0.1", nin_port]],
    });
    let py = run_python_json(CHECK_CONNECTIVITY_SCRIPT, &payload);

    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;

    assert_eq!(py["international_ok"], json!(international_ok));
    assert_eq!(py["nin_active"], json!(nin_active));
    assert!(nin_active);
}

#[tokio::test]
async fn check_connectivity_matches_python_when_both_reachable() {
    let (int_port, _g1) = start_reachable_listener();
    let (nin_port, _g2) = start_reachable_listener();
    let payload = json!({
        "international": [["127.0.0.1", int_port]],
        "nin": [["127.0.0.1", nin_port]],
    });
    let py = run_python_json(CHECK_CONNECTIVITY_SCRIPT, &payload);

    let international = vec![("127.0.0.1", int_port)];
    let nin = vec![("127.0.0.1", nin_port)];
    let (international_ok, nin_active) =
        check_connectivity_with_targets(&international, &nin, 2.0).await;

    assert_eq!(py["international_ok"], json!(international_ok));
    assert_eq!(py["nin_active"], json!(nin_active));
    assert!(!nin_active);
}

// ─────────────────────────────────────────────────────────────────────────────
// NinDetector — record_event, the unguarded-directory-creation contract,
// and the 30s cache / force_refresh contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn record_event_creates_file_and_appends() {
    let dir = std::env::temp_dir().join(format!("torshield-nin-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let events_path = dir.join("nin_events.json");
    let detector = NinDetector::new(&events_path, dir.join("iran_cut_pack.txt"));

    detector.record_event("first", json!({ "n": 1 }));
    let after_first: Value =
        serde_json::from_str(&std::fs::read_to_string(&events_path).unwrap()).unwrap();
    let arr_first = after_first.as_array().expect("must be a JSON array");
    assert_eq!(arr_first.len(), 1);
    assert_eq!(arr_first[0]["kind"], json!("first"));
    assert_eq!(arr_first[0]["details"], json!({ "n": 1 }));
    assert!(arr_first[0]["timestamp"].is_string());

    detector.record_event("second", json!({ "n": 2 }));
    let after_second: Value =
        serde_json::from_str(&std::fs::read_to_string(&events_path).unwrap()).unwrap();
    let arr_second = after_second.as_array().unwrap();
    assert_eq!(arr_second.len(), 2, "second call must append, not overwrite");
    assert_eq!(arr_second[0]["kind"], json!("first"));
    assert_eq!(arr_second[1]["kind"], json!("second"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_event_recovers_from_corrupt_json() {
    let dir = std::env::temp_dir().join(format!("torshield-nin-test-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let events_path = dir.join("nin_events.json");
    std::fs::write(&events_path, "{ this is not valid json").unwrap();

    let detector = NinDetector::new(&events_path, dir.join("iran_cut_pack.txt"));
    detector.record_event("after_corruption", json!({}));

    let contents: Value = serde_json::from_str(&std::fs::read_to_string(&events_path).unwrap()).unwrap();
    let arr = contents.as_array().expect("must recover to a fresh array");
    assert_eq!(arr.len(), 1, "corrupt prior contents must be discarded, not appended to");
    assert_eq!(arr[0]["kind"], json!("after_corruption"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_event_recovers_from_non_array_json() {
    let dir = std::env::temp_dir().join(format!("torshield-nin-test-nonarr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let events_path = dir.join("nin_events.json");
    std::fs::write(&events_path, r#"{"not": "a list"}"#).unwrap();

    let detector = NinDetector::new(&events_path, dir.join("iran_cut_pack.txt"));
    detector.record_event("after_wrong_shape", json!({}));

    let contents: Value = serde_json::from_str(&std::fs::read_to_string(&events_path).unwrap()).unwrap();
    let arr = contents.as_array().expect("must recover to a fresh array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["kind"], json!("after_wrong_shape"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Confirms the deliberate, documented choice in `NinDetector::record_event`:
/// a directory-creation failure is not caught, matching the Python
/// original's unguarded `os.makedirs` call (see that method's doc
/// comment). Forces `ENOTDIR` by pointing the parent directory at a path
/// that is actually a file.
#[test]
fn record_event_directory_creation_failure_panics() {
    let dir = std::env::temp_dir().join(format!("torshield-nin-test-panic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let blocking_file = dir.join("not_a_directory");
    std::fs::write(&blocking_file, b"blocks create_dir_all below it").unwrap();
    let events_path = blocking_file.join("nested").join("nin_events.json");

    let detector = NinDetector::new(events_path, dir.join("iran_cut_pack.txt"));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        detector.record_event("should_not_be_written", json!({}));
    }));
    assert!(
        result.is_err(),
        "record_event must panic when its parent directory cannot be created, matching Python's unguarded os.makedirs"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Real end-to-end probing (no injected targets — `is_nin_active` calls
/// the module-level `check_connectivity()` directly, same as Python, with
/// no seam to inject through), so this genuinely costs the ~3s probe
/// budget twice. Confirmed empirically in this sandbox: international
/// probes reliably time out and both NIN probes reliably connect
/// instantly (see module doc comment), so `is_nin_active` reliably
/// returns `true` here — but this test only relies on the *value staying
/// consistent across calls* and on *timing*, not on which boolean it
/// happens to be, so it would still pass if this sandbox's network
/// characteristics ever changed.
#[test]
fn is_nin_active_caches_within_30s_and_force_refresh_bypasses_it() {
    let dir = std::env::temp_dir().join(format!("torshield-nin-test-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let detector = NinDetector::new(
        dir.join("nin_events.json"),
        dir.join("iran_cut_pack.txt"),
    );

    let t0 = Instant::now();
    let first = detector.is_nin_active(false);
    let first_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let second = detector.is_nin_active(false);
    let second_elapsed = t1.elapsed();

    assert_eq!(first, second, "within 30s, the cached value must be returned");
    assert!(
        second_elapsed < Duration::from_millis(500),
        "a cache hit must not re-probe the network; took {second_elapsed:?}"
    );
    assert!(
        first_elapsed > Duration::from_millis(500),
        "the first, uncached call is expected to actually probe; took {first_elapsed:?}"
    );

    let t2 = Instant::now();
    let _third = detector.is_nin_active(true);
    let third_elapsed = t2.elapsed();
    assert!(
        third_elapsed > Duration::from_millis(500),
        "force_refresh=true must bypass the cache and re-probe; took {third_elapsed:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
