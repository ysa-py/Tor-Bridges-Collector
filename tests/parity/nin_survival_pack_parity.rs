#![allow(warnings)]
// Parity tests for `src/nin_survival_pack.rs` vs `core/nin_survival_pack.py`.
//
// Follows the JSON-payload-via-argv pattern established in
// `nin_selector_parity.rs`: Python driver scripts are inline `-c` strings,
// data is passed as one JSON blob via `sys.argv[1]`, output compared as
// parsed `serde_json::Value` (order-insensitive for objects).
//
// The live `core.iran_detector.NINDetector` import succeeds in this
// environment (nest_asyncio is installed), so by default
// `NINSurvivalPack()._detector` is a real, non-None object and
// `detect_nin_state()`/`get_status()` would exercise the *live-detector*
// branch — not the branch this Rust port implements today (see
// `src/nin_survival_pack.rs` module doc comment). Driver scripts that
// exercise `detect_nin_state`/`get_status` explicitly force
// `_NIN_DETECTOR_AVAILABLE = False` before constructing the object, to
// compare against the same fallback branch this port takes, rather than
// against a branch this port deliberately doesn't implement yet. This is
// forcing a real, Python-defined code path (the module's own
// import-failure fallback), not fabricating new behavior.
//
// Coverage:
// * `generate_pack`: transport filtering, `setdefault`-vs-overwrite
//   (including the explicit-obfs4+port-443 case where the emitted
//   `transport` field and the internal priority bump disagree), both
//   port-defaulting rules (falsy-or vs missing-only), the null-port
//   silent-skip-bonus path, the IPv4 bonus, sort order including ties,
//   and the non-numeric-sort-key whole-call failure.
// * `export_pack`: header shape, bridge-line passthrough vs.
//   `_format_bridge_line` fallback, dedup-free multi-line output.
// * `detect_nin_state`/`get_status` against the forced no-detector
//   branch.

use std::path::Path;
use std::process::Command;

use serde_json::{json, Map, Value};

use torshield_ir_ultra::nin_survival_pack::{
    is_nin_capable, normalize_transport, NinSurvivalPack, NIN_TRANSPORT_PRIORITIES,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

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

fn as_map(v: &Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// generate_pack
// ─────────────────────────────────────────────────────────────────────────────

const GENERATE_PACK_SCRIPT: &str = r##"
import json, sys
from core.nin_survival_pack import NINSurvivalPack

payload = json.loads(sys.argv[1])
pack = NINSurvivalPack()
result = pack.generate_pack(payload["bridges"])
print(json.dumps(result))
"##;

fn python_generate_pack(bridges: &[Value]) -> PythonResult {
    let payload = json!({ "bridges": bridges });
    run_python_script(GENERATE_PACK_SCRIPT, &payload)
}

macro_rules! parity_generate_pack {
    ($name:ident, $bridges:expr) => {
        #[test]
        fn $name() {
            let bridges_json: Vec<Value> = $bridges;
            let py = python_generate_pack(&bridges_json);
            assert!(py.success, "python call failed unexpectedly: {}", py.stderr);
            let py_value: Value =
                serde_json::from_str(py.stdout.trim()).expect("python must emit JSON");

            let bridges_rs: Vec<Map<String, Value>> = bridges_json.iter().map(as_map).collect();
            let mut pack = NinSurvivalPack::default();
            let rs_value = pack
                .generate_pack(&bridges_rs)
                .expect("rust call must succeed");

            assert_eq!(py_value, json!(rs_value));
        }
    };
}

parity_generate_pack!(empty_input_yields_empty_output, vec![]);

parity_generate_pack!(
    filters_non_nin_capable_transports,
    vec![
        json!({"transport": "vanilla"}),
        json!({"transport": "obfs4"}),
        json!({"transport": "snowflake"}),
    ]
);

parity_generate_pack!(
    setdefault_preserves_original_transport_casing,
    vec![json!({"transport": "Snowflake"})]
);

parity_generate_pack!(
    missing_transport_gets_normalized_value_inserted,
    vec![json!({"bridge_line": "bridge webtunnel 5.6.7.8:443 ff00"})]
);

parity_generate_pack!(
    explicit_obfs4_with_port_443_keeps_label_but_bumps_priority,
    vec![json!({"transport": "obfs4", "port": 443})]
);

parity_generate_pack!(
    webtunnel_port_443_bonus_floors_at_one,
    vec![
        json!({"transport": "snowflake", "port": 443}),
        json!({"transport": "webtunnel", "port": 443}),
    ]
);

parity_generate_pack!(
    null_port_present_skips_bonus_but_keeps_entry,
    vec![json!({"transport": "webtunnel", "port": null})]
);

parity_generate_pack!(
    missing_port_key_defaults_to_zero_no_bonus,
    vec![json!({"transport": "webtunnel"})]
);

parity_generate_pack!(
    string_port_443_bonus_applies,
    vec![json!({"transport": "webtunnel", "port": "443"})]
);

parity_generate_pack!(
    non_numeric_string_port_skips_bonus_silently,
    vec![json!({"transport": "webtunnel", "port": "not-a-port"})]
);

parity_generate_pack!(
    ipv4_address_gets_bonus_ipv6_does_not,
    vec![
        json!({"transport": "snowflake", "address": "1.2.3.4"}),
        json!({"transport": "snowflake", "address": "2001:db8::1"}),
        json!({"transport": "snowflake", "ip": "9.9.9.9"}),
    ]
);

parity_generate_pack!(
    sort_by_priority_then_score_then_last_seen_with_ties,
    vec![
        json!({"transport": "obfs4", "iran_score": 0.9}),
        json!({"transport": "snowflake", "iran_score": 0.1}),
        json!({"transport": "snowflake", "iran_score": 0.8}),
        json!({"transport": "webtunnel", "iran_score": 0.5, "last_seen_ts": 100.0}),
        json!({"transport": "webtunnel", "iran_score": 0.5, "last_seen_ts": 200.0}),
    ]
);

parity_generate_pack!(
    score_falls_back_to_score_field_then_zero,
    vec![
        json!({"transport": "snowflake", "score": 0.7}),
        json!({"transport": "obfs4"}),
    ]
);

parity_generate_pack!(
    non_string_bridge_line_bridge_is_silently_dropped,
    vec![
        json!({"bridge_line": {"nested": true}}),
        json!({"transport": "snowflake"}),
    ]
);

parity_generate_pack!(
    original_fields_are_preserved_in_output,
    vec![json!({
        "transport": "snowflake",
        "custom_field": "kept",
        "nested": {"a": 1},
    })]
);

// Non-numeric sort key: whole-call failure on both sides.
#[test]
fn parity_non_numeric_score_fails_whole_call_both_sides() {
    let bridges_json = vec![json!({"transport": "snowflake", "iran_score": "not-a-number"})];
    let py = python_generate_pack(&bridges_json);
    assert!(!py.success, "python was expected to raise but didn't");

    let bridges_rs: Vec<Map<String, Value>> = bridges_json.iter().map(as_map).collect();
    let mut pack = NinSurvivalPack::default();
    assert!(pack.generate_pack(&bridges_rs).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// export_pack
// ─────────────────────────────────────────────────────────────────────────────

const EXPORT_PACK_SCRIPT: &str = r##"
import json, sys, re
from core.nin_survival_pack import NINSurvivalPack

payload = json.loads(sys.argv[1])
pack = NINSurvivalPack(export_path=payload["export_path"])
pack.generate_pack(payload["bridges"])
pack.export_pack()
with open(payload["export_path"]) as fh:
    content = fh.read()
# Strip the wall-clock-dependent "# Generated:" line before comparing —
# not reproducible between two independent process runs.
content = re.sub(r"^# Generated:.*$", "# Generated: STRIPPED", content, flags=re.MULTILINE)
print(json.dumps({"content": content}))
"##;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nin_survival_pack_parity_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn strip_generated_line(content: &str) -> String {
    content
        .lines()
        .map(|l| {
            if l.starts_with("# Generated:") {
                "# Generated: STRIPPED".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn parity_export_pack_with_bridge_lines_and_fallback_formatting() {
    let dir = temp_dir("export1");
    let export_path = dir.join("pack.txt");
    let bridges = vec![
        json!({"transport": "snowflake", "bridge_line": "bridge snowflake 1.2.3.4:443 abcd"}),
        json!({
            "transport": "webtunnel",
            "address": "9.9.9.9",
            "port": 443,
            "fingerprint": "DEADBEEF",
        }),
    ];

    let payload = json!({
        "export_path": export_path.to_str().unwrap(),
        "bridges": bridges,
    });
    let py_value = run_python_json(EXPORT_PACK_SCRIPT, &payload);
    let py_content = py_value["content"].as_str().unwrap().to_string();

    let bridges_rs: Vec<Map<String, Value>> = bridges.iter().map(as_map).collect();
    let mut pack = NinSurvivalPack::new(export_path.to_str().unwrap(), "unused.json");
    pack.generate_pack(&bridges_rs).unwrap();
    pack.export_pack(None).unwrap();
    let rs_content = std::fs::read_to_string(&export_path).unwrap();
    let rs_stripped = strip_generated_line(&rs_content);

    assert_eq!(py_content, rs_stripped);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parity_export_pack_empty_pack_still_writes_header() {
    let dir = temp_dir("export2");
    let export_path = dir.join("pack.txt");

    let payload = json!({
        "export_path": export_path.to_str().unwrap(),
        "bridges": Vec::<Value>::new(),
    });
    let py_value = run_python_json(EXPORT_PACK_SCRIPT, &payload);
    let py_content = py_value["content"].as_str().unwrap().to_string();

    let mut pack = NinSurvivalPack::new(export_path.to_str().unwrap(), "unused.json");
    pack.generate_pack(&[]).unwrap();
    pack.export_pack(None).unwrap();
    let rs_content = std::fs::read_to_string(&export_path).unwrap();
    let rs_stripped = strip_generated_line(&rs_content);

    assert_eq!(py_content, rs_stripped);
    let _ = std::fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_nin_state / get_status — forced no-detector branch
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_NO_DETECTOR_SCRIPT: &str = r##"
import json, sys
import core.nin_survival_pack as nsp

# Force the same fallback branch this Rust port takes unconditionally —
# see src/nin_survival_pack.rs module doc comment.
nsp._NIN_DETECTOR_AVAILABLE = False
pack = nsp.NINSurvivalPack()
result = {
    "detect_nin_state": pack.detect_nin_state(),
    "status": pack.get_status(),
}
print(json.dumps(result, default=str))
"##;

#[test]
fn parity_detect_nin_state_and_status_no_detector_branch() {
    let py_value = run_python_json(STATUS_NO_DETECTOR_SCRIPT, &json!({}));

    // `default()`/`new()` now construct a real detector (Session 9 wired
    // `iran_detector.rs` up) — `without_detector` is the explicit
    // constructor for this still-real, still-reachable Python branch. See
    // `src/nin_survival_pack.rs`'s module doc comment.
    let pack =
        NinSurvivalPack::without_detector("export/iran_cut_pack.txt", "data/nin_events.json");
    assert_eq!(py_value["detect_nin_state"], json!(pack.detect_nin_state()));

    let py_status = &py_value["status"];
    let rs_status = pack.get_status();
    assert_eq!(py_status["engine"], rs_status["engine"]);
    assert_eq!(
        py_status["nin_detector_available"],
        rs_status["nin_detector_available"]
    );
    assert_eq!(py_status["nin_active"], rs_status["nin_active"]);
    assert_eq!(py_status["last_pack_size"], rs_status["last_pack_size"]);
    assert_eq!(
        py_status["transport_priorities"],
        rs_status["transport_priorities"]
    );
    assert_eq!(py_status["export_path"], rs_status["export_path"]);
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_nin_state / get_status — real detector branch (Session 9)
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_WITH_DETECTOR_SCRIPT: &str = r##"
import json, sys
import core.nin_survival_pack as nsp

# Default construction — real NINDetector, same as this Rust port's
# `new`/`default` now that `iran_detector.rs` exists. Both sides do their
# own independent real network probing in this sandbox; see
# src/iran_detector.rs's module doc comment for why that's expected to be
# deterministic here (both NIN targets connect instantly, both
# international targets time out), not flaky.
p = json.loads(sys.argv[1])
pack = nsp.NINSurvivalPack(events_path=p["events_path"])
result = {
    "detect_nin_state": pack.detect_nin_state(),
    "status": pack.get_status(),
}
print(json.dumps(result, default=str))
"##;

#[test]
fn parity_detect_nin_state_and_status_with_real_detector() {
    let dir = std::env::temp_dir().join(format!(
        "torshield-survival-pack-parity-detector-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let events_path = dir.join("nin_events.json");

    let payload = json!({ "events_path": events_path.to_string_lossy() });
    let py_value = run_python_json(STATUS_WITH_DETECTOR_SCRIPT, &payload);

    let pack = NinSurvivalPack::new(
        "export/iran_cut_pack.txt",
        events_path.to_string_lossy().to_string(),
    );
    assert_eq!(py_value["detect_nin_state"], json!(pack.detect_nin_state()));

    let py_status = &py_value["status"];
    let rs_status = pack.get_status();
    assert_eq!(
        py_status["nin_detector_available"],
        rs_status["nin_detector_available"]
    );
    assert_eq!(py_status["nin_detector_available"], json!(true));
    assert_eq!(py_status["nin_active"], rs_status["nin_active"]);

    let _ = std::fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Module-level constants / pure functions
// ─────────────────────────────────────────────────────────────────────────────

const PRIORITIES_SCRIPT: &str = r##"
import json
from core.nin_survival_pack import NIN_TRANSPORT_PRIORITIES
print(json.dumps(NIN_TRANSPORT_PRIORITIES))
"##;

#[test]
fn parity_transport_priorities_table_matches() {
    let py_value = run_python_json(PRIORITIES_SCRIPT, &json!({}));
    let py_map = py_value.as_object().unwrap();

    for (k, v) in py_map {
        let expected = v.as_i64().unwrap();
        let actual = NIN_TRANSPORT_PRIORITIES
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, val)| *val);
        assert_eq!(actual, Some(expected), "mismatch for key {k}");
    }
    assert_eq!(py_map.len(), NIN_TRANSPORT_PRIORITIES.len());
}

const NORMALIZE_SCRIPT: &str = r##"
import json, sys
from core.nin_survival_pack import _normalize_transport

payload = json.loads(sys.argv[1])
result = _normalize_transport(payload["bridge"])
print(json.dumps(result))
"##;

macro_rules! parity_normalize {
    ($name:ident, $bridge:expr) => {
        #[test]
        fn $name() {
            let bridge_json = $bridge;
            let payload = json!({ "bridge": bridge_json });
            let py = run_python_script(NORMALIZE_SCRIPT, &payload);
            assert!(py.success, "python call failed: {}", py.stderr);
            let py_value: String =
                serde_json::from_str(py.stdout.trim()).expect("python must emit a JSON string");
            let rs_value = normalize_transport(&as_map(&bridge_json)).expect("rust must succeed");
            assert_eq!(py_value, rs_value);
        }
    };
}

parity_normalize!(
    normalize_plain_transport_field,
    json!({"transport": "obfs4"})
);
parity_normalize!(
    normalize_transport_type_field,
    json!({"transport_type": "meek-lite"})
);
parity_normalize!(normalize_type_field, json!({"type": "SNOWFLAKE"}));
parity_normalize!(
    normalize_obfs4_port_443_becomes_obfs4_443,
    json!({"transport": "obfs4", "port": 443})
);
parity_normalize!(
    normalize_obfs4_string_port_443,
    json!({"transport": "obfs4", "port": "443"})
);
parity_normalize!(
    normalize_falls_back_to_bridge_line_prefix,
    json!({"bridge_line": "bridge meek-lite 1.1.1.1:443 aa"})
);
parity_normalize!(
    normalize_falls_back_to_line_field,
    json!({"line": "bridge obfs4 2.2.2.2:9001 bb"})
);
parity_normalize!(normalize_empty_bridge_yields_empty_string, json!({}));

#[test]
fn parity_is_nin_capable_matches_priority_table_membership() {
    for t in [
        "snowflake",
        "webtunnel",
        "meek_lite",
        "meek-lite",
        "obfs4_443",
        "obfs4",
        "vanilla",
        "",
    ] {
        let script = format!(
            r##"
import json
from core.nin_survival_pack import _is_nin_capable
print(json.dumps(_is_nin_capable({t:?})))
"##
        );
        let py = run_python_json(&script, &json!({}));
        assert_eq!(py, json!(is_nin_capable(t)), "mismatch for transport {t}");
    }
}

// Sanity: no path in this file should ever try to load a real path via
// `Path::new` incorrectly — keep the import used to avoid an unused-import
// warning if future edits remove the one live usage above.
#[allow(dead_code)]
fn _unused_path_import_anchor(p: &Path) -> bool {
    p.exists()
}
