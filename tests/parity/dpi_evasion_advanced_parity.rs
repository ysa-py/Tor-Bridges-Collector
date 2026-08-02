// Parity tests for `src/dpi_evasion_advanced.rs` vs `dpi_evasion_advanced.py`.
//
// Pure functions, no network I/O — straightforward differential testing
// against real Python, same pattern as `iran_dpi_shaper_parity.rs` and
// `ai_anti_dpi_iran_parity.rs`. `update_dpi_report`'s real signature reads
// the wall clock and writes to a fixed path; tested via the
// injectable-time/injectable-path `update_dpi_report` directly (see that
// function's own doc comment for why), passing the same fixed timestamp
// to both languages so the `generated_at` field can be compared exactly
// too, not just excluded from the comparison.

use std::process::Command;

use serde_json::{json, Value};

use torshield_ir_ultra::dpi_evasion_advanced::{dpi_resistance_tier, dpi_score, update_dpi_report};

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

// ─────────────────────────────────────────────────────────────────────────────
// dpi_resistance_tier / dpi_score
// ─────────────────────────────────────────────────────────────────────────────

const TIER_SCRIPT: &str = r##"
import json, sys
from dpi_evasion_advanced import dpi_resistance_tier

p = json.loads(sys.argv[1])
print(json.dumps({"result": dpi_resistance_tier(p["transport"])}))
"##;

#[test]
fn resistance_tier_matches_for_every_known_and_unknown_transport() {
    for transport in [
        "snowflake",
        "webtunnel",
        "obfs4",
        "meek_lite",
        "vanilla",
        "hysteria2",
        "reality",
        "shadowsocks_2022",
        "vless_xtls",
        "SNOWFLAKE",
        "totally-unknown-transport",
    ] {
        let payload = json!({ "transport": transport });
        let py = run_python_json(TIER_SCRIPT, &payload);
        assert_eq!(
            py["result"],
            json!(dpi_resistance_tier(transport)),
            "transport: {transport}"
        );
    }
}

const SCORE_SCRIPT: &str = r##"
import json, sys
from dpi_evasion_advanced import dpi_score

p = json.loads(sys.argv[1])
print(json.dumps({"result": dpi_score(p["record"])}))
"##;

fn assert_score_matches(record: Value) {
    let payload = json!({ "record": record });
    let py = run_python_json(SCORE_SCRIPT, &payload);
    let rs = dpi_score(&record);
    assert_eq!(py["result"], json!(rs), "record: {record}");
}

#[test]
fn dpi_score_snowflake_port_443_with_cdn_bonus() {
    assert_score_matches(json!({
        "transport": "snowflake",
        "port": 443,
        "flags": ["domain_front_cdn_ok"],
    }));
}

#[test]
fn dpi_score_vanilla_on_known_tor_port_with_high_risk_flag() {
    assert_score_matches(json!({
        "transport": "vanilla",
        "port": 9001,
        "flags": ["iran_dpi_high_risk"],
    }));
}

#[test]
fn dpi_score_obfs4_port_80_no_flags() {
    assert_score_matches(json!({ "transport": "obfs4", "port": 80 }));
}

#[test]
fn dpi_score_missing_port_and_flags_default() {
    assert_score_matches(json!({ "transport": "meek_lite" }));
}

#[test]
fn dpi_score_unknown_transport_uses_fallback() {
    assert_score_matches(json!({ "transport": "made_up_transport", "port": 12345 }));
}

#[test]
fn dpi_score_next_gen_transport() {
    assert_score_matches(json!({
        "transport": "hysteria2",
        "port": 443,
        "flags": ["domain_front_cdn_ok"],
    }));
}

#[test]
fn dpi_score_clamps_to_zero_for_worst_case() {
    // vanilla (base 0.10) with the Tor-port penalty (-0.15) and the DPI
    // high-risk penalty (-0.12) drives the raw sum negative; must clamp
    // to 0.0, not go negative, matching Python's `max(0.0, min(1.0, ...))`.
    assert_score_matches(json!({
        "transport": "vanilla",
        "port": 9030,
        "flags": ["iran_dpi_high_risk"],
    }));
}

// ─────────────────────────────────────────────────────────────────────────────
// update_dpi_report
// ─────────────────────────────────────────────────────────────────────────────

const UPDATE_REPORT_SCRIPT: &str = r##"
import json, sys
import dpi_evasion_advanced as m

p = json.loads(sys.argv[1])
# Same injectable-time adaptation as the Rust side: monkeypatch the one
# real-clock read so both languages compare the same `generated_at`.
class _FixedDatetime:
    @staticmethod
    def now(tz=None):
        from datetime import datetime
        return datetime.fromisoformat(p["generated_at"])

m.datetime = _FixedDatetime
m.DPI_INTELLIGENCE_PATH = __import__("pathlib").Path(p["output_path"])

report = m.update_dpi_report(p["records"])
print(json.dumps(report))
"##;

#[test]
fn update_dpi_report_matches_python_with_mixed_records() {
    let dir =
        std::env::temp_dir().join(format!("dpi-evasion-advanced-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let output_path = dir.join("dpi_intelligence.json");

    let records = json!([
        {"transport": "snowflake", "port": 443, "iran_status": "iran_likely_working", "flags": ["domain_front_cdn_ok"]},
        {"transport": "obfs4", "port": 9001, "iran_status": "iran_likely_blocked", "flags": ["iran_dpi_high_risk"]},
        {"transport": "obfs4", "port": 443, "iran_status": "iran_likely_working"},
        {"transport": "vanilla", "port": 9050, "iran_status": "iran_frequently_blocked", "flags": ["iran_dpi_high_risk"]},
    ]);
    let generated_at = "2026-07-11T12:00:00+00:00";

    let payload = json!({
        "records": records,
        "generated_at": generated_at,
        "output_path": output_path.to_string_lossy(),
    });
    let py = run_python_json(UPDATE_REPORT_SCRIPT, &payload);

    let records_vec: Vec<Value> = records.as_array().unwrap().clone();
    let rs = update_dpi_report(&records_vec, generated_at, &output_path).unwrap();

    assert_eq!(py, rs);

    // Confirm the report was genuinely written to disk, not just returned.
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).unwrap()).unwrap();
    assert_eq!(on_disk, rs);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn update_dpi_report_empty_records_is_profile_only() {
    let dir = std::env::temp_dir().join(format!(
        "dpi-evasion-advanced-test-empty-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let output_path = dir.join("dpi_intelligence.json");
    let generated_at = "2026-01-01T00:00:00+00:00";

    let payload = json!({
        "records": [],
        "generated_at": generated_at,
        "output_path": output_path.to_string_lossy(),
    });
    let py = run_python_json(UPDATE_REPORT_SCRIPT, &payload);

    let rs = update_dpi_report(&[], generated_at, &output_path).unwrap();
    assert_eq!(py, rs);
    assert_eq!(rs["total_bridges_analyzed"], json!(0));
    assert_eq!(rs["empirical_stats"], json!({}));

    let _ = std::fs::remove_dir_all(&dir);
}
