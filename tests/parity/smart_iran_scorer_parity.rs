// Parity tests for `src/smart_iran_scorer.rs` vs `core/smart_iran_scorer.py`.
//
// See `src/smart_iran_scorer.rs`'s module doc comment, section "Inherited
// from `scorer.rs`", before changing the `base_score`/`score_record`
// tests below — they deliberately monkeypatch Python's
// `IranScorer._ja3_penalty` to `0` so the comparison isolates this
// module's own logic from an already-disclosed, differently-scoped gap
// in `scorer.rs`. One test (`measures_real_world_ja3_gap_unpatched`)
// deliberately does NOT patch, to keep the real-world gap size a
// documented, checked number rather than just a comment.

use std::process::Command;

use serde_json::{json, Map, Value};

use torshield_ir_ultra::smart_iran_scorer::{extract_endpoint, SmartIranScorer};

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

// Shared preamble for every driver script below.
//
// SESSION 10: this used to monkeypatch `IranScorer._ja3_penalty` to `0` to
// match `scorer.rs`'s old ja3 *stub*. That stub is gone — `scorer.rs` now
// wires `IranScorer::ja3_penalty` to the fully-ported
// `ja3_intelligence::JA3Intel`, so the Rust base score matches Python's
// real ja3 heuristic byte-for-byte with NO patching. The preamble is kept
// (empty) so the driver scripts and the `_ja3_patched` test names remain
// stable, but it no longer alters Python behavior; the comparison now runs
// real-vs-real. See `measures_real_world_ja3_gap_unpatched` (now a
// parity/closed-gap assertion) and the module doc comment.
const JA3_PATCH_PREAMBLE: &str = "";

// ─────────────────────────────────────────────────────────────────────────────
// Pure signal functions — no scorer.rs dependency, exact parity expected
// ─────────────────────────────────────────────────────────────────────────────

const EXTRACT_ENDPOINT_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import _extract_endpoint

payload = json.loads(sys.argv[1])
host, port, transport = _extract_endpoint(payload["raw"])
print(json.dumps({"host": host, "port": port, "transport": transport}))
"##;

macro_rules! parity_extract_endpoint {
    ($name:ident, $raw:expr) => {
        #[test]
        fn $name() {
            let raw: &str = $raw;
            let payload = json!({ "raw": raw });
            let py = run_python_json(EXTRACT_ENDPOINT_SCRIPT, &payload);
            let (host, port, transport) = extract_endpoint(raw);
            assert_eq!(py["host"], json!(host));
            assert_eq!(py["port"], json!(port));
            assert_eq!(py["transport"], json!(transport));
        }
    };
}

parity_extract_endpoint!(
    endpoint_snowflake_basic,
    "bridge snowflake 1.2.3.4:443 abcd"
);
parity_extract_endpoint!(
    endpoint_obfs4_override_wins_over_other_regex_match,
    "webtunnel-ish but really obfs4 1.1.1.1:9001"
);
parity_extract_endpoint!(
    endpoint_underscore_blocks_word_boundary_but_override_fires,
    "bridge_obfs4_test 1.1.1.1:1"
);
parity_extract_endpoint!(endpoint_no_ip_present, "obfs4 no address here");
parity_extract_endpoint!(endpoint_unknown_transport, "some random line 8.8.8.8:53");
parity_extract_endpoint!(
    endpoint_meek_lite_case_insensitive,
    "Bridge MEEK_LITE 9.9.9.9:2083 ff"
);
parity_extract_endpoint!(endpoint_vanilla, "bridge vanilla 5.5.5.5:9001 aa");
parity_extract_endpoint!(
    endpoint_multiple_ip_ports_takes_first,
    "1.1.1.1:1 then 2.2.2.2:2 snowflake"
);

const NIN_SIGNAL_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer()
print(json.dumps(s._nin_signal(payload["record"])))
"##;

macro_rules! parity_nin_signal {
    ($name:ident, $record:expr) => {
        #[test]
        fn $name() {
            let record_json = $record;
            let payload = json!({ "record": record_json });
            let py = run_python_json(NIN_SIGNAL_SCRIPT, &payload);

            let scorer = SmartIranScorer::default();
            let record = as_map(&record_json);
            let rs = scorer.nin_signal(&record);
            assert_eq!(py.as_f64().unwrap(), rs);
        }
    };
}

parity_nin_signal!(
    nin_signal_snowflake_good_port_no_asn,
    json!({"raw": "bridge snowflake 1.2.3.4:443 abcd"})
);
parity_nin_signal!(
    nin_signal_vanilla_bad_port,
    json!({"raw": "bridge vanilla 1.2.3.4:9001 abcd"})
);
parity_nin_signal!(
    nin_signal_with_cdn_asn_bonus,
    json!({"raw": "bridge webtunnel 1.2.3.4:443 abcd", "asn": "AS13335"})
);
parity_nin_signal!(
    nin_signal_unknown_asn_no_bonus,
    json!({"raw": "bridge webtunnel 1.2.3.4:443 abcd", "asn": "AS99999"})
);

const DPI_SIGNAL_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer()
print(json.dumps(s._dpi_signal(payload["record"])))
"##;

macro_rules! parity_dpi_signal {
    ($name:ident, $record:expr) => {
        #[test]
        fn $name() {
            let record_json = $record;
            let payload = json!({ "record": record_json });
            let py = run_python_json(DPI_SIGNAL_SCRIPT, &payload);

            let scorer = SmartIranScorer::default();
            let record = as_map(&record_json);
            let rs = scorer.dpi_signal(&record);
            assert_eq!(py.as_f64().unwrap(), rs);
        }
    };
}

parity_dpi_signal!(
    dpi_signal_snowflake,
    json!({"raw": "bridge snowflake 1.2.3.4:443 abcd"})
);
parity_dpi_signal!(
    dpi_signal_vanilla,
    json!({"raw": "bridge vanilla 1.2.3.4:9001 abcd"})
);
parity_dpi_signal!(
    dpi_signal_unrecognized_transport,
    json!({"raw": "no transport keyword 1.1.1.1:1"})
);

const PORT_SIGNAL_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer()
print(json.dumps(s._port_signal(payload["port"])))
"##;

macro_rules! parity_port_signal {
    ($name:ident, $port:expr) => {
        #[test]
        fn $name() {
            let port: i64 = $port;
            let payload = json!({ "port": port });
            let py = run_python_json(PORT_SIGNAL_SCRIPT, &payload);

            let scorer = SmartIranScorer::default();
            let rs = scorer.port_signal(port);
            assert_eq!(py.as_f64().unwrap(), rs);
        }
    };
}

parity_port_signal!(port_signal_443, 443);
parity_port_signal!(port_signal_8080, 8080);
parity_port_signal!(port_signal_unlisted, 12345);

const LEVEL_MODIFIER_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level=payload["level"])
print(json.dumps(s._level_modifier(payload["transport"])))
"##;

macro_rules! parity_level_modifier {
    ($name:ident, $level:expr, $transport:expr) => {
        #[test]
        fn $name() {
            let level: i64 = $level;
            let transport: &str = $transport;
            let payload = json!({ "level": level, "transport": transport });
            let py = run_python_json(LEVEL_MODIFIER_SCRIPT, &payload);

            let scorer = SmartIranScorer::new(level, false, 35.0, 70.0);
            let rs = scorer.level_modifier(transport);
            assert_eq!(py.as_f64().unwrap(), rs);
        }
    };
}

parity_level_modifier!(level_mod_level1_no_boost_table, 1, "snowflake");
parity_level_modifier!(level_mod_level4_snowflake_boost, 4, "snowflake");
parity_level_modifier!(level_mod_level4_obfs4_penalty, 4, "obfs4");
parity_level_modifier!(level_mod_level4_unlisted_transport, 4, "meek_lite");
parity_level_modifier!(level_mod_level5_meek_lite_boost, 5, "meek_lite");
parity_level_modifier!(level_mod_level5_vanilla_penalty, 5, "vanilla");
parity_level_modifier!(level_mod_clamped_level_zero_to_one, 0, "snowflake");
parity_level_modifier!(level_mod_clamped_level_ten_to_five, 10, "snowflake");

// ─────────────────────────────────────────────────────────────────────────────
// score_record / score_all — JA3-patched (see module doc comment)
// ─────────────────────────────────────────────────────────────────────────────

fn score_record_script(level: i64) -> String {
    format!(
        r##"
import json, sys
{JA3_PATCH_PREAMBLE}
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level={level})
bs = s.score_record(payload["record"])
print(json.dumps({{
    "bridge_id": bs.bridge_id,
    "transport": bs.transport,
    "port": bs.port,
    "base_score": bs.base_score,
    "nin_score": bs.nin_score,
    "dpi_score": bs.dpi_score,
    "port_score": bs.port_score,
    "level_mod": bs.level_mod,
    "final_score": bs.final_score,
    "ai_refined": bs.ai_refined,
    "ai_score": bs.ai_score,
    "tier": bs.tier,
    "recommendation": bs.recommendation,
    "raw": bs.raw,
}}))
"##
    )
}

macro_rules! parity_score_record {
    ($name:ident, $level:expr, $record:expr) => {
        #[test]
        fn $name() {
            let level: i64 = $level;
            let record_json = $record;
            let payload = json!({ "record": record_json });
            let script = score_record_script(level);
            let py = run_python_json(&script, &payload);

            let scorer = SmartIranScorer::new(level, false, 35.0, 70.0);
            let record = as_map(&record_json);
            let rs = scorer.score_record(&record);

            assert_eq!(py["bridge_id"], rs.bridge_id, "bridge_id");
            assert_eq!(py["transport"], json!(rs.transport), "transport");
            assert_eq!(py["port"], json!(rs.port), "port");
            assert_eq!(py["base_score"], json!(rs.base_score), "base_score");
            assert_eq!(py["nin_score"], json!(rs.nin_score), "nin_score");
            assert_eq!(py["dpi_score"], json!(rs.dpi_score), "dpi_score");
            assert_eq!(py["port_score"], json!(rs.port_score), "port_score");
            assert_eq!(py["level_mod"], json!(rs.level_mod), "level_mod");
            assert_eq!(py["final_score"], json!(rs.final_score), "final_score");
            assert_eq!(py["ai_refined"], json!(rs.ai_refined), "ai_refined");
            assert_eq!(py["tier"], json!(rs.tier.as_str()), "tier");
            assert_eq!(
                py["recommendation"],
                json!(rs.recommendation.as_str()),
                "recommendation"
            );
            assert_eq!(py["raw"], json!(rs.raw), "raw");
        }
    };
}

parity_score_record!(
    score_record_snowflake_level4_ja3_patched,
    4,
    json!({"raw": "bridge snowflake 1.2.3.4:443 abcd"})
);
parity_score_record!(
    score_record_vanilla_level3_ja3_patched,
    3,
    json!({"raw": "bridge vanilla 1.2.3.4:9001 abcd"})
);
parity_score_record!(
    score_record_obfs4_level5_ja3_patched,
    5,
    json!({"raw": "bridge obfs4 8.8.8.8:9050 ffff"})
);
parity_score_record!(
    score_record_with_explicit_first_seen_and_test_pass,
    3,
    json!({
        "raw": "bridge webtunnel 2.2.2.2:443 aa",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "test_pass": true,
        "asn": "AS13335",
    })
);
parity_score_record!(
    score_record_fingerprint_present_as_null_kept_not_defaulted,
    3,
    json!({"raw": "x", "fingerprint": Value::Null, "id": "ID1"})
);
parity_score_record!(
    score_record_no_fingerprint_or_id_falls_back_to_raw_prefix,
    3,
    json!({"raw": "hello world"})
);

fn score_all_script(level: i64) -> String {
    format!(
        r##"
import json, sys
{JA3_PATCH_PREAMBLE}
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level={level})
results = s.score_all(payload["records"])
print(json.dumps([
    {{"transport": r.transport, "final_score": r.final_score, "bridge_id": r.bridge_id}}
    for r in results
]))
"##
    )
}

#[test]
fn parity_score_all_sorts_descending_stable_ja3_patched() {
    let records = vec![
        json!({"raw": "bridge obfs4 1.1.1.1:1 a", "id": "obfs4-1"}),
        json!({"raw": "bridge snowflake 1.1.1.1:443 b", "id": "snow-1"}),
        json!({"raw": "bridge obfs4 1.1.1.1:1 c", "id": "obfs4-2"}), // tie with obfs4-1
        json!({"raw": "bridge vanilla 1.1.1.1:1 d", "id": "van-1"}),
    ];
    let payload = json!({ "records": records });
    let script = score_all_script(3);
    let py = run_python_json(&script, &payload);

    let scorer = SmartIranScorer::new(3, false, 35.0, 70.0);
    let records_rs: Vec<Map<String, Value>> = records.iter().map(as_map).collect();
    let results = scorer.score_all(&records_rs);
    let rs_json: Vec<Value> = results
        .iter()
        .map(|r| json!({"transport": r.transport, "final_score": r.final_score, "bridge_id": r.bridge_id}))
        .collect();

    assert_eq!(py, json!(rs_json));
}

// ─────────────────────────────────────────────────────────────────────────────
// top_bridges
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_top_bridges_filters_score_and_transport() {
    let script = format!(
        r##"
import json, sys
{JA3_PATCH_PREAMBLE}
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level=3)
results = s.score_all(payload["records"])
top = s.top_bridges(results, n=2, min_score=0.0, transports=["snowflake", "obfs4"])
print(json.dumps([{{"transport": r.transport, "final_score": r.final_score}} for r in top]))
"##
    );

    let records = vec![
        json!({"raw": "bridge snowflake 1.1.1.1:443 a"}),
        json!({"raw": "bridge obfs4 1.1.1.1:1 b"}),
        json!({"raw": "bridge vanilla 1.1.1.1:1 c"}),
    ];
    let payload = json!({ "records": records });
    let py = run_python_json(&script, &payload);

    let scorer = SmartIranScorer::new(3, false, 35.0, 70.0);
    let records_rs: Vec<Map<String, Value>> = records.iter().map(as_map).collect();
    let results = scorer.score_all(&records_rs);
    let transports = vec!["snowflake".to_string(), "obfs4".to_string()];
    let top = scorer.top_bridges(&results, 2, 0.0, Some(&transports));
    let rs_json: Vec<Value> = top
        .iter()
        .map(|r| json!({"transport": r.transport, "final_score": r.final_score}))
        .collect();

    assert_eq!(py, json!(rs_json));
}

// ─────────────────────────────────────────────────────────────────────────────
// write_report / export_bridge_lines
// ─────────────────────────────────────────────────────────────────────────────

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "smart_iran_scorer_parity_{tag}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn parity_write_report_structure_matches() {
    let dir = temp_dir("report");
    let report_path = dir.join("report.json");

    let script = format!(
        r##"
import json, sys
{JA3_PATCH_PREAMBLE}
from core.smart_iran_scorer import SmartIranScorer
from pathlib import Path

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level=3)
results = s.score_all(payload["records"])
s.write_report(results, Path(payload["path"]))
print(Path(payload["path"]).read_text())
"##
    );

    let records = vec![
        json!({"raw": "bridge snowflake 1.1.1.1:443 a"}),
        json!({"raw": "bridge vanilla 1.1.1.1:1 b"}),
    ];
    let payload = json!({ "records": records, "path": report_path.to_str().unwrap() });
    let py = run_python_script(&script, &payload);
    assert!(py.success, "python failed: {}", py.stderr);
    let py_report: Value = serde_json::from_str(py.stdout.trim()).unwrap();

    let scorer = SmartIranScorer::new(3, false, 35.0, 70.0);
    let records_rs: Vec<Map<String, Value>> = records.iter().map(as_map).collect();
    let results = scorer.score_all(&records_rs);
    let rs_report_path = dir.join("report_rs.json");
    scorer
        .write_report(&results, Some(&rs_report_path))
        .unwrap();
    let rs_report: Value =
        serde_json::from_str(&std::fs::read_to_string(&rs_report_path).unwrap()).unwrap();

    assert_eq!(py_report, rs_report);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parity_export_bridge_lines_content_and_count() {
    let dir = temp_dir("export");
    let export_path = dir.join("sub").join("best.txt");

    let script = format!(
        r##"
import json, sys
{JA3_PATCH_PREAMBLE}
from core.smart_iran_scorer import SmartIranScorer
from pathlib import Path

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level=3)
results = s.score_all(payload["records"])
n = s.export_bridge_lines(results, Path(payload["path"]), n=50, min_score=0.0)
print(json.dumps({{"n": n, "content": Path(payload["path"]).read_text()}}))
"##
    );

    let records = vec![
        json!({"raw": "bridge snowflake 1.1.1.1:443 a"}),
        json!({"raw": "  "}), // blank raw after strip -> excluded
    ];
    let payload = json!({ "records": records, "path": export_path.to_str().unwrap() });
    let py = run_python_json(&script, &payload);

    let scorer = SmartIranScorer::new(3, false, 35.0, 70.0);
    let records_rs: Vec<Map<String, Value>> = records.iter().map(as_map).collect();
    let results = scorer.score_all(&records_rs);
    let rs_export_path = dir.join("sub_rs").join("best.txt");
    let n = scorer
        .export_bridge_lines(&results, &rs_export_path, 50, 0.0)
        .unwrap();
    let content = std::fs::read_to_string(&rs_export_path).unwrap();

    assert_eq!(py["n"], json!(n));
    assert_eq!(py["content"], json!(content));
    let _ = std::fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// The one deliberately-UNPATCHED test: measures and pins the real gap
// ─────────────────────────────────────────────────────────────────────────────

const UNPATCHED_SCORE_SCRIPT: &str = r##"
import json, sys
from core.smart_iran_scorer import SmartIranScorer

payload = json.loads(sys.argv[1])
s = SmartIranScorer(censorship_level=3)
bs = s.score_record(payload["record"])
print(json.dumps({"base_score": bs.base_score, "final_score": bs.final_score}))
"##;

#[test]
fn measures_real_world_ja3_gap_unpatched() {
    // SESSION 10 — GAP CLOSED. This test historically pinned a ~14-point
    // "vanilla" base-score gap caused by `scorer.rs`'s ja3 stub returning 0
    // while Python applied its transport-keyed fallback heuristic. That gap
    // is now eliminated: `scorer::IranScorer::ja3_penalty` is wired to the
    // ported `ja3_intelligence::JA3Intel`, so the Rust base/final scores
    // match the *real, unpatched* Python scorer byte-for-byte. This test now
    // asserts parity (gap ≈ 0). If a nonzero gap ever reappears, ja3 parity
    // has regressed — investigate rather than silently update the tolerance.
    let record = json!({"raw": "bridge vanilla 1.2.3.4:9001 abcd"});
    let payload = json!({ "record": record });
    let py = run_python_json(UNPATCHED_SCORE_SCRIPT, &payload);
    let py_base = py["base_score"].as_f64().unwrap();
    let py_final = py["final_score"].as_f64().unwrap();

    let scorer = SmartIranScorer::new(3, false, 35.0, 70.0);
    let record_rs = as_map(&record);
    let rs = scorer.score_record(&record_rs);

    let base_gap = (rs.base_score - py_base).abs();
    assert!(
        base_gap < 0.05,
        "ja3 parity regressed: rust base_score ({}) vs python ({}), gap {base_gap}",
        rs.base_score,
        py_base
    );
    let final_gap = (rs.final_score - py_final).abs();
    assert!(
        final_gap < 0.05,
        "ja3 parity regressed: rust final_score ({}) vs python ({}), gap {final_gap}",
        rs.final_score,
        py_final
    );
}
