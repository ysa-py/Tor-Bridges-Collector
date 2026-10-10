use std::{fs, path::PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use torshield_ir_ultra::results_writer::{
    load_iran_results, write_result_files, ResultsWriterError,
};

const OUTPUT_FILES: &[&str] = &[
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_likely_working_vanilla.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_meek_lite.txt",
    "iran_likely_working_all.txt",
    "iran_blocked.txt",
    "tested_global_obfs4.txt",
    "tested_global_webtunnel.txt",
    "tested_global_vanilla.txt",
];

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_results_writer_contract_{}_{}",
        name,
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale test directory");
    }
    fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn typed(status: &str, stage: &str, probe_type: &str, vantage: Option<&str>) -> Value {
    let vantage = vantage.map(|kind| json!({ "type": kind, "colo": "FRA" }));
    json!({
        "status": status,
        "stage": stage,
        "vantage": vantage,
        "probe_type": probe_type,
        "rtt_ms": 25.0,
        "detail": "fixture observation",
        "observed_at": Utc::now().to_rfc3339()
    })
}

#[test]
fn typed_evidence_gates_working_and_global_outputs() {
    let dir = case_dir("typed_gates");
    let iran_at = Utc::now().to_rfc3339();
    let records = vec![
        json!({
            "line": "obfs4 verified 1.2.3.4:443",
            "transport": "obfs4",
            "iran_status": "iran_likely_working",
            "iran_assessment": {
                "status": "iran_likely_working", "source": "ooni_measurements_api", "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" }, "queried_at": iran_at.clone(),
                "measurement_at": iran_at.clone(), "measurement_window_days": 7,
                "historical_measurement_at": iran_at.clone(), "historical_window_days": 90
            },
            "verification": typed("connected", "S2", "obfs4-handshake", Some("cloudflare_worker"))
        }),
        json!({
            "line": "obfs4 tcp-only 1.2.3.5:443",
            "transport": "obfs4",
            "iran_status": "iran_likely_working",
            "verification": typed("connected", "S1", "tcp", Some("github_actions_runner"))
        }),
        json!({
            "line": "webtunnel unknown-iran 1.2.3.6:443",
            "transport": "webtunnel",
            "iran_status": "iran_unknown",
            "verification": typed("connected", "S2", "websocket-101", Some("cloudflare_worker"))
        }),
        json!({
            "line": "webtunnel no-vantage 1.2.3.7:443",
            "transport": "webtunnel",
            "iran_status": "iran_likely_working",
            "verification": typed("connected", "S2", "websocket-101", None)
        }),
        json!({
            "line": "snowflake legacy-bool 1.2.3.8:443",
            "transport": "snowflake",
            "iran_status": "iran_likely_working",
            "tcp_reachable": true,
            "transport_capable": true
        }),
        json!({
            "line": "vanilla timeout 1.2.3.9:443",
            "transport": "vanilla",
            "iran_status": "iran_unknown",
            "verification": typed("timeout", "S1", "tcp", Some("cloudflare_worker"))
        }),
        json!({
            "line": "vanilla blocked 1.2.3.10:443",
            "transport": "vanilla",
            "iran_status": "iran_likely_blocked",
            "iran_assessment": {
                "status": "iran_likely_blocked", "source": "ooni_measurements_api", "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" }, "queried_at": iran_at.clone(),
                "measurement_at": iran_at.clone(), "measurement_window_days": 7,
                "historical_measurement_at": iran_at.clone(), "historical_window_days": 90
            },
            "verification": typed("refused", "S1", "tcp", Some("iran_probe"))
        })
    ];

    let stats = write_result_files(&dir, &records).expect("writer succeeds");
    let read = |name: &str| fs::read_to_string(dir.join(name)).expect("output exists");

    assert_eq!(stats["iran_likely_working_obfs4.txt"], 1);
    assert_eq!(read("iran_likely_working_obfs4.txt"), "obfs4 verified 1.2.3.4:443\n");
    assert_eq!(stats["iran_likely_working_webtunnel.txt"], 0);
    assert_eq!(stats["iran_likely_working_snowflake.txt"], 0);
    assert_eq!(stats["iran_likely_working_vanilla.txt"], 0);
    assert_eq!(read("iran_likely_working_all.txt"), "obfs4 verified 1.2.3.4:443\n");
    assert_eq!(read("tested_global_obfs4.txt"), "obfs4 verified 1.2.3.4:443\n");
    assert_eq!(
        read("tested_global_webtunnel.txt"),
        "webtunnel unknown-iran 1.2.3.6:443\n",
        "global S2+ evidence is not itself an Iran-reachability claim"
    );
    assert_eq!(read("tested_global_vanilla.txt"), "");
    assert_eq!(read("iran_blocked.txt"), "vanilla blocked 1.2.3.10:443\n");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn empty_input_still_writes_mandatory_empty_files() {
    let dir = case_dir("empty");
    let stats = write_result_files(&dir, &[]).expect("writer succeeds");
    for name in OUTPUT_FILES {
        assert_eq!(stats[*name], 0, "{name} count");
        assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), "", "{name} body");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_iran_results_accepts_valid_json_without_schema_assumptions() {
    let dir = case_dir("load_valid");
    let path = dir.join("iran_results.json");
    let value = json!({ "bridges": [{ "line": "x", "verification": typed("inconclusive", "S0", "none", None) }] });
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(load_iran_results(&path).unwrap(), value);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_iran_results_reports_missing_malformed_and_directory_inputs() {
    let dir = case_dir("load_errors");
    let missing = load_iran_results(&dir.join("missing.json")).expect_err("missing is typed");
    assert!(matches!(missing, ResultsWriterError::MissingIranResults { .. }));

    let malformed_path = dir.join("malformed.json");
    fs::write(&malformed_path, "{not valid json").unwrap();
    let malformed = load_iran_results(&malformed_path).expect_err("parse error is typed");
    assert!(matches!(malformed, ResultsWriterError::ParseIranResults { .. }));

    let directory_path = dir.join("results-directory");
    fs::create_dir(&directory_path).unwrap();
    let directory = load_iran_results(&directory_path).expect_err("read error is typed");
    assert!(matches!(directory, ResultsWriterError::ReadIranResults { .. }));

    let _ = fs::remove_dir_all(dir);
}
