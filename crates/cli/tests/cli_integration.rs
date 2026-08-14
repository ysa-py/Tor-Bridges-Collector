//! End-to-end integration tests for the `tbc` CLI surface.
//!
//! `score` and `publish` are offline, so these tests run them for real against
//! scratch directories and assert on the artifacts they produce. The
//! network-bound subcommands are exercised at the validation boundary (their
//! network execution is the second gate owned by the pipeline crates).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde_json::json;

use tbc_cli::{parse_command, run, CliError, Command};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("tbc-cli-{}-{}-{tag}", std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_to_string(command: &Command) -> String {
    let mut out = Vec::new();
    run(command, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn version_schema_and_help_round_trip() {
    assert!(run_to_string(&Command::Version).starts_with("tbc "));
    assert!(run_to_string(&Command::Schema)
        .trim()
        .parse::<u32>()
        .is_ok());
    assert!(run_to_string(&Command::Help { topic: None }).contains("SUBCOMMANDS"));
    assert!(run_to_string(&Command::Help {
        topic: Some("score".to_owned())
    })
    .contains("--input"));
}

#[test]
fn score_runs_end_to_end_offline() {
    let dir = scratch_dir("score");
    let input = dir.join("observations.json");
    let output = dir.join("scores.json");
    let observation = json!({
        "bridge_key": "obfs4|1.2.3.4|443||",
        "vantage": { "kind": "runner", "is_mobile": false },
        "probe_kind": "obfs4_handshake",
        "evasion_profile": "none",
        "verdict": "reachable",
        "measured_at": Utc::now(),
    });
    fs::write(&input, serde_json::to_string(&vec![observation]).unwrap()).unwrap();

    let command = Command::Score {
        input: input.clone(),
        output: output.clone(),
    };
    let report = run_to_string(&command);
    assert!(report.contains("scored 1 bridge(s)"));

    let scored: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let first = &scored.as_array().unwrap()[0];
    assert_eq!(first["bridge_key"], "obfs4|1.2.3.4|443||");
    assert!(first["score"]["global"].as_f64().unwrap() > 0.0);

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn publish_runs_end_to_end_offline() {
    let dir = scratch_dir("publish");
    let input = dir.join("bridges.txt");
    let output = dir.join("out");
    fs::write(
        &input,
        "obfs4 100.11.30.96:10002 19A74939D0D3400295A8E66D57BC9894CF388CFA cert=JjMIPTQ4gJnop+XASRS9tdY6jJbH4BVyiOPFlNAULeH2bf9UJn59SzbZRTB17Usv++apAw iat-mode=0\nvanilla 1.2.3.4:9001\n",
    )
    .unwrap();

    let command = Command::Publish {
        input: input.clone(),
        output: output.clone(),
    };
    let report = run_to_string(&command);
    assert!(report.contains("publish: wrote"));

    assert!(output.join("obfs4.txt").exists());
    assert!(output.join("vanilla.txt").exists());
    assert!(output.join("snapshot.json").exists());
    assert!(output.join("manifest.json").exists());
    assert!(output.join("tor_bridges.zip").exists());

    let obfs4 = fs::read_to_string(output.join("obfs4.txt")).unwrap();
    assert!(obfs4.contains("obfs4 100.11.30.96:10002"));
    let vanilla = fs::read_to_string(output.join("vanilla.txt")).unwrap();
    assert_eq!(vanilla, "vanilla 1.2.3.4:9001\n");

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn score_reports_a_typed_error_for_missing_input() {
    let command = Command::Score {
        input: PathBuf::from("/nonexistent/observations.json"),
        output: PathBuf::from("/tmp/never-written.json"),
    };
    let mut out = Vec::new();
    let error = run(&command, &mut out).unwrap_err();
    assert_eq!(error.kind_name(), "io_error");
}

#[test]
fn collect_validates_and_rejects_bad_config() {
    let dir = scratch_dir("collect");
    let good = dir.join("good.json");
    fs::write(
        &good,
        json!({ "sources": ["https://bridges.example.com/list"] }).to_string(),
    )
    .unwrap();
    let report = run_to_string(&Command::Collect {
        config: good.clone(),
    });
    assert!(report.contains("validated 1 source(s)"));

    let bad = dir.join("bad.json");
    fs::write(&bad, json!({ "nope": [] }).to_string()).unwrap();
    let mut out = Vec::new();
    let error = run(&Command::Collect { config: bad }, &mut out).unwrap_err();
    assert_eq!(error.kind_name(), "config_error");

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn agent_validates_bind_configuration() {
    let mut out = Vec::new();
    run(
        &Command::Agent {
            bind: "127.0.0.1".to_owned(),
            port: 9090,
        },
        &mut out,
    )
    .unwrap();
    let report = String::from_utf8(out).unwrap();
    assert!(report.contains("127.0.0.1:9090"));

    let error = run(
        &Command::Agent {
            bind: "  ".to_owned(),
            port: 9090,
        },
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error.kind_name(), "usage_error");
}

#[test]
fn parse_rejects_unknown_and_missing_flags() {
    let argv = |items: &[&str]| {
        items
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<String>>()
    };
    assert!(matches!(
        parse_command(&argv(&["bogus"])),
        Err(CliError::UnknownSubcommand { .. })
    ));
    assert!(matches!(
        parse_command(&argv(&["score", "--input", "a.json"])),
        Err(CliError::MissingRequiredFlag { .. })
    ));
    assert!(matches!(
        parse_command(&argv(&[
            "score", "--nope", "x", "--input", "a", "--output", "b"
        ])),
        Err(CliError::UnknownFlag { .. })
    ));
}
