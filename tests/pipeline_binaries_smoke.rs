//! Runtime smoke tests for the Rust-native pipeline binaries.
//!
//! `cargo clippy` proves the binaries *compile*; these tests prove they
//! actually *run* end-to-end without panicking, which is what the CI
//! workflows depend on after the Python→Rust migration replaced every
//! `python <module>.py` stage with a Rust entry point.
//!
//! Each test runs the real binary (via the `CARGO_BIN_EXE_*` env vars Cargo
//! sets for integration tests) inside a scratch directory, so nothing in the
//! repository working tree is mutated.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Create an isolated scratch working directory seeded with the minimal
/// inputs the pipeline stages look for.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield-pipeline-smoke-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["data", "export", "docs", "bridge", "scripts", "src"] {
        std::fs::create_dir_all(dir.join(sub)).expect("create scratch subdir");
    }

    // Minimal, structurally valid iran_results.json.
    std::fs::write(
        dir.join("bridge/iran_results.json"),
        r#"{
  "bridges": [
    {
      "line": "obfs4 192.0.2.10:443 0000000000000000000000000000000000000000 cert=AAAA iat-mode=0",
      "raw": "obfs4 192.0.2.10:443 0000000000000000000000000000000000000000 cert=AAAA iat-mode=0",
      "transport": "obfs4",
      "tcp_reachable": true,
      "composite_score": 0.82
    },
    {
      "line": "snowflake 192.0.2.11:443 1111111111111111111111111111111111111111",
      "raw": "snowflake 192.0.2.11:443 1111111111111111111111111111111111111111",
      "transport": "snowflake",
      "tcp_reachable": false,
      "composite_score": 0.41
    }
  ],
  "summary": { "total_tested": 2 }
}
"#,
    )
    .expect("write iran_results.json");

    // Bridge list used by the ECH / anti-AI-DPI / NIN stages.
    std::fs::write(
        dir.join("bridge/bridge_list_for_testing.json"),
        r#"[
  "obfs4 192.0.2.10:443 0000000000000000000000000000000000000000 cert=AAAA iat-mode=0",
  "snowflake 192.0.2.11:443 1111111111111111111111111111111111111111"
]
"#,
    )
    .expect("write bridge_list_for_testing.json");

    // Files the self_heal preflight asserts on.
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"scratch\"\n").unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 3\n").unwrap();
    std::fs::write(dir.join("src/lib.rs"), "").unwrap();
    std::fs::write(dir.join("scripts/self_heal.sh"), "#!/usr/bin/env bash\n").unwrap();
    std::fs::write(dir.join("scripts/self_heal.ps1"), "").unwrap();

    dir
}

fn run(bin: &str, dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {bin}: {error}"))
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} exited with {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn unified_collector_help_exits_cleanly() {
    let dir = scratch("unified-collector-help");
    let output = run(
        env!("CARGO_BIN_EXE_tor-bridges-collector"),
        &dir,
        &["--help"],
    );
    assert_success("tor-bridges-collector --help", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--metrics"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unified_collector_dry_run_never_writes_publication_files() {
    let dir = scratch("unified-collector-dry-run");
    let output = Command::new(env!("CARGO_BIN_EXE_tor-bridges-collector"))
        .current_dir(&dir)
        // Unreachable local endpoints make this deterministic while still
        // exercising the async fetch/retry, history, test, README, ZIP, and
        // dry-run orchestration paths. Fronted probes are bounded to one
        // second and all per-list probes are capped at one candidate.
        .env("BRIDGEDB_BASE_URL", "http://127.0.0.1:9/bridges")
        .env("DELTA_RAW_BASE_URL", "http://127.0.0.1:9/bridge")
        .env("CONNECT_TIMEOUT", "1")
        .env("MAX_RETRIES", "1")
        .env("FETCH_RETRIES", "1")
        .args([
            "--dry-run",
            "--timeout-seconds",
            "1",
            "--retry-count",
            "1",
            "--max-test-per-list",
            "1",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn unified collector: {error}"));
    assert_success("tor-bridges-collector --dry-run", &output);
    assert!(!dir.join("README.md").exists());
    assert!(!dir.join("bridge/bridge_history.json").exists());
    assert!(!dir.join("bridge/tor_bridges.zip").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A real-network smoke run. Every source and protocol failure is recoverable
/// by design, so this asserts process resilience rather than assuming a public
/// bridge stays reachable from every CI region. It proves the standalone binary
/// actually performs its live BridgeDB/Delta/front-domain code paths while
/// `--dry-run` protects repository output.
#[test]
fn unified_collector_live_network_dry_run_completes() {
    let dir = scratch("unified-collector-live-network");
    let output = Command::new(env!("CARGO_BIN_EXE_tor-bridges-collector"))
        .current_dir(&dir)
        .env("BRIDGEDB_BASE_URL", "https://bridges.torproject.org/bridges")
        .env(
            "DELTA_RAW_BASE_URL",
            "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge",
        )
        .env("CONNECT_TIMEOUT", "2")
        .env("MAX_RETRIES", "1")
        .env("FETCH_RETRIES", "1")
        .args([
            "--dry-run",
            "--timeout-seconds",
            "2",
            "--retry-count",
            "1",
            "--max-test-per-list",
            "1",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn live unified collector: {error}"));
    assert_success("tor-bridges-collector live --dry-run", &output);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_lists_every_stage() {
    let dir = scratch("list");
    let output = run(env!("CARGO_BIN_EXE_pipeline"), &dir, &["--list"]);
    assert_success("pipeline --list", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let listed: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        listed.len(),
        20,
        "expected 20 stages, got {}: {listed:?}",
        listed.len()
    );
    for expected in [
        "results",
        "adaptive",
        "dpi",
        "nextgen",
        "nin-pack",
        "nin-bypass",
        "quantum",
        "warp",
        "ech",
        "nin-advanced",
        "anti-ai-dpi",
        "ml",
        "nin-cut",
        "reality",
        "ebpf",
        "ja3",
        "ct",
        "nin-classify",
        "siam",
        "rotation",
    ] {
        assert!(listed.contains(&expected), "stage {expected} not listed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_rejects_unknown_stage() {
    let dir = scratch("unknown");
    let output = run(
        env!("CARGO_BIN_EXE_pipeline"),
        &dir,
        &["--stage", "definitely-not-a-stage"],
    );
    assert!(
        !output.status.success(),
        "unknown stage must be rejected, got success"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The critical regression test: running every stage must complete without
/// a panic, must not fail any required stage, and must emit a report.
#[test]
fn pipeline_runs_all_stages_without_failure() {
    let dir = scratch("all");
    let output = run(
        env!("CARGO_BIN_EXE_pipeline"),
        &dir,
        &[
            "--all",
            "--input",
            "bridge/iran_results.json",
            "--report",
            "data/pipeline_report.json",
        ],
    );
    assert_success("pipeline --all", &output);

    let report_path = dir.join("data/pipeline_report.json");
    let body = std::fs::read_to_string(&report_path).expect("pipeline report written");
    let report: serde_json::Value = serde_json::from_str(&body).expect("report is valid JSON");

    let stages = report["stages"].as_array().expect("stages array");
    assert_eq!(stages.len(), 20, "every stage must be recorded");

    // No stage may report `failed`; `ok` and `skipped` are both acceptable
    // because some stages legitimately self-skip on absent optional inputs.
    let failures: Vec<String> = stages
        .iter()
        .filter(|s| s["status"] == "failed")
        .map(|s| {
            format!(
                "{}: {}",
                s["stage"].as_str().unwrap_or("?"),
                s["detail"]["error"].as_str().unwrap_or("?")
            )
        })
        .collect();
    assert!(failures.is_empty(), "stages failed: {failures:#?}");

    assert_eq!(report["summary"]["failed"], 0);

    // The required `results` stage must have actually produced bridge files.
    assert!(
        dir.join("bridge").read_dir().unwrap().count() > 2,
        "results stage should have written bridge/*.txt files"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_runs_a_single_stage() {
    let dir = scratch("single");
    let output = run(
        env!("CARGO_BIN_EXE_pipeline"),
        &dir,
        &["--stage", "ebpf", "--report", "data/one.json"],
    );
    assert_success("pipeline --stage ebpf", &output);

    let body = std::fs::read_to_string(dir.join("data/one.json")).expect("report written");
    let report: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(report["stages"].as_array().unwrap().len(), 1);
    assert_eq!(report["stages"][0]["stage"], "ebpf");
    assert_eq!(report["stages"][0]["status"], "ok");
    assert!(dir.join("docs/ebpf_xdp_blueprint.md").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_heal_reports_healthy_on_a_complete_tree() {
    let dir = scratch("selfheal");
    let output = run(env!("CARGO_BIN_EXE_self_heal"), &dir, &["--heal"]);
    assert_success("self_heal --heal", &output);
    assert!(dir.join("diagnostics/rust-self-heal.json").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_heal_fails_loudly_when_required_files_are_missing() {
    let dir = scratch("selfheal-missing");
    std::fs::remove_file(dir.join("scripts/self_heal.sh")).unwrap();
    std::fs::remove_file(dir.join("scripts/self_heal.ps1")).unwrap();
    let output = run(env!("CARGO_BIN_EXE_self_heal"), &dir, &["--heal"]);
    assert!(
        !output.status.success(),
        "self_heal must fail when required files are missing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auto_debug_writes_a_report_and_exits_zero() {
    let dir = scratch("autodebug");
    let output = run(
        env!("CARGO_BIN_EXE_auto_debug"),
        &dir,
        &["some-workflow", "12345", "--output", "data/ad.json"],
    );
    assert_success("auto_debug", &output);

    let body = std::fs::read_to_string(dir.join("data/ad.json")).expect("report written");
    let report: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(report["workflow"], "some-workflow");
    assert_eq!(report["run_id"], "12345");
    assert_eq!(report["mode"], "diagnose");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bridge_intelligence_produces_the_iran_reports() {
    let dir = scratch("intel");
    let output = run(
        env!("CARGO_BIN_EXE_bridge_intelligence"),
        &dir,
        &[
            "--input",
            "bridge/iran_results.json",
            "--censorship-level",
            "auto",
        ],
    );
    assert_success("bridge_intelligence", &output);

    for expected in [
        "data/bridge_intelligence_summary.json",
        "data/iran_censorship_fusion.json",
        "data/iran_routing_recommendation.json",
        "data/iran_quantum_shield_report.json",
        "data/iran_advanced_anti_censorship_report.json",
        "bridge/bridges_ai_iran_ranked.json",
    ] {
        assert!(dir.join(expected).is_file(), "missing output: {expected}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
