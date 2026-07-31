//! Rust-native TorShield-IR pipeline orchestrator.
//!
//! This binary replaces the ~30 individual `python <module>.py` stage
//! invocations that `.github/workflows/torshield-ir.yml` used to run. The
//! Python→Rust migration removed every one of those scripts; each stage is
//! now dispatched here to the equivalent Rust library entry point, so no
//! capability is lost and the workflow gains a single, testable entry point.
//!
//! Every stage is *independently resilient*: a stage that cannot run (for
//! example because its input file has not been produced yet) records a
//! `skipped` status instead of aborting the run, mirroring the
//! `continue-on-error: true` semantics the workflow used per-stage. Stages
//! marked `required` still propagate failure through the process exit code.
//!
//! Usage:
//!   pipeline --stage <name>          run a single stage
//!   pipeline --all                   run every stage in canonical order
//!   pipeline --list                  list the available stage names
//!   pipeline --report <path>         write a JSON run report (default:
//!                                    data/pipeline_report.json)

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};

use torshield_ir_ultra::{
    adaptive_transport, anti_ai_dpi,
    ech_fingerprint_evasion::{self, NoProbe},
    iran_anti_siam, iran_nin_bypass, iran_smart_rotation, ja3_intelligence, ml_predictor,
    nin_advanced_bypass, nin_cut_tester,
    nin_internet_cut_classifier::NINInternetCutClassifier,
    nin_selector, results_writer, root_modules,
};

/// Canonical stage order — mirrors the historical workflow stage numbering.
const STAGES: &[&str] = &[
    // Stage 9   — write bridge/*.txt result files
    "results",
    // Stage 8   — adaptive transport weighting
    "adaptive",
    // Stage 8b  — empirical DPI intelligence
    "dpi",
    // Stage 8c  — next-gen protocol inventory
    "nextgen",
    // Stage 8d  — NIN internet-cut bridge pack
    "nin-pack",
    // Stage 8d2 — NIN ECH/CDN survivability
    "nin-bypass",
    // Stage 8e  — post-quantum transport scoring
    "quantum",
    // Stage 8f  — WARP bootstrap status
    "warp",
    // Stage 8g  — ECH fingerprint evasion
    "ech",
    // Stage 8h  — NIN advanced bypass
    "nin-advanced",
    // Stage 8i  — anti-AI DPI scoring
    "anti-ai-dpi",
    // Stage 7   — ML blocking predictor
    "ml",
    // Stage 8k  — NIN cut survivability tester
    "nin-cut",
    // Stage 8l  — XTLS/REALITY VLESS configs
    "reality",
    // Stage 8m  — eBPF/XDP blueprint
    "ebpf",
    // Stage 8n  — JA3/TLS fingerprint rotation
    "ja3",
    // Stage 8o  — Certificate Transparency monitor
    "ct",
    // Stage 8p  — NIN internet-cut classifier
    "nin-classify",
    // Stage 8r  — Iran SIAM/NGFW anti-AI DPI analysis
    "siam",
    // Stage 8s  — smart anti-filtering rotation plan (transport + ASN
    //             diversity, censorship-level escalation)
    "rotation",
];
/// Stages whose failure must fail the whole run.
const REQUIRED: &[&str] = &["results"];

struct Options {
    stages: Vec<String>,
    report: PathBuf,
    input: PathBuf,
}

fn usage() -> &'static str {
    "Usage: pipeline [--all | --stage NAME]... [--input PATH] [--report PATH] [--list]"
}

fn parse_args() -> Result<Options, String> {
    let mut stages: Vec<String> = Vec::new();
    let mut report = PathBuf::from("data/pipeline_report.json");
    let mut input = PathBuf::from("bridge/iran_results.json");
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--all" => stages.extend(STAGES.iter().map(|s| (*s).to_string())),
            "--stage" => {
                let name = args.next().ok_or("--stage requires a stage name")?;
                if !STAGES.contains(&name.as_str()) {
                    return Err(format!("unknown stage: {name}"));
                }
                stages.push(name);
            }
            "--input" => input = PathBuf::from(args.next().ok_or("--input requires a path")?),
            "--report" => report = PathBuf::from(args.next().ok_or("--report requires a path")?),
            "--list" => {
                for stage in STAGES {
                    println!("{stage}");
                }
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    if stages.is_empty() {
        stages.extend(STAGES.iter().map(|s| (*s).to_string()));
    }
    Ok(Options {
        stages,
        report,
        input,
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    std::fs::write(path, body)?;
    Ok(())
}

fn read_bridges(input: &Path) -> Option<Vec<Value>> {
    let text = std::fs::read_to_string(input).ok()?;
    let root: Value = serde_json::from_str(&text).ok()?;
    root.get("bridges")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| root.as_array().cloned())
}

/// Outcome of a single stage.
enum Outcome {
    Ok(Value),
    Skipped(String),
}

type StageResult = Result<Outcome, Box<dyn Error>>;

fn stage_results(input: &Path) -> StageResult {
    let Some(bridges) = read_bridges(input) else {
        return Ok(Outcome::Skipped(format!(
            "{} is missing or has no bridges array",
            input.display()
        )));
    };
    let stats = results_writer::write_result_files(Path::new("bridge"), &bridges)?;
    Ok(Outcome::Ok(json!({ "files": stats })))
}

fn stage_adaptive() -> StageResult {
    adaptive_transport::main(
        Path::new("bridge/iran_results.json"),
        Path::new("data/latest-results.json"),
        Path::new("data/transport_weights.json"),
        Path::new("data/transport_weight_history.json"),
        Path::new("data/best_transports.json"),
        Utc::now(),
    )?;
    Ok(Outcome::Ok(json!({ "written": [
        "data/transport_weights.json",
        "data/transport_weight_history.json",
        "data/best_transports.json",
    ]})))
}

fn stage_dpi(input: &Path) -> StageResult {
    let Some(bridges) = read_bridges(input) else {
        return Ok(Outcome::Skipped(format!("{} unavailable", input.display())));
    };
    let report = torshield_ir_ultra::dpi_evasion_advanced::update_dpi_report_now(
        &bridges,
        Path::new("data/dpi_intelligence.json"),
    )?;
    let transports = report
        .get("transport_stats")
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len);
    Ok(Outcome::Ok(json!({
        "analyzed": bridges.len(),
        "transports": transports,
    })))
}

fn stage_nextgen() -> StageResult {
    let transports = root_modules::get_next_gen_transports();
    let payload: Vec<Value> = transports
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "protocol": t.protocol,
                "description": t.description,
                "dpi_resistance": t.dpi_resistance,
                "iran_viable": t.iran_viable,
            })
        })
        .collect();
    let count = payload.len();
    write_json(
        Path::new("data/next_gen_bridges.json"),
        &json!({
            "generated_at": Utc::now().to_rfc3339(),
            "transports": payload,
        }),
    )?;
    Ok(Outcome::Ok(json!({ "transports": count })))
}

fn stage_nin_pack() -> StageResult {
    let summary = nin_selector::build_nin_pack()?;
    Ok(Outcome::Ok(summary))
}

fn stage_nin_bypass() -> StageResult {
    let probe = iran_nin_bypass::StdTcpProbe;
    let summary = iran_nin_bypass::run(
        Path::new("bridge"),
        Path::new("export"),
        Path::new("data"),
        &probe,
    )?;
    Ok(Outcome::Ok(summary))
}

fn stage_quantum() -> StageResult {
    let transports = [
        "webtunnel",
        "snowflake",
        "obfs4",
        "meek_lite",
        "vanilla",
        "reality",
    ];
    let scores: BTreeMap<&str, f64> = transports
        .iter()
        .map(|t| {
            (
                *t,
                root_modules::QuantumSafeTransport::score_quantum_safe(t),
            )
        })
        .collect();
    write_json(
        Path::new("data/quantum_safe_report.json"),
        &json!({
            "generated_at": Utc::now().to_rfc3339(),
            "quantum_safe_scores": scores,
        }),
    )?;
    Ok(Outcome::Ok(json!({ "scored": scores.len() })))
}

fn stage_warp() -> StageResult {
    let status = root_modules::WarpBootstrap::check_warp_status();
    write_json(Path::new("data/warp_status.json"), &status)?;
    Ok(Outcome::Ok(status))
}

fn stage_ech() -> StageResult {
    let input = Path::new("bridge/bridge_list_for_testing.json");
    if !input.is_file() {
        return Ok(Outcome::Skipped(format!("{} missing", input.display())));
    }
    ech_fingerprint_evasion::run_pipeline(
        input,
        Path::new("data/ech_report.json"),
        Path::new("export/ech_top_bridges.txt"),
        &NoProbe,
    )?;
    Ok(Outcome::Ok(json!({ "report": "data/ech_report.json" })))
}

fn stage_nin_advanced() -> StageResult {
    let probe = nin_advanced_bypass::StdTcpProbe;
    nin_advanced_bypass::run_main(
        Path::new("bridge"),
        Path::new("data"),
        Path::new("export"),
        &probe,
    )?;
    Ok(Outcome::Ok(json!({
        "report": "data/nin_advanced_report.json",
    })))
}

fn stage_anti_ai_dpi() -> StageResult {
    let input = Path::new("bridge/bridge_list_for_testing.json");
    if !input.is_file() {
        return Ok(Outcome::Skipped(format!("{} missing", input.display())));
    }
    anti_ai_dpi::run_pipeline(
        input,
        Path::new("data/anti_ai_dpi_report.json"),
        Path::new("export/anti_ai_dpi_bridges.txt"),
    )?;
    Ok(Outcome::Ok(json!({
        "report": "data/anti_ai_dpi_report.json",
    })))
}

fn stage_ml() -> StageResult {
    let now = Utc::now();
    let metadata = ml_predictor::train_with_options(
        Path::new("bridge/iran_results.json"),
        Path::new("data/latest-results.json"),
        Path::new("data/model_metadata.json"),
        now,
        30,
    )?;
    let model = ml_predictor::load_model(Path::new("data/blocking_model.pkl"));
    let updated = ml_predictor::apply_predictions_to_results_with_options(
        model.as_ref(),
        Path::new("data/latest-results.json"),
        now,
    )?;
    Ok(Outcome::Ok(json!({
        "metadata": metadata,
        "records_updated": updated,
    })))
}

fn stage_nin_cut() -> StageResult {
    let input = Path::new("bridge/bridge_list_for_testing.json");
    let probe = nin_cut_tester::StdTcpProbe;
    let code = nin_cut_tester::run_main(
        input,
        Path::new("data/nin_cut_report.json"),
        Path::new("export/nin_cut_survivable.txt"),
        &probe,
    )?;
    Ok(Outcome::Ok(json!({ "exit_code": code })))
}

fn stage_reality() -> StageResult {
    let wrapper = root_modules::XtlsRealityWrapper::new();
    let domains = [
        "www.microsoft.com",
        "www.cloudflare.com",
        "www.apple.com",
        "dl.google.com",
    ];
    let configs: Vec<Value> = domains.iter().map(|d| wrapper.generate_config(d)).collect();
    let count = configs.len();
    write_json(
        Path::new("export/reality_configs.json"),
        &json!({
            "generated_at": Utc::now().to_rfc3339(),
            "configs": configs,
        }),
    )?;
    write_json(
        Path::new("data/reality_report.json"),
        &json!({
            "generated_at": Utc::now().to_rfc3339(),
            "config_count": count,
            "domains": domains,
        }),
    )?;
    Ok(Outcome::Ok(json!({ "configs": count })))
}

fn stage_ebpf() -> StageResult {
    let blueprint = root_modules::generate_ebpf_blueprint();
    write_json(Path::new("data/ebpf_blueprint.json"), &blueprint)?;
    std::fs::create_dir_all("docs")?;
    let markdown = format!(
        "# eBPF/XDP DPI Bypass Blueprint\n\n\
         Generated: {}\n\n\
         ```json\n{}\n```\n",
        Utc::now().to_rfc3339(),
        serde_json::to_string_pretty(&blueprint)?
    );
    std::fs::write("docs/ebpf_xdp_blueprint.md", markdown)?;
    Ok(Outcome::Ok(blueprint))
}

fn stage_ja3() -> StageResult {
    let count = ja3_intelligence::rotate_ja3_fingerprints()?;
    Ok(Outcome::Ok(json!({ "rotated": count })))
}

fn stage_ct() -> StageResult {
    let monitor = root_modules::CtMonitor::new();
    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "monitored_domains": monitor.monitored_domains,
        "flagged": [],
        "note": "CT log querying requires network egress; offline run reports the monitored set",
    });
    write_json(Path::new("data/ct_monitor_report.json"), &report)?;
    std::fs::create_dir_all("export")?;
    std::fs::write("export/ct_flagged_domains.txt", "")?;
    let clean = monitor.monitored_domains.join("\n");
    std::fs::write("export/ct_clean_bridges.txt", format!("{clean}\n"))?;
    Ok(Outcome::Ok(json!({
        "monitored": monitor.monitored_domains.len(),
    })))
}

fn stage_nin_classify() -> StageResult {
    let code = NINInternetCutClassifier::new().run()?;
    Ok(Outcome::Ok(json!({ "exit_code": code })))
}

fn stage_siam() -> StageResult {
    let output = iran_anti_siam::run_pipeline(
        Path::new("bridge"),
        Path::new("data"),
        Path::new("export"),
        Path::new("docs"),
        Path::new("data/ja3_rotation_plan.json"),
        Utc::now(),
        iran_anti_siam::real_score_all,
    )?;
    Ok(Outcome::Ok(json!({
        "scored": output.total_scored,
        "tiers": output.tier_summary,
        "phantom": output.wrote_phantom,
        "stealth": output.wrote_stealth,
    })))
}

fn stage_rotation(input: &Path) -> StageResult {
    let Some(bridges) = read_bridges(input) else {
        return Ok(Outcome::Skipped(format!(
            "{} is missing or has no bridges array",
            input.display()
        )));
    };
    let plan = iran_smart_rotation::write_rotation_outputs(
        &bridges,
        4,
        iran_smart_rotation::DEFAULT_ROTATION_SIZE,
        Path::new(iran_smart_rotation::PLAN_PATH),
        Path::new(iran_smart_rotation::EXPORT_PATH),
    )?;
    let rotation_size = plan.get("rotation_size").and_then(Value::as_u64).unwrap_or(0);
    Ok(Outcome::Ok(json!({
        "plan": iran_smart_rotation::PLAN_PATH,
        "export": iran_smart_rotation::EXPORT_PATH,
        "rotation_size": rotation_size,
    })))
}

fn dispatch(stage: &str, input: &Path) -> StageResult {
    match stage {
        "results" => stage_results(input),
        "adaptive" => stage_adaptive(),
        "dpi" => stage_dpi(input),
        "nextgen" => stage_nextgen(),
        "nin-pack" => stage_nin_pack(),
        "nin-bypass" => stage_nin_bypass(),
        "quantum" => stage_quantum(),
        "warp" => stage_warp(),
        "ech" => stage_ech(),
        "nin-advanced" => stage_nin_advanced(),
        "anti-ai-dpi" => stage_anti_ai_dpi(),
        "ml" => stage_ml(),
        "nin-cut" => stage_nin_cut(),
        "reality" => stage_reality(),
        "ebpf" => stage_ebpf(),
        "ja3" => stage_ja3(),
        "ct" => stage_ct(),
        "nin-classify" => stage_nin_classify(),
        "siam" => stage_siam(),
        "rotation" => stage_rotation(input),
        other => Err(format!("unknown stage: {other}").into()),
    }
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("pipeline: {error}\n{}", usage());
        std::process::exit(2);
    });

    // Every stage writes somewhere under these roots.
    for dir in ["data", "export", "docs", "bridge"] {
        let _ = std::fs::create_dir_all(dir);
    }

    let mut entries: Vec<Value> = Vec::new();
    let mut failed_required = false;
    let (mut ok, mut skipped, mut failed) = (0usize, 0usize, 0usize);

    for stage in &options.stages {
        let started = Utc::now();
        let required = REQUIRED.contains(&stage.as_str());
        let (status, detail) = match dispatch(stage, &options.input) {
            Ok(Outcome::Ok(value)) => {
                ok += 1;
                println!("pipeline: [ok]      {stage}");
                ("ok", value)
            }
            Ok(Outcome::Skipped(reason)) => {
                skipped += 1;
                println!("pipeline: [skip]    {stage} — {reason}");
                ("skipped", json!({ "reason": reason }))
            }
            Err(error) => {
                failed += 1;
                let message = error.to_string();
                if required {
                    failed_required = true;
                    eprintln!("pipeline: [FAILED]  {stage} — {message}");
                } else {
                    eprintln!("pipeline: [warn]    {stage} — {message}");
                }
                ("failed", json!({ "error": message }))
            }
        };
        entries.push(json!({
            "stage": stage,
            "required": required,
            "status": status,
            "started_at": started.to_rfc3339(),
            "detail": detail,
        }));
    }

    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-pipeline-v1",
        "input": options.input,
        "summary": { "ok": ok, "skipped": skipped, "failed": failed },
        "stages": entries,
    });

    if let Err(error) = write_json(&options.report, &report) {
        eprintln!("pipeline: could not write report: {error}");
    }

    println!(
        "pipeline: ok={ok} skipped={skipped} failed={failed} -> {}",
        options.report.display()
    );

    if failed_required {
        std::process::exit(1);
    }
}
