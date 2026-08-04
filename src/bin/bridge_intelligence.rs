//! End-to-end Rust-native bridge intelligence and Iran anti-censorship report.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Map, Value};
use torshield_ir_ultra::censorship_fusion::{CensorshipSignals, FusedCensorshipAssessment};
use torshield_ir_ultra::dpi_evasion_advanced::update_dpi_report_now;
use torshield_ir_ultra::iran_advanced_dpi_evasion::{
    generate_anti_censorship_report, generate_evasion_strategy, EvasionStrategy, MULTI_PATH_ROUTES,
};
use torshield_ir_ultra::iran_quantum_dpi_shield_v2::{ForecastInput, Shield, TransportLastUsed};
use torshield_ir_ultra::iran_smart_anti_filter_v2::{
    routing_recommendation, utc_to_irst_hour, IrstTierConfig,
};
use torshield_ir_ultra::results_writer::write_result_files;
use torshield_ir_ultra::smart_iran_scorer::{extract_endpoint, BridgeScore, SmartIranScorer};

#[derive(Debug)]
struct Options {
    input: PathBuf,
    censorship_level: Option<u32>,
    strategy_limit: usize,
}

fn parse_args() -> Result<Options, String> {
    let mut input = PathBuf::from("bridge/iran_results.json");
    let mut censorship_level = None;
    // Dynamic yield: default strategy_limit from config instead of hardcoded 50.
    // User can override via --strategy-limit CLI flag.
    let mut strategy_limit = torshield_ir_ultra::config::Config::from_env()
        .map(|cfg| cfg.max_bridges_per_run as usize)
        .unwrap_or(50);
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input = PathBuf::from(args.next().ok_or("--input requires a path")?),
            "--censorship-level" => {
                let value = args
                    .next()
                    .ok_or("--censorship-level requires auto or an integer")?;
                censorship_level = if value.eq_ignore_ascii_case("auto") {
                    None
                } else {
                    Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| "--censorship-level must be auto or an integer")?
                            .clamp(1, 5),
                    )
                };
            }
            "--strategy-limit" => {
                strategy_limit = args
                    .next()
                    .ok_or("--strategy-limit requires an integer")?
                    .parse()
                    .map_err(|_| "--strategy-limit must be an integer")?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: bridge_intelligence [--input PATH] \
                     [--censorship-level auto|1..5] [--strategy-limit N]"
                );
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(Options {
        input,
        censorship_level,
        strategy_limit,
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

fn bridge_array(root: &Value) -> Result<&[Value], Box<dyn Error>> {
    root.get("bridges")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "input object does not contain a bridges array",
            )
            .into()
        })
}

fn scoring_record(value: &Value) -> Option<Map<String, Value>> {
    let mut record = value.as_object()?.clone();
    if !record.contains_key("raw") {
        let line = record.get("line").and_then(Value::as_str)?.to_string();
        record.insert("raw".to_string(), json!(line));
    }
    Some(record)
}

fn ranked_report(scores: &[BridgeScore], input_count: usize, level: i64) -> Value {
    let bridges: Vec<Value> = scores.iter().map(BridgeScore::to_json).collect();
    json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-bridge-intelligence-v1",
        "censorship_level": level,
        "bridges": bridges,
        "summary": {
            "input_records": input_count,
            "ranked_records": scores.len(),
        },
    })
}

fn failure_forecast(assessment: &FusedCensorshipAssessment) -> ForecastInput {
    let signals = &assessment.signals;
    ForecastInput {
        anomaly_count: u32::try_from(signals.unknown).unwrap_or(u32::MAX),
        confirmed_count: u32::try_from(signals.confirmed_blocked).unwrap_or(u32::MAX),
        failure_count: u32::try_from(signals.tcp_unreachable).unwrap_or(u32::MAX),
        window_hours: 24,
        bridge_failure_rate: if signals.total == 0 {
            0.0
        } else {
            signals.tcp_unreachable as f64 / signals.total as f64
        },
        nin_detected: assessment.nin_likely,
    }
}

fn run(options: &Options) -> Result<usize, Box<dyn Error>> {
    let source = std::fs::read_to_string(&options.input)?;
    let root: Value = serde_json::from_str(&source)?;
    let bridges = bridge_array(&root)?;
    let assessment = CensorshipSignals::from_bridge_results(bridges).assess();
    let effective_level = options.censorship_level.unwrap_or(assessment.level);
    write_json(
        Path::new("data/iran_censorship_fusion.json"),
        &assessment.to_json(),
    )?;

    let result_stats = write_result_files(Path::new("bridge"), bridges)?;
    let records: Vec<Map<String, Value>> = bridges.iter().filter_map(scoring_record).collect();
    let scorer = SmartIranScorer::new(effective_level.into(), false, 35.0, 70.0);
    let scores = scorer.score_all(&records);
    write_json(
        Path::new("bridge/bridges_ai_iran_ranked.json"),
        &ranked_report(&scores, records.len(), scorer.level()),
    )?;

    let now = Utc::now();
    let routing_bridges: Vec<(String, String, f64)> = scores
        .iter()
        .map(|score| {
            let (host, _, _) = extract_endpoint(&score.raw);
            (host, score.transport.clone(), score.final_score)
        })
        .collect();
    let routing = routing_recommendation(
        now,
        &IrstTierConfig::default(),
        &routing_bridges,
        &[],
        &[],
        14,
        15,
    );
    write_json(Path::new("data/iran_routing_recommendation.json"), &routing)?;

    let shield = Shield::new(now);
    let forecast = failure_forecast(&assessment);
    let last_used = TransportLastUsed::new();
    write_json(
        Path::new("data/iran_quantum_shield_report.json"),
        &shield.recommend(&forecast, &last_used),
    )?;

    let previous_ja3 = BTreeSet::new();
    let blocked_cdns = BTreeSet::new();
    let route_statuses = BTreeMap::new();
    let irst_hour = utc_to_irst_hour(now);
    let strategies: Vec<EvasionStrategy> = scores
        .iter()
        .take(options.strategy_limit)
        .enumerate()
        .map(|(index, score)| {
            generate_evasion_strategy(
                &score.raw,
                &score.transport,
                effective_level,
                irst_hour,
                &previous_ja3,
                &blocked_cdns,
                &route_statuses,
                false,
                false,
                index as u64,
            )
        })
        .collect();
    let advanced_report = generate_anti_censorship_report(
        now,
        &strategies,
        effective_level,
        irst_hour,
        MULTI_PATH_ROUTES.len(),
    );
    write_json(
        Path::new("data/iran_advanced_anti_censorship_report.json"),
        &advanced_report,
    )?;

    update_dpi_report_now(bridges, Path::new("data/dpi_intelligence.json"))?;
    write_json(
        Path::new("data/bridge_intelligence_summary.json"),
        &json!({
            "generated_at": now.to_rfc3339(),
            "input": options.input,
            "bridges": bridges.len(),
            "ranked": scores.len(),
            "censorship_level_mode": if options.censorship_level.is_some() { "manual" } else { "auto" },
            "effective_censorship_level": effective_level,
            "censorship_pressure": assessment.pressure,
            "censorship_confidence": assessment.confidence,
            "nin_likely": assessment.nin_likely,
            "generated_bridge_files": result_stats,
            "status": "ok",
        }),
    )?;

    Ok(scores.len())
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("bridge_intelligence: {error}");
        std::process::exit(2);
    });
    match run(&options) {
        Ok(count) => println!("bridge_intelligence: processed and ranked {count} bridges"),
        Err(error) => {
            eprintln!("bridge_intelligence: {error}");
            std::process::exit(1);
        }
    }
}
