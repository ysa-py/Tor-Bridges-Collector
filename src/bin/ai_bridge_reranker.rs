//! Rust-native Iran bridge re-ranker used by scheduled automation.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Map, Value};
use torshield_ir_ultra::smart_iran_scorer::{BridgeScore, SmartIranScorer};

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    censorship_level: i64,
    top_n: usize,
}

fn parse_args() -> Result<Options, String> {
    let mut input = PathBuf::from("bridge/iran_results.json");
    let mut output = PathBuf::from("bridge/bridges_ai_iran_ranked.json");
    let mut censorship_level = 4_i64;
    let mut top_n = 0_usize;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                input = PathBuf::from(args.next().ok_or("--input requires a path")?);
            }
            "--output" => {
                output = PathBuf::from(args.next().ok_or("--output requires a path")?);
            }
            "--censorship-level" => {
                censorship_level = args
                    .next()
                    .ok_or("--censorship-level requires an integer")?
                    .parse()
                    .map_err(|_| "--censorship-level must be an integer")?;
            }
            "--top-n" => {
                top_n = args
                    .next()
                    .ok_or("--top-n requires an integer")?
                    .parse()
                    .map_err(|_| "--top-n must be an integer")?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: ai_bridge_reranker [--input PATH] [--output PATH] \
                     [--censorship-level 1..5] [--top-n N]"
                );
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(Options {
        input,
        output,
        censorship_level,
        top_n,
    })
}

fn bridge_values(root: &Value) -> Result<&[Value], String> {
    if let Some(values) = root.as_array() {
        return Ok(values);
    }
    root.get("bridges")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "input must be an array or an object containing a bridges array".to_string())
}

fn normalize_record(value: &Value) -> Option<Map<String, Value>> {
    match value {
        Value::String(line) => {
            let mut record = Map::new();
            record.insert("raw".to_string(), json!(line));
            Some(record)
        }
        Value::Object(object) => {
            let mut record = object.clone();
            if !record.contains_key("raw") {
                if let Some(line) = record.get("line").and_then(Value::as_str) {
                    record.insert("raw".to_string(), json!(line));
                }
            }
            record
                .get("raw")
                .and_then(Value::as_str)
                .filter(|line| !line.trim().is_empty())?;
            Some(record)
        }
        _ => None,
    }
}

fn tier_counts(scores: &[BridgeScore]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for score in scores {
        *counts.entry(score.tier.as_str()).or_insert(0) += 1;
    }
    counts
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

fn run(options: &Options) -> Result<usize, Box<dyn Error>> {
    let source = std::fs::read_to_string(&options.input)?;
    let root: Value = serde_json::from_str(&source)?;
    let values = bridge_values(&root)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, message))?;
    let records: Vec<Map<String, Value>> = values.iter().filter_map(normalize_record).collect();

    let scorer = SmartIranScorer::new(options.censorship_level, false, 35.0, 70.0);
    let mut scores = scorer.score_all(&records);
    if options.top_n > 0 {
        scores.truncate(options.top_n);
    }

    // Attach the Iran DPI hardening layer (uTLS profile + ALPN mutation)
    // to every ranked bridge so downstream clients can deploy the hardened
    // line directly. Additive — the parity field set is preserved intact.
    let mut score_values: Vec<Value> = Vec::with_capacity(scores.len());
    for score in &scores {
        let mut value = score.to_json();
        let hardening = torshield_ir_ultra::anti_ai_dpi::score_iran_dpi_hardening(&score.raw);
        if let (Some(obj), Some(h)) = (value.as_object_mut(), hardening.as_object()) {
            for key in ["hardened_line", "utls_profile", "alpn", "iran_dpi_hardening_score"] {
                if let Some(entry) = h.get(key) {
                    obj.insert(key.to_string(), entry.clone());
                }
            }
        }
        score_values.push(value);
    }

    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-smart-iran-scorer-v1",
        "censorship_level": scorer.level(),
        "tls_hardening": "utls-rotation+alpn-mutation",
        "bridges": score_values,
        "summary": {
            "input_records": records.len(),
            "ranked_records": scores.len(),
            "tiers": tier_counts(&scores),
        },
    });
    write_json(&options.output, &report)?;
    Ok(scores.len())
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("ai_bridge_reranker: {error}");
        std::process::exit(2);
    });

    match run(&options) {
        Ok(count) => println!(
            "ai_bridge_reranker: ranked {count} bridges -> {}",
            options.output.display()
        ),
        Err(error) => {
            eprintln!("ai_bridge_reranker: {error}");
            std::process::exit(1);
        }
    }
}
