//! Rust-native Iran bridge re-ranker used by scheduled automation.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Map, Value};
use torshield_ir_ultra::smart_iran_scorer::{extract_endpoint, BridgeScore, SmartIranScorer};

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    censorship_level: i64,
    top_n: usize,
    /// `--deterministic-tiebreak` (default false): break final-score ties
    /// with a total order instead of input order, making the ranked
    /// artifact reproducible under input permutation. See
    /// docs/RERANK_TOP10_ROOT_CAUSE_2026-09-09.md §3.
    deterministic_tiebreak: bool,
}

fn parse_args() -> Result<Options, String> {
    let mut input = PathBuf::from("bridge/iran_results.json");
    let mut output = PathBuf::from("bridge/bridges_ai_iran_ranked.json");
    let mut censorship_level = 4_i64;
    let mut top_n = 0_usize;
    let mut deterministic_tiebreak = false;
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
                    .map_err(|_| "--censorship-level must be an integer".to_string())?;
            }
            "--top-n" => {
                top_n = args
                    .next()
                    .ok_or("--top-n requires an integer")?
                    .parse()
                    .map_err(|_| "--top-n must be an integer".to_string())?;
            }
            "--deterministic-tiebreak" => {
                deterministic_tiebreak = true;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: ai_bridge_reranker [--input PATH] [--output PATH] \
                     [--censorship-level 1..5] [--top-n N] [--deterministic-tiebreak]"
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
        deterministic_tiebreak,
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

/// Tie-break key for [`apply_tiebreak`]: a total order on otherwise-tied
/// scores (bridge id first, then the raw line).
fn tiebreak_key(score: &BridgeScore) -> (String, String) {
    let id = match &score.bridge_id {
        Value::String(text) => text.clone(),
        _ => String::new(),
    };
    (id, score.raw.clone())
}

/// Order the ranked list deterministically when `deterministic` is set.
///
/// Default (`false`): the list keeps `score_all`'s stable ordering — ties
/// preserve input order (Python parity; historical behavior, output
/// byte-identical).
///
/// With the flag: ties are broken by `(bridge_id, raw)` ascending, making
/// the artifact invariant under input permutation. The v43 audit
/// (docs/RERANK_TOP10_ROOT_CAUSE_2026-09-09.md, finding F2) measured the
/// default behavior's top-10 precision swinging 0.2 → 0.5 purely on input
/// order, because the top-10 was an arbitrary slice of a 70-member
/// score-tie group.
fn apply_tiebreak(scores: &mut [BridgeScore], deterministic: bool) {
    if !deterministic {
        return;
    }
    scores.sort_by(|a, b| {
        b.final_score
            .partial_cmp(&a.final_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| tiebreak_key(a).cmp(&tiebreak_key(b)))
    });
}

/// Whether the line carries an IPv4 `ip:port` endpoint — the only form the
/// Go TCP tier can dial from an IPv4-only CI runner. Broker-only
/// (snowflake), url-only (webtunnel), and bracketed-IPv6 lines are
/// TCP-untestable by design and must not be counted as false positives in
/// precision audits (v43 audit, finding F3: 336 of 1,626 records in the
/// audited dataset, including a 329-record IPv6 cohort at 0/329 measured
/// purely because the runner has no IPv6 egress).
fn tcp_tier_measurable_line(raw: &str) -> bool {
    !extract_endpoint(raw).0.is_empty()
}

/// `(distinct final scores, largest tie group)` for the summary's
/// degeneracy disclosure (v43 audit, finding F1: 22 distinct scores across
/// 1,626 records, largest tie group 574 — the per-bridge discrimination
/// ceiling any consumer of this artifact should know about).
fn score_tie_stats(scores: &[BridgeScore]) -> (usize, usize) {
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for score in scores {
        *counts.entry(score.final_score.to_bits()).or_insert(0) += 1;
    }
    let largest = counts.values().copied().max().unwrap_or(0);
    (counts.len(), largest)
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
    apply_tiebreak(&mut scores, options.deterministic_tiebreak);
    if options.top_n > 0 {
        scores.truncate(options.top_n);
    }

    let (distinct_final_scores, largest_tie_group) = score_tie_stats(&scores);
    let measurable = scores
        .iter()
        .filter(|score| tcp_tier_measurable_line(&score.raw))
        .count();
    let unmeasurable = scores.len() - measurable;

    let score_values: Vec<Value> = scores
        .iter()
        .map(|score| {
            let mut value = score.to_json();
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "tcp_tier_measurable".to_string(),
                    Value::Bool(tcp_tier_measurable_line(&score.raw)),
                );
            }
            value
        })
        .collect();
    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-smart-iran-scorer-v1",
        "censorship_level": scorer.level(),
        "bridges": score_values,
        "summary": {
            "input_records": records.len(),
            "ranked_records": scores.len(),
            "tiers": tier_counts(&scores),
            "tiebreak": if options.deterministic_tiebreak {
                "deterministic(final desc, bridge_id/raw asc)"
            } else {
                "input_order"
            },
            "distinct_final_scores": distinct_final_scores,
            "largest_tie_group": largest_tie_group,
            "tcp_tier_measurable_records": measurable,
            "tcp_tier_unmeasurable_records": unmeasurable,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pairs: &[(&str, Value)]) -> Map<String, Value> {
        let mut map = Map::new();
        for (key, value) in pairs {
            map.insert((*key).to_string(), value.clone());
        }
        map
    }

    #[test]
    fn deterministic_tiebreak_is_invariant_under_input_permutation() {
        let scorer = SmartIranScorer::default();
        let records = vec![
            record(&[("raw", json!("bridge obfs4 1.1.1.1:1 alpha"))]),
            record(&[("raw", json!("bridge obfs4 1.1.1.1:1 beta"))]),
            record(&[("raw", json!("bridge obfs4 1.1.1.1:1 gamma"))]),
        ];
        let reversed: Vec<Map<String, Value>> = records.iter().rev().cloned().collect();

        // All three records have identical scoring inputs, so their final
        // scores tie and only the tie-break decides the order.
        let mut default_forward = scorer.score_all(&records);
        apply_tiebreak(&mut default_forward, false);
        assert_eq!(default_forward[0].raw, "bridge obfs4 1.1.1.1:1 alpha");
        assert_eq!(default_forward[2].raw, "bridge obfs4 1.1.1.1:1 gamma");

        // Default (flag off): ties keep input order — reversed input yields
        // a different ranked list (the F2 defect).
        let mut default_reversed = scorer.score_all(&reversed);
        apply_tiebreak(&mut default_reversed, false);
        assert_eq!(default_reversed[0].raw, "bridge obfs4 1.1.1.1:1 gamma");
        assert_eq!(default_reversed[2].raw, "bridge obfs4 1.1.1.1:1 alpha");

        // Flag on: identical output regardless of input order, with the
        // total order (raw ascending) inside the tie group.
        let mut det_forward = scorer.score_all(&records);
        apply_tiebreak(&mut det_forward, true);
        let mut det_reversed = scorer.score_all(&reversed);
        apply_tiebreak(&mut det_reversed, true);
        for (forward, reversed) in det_forward.iter().zip(det_reversed.iter()) {
            assert_eq!(forward.raw, reversed.raw);
            assert_eq!(forward.final_score, reversed.final_score);
        }
        assert_eq!(det_forward[0].raw, "bridge obfs4 1.1.1.1:1 alpha");
        assert_eq!(det_forward[1].raw, "bridge obfs4 1.1.1.1:1 beta");
        assert_eq!(det_forward[2].raw, "bridge obfs4 1.1.1.1:1 gamma");
    }

    #[test]
    fn tcp_tier_measurable_line_classifies_endpoint_forms() {
        // IPv4 endpoints are dialable by the TCP tier.
        assert!(tcp_tier_measurable_line("obfs4 1.2.3.4:443 fp cert=xx"));
        assert!(tcp_tier_measurable_line("Bridge 5.6.7.8:9001 fp"));
        // Bracketed IPv6 endpoints cannot be dialed from the IPv4-only CI
        // runner — unmeasurable by the TCP tier by environment.
        assert!(!tcp_tier_measurable_line(
            "obfs4 [2001:db8::1]:443 fp cert=xx"
        ));
        // Broker-only / url-only lines have no endpoint to dial at all.
        assert!(!tcp_tier_measurable_line(
            "snowflake 2B280B23E1107BB6 fingerprint=2B280B23E1107BB6"
        ));
        assert!(!tcp_tier_measurable_line(
            "webtunnel 88C9B6F63D50 url=https://example.com/path"
        ));
    }

    #[test]
    fn score_tie_stats_reports_distinct_and_largest_group() {
        let scorer = SmartIranScorer::default();
        let records = vec![
            record(&[("raw", json!("bridge obfs4 1.1.1.1:1 a"))]),
            record(&[("raw", json!("bridge obfs4 1.1.1.1:1 b"))]),
            record(&[("raw", json!("bridge snowflake 2.2.2.2:443 c"))]),
        ];
        let scores = scorer.score_all(&records);
        let (distinct, largest) = score_tie_stats(&scores);
        assert_eq!(distinct, 2);
        assert_eq!(largest, 2);
    }
}
