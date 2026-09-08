//! Pipeline funnel advisory (additive, advisory-only).
//!
//! Turns the Section-1 diagnostic funnel into a REPEATABLE per-run
//! artifact. The binary reads only committed pipeline outputs
//! (`bridge/bridge_history.json`, `bridge/bridge_list_for_testing.json`,
//! `data/pt_results.json`, `bridge/iran_results.json`,
//! `data/supply_diagnostics.json`, published `bridge/*.txt` files) and
//! writes `data/funnel_advisory.json` plus GitHub Actions `::notice`
//! annotations with:
//!
//! * the full funnel table — sources → candidates → relay → TCP/probe →
//!   published — with real counts for THIS run;
//! * a non-routable endpoint census of the candidate pool (the shared
//!   [`crate::ip_guard`] policy applied to every history record, with the
//!   exact reason label per rejected line);
//! * the relay-coverage gap (candidates with NO relay observation, split
//!   into non-routable endpoints vs. everything else);
//! * an evidence-driven WebTunnel front-domain health advisory built from
//!   the live relay observations ([`crate::webtunnel_v2`]);
//! * an advisory retry plan for the probe-relay stage derived from
//!   [`crate::retry_engine::default_backoff`] — extending the retry
//!   engine's coverage to a stage it never served before.
//!
//! NOTHING here modifies any pipeline file, score, threshold, or published
//! bridge list. Every output is advisory; the binary always exits 0 unless
//! the report itself cannot be written.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{json, Value};

/// Advisory report path (new file; nothing existing is overwritten).
pub const REPORT_FILE: &str = "data/funnel_advisory.json";

/// Maximum number of sample history keys included in the non-routable
/// census (keeps the report bounded).
pub const CENSUS_SAMPLE_CAP: usize = 8;

/// One stage row of the funnel table.
#[derive(Debug, Clone, Default)]
pub struct FunnelStage {
    /// Stage name (e.g. `candidates_in_history`).
    pub name: &'static str,
    /// Count observed for this stage in this run.
    pub count: usize,
    /// Human-readable note about what the stage counts.
    pub note: &'static str,
}

impl FunnelStage {
    /// Serializable form used in the report.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "stage": self.name,
            "count": self.count,
            "note": self.note,
        })
    }
}

/// Read and parse a JSON file, degrading to `None` when missing or invalid.
#[must_use]
pub fn read_json_file(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Read a string-array bridge list (`bridge_list_for_testing.json`
/// schema). Non-string entries are skipped.
#[must_use]
pub fn read_bridge_lines(path: &Path) -> Vec<String> {
    match read_json_file(path) {
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|item| match item {
                Value::String(line) => Some(line),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Count non-empty lines in a text file (published-list counting).
#[must_use]
pub fn count_non_empty_lines(path: &Path) -> Option<usize> {
    let text = fs::read_to_string(path).ok()?;
    Some(text.lines().filter(|line| !line.trim().is_empty()).count())
}

/// Extract a normalised `host:port` endpoint key from a bridge line.
///
/// Handles the three shapes that occur in the testing list: `transport
/// IP:port`, bare `IP:port` (optionally after a `Bridge ` prefix), and
/// bracketed IPv6 endpoints. Returns `None` for URL-only lines without a
/// literal endpoint.
#[must_use]
pub fn endpoint_key(line: &str) -> Option<String> {
    let cleaned = line.trim().strip_prefix("Bridge ").unwrap_or(line.trim());
    // Bracketed IPv6 endpoint: [addr]:port
    if let Some((rest, _)) = cleaned.split_once(']') {
        if let Some(index) = rest.find('[') {
            let host = rest[index + 1..].to_string();
            if let Some(port) = cleaned
                .split(']')
                .nth(1)
                .and_then(|after| after.trim_start_matches(':').split_whitespace().next())
                .and_then(|port| port.parse::<u16>().ok())
            {
                return Some(format!("{host}:{port}"));
            }
        }
    }
    // IPv4 endpoint: first dotted quad followed by :port
    for token in cleaned.split_whitespace() {
        let candidate = token.trim_matches(['[', ']']);
        let Some((host, port)) = candidate.rsplit_once(':') else {
            continue;
        };
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            if let Ok(port) = port.parse::<u16>() {
                return Some(format!("{host}:{port}"));
            }
        }
    }
    None
}

/// Normalise a relay observation into the same `host:port` key space.
#[must_use]
fn relay_observation_key(observation: &Value) -> Option<String> {
    let host = observation.get("host").and_then(Value::as_str)?;
    let port = observation.get("port").and_then(Value::as_u64)?;
    if host.is_empty() || port == 0 {
        return None;
    }
    let host = host.trim_matches(['[', ']']);
    Some(format!("{host}:{port}"))
}

/// Census of non-routable endpoints in the candidate pool, using the exact
/// shared policy table every scraper already enforces
/// ([`crate::ip_guard::check_endpoint`]).
#[must_use]
pub fn non_routable_census(history: &Value) -> Value {
    let mut by_transport: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut samples: Vec<String> = Vec::new();
    let mut total = 0_usize;
    let Some(object) = history.as_object() else {
        return json!({
            "total_non_routable": 0,
            "by_transport": by_transport,
            "by_reason": by_reason,
            "samples": samples,
        });
    };
    for (key, record) in object {
        let raw = record
            .get("raw")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| key.clone());
        if let Some(reason) = crate::ip_guard::check_endpoint(&raw) {
            total += 1;
            *by_transport
                .entry(
                    record
                        .get("transport")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                )
                .or_insert(0) += 1;
            *by_reason.entry(reason.to_string()).or_insert(0) += 1;
            if samples.len() < CENSUS_SAMPLE_CAP {
                samples.push(key.clone());
            }
        }
    }
    json!({
        "total_non_routable": total,
        "by_transport": by_transport,
        "by_reason": by_reason,
        "samples": samples,
        "policy": "ip_guard::check_endpoint (the same reserved-range table every scraper source applies at ingest)",
    })
}

/// Relay-coverage accounting: which candidates received a relay observation
/// in this run, and whether the unobserved tail is dominated by
/// non-routable endpoints (which can never succeed and only burn the relay
/// budget).
#[must_use]
pub fn relay_coverage(testing_lines: &[String], relay_results: &[Value]) -> Value {
    let observed: std::collections::BTreeSet<String> = relay_results
        .iter()
        .filter_map(relay_observation_key)
        .collect();
    let mut unobserved_non_routable = 0_usize;
    let mut unobserved_other = 0_usize;
    let mut unobserved_by_transport: BTreeMap<String, usize> = BTreeMap::new();
    for line in testing_lines {
        let Some(key) = endpoint_key(line) else {
            // URL-only lines without a literal endpoint cannot be joined by
            // host:port; count separately.
            *unobserved_by_transport
                .entry("no_literal_endpoint".to_string())
                .or_insert(0) += 1;
            continue;
        };
        if observed.contains(&key) {
            continue;
        }
        if crate::ip_guard::contains_documentation_or_reserved_endpoint(line) {
            unobserved_non_routable += 1;
        } else {
            unobserved_other += 1;
        }
        let transport = line
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();
        *unobserved_by_transport
            .entry(
                if transport == "Bridge" || transport.parse::<std::net::Ipv4Addr>().is_ok() {
                    "vanilla".to_string()
                } else {
                    transport
                },
            )
            .or_insert(0) += 1;
    }
    let success = relay_results
        .iter()
        .filter(|observation| {
            observation
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    json!({
        "candidates": testing_lines.len(),
        "relay_observations": relay_results.len(),
        "relay_success": success,
        "unobserved_candidates": unobserved_non_routable + unobserved_other,
        "unobserved_non_routable": unobserved_non_routable,
        "unobserved_other": unobserved_other,
        "unobserved_by_transport": unobserved_by_transport,
    })
}

/// Per-source yield table from `data/supply_diagnostics.json` (and the
/// community-mirror advisory report when present).
#[must_use]
pub fn source_yield(supply: Option<&Value>, community: Option<&Value>) -> Value {
    let mut sources: Vec<Value> = Vec::new();
    if let Some(list) = supply
        .and_then(|value| value.get("sources"))
        .and_then(Value::as_array)
    {
        for source in list {
            sources.push(json!({
                "source": source.get("source").cloned().unwrap_or(Value::Null),
                "requests": source.get("requests").cloned().unwrap_or(Value::Null),
                "responses_ok": source.get("responses_ok").cloned().unwrap_or(Value::Null),
                "fetched_lines": source.get("fetched_lines").cloned().unwrap_or(Value::Null),
                "added_records": source.get("added_records").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    if let Some(mirrors) = community
        .and_then(|value| value.get("mirrors"))
        .and_then(Value::as_array)
    {
        for mirror in mirrors {
            sources.push(json!({
                "source": format!(
                    "community_mirror:{}",
                    mirror.get("repo").and_then(Value::as_str).unwrap_or("?")
                ),
                "requests": mirror
                    .get("files")
                    .and_then(Value::as_array)
                    .map(|files| files.len())
                    .unwrap_or(0),
                "responses_ok": mirror.get("files_fetched_ok").cloned().unwrap_or(Value::Null),
                "fetched_lines": mirror.get("fetched_lines").cloned().unwrap_or(Value::Null),
                "added_records": 0,
                "note": "advisory mode: valid_lines reported, merge disabled by default (COMMUNITY_MIRRORS_MERGE=true to merge)",
            }));
        }
    }
    json!({ "sources": sources })
}

/// Advisory retry plan for the probe-relay stage, derived from the shared
/// retry engine's backoff curve. This extends [`crate::retry_engine`]
/// coverage to the relay stage (a stage it never served before) without
/// changing any existing retry behaviour.
#[must_use]
pub fn relay_retry_plan(unobserved: usize) -> Value {
    let attempts: Vec<Value> = (1_i64..=3)
        .map(|attempt| {
            json!({
                "attempt": attempt,
                "suggested_backoff_secs": crate::retry_engine::default_backoff(attempt),
            })
        })
        .collect();
    json!({
        "stage": "probe-relay",
        "unobserved_candidates": unobserved,
        "recommendation": if unobserved == 0 {
            "full coverage — no re-run needed"
        } else {
            "re-run Stage 4 for the unobserved set (non-routable endpoints can be excluded to save budget)"
        },
        "backoff_schedule": attempts,
        "advisory_only": true,
    })
}

/// Published-list counts used as the final funnel stage.
#[must_use]
pub fn published_counts(bridge_dir: &Path) -> Value {
    let files = [
        "obfs4.txt",
        "obfs4_tested.txt",
        "vanilla.txt",
        "vanilla_tested.txt",
        "webtunnel.txt",
        "webtunnel_ipv6.txt",
        "iran_likely_working_all.txt",
        "iran_likely_working_obfs4.txt",
        "iran_likely_working_vanilla.txt",
        "iran_likely_working_webtunnel.txt",
        "iran_likely_working_snowflake.txt",
        "tested_global_obfs4.txt",
        "tested_global_vanilla.txt",
        "tested_global_webtunnel.txt",
    ];
    let mut counts = serde_json::Map::new();
    for file in files {
        let count = count_non_empty_lines(&bridge_dir.join(file));
        counts.insert(
            file.to_string(),
            count.map_or(Value::Null, |value| json!(value)),
        );
    }
    Value::Object(counts)
}

/// Build the complete funnel report for a repository checkout.
#[must_use]
pub fn build_funnel_report(repo_root: &Path) -> Value {
    let history = read_json_file(&repo_root.join("bridge/bridge_history.json"));
    let testing_lines = read_bridge_lines(&repo_root.join("bridge/bridge_list_for_testing.json"));
    let relay = read_json_file(&repo_root.join("data/pt_results.json"))
        .and_then(|value| {
            value
                .as_array()
                .cloned()
                .or_else(|| value.get("bridges").and_then(Value::as_array).cloned())
        })
        .unwrap_or_default();
    let iran_results = read_json_file(&repo_root.join("bridge/iran_results.json"));
    let supply = read_json_file(&repo_root.join("data/supply_diagnostics.json"));
    let community = read_json_file(&repo_root.join("data/community_mirrors_report.json"));

    let history_len = history
        .as_ref()
        .and_then(|value| value.as_object())
        .map_or(0, |object| object.len());
    let bridges = iran_results
        .as_ref()
        .and_then(|value| value.get("bridges"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tcp_tested = bridges.len();
    let tcp_reachable = bridges
        .iter()
        .filter(|bridge| {
            bridge
                .get("tcp_reachable")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let relay_success = relay
        .iter()
        .filter(|observation| {
            observation
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();

    let coverage = relay_coverage(&testing_lines, &relay);
    let census = history
        .as_ref()
        .map_or_else(|| non_routable_census(&Value::Null), non_routable_census);
    let webtunnel_lines: Vec<String> = testing_lines
        .iter()
        .filter(|line| line.trim_start_matches("Bridge ").starts_with("webtunnel"))
        .cloned()
        .collect();
    let front_advisory = crate::webtunnel_v2::front_health_advisory(&webtunnel_lines, &relay);
    let unobserved = coverage
        .get("unobserved_candidates")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;

    let stages = [
        FunnelStage {
            name: "sources_fetched_lines",
            count: supply
                .as_ref()
                .and_then(|value| value.get("sources"))
                .and_then(Value::as_array)
                .map(|sources| {
                    sources
                        .iter()
                        .filter_map(|s| s.get("fetched_lines").and_then(Value::as_u64))
                        .sum::<u64>() as usize
                })
                .unwrap_or(0),
            note: "raw lines fetched by the extended-source draws this run (see sources table)",
        },
        FunnelStage {
            name: "candidates_in_history",
            count: history_len,
            note: "deduplicated bridge_history.json records (the whole candidate pool)",
        },
        FunnelStage {
            name: "testing_candidates",
            count: testing_lines.len(),
            note: "bridge_list_for_testing.json entries handed to the probe stages",
        },
        FunnelStage {
            name: "relay_attempted",
            count: relay.len(),
            note: "probe-relay observations returned by the Cloudflare Worker",
        },
        FunnelStage {
            name: "relay_success",
            count: relay_success,
            note: "relay observations with success=true",
        },
        FunnelStage {
            name: "tcp_tested",
            count: tcp_tested,
            note: "iran_tester bridges array (runner-side TCP/ASN/OONI analysis)",
        },
        FunnelStage {
            name: "tcp_reachable",
            count: tcp_reachable,
            note: "iran_tester tcp_reachable=true (the publication evidence tier)",
        },
        FunnelStage {
            name: "published_advisory_working",
            count: count_non_empty_lines(&repo_root.join("bridge/iran_likely_working_all.txt"))
                .unwrap_or(0),
            note: "bridge/iran_likely_working_all.txt lines (advisory working set)",
        },
    ];

    json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "module": "pipeline_funnel_advisory",
        "advisory_only": true,
        "funnel": stages.iter().map(FunnelStage::to_json).collect::<Vec<_>>(),
        "sources": source_yield(supply.as_ref(), community.as_ref()),
        "non_routable_census": census,
        "relay_coverage": coverage,
        "webtunnel_front_health": front_advisory,
        "relay_retry_plan": relay_retry_plan(unobserved),
        "published_counts": published_counts(&repo_root.join("bridge")),
        "publications_gate": {
            "live_gate": "bridge_publication.rs candidates_from_history: probe.tcp_reachable || probe.transport_capable, else history tcp_reachable || probe_successes > 0 || test_pass",
            "ewma_health_score_used_by_publication": false,
            "ewma_consumers": [
                "tor_collector/service.rs candidate ordering (prioritisation only)",
                "drift_advisory.rs advisory report (Stage 8u)",
            ],
        },
    })
}

/// Emit GitHub Actions `::notice` annotations for the headline numbers.
pub fn emit_notices(report: &Value) {
    if let Some(stages) = report.get("funnel").and_then(Value::as_array) {
        let parts: Vec<String> = stages
            .iter()
            .map(|stage| {
                format!(
                    "{}={}",
                    stage.get("stage").and_then(Value::as_str).unwrap_or("?"),
                    stage.get("count").and_then(Value::as_u64).unwrap_or(0)
                )
            })
            .collect();
        println!("::notice title=FUNNEL::{}", parts.join(" "));
    }
    if let Some(census) = report.get("non_routable_census") {
        println!(
            "::notice title=FUNNEL::non_routable_endpoints_in_pool={}",
            census
                .get("total_non_routable")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        );
    }
    if let Some(coverage) = report.get("relay_coverage") {
        println!(
            "::notice title=FUNNEL::relay_unobserved={} (non_routable={}, other={})",
            coverage
                .get("unobserved_candidates")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            coverage
                .get("unobserved_non_routable")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            coverage
                .get("unobserved_other")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_key_parses_vanilla_obfs4_and_ipv6_lines() {
        assert_eq!(
            endpoint_key("Bridge 102.212.98.168:9393 B2CF966100CA013C4456643C98092B6FEBA3A304"),
            Some("102.212.98.168:9393".to_string())
        );
        assert_eq!(
            endpoint_key("obfs4 1.2.3.4:443 FINGER cert=abc"),
            Some("1.2.3.4:443".to_string())
        );
        assert_eq!(
            endpoint_key("webtunnel [2001:db8::1]:443 FINGER url=https://front.example.com/x"),
            Some("2001:db8::1:443".to_string())
        );
        assert_eq!(
            endpoint_key("snowflake url=https://broker.example.com/x"),
            None
        );
    }

    #[test]
    fn census_counts_documentation_ranges_by_reason() {
        let history = json!({
            "webtunnel [2001:db8:1169::1]:443 FINGER url=https://front.example.com/x ver=0.0.4": {
                "raw": "webtunnel [2001:db8:1169::1]:443 FINGER url=https://front.example.com/x ver=0.0.4",
                "transport": "webtunnel"
            },
            "obfs4 1.2.3.4:443 FINGER cert=abc": {
                "raw": "obfs4 1.2.3.4:443 FINGER cert=abc",
                "transport": "obfs4"
            },
            "obfs4 127.0.0.1:9001 FINGER cert=abc": {
                "raw": "obfs4 127.0.0.1:9001 FINGER cert=abc",
                "transport": "obfs4"
            }
        });
        let census = non_routable_census(&history);
        assert_eq!(census["total_non_routable"], 2);
        assert_eq!(census["by_transport"]["webtunnel"], 1);
        assert_eq!(census["by_transport"]["obfs4"], 1);
    }

    #[test]
    fn coverage_splits_unobserved_into_non_routable_and_other() {
        let lines = vec![
            "obfs4 1.2.3.4:443 FINGER cert=abc".to_string(),
            "webtunnel [2001:db8::1]:443 FINGER url=https://front.example.com/x".to_string(),
            "obfs4 5.6.7.8:443 FINGER cert=abc".to_string(),
        ];
        let relay = vec![json!({
            "host": "1.2.3.4",
            "port": 443,
            "success": true,
        })];
        let coverage = relay_coverage(&lines, &relay);
        assert_eq!(coverage["candidates"], 3);
        assert_eq!(coverage["relay_observations"], 1);
        assert_eq!(coverage["relay_success"], 1);
        assert_eq!(coverage["unobserved_candidates"], 2);
        assert_eq!(coverage["unobserved_non_routable"], 1);
        assert_eq!(coverage["unobserved_other"], 1);
    }

    #[test]
    fn retry_plan_uses_retry_engine_backoff_curve() {
        let plan = relay_retry_plan(248);
        assert_eq!(plan["unobserved_candidates"], 248);
        let schedule = plan["backoff_schedule"].as_array().expect("schedule");
        assert_eq!(schedule.len(), 3);
        let first = schedule[0]["suggested_backoff_secs"].as_f64().unwrap();
        let third = schedule[2]["suggested_backoff_secs"].as_f64().unwrap();
        assert!(third > first, "backoff must increase across attempts");
        assert_eq!(first, crate::retry_engine::default_backoff(1));
    }

    #[test]
    fn build_report_over_a_fixture_tree() {
        let dir = std::env::temp_dir().join(format!(
            "funnel_fixture_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("bridge")).unwrap();
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::write(
            dir.join("bridge/bridge_history.json"),
            r#"{"obfs4 1.2.3.4:443 FINGER cert=abc": {"raw": "obfs4 1.2.3.4:443 FINGER cert=abc", "transport": "obfs4"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("bridge/bridge_list_for_testing.json"),
            r#"["obfs4 1.2.3.4:443 FINGER cert=abc", "webtunnel [2001:db8::1]:443 FINGER url=https://front.example.com/x"]"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("data/pt_results.json"),
            r#"[{"host": "1.2.3.4", "port": 443, "success": true, "transport": "obfs4"}]"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("bridge/iran_results.json"),
            r#"{"bridges": [{"line": "obfs4 1.2.3.4:443 FINGER cert=abc", "tcp_reachable": true}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("data/supply_diagnostics.json"),
            r#"{"sources": [{"source": "moat_builtin", "requests": 3, "responses_ok": 3, "fetched_lines": 7, "added_records": 0}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("bridge/iran_likely_working_all.txt"),
            "obfs4 1.2.3.4:443 FINGER cert=abc\n",
        )
        .unwrap();

        let report = build_funnel_report(&dir);
        let stages = report["funnel"].as_array().expect("funnel stages");
        assert!(stages
            .iter()
            .any(|s| s["stage"] == "candidates_in_history" && s["count"] == 1));
        assert!(stages
            .iter()
            .any(|s| s["stage"] == "published_advisory_working" && s["count"] == 1));
        assert_eq!(report["relay_coverage"]["unobserved_non_routable"], 1);
        assert_eq!(report["non_routable_census"]["total_non_routable"], 0);
        assert_eq!(report["sources"]["sources"][0]["source"], "moat_builtin");
        assert_eq!(
            report["publications_gate"]["ewma_health_score_used_by_publication"],
            false
        );
        emit_notices(&report); // must not panic
        let _ = std::fs::remove_dir_all(&dir);
    }
}
