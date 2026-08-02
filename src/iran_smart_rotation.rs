//! Smart anti-filtering bridge rotation planner for Iran-native threat models.
//!
//! This module adds an additive, pure-logic capability on top of the existing
//! scored-bridge datasets (`bridge/iran_results.json`): it builds a *rotation
//! plan* that maximises resilience against Iran's SIAM/NGFW filtering stack by
//! combining four independent signals for every candidate bridge:
//!
//!  1. **Transport diversity** — consecutive plan entries round-robin across
//!     transports, because Iranian DPI blocks whole transports in waves
//!     (obfs4 waves, snowflake waves). A rotation that alternates transports
//!     keeps a survivable entry regardless of which transport is currently
//!     under siege.
//!  2. **Network-location (ASN surrogate) diversity** — bridges sharing an
//!     IPv4 /24 (or IPv6 /64) prefix tend to fail together when IRNA/TIC
//!     null-routes a subnet, so the planner cap-limits entries per prefix.
//!  3. **Empirical quality** — the `composite_score` already produced by the
//!     NIN/PT testing stages orders candidates inside each diversity bucket.
//!  4. **Censorship-level escalation** — at high censorship levels (NIN
//!     internet-cut) the transport preference order promotes pluggable
//!     transports with domain-fronting / traffic-morphing properties
//!     (`snowflake`, `webtunnel`) over more fingerprintable ones.
//!
//! The module is deterministic (no RNG, no wall-clock inside the ordering
//! logic) so CI parity gates stay reproducible, and it is pure
//! `serde_json`/`std` so it adds no dependency to the workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

use chrono::Utc;
use serde_json::{json, Value};

/// Canonical output locations consumed by the pipeline and the workflow.
pub const PLAN_PATH: &str = "data/iran_rotation_plan.json";
pub const EXPORT_PATH: &str = "export/iran_rotation_bridges.txt";

/// Default maximum size of a rotation plan.
pub const DEFAULT_ROTATION_SIZE: usize = 25;

/// Maximum number of entries accepted from a single ASN surrogate prefix.
const MAX_PER_PREFIX: usize = 3;

/// Transport preference order for censorship levels 1-3 (normal internet).
const PREFERENCE_NORMAL: [&str; 5] = ["obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla"];

/// Transport preference order for censorship levels 4-5 (SIAM escalation /
/// NIN internet-cut): fronting- and morphing-capable transports first.
const PREFERENCE_ESCALATED: [&str; 5] = ["snowflake", "webtunnel", "meek_lite", "obfs4", "vanilla"];

/// One scored rotation candidate extracted from a raw bridge record.
#[derive(Debug, Clone)]
struct Candidate {
    line: String,
    transport: String,
    prefix: String,
    score: f64,
    /// Original dataset index — stable tie-breaker for determinism.
    ordinal: usize,
}

impl Candidate {
    /// Deterministic total ordering: higher score first, then preferred
    /// transport, then original ordinal.
    fn sort_key(&self, transport_rank: usize) -> (i64, usize, usize) {
        // Scale the score to an integer for a total, NaN-safe order. Values
        // outside [0.0, 1.0] and non-finite inputs clamp to 0.
        let scaled = if self.score.is_finite() {
            (self.score.clamp(0.0, 1.0) * 1_000_000_000.0).round() as i64
        } else {
            0
        };
        (-scaled, transport_rank, self.ordinal)
    }
}

/// Extract the transport name from a bridge record, mirroring the tolerant
/// extraction used across the workspace: explicit `transport` field wins,
/// otherwise the first word of the raw line.
fn transport_of(bridge: &Value) -> String {
    for key in ["transport", "type"] {
        if let Some(t) = bridge.get(key).and_then(Value::as_str) {
            let t = t.trim().to_ascii_lowercase();
            if !t.is_empty() {
                return t;
            }
        }
    }
    let raw = bridge
        .get("raw")
        .or_else(|| bridge.get("line"))
        .and_then(Value::as_str)
        .unwrap_or("");
    raw.split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}

/// Extract the endpoint IP from the second whitespace-separated field of the
/// raw bridge line (`<transport> <ip:port> ...`).
fn ip_of(bridge: &Value) -> String {
    let raw = bridge
        .get("raw")
        .or_else(|| bridge.get("line"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let hostport = raw.split_whitespace().nth(1).unwrap_or("");
    hostport
        .rsplit_once(':')
        .map_or(hostport, |(host, _)| host)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string()
}

/// ASN surrogate prefix: IPv4 collapses to its /24, IPv6 to its /64 — the
/// granularity at which Iranian null-routing waves are typically observed.
fn prefix_of(ip: &str) -> String {
    if ip.is_empty() {
        return "unknown".to_string();
    }
    if ip.contains(':') {
        let hextets: Vec<&str> = ip.split(':').collect();
        if hextets.len() >= 4 {
            return hextets[..4].join(":");
        }
        return ip.to_string();
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 {
        return octets[..3].join(".");
    }
    ip.to_string()
}

/// Rank of a transport inside the censorship-appropriate preference list;
/// unknown transports sort after all known ones, in input order.
fn transport_rank(transport: &str, censorship_level: u8) -> usize {
    let preference = if censorship_level >= 4 {
        &PREFERENCE_ESCALATED
    } else {
        &PREFERENCE_NORMAL
    };
    preference
        .iter()
        .position(|t| *t == transport)
        .unwrap_or(preference.len())
}

/// Build the rotation plan from scored bridge records.
///
/// * `bridges` — records shaped like `bridge/iran_results.json` entries.
/// * `censorship_level` — 1 (open) ..= 5 (NIN cut); >= 4 escalates the
///   transport preference order.
/// * `max_entries` — upper bound of the plan; `0` means "unbounded".
///
/// The returned value is a self-describing JSON object; it is pure (no I/O)
/// and deterministic for identical inputs.
pub fn build_rotation_plan(bridges: &[Value], censorship_level: u8, max_entries: usize) -> Value {
    // ── 1. Extract + score candidates ────────────────────────────────────
    let mut candidates: Vec<Candidate> = Vec::with_capacity(bridges.len());
    for (ordinal, bridge) in bridges.iter().enumerate() {
        let transport = transport_of(bridge);
        let prefix = prefix_of(&ip_of(bridge));
        let score = bridge
            .get("composite_score")
            .or_else(|| bridge.get("score"))
            .or_else(|| {
                bridge
                    .get("smart_iran_scores")
                    .and_then(|s| s.get("composite"))
            })
            .and_then(Value::as_f64)
            .unwrap_or(0.5);
        let line = bridge
            .get("raw")
            .or_else(|| bridge.get("line"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if line.is_empty() {
            continue;
        }
        candidates.push(Candidate {
            line,
            transport,
            prefix,
            score,
            ordinal,
        });
    }

    // ── 2. Transport-aware deterministic ordering ────────────────────────
    candidates.sort_by(|a, b| {
        a.sort_key(transport_rank(&a.transport, censorship_level))
            .cmp(&b.sort_key(transport_rank(&b.transport, censorship_level)))
    });

    // ── 3. Diversity-constrained selection ───────────────────────────────
    let mut per_prefix: BTreeMap<String, usize> = BTreeMap::new();
    let mut last_transport: Option<String> = None;
    let mut deferred: Vec<Candidate> = Vec::new();
    let mut chosen: Vec<Candidate> = Vec::new();
    let cap = if max_entries == 0 {
        usize::MAX
    } else {
        max_entries
    };

    for candidate in candidates {
        if chosen.len() >= cap {
            break;
        }
        let used = per_prefix.entry(candidate.prefix.clone()).or_insert(0);
        let same_transport = last_transport.as_deref() == Some(candidate.transport.as_str());
        if *used >= MAX_PER_PREFIX || (same_transport && !chosen.is_empty()) {
            deferred.push(candidate);
            continue;
        }
        *used += 1;
        last_transport = Some(candidate.transport.clone());
        chosen.push(candidate);
    }
    // Second pass: fill remaining slots from deferred candidates, still
    // honouring the prefix cap (transport alternation relaxes once the
    // primary pass is exhausted — any surviving bridge beats none).
    if chosen.len() < cap {
        for candidate in deferred {
            if chosen.len() >= cap {
                break;
            }
            let used = per_prefix.entry(candidate.prefix.clone()).or_insert(0);
            if *used >= MAX_PER_PREFIX {
                continue;
            }
            *used += 1;
            chosen.push(candidate);
        }
    }

    // ── 4. Serialize plan + histograms ───────────────────────────────────
    let mut transport_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut prefixes: BTreeSet<String> = BTreeSet::new();
    let entries: Vec<Value> = chosen
        .iter()
        .enumerate()
        .map(|(rank, c)| {
            *transport_histogram.entry(c.transport.clone()).or_insert(0) += 1;
            prefixes.insert(c.prefix.clone());
            json!({
                "rank": rank + 1,
                "line": c.line,
                "transport": c.transport,
                "asn_prefix": c.prefix,
                "composite_score": c.score,
            })
        })
        .collect();

    json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "iran-smart-rotation-v1",
        "censorship_level": censorship_level,
        "candidates_evaluated": bridges.len(),
        "rotation_size": entries.len(),
        "asn_diversity": prefixes.len(),
        "transport_histogram": transport_histogram,
        "plan": entries,
    })
}

/// Build the plan and persist both the JSON plan and the plain-text export
/// (one bridge line per entry — directly usable by Tor Browser's network
/// settings or downstream distribution stages).
pub fn write_rotation_outputs(
    bridges: &[Value],
    censorship_level: u8,
    max_entries: usize,
    plan_path: &Path,
    export_path: &Path,
) -> Result<Value, Box<dyn Error>> {
    let plan = build_rotation_plan(bridges, censorship_level, max_entries);

    if let Some(parent) = plan_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_string_pretty(&plan)?;
    body.push('\n');
    std::fs::write(plan_path, body)?;

    if let Some(parent) = export_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut lines = String::new();
    if let Some(entries) = plan.get("plan").and_then(Value::as_array) {
        for entry in entries {
            if let Some(line) = entry.get("line").and_then(Value::as_str) {
                lines.push_str(line);
                lines.push('\n');
            }
        }
    }
    std::fs::write(export_path, lines)?;

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(raw: &str, transport: &str, score: f64) -> Value {
        json!({
            "raw": raw,
            "transport": transport,
            "composite_score": score,
        })
    }

    #[test]
    fn plans_alternate_transports_for_dpi_wave_resilience() {
        let bridges = vec![
            bridge(
                "obfs4 203.0.113.1:443 AAAA cert=AAAA iat-mode=0",
                "obfs4",
                0.99,
            ),
            bridge(
                "obfs4 203.0.113.2:443 BBBB cert=BBBB iat-mode=0",
                "obfs4",
                0.98,
            ),
            bridge("snowflake 192.0.2.1:1 CCCC", "snowflake", 0.01),
        ];
        let plan = build_rotation_plan(&bridges, 3, 0);
        let entries = plan["plan"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        // The top two entries must NOT share a transport even though obfs4
        // out-scores snowflake 99:1 — the alternation is the anti-wave
        // property under test.
        assert_ne!(entries[0]["transport"], entries[1]["transport"]);
    }

    #[test]
    fn caps_entries_per_asn_prefix() {
        let bridges: Vec<Value> = (1..=6)
            .map(|i| {
                bridge(
                    &format!("obfs4 198.51.100.{i}:443 FFFF{i} cert=C{i} iat-mode=0"),
                    "obfs4",
                    0.9,
                )
            })
            .collect();
        let plan = build_rotation_plan(&bridges, 3, 0);
        // All six share 198.51.100.0/24 — the cap allows at most 3.
        assert_eq!(plan["plan"].as_array().unwrap().len(), MAX_PER_PREFIX);
        assert_eq!(plan["asn_diversity"], 1);
    }

    #[test]
    fn escalated_censorship_promotes_fronting_transports() {
        let bridges = vec![
            bridge(
                "obfs4 203.0.113.9:443 DDDD cert=DDDD iat-mode=0",
                "obfs4",
                0.9,
            ),
            bridge("webtunnel 203.0.113.10:443 EEEE", "webtunnel", 0.9),
        ];
        let plan = build_rotation_plan(&bridges, 5, 0);
        assert_eq!(plan["plan"][0]["transport"], "webtunnel");
    }

    #[test]
    fn deterministic_for_identical_input() {
        let bridges = vec![
            bridge(
                "obfs4 203.0.113.1:443 AAAA cert=AAAA iat-mode=0",
                "obfs4",
                0.5,
            ),
            bridge("snowflake 192.0.2.9:2 BBBB", "snowflake", 0.5),
            bridge("webtunnel 192.0.2.10:3 CCCC", "webtunnel", 0.5),
        ];
        let first = build_rotation_plan(&bridges, 4, 10);
        let second = build_rotation_plan(&bridges, 4, 10);
        assert_eq!(first["plan"], second["plan"]);
    }

    #[test]
    fn skips_records_without_lines_and_reports_histogram() {
        let bridges = vec![
            json!({"transport": "obfs4", "composite_score": 0.7}),
            bridge(
                "meek_lite 192.0.2.20:443 ZZZZ url=https://meek.example/",
                "meek_lite",
                0.7,
            ),
        ];
        let plan = build_rotation_plan(&bridges, 2, 0);
        assert_eq!(plan["candidates_evaluated"], 2);
        assert_eq!(plan["rotation_size"], 1);
        assert_eq!(plan["transport_histogram"]["meek_lite"], 1);
    }

    #[test]
    fn write_rotation_outputs_persists_plan_and_export() {
        let dir =
            std::env::temp_dir().join(format!("iran-smart-rotation-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bridges = vec![
            bridge(
                "obfs4 203.0.113.1:443 AAAA cert=AAAA iat-mode=0",
                "obfs4",
                0.8,
            ),
            bridge("webtunnel 192.0.2.7:443 BBBB", "webtunnel", 0.8),
        ];
        let plan = write_rotation_outputs(
            &bridges,
            4,
            0,
            &dir.join("plan.json"),
            &dir.join("export.txt"),
        )
        .unwrap();
        assert_eq!(plan["rotation_size"], 2);
        let export = std::fs::read_to_string(dir.join("export.txt")).unwrap();
        assert_eq!(export.lines().count(), 2);
        assert!(export.contains("webtunnel"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
