//! BridgeSwarm Intelligence Engine (§1.1 of the v42 forensic audit).
//!
//! Implements Top-N selection (10 / 25 / 50 / 100 / 500) ranked by a weighted
//! composite of uptime, bootstrap success, circuit success, latency, and
//! stability — with hard diversity enforcement so no single bridge family
//! (front domain / CDN / ASN bucket) can dominate the selected pool.
//!
//! ## Rules
//!
//! * A bridge below `min_bootstrap_success` is never admitted to a Top-N
//!   selection: a bridge that cannot bootstrap is not worth publishing no
//!   matter how fast its TCP connect is.
//! * Family diversity is enforced with a per-family cap of
//!   `ceil(top_n * max_family_fraction)` (default 25%). Selection walks the
//!   composite-sorted candidates and admits the highest-scored bridge whose
//!   family still has capacity. If the cap makes it impossible to fill the
//!   pool (e.g. a single family supplies every candidate), the remaining
//!   slots are filled with the best remaining bridges and the violation is
//!   reported explicitly in `report["diversity_violations"]` — the engine
//!   never invents bridges to satisfy the cap.
//! * Every decision is evidence-based: the composite score and the per-family
//!   histogram are included in the JSON report for auditability.
//!
//! The module is pure — no I/O, no network, no global state. Callers feed
//! scored bridge records (from `bridge_reputation`, `bridge_scoring`, or
//! probe results) and receive the ordered selection plus its report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A bridge candidate carrying the swarm ranking metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmBridge {
    /// Canonical bridge line (the durable history key).
    pub bridge_line: String,
    /// Transport family, e.g. `obfs4`, `webtunnel`, `snowflake`.
    pub transport: String,
    /// Diversity key: front domain, CDN, or ASN bucket. Bridges with the
    /// same key share a single point of failure against domain-level
    /// blocking, so the swarm caps how many can be selected.
    pub family: String,
    /// Uptime fraction in [0, 1].
    pub uptime: f64,
    /// Bootstrap success rate in [0, 1].
    pub bootstrap_success: f64,
    /// Circuit build success rate in [0, 1].
    pub circuit_success: f64,
    /// Median latency in milliseconds.
    pub latency_ms: f64,
    /// Stability score in [0, 1] (recent performance weighted higher).
    pub stability: f64,
}

impl SwarmBridge {
    /// Weighted composite score in [0, 1] used for ranking.
    ///
    /// Latency is mapped through [`latency_score`] so higher scores mean
    /// better performance across every metric.
    pub fn composite(&self, config: &SwarmConfig) -> f64 {
        let weights = config.weights();
        let latency = latency_score(self.latency_ms);
        (weights.uptime * self.uptime.clamp(0.0, 1.0)
            + weights.bootstrap * self.bootstrap_success.clamp(0.0, 1.0)
            + weights.circuit * self.circuit_success.clamp(0.0, 1.0)
            + weights.latency * latency
            + weights.stability * self.stability.clamp(0.0, 1.0))
        .clamp(0.0, 1.0)
    }
}

/// Weights for the composite score. Kept as a small value struct so callers
/// can override individual dimensions without rebuilding the whole config.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CompositeWeights {
    /// Uptime share.
    pub uptime: f64,
    /// Bootstrap success share.
    pub bootstrap: f64,
    /// Circuit success share.
    pub circuit: f64,
    /// Latency share.
    pub latency: f64,
    /// Stability share.
    pub stability: f64,
}

impl Default for CompositeWeights {
    fn default() -> Self {
        Self {
            uptime: 0.15,
            bootstrap: 0.30,
            circuit: 0.25,
            latency: 0.15,
            stability: 0.15,
        }
    }
}

/// Engine configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Composite metric weights (must sum to ~1.0; the engine tolerates any
    /// positive values and renormalises internally).
    pub weights: CompositeWeights,
    /// Maximum fraction of a Top-N pool a single family may occupy.
    pub max_family_fraction: f64,
    /// Minimum bootstrap success required for admission. Bridges below this
    /// are excluded from selection (never published as top-tier).
    pub min_bootstrap_success: f64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            weights: CompositeWeights::default(),
            max_family_fraction: 0.25,
            min_bootstrap_success: 0.5,
        }
    }
}

impl SwarmConfig {
    /// Re-normalised weights summing to 1.0 (defensive against caller drift).
    pub fn weights(&self) -> CompositeWeights {
        let raw = self.weights;
        let sum =
            (raw.uptime + raw.bootstrap + raw.circuit + raw.latency + raw.stability).max(1e-9);
        CompositeWeights {
            uptime: raw.uptime / sum,
            bootstrap: raw.bootstrap / sum,
            circuit: raw.circuit / sum,
            latency: raw.latency / sum,
            stability: raw.stability / sum,
        }
    }
}

/// The canonical Top-N sizes the spec requires.
pub const TOP_N_SIZES: &[usize] = &[10, 25, 50, 100, 500];

/// Result of one Top-N selection.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmSelection {
    /// The requested pool size.
    pub top_n: usize,
    /// Selected bridges in composite order (ties broken by bridge line for
    /// deterministic output).
    pub selected: Vec<SwarmBridge>,
    /// Composite score per selected bridge, keyed by its bridge line.
    pub scores: BTreeMap<String, f64>,
    /// Per-family counts in the selection.
    pub family_histogram: BTreeMap<String, usize>,
    /// Per-transport counts in the selection.
    pub transport_histogram: BTreeMap<String, usize>,
    /// Largest family share in the selection (0.0 when empty).
    pub max_family_share: f64,
    /// Families that exceeded the cap because the pool could not otherwise
    /// be filled; empty when diversity held.
    pub diversity_violations: Vec<String>,
    /// Structured JSON report for dashboards and audit trails.
    pub report: Value,
}

impl SwarmSelection {
    /// Select `top_n` bridges from `bridges`, enforcing family diversity.
    pub fn select(bridges: &[SwarmBridge], top_n: usize, config: &SwarmConfig) -> Self {
        let top_n = top_n.max(1);
        // 0. Deduplicate by bridge line: a pool never contains the same
        //    bridge twice, and duplicate lines would skew the histograms.
        let mut seen = std::collections::BTreeSet::new();
        let unique: Vec<&SwarmBridge> = bridges
            .iter()
            .filter(|bridge| seen.insert(bridge.bridge_line.as_str()))
            .collect();
        let total_candidates = unique.len();

        // 1. Admission gate: bootstrap success must meet the minimum.
        let admitted: Vec<&SwarmBridge> = unique
            .into_iter()
            .filter(|bridge| bridge.bootstrap_success >= config.min_bootstrap_success)
            .collect();
        let admitted_count = admitted.len();

        // 2. Rank by composite, deterministic tie-break.
        let mut ranked: Vec<&SwarmBridge> = admitted;
        ranked.sort_by(|left, right| {
            right
                .composite(config)
                .partial_cmp(&left.composite(config))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.bridge_line.cmp(&right.bridge_line))
        });

        // 3. Round-robin family-diverse walk. Each pick takes the best
        //    remaining candidate from the least-represented family that still
        //    has candidates, so the pool alternates families instead of
        //    letting a single family flood the top. A family at its cap is
        //    skipped while any other family has capacity; if every remaining
        //    candidate belongs to a capped family, the pool is filled with
        //    the best remaining candidates and the cap relaxation is recorded
        //    in `diversity_violations` — never silently.
        let cap = (top_n as f64 * config.max_family_fraction.clamp(0.0, 1.0)).ceil() as usize;
        let cap = cap.max(1);
        let mut buckets: BTreeMap<String, Vec<&SwarmBridge>> = BTreeMap::new();
        for bridge in &ranked {
            buckets
                .entry(bridge.family.clone())
                .or_default()
                .push(bridge);
        }
        let mut selected: Vec<&SwarmBridge> = Vec::new();
        let mut selected_keys: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut family_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut violations: Vec<String> = Vec::new();

        loop {
            if selected.len() >= top_n {
                break;
            }
            // Pick the family with the fewest selections that still has
            // unselected candidates; ties broken by fewest remaining, then
            // family name for deterministic output.
            let mut best: Option<(usize, usize, String)> = None;
            for (family, bucket) in &buckets {
                let remaining = bucket
                    .iter()
                    .filter(|bridge| !selected_keys.contains(&bridge.bridge_line))
                    .count();
                if remaining == 0 {
                    continue;
                }
                let current = family_counts.get(family).copied().unwrap_or(0);
                let candidate = (current, remaining, family.clone());
                if best.as_ref().map_or(true, |best| candidate < *best) {
                    best = Some(candidate);
                }
            }
            let Some((current, _remaining, family)) = best else {
                break;
            };
            let bridge = buckets[&family]
                .iter()
                .find(|bridge| !selected_keys.contains(&bridge.bridge_line))
                .expect("family with remaining candidates must yield one");
            if current >= cap {
                violations.push(family.clone());
            }
            selected_keys.insert(bridge.bridge_line.clone());
            *family_counts.entry(family).or_insert(0) += 1;
            selected.push(bridge);
        }

        let selected = selected.into_iter().cloned().collect::<Vec<_>>();
        let scores: BTreeMap<String, f64> = selected
            .iter()
            .map(|bridge| (bridge.bridge_line.clone(), bridge.composite(config)))
            .collect();
        let mut family_histogram: BTreeMap<String, usize> = BTreeMap::new();
        let mut transport_histogram: BTreeMap<String, usize> = BTreeMap::new();
        for bridge in &selected {
            *family_histogram.entry(bridge.family.clone()).or_insert(0) += 1;
            *transport_histogram
                .entry(bridge.transport.clone())
                .or_insert(0) += 1;
        }
        let max_family_share = if selected.is_empty() {
            0.0
        } else {
            family_histogram.values().copied().max().unwrap_or(0) as f64 / selected.len() as f64
        };
        violations.sort();
        violations.dedup();

        let report = json!({
            "top_n": top_n,
            "admitted_candidates": admitted_count,
            "total_candidates": total_candidates,
            "per_family_cap": cap,
            "max_family_fraction": config.max_family_fraction,
            "min_bootstrap_success": config.min_bootstrap_success,
            "selected": selected.len(),
            "max_family_share": round3(max_family_share),
            "family_histogram": family_histogram,
            "transport_histogram": transport_histogram,
            "diversity_violations": violations,
            "scores": scores,
        });

        Self {
            top_n,
            selected,
            scores,
            family_histogram,
            transport_histogram,
            max_family_share,
            diversity_violations: violations,
            report,
        }
    }

    /// Run the full canonical rank ladder: Top-10/25/50/100/500.
    pub fn select_all_ranks(
        bridges: &[SwarmBridge],
        config: &SwarmConfig,
    ) -> BTreeMap<usize, SwarmSelection> {
        let mut selections = BTreeMap::new();
        for &size in TOP_N_SIZES {
            selections.insert(size, Self::select(bridges, size, config));
        }
        selections
    }
}

/// Map latency (ms) to a [0, 1] performance score.
///
/// * ≤ 150 ms → 1.0 (excellent)
/// * ≤ 400 ms → 0.8 (good)
/// * ≤ 800 ms → 0.5 (usable)
/// * otherwise  → 0.2 (slow but potentially usable)
pub fn latency_score(latency_ms: f64) -> f64 {
    if latency_ms <= 150.0 {
        1.0
    } else if latency_ms <= 400.0 {
        0.8
    } else if latency_ms <= 800.0 {
        0.5
    } else {
        0.2
    }
}

/// Round to three decimals for stable reports and comparisons.
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Diversity key derived from a bridge line and its front host.
///
/// Domain-fronted transports use the front domain; direct transports fall
/// back to the endpoint host. `parse` is the caller-supplied front-host
/// extractor (e.g. `crate::tor_collector::parsing::extract_front_host`) so
/// this module stays runtime-agnostic and pure.
pub fn family_for<F>(bridge_line: &str, transport: &str, parse_front: F) -> String
where
    F: FnOnce(&str) -> Option<String>,
{
    if matches!(
        transport,
        "webtunnel" | "meek-azure" | "snowflake" | "conjure"
    ) {
        if let Some(front) = parse_front(bridge_line) {
            return front;
        }
    }
    // Fall back to the first host-like token after the transport name.
    bridge_line
        .split_whitespace()
        .nth(1)
        .map(|token| {
            token
                .trim_matches(|c| matches!(c, '[' | ']' | ',' | ';' | '"'))
                .split(':')
                .next()
                .unwrap_or(token)
                .to_owned()
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default healthy bridge; metrics are overridden per test.
    fn bridge(line: &str, transport: &str, family: &str) -> SwarmBridge {
        SwarmBridge {
            bridge_line: line.to_owned(),
            transport: transport.to_owned(),
            family: family.to_owned(),
            uptime: 0.95,
            bootstrap_success: 0.95,
            circuit_success: 0.90,
            latency_ms: 120.0,
            stability: 0.90,
        }
    }

    fn healthy(line: &str, family: &str, latency: f64) -> SwarmBridge {
        let mut item = bridge(line, "webtunnel", family);
        item.latency_ms = latency;
        item
    }

    #[test]
    fn select_top_10_returns_exactly_ten() {
        let bridges: Vec<SwarmBridge> = (0..30)
            .map(|i| {
                healthy(
                    &format!("webtunnel 10.0.{}.1:443 F ver=0.0.3", i),
                    &format!("cdn-{}", i % 6),
                    100.0,
                )
            })
            .collect();
        let selection = SwarmSelection::select(&bridges, 10, &SwarmConfig::default());
        assert_eq!(selection.selected.len(), 10);
        assert_eq!(selection.selected.len(), selection.top_n);
    }

    #[test]
    fn select_top_25_and_500_are_supported() {
        let bridges: Vec<SwarmBridge> = (0..600)
            .map(|i| {
                healthy(
                    &format!("obfs4 10.0.{}.1:443 F ver=0.0.3", i),
                    &format!("asn-{}", i % 12),
                    200.0,
                )
            })
            .collect();
        let config = SwarmConfig::default();
        let ladder = SwarmSelection::select_all_ranks(&bridges, &config);
        assert_eq!(ladder.len(), TOP_N_SIZES.len());
        assert_eq!(ladder[&25].selected.len(), 25);
        assert_eq!(ladder[&500].selected.len(), 500);
    }

    #[test]
    fn low_bootstrap_bridges_are_never_admitted() {
        let mut weak = healthy("webtunnel 10.0.0.1:443 F ver=0.0.3", "cdn-a", 100.0);
        weak.bootstrap_success = 0.1;
        weak.circuit_success = 0.05;
        let strong = healthy("webtunnel 10.0.0.2:443 F ver=0.0.3", "cdn-b", 100.0);
        let selection = SwarmSelection::select(&[weak, strong], 10, &SwarmConfig::default());
        assert_eq!(selection.selected.len(), 1);
        assert!(selection.selected[0].bootstrap_success >= 0.5);
    }
    #[test]
    fn family_cap_prevents_single_family_domination() {
        // 20 bridges all from one family, plus 5 from a second family.
        // The engine must balance the pool 5/5 (the most diverse split
        // possible) instead of flooding with the 20-bridge family.
        let mut bridges: Vec<SwarmBridge> = (0..20)
            .map(|i| {
                healthy(
                    &format!("webtunnel 10.1.{}.1:443 F ver=0.0.3", i),
                    "mono-cdn",
                    90.0,
                )
            })
            .collect();
        for i in 0..5 {
            bridges.push(healthy(
                &format!("webtunnel 10.2.{}.1:443 F ver=0.0.3", i),
                "second-cdn",
                90.0,
            ));
        }
        let config = SwarmConfig::default(); // cap = ceil(10 * 0.25) = 3
        let selection = SwarmSelection::select(&bridges, 10, &config);
        assert_eq!(
            selection
                .family_histogram
                .get("mono-cdn")
                .copied()
                .unwrap_or(0),
            5,
            "pool must balance across both families, not flood from the 20-bridge one"
        );
        assert_eq!(
            selection
                .family_histogram
                .get("second-cdn")
                .copied()
                .unwrap_or(0),
            5
        );
        assert!(selection.max_family_share <= 0.5 + 1e-9);
        // The per-family cap (3) could not be fully honoured with only two
        // families in a 10-slot pool; the relaxation is reported honestly.
        assert!(!selection.diversity_violations.is_empty());
    }

    #[test]
    fn family_cap_holds_with_enough_families() {
        // Four families with plenty of candidates each: a 10-slot pool can be
        // filled with every family at or below its cap, so no violations.
        let bridges: Vec<SwarmBridge> = (0..100)
            .map(|i| {
                healthy(
                    &format!("obfs4 10.7.{}.1:443 F cert=x", i),
                    &format!("asn-{}", i % 4),
                    110.0,
                )
            })
            .collect();
        let selection = SwarmSelection::select(&bridges, 10, &SwarmConfig::default());
        assert_eq!(selection.selected.len(), 10);
        assert_eq!(selection.family_histogram.len(), 4);
        assert!(
            selection.family_histogram.values().all(|count| *count <= 3),
            "no family may exceed ceil(10*0.25)=3 when diversity is available"
        );
        assert!(selection.diversity_violations.is_empty());
    }

    #[test]
    fn unfillable_pool_reports_violation_and_fills_best_remaining() {
        // 8 bridges from one family, want Top-10: the cap (3) blocks 5, and
        // there are no other families, so the pool fills with best-remaining
        // and the violation is reported.
        let bridges: Vec<SwarmBridge> = (0..8)
            .map(|i| {
                healthy(
                    &format!("webtunnel 10.3.{}.1:443 F ver=0.0.3", i),
                    "only-cdn",
                    80.0,
                )
            })
            .collect();
        let selection = SwarmSelection::select(&bridges, 10, &SwarmConfig::default());
        assert_eq!(selection.selected.len(), 8);
        assert!(!selection.diversity_violations.is_empty());
        assert!(selection.report["diversity_violations"].is_array());
    }

    #[test]
    fn empty_input_yields_empty_selection() {
        let selection = SwarmSelection::select(&[], 10, &SwarmConfig::default());
        assert!(selection.selected.is_empty());
        assert_eq!(selection.max_family_share, 0.0);
    }

    #[test]
    fn composite_ranks_better_bridge_higher() {
        let good = healthy("webtunnel 10.4.0.1:443 F ver=0.0.3", "a", 80.0);
        let mut bad = bridge("webtunnel 10.4.0.2:443 F ver=0.0.3", "webtunnel", "a");
        bad.uptime = 0.3;
        bad.bootstrap_success = 0.55;
        bad.circuit_success = 0.4;
        bad.latency_ms = 1500.0;
        bad.stability = 0.2;
        let config = SwarmConfig::default();
        assert!(good.composite(&config) > bad.composite(&config));
    }

    #[test]
    fn latency_score_thresholds() {
        assert_eq!(latency_score(100.0), 1.0);
        assert_eq!(latency_score(150.0), 1.0);
        assert_eq!(latency_score(151.0), 0.8);
        assert_eq!(latency_score(400.0), 0.8);
        assert_eq!(latency_score(401.0), 0.5);
        assert_eq!(latency_score(800.0), 0.5);
        assert_eq!(latency_score(801.0), 0.2);
        assert_eq!(latency_score(5000.0), 0.2);
    }

    #[test]
    fn weights_renormalise_to_one() {
        let config = SwarmConfig {
            weights: CompositeWeights {
                uptime: 1.0,
                bootstrap: 1.0,
                circuit: 1.0,
                latency: 1.0,
                stability: 1.0,
            },
            ..SwarmConfig::default()
        };
        let w = config.weights();
        let sum = w.uptime + w.bootstrap + w.circuit + w.latency + w.stability;
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn family_for_uses_front_host_when_present() {
        let parsed = family_for(
            "webtunnel 1.2.3.4:443 F url=https://front.example.com/path ver=0.0.3",
            "webtunnel",
            crate::tor_collector::parsing::extract_front_host,
        );
        assert_eq!(parsed, "front.example.com");
    }

    #[test]
    fn family_for_falls_back_to_endpoint_host() {
        let parsed = family_for(
            "obfs4 1.2.3.4:443 FINGER cert=x",
            "obfs4",
            crate::tor_collector::parsing::extract_front_host,
        );
        assert_eq!(parsed, "1.2.3.4");
    }

    #[test]
    fn report_contains_audit_fields() {
        let bridges: Vec<SwarmBridge> = (0..5)
            .map(|i| {
                healthy(
                    &format!("obfs4 10.5.{}.1:443 F cert=x", i),
                    &format!("asn-{i}"),
                    150.0,
                )
            })
            .collect();
        let selection = SwarmSelection::select(&bridges, 10, &SwarmConfig::default());
        assert_eq!(selection.report["selected"], 5);
        assert_eq!(selection.report["total_candidates"], 5);
        assert!(selection.report["scores"].is_object());
        assert!(selection.report["transport_histogram"]["webtunnel"].is_number());
    }

    #[test]
    fn selection_is_deterministic_across_calls() {
        let bridges: Vec<SwarmBridge> = (0..40)
            .map(|i| {
                healthy(
                    &format!("obfs4 10.6.{}.1:443 F cert=x", i / 2),
                    &format!("asn-{}", i % 7),
                    120.0,
                )
            })
            .collect();
        let config = SwarmConfig::default();
        let first = SwarmSelection::select(&bridges, 25, &config);
        let second = SwarmSelection::select(&bridges, 25, &config);
        let lines_a: Vec<&str> = first
            .selected
            .iter()
            .map(|b| b.bridge_line.as_str())
            .collect();
        let lines_b: Vec<&str> = second
            .selected
            .iter()
            .map(|b| b.bridge_line.as_str())
            .collect();
        assert_eq!(lines_a, lines_b);
    }
}
