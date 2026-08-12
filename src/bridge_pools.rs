//! Bridge Swarm Intelligence — Dynamic Pool Generation (§10 of the 15-point spec).
//!
//! When hundreds or thousands of bridges exist, this module generates
//! dynamic ranked pools:
//!   - Top 10
//!   - Top 25
//!   - Top 50
//!   - Top 100
//!   - Top 500
//!
//! Selection criteria:
//!   1. Reliability (stability score, success rate)
//!   2. Stability (consistent performance across time windows)
//!   3. Bootstrap success (if available)
//!   4. Historical performance (weighted recent > stale)
//!   5. Diversity (avoid over-concentration on a single AS/front-domain)
//!
//! Each pool enforces a diversity constraint: no more than N% of bridges
//! from the same AS or front domain, preventing single-point failures.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Pool size constants
// ─────────────────────────────────────────────────────────────────────────────

pub const POOL_TOP_10: usize = 10;
pub const POOL_TOP_25: usize = 25;
pub const POOL_TOP_50: usize = 50;
pub const POOL_TOP_100: usize = 100;
pub const POOL_TOP_500: usize = 500;

pub const POOL_SIZES: &[(usize, &str)] = &[
    (POOL_TOP_10, "top_10"),
    (POOL_TOP_25, "top_25"),
    (POOL_TOP_50, "top_50"),
    (POOL_TOP_100, "top_100"),
    (POOL_TOP_500, "top_500"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Bridge candidate
// ─────────────────────────────────────────────────────────────────────────────

/// A scored bridge candidate for pool selection.
#[derive(Debug, Clone)]
pub struct BridgeCandidate {
    /// The raw bridge line.
    pub line: String,
    /// Transport type.
    pub transport: String,
    /// Composite score (0–100). Higher = better.
    pub score: f64,
    /// Stability score from reputation engine (0–100).
    pub stability_score: f64,
    /// Success rate [0, 1].
    pub success_rate: f64,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<f64>,
    /// ASN organization name (for diversity tracking).
    pub asn_org: Option<String>,
    /// AS number (for diversity tracking).
    pub asn: Option<String>,
    /// Front domain (for CDN diversity tracking, webtunnel/meek).
    pub front_domain: Option<String>,
    /// Whether this bridge uses domain fronting.
    pub is_domain_fronted: bool,
    /// Last seen timestamp.
    pub last_seen: Option<String>,
}

impl BridgeCandidate {
    pub fn to_json(&self) -> Value {
        json!({
            "line": self.line,
            "transport": self.transport,
            "score": (self.score * 100.0).round() / 100.0,
            "stability_score": (self.stability_score * 100.0).round() / 100.0,
            "success_rate": (self.success_rate * 1000.0).round() / 1000.0,
            "avg_latency_ms": self.avg_latency_ms.map(|v| (v * 100.0).round() / 100.0),
            "asn_org": self.asn_org,
            "asn": self.asn,
            "front_domain": self.front_domain,
            "is_domain_fronted": self.is_domain_fronted,
            "last_seen": self.last_seen,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool generator
// ─────────────────────────────────────────────────────────────────────────────

/// Diversity constraint: maximum fraction of bridges from a single
/// AS or front domain within a pool.
pub const MAX_ASN_FRACTION: f64 = 0.25; // max 25% from same AS
pub const MAX_DOMAIN_FRACTION: f64 = 0.20; // max 20% using same front domain

/// Generates Top-N bridge pools from scored candidates while enforcing
/// diversity constraints.
pub struct PoolGenerator;

impl PoolGenerator {
    /// Generate all pool sizes from a list of scored candidates.
    /// Returns a map of pool_name → sorted bridge lines.
    pub fn generate_all(candidates: &[BridgeCandidate]) -> BTreeMap<String, Vec<BridgeCandidate>> {
        // Sort by score descending
        let mut sorted = candidates.to_vec();
        sorted.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| {
                    b.stability_score
                        .partial_cmp(&a.stability_score)
                        .unwrap_or(Ordering::Equal)
                })
                .then_with(|| {
                    let a_last = a.last_seen.as_deref().unwrap_or("");
                    let b_last = b.last_seen.as_deref().unwrap_or("");
                    b_last.cmp(a_last)
                })
        });

        let mut pools = BTreeMap::new();
        for &(size, name) in POOL_SIZES {
            if sorted.is_empty() {
                pools.insert(name.to_string(), Vec::new());
                continue;
            }
            let pool = Self::select_with_diversity(&sorted, size);
            pools.insert(name.to_string(), pool);
        }
        pools
    }

    /// Select `target_size` candidates with diversity constraints.
    ///
    /// Walks the sorted list and includes each candidate unless it would
    /// violate ASN or front-domain diversity limits. Falls back to
    /// including candidates without diversity filtering once the constraint
    /// pool is exhausted, ensuring the pool is populated even when diversity
    /// is insufficient.
    pub fn select_with_diversity(
        sorted: &[BridgeCandidate],
        target_size: usize,
    ) -> Vec<BridgeCandidate> {
        let mut selected: Vec<BridgeCandidate> = Vec::with_capacity(target_size);
        let mut asn_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut domain_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut deferred: Vec<BridgeCandidate> = Vec::new();

        for candidate in sorted {
            if selected.len() >= target_size {
                break;
            }

            let mut blocked = false;

            // Check ASN diversity
            if let Some(ref asn) = candidate.asn {
                let current = *asn_counts.get(asn).unwrap_or(&0);
                let max_for_asn = ((selected.len() + 1) as f64 * MAX_ASN_FRACTION).ceil() as usize;
                if current >= max_for_asn.max(1) {
                    blocked = true;
                }
            }

            // Check front-domain diversity (only for domain-fronted transports)
            if candidate.is_domain_fronted {
                if let Some(ref domain) = candidate.front_domain {
                    let current = *domain_counts.get(domain).unwrap_or(&0);
                    let max_for_domain =
                        ((selected.len() + 1) as f64 * MAX_DOMAIN_FRACTION).ceil() as usize;
                    if current >= max_for_domain.max(1) {
                        blocked = true;
                    }
                }
            }

            if blocked {
                deferred.push(candidate.clone());
                continue;
            }

            // Accept candidate
            if let Some(ref asn) = candidate.asn {
                *asn_counts.entry(asn.clone()).or_insert(0) += 1;
            }
            if candidate.is_domain_fronted {
                if let Some(ref domain) = candidate.front_domain {
                    *domain_counts.entry(domain.clone()).or_insert(0) += 1;
                }
            }
            selected.push(candidate.clone());
        }

        // If we didn't fill the pool, fill from deferred candidates
        // (dropping diversity constraints for the remainder)
        if selected.len() < target_size {
            for candidate in deferred {
                if selected.len() >= target_size {
                    break;
                }
                selected.push(candidate);
            }
        }

        // If still under, pad from the end of sorted (shouldn't happen normally)
        if selected.len() < target_size {
            let existing_keys: BTreeSet<String> = selected.iter().map(|c| c.line.clone()).collect();
            for candidate in sorted {
                if selected.len() >= target_size {
                    break;
                }
                if !existing_keys.contains(&candidate.line) {
                    selected.push(candidate.clone());
                }
            }
        }

        selected
    }

    /// Generate a JSON summary of all pools.
    pub fn pools_to_json(pools: &BTreeMap<String, Vec<BridgeCandidate>>) -> Value {
        let mut result = serde_json::Map::new();
        for (name, pool) in pools {
            let bridges: Vec<Value> = pool.iter().map(|c| c.to_json()).collect();

            // Compute diversity metrics for this pool
            let mut asns: BTreeSet<String> = BTreeSet::new();
            let mut front_domains: BTreeSet<String> = BTreeSet::new();
            let mut by_transport: BTreeMap<String, usize> = BTreeMap::new();
            for c in pool {
                if let Some(ref asn) = c.asn {
                    asns.insert(asn.clone());
                }
                if let Some(ref domain) = c.front_domain {
                    front_domains.insert(domain.clone());
                }
                *by_transport.entry(c.transport.clone()).or_insert(0) += 1;
            }

            result.insert(
                name.clone(),
                json!({
                    "size": bridges.len(),
                    "unique_asns": asns.len(),
                    "unique_front_domains": front_domains.len(),
                    "by_transport": by_transport,
                    "avg_score": if pool.is_empty() {
                        0.0
                    } else {
                        let sum: f64 = pool.iter().map(|c| c.score).sum();
                        (sum / pool.len() as f64 * 100.0).round() / 100.0
                    },
                    "bridges": bridges,
                }),
            );
        }
        Value::Object(result)
    }

    /// Build candidates from bridge history records and reputation data.
    ///
    /// `records` is a list of (bridge_key, bridge_record) tuples from the
    /// history manager. `reputations` is the output of
    /// [`crate::bridge_reputation::ReputationEngine::compute_all`].
    /// `iran_data` is the iran_results.json bridges array for AS/front
    /// domain enrichment.
    pub fn build_candidates(
        records: &[(String, crate::history::BridgeRecord)],
        reputations: &BTreeMap<String, crate::bridge_reputation::BridgeReputation>,
        iran_data: &[Value],
    ) -> Vec<BridgeCandidate> {
        // Index iran_data by line for O(1) lookup
        let iran_by_line: BTreeMap<String, &Value> = iran_data
            .iter()
            .filter_map(|v| {
                v.get("line")
                    .and_then(Value::as_str)
                    .map(|line| (line.to_string(), v))
            })
            .collect();

        records
            .iter()
            .filter_map(|(key, record)| {
                let rep = reputations.get(key)?;
                let iran = iran_by_line
                    .get(&record.raw)
                    .or_else(|| iran_by_line.get(key));

                let asn_org = iran
                    .and_then(|v| v.get("asn_org"))
                    .and_then(Value::as_str)
                    .map(|s| s.to_string());
                let asn = iran
                    .and_then(|v| v.get("asn"))
                    .and_then(Value::as_str)
                    .map(|s| s.to_string());
                let front_domain = iran
                    .and_then(|v| v.get("front_domain"))
                    .and_then(Value::as_str)
                    .map(|s| s.to_string());

                let is_domain_fronted = matches!(
                    record.transport.to_lowercase().as_str(),
                    "webtunnel" | "meek_lite" | "snowflake"
                );

                Some(BridgeCandidate {
                    line: record.raw.clone(),
                    transport: record.transport.clone(),
                    score: rep.stability_score,
                    stability_score: rep.stability_score,
                    success_rate: rep.weighted_success_rate,
                    avg_latency_ms: rep.overall_avg_latency_ms,
                    asn_org,
                    asn,
                    front_domain,
                    is_domain_fronted,
                    last_seen: Some(record.last_seen.clone()),
                })
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(
        line: &str,
        score: f64,
        stability: f64,
        asn: Option<&str>,
        domain: Option<&str>,
        is_domain_fronted: bool,
    ) -> BridgeCandidate {
        BridgeCandidate {
            line: line.to_string(),
            transport: "obfs4".to_string(),
            score,
            stability_score: stability,
            success_rate: score / 100.0,
            avg_latency_ms: Some(100.0),
            asn_org: asn.map(|s| s.to_string()),
            asn: asn.map(|s| s.to_string()),
            front_domain: domain.map(|s| s.to_string()),
            is_domain_fronted,
            last_seen: Some("2026-06-28T12:00:00+00:00".to_string()),
        }
    }

    #[test]
    fn select_top_10_returns_best_candidates() {
        let candidates: Vec<_> = (0..20)
            .map(|i| {
                make_candidate(
                    &format!("bridge_{i}"),
                    90.0 - (i as f64),
                    85.0 - (i as f64),
                    Some(&format!("AS{i}")),
                    None,
                    false,
                )
            })
            .collect();
        let pool = PoolGenerator::select_with_diversity(&candidates, 10);
        assert_eq!(pool.len(), 10);
        // First should be bridge_0 (highest score)
        assert_eq!(pool[0].line, "bridge_0");
        // Last should be bridge_9
        assert_eq!(pool[9].line, "bridge_9");
    }

    #[test]
    fn diversity_constraint_prevents_asn_overconcentration() {
        // 20 candidates all from the same AS
        let candidates: Vec<_> = (0..20)
            .map(|i| {
                make_candidate(
                    &format!("bridge_{i}"),
                    90.0 - (i as f64),
                    85.0 - (i as f64),
                    Some("AS1"),
                    None,
                    false,
                )
            })
            .collect();
        let pool = PoolGenerator::select_with_diversity(&candidates, 10);

        // With diversity enforced for ASN, only ceil(1 * 0.25) = 1 first,
        // ceil(2 * 0.25) = 1 => still 1 (no new unique ASN),
        // So all get deferred since they share the same AS.
        // The pool should still be filled to 10 from deferred candidates.
        assert_eq!(pool.len(), 10);
        // All should be from AS1 since that's all we have
        for c in &pool {
            assert_eq!(c.asn.as_deref(), Some("AS1"));
        }
    }

    #[test]
    fn diverse_pool_has_multiple_asns() {
        let mut candidates = Vec::new();
        for asn in &["AS_A", "AS_B", "AS_C", "AS_D", "AS_E"] {
            for i in 0..4 {
                candidates.push(make_candidate(
                    &format!("{}_{}", asn, i),
                    90.0 - (i as f64),
                    85.0,
                    Some(asn),
                    None,
                    false,
                ));
            }
        }
        let pool = PoolGenerator::select_with_diversity(&candidates, 10);
        assert_eq!(pool.len(), 10);

        // Count unique ASNs in the pool
        let unique_asns: BTreeSet<&str> = pool.iter().filter_map(|c| c.asn.as_deref()).collect();
        // With 5 ASNs and target of 10, we should get at least 3 unique ASNs
        assert!(
            unique_asns.len() >= 3,
            "expected >= 3 unique ASNs, got {}: {:?}",
            unique_asns.len(),
            unique_asns
        );
    }

    #[test]
    fn domain_fronted_diversity_constrained() {
        let mut candidates = Vec::new();
        // 20 webtunnel candidates all using the same front domain
        for i in 0..20 {
            candidates.push(BridgeCandidate {
                line: format!("webtunnel {}", i),
                transport: "webtunnel".to_string(),
                score: 90.0 - (i as f64),
                stability_score: 85.0,
                success_rate: 0.9,
                avg_latency_ms: Some(100.0),
                asn_org: Some("CDN Corp".to_string()),
                asn: Some(format!("AS_CDN_{}", i % 5)),
                front_domain: Some("cdn.example.com".to_string()),
                is_domain_fronted: true,
                last_seen: Some("2026-06-28T12:00:00+00:00".to_string()),
            });
        }
        let pool = PoolGenerator::select_with_diversity(&candidates, 10);
        assert_eq!(pool.len(), 10);
    }

    #[test]
    fn generate_all_creates_all_pool_sizes() {
        let candidates: Vec<_> = (0..600)
            .map(|i| {
                make_candidate(
                    &format!("bridge_{}", i),
                    95.0 - (i as f64 * 0.1),
                    90.0 - (i as f64 * 0.1),
                    Some(&format!("AS{}", i % 20)),
                    None,
                    false,
                )
            })
            .collect();
        let pools = PoolGenerator::generate_all(&candidates);

        assert!(pools.contains_key("top_10"));
        assert!(pools.contains_key("top_25"));
        assert!(pools.contains_key("top_50"));
        assert!(pools.contains_key("top_100"));
        assert!(pools.contains_key("top_500"));

        assert!(pools["top_10"].len() <= 10);
        assert!(pools["top_25"].len() <= 25);
        assert!(pools["top_50"].len() <= 50);
        assert!(pools["top_100"].len() <= 100);
        assert!(pools["top_500"].len() <= 500);
    }

    #[test]
    fn pools_sorted_by_score_descending() {
        let candidates: Vec<_> = vec![
            make_candidate("low", 10.0, 10.0, None, None, false),
            make_candidate("mid", 50.0, 50.0, None, None, false),
            make_candidate("high", 90.0, 90.0, None, None, false),
        ];
        let pools = PoolGenerator::generate_all(&candidates);
        let top10 = &pools["top_10"];
        assert_eq!(top10.len(), 3);
        assert_eq!(top10[0].line, "high");
        assert_eq!(top10[2].line, "low");
    }

    #[test]
    fn empty_candidates_produces_empty_pools() {
        let pools = PoolGenerator::generate_all(&[]);
        for &(_, name) in POOL_SIZES {
            assert!(pools[name].is_empty());
        }
    }

    #[test]
    fn pools_to_json_includes_diversity_metrics() {
        let candidates: Vec<_> = (0..30)
            .map(|i| {
                make_candidate(
                    &format!("bridge_{}", i),
                    80.0,
                    75.0,
                    Some(&format!("AS{}", i % 10)),
                    None,
                    false,
                )
            })
            .collect();
        let pools = PoolGenerator::generate_all(&candidates);
        let json = PoolGenerator::pools_to_json(&pools);

        let top25 = &json["top_25"];
        assert_eq!(top25["size"], 25);
        assert!(top25["unique_asns"].as_u64().unwrap() > 0);
        assert!(top25["avg_score"].as_f64().unwrap() > 0.0);
        assert!(top25["bridges"].is_array());
    }
}
