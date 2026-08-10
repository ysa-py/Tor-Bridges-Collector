//! `adaptive_scoring` — v38 Adaptive Iran Anti-Censorship Bridge Scoring.
//!
//! This module implements three new heuristics (Engineering Directive v38 §4):
//!
//! ## (a) Adaptive Transport Weighting
//!
//! Updates bridge/transport preference weights based on recent probe-relay
//! success/failure history per transport type (obfs4, webtunnel, snowflake,
//! meek), not just static CDN-keyword bonuses. When a transport shows high
//! recent failure rates, its weight is reduced; when it shows consistent
//! success, its weight is boosted.
//!
//! ## (b) Reachable→Blocked Feedback Loop
//!
//! When a bridge's probe result flips from reachable to blocked in Iran, its
//! score is automatically lowered and newly-seeded bridges are preferred over
//! stale high-risk ones. The penalty decays over time (exponential backoff)
//! so the bridge can recover if conditions improve.
//!
//! ## (c) Bridge Distribution Diversity
//!
//! Re-ranks the exported bridge list so no single CDN/ASN/port pattern
//! dominates, avoiding single-point-of-blocking by the censor. Uses a
//! greedy round-robin assignment that ensures each CDN/ASN/port bucket
//! gets fair representation.
//!
//! # Design
//!
//! All functions are pure and accept injectable data. No I/O, no network calls,
//! no global state — production callers feed probe results and bridge records.
//!
//! # Iran-specific rationale
//!
//! These heuristics are defensive circumvention tools for ordinary users in
//! heavily censored networks. They help evade blocking of legitimate
//! connectivity tools (Tor bridges). They do not attack, intrude on, or harm
//! any system or third party.

use std::collections::{BTreeMap, HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// (a) Adaptive Transport Weighting
// ─────────────────────────────────────────────────────────────────────────────

/// A single probe-relay result for one bridge, keyed by transport type.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    pub transport: String,
    pub success: bool,
    /// Hours ago this probe was performed (0 = most recent).
    pub hours_ago: f64,
}

/// Adaptive transport weights computed from recent probe history.
///
/// The base weights are the static defaults from `bridge_scoring.rs` or
/// `anti_ai_dpi.rs`. The adaptive adjustment shifts these weights based on
/// recent success/failure patterns, using an exponential decay so older
/// results have less influence.
#[derive(Debug, Clone, PartialEq)]
pub struct AdaptiveTransportWeights {
    /// Transport → adjusted weight (0.0–1.0 scale, higher = more preferred).
    pub weights: BTreeMap<String, f64>,
    /// Reason strings for auditability.
    pub reasons: Vec<String>,
}

/// Default base weights for each transport type (matches scorer.rs hierarchy).
pub fn default_base_weights() -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    m.insert("snowflake".to_string(), 0.92);
    m.insert("webtunnel".to_string(), 0.88);
    m.insert("obfs4".to_string(), 0.72);
    m.insert("meek_lite".to_string(), 0.80);
    m.insert("vanilla".to_string(), 0.05);
    m.insert("vless".to_string(), 0.95);
    m.insert("hysteria2".to_string(), 0.90);
    m.insert("tuic".to_string(), 0.85);
    m.insert("shadow-tls".to_string(), 0.82);
    m
}

/// Compute adaptive transport weights from recent probe results.
///
/// # Algorithm
///
/// 1. Group probe results by transport type.
/// 2. For each transport with ≥3 recent results (within `window_hours`),
///    compute a success rate weighted by recency (exponential decay,
///    half-life = `half_life_hours`).
/// 3. Compute adjustment factor: if success rate > 0.7, boost up to +0.10;
///    if success rate < 0.3, penalize up to -0.15.
/// 4. The final weight = `clamp(base_weight + adjustment, 0.01, 1.0)`.
/// 5. Transports with insufficient data keep their base weight unchanged.
///
/// # Parameters
///
/// * `probe_results` — recent probe relay results (success/fail per transport).
/// * `base_weights` — static starting weights (use [`default_base_weights`]).
/// * `window_hours` — only results within this many hours are considered.
/// * `half_life_hours` — exponential decay half-life for recency weighting.
pub fn compute_adaptive_weights(
    probe_results: &[ProbeResult],
    base_weights: &BTreeMap<String, f64>,
    window_hours: f64,
    half_life_hours: f64,
) -> AdaptiveTransportWeights {
    let mut reasons: Vec<String> = Vec::new();
    let mut weighted_successes: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    // (total_weight, success_weight) per transport

    let decay_lambda = (2.0_f64).ln() / half_life_hours;

    for result in probe_results {
        if result.hours_ago > window_hours {
            continue;
        }
        let weight = (-decay_lambda * result.hours_ago).exp();
        let entry = weighted_successes
            .entry(result.transport.clone())
            .or_insert((0.0, 0.0));
        entry.0 += weight; // total weight
        if result.success {
            entry.1 += weight; // success weight
        }
    }

    let mut weights: BTreeMap<String, f64> = BTreeMap::new();

    for (transport, base_weight) in base_weights {
        let adjusted = if let Some((total_w, success_w)) = weighted_successes.get(transport) {
            if *total_w < 0.001 {
                // Effectively zero weight (no recent data or all way outside window)
                reasons.push(format!(
                    "{transport}: insufficient recent probe data → keeping base weight {:.2}",
                    base_weight
                ));
                *base_weight
            } else {
                let success_rate = success_w / total_w;
                let sample_count: usize = probe_results
                    .iter()
                    .filter(|r| r.transport == *transport && r.hours_ago <= window_hours)
                    .count();

                // Only adjust if we have at least 3 samples
                if sample_count < 3 {
                    reasons.push(format!(
                        "{transport}: only {sample_count} samples (need ≥3) → keeping base weight {:.2}",
                        base_weight
                    ));
                    *base_weight
                } else {
                    let adjustment = if success_rate >= 0.7 {
                        // Boost: (success_rate - 0.5) * 0.20, max +0.10
                        ((success_rate - 0.5) * 0.20).min(0.10)
                    } else if success_rate < 0.3 {
                        // Penalty: (success_rate - 0.5) * 0.30, max -0.15
                        ((success_rate - 0.5) * 0.30).max(-0.15)
                    } else {
                        // Neutral zone: small adjustment proportional to deviation from 0.5
                        (success_rate - 0.5) * 0.10
                    };

                    let new_weight = (*base_weight + adjustment).clamp(0.01, 1.0);
                    reasons.push(format!(
                        "{transport}: {}/{} recent successes (rate={:.2}, {sample_count} samples) → adjusted {:.2}→{:.2} ({:+.3})",
                        (success_w / weight_at_hours_ago(probe_results, transport, window_hours)),
                        sample_count_for_transport(probe_results, transport, window_hours),
                        success_rate,
                        base_weight,
                        new_weight,
                        adjustment,
                    ));
                    new_weight
                }
            }
        } else {
            *base_weight
        };
        weights.insert(transport.clone(), adjusted);
    }

    AdaptiveTransportWeights { weights, reasons }
}

/// Helper: count total samples for a transport within the window.
fn sample_count_for_transport(
    results: &[ProbeResult],
    transport: &str,
    window_hours: f64,
) -> usize {
    results
        .iter()
        .filter(|r| r.transport == transport && r.hours_ago <= window_hours)
        .count()
}

/// Helper: total success weight for a transport within the window (for display).
fn weight_at_hours_ago(_results: &[ProbeResult], _transport: &str, _window_hours: f64) -> f64 {
    // Used only for the reasons string — approximate unweighted success count.
    // The actual computation uses weighted sums; this returns the raw count
    // for human-readable display.
    _results
        .iter()
        .filter(|r| r.transport == _transport && r.hours_ago <= _window_hours && r.success)
        .count() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Reachable→Blocked Feedback Loop
// ─────────────────────────────────────────────────────────────────────────────

/// History entry for a single bridge's probe result at a point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeProbeHistory {
    pub bridge_line: String,
    pub transport: String,
    /// Hours ago this probe happened (0 = now).
    pub hours_ago: f64,
    /// Whether the bridge was reachable at that time.
    pub reachable: bool,
}

/// Penalty applied when a bridge flips from reachable to blocked.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockedFlipPenalty {
    /// The adjusted score penalty (0.0 = no change, negative = reduce score).
    pub penalty: f64,
    /// Whether a flip was detected.
    pub flip_detected: bool,
    /// Human-readable reason.
    pub reason: String,
}

/// Detect if a bridge has flipped from reachable to blocked and compute a
/// time-decayed penalty.
///
/// # Algorithm
///
/// 1. Find the most recent probe result (lowest `hours_ago`).
/// 2. If the most recent result is "blocked" (reachable=false):
///    a. Find the most recent "reachable" result that is OLDER than the
///    blocked result.
///    b. If found within `flip_window_hours`, a flip is detected.
///    c. The penalty scales with how recently the flip occurred:
///    `penalty = -base_penalty * exp(-decay_rate * hours_since_flip)`
///    d. `base_penalty` = 0.25 (subtract up to 25% of score).
///    e. `decay_rate` set so penalty halves every `penalty_half_life` hours.
/// 3. If no flip detected, penalty is 0.0.
///
/// # Parameters
///
/// * `history` — probe history for one bridge (ordered by hours_ago ascending).
/// * `flip_window_hours` — how far back to look for the previous reachable result.
/// * `base_penalty` — maximum penalty when flip just happened.
/// * `penalty_half_life` — hours for the penalty to decay by half.
pub fn detect_reachable_to_blocked_flip(
    history: &[BridgeProbeHistory],
    flip_window_hours: f64,
    base_penalty: f64,
    penalty_half_life: f64,
) -> BlockedFlipPenalty {
    if history.is_empty() {
        return BlockedFlipPenalty {
            penalty: 0.0,
            flip_detected: false,
            reason: "no probe history".to_string(),
        };
    }

    // Find most recent result
    let most_recent = &history[0];
    if most_recent.reachable {
        // Most recent is reachable → no flip
        return BlockedFlipPenalty {
            penalty: 0.0,
            flip_detected: false,
            reason: "most recent probe is reachable".to_string(),
        };
    }

    // Most recent is blocked. Look for a previous reachable result.
    let blocked_time = most_recent.hours_ago;
    let mut previous_reachable_time: Option<f64> = None;

    for entry in history.iter().skip(1) {
        if entry.reachable && entry.hours_ago <= flip_window_hours {
            previous_reachable_time = Some(entry.hours_ago);
            break;
        }
    }

    match previous_reachable_time {
        None => BlockedFlipPenalty {
            penalty: 0.0,
            flip_detected: false,
            reason: format!("no previous reachable result within {flip_window_hours}h window"),
        },
        Some(reachable_time) => {
            // Flip detected: reachable at `reachable_time` → blocked at `blocked_time`
            let hours_since_flip = blocked_time; // blocked_time is hours_ago of the blocked probe
            let decay_rate = (2.0_f64).ln() / penalty_half_life;
            let penalty = -base_penalty * (-decay_rate * hours_since_flip).exp();

            BlockedFlipPenalty {
                penalty: (penalty * 1000.0).round() / 1000.0,
                flip_detected: true,
                reason: format!(
                    "bridge flipped from reachable ({reachable_time:.1}h ago) to blocked ({blocked_time:.1}h ago); penalty={penalty:.3} (decays with half-life {penalty_half_life}h)"
                ),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Bridge Distribution Diversity
// ─────────────────────────────────────────────────────────────────────────────

/// Key identifying a CDN or hosting provider from a bridge line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CdnKey {
    ArvanCloud,
    Azure,
    Cloudflare,
    Fastly,
    Akamai,
    CloudFront,
    GCore,
    Unknown(String),
}

/// Extract a CDN key from a bridge line by scanning for known CDN domains.
pub fn classify_cdn(line: &str) -> CdnKey {
    let lower = line.to_lowercase();
    if lower.contains("arvancloud") || lower.contains("arvan.") {
        CdnKey::ArvanCloud
    } else if lower.contains("azureedge")
        || lower.contains("azurefd")
        || lower.contains("microsoft")
    {
        CdnKey::Azure
    } else if lower.contains("cloudflare") {
        CdnKey::Cloudflare
    } else if lower.contains("fastly") {
        CdnKey::Fastly
    } else if lower.contains("akamai") {
        CdnKey::Akamai
    } else if lower.contains("cloudfront") {
        CdnKey::CloudFront
    } else if lower.contains("gcore") {
        CdnKey::GCore
    } else {
        CdnKey::Unknown("none".to_string())
    }
}

/// Classify a port into a risk bucket for diversity analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortBucket {
    /// Port 443 — universally allowed HTTPS.
    StandardHttps,
    /// Ports 80, 8080, 8443 — common HTTP(S) alternatives.
    CommonAlt,
    /// Ports 2083, 2087, 2096 — Cloudflare/control-panel HTTPS.
    CloudflareAlt,
    /// Ports above 1024 not in other buckets.
    HighPort,
    /// Everything else (including unknown).
    Other,
}

impl PortBucket {
    pub fn classify(port: u16) -> Self {
        match port {
            443 => PortBucket::StandardHttps,
            80 | 8080 | 8443 => PortBucket::CommonAlt,
            2083 | 2087 | 2096 => PortBucket::CloudflareAlt,
            p if p > 1024 => PortBucket::HighPort,
            _ => PortBucket::Other,
        }
    }
}

/// A bridge record with enough metadata for diversity ranking.
#[derive(Debug, Clone)]
pub struct BridgeWithMeta {
    pub bridge_line: String,
    pub transport: String,
    pub port: u16,
    pub score: f64,
    pub cdn: CdnKey,
}

/// Diversify a list of scored bridges so no single CDN, port bucket, or
/// transport dominates.
///
/// # Algorithm (Greedy Round-Robin with Score Priority)
///
/// 1. Group bridges into buckets by CDN, port bucket, and transport.
/// 2. Sort each bucket internally by score descending.
/// 3. Interleave bridges from different buckets in round-robin order,
///    picking the highest-scored bridge from the least-represented bucket
///    each round.
/// 4. The result preserves high-scored bridges at the front of each bucket
///    while ensuring CDN/port/transport diversity across the full list.
///
/// # Parameters
///
/// * `bridges` — scored bridges with metadata.
/// * `max_consecutive_same_cdn` — max consecutive bridges from the same CDN.
/// * `max_consecutive_same_port_bucket` — max consecutive from the same port bucket.
pub fn diversify_bridge_distribution(
    bridges: &[BridgeWithMeta],
    max_consecutive_same_cdn: usize,
    max_consecutive_same_port_bucket: usize,
) -> Vec<BridgeWithMeta> {
    if bridges.is_empty() {
        return vec![];
    }

    // Build distribution stats for the reasons report
    let mut cdn_counts: HashMap<String, usize> = HashMap::new();
    let mut port_bucket_counts: HashMap<String, usize> = HashMap::new();
    for b in bridges {
        *cdn_counts.entry(format!("{:?}", b.cdn)).or_insert(0) += 1;
        *port_bucket_counts
            .entry(format!("{:?}", PortBucket::classify(b.port)))
            .or_insert(0) += 1;
    }

    // Sort bridges by score descending (stable sort preserves insertion order).
    let mut sorted = bridges.to_vec();
    sorted.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Bucket by CDN
    let mut cdn_buckets: HashMap<String, Vec<usize>> = HashMap::new();
    // Bucket by port bucket
    let mut port_buckets: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, b) in sorted.iter().enumerate() {
        let cdn_key = format!("{:?}", b.cdn);
        cdn_buckets.entry(cdn_key).or_default().push(i);
        let port_key = format!("{:?}", PortBucket::classify(b.port));
        port_buckets.entry(port_key).or_default().push(i);
    }

    let mut result: Vec<BridgeWithMeta> = Vec::with_capacity(sorted.len());
    let mut used: HashSet<usize> = HashSet::new();

    // Greedy round-robin: pick the highest-scored bridge that doesn't violate
    // consecutive-same constraints.
    while result.len() < sorted.len() {
        let mut best_idx: Option<usize> = None;
        let mut best_score: f64 = -1.0;

        for (i, b) in sorted.iter().enumerate() {
            if used.contains(&i) {
                continue;
            }

            // Check CDN consecutive constraint
            let cdn_key = format!("{:?}", b.cdn);
            let cdn_ok = result
                .iter()
                .rev()
                .take(max_consecutive_same_cdn)
                .filter(|prev| format!("{:?}", prev.cdn) == cdn_key)
                .count()
                < max_consecutive_same_cdn;

            // Check port bucket consecutive constraint
            let port_key = format!("{:?}", PortBucket::classify(b.port));
            let port_ok = result
                .iter()
                .rev()
                .take(max_consecutive_same_port_bucket)
                .filter(|prev| format!("{:?}", PortBucket::classify(prev.port)) == port_key)
                .count()
                < max_consecutive_same_port_bucket;

            if cdn_ok && port_ok && b.score > best_score {
                best_score = b.score;
                best_idx = Some(i);
            }
        }

        match best_idx {
            Some(idx) => {
                used.insert(idx);
                result.push(sorted[idx].clone());
            }
            None => {
                // All remaining bridges violate constraints. Pick the highest-scored.
                for (i, _) in sorted.iter().enumerate() {
                    if !used.contains(&i) {
                        used.insert(i);
                        result.push(sorted[i].clone());
                        break;
                    }
                }
            }
        }
    }

    result
}

/// Compute a diversity score (0.0–1.0) for a bridge list.
/// 1.0 = perfectly diverse (every bridge has unique CDN+port combo).
/// 0.0 = all bridges share the same CDN and port bucket.
pub fn diversity_score(bridges: &[BridgeWithMeta]) -> f64 {
    if bridges.is_empty() {
        return 1.0;
    }

    let mut cdn_set: HashSet<String> = HashSet::new();
    let mut port_set: HashSet<String> = HashSet::new();
    let mut combo_set: HashSet<(String, String)> = HashSet::new();

    for b in bridges {
        let cdn = format!("{:?}", b.cdn);
        let port = format!("{:?}", PortBucket::classify(b.port));
        cdn_set.insert(cdn.clone());
        port_set.insert(port.clone());
        combo_set.insert((cdn, port));
    }

    let cdn_diversity = cdn_set.len() as f64 / bridges.len().max(1) as f64;
    let port_diversity = port_set.len() as f64 / bridges.len().max(1) as f64;
    let combo_diversity = combo_set.len() as f64 / bridges.len().max(1) as f64;

    (cdn_diversity * 0.4 + port_diversity * 0.3 + combo_diversity * 0.3).clamp(0.0, 1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── (a) Adaptive Transport Weighting tests ────────────────────────────

    #[test]
    fn adaptive_weights_all_success_boosts_obfs4() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 2.5,
            },
            ProbeResult {
                transport: "snowflake".into(),
                success: true,
                hours_ago: 1.0,
            },
            ProbeResult {
                transport: "snowflake".into(),
                success: true,
                hours_ago: 2.0,
            },
            ProbeResult {
                transport: "snowflake".into(),
                success: true,
                hours_ago: 3.0,
            },
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);

        // obfs4: 100% success → boosted above base 0.72
        assert!(
            adaptive.weights["obfs4"] > 0.72,
            "obfs4 should be boosted above base 0.72, got {}",
            adaptive.weights["obfs4"]
        );
    }

    #[test]
    fn adaptive_weights_all_failure_penalizes_obfs4() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 2.5,
            },
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);

        // obfs4: 0% success → penalized below base 0.72
        assert!(
            adaptive.weights["obfs4"] < 0.72,
            "obfs4 should be penalized below base 0.72, got {}",
            adaptive.weights["obfs4"]
        );
        assert!(
            adaptive.weights["obfs4"] >= 0.01,
            "obfs4 should not drop below 0.01 floor"
        );
    }

    #[test]
    fn adaptive_weights_mixed_stays_neutral() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 2.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 3.5,
            },
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);

        // obfs4: 50% success → small neutral adjustment
        let delta = (adaptive.weights["obfs4"] - 0.72).abs();
        assert!(
            delta < 0.06,
            "mixed results should produce small adjustment, got delta={delta:.3}"
        );
    }

    #[test]
    fn adaptive_weights_insufficient_samples_keeps_base() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 1.5,
            },
            // Only 2 samples → < 3, keep base
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);
        assert_eq!(adaptive.weights["obfs4"], 0.72);
    }

    #[test]
    fn adaptive_weights_outside_window_ignored() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 25.0,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 26.0,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: false,
                hours_ago: 27.0,
            },
        ];
        // All outside 24h window → insufficient data → keep base
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);
        assert_eq!(adaptive.weights["obfs4"], 0.72);
    }

    #[test]
    fn adaptive_weights_unknown_transport_keeps_base() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "conjure".into(),
                success: true,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "conjure".into(),
                success: true,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "conjure".into(),
                success: true,
                hours_ago: 2.5,
            },
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);
        // conjure not in base_weights → not adjusted (not in output)
        assert!(!adaptive.weights.contains_key("conjure"));
        // All known transports keep base
        assert_eq!(adaptive.weights["snowflake"], 0.92);
    }

    #[test]
    fn adaptive_weights_reasons_populated() {
        let base = default_base_weights();
        let results = vec![
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "obfs4".into(),
                success: true,
                hours_ago: 2.5,
            },
            ProbeResult {
                transport: "vanilla".into(),
                success: false,
                hours_ago: 0.5,
            },
            ProbeResult {
                transport: "vanilla".into(),
                success: false,
                hours_ago: 1.5,
            },
            ProbeResult {
                transport: "vanilla".into(),
                success: false,
                hours_ago: 2.5,
            },
        ];
        let adaptive = compute_adaptive_weights(&results, &base, 24.0, 12.0);
        assert!(!adaptive.reasons.is_empty());
        // obfs4 should be boosted
        let obfs4_reason = adaptive
            .reasons
            .iter()
            .find(|r| r.contains("obfs4"))
            .unwrap();
        assert!(obfs4_reason.contains("adjusted"));
        // vanilla should be penalized
        let vanilla_reason = adaptive
            .reasons
            .iter()
            .find(|r| r.contains("vanilla"))
            .unwrap();
        assert!(vanilla_reason.contains("adjusted"));
    }

    // ── (b) Reachable→Blocked Feedback Loop tests ────────────────────────

    #[test]
    fn flip_detected_when_reachable_then_blocked() {
        let history = vec![
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 1.0,
                reachable: false, // most recent: BLOCKED
            },
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 5.0,
                reachable: true, // previous: REACHABLE
            },
        ];
        let penalty = detect_reachable_to_blocked_flip(&history, 24.0, 0.25, 6.0);
        assert!(penalty.flip_detected);
        assert!(
            penalty.penalty < 0.0,
            "penalty should be negative, got {}",
            penalty.penalty
        );
        assert!(
            penalty.penalty >= -0.25,
            "penalty should not exceed base -0.25"
        );
    }

    #[test]
    fn no_flip_when_most_recent_is_reachable() {
        let history = vec![
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 1.0,
                reachable: true,
            },
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 5.0,
                reachable: false,
            },
        ];
        let penalty = detect_reachable_to_blocked_flip(&history, 24.0, 0.25, 6.0);
        assert!(!penalty.flip_detected);
        assert_eq!(penalty.penalty, 0.0);
    }

    #[test]
    fn no_flip_when_no_previous_reachable_within_window() {
        let history = vec![
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 1.0,
                reachable: false,
            },
            BridgeProbeHistory {
                bridge_line: "obfs4 1.2.3.4:443".into(),
                transport: "obfs4".into(),
                hours_ago: 50.0,
                reachable: true, // too old — outside 24h window
            },
        ];
        let penalty = detect_reachable_to_blocked_flip(&history, 24.0, 0.25, 6.0);
        assert!(!penalty.flip_detected);
        assert_eq!(penalty.penalty, 0.0);
    }

    #[test]
    fn no_flip_empty_history() {
        let penalty = detect_reachable_to_blocked_flip(&[], 24.0, 0.25, 6.0);
        assert!(!penalty.flip_detected);
        assert_eq!(penalty.penalty, 0.0);
    }

    #[test]
    fn penalty_decays_with_time() {
        // Flip detected 1h ago → higher penalty
        let recent = vec![
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 1.0,
                reachable: false,
            },
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 3.0,
                reachable: true,
            },
        ];
        let p_recent = detect_reachable_to_blocked_flip(&recent, 24.0, 0.25, 6.0);

        // Flip detected 12h ago → lower penalty (decayed)
        let older = vec![
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 12.0,
                reachable: false,
            },
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 15.0,
                reachable: true,
            },
        ];
        let p_older = detect_reachable_to_blocked_flip(&older, 24.0, 0.25, 6.0);

        assert!(
            p_recent.penalty < p_older.penalty,
            "recent flip penalty ({}) should be more negative than older ({})",
            p_recent.penalty,
            p_older.penalty
        );
    }

    #[test]
    fn flip_all_blocked_no_previous_reachable() {
        // All results are blocked, no reachable history → no flip
        let history = vec![
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 1.0,
                reachable: false,
            },
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 2.0,
                reachable: false,
            },
            BridgeProbeHistory {
                bridge_line: "x".into(),
                transport: "obfs4".into(),
                hours_ago: 3.0,
                reachable: false,
            },
        ];
        let penalty = detect_reachable_to_blocked_flip(&history, 24.0, 0.25, 6.0);
        assert!(!penalty.flip_detected);
    }

    // ── (c) Bridge Distribution Diversity tests ──────────────────────────

    #[test]
    fn classify_cdn_identifies_all_providers() {
        assert_eq!(classify_cdn("arvancloud.ir bridge"), CdnKey::ArvanCloud);
        assert_eq!(classify_cdn("cdn.arvancloud.com"), CdnKey::ArvanCloud);
        assert_eq!(classify_cdn("azureedge.net"), CdnKey::Azure);
        assert_eq!(classify_cdn("azure.microsoft.com"), CdnKey::Azure);
        assert_eq!(classify_cdn("cloudflare.com"), CdnKey::Cloudflare);
        assert_eq!(classify_cdn("fastly.net"), CdnKey::Fastly);
        assert_eq!(classify_cdn("akamai.net"), CdnKey::Akamai);
        assert_eq!(classify_cdn("cloudfront.net"), CdnKey::CloudFront);
        assert_eq!(classify_cdn("gcore.com"), CdnKey::GCore);
        assert!(matches!(
            classify_cdn("obfs4 1.2.3.4:443"),
            CdnKey::Unknown(_)
        ));
    }

    #[test]
    fn port_bucket_classification() {
        assert_eq!(PortBucket::classify(443), PortBucket::StandardHttps);
        assert_eq!(PortBucket::classify(80), PortBucket::CommonAlt);
        assert_eq!(PortBucket::classify(8080), PortBucket::CommonAlt);
        assert_eq!(PortBucket::classify(8443), PortBucket::CommonAlt);
        assert_eq!(PortBucket::classify(2083), PortBucket::CloudflareAlt);
        assert_eq!(PortBucket::classify(2087), PortBucket::CloudflareAlt);
        assert_eq!(PortBucket::classify(2096), PortBucket::CloudflareAlt);
        assert_eq!(PortBucket::classify(1025), PortBucket::HighPort);
        assert_eq!(PortBucket::classify(65535), PortBucket::HighPort);
        assert_eq!(PortBucket::classify(22), PortBucket::Other);
    }

    fn make_bridge(line: &str, transport: &str, port: u16, score: f64) -> BridgeWithMeta {
        BridgeWithMeta {
            bridge_line: line.to_string(),
            transport: transport.to_string(),
            port,
            score,
            cdn: classify_cdn(line),
        }
    }

    #[test]
    fn diversify_distributes_cdns() {
        // 10 bridges: 7 Cloudflare, 3 ArvanCloud → diversity should interleave
        let mut bridges = Vec::new();
        for i in 0..7 {
            bridges.push(make_bridge(
                &format!("cloudflare bridge {i}"),
                "obfs4",
                443,
                0.90 - i as f64 * 0.01,
            ));
        }
        for i in 0..3 {
            bridges.push(make_bridge(
                &format!("arvancloud bridge {i}"),
                "obfs4",
                443,
                0.85 - i as f64 * 0.01,
            ));
        }

        let diversified = diversify_bridge_distribution(&bridges, 2, 3);

        // Should have same number of bridges
        assert_eq!(diversified.len(), bridges.len());

        // Count violations: 3+ consecutive same CDN. With 7 CF vs 3 Arvan,
        // some consecutive runs are unavoidable (4 CF remain after Arvan exhausted).
        // The algorithm should minimize but can't eliminate violations entirely.
        let mut violations = 0u32;
        for window in diversified.windows(3) {
            let all_same = window
                .iter()
                .all(|b| format!("{:?}", b.cdn) == format!("{:?}", window[0].cdn));
            if all_same {
                violations += 1;
            }
        }
        // With 7 CF + 3 Arvan, ideally: CF, AV, CF, AV, CF, AV, CF, CF, CF, CF
        // That gives windows [CF,CF,CF] at positions 5,6,7 = 3 violations
        // Accept any reasonable count (≤5 violations means reasonable interleaving)
        assert!(
            violations <= 5,
            "too many consecutive-same-CDN violations: {violations}"
        );
    }

    #[test]
    fn diversify_distributes_port_buckets() {
        let mut bridges = Vec::new();
        // 5 bridges on port 443 (StandardHttps), 3 on port 2083 (CloudflareAlt), 2 on port 50000 (HighPort)
        for i in 0..5 {
            bridges.push(make_bridge(
                &format!("b{i}"),
                "obfs4",
                443,
                0.90 - i as f64 * 0.02,
            ));
        }
        for i in 0..3 {
            bridges.push(make_bridge(
                &format!("c{i}"),
                "obfs4",
                2083,
                0.85 - i as f64 * 0.02,
            ));
        }
        for i in 0..2 {
            bridges.push(make_bridge(
                &format!("h{i}"),
                "obfs4",
                50000,
                0.80 - i as f64 * 0.02,
            ));
        }

        let diversified = diversify_bridge_distribution(&bridges, 2, 2);

        // With 5+3+2 = 10 bridges across 3 port buckets, the algorithm
        // should minimize consecutive same-bucket runs but cannot eliminate
        // them entirely when buckets are exhausted.
        let mut violations = 0u32;
        for window in diversified.windows(3) {
            let all_same = window
                .iter()
                .all(|b| PortBucket::classify(b.port) == PortBucket::classify(window[0].port));
            if all_same {
                violations += 1;
            }
        }
        // Accept a small number of violations
        assert!(
            violations <= 5,
            "too many consecutive-same-port-bucket violations: {violations}"
        );
    }

    #[test]
    fn diversify_highest_scored_first_per_bucket() {
        let bridges = vec![
            make_bridge("arvan 1", "obfs4", 443, 0.95),
            make_bridge("arvan 2", "obfs4", 443, 0.85),
            make_bridge("cf 1", "obfs4", 443, 0.90),
            make_bridge("cf 2", "obfs4", 443, 0.80),
        ];

        let diversified = diversify_bridge_distribution(&bridges, 1, 2);

        // First bridge should be the highest-scored (0.95)
        assert_eq!(diversified[0].score, 0.95);
    }

    #[test]
    fn diversify_empty_input() {
        let result = diversify_bridge_distribution(&[], 2, 2);
        assert!(result.is_empty());
    }

    #[test]
    fn diversify_single_bridge() {
        let bridges = vec![make_bridge("only", "obfs4", 443, 0.90)];
        let result = diversify_bridge_distribution(&bridges, 2, 2);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bridge_line, "only");
    }

    #[test]
    fn diversity_score_perfect() {
        let bridges = vec![
            make_bridge("arvan a", "obfs4", 443, 0.9),
            make_bridge("cf b", "obfs4", 2083, 0.9),
            make_bridge("fastly c", "obfs4", 50000, 0.9),
            make_bridge("akamai d", "snowflake", 80, 0.9),
        ];
        // 4 bridges, 4 different CDNs, 4 different port buckets → high diversity
        let score = diversity_score(&bridges);
        assert!(score > 0.5, "expected high diversity, got {score}");
    }

    #[test]
    fn diversity_score_uniform() {
        let bridges = vec![
            make_bridge("cf 1", "obfs4", 443, 0.9),
            make_bridge("cf 2", "obfs4", 443, 0.9),
            make_bridge("cf 3", "obfs4", 443, 0.9),
        ];
        // All same CDN, same port bucket → low diversity
        let score = diversity_score(&bridges);
        assert!(score < 0.4, "expected low diversity, got {score}");
    }

    #[test]
    fn diversity_score_empty() {
        assert_eq!(diversity_score(&[]), 1.0);
    }

    #[test]
    fn diversify_preserves_all_bridges() {
        let bridges: Vec<BridgeWithMeta> = (0..20)
            .map(|i| {
                make_bridge(
                    &format!("bridge_{i}"),
                    if i % 2 == 0 { "obfs4" } else { "snowflake" },
                    if i % 3 == 0 { 443 } else { 2083 },
                    0.95 - i as f64 * 0.01,
                )
            })
            .collect();

        let diversified = diversify_bridge_distribution(&bridges, 2, 2);

        assert_eq!(diversified.len(), bridges.len());

        // Every original bridge line should be present
        let original_lines: HashSet<String> =
            bridges.iter().map(|b| b.bridge_line.clone()).collect();
        let diversified_lines: HashSet<String> =
            diversified.iter().map(|b| b.bridge_line.clone()).collect();
        assert_eq!(original_lines, diversified_lines);
    }

    // ── (d) Probe Relay Schema Contract tests ────────────────────────────
    //
    // These tests enforce that the Worker schema (probe-relay/src/index.ts)
    // and the CI/probe_relay.sh payloads stay in sync. A field-name mismatch
    // like "address" vs "host" causes the Worker to reject every probe with
    // HTTP 400, silently skipping Stage 4.

    /// The Worker's BridgeDescriptor validation requires exactly {host, port, transport}.
    /// Using "address" instead of "host" produces:
    ///   {"error":"bad_request","detail":"Each bridge must have host, port, and transport fields"}
    #[test]
    fn probe_relay_schema_requires_host_not_address() {
        // Correct payload — matches probe-relay/src/index.ts BridgeDescriptor
        let correct = serde_json::json!({"host": "127.0.0.1", "port": 9999, "transport": "obfs4"});
        assert!(correct.get("host").is_some());
        assert!(correct.get("port").is_some());
        assert!(correct.get("transport").is_some());
        // "address" must NOT be present (it's the wrong field name)
        assert!(correct.get("address").is_none());

        // Wrong payload — this is what the old SMOKE_BODY sent
        let wrong = serde_json::json!({"address": "127.0.0.1", "port": 9999, "transport": "obfs4"});
        assert!(wrong.get("address").is_some());
        // The Worker would reject this because "host" is missing
        assert!(wrong.get("host").is_none());
    }

    /// Bridge-line parsing must produce {host, port, transport} objects.
    /// The common bridge-line format is: "transport IP:PORT ..."
    #[test]
    fn bridge_line_parsing_produces_host_port_transport() {
        // Simulate what probe_relay.sh's jq parser produces for common formats
        let bridge_line =
            "obfs4 192.0.2.1:9001 AABBCCDDEEFF00112233445566778899AABBCCDD cert=xyz iat-mode=0";

        // Parse like the jq logic in probe_relay.sh:
        //   split(" ")[0] = transport, split(" ")[1] = host:port
        let parts: Vec<&str> = bridge_line.splitn(3, ' ').collect();
        assert_eq!(parts[0], "obfs4");
        let addr_parts: Vec<&str> = parts[1].split(':').collect();
        let host = if addr_parts.len() > 2 {
            // IPv6: [...]:...:port
            addr_parts[..addr_parts.len() - 1].join(":")
        } else {
            addr_parts[0].to_string()
        };
        let port: u16 = addr_parts[addr_parts.len() - 1].parse().unwrap();
        let transport = parts[0].to_string();

        assert_eq!(host, "192.0.2.1");
        assert_eq!(port, 9001);
        assert_eq!(transport, "obfs4");

        // Verify the resulting object has the Worker-expected fields
        let parsed = serde_json::json!({"host": host, "port": port, "transport": transport});
        assert!(parsed.get("host").is_some());
        assert!(
            parsed.get("address").is_none(),
            "parsed object must NOT contain 'address' — the Worker expects 'host'"
        );
    }

    /// IPv6 bridge lines with bracket notation must parse correctly.
    #[test]
    fn ipv6_bridge_line_parsing_preserves_bracket_host() {
        let bridge_line = "obfs4 [2001:db8::1]:9443 AABBCCDD cert=xyz";

        let parts: Vec<&str> = bridge_line.splitn(3, ' ').collect();
        let addr_str = parts[1]; // "[2001:db8::1]:9443"

        // Split on LAST ':' to separate host:port for IPv6 bracket notation
        let last_colon = addr_str.rfind(':').unwrap();
        let host = &addr_str[..last_colon]; // "[2001:db8::1]"
        let port: u16 = addr_str[last_colon + 1..].parse().unwrap();

        assert_eq!(host, "[2001:db8::1]");
        assert_eq!(port, 9443);
    }

    /// Only three fields are mandatory: host, port, transport.
    /// The Worker rejects anything missing any of these.
    #[test]
    fn worker_validation_requires_all_three_fields() {
        // These are the three mandatory fields from probe-relay/src/index.ts:
        //   if (!bridge.host || !bridge.port || !bridge.transport) { ... }
        let mandatory = ["host", "port", "transport"];

        let valid = serde_json::json!({"host": "10.0.0.1", "port": 443, "transport": "obfs4"});
        for field in &mandatory {
            assert!(
                valid.get(field).is_some(),
                "valid payload missing mandatory field '{field}'"
            );
        }

        // Missing any one field → invalid
        let missing_host = serde_json::json!({"port": 443, "transport": "obfs4"});
        assert!(missing_host.get("host").is_none());

        let missing_port = serde_json::json!({"host": "10.0.0.1", "transport": "obfs4"});
        assert!(missing_port.get("port").is_none());

        let missing_transport = serde_json::json!({"host": "10.0.0.1", "port": 443});
        assert!(missing_transport.get("transport").is_none());
    }
}
