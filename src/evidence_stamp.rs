//! Per-bridge test-evidence stamping for `iran_results.json`.
//!
//! Every bridge entry carries a timestamped test result and its highest typed
//! verification stage. Legacy booleans and static inventory fields are not
//! promoted into observations because they do not preserve stage or vantage.
//!
//! Tier semantics (the stage actually recorded, not the protocol requested):
//!   * `tier_4_pt_handshake` — full PT/Tor handshake verified.
//!   * `tier_3_transport` — transport-specific handshake/signature verified.
//!   * `tier_2_pt_handshake` — a protocol-level signature (for example WS 101)
//!     verified.
//!   * `tier_1_tcp` — TCP connected; this does not establish PT capability.
//!   * `tier_0_attempt` — an observed refusal/timeout/error/inconclusive result
//!     before a positive connection stage.
//!   * `untested` — no typed observation with a recognized observer exists.
//!
//! Result semantics preserve the Stage 10 tags:
//!   * `tested_working` — a positive, typed S2+ protocol result from a recognized vantage.
//!   * `tcp_reachable_s1` — TCP opened, but no transport capability is claimed.
//!   * `tested_failing` — an explicit, observed connection refusal.
//!   * `untested (rate-limited)` — missing or inconclusive evidence. Timeouts and
//!     generic errors are neutral and never reduce Rust scoring.
//!
//! These are per-observation tags, not claims of Iranian reachability or a full
//! Tor circuit. Iran-specific projections require separate Iran-vantage evidence.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;

/// Label for a successful pluggable-transport-level verification.
pub const TIER_4_PT_HANDSHAKE: &str = "tier_4_pt_handshake";
/// Label for a transport-specific stage-3 observation.
pub const TIER_3_TRANSPORT: &str = "tier_3_transport";
/// Label for a positive stage-2 protocol observation.
pub const TIER_2_PT_HANDSHAKE: &str = "tier_2_pt_handshake";
/// Label for a TCP-level observation.
pub const TIER_1_TCP: &str = "tier_1_tcp";
/// Label for an attempted but not yet positive stage-0 observation.
pub const TIER_0_ATTEMPT: &str = "tier_0_attempt";
/// Label for entries with no conclusive probe observation.
pub const TIER_UNTESTED: &str = "untested";

/// Directive v37 result tags; `tested_working` is restricted to S2+ evidence.
pub const RESULT_WORKING: &str = "tested_working";
/// S1 TCP connection evidence; reachable is a prefilter, not working status.
pub const RESULT_REACHABLE_S1: &str = "tcp_reachable_s1";
pub const RESULT_FAILING: &str = "tested_failing";
pub const RESULT_UNTESTED: &str = "untested (rate-limited)";


/// Return the typed verification object, accepting the relay's flat result
/// shape as a compatibility input. Published bridge records use the nested
/// `verification` object so the evidence stays distinct from Iran assessment.
#[must_use]
pub fn verification(entry: &Value) -> Option<&Value> {
    entry
        .get("verification")
        .filter(|value| value.is_object())
        .or_else(|| {
            (entry.get("status").and_then(Value::as_str).is_some()
                && entry.get("stage").and_then(Value::as_str).is_some())
            .then_some(entry)
        })
}

/// Numeric order of the typed verification stages.
#[must_use]
pub fn stage_rank(stage: &str) -> Option<u8> {
    match stage {
        "S0" => Some(0),
        "S1" => Some(1),
        "S2" => Some(2),
        "S3" => Some(3),
        "S4" => Some(4),
        _ => None,
    }
}

/// Current observations may be up to ten minutes old; timestamps more than
/// two minutes in the future are rejected (allowing modest clock skew).
pub const OBSERVATION_MAX_AGE_SECONDS: i64 = 10 * 60;
pub const OBSERVATION_FUTURE_SKEW_SECONDS: i64 = 2 * 60;
/// Iran assessment queries are hourly, but allow one missed schedule while
/// rejecting persisted labels from previous days.
pub const IRAN_ASSESSMENT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
/// The OONI client labels current working/blocked classifications from its
/// seven-day result query; do not substitute the later query time for a missing
/// measurement time.
pub const IRAN_RECENT_MEASUREMENT_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;
/// Recurrence classifications are explicitly historical and use the separate
/// ninety-day query window.
pub const IRAN_HISTORICAL_MEASUREMENT_MAX_AGE_SECONDS: i64 = 90 * 24 * 60 * 60;

fn timestamp_is_fresh_at(timestamp: &str, now: DateTime<Utc>, max_age_seconds: i64) -> bool {
    let Ok(observed_at) = DateTime::parse_from_rfc3339(timestamp) else {
        return false;
    };
    let age = now.signed_duration_since(observed_at.with_timezone(&Utc));
    age >= -Duration::seconds(OBSERVATION_FUTURE_SKEW_SECONDS)
        && age <= Duration::seconds(max_age_seconds)
}

/// True only when a typed observation has a parseable, recent timestamp. This
/// uses RFC3339 parsing, including fractional seconds from JavaScript
/// `Date.toISOString()`.
#[must_use]
pub fn observation_is_fresh_at(entry: &Value, now: DateTime<Utc>) -> bool {
    verification(entry)
        .and_then(|evidence| evidence.get("observed_at"))
        .and_then(Value::as_str)
        .is_some_and(|timestamp| {
            timestamp_is_fresh_at(timestamp, now, OBSERVATION_MAX_AGE_SECONDS)
        })
}

/// True only for positive S2+ protocol evidence from a recognized vantage
/// whose observation is current at `now`. S1 TCP, static fallback, malformed
/// timestamps, stale evidence, and observations too far in the future fail.
#[must_use]
pub fn has_verified_s2plus_at(entry: &Value, now: DateTime<Utc>) -> bool {
    let Some(evidence) = verification(entry) else {
        return false;
    };
    evidence.get("status").and_then(Value::as_str) == Some("connected")
        && evidence
            .get("stage")
            .and_then(Value::as_str)
            .and_then(stage_rank)
            .is_some_and(|stage| stage >= 2)
        && has_observing_vantage(evidence)
        && evidence
            .get("probe_type")
            .and_then(Value::as_str)
            .is_some_and(|probe_type| {
                !probe_type.trim().is_empty() && !matches!(probe_type, "none" | "tcp" | "tls")
            })
        && observation_is_fresh_at(entry, now)
}

/// Check against the current UTC wall clock. Use [`has_verified_s2plus_at`]
/// when a caller has an injected run clock.
#[must_use]
pub fn has_verified_s2plus(entry: &Value) -> bool {
    has_verified_s2plus_at(entry, Utc::now())
}

/// Whether the typed status is suitable for scoring at the supplied run time.
/// Stale/malformed evidence is neutral; explicit refusals are negative only
/// while current and observed from a recognized vantage.
#[must_use]
pub fn scoring_reachability_at(entry: &Value, now: DateTime<Utc>) -> Option<bool> {
    if !observation_is_fresh_at(entry, now) {
        return None;
    }
    scoring_reachability_unchecked(entry, now)
}

fn has_observing_vantage(evidence: &Value) -> bool {
    evidence
        .get("vantage")
        .and_then(Value::as_object)
        .and_then(|vantage| vantage.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            matches!(
                kind,
                "cloudflare_worker"
                    | "github_actions_runner"
                    | "iran_probe"
                    | "local_runner"
                    | "probe_relay"
            )
        })
}

/// Return an explicit reachability outcome suitable for scoring.
///
/// `None` means the observation is absent, inconclusive, timed out, or errored;
/// callers should use a neutral factor instead of treating it as failure.
#[must_use]
pub fn scoring_reachability(entry: &Value) -> Option<bool> {
    scoring_reachability_at(entry, Utc::now())
}

fn scoring_reachability_unchecked(entry: &Value, now: DateTime<Utc>) -> Option<bool> {
    let evidence = verification(entry)?;
    let stage = evidence
        .get("stage")
        .and_then(Value::as_str)
        .and_then(stage_rank)?;
    if !has_observing_vantage(evidence) {
        return None;
    }
    match evidence.get("status").and_then(Value::as_str) {
        Some("connected") if stage == 1 => Some(true),
        Some("connected") if stage >= 2 && has_verified_s2plus_at(entry, now) => Some(true),
        Some("refused") => Some(false),
        _ => None,
    }
}

/// True when an OONI query was completed with an explicit Iranian probe
/// vantage, including a checked query that produced no classifiable result,
/// and the query timestamp is current at `now`.
#[must_use]
pub fn has_iran_measurement_provenance_at(entry: &Value, now: DateTime<Utc>) -> bool {
    let Some(status) = entry.get("iran_status").and_then(Value::as_str) else {
        return false;
    };
    if !matches!(
        status,
        "iran_likely_working"
            | "iran_likely_blocked"
            | "iran_frequently_blocked"
            | "iran_unknown"
    ) {
        return false;
    }
    let Some(assessment) = entry.get("iran_assessment") else {
        return false;
    };
    assessment.get("status").and_then(Value::as_str) == Some(status)
        && assessment.get("source").and_then(Value::as_str) == Some("ooni_measurements_api")
        && assessment.get("checked").and_then(Value::as_bool) == Some(true)
        && assessment
            .get("vantage")
            .and_then(Value::as_object)
            .is_some_and(|vantage| {
                vantage.get("type").and_then(Value::as_str) == Some("ooni_probe")
                    && vantage.get("country").and_then(Value::as_str) == Some("IR")
            })
        && assessment
            .get("queried_at")
            .and_then(Value::as_str)
            .is_some_and(|queried_at| {
                timestamp_is_fresh_at(queried_at, now, IRAN_ASSESSMENT_MAX_AGE_SECONDS)
            })
}

/// Check Iran measurement provenance against the current UTC wall clock.
#[must_use]
pub fn has_iran_measurement_provenance(entry: &Value) -> bool {
    has_iran_measurement_provenance_at(entry, Utc::now())
}

/// True when an Iran reachability classification is backed by an explicit
/// Iranian vantage, a current query, and the original timestamp/window of the
/// OONI measurement that supports that classification. Query time alone never
/// turns an old or timestamp-less measurement into current evidence.
#[must_use]
pub fn has_iran_specific_assessment_at(entry: &Value, now: DateTime<Utc>) -> bool {
    if !has_iran_measurement_provenance_at(entry, now) {
        return false;
    }
    let status = entry.get("iran_status").and_then(Value::as_str);
    let Some(assessment) = entry.get("iran_assessment") else {
        return false;
    };
    let (timestamp_key, window_key, expected_days, max_age_seconds) = match status {
        Some("iran_likely_working" | "iran_likely_blocked") => (
            "measurement_at",
            "measurement_window_days",
            7,
            IRAN_RECENT_MEASUREMENT_MAX_AGE_SECONDS,
        ),
        Some("iran_frequently_blocked") => (
            "historical_measurement_at",
            "historical_window_days",
            90,
            IRAN_HISTORICAL_MEASUREMENT_MAX_AGE_SECONDS,
        ),
        _ => return false,
    };
    assessment.get(window_key).and_then(Value::as_i64) == Some(expected_days)
        && assessment
            .get(timestamp_key)
            .and_then(Value::as_str)
            .is_some_and(|timestamp| timestamp_is_fresh_at(timestamp, now, max_age_seconds))
}

/// Check the Iran-specific assessment against the current UTC wall clock.
#[must_use]
pub fn has_iran_specific_assessment(entry: &Value) -> bool {
    has_iran_specific_assessment_at(entry, Utc::now())
}

/// True only when the Iran-working label has a recent Iran-specific OONI
/// assessment, rather than a generic runner or relay observation.
#[must_use]
pub fn has_iran_specific_working_assessment_at(entry: &Value, now: DateTime<Utc>) -> bool {
    entry.get("iran_status").and_then(Value::as_str) == Some("iran_likely_working")
        && has_iran_specific_assessment_at(entry, now)
}

/// Check the Iran-working assessment against the current UTC wall clock.
#[must_use]
pub fn has_iran_specific_working_assessment(entry: &Value) -> bool {
    has_iran_specific_working_assessment_at(entry, Utc::now())
}

fn default_verification(entry: &Value, _fallback_timestamp: &str) -> Value {
    if let Some(existing) = verification(entry) {
        let mut object = existing.as_object().cloned().unwrap_or_default();
        // A stamping/run timestamp is not an observation timestamp. Preserve
        // the unknown explicitly instead of upgrading historical evidence.
        object
            .entry("observed_at".to_string())
            .or_insert(Value::Null);
        object.entry("source".to_string()).or_insert_with(|| {
            Value::String("iran_results".to_string())
        });
        return Value::Object(object);
    }

    // Legacy booleans, counters, and status strings do not preserve the
    // observer, stage, or observation time. Never manufacture those fields.
    serde_json::json!({
        "status": "inconclusive",
        "stage": "S0",
        "vantage": Value::Null,
        "rtt_ms": Value::Null,
        "probe_type": "none",
        "detail": "no typed verification observation was recorded",
        "error_class": "missing_typed_observation",
        "observed_at": Value::Null,
        "source": "iran_results",
    })
}

fn status_rank(status: &str) -> u8 {
    match status {
        "connected" => 5,
        "refused" => 4,
        "timeout" => 3,
        "error" => 2,
        "inconclusive" => 1,
        _ => 0,
    }
}

fn verification_order_at(value: &Value, now: DateTime<Utc>) -> (u8, u8, u8, u8) {
    let stage = value
        .get("stage")
        .and_then(Value::as_str)
        .and_then(stage_rank)
        .unwrap_or(0);
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map(status_rank)
        .unwrap_or(0);
    let has_vantage = has_observing_vantage(value) as u8;
    let fresh = observation_is_fresh_at(value, now) as u8;
    (fresh, stage, status, has_vantage)
}

/// Attach a typed observation while retaining the prior record and selecting
/// the highest current observed stage. Stale history remains attached for audit
/// but cannot override a newer observation.
pub fn merge_verification_observation(entry: &mut Value, incoming: Value) {
    merge_verification_observation_at(entry, incoming, Utc::now());
}

/// Deterministic-clock variant of [`merge_verification_observation`].
pub fn merge_verification_observation_at(
    entry: &mut Value,
    incoming: Value,
    now: DateTime<Utc>,
) {
    let current = verification(entry).cloned();
    let mut observations = current
        .as_ref()
        .and_then(|value| value.get("observations"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| current.into_iter().collect());
    observations.push(incoming);

    let Some(best) = observations
        .iter()
        .max_by_key(|observation| verification_order_at(observation, now))
        .cloned()
    else {
        return;
    };
    let mut selected = best.as_object().cloned().unwrap_or_default();
    selected.insert("observations".to_string(), Value::Array(observations));
    if let Some(object) = entry.as_object_mut() {
        object.insert("verification".to_string(), Value::Object(selected));
    }
}

fn normalize_line(line: &str) -> String {
    line.trim()
        .strip_prefix("Bridge ")
        .unwrap_or(line.trim())
        .trim()
        .to_ascii_lowercase()
}

fn relay_observation(result: &Value) -> Option<Value> {
    let status = result.get("status").and_then(Value::as_str)?;
    if !matches!(status, "connected" | "refused" | "timeout" | "inconclusive" | "error") {
        return None;
    }
    let stage = result.get("stage").and_then(Value::as_str)?;
    stage_rank(stage)?;
    let mut observation = serde_json::Map::new();
    for key in [
        "status",
        "stage",
        "vantage",
        "rtt_ms",
        "observed_at",
        "probe_type",
        "detail",
        "error_class",
        "http_status",
    ] {
        if let Some(value) = result.get(key) {
            observation.insert(key.to_string(), value.clone());
        }
    }
    observation.insert(
        "source".to_string(),
        Value::String("probe-relay".to_string()),
    );
    Some(Value::Object(observation))
}

/// Merge per-descriptor relay observations into each matching bridge record.
/// Fresh observations take precedence over historical ones; within the current
/// window the highest stage is selected. Every observation remains for audit.
#[must_use]
pub fn merge_relay_results(bridges: &mut [Value], relay_results: &[Value]) -> Value {
    merge_relay_results_at(bridges, relay_results, Utc::now())
}

/// Deterministic-clock variant of [`merge_relay_results`].
#[must_use]
pub fn merge_relay_results_at(
    bridges: &mut [Value],
    relay_results: &[Value],
    now: DateTime<Utc>,
) -> Value {
    let mut by_line: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for result in relay_results {
        let Some(line) = result.get("line").and_then(Value::as_str) else {
            continue;
        };
        let key = normalize_line(line);
        if key.is_empty() {
            continue;
        }
        if let Some(observation) = relay_observation(result) {
            by_line.entry(key).or_default().push(observation);
        }
    }

    let mut matched = 0_usize;
    let mut upgraded = 0_usize;
    let mut s2plus_connected = 0_usize;
    for bridge in bridges {
        let line = bridge
            .get("line")
            .or_else(|| bridge.get("bridge"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = normalize_line(line);
        let Some(relay) = by_line.get(&key) else {
            continue;
        };
        let old = default_verification(bridge, "");
        let old_order = verification_order_at(&old, now);
        matched += 1;
        let mut observations = vec![old.clone()];
        observations.extend(relay.iter().cloned());
        let Some(best) = observations
            .iter()
            .max_by_key(|observation| verification_order_at(observation, now))
            .cloned()
        else {
            continue;
        };
        if verification_order_at(&best, now) > old_order {
            upgraded += 1;
        }
        if has_verified_s2plus_at(&best, now) {
            s2plus_connected += 1;
        }
        let mut selected = best.as_object().cloned().unwrap_or_default();
        selected.insert("observations".to_string(), Value::Array(observations));
        if let Some(object) = bridge.as_object_mut() {
            object.insert("verification".to_string(), Value::Object(selected));
        }
    }
    serde_json::json!({
        "relay_observations": relay_results.len(),
        "bridges_matched": matched,
        "verification_upgrades": upgraded,
        "s2plus_connected": s2plus_connected,
    })
}

/// Derive the highest current tier of test evidenced by one `iran_results.json`
/// entry. Use [`derive_tier_at`] for an injected clock.
#[must_use]
pub fn derive_tier(entry: &Value) -> String {
    derive_tier_at(entry, Utc::now())
}

/// Deterministic-clock variant of [`derive_tier`]. Stale or missing timestamp
/// evidence is visible in `verification` but is not counted as a current tier.
#[must_use]
pub fn derive_tier_at(entry: &Value, now: DateTime<Utc>) -> String {
    let verification = default_verification(entry, "");
    if !observation_is_fresh_at(&verification, now) {
        return TIER_UNTESTED.to_string();
    }
    let status = verification
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("inconclusive");
    let rank = verification
        .get("stage")
        .and_then(Value::as_str)
        .and_then(stage_rank)
        .unwrap_or(0);
    if status == "connected" && rank >= 2 {
        if !has_verified_s2plus_at(entry, now) {
            return TIER_UNTESTED.to_string();
        }
        return match rank {
            4 => TIER_4_PT_HANDSHAKE.to_string(),
            3 => TIER_3_TRANSPORT.to_string(),
            _ => TIER_2_PT_HANDSHAKE.to_string(),
        };
    }
    let evidence = default_verification(entry, "");
    if rank >= 1
        && has_observing_vantage(&evidence)
        && matches!(status, "connected" | "refused" | "timeout" | "inconclusive" | "error")
    {
        return TIER_1_TCP.to_string();
    }
    if rank == 0
        && has_observing_vantage(&evidence)
        && matches!(status, "refused" | "timeout" | "inconclusive" | "error")
    {
        return TIER_0_ATTEMPT.to_string();
    }
    TIER_UNTESTED.to_string()
}

/// Derive the current test result without turning stale, inconclusive, or
/// error outcomes into failures or treating bare TCP reachability as PT proof.
#[must_use]
pub fn derive_result(entry: &Value) -> String {
    derive_result_at(entry, Utc::now())
}

/// Deterministic-clock variant of [`derive_result`].
#[must_use]
pub fn derive_result_at(entry: &Value, now: DateTime<Utc>) -> String {
    let verification = default_verification(entry, "");
    if !observation_is_fresh_at(&verification, now) {
        return RESULT_UNTESTED.to_string();
    }
    let stage = verification
        .get("stage")
        .and_then(Value::as_str)
        .and_then(stage_rank);
    let observed = has_observing_vantage(&verification);
    match verification.get("status").and_then(Value::as_str) {
        Some("connected")
            if stage.is_some_and(|rank| rank >= 2)
                && has_verified_s2plus_at(&verification, now)
                && observed =>
        {
            RESULT_WORKING.to_string()
        }
        Some("connected") if stage == Some(1) && observed => RESULT_REACHABLE_S1.to_string(),
        Some("refused") if stage.is_some() && observed => RESULT_FAILING.to_string(),
        _ => RESULT_UNTESTED.to_string(),
    }
}

/// Ensure one bridge carries an explicit `verification` object and stamp
/// `tested_at`, `test_tier`, and `test_result` from that same evidence.
/// Returns `true` if any field was added or changed.
pub fn stamp_entry(entry: &mut Value, run_timestamp: &str) -> bool {
    if !entry.is_object() {
        return false;
    }
    let mut changed = false;
    let verification = default_verification(entry, run_timestamp);
    if entry.get("verification") != Some(&verification) {
        entry["verification"] = verification;
        changed = true;
    }
    if entry.get("tested_at").is_none() && !run_timestamp.is_empty() {
        entry["tested_at"] = Value::String(run_timestamp.to_string());
        changed = true;
    }
    let now = DateTime::parse_from_rfc3339(run_timestamp)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let tier = derive_tier_at(entry, now);
    let result = derive_result_at(entry, now);
    let object = entry.as_object_mut().expect("checked object above");
    let tier_changed =
        !matches!(object.get("test_tier"), Some(Value::String(existing)) if existing == &tier);
    if tier_changed {
        object.insert("test_tier".to_string(), Value::String(tier));
        changed = true;
    }
    let result_changed = !matches!(
        object.get("test_result"),
        Some(Value::String(existing)) if existing == &result
    );
    if result_changed {
        object.insert("test_result".to_string(), Value::String(result));
        changed = true;
    }
    changed
}

/// Summary of one stamping pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StampSummary {
    /// Number of entries that were modified.
    pub stamped: usize,
    /// Tier label -> entry count.
    pub tiers: BTreeMap<String, usize>,
    /// Result tag -> entry count.
    pub results: BTreeMap<String, usize>,
}

/// Stamp every entry in a `{ "bridges": [...] }` document. The evaluation
/// clock is the document's `generated_at`, or the caller-supplied fallback.
pub fn stamp_results(doc: &mut Value, fallback_timestamp: &str) -> StampSummary {
    let run_timestamp = doc
        .get("generated_at")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_timestamp)
        .to_string();
    let now = DateTime::parse_from_rfc3339(&run_timestamp)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let mut summary = StampSummary {
        stamped: 0,
        tiers: BTreeMap::new(),
        results: BTreeMap::new(),
    };

    if let Some(bridges) = doc.get_mut("bridges").and_then(Value::as_array_mut) {
        for entry in bridges.iter_mut() {
            if stamp_entry(entry, &run_timestamp) {
                summary.stamped += 1;
            }
            let tier = derive_tier_at(entry, now);
            *summary.tiers.entry(tier).or_insert(0) += 1;
            let result = derive_result_at(entry, now);
            *summary.results.entry(result).or_insert(0) += 1;
        }
    }

    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "evidence_scope".to_string(),
            Value::String(
                "runner-side probe observations; tiers and results are per-observation \
                 and do not assert Iranian reachability or full circuits"
                    .to_string(),
            ),
        );
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn typed(status: &str, stage: &str, probe_type: &str, vantage: Option<&str>) -> Value {
        let vantage = vantage.map(|kind| json!({ "type": kind, "region": null }));
        let observed_at = Utc::now().to_rfc3339();
        json!({
            "status": status,
            "stage": stage,
            "vantage": vantage,
            "rtt_ms": 12.5,
            "probe_type": probe_type,
            "detail": "test observation",
            "error_class": null,
            "observed_at": observed_at,
        })
    }

    #[test]
    fn missing_and_legacy_boolean_evidence_stay_unverified() {
        for entry in [
            json!({ "host": "1.2.3.4", "port": 9001 }),
            json!({ "tcp_reachable": true, "transport_capable": true }),
            json!({ "iran_status": "iran_likely_working", "test_pass": true }),
        ] {
            assert_eq!(derive_tier(&entry), TIER_UNTESTED);
            assert_eq!(derive_result(&entry), RESULT_UNTESTED);
            assert!(!has_verified_s2plus(&entry));
        }
    }

    #[test]
    fn tcp_connected_is_only_s1_and_requires_a_vantage() {
        let entry = json!({ "verification": typed("connected", "S1", "tcp", Some("github_actions_runner")) });
        assert_eq!(derive_tier(&entry), TIER_1_TCP);
        assert_eq!(derive_result(&entry), RESULT_REACHABLE_S1);
        assert!(!has_verified_s2plus(&entry));

        let missing_vantage = json!({ "verification": typed("connected", "S1", "tcp", None) });
        assert_eq!(derive_tier(&missing_vantage), TIER_UNTESTED);
        assert_eq!(derive_result(&missing_vantage), RESULT_UNTESTED);
    }

    #[test]
    fn explicit_refusal_is_failing_but_timeout_is_neutral() {
        let refused = json!({ "verification": typed("refused", "S0", "tcp", Some("cloudflare_worker")) });
        assert_eq!(derive_tier(&refused), TIER_0_ATTEMPT);
        assert_eq!(derive_result(&refused), RESULT_FAILING);
        assert_eq!(scoring_reachability(&refused), Some(false));

        for status in ["timeout", "inconclusive", "error"] {
            let entry = json!({ "verification": typed(status, "S0", "tcp", Some("cloudflare_worker")) });
            assert_eq!(derive_tier(&entry), TIER_0_ATTEMPT);
            assert_eq!(derive_result(&entry), RESULT_UNTESTED);
            assert_eq!(scoring_reachability(&entry), None, "{status} must be neutral");
        }
    }

    #[test]
    fn lower_stage_observation_does_not_replace_higher_stage_evidence() {
        let mut entry = json!({
            "verification": typed("connected", "S3", "tor-handshake", Some("probe_relay"))
        });
        merge_verification_observation(
            &mut entry,
            typed("connected", "S1", "websocket-front-check", Some("github_actions_runner")),
        );
        assert_eq!(entry["verification"]["stage"], "S3");
        assert_eq!(entry["verification"]["observations"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn only_connected_s2_plus_with_protocol_and_vantage_is_transport_verified() {
        let good = json!({ "verification": typed("connected", "S2", "websocket-101", Some("cloudflare_worker")) });
        assert!(has_verified_s2plus(&good));
        assert_eq!(derive_tier(&good), TIER_2_PT_HANDSHAKE);
        assert_eq!(derive_result(&good), RESULT_WORKING);

        let s1 = json!({ "verification": typed("connected", "S1", "tcp", Some("cloudflare_worker")) });
        let no_vantage = json!({ "verification": typed("connected", "S2", "websocket-101", None) });
        let unknown_vantage = json!({ "verification": typed("connected", "S2", "websocket-101", Some("unrecognized")) });
        let refused = json!({ "verification": typed("refused", "S0", "websocket-101", Some("cloudflare_worker")) });
        let tcp_only = json!({ "verification": typed("connected", "S2", "tcp", Some("cloudflare_worker")) });
        for evidence in [&s1, &no_vantage, &unknown_vantage, &refused, &tcp_only] {
            assert!(!has_verified_s2plus(evidence), "unexpected evidence: {evidence}");
        }
        assert_eq!(derive_result(&s1), RESULT_REACHABLE_S1);
        assert_eq!(derive_result(&no_vantage), RESULT_UNTESTED);
        assert_eq!(derive_result(&unknown_vantage), RESULT_UNTESTED);
        assert_eq!(derive_result(&refused), RESULT_FAILING);
        assert_eq!(derive_result(&tcp_only), RESULT_UNTESTED);
    }

    #[test]
    fn checked_iran_unknown_is_measurement_provenance_not_reachability() {
        let queried_at = Utc::now().to_rfc3339();
        let unknown = json!({
            "iran_status": "iran_unknown",
            "iran_assessment": {
                "status": "iran_unknown",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": queried_at
            }
        });
        assert!(has_iran_measurement_provenance(&unknown));
        assert!(!has_iran_specific_assessment(&unknown));
        assert!(!has_iran_specific_working_assessment(&unknown));
    }

    #[test]
    fn iran_working_requires_an_explicit_iran_specific_assessment() {
        let queried_at = Utc::now().to_rfc3339();
        let measurement_at = (Utc::now() - Duration::seconds(30)).to_rfc3339();
        let valid = json!({
            "iran_status": "iran_likely_working",
            "iran_assessment": {
                "status": "iran_likely_working",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": queried_at.clone(),
                "measurement_at": measurement_at.clone(),
                "measurement_window_days": 7
            }
        });
        assert!(has_iran_specific_working_assessment(&valid));
        assert!(has_iran_specific_assessment(&valid));

        let blocked = json!({
            "iran_status": "iran_likely_blocked",
            "iran_assessment": {
                "status": "iran_likely_blocked",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": queried_at.clone(),
                "measurement_at": measurement_at.clone(),
                "measurement_window_days": 7
            }
        });
        assert!(has_iran_specific_assessment(&blocked));
        assert!(!has_iran_specific_working_assessment(&blocked));

        let frequently_blocked = json!({
            "iran_status": "iran_frequently_blocked",
            "iran_assessment": {
                "status": "iran_frequently_blocked",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": queried_at,
                "historical_measurement_at": measurement_at,
                "historical_window_days": 90
            }
        });
        assert!(has_iran_specific_assessment(&frequently_blocked));
        assert!(!has_iran_specific_working_assessment(&frequently_blocked));

        for invalid in [
            json!({"iran_status":"iran_likely_working"}),
            json!({
                "iran_status":"iran_likely_working",
                "iran_assessment": {
                    "status":"iran_likely_working", "source":"ooni_measurements_api", "checked":true,
                    "vantage":{"type":"cloudflare_worker", "country":"IR"}, "queried_at":"now"
                }
            }),
            json!({
                "iran_status":"iran_likely_working",
                "iran_assessment": {
                    "status":"iran_likely_working", "source":"ooni_measurements_api", "checked":true,
                    "vantage":{"type":"ooni_probe", "country":"DE"}, "queried_at":"now"
                }
            }),
            json!({
                "iran_status":"iran_unknown",
                "iran_assessment": {
                    "status":"iran_likely_working", "source":"ooni_measurements_api", "checked":true,
                    "vantage":{"type":"ooni_probe", "country":"IR"}, "queried_at":"now"
                }
            }),
        ] {
            assert!(!has_iran_specific_working_assessment(&invalid));
        }
    }

    #[test]
    fn iran_measurement_freshness_uses_injected_clock_and_status_window() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let queried_at = now.to_rfc3339();
        let recent_at = (now - Duration::days(7)).to_rfc3339();
        let recent = json!({
            "iran_status": "iran_likely_working",
            "iran_assessment": {
                "status": "iran_likely_working",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": queried_at,
                "measurement_at": recent_at,
                "measurement_window_days": 7
            }
        });
        assert!(has_iran_specific_assessment_at(&recent, now));

        let stale = json!({
            "iran_status": "iran_likely_working",
            "iran_assessment": {
                "status": "iran_likely_working",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": now.to_rfc3339(),
                "measurement_at": (now - Duration::days(7) - Duration::seconds(1)).to_rfc3339(),
                "measurement_window_days": 7
            }
        });
        assert!(!has_iran_specific_assessment_at(&stale, now));

        let wrong_window = json!({
            "iran_status": "iran_likely_working",
            "iran_assessment": {
                "status": "iran_likely_working",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": now.to_rfc3339(),
                "measurement_at": now.to_rfc3339(),
                "measurement_window_days": 90
            }
        });
        assert!(!has_iran_specific_assessment_at(&wrong_window, now));

        let historical = json!({
            "iran_status": "iran_frequently_blocked",
            "iran_assessment": {
                "status": "iran_frequently_blocked",
                "source": "ooni_measurements_api",
                "checked": true,
                "vantage": { "type": "ooni_probe", "country": "IR" },
                "queried_at": now.to_rfc3339(),
                "historical_measurement_at": (now - Duration::days(90)).to_rfc3339(),
                "historical_window_days": 90
            }
        });
        assert!(has_iran_specific_assessment_at(&historical, now));
    }

    #[test]
    fn scoring_uses_the_supplied_clock_for_s2plus_freshness() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = json!({
            "verification": {
                "status": "connected",
                "stage": "S2",
                "vantage": { "type": "probe_relay" },
                "probe_type": "obfs4-handshake",
                "observed_at": (now - Duration::seconds(30)).to_rfc3339()
            }
        });
        assert_eq!(scoring_reachability_at(&entry, now), Some(true));
        assert_eq!(
            scoring_reachability_at(&entry, now + Duration::days(1)),
            None,
            "evidence must expire according to the injected scoring clock"
        );
    }

    #[test]
    fn relay_observation_upgrades_a_bridge_without_losing_history() {
        let observed_at = Utc::now().to_rfc3339();
        let line = "webtunnel 192.0.2.5:443 fingerprint url=https://front.example/bridge";
        let mut bridges = vec![json!({
            "line": line,
            "verification": typed("connected", "S1", "tls", Some("github_actions_runner"))
        })];
        let relay = vec![json!({
            "line": line,
            "status": "connected",
            "stage": "S2",
            "vantage": { "type": "cloudflare_worker", "colo": "FRA" },
            "rtt_ms": 35.0,
            "probe_type": "websocket-101",
            "detail": "WebTunnel WebSocket upgrade signature verified",
            "error_class": null,
            "observed_at": observed_at
        })];
        let summary = merge_relay_results(&mut bridges, &relay);
        assert_eq!(summary["bridges_matched"], 1);
        assert_eq!(summary["s2plus_connected"], 1);
        assert!(has_verified_s2plus(&bridges[0]));
        assert_eq!(bridges[0]["verification"]["stage"], "S2");
        assert_eq!(bridges[0]["verification"]["observations"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn stamp_entry_records_the_same_typed_evidence() {
        let run_timestamp = Utc::now().to_rfc3339();
        let mut entry = json!({
            "verification": typed("connected", "S1", "tcp", Some("github_actions_runner"))
        });
        assert!(stamp_entry(&mut entry, &run_timestamp));
        assert_eq!(entry["tested_at"], json!(run_timestamp));
        assert_eq!(entry["test_tier"], json!(TIER_1_TCP));
        assert_eq!(entry["test_result"], json!(RESULT_REACHABLE_S1));
        assert_eq!(entry["verification"]["stage"], json!("S1"));
    }

    #[test]
    fn stamp_preserves_existing_tested_at_and_is_idempotent() {
        let run_timestamp = Utc::now().to_rfc3339();
        let mut entry = json!({
            "verification": typed("connected", "S1", "tcp", Some("github_actions_runner")),
            "tested_at": "2026-10-10T07:00:00Z"
        });
        assert!(stamp_entry(&mut entry, &run_timestamp));
        assert_eq!(entry["tested_at"], json!("2026-10-10T07:00:00Z"));
        assert!(!stamp_entry(&mut entry, &run_timestamp));
    }

    #[test]
    fn freshness_accepts_javascript_fractional_seconds_and_rejects_stale_or_future_data() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let observation = |observed_at: &str| {
            json!({
                "verification": {
                    "status":"connected", "stage":"S2",
                    "vantage":{"type":"probe_relay"},
                    "probe_type":"websocket-101",
                    "observed_at":observed_at
                }
            })
        };

        let fractional = observation("2026-10-10T09:59:59.999Z");
        assert!(observation_is_fresh_at(&fractional, now));
        assert!(has_verified_s2plus_at(&fractional, now));

        let age_limit = observation("2026-10-10T09:50:00Z");
        assert!(observation_is_fresh_at(&age_limit, now));
        let stale = observation("2026-10-10T09:49:59.999Z");
        assert!(!observation_is_fresh_at(&stale, now));
        assert!(!has_verified_s2plus_at(&stale, now));
        assert_eq!(derive_result_at(&stale, now), RESULT_UNTESTED);

        let allowed_clock_skew = observation("2026-10-10T10:02:00Z");
        assert!(observation_is_fresh_at(&allowed_clock_skew, now));
        let too_far_future = observation("2026-10-10T10:02:00.001Z");
        assert!(!observation_is_fresh_at(&too_far_future, now));
        let malformed = observation("not-an-iso-timestamp");
        assert!(!observation_is_fresh_at(&malformed, now));
        assert!(!observation_is_fresh_at(&json!({"status":"connected", "stage":"S2"}), now));
    }

    #[test]
    fn stamp_results_treats_inconclusive_and_static_records_as_neutral() {
        let run_timestamp = Utc::now().to_rfc3339();
        let mut doc = json!({
            "generated_at": run_timestamp.clone(),
            "bridges": [
                { "verification": typed("connected", "S1", "tcp", Some("github_actions_runner")) },
                { "verification": typed("refused", "S0", "tcp", Some("github_actions_runner")) },
                { "verification": typed("timeout", "S0", "tcp", Some("github_actions_runner")) },
                { "tcp_reachable": true, "iran_status": "iran_likely_working" },
                { "verification": typed("connected", "S2", "websocket-101", Some("cloudflare_worker")) }
            ]
        });
        let summary = stamp_results(&mut doc, "fallback");
        assert_eq!(summary.stamped, 5);
        assert_eq!(summary.tiers.get(TIER_1_TCP), Some(&1));
        assert_eq!(summary.tiers.get(TIER_0_ATTEMPT), Some(&2));
        assert_eq!(summary.tiers.get(TIER_2_PT_HANDSHAKE), Some(&1));
        assert_eq!(summary.tiers.get(TIER_UNTESTED), Some(&1));
        assert_eq!(summary.results.get(RESULT_WORKING), Some(&1));
        assert_eq!(summary.results.get(RESULT_REACHABLE_S1), Some(&1));
        assert_eq!(summary.results.get(RESULT_FAILING), Some(&1));
        assert_eq!(summary.results.get(RESULT_UNTESTED), Some(&2));
        assert_eq!(doc["bridges"][2]["test_result"], json!(RESULT_UNTESTED));
        assert_eq!(doc["bridges"][3]["test_tier"], json!(TIER_UNTESTED));
        assert!(doc["evidence_scope"].is_string());
    }

    #[test]
    fn stamp_results_handles_missing_bridges_and_non_object_entries() {
        let mut missing = json!({ "generated_at": "2026-10-10T10:20:55Z" });
        let summary = stamp_results(&mut missing, "fallback");
        assert_eq!(summary.stamped, 0);
        assert!(summary.tiers.is_empty());

        let mut non_object = json!({ "bridges": ["Bridge 1.2.3.4:443 ABC"] });
        let summary = stamp_results(&mut non_object, "fallback");
        assert_eq!(summary.stamped, 0);
    }
}
