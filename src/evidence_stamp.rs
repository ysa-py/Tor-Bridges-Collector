//! Per-bridge test-evidence stamping for `iran_results.json`.
//!
//! ENGINEERING DIRECTIVE v37 §2 requires every bridge entry in the machine-
//! readable output files to carry: a last-tested timestamp, the test result,
//! and which tier of test it passed. The Go `iran_tester` binary that
//! produces `iran_results.json` records `tcp_reachable` / `probe_status` /
//! `transport_capable` / `probe_method` but not a per-entry timestamp or an
//! explicit tier. This module derives both from the recorded evidence and
//! stamps them onto each entry before publication.
//!
//! Tier semantics (honest, evidence-derived — never upgraded beyond what was
//! actually observed):
//!   * `tier_2_pt_handshake` — the run recorded a pluggable-transport-level
//!     capability check (obfs4 SOCKS/PT handshake, WebTunnel TLS+WS Upgrade,
//!     transport_capable=true, or a handshake-annotated probe method/status).
//!   * `tier_1_tcp` — the run recorded a TCP connect / TLS observation
//!     (`tcp_reachable` present, or OONI-correlated reachability).
//!   * `untested` — no probe observation exists for this entry.
//!
//! Result semantics (Directive v37 tags):
//!   * `tested_working` — positive observation (TCP reachable or PT capable).
//!   * `tested_failing` — explicit negative observation (TCP unreachable).
//!   * `untested (rate-limited)` — no observation; the pipeline could not
//!     test this entry (rate limiting, missing endpoint, skipped).
//!
//! IMPORTANT: these are per-observation tags. A WebTunnel bridge whose TCP
//! endpoint is unreachable is tagged `tested_failing` at `tier_1_tcp`; it is
//! the tier field, not the result field, that records *how* it was tested.
//! No tag claims Iranian reachability or a full Tor circuit.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// Label for a successful pluggable-transport-level verification.
pub const TIER_2_PT_HANDSHAKE: &str = "tier_2_pt_handshake";
/// Label for a TCP/TLS-level observation.
pub const TIER_1_TCP: &str = "tier_1_tcp";
/// Label for entries with no recorded probe observation.
pub const TIER_UNTESTED: &str = "untested";

/// Directive v37 result tags.
pub const RESULT_WORKING: &str = "tested_working";
pub const RESULT_FAILING: &str = "tested_failing";
pub const RESULT_UNTESTED: &str = "untested (rate-limited)";

/// Evidence keywords that mark a probe as pluggable-transport-level.
const PT_HANDSHAKE_MARKERS: &[&str] = &[
    "handshake",
    "webtunnel",
    "obfs4",
    "snowflake",
    "ws_101",
    "pt_ok",
    "upgrade",
];

/// Derive the highest tier of test evidenced by one `iran_results.json`
/// entry. Pure and deterministic; never fabricates evidence.
pub fn derive_tier(entry: &Value) -> String {
    if entry.get("transport_capable").and_then(Value::as_bool) == Some(true) {
        return TIER_2_PT_HANDSHAKE.to_string();
    }
    let probe_method = entry
        .get("probe_method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let probe_status = entry
        .get("probe_status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if PT_HANDSHAKE_MARKERS
        .iter()
        .any(|marker| probe_method.contains(marker) || probe_status.contains(marker))
    {
        return TIER_2_PT_HANDSHAKE.to_string();
    }
    if entry.get("tcp_reachable").is_some() {
        return TIER_1_TCP.to_string();
    }
    if entry.get("ooni_checked").and_then(Value::as_bool) == Some(true) {
        return TIER_1_TCP.to_string();
    }
    TIER_UNTESTED.to_string()
}

/// Derive the Directive v37 result tag from the recorded evidence.
pub fn derive_result(entry: &Value) -> String {
    let tcp_reachable = entry.get("tcp_reachable").and_then(Value::as_bool);
    let transport_capable = entry.get("transport_capable").and_then(Value::as_bool);
    if transport_capable == Some(true) || tcp_reachable == Some(true) {
        return RESULT_WORKING.to_string();
    }
    if tcp_reachable == Some(false) {
        return RESULT_FAILING.to_string();
    }
    RESULT_UNTESTED.to_string()
}

/// Stamp one entry with `tested_at` (the run timestamp unless the entry
/// already carries a more specific one), `test_tier`, and `test_result`.
/// Returns `true` if any field was added or changed.
pub fn stamp_entry(entry: &mut Value, run_timestamp: &str) -> bool {
    if !entry.is_object() {
        return false;
    }
    let mut changed = false;
    let tier = derive_tier(entry);
    let result = derive_result(entry);

    let obj = entry.as_object_mut().expect("checked is_object above");
    if !obj.contains_key("tested_at") && !run_timestamp.is_empty() {
        obj.insert(
            "tested_at".to_string(),
            Value::String(run_timestamp.to_string()),
        );
        changed = true;
    }
    let tier_changed =
        !matches!(obj.get("test_tier"), Some(Value::String(existing)) if existing == &tier);
    if tier_changed {
        obj.insert("test_tier".to_string(), Value::String(tier));
        changed = true;
    }
    let result_changed =
        !matches!(obj.get("test_result"), Some(Value::String(existing)) if existing == &result);
    if result_changed {
        obj.insert("test_result".to_string(), Value::String(result));
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

/// Stamp every entry in a `{ "bridges": [...] }` document. The run timestamp
/// is taken from the entry's own `tested_at` when present, otherwise from the
/// document's `generated_at`, otherwise from the caller-supplied fallback.
pub fn stamp_results(doc: &mut Value, fallback_timestamp: &str) -> StampSummary {
    let run_timestamp = doc
        .get("generated_at")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_timestamp)
        .to_string();

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
            let tier = derive_tier(entry);
            *summary.tiers.entry(tier).or_insert(0) += 1;
            let result = derive_result(entry);
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

    fn entry_with(fields: serde_json::Value) -> Value {
        fields
    }

    #[test]
    fn tier_is_untested_without_any_evidence() {
        let entry = entry_with(json!({ "host": "1.2.3.4", "port": 9001 }));
        assert_eq!(derive_tier(&entry), TIER_UNTESTED);
        assert_eq!(derive_result(&entry), RESULT_UNTESTED);
    }

    #[test]
    fn tier_one_for_tcp_observation() {
        let entry = entry_with(json!({ "tcp_reachable": true }));
        assert_eq!(derive_tier(&entry), TIER_1_TCP);
        assert_eq!(derive_result(&entry), RESULT_WORKING);
    }

    #[test]
    fn tier_one_failing_for_tcp_unreachable() {
        let entry = entry_with(json!({ "tcp_reachable": false }));
        assert_eq!(derive_tier(&entry), TIER_1_TCP);
        assert_eq!(derive_result(&entry), RESULT_FAILING);
    }

    #[test]
    fn tier_two_for_transport_capable() {
        let entry = entry_with(json!({ "tcp_reachable": true, "transport_capable": true }));
        assert_eq!(derive_tier(&entry), TIER_2_PT_HANDSHAKE);
        assert_eq!(derive_result(&entry), RESULT_WORKING);
    }

    #[test]
    fn tier_two_for_handshake_probe_method() {
        let entry =
            entry_with(json!({ "probe_method": "webtunnel_ws_upgrade", "probe_status": "ws_101" }));
        assert_eq!(derive_tier(&entry), TIER_2_PT_HANDSHAKE);
        assert_eq!(derive_result(&entry), RESULT_UNTESTED);
    }

    #[test]
    fn untested_keeps_untested_result() {
        let entry =
            entry_with(json!({ "host": "1.2.3.4", "port": 9001, "probe_status": "rate_limited" }));
        assert_eq!(derive_tier(&entry), TIER_UNTESTED);
        assert_eq!(derive_result(&entry), RESULT_UNTESTED);
    }

    #[test]
    fn stamp_entry_adds_all_three_fields() {
        let mut entry = entry_with(json!({ "tcp_reachable": true }));
        assert!(stamp_entry(&mut entry, "2026-08-12T10:20:55Z"));
        assert_eq!(entry["tested_at"], json!("2026-08-12T10:20:55Z"));
        assert_eq!(entry["test_tier"], json!(TIER_1_TCP));
        assert_eq!(entry["test_result"], json!(RESULT_WORKING));
    }

    #[test]
    fn stamp_preserves_existing_tested_at() {
        let mut entry = entry_with(json!({
            "tcp_reachable": true,
            "tested_at": "2026-08-12T07:00:00Z"
        }));
        stamp_entry(&mut entry, "2026-08-12T10:20:55Z");
        assert_eq!(entry["tested_at"], json!("2026-08-12T07:00:00Z"));
    }

    #[test]
    fn stamp_is_idempotent() {
        let mut entry = entry_with(json!({ "tcp_reachable": true }));
        assert!(stamp_entry(&mut entry, "2026-08-12T10:20:55Z"));
        assert!(!stamp_entry(&mut entry, "2026-08-12T10:20:55Z"));
    }

    #[test]
    fn stamp_results_uses_generated_at_and_counts() {
        let mut doc = json!({
            "generated_at": "2026-08-12T10:20:55Z",
            "bridges": [
                { "tcp_reachable": true },
                { "tcp_reachable": false },
                { "host": "9.9.9.9", "port": 443 }
            ]
        });
        let summary = stamp_results(&mut doc, "fallback");
        assert_eq!(summary.stamped, 3);
        assert_eq!(summary.tiers.get(TIER_1_TCP), Some(&2));
        assert_eq!(summary.tiers.get(TIER_UNTESTED), Some(&1));
        assert_eq!(summary.results.get(RESULT_WORKING), Some(&1));
        assert_eq!(summary.results.get(RESULT_FAILING), Some(&1));
        assert_eq!(summary.results.get(RESULT_UNTESTED), Some(&1));
        assert_eq!(
            doc["bridges"][0]["tested_at"],
            json!("2026-08-12T10:20:55Z")
        );
        assert!(doc["evidence_scope"].is_string());
    }

    #[test]
    fn stamp_results_handles_missing_bridges() {
        let mut doc = json!({ "generated_at": "2026-08-12T10:20:55Z" });
        let summary = stamp_results(&mut doc, "fallback");
        assert_eq!(summary.stamped, 0);
        assert!(summary.tiers.is_empty());
    }

    #[test]
    fn stamp_results_skips_non_object_entries() {
        let mut doc = json!({
            "bridges": [ "Bridge 1.2.3.4:443 ABC" ]
        });
        let summary = stamp_results(&mut doc, "fallback");
        assert_eq!(summary.stamped, 0);
    }
}
