//! Channel-variant MOAT single-transport draws (strictly additive).
//!
//! The original extended-supply stage ([`crate::supply_extension`]) draws
//! single-transport MOAT payloads that always carry `"country": "ir"`.  Live
//! runs proved those draws repeat the same small Iran-allocated bridge set
//! the core scraper already captures, so they add zero *new* candidates even
//! though the stage itself is healthy (see `docs/SUPPLY_EXPANSION.md`).
//!
//! This module adds two **architecturally distinct request contexts** against
//! the same official MOAT endpoints.  Both are grounded in BridgeDB's own
//! request parser (`bridgedb/distributors/moat/request.py`, Tor Project):
//!
//! * **Geolocated draws** — the same single-transport payloads *without* an
//!   explicit `country` field.  BridgeDB's moat distributor then geolocates
//!   the client IP and serves from that country's bucket instead of the
//!   Iran bucket, i.e. exactly what a non-Iranian Tor Browser user would
//!   receive.  This samples a different, larger portion of BridgeDB's ring.
//! * **`unblocked` draws** — single-transport payloads carrying the
//!   documented `unblocked: ["ir"]` country-list field (BridgeDB's
//!   `withoutBlockInCountry()`), i.e. bridges that are *not blocked in
//!   Iran* regardless of which country bucket they are allocated to.  That
//!   is the semantically precise request for this pipeline's purpose and
//!   widens the eligible set beyond the Iran bucket.
//!
//! # Guarantees (identical to the v1 module)
//!
//! * Nothing here removes, disables, or weakens an existing source, filter,
//!   validation rule, or safety check; the v1 sources are untouched.
//! * Every response is parsed by the same
//!   [`crate::scraper::parse_moat_response`] used by the core scraper and by
//!   v1, which applies [`crate::scraper::is_valid_line`] plus the
//!   reserved-endpoint / documentation-IP rejection gate.
//! * Merging still happens only through
//!   [`crate::scraper::merge_raw_into_history`] in the `supply_extender`
//!   binary — this module only returns validated `(line, transport,
//!   ip_version)` tuples grouped per source label.
//! * Request volume is bounded by `MOAT_VARIANT_ROUNDS` (default `1`, clamp
//!   `0..=2`), paced with the same jittered 0.6–1.8 s pause as v1, and every
//!   non-2xx / unparsable response degrades to a counted zero-line result —
//!   never a pipeline failure.
//!
//! The source labels are deliberately distinct from v1's
//! (`moat_builtin_single_transport`, `moat_settings_single_transport`) so
//! the per-source diagnostics table shows exactly which request context
//! contributed what.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::scraper::{
    moat_headers, parse_moat_response, HttpFetch, MOAT_BUILTIN_URL, MOAT_SETTINGS_URL,
};
use crate::supply_extension::{pace_request, SourceLines, SupplyConfig};

/// Request timeout used by every variant fetch (mirrors the core scrapers).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Transports requested by the channel-variant payloads, one per request.
///
/// Same set as the v1 single-transport draws (obfs4, webTunnel, snowflake):
/// these are the transports BridgeDB's MOAT service distributes.  conjure
/// and meek-azure are operator/community transports that BridgeDB does not
/// distribute via MOAT (see `docs/SUPPLY_EXPANSION.md` section 2).
pub const MOAT_VARIANT_TRANSPORTS: &[&str] = &["snowflake", "webTunnel", "obfs4"];

/// MOAT single-transport payloads with **no** explicit `country` field.
///
/// BridgeDB geolocates the requesting IP and serves that country bucket —
/// i.e. the ordinary experience of a non-Iranian client.  On CI runners
/// (US/Azure) this samples the US bucket instead of the tiny Iran bucket
/// that the v1 `country: "ir"` draws repeatedly return.
#[must_use]
pub fn moat_geolocated_payloads() -> Vec<Value> {
    MOAT_VARIANT_TRANSPORTS
        .iter()
        .map(|transport| {
            json!({
                "version": "0.1.0",
                "transports": [transport],
            })
        })
        .collect()
}

/// MOAT single-transport payloads requesting bridges **not blocked in
/// Iran**, using BridgeDB's documented `unblocked` country-list field.
///
/// BridgeDB's moat request parser (`withoutBlockInCountry()` in
/// `bridgedb/distributors/moat/request.py`) reads `unblocked` as the list
/// of countries the returned bridges must not be blocked in.  For this
/// pipeline's purpose (bridges usable from Iran) `["ir"]` is the precise
/// request, and it widens the eligible set to every bridge outside the Iran
/// allocation bucket.
#[must_use]
pub fn moat_unblocked_ir_payloads() -> Vec<Value> {
    MOAT_VARIANT_TRANSPORTS
        .iter()
        .map(|transport| {
            json!({
                "version": "0.1.0",
                "transports": [transport],
                "unblocked": ["ir"],
            })
        })
        .collect()
}

/// Fetch the channel-variant MOAT supply.
///
/// POSTs each geolocated and each `unblocked: ["ir"]` single-transport
/// payload to both MOAT endpoints (builtin + settings), `rounds` times
/// (clamped to [`SupplyConfig::MAX_MOAT_VARIANT_ROUNDS`]).  Responses are
/// parsed with [`parse_moat_response`] — the identical schema-negotiation
/// and validation chain as the core MOAT fetch and the v1 extended fetch.
/// Per-request failures are counted, logged, and skipped.
pub fn fetch_moat_variant_supply(client: &dyn HttpFetch, rounds: usize) -> Vec<SourceLines> {
    const SOURCE_GEO_BUILTIN: &str = "moat_builtin_geolocated_single_transport";
    const SOURCE_GEO_SETTINGS: &str = "moat_settings_geolocated_single_transport";
    const SOURCE_UNB_BUILTIN: &str = "moat_builtin_unblocked_ir_single_transport";
    const SOURCE_UNB_SETTINGS: &str = "moat_settings_unblocked_ir_single_transport";

    // Flat variant list: one entry per payload, each carrying the labels of
    // the two endpoint groups it will be POSTed to (builtin + settings).
    // Keeping the request loop at the same nesting depth as the v1 fetcher
    // keeps this module's per-request handling byte-identical in shape.
    let mut variants: Vec<(&'static str, &'static str, Value)> = Vec::new();
    for payload in moat_geolocated_payloads() {
        variants.push((SOURCE_GEO_BUILTIN, SOURCE_GEO_SETTINGS, payload));
    }
    for payload in moat_unblocked_ir_payloads() {
        variants.push((SOURCE_UNB_BUILTIN, SOURCE_UNB_SETTINGS, payload));
    }

    let headers = moat_headers();
    let mut per_source: BTreeMap<&'static str, SourceLines> = BTreeMap::new();
    let mut first_request = true;
    let rounds = rounds.min(SupplyConfig::MAX_MOAT_VARIANT_ROUNDS);

    for _ in 0..rounds {
        for (builtin_label, settings_label, payload) in &variants {
            for (source, url) in [
                (*builtin_label, MOAT_BUILTIN_URL),
                (*settings_label, MOAT_SETTINGS_URL),
            ] {
                if !first_request {
                    pace_request();
                }
                first_request = false;
                let entry = per_source.entry(source).or_insert_with(|| SourceLines {
                    source,
                    requests: 0,
                    responses_ok: 0,
                    lines: Vec::new(),
                });
                entry.requests += 1;
                match client.post_json(url, payload, &headers, REQUEST_TIMEOUT) {
                    Ok(resp) if resp.status == 200 => {
                        entry.responses_ok += 1;
                        match resp.json() {
                            Ok(data) => match parse_moat_response(&data) {
                                Ok(pairs) => {
                                    tracing::info!(
                                        source,
                                        url,
                                        parsed_lines = pairs.len(),
                                        "channel-variant MOAT draw"
                                    );
                                    for (line, transport) in pairs {
                                        let ip_version =
                                            if line.contains('[') { "ipv6" } else { "ipv4" };
                                        entry.lines.push((line, transport, ip_version.to_string()));
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        source,
                                        url,
                                        error = %err,
                                        "channel-variant MOAT parse error"
                                    );
                                }
                            },
                            Err(err) => {
                                tracing::warn!(
                                    source,
                                    url,
                                    error = %err,
                                    "channel-variant MOAT invalid JSON"
                                );
                            }
                        }
                    }
                    Ok(resp) => {
                        tracing::warn!(
                            source,
                            url,
                            status = resp.status,
                            "channel-variant MOAT draw returned non-200"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            source,
                            url,
                            error = %err,
                            "channel-variant MOAT draw failed"
                        );
                    }
                }
            }
        }
    }
    per_source.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geolocated_payloads_omit_country_and_unblocked() {
        let payloads = moat_geolocated_payloads();
        assert_eq!(payloads.len(), MOAT_VARIANT_TRANSPORTS.len());
        for payload in &payloads {
            assert!(payload.get("country").is_none());
            assert!(payload.get("unblocked").is_none());
            let transports = payload.get("transports").and_then(Value::as_array);
            assert_eq!(transports.map(Vec::len), Some(1));
            assert_eq!(payload.get("version").and_then(Value::as_str), Some("0.1.0"));
        }
    }

    #[test]
    fn unblocked_ir_payloads_use_documented_unblocked_field() {
        let payloads = moat_unblocked_ir_payloads();
        assert_eq!(payloads.len(), MOAT_VARIANT_TRANSPORTS.len());
        for payload in &payloads {
            assert!(payload.get("country").is_none());
            let unblocked = payload.get("unblocked").and_then(Value::as_array);
            assert_eq!(unblocked.map(Vec::len), Some(1));
            assert_eq!(
                unblocked
                    .and_then(|items| items.first())
                    .and_then(Value::as_str),
                Some("ir")
            );
            let transports = payload.get("transports").and_then(Value::as_array);
            assert_eq!(transports.map(Vec::len), Some(1));
        }
    }
}
