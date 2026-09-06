//! Extended, strictly-additive bridge-supply pulls for low-count transports.
//!
//! The production pipeline's core scraper ([`crate::scraper`]) already pulls
//! one fixed set of BridgeDB HTML pages ([`crate::scraper::TORPROJECT_TARGETS`])
//! and two MOAT payload shapes ([`crate::scraper::fetch_moat`]) per run.  For
//! transports whose usable pools are small (webtunnel, snowflake, conjure,
//! meek-azure, meek_lite, vanilla IPv6), every extra legitimate *draw* from
//! the same official distributor can surface additional distinct bridge lines
//! that the fixed request set happened not to return this run.  BridgeDB
//! rotates its per-request answer, so repeated bounded draws accumulate into
//! `bridge_history.json` over time without touching any existing scraper,
//! filter, prober, or publication logic.
//!
//! # Guarantees (additive-only)
//!
//! * Nothing in this module removes, disables, or weakens an existing source,
//!   filter, validation rule, or safety check.
//! * Every fetched line is routed through the exact same public parsers the
//!   core scrapers use — [`crate::scraper::parse_bridgelines_html`] and
//!   [`crate::scraper::parse_moat_response`] — which apply
//!   [`crate::scraper::is_valid_line`] plus the reserved-endpoint /
//!   documentation-IP rejection gate before a line is returned.
//! * Merging reuses [`crate::scraper::merge_raw_into_history`] (keyed by
//!   [`crate::scraper::normalize_for_history`]), so new lines are deduplicated
//!   against existing history exactly like every other source.
//! * Requests are self-limited and paced: an absolute per-run ceiling per
//!   endpoint family (env-overridable, clamped), with a jittered pause between
//!   requests.  The defaults add roughly a handful of requests per pipeline
//!   run, which stays far below the official distributor's abuse thresholds.
//!
//! # Diagnostics
//!
//! Every run writes per-source/per-transport pull counts to
//! `data/supply_diagnostics.json` plus an append-only history in
//! `data/supply_diagnostics_history.json` (both NEW files; no existing output
//! file is ever overwritten or repurposed).  See `docs/SUPPLY_EXPANSION.md`
//! for the per-transport supply analysis and the measurement methodology.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::scraper::{
    HttpFetch, MOAT_BUILTIN_URL, moat_headers, MOAT_SETTINGS_URL, normalize_for_history,
    parse_bridgelines_html, parse_moat_response, TORPROJECT_TARGETS,
};

/// Request timeout used by every extended fetch (mirrors the core scrapers).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Lower bound (ms) of the jittered pacing pause between requests.
const PACE_MIN_MS: u64 = 600;

/// Extra jitter spread (ms) added on top of [`PACE_MIN_MS`].
const PACE_JITTER_MS: u64 = 1_200;

/// Focus transports reported through GitHub workflow `::notice` annotations.
///
/// These are the file families the user-facing inventory tracks; the JSON
/// diagnostics themselves cover every transport found in history.
pub const NOTICE_FOCUS_FAMILIES: &[&str] = &[
    "webtunnel",
    "webtunnel_ipv6",
    "snowflake",
    "snowflake_ipv6",
    "conjure",
    "meek-azure",
    "meek_lite",
    "meek_lite_ipv6",
    "vanilla",
    "vanilla_ipv6",
];

/// One grouped result from an extended supply fetch: everything that a single
/// named source contributed during this run, plus request counters so the
/// diagnostics can distinguish "source unavailable" from "source returned
/// nothing new".
#[derive(Debug, Clone)]
pub struct SourceLines {
    /// Stable source label, e.g. `bridgedb_html_rotation`.
    pub source: &'static str,
    /// HTTP requests issued to this source in this run.
    pub requests: usize,
    /// HTTP 2xx / MOAT 200 responses received from this source.
    pub responses_ok: usize,
    /// Validated `(bridge_line, transport, ip_version)` tuples.  Every line
    /// passed the same validation the core scrapers apply.
    pub lines: Vec<(String, String, String)>,
}

/// Bounded per-run tuning for the extended draws.
///
/// * `html_draws` — extra BridgeDB HTML requests of the core target set
///   (default `1`, clamped to `0..=MAX_HTML_DRAWS`).
/// * `moat_rounds` — extra MOAT rounds of single-transport settings/builtin
///   requests (default `1`, clamped to `0..=MAX_MOAT_ROUNDS`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SupplyConfig {
    pub html_draws: usize,
    pub moat_rounds: usize,
}

impl SupplyConfig {
    pub const DEFAULT_HTML_DRAWS: usize = 1;
    pub const MAX_HTML_DRAWS: usize = 6;
    pub const DEFAULT_MOAT_ROUNDS: usize = 1;
    pub const MAX_MOAT_ROUNDS: usize = 3;

    /// Read the per-run configuration from the environment.
    ///
    /// * `SUPPLY_EXTRA_DRAWS` — extra BridgeDB HTML rotation draws.
    /// * `MOAT_EXTRA_ROUNDS` — extra MOAT single-transport rounds.
    ///
    /// Unset, non-numeric, or out-of-range values fall back to the default
    /// (never below `0`, never above the per-run ceiling).
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            html_draws: parse_bounded(
                std::env::var("SUPPLY_EXTRA_DRAWS").ok().as_deref(),
                Self::DEFAULT_HTML_DRAWS,
                Self::MAX_HTML_DRAWS,
            ),
            moat_rounds: parse_bounded(
                std::env::var("MOAT_EXTRA_ROUNDS").ok().as_deref(),
                Self::DEFAULT_MOAT_ROUNDS,
                Self::MAX_MOAT_ROUNDS,
            ),
        }
    }
}

/// Parse a bounded non-negative integer configuration value.
fn parse_bounded(raw: Option<&str>, default: usize, max: usize) -> usize {
    match raw {
        Some(value) => value.trim().parse::<usize>().unwrap_or(default).min(max),
        None => default,
    }
}

/// Human/script-friendly family key for a transport/IP pair:
/// `webtunnel` → `webtunnel`, `webtunnel`+ipv6 → `webtunnel_ipv6`.
///
/// The key mirrors the file-stem convention of the published projections so
/// diagnostics rows line up with `bridge/*.txt` filenames.
#[must_use]
pub fn transport_family_key(transport: &str, ip_version: &str) -> String {
    if ip_version == "ipv6" {
        format!("{transport}_ipv6")
    } else {
        transport.to_string()
    }
}

/// One BridgeDB HTML target row: `(url, hint, transport, ip_version)`.
pub type BridgedbTarget = (&'static str, &'static str, &'static str, &'static str);

/// BridgeDB HTML pages for transports that the core fixed target list
/// ([`TORPROJECT_TARGETS`]) does not request directly.
///
/// Snowflake is the only remaining BridgeDB-web-served transport absent from
/// the core six targets.  Conjure and meek-azure are not distributed by
/// BridgeDB's web endpoint at all (they are fixed operator/community fronted
/// lines), so no request is made for them here — see
/// `docs/SUPPLY_EXPANSION.md` for that analysis.
pub const EXTRA_BRIDGEDB_TARGETS: &[BridgedbTarget] = &[
    (
        "https://bridges.torproject.org/bridges?transport=snowflake",
        "snowflake",
        "snowflake",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=snowflake&ipv6=yes",
        "snowflake_ipv6",
        "snowflake",
        "ipv6",
    ),
];

/// Assemble the full request plan for one run: the extra slugs first, then
/// `draws` rotation draws over the core target set.  `draws` is clamped to
/// [`SupplyConfig::MAX_HTML_DRAWS`].
#[must_use]
pub fn html_supply_plan(draws: usize) -> Vec<BridgedbTarget> {
    let mut plan: Vec<BridgedbTarget> = Vec::new();
    plan.extend_from_slice(EXTRA_BRIDGEDB_TARGETS);
    for _ in 0..draws.min(SupplyConfig::MAX_HTML_DRAWS) {
        plan.extend_from_slice(TORPROJECT_TARGETS);
    }
    plan
}

/// MOAT single-transport request payloads used for the extra draws.
///
/// The core [`crate::scraper::fetch_moat`] asks for `obfs4`, `webTunnel` and
/// `snowflake` in one combined request.  Asking for each transport in its own
/// request gives BridgeDB additional independent draws, which can surface
/// distinct lines the combined draw skipped.  Every payload keeps the exact
/// same schema and `country: "ir"` semantics as the core request.
#[must_use]
pub fn moat_supply_payloads() -> Vec<Value> {
    ["snowflake", "webTunnel", "obfs4"]
        .into_iter()
        .map(|transport| {
            json!({
                "version": "0.1.0",
                "transports": [transport],
                "country": "ir",
            })
        })
        .collect()
}

/// Sleep briefly between requests (jittered pacing for rate-limit awareness).
fn pace_request() {
    use rand::Rng;
    let jitter = rand::thread_rng().gen_range(0..=PACE_JITTER_MS);
    thread::sleep(Duration::from_millis(PACE_MIN_MS + jitter));
}

/// Fetch the extended BridgeDB HTML supply.
///
/// Requests the extra snowflake slugs plus `draws` rotation draws over the
/// core target list.  Every response is parsed with
/// [`parse_bridgelines_html`], which applies the identical validation chain
/// (format, reserved endpoints, documentation IPs) as the core scraper.
/// Per-URL failures are logged and skipped — never fatal.
pub fn fetch_html_supply(client: &dyn HttpFetch, draws: usize) -> Vec<SourceLines> {
    const SOURCE_EXTRA: &str = "bridgedb_html_snowflake";
    const SOURCE_ROTATION: &str = "bridgedb_html_rotation";

    let plan = html_supply_plan(draws);
    let mut per_source: BTreeMap<&'static str, SourceLines> = BTreeMap::new();
    let extra_count = EXTRA_BRIDGEDB_TARGETS.len();

    for (index, &(url, _hint, transport, ip_version)) in plan.iter().enumerate() {
        if index > 0 {
            pace_request();
        }
        // The plan always leads with the extra slugs, followed by the
        // rotation draws, so the group label follows directly from the row
        // position (see `html_supply_plan`).
        let source = if index < extra_count {
            SOURCE_EXTRA
        } else {
            SOURCE_ROTATION
        };
        let entry = per_source.entry(source).or_insert_with(|| SourceLines {
            source,
            requests: 0,
            responses_ok: 0,
            lines: Vec::new(),
        });
        entry.requests += 1;
        match client.get(url, REQUEST_TIMEOUT) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                entry.responses_ok += 1;
                let parsed = parse_bridgelines_html(&resp.text);
                tracing::info!(
                    source,
                    url,
                    parsed_lines = parsed.len(),
                    "extended BridgeDB HTML draw"
                );
                for line in parsed {
                    entry.lines.push((line, transport.to_string(), ip_version.to_string()));
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    source,
                    url,
                    status = resp.status,
                    "extended BridgeDB HTML draw returned non-2xx"
                );
            }
            Err(err) => {
                tracing::warn!(source, url, error = %err, "extended BridgeDB HTML draw failed");
            }
        }
    }
    per_source.into_values().collect()
}

/// Fetch the extended MOAT supply.
///
/// POSTs each single-transport payload from [`moat_supply_payloads`] to both
/// MOAT endpoints, `rounds` times (clamped).  Responses are parsed with
/// [`parse_moat_response`] (identical schema-negotiation and validation as
/// the core MOAT fetch).  Per-request failures are logged and skipped.
pub fn fetch_moat_supply(client: &dyn HttpFetch, rounds: usize) -> Vec<SourceLines> {
    const SOURCE_BUILTIN: &str = "moat_builtin_single_transport";
    const SOURCE_SETTINGS: &str = "moat_settings_single_transport";

    let headers = moat_headers();
    let payloads = moat_supply_payloads();
    let mut per_source: BTreeMap<&'static str, SourceLines> = BTreeMap::new();
    let mut first_request = true;

    for _ in 0..rounds.min(SupplyConfig::MAX_MOAT_ROUNDS) {
        for payload in &payloads {
            for (source, url) in [
                (SOURCE_BUILTIN, MOAT_BUILTIN_URL),
                (SOURCE_SETTINGS, MOAT_SETTINGS_URL),
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
                                        "extended MOAT draw"
                                    );
                                    for (line, transport) in pairs {
                                        let ip_version = if line.contains('[') {
                                            "ipv6"
                                        } else {
                                            "ipv4"
                                        };
                                        entry.lines.push((line, transport, ip_version.to_string()));
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        source,
                                        url,
                                        error = %err,
                                        "extended MOAT parse error"
                                    );
                                }
                            },
                            Err(err) => {
                                tracing::warn!(
                                    source,
                                    url,
                                    error = %err,
                                    "extended MOAT invalid JSON"
                                );
                            }
                        }
                    }
                    Ok(resp) => {
                        tracing::warn!(
                            source,
                            url,
                            status = resp.status,
                            "extended MOAT draw returned non-200"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(source, url, error = %err, "extended MOAT draw failed");
                    }
                }
            }
        }
    }
    per_source.into_values().collect()
}

/// Count history records grouped by transport family key (see
/// [`transport_family_key`]).  Non-object entries are ignored so legacy
/// string-form history records never crash the report.
#[must_use]
pub fn history_family_counts(history: &Value) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let Some(object) = history.as_object() else {
        return counts;
    };
    for entry in object.values() {
        let Some(record) = entry.as_object() else {
            continue;
        };
        let transport = record.get("transport").and_then(Value::as_str).unwrap_or("unknown");
        let ip_version = record.get("ip_version").and_then(Value::as_str).unwrap_or("ipv4");
        *counts.entry(transport_family_key(transport, ip_version)).or_insert(0) += 1;
    }
    counts
}

/// Count how many of `lines` would be NEW history records (by the exact
/// canonical key used by [`crate::scraper::merge_raw_into_history`]), grouped
/// by transport family.  Duplicate lines within the batch are counted once,
/// exactly as the history merge would deduplicate them.
#[must_use]
pub fn count_added_lines(
    history: &Value,
    lines: &[(String, String, String)],
) -> BTreeMap<String, usize> {
    let mut added: BTreeMap<String, usize> = BTreeMap::new();
    let Some(object) = history.as_object() else {
        return added;
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (line, transport, ip_version) in lines {
        let key = normalize_for_history(line, transport);
        if !seen.insert(key.clone()) {
            continue;
        }
        if !object.contains_key(&key) {
            *added.entry(transport_family_key(transport, ip_version)).or_insert(0) += 1;
        }
    }
    added
}

/// Render a counts map as a JSON object value.
#[must_use]
pub fn family_counts_to_json(counts: &BTreeMap<String, usize>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, count) in counts {
        map.insert(key.clone(), json!(count));
    }
    Value::Object(map)
}

/// Build the per-run diagnostics document written to
/// `data/supply_diagnostics.json`.
#[must_use]
pub fn diagnostics_payload(
    config: &SupplyConfig,
    sources: &[SourceLines],
    before: &BTreeMap<String, usize>,
    after: &BTreeMap<String, usize>,
    added: &BTreeMap<String, usize>,
    generated_at: String,
) -> Value {
    let source_entries: Vec<Value> = sources
        .iter()
        .map(|group| {
            json!({
                "source": group.source,
                "requests": group.requests,
                "responses_ok": group.responses_ok,
                "fetched_lines": group.lines.len(),
            })
        })
        .collect();
    json!({
        "generated_at": generated_at,
        "config": {
            "html_extra_draws": config.html_draws,
            "moat_single_transport_rounds": config.moat_rounds,
        },
        "sources": source_entries,
        "history_family_counts": {
            "before": family_counts_to_json(before),
            "after": family_counts_to_json(after),
            "added_by_extended_sources": family_counts_to_json(added),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bounded_clamps_and_defaults() {
        assert_eq!(parse_bounded(None, 2, 6), 2);
        assert_eq!(parse_bounded(Some(""), 2, 6), 2);
        assert_eq!(parse_bounded(Some("0"), 2, 6), 0);
        assert_eq!(parse_bounded(Some("4"), 2, 6), 4);
        assert_eq!(parse_bounded(Some("99"), 2, 6), 6);
        assert_eq!(parse_bounded(Some("abc"), 2, 6), 2);
    }

    #[test]
    fn html_supply_plan_contains_extra_slugs_and_bounded_draws() {
        let plan = html_supply_plan(2);
        assert_eq!(plan.len(), EXTRA_BRIDGEDB_TARGETS.len() + 2 * TORPROJECT_TARGETS.len());
        assert!(plan.iter().any(|row| row.2 == "snowflake"));
        let plan_zero = html_supply_plan(0);
        assert_eq!(plan_zero.len(), EXTRA_BRIDGEDB_TARGETS.len());
        let plan_huge = html_supply_plan(SupplyConfig::MAX_HTML_DRAWS + 10);
        assert_eq!(
            plan_huge.len(),
            EXTRA_BRIDGEDB_TARGETS.len() + SupplyConfig::MAX_HTML_DRAWS * TORPROJECT_TARGETS.len()
        );
    }

    #[test]
    fn transport_family_key_matches_file_stem_convention() {
        assert_eq!(transport_family_key("webtunnel", "ipv4"), "webtunnel");
        assert_eq!(transport_family_key("webtunnel", "ipv6"), "webtunnel_ipv6");
        assert_eq!(transport_family_key("vanilla", "ipv6"), "vanilla_ipv6");
    }

    #[test]
    fn moat_supply_payloads_are_single_transport_ir_payloads() {
        let payloads = moat_supply_payloads();
        assert_eq!(payloads.len(), 3);
        for payload in &payloads {
            let transports = payload.get("transports").and_then(Value::as_array);
            assert_eq!(transports.map(Vec::len), Some(1));
            assert_eq!(
                payload.get("country").and_then(Value::as_str),
                Some("ir")
            );
        }
    }

    #[test]
    fn history_family_counts_group_by_transport_and_ip_version() {
        let history = json!({
            "a": {"transport": "webtunnel", "ip_version": "ipv4"},
            "b": {"transport": "webtunnel", "ip_version": "ipv6"},
            "c": {"transport": "webtunnel", "ip_version": "ipv6"},
            "d": {"transport": "snowflake", "ip_version": "ipv4"},
            "e": {"transport": "vanilla", "ip_version": "ipv6"},
            "f": "legacy string record",
        });
        let counts = history_family_counts(&history);
        assert_eq!(counts.get("webtunnel"), Some(&1));
        assert_eq!(counts.get("webtunnel_ipv6"), Some(&2));
        assert_eq!(counts.get("snowflake"), Some(&1));
        assert_eq!(counts.get("vanilla_ipv6"), Some(&1));
        assert_eq!(counts.len(), 4);
    }

    #[test]
    fn count_added_lines_deduplicates_and_respects_existing_keys() {
        let history = json!({
            "webtunnel 1.2.3.4:443 1111111111111111111111111111111111111111 url=https://example.test/": {
                "transport": "webtunnel",
                "ip_version": "ipv4",
            }
        });
        let existing = (
            "webtunnel 1.2.3.4:443 1111111111111111111111111111111111111111 url=https://example.test/"
                .to_string(),
            "webtunnel".to_string(),
            "ipv4".to_string(),
        );
        let fresh = (
            "webtunnel 5.6.7.8:443 2222222222222222222222222222222222222222 url=https://other.test/"
                .to_string(),
            "webtunnel".to_string(),
            "ipv4".to_string(),
        );
        let fresh_ipv6 = (
            "webtunnel [2001:4860:4860::8888]:443 3333333333333333333333333333333333333333 url=https://six.test/"
                .to_string(),
            "webtunnel".to_string(),
            "ipv6".to_string(),
        );
        let lines = vec![existing, fresh.clone(), fresh, fresh_ipv6];
        let added = count_added_lines(&history, &lines);
        assert_eq!(added.get("webtunnel"), Some(&1));
        assert_eq!(added.get("webtunnel_ipv6"), Some(&1));
    }

    #[test]
    fn diagnostics_payload_includes_config_sources_and_deltas() {
        let config = SupplyConfig {
            html_draws: 1,
            moat_rounds: 1,
        };
        let before: BTreeMap<String, usize> = [("webtunnel".to_string(), 4)].into_iter().collect();
        let after: BTreeMap<String, usize> = [
            ("webtunnel".to_string(), 5),
            ("snowflake".to_string(), 3),
        ]
        .into_iter()
        .collect();
        let added: BTreeMap<String, usize> = [
            ("webtunnel".to_string(), 1),
            ("snowflake".to_string(), 1),
        ]
        .into_iter()
        .collect();
        let groups = vec![SourceLines {
            source: "bridgedb_html_snowflake",
            requests: 2,
            responses_ok: 1,
            lines: vec![(
                "snowflake 9.9.9.9:443 4444444444444444444444444444444444444444".to_string(),
                "snowflake".to_string(),
                "ipv4".to_string(),
            )],
        }];
        let payload = diagnostics_payload(
            &config,
            &groups,
            &before,
            &after,
            &added,
            "2026-09-06T00:00:00+00:00".to_string(),
        );
        assert_eq!(payload.pointer("/config/html_extra_draws").and_then(Value::as_u64), Some(1));
        assert_eq!(
            payload.pointer("/history_family_counts/before/webtunnel").and_then(Value::as_u64),
            Some(4)
        );
        assert_eq!(
            payload
                .pointer("/history_family_counts/added_by_extended_sources/snowflake")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            payload.pointer("/sources/0/source").and_then(Value::as_str),
            Some("bridgedb_html_snowflake")
        );
    }
}
