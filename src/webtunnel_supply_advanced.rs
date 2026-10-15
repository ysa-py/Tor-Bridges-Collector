//! Advanced, fully-automated WebTunnel supply expansion (strictly additive).
//!
//! WebTunnel is the pipeline's smallest usable pool, and the earlier
//! extended-supply stage (Stage 1x, [`crate::supply_extension`] +
//! [`crate::supply_extension_v2`]) proved via live CI traces that the
//! canonical MOAT request-parameter space is already exhausted: the only
//! legitimately different MOAT payload fields BridgeDB/rdsys parses are
//! `transports` and `unblocked`, and both variants are already drawn every
//! run. The official distributor picture (rdsys, the BridgeDB successor
//! that serves bridges.torproject.org since 2024) distributes webtunnel
//! through the HTTPS web endpoint and the moat settings endpoint only.
//!
//! This module therefore automates the *remaining* legitimate growth levers
//! and makes every run's webtunnel supply status transparent:
//!
//! 1. **Bounded extra WebTunnel HTML draws** (new source label
//!    `webtunnel_html_rotation`): the two canonical
//!    `bridges.torproject.org/bridges?transport=webtunnel[&ipv6=yes]`
//!    pages are re-drawn `WEBTUNNEL_EXTRA_DRAWS` times per run (default 1,
//!    clamp `0..=4`), paced and merged through the exact existing pipeline
//!    (`merge_raw_into_history` + validation). BridgeDB rotates per-request
//!    answers, so repeated bounded draws over the pipeline's 3-hour cadence
//!    are the only remaining honest way to sample new webtunnel subsets.
//!    `0` disables the extra draws entirely.
//! 2. **Automatic canonical documentation audit** (on by default,
//!    `WEBTUNNEL_DOCS_AUDIT`): each run fetches the official Tor Project
//!    rdsys / webtunnel documentation pages and scans them for distributor
//!    mechanism tokens (moat, https, email, telegram, gettor, ...). The
//!    audit result is recorded in the report; if a *new* canonical
//!    mechanism ever appears upstream it will show up in the audit instead
//!    of being silently missed. Fetches are best-effort and never fatal.
//! 3. **Relay probe history sidecar** (`data/webtunnel_probe_history.json`,
//!    append-only, capped): every run records what the Stage 4 probe relay
//!    observed per transport and per host from `data/pt_results.json`
//!    (which itself is re-generated every run, so every webtunnel front is
//!    automatically re-probed on the 3-hour schedule — a temporarily down
//!    front is retried every run, never permanently written off after one
//!    failure). The sidecar makes the retry cadence and per-host results
//!    visible and auditable across runs.
//! 4. **Advanced diagnostics**: the job's step summary is *extended* with
//!    per-channel rows for this module (`webtunnel_html_rotation`), the
//!    webtunnel family before/after/added table, the relay per-transport
//!    totals, and the docs audit table. `data/supply_diagnostics.json` from
//!    Stage 1x is never modified.
//!
//! # Guarantees (identical to the v1/v2 supply modules)
//!
//! * Nothing here removes, disables, or weakens an existing source,
//!   scraper, parser, filter, prober, test, or safety check.
//! * Every fetched line is parsed by [`crate::scraper::parse_bridgelines_html`]
//!   (same validation and reserved-endpoint / documentation-IP gate as the
//!   core scrapers) and merged only through
//!   [`crate::scraper::merge_raw_into_history`].
//! * Request volume is bounded (`WEBTUNNEL_EXTRA_DRAWS` clamped `0..=4` of
//!   two canonical pages = at most 8 requests per run) and paced with the
//!   same jittered pause as the other supply modules. Non-2xx and
//!   unparsable responses degrade to counted zero-line results, never
//!   pipeline failures. Docs-audit fetches are best-effort.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use serde_json::{json, Value};

use crate::scraper::{
    load_history, merge_raw_into_history, normalize_for_history, parse_bridgelines_html,
    prune_history, save_history, HttpFetch, DEFAULT_BRIDGE_DIR,
};
use crate::supply_extension::{
    count_added_lines, history_family_counts, pace_request, SourceLines,
};

/// Request timeout used by every fetch in this module (mirrors the core
/// scrapers and the v1/v2 supply modules).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// New diagnostics report written by every run (new file; never overwrites
/// an existing pipeline output).
const REPORT_FILE: &str = "data/webtunnel_supply_report.json";

/// Append-only per-run probe-history sidecar (new file too).
const PROBE_HISTORY_FILE: &str = "data/webtunnel_probe_history.json";

/// Maximum number of per-run records kept in the probe-history sidecar.
const PROBE_HISTORY_CAP: usize = 300;

/// Stable source label for this module's extra HTML draws. Deliberately
/// distinct from the Stage 1x labels (`bridgedb_html_rotation`,
/// `bridgedb_html_snowflake`) so the diagnostics table shows exactly which
/// module contributed what.
pub const SOURCE_WEBTUNNEL_HTML_ROTATION: &str = "webtunnel_html_rotation";

/// Stable source label for bridge lines recovered through the authenticated
/// probe-relay Worker's `POST /page` edge-vantage fallback (additive,
/// 2026-10-14). Kept distinct from `webtunnel_html_rotation` so the
/// diagnostics table shows exactly which vantage contributed what.
pub const SOURCE_WEBTUNNEL_HTML_EDGE: &str = "webtunnel_html_edge";

/// The two canonical WebTunnel pages served by bridges.torproject.org
/// (rdsys HTTPS distributor). `ip_version` mirrors the file-stem/family
/// convention used everywhere else in the pipeline.
pub const WEBTUNNEL_HTML_TARGETS: &[(&str, &str, &str)] = &[
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel",
        "webtunnel",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes",
        "webtunnel",
        "ipv6",
    ),
];

/// Official Tor Project documentation endpoints audited every run for
/// distributor mechanism tokens. All are public project pages; each fetch
/// is best-effort and non-fatal (a failed fetch is recorded in the audit
/// output, it never fails the pipeline).
///
/// ROUTE FIX (2026-10-14, live-verified): the previous targets used
/// gitlab.torproject.org's `/-/raw/<ref>/<path>` web route, which the
/// gitlab.tpo edge serves 403 (in CI; 400 from other datacenter vantages)
/// to non-browser clients — those three entries had returned 403 in every
/// recorded run. The GitLab API v4 raw-file endpoint serves the identical
/// bytes without the block, verified live with plain curl:
///   * rdsys README                        -> 200 (1644/959B markdown)
///   * rdsys conf/config.json              -> 200 (distributors: https, email,
///     stub, gettor, moat, telegram)
///   * webtunnel README                    -> 200
///
/// The distributor-config entry additionally moves from
/// `config/rdsys.yaml` — which no longer exists on rdsys main (the repo
/// restructured its configuration into `conf/`) — to the modern
/// `conf/config.json`, the file that actually carries the distributor
/// definitions today.
pub const DOC_AUDIT_TARGETS: &[(&str, &str)] = &[
    (
        "rdsys-readme",
        "https://gitlab.torproject.org/api/v4/projects/tpo%2Fanti-censorship%2Frdsys/repository/files/README%2Emd/raw?ref=main",
    ),
    (
        "rdsys-distributor-config",
        "https://gitlab.torproject.org/api/v4/projects/tpo%2Fanti-censorship%2Frdsys/repository/files/conf%2Fconfig%2Ejson/raw?ref=main",
    ),
    (
        "webtunnel-project-readme",
        "https://gitlab.torproject.org/api/v4/projects/tpo%2Fanti-censorship%2Fpluggable-transports%2Fwebtunnel/repository/files/README%2Emd/raw?ref=main",
    ),
    (
        "bridges-torproject-home",
        "https://bridges.torproject.org/",
    ),
];

/// Real-browser header bundle for the additive docs-audit 403 experiment
/// (2026-09-07). The default production client already sends a
/// browser-like Firefox User-Agent (see `scraper::USER_AGENT`) with
/// Accept/Accept-Language defaults, so a plain UA swap alone is not a
/// meaningful variation: this bundle swaps in a current Chrome UA plus the
/// full navigation header set a real browser sends (Sec-Fetch-*,
/// Upgrade-Insecure-Requests), to test whether the gitlab.torproject.org
/// 403s are fingerprint-related rather than IP/challenge-based.
const DOCS_AUDIT_BROWSER_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Upgrade-Insecure-Requests", "1"),
];

/// Mechanism tokens the docs audit scans for. The known canonical
/// distribution mechanisms today are moat (builtin/settings endpoints) and
/// the HTTPS web endpoint; email and telegram exist upstream but are
/// captcha-gated / community-run and out of scope for this pipeline (same
/// constraint as `docs/SUPPLY_EXPANSION.md`).
pub const MECHANISM_TOKENS: &[&str] = &[
    "moat",
    "https",
    "email",
    "telegram",
    "gettor",
    "distributor",
    "webtunnel",
];

/// Bounded per-run tuning for this module.
///
/// * `webtunnel_draws` — extra draws of the two canonical WebTunnel pages
///   (default `1`, clamped `0..=MAX_WEBTUNNEL_DRAWS`).
/// * `docs_audit` — whether the canonical documentation audit runs
///   (default `true`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WebtunnelAdvConfig {
    pub webtunnel_draws: usize,
    pub docs_audit: bool,
}

impl WebtunnelAdvConfig {
    pub const DEFAULT_WEBTUNNEL_DRAWS: usize = 1;
    pub const MAX_WEBTUNNEL_DRAWS: usize = 4;

    /// Read the per-run configuration from the environment.
    ///
    /// * `WEBTUNNEL_EXTRA_DRAWS` — extra draws of the canonical WebTunnel
    ///   pages (clamped to `0..=4`; `0` disables this module's fetching).
    /// * `WEBTUNNEL_DOCS_AUDIT` — `0`/`false` disables the docs audit.
    ///
    /// Unset, non-numeric, or out-of-range values fall back to the default.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            webtunnel_draws: parse_bounded(
                std::env::var("WEBTUNNEL_EXTRA_DRAWS").ok().as_deref(),
                Self::DEFAULT_WEBTUNNEL_DRAWS,
                Self::MAX_WEBTUNNEL_DRAWS,
            ),
            docs_audit: parse_bool_value(
                std::env::var("WEBTUNNEL_DOCS_AUDIT").ok().as_deref(),
                true,
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

/// Parse a boolean configuration value: `0`/`false`/`no` (any case)
/// disables, anything else keeps `default` (so an unset var stays enabled).
fn parse_bool_value(raw: Option<&str>, default: bool) -> bool {
    match raw {
        Some(value) => {
            let value = value.trim().to_ascii_lowercase();
            !(value == "0" || value == "false" || value == "no")
        }
        None => default,
    }
}

/// Assemble the per-run draw plan: `draws` rounds over the two canonical
/// WebTunnel pages. `draws` is clamped to
/// [`WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS`].
#[must_use]
pub fn webtunnel_html_plan(draws: usize) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut plan = Vec::new();
    for _ in 0..draws.min(WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS) {
        plan.extend_from_slice(WEBTUNNEL_HTML_TARGETS);
    }
    plan
}

/// Fetch the extra WebTunnel HTML draws.
///
/// Requests each URL from [`webtunnel_html_plan`] with the same jittered
/// pacing as the v1/v2 supply modules and parses every response with
/// [`parse_bridgelines_html`] — the identical validation chain as the core
/// scraper. Per-URL failures are counted, logged, and skipped.
pub fn fetch_webtunnel_html(client: &dyn HttpFetch, draws: usize) -> SourceLines {
    let plan = webtunnel_html_plan(draws);
    let mut group = SourceLines {
        source: SOURCE_WEBTUNNEL_HTML_ROTATION,
        requests: 0,
        responses_ok: 0,
        lines: Vec::new(),
    };
    let browser_headers: Vec<(String, String)> = DOCS_AUDIT_BROWSER_HEADERS
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();

    for (index, &(url, transport, ip_version)) in plan.iter().enumerate() {
        if index > 0 {
            pace_request();
        }

        let mut parsed = Vec::new();
        let mut last_variant = "no_response";
        for attempt in 0..=1 {
            if attempt > 0 {
                // One bounded fallback attempt per page. The pacing applies to
                // retries too, so empty/challenge responses never create a
                // tight retry loop against BridgeDB.
                pace_request();
            }
            group.requests += 1;
            let result = if attempt == 0 {
                client.get(url, REQUEST_TIMEOUT)
            } else {
                client.get_with_headers(url, &browser_headers, REQUEST_TIMEOUT)
            };
            let method = if attempt == 0 {
                "GET"
            } else {
                "GET+browser-headers"
            };

            match result {
                Ok(resp) if (200..300).contains(&resp.status) => {
                    group.responses_ok += 1;
                    last_variant = bridgedb_page_variant(&resp.text);
                    parsed = parse_bridgelines_html(&resp.text);
                    println!(
                        "webtunnel_supply_advanced draw: url={url} attempt={} method={} status={} parsed_lines={} page_variant={} source={}",
                        attempt + 1,
                        method,
                        resp.status,
                        parsed.len(),
                        bridgedb_page_variant(&resp.text),
                        group.source,
                    );
                    if !parsed.is_empty() {
                        break;
                    }
                    if attempt == 0 {
                        eprintln!(
                            "webtunnel_supply_advanced draw: url={url} returned HTTP {} but no validated bridge lines (page_variant={}); retrying once with browser headers",
                            resp.status,
                            bridgedb_page_variant(&resp.text),
                        );
                    }
                }
                Ok(resp) => {
                    eprintln!(
                        "webtunnel_supply_advanced draw: url={url} attempt={} method={} status={} source={}",
                        attempt + 1,
                        method,
                        resp.status,
                        group.source,
                    );
                    if attempt == 0 {
                        eprintln!(
                            "webtunnel_supply_advanced draw: url={url} retrying once with browser headers after non-2xx response"
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "webtunnel_supply_advanced draw: url={url} attempt={} method={} error={} source={}",
                        attempt + 1,
                        method,
                        err,
                        group.source,
                    );
                    if attempt == 0 {
                        eprintln!(
                            "webtunnel_supply_advanced draw: url={url} retrying once with browser headers after request error"
                        );
                    }
                }
            }
        }

        if parsed.is_empty() {
            eprintln!(
                "webtunnel_supply_advanced draw: url={url} produced no validated bridge lines after the bounded retry (page_variant={last_variant}); no records added. BridgeDB gates its HTML interface per client vantage (IP reputation / rate limit / k-anonymity), so an empty page from the CI runner is commonly vantage-gating, not an empty global supply."
            );
        }
        for line in parsed {
            group
                .lines
                .push((line, transport.to_string(), ip_version.to_string()));
        }
    }
    group
}

/// Classify which BridgeDB page variant a response body is, so a zero-line
/// draw is diagnosable from the log alone (additive, 2026-10-14).
///
/// * `bridgelines_div_present` — the real bridge-issuing page rendered; zero
///   validated lines means BridgeDB genuinely issued nothing for this
///   transport/vantage in this window.
/// * `no_bridgelines_div` — an interstitial (rate-limit, consent, or error
///   page) was served instead; the vantage is gated and the draw carries no
///   supply information at all.
/// * `empty_body` — 2xx with no usable body.
#[must_use]
pub fn bridgedb_page_variant(body: &str) -> &'static str {
    if body.trim().is_empty() {
        "empty_body"
    } else if body.contains("id=\"bridgelines\"") {
        "bridgelines_div_present"
    } else {
        "no_bridgelines_div"
    }
}

/// Classify a non-JSON relay reply by SHAPE only (redaction-safe: the body
/// content itself is never logged, only a structural class).
fn relay_envelope_shape_class(body: &str) -> &'static str {
    let trimmed = body.trim_start();
    if trimmed.is_empty() {
        "empty"
    } else if trimmed.starts_with('<') {
        "html_like"
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        "json_like_but_unparsed"
    } else {
        "text_like"
    }
}

/// Bounded per-run tuning for the authenticated edge-vantage fallback draw.
///
/// * `enabled` — master switch (`WEBTUNNEL_EDGE_FETCH`, default on).
/// * `relay_base_url` / `relay_token` — the probe-relay endpoint and its
///   shared secret, read from the same `PROBE_RELAY_URL` / `PROBE_RELAY_TOKEN`
///   environment variables Stage 4-prep/Stage 4 already use, so no new
///   secret is introduced. When either is absent the fallback silently
///   stays off (the direct draws remain the primary source).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdgeFetchConfig {
    pub enabled: bool,
    pub relay_base_url: String,
    pub relay_token: String,
}

impl EdgeFetchConfig {
    /// Read the configuration from the environment. Returns `None` when the
    /// fallback cannot run (disabled, or the relay endpoint/secret is not
    /// configured in this job).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let enabled = parse_bool_value(std::env::var("WEBTUNNEL_EDGE_FETCH").ok().as_deref(), true);
        let relay_base_url = std::env::var("PROBE_RELAY_URL").ok()?;
        let relay_token = std::env::var("PROBE_RELAY_TOKEN").ok()?;
        if !enabled
            || !relay_base_url.starts_with("https://")
            || relay_base_url.contains(['?', '#', '@', '"', '\\'])
            || relay_base_url.chars().any(char::is_whitespace)
            || relay_token.len() < 16
            || relay_token.len() > 1024
            || relay_token.chars().any(|c| c.is_control())
        {
            return None;
        }
        Some(Self {
            enabled,
            relay_base_url,
            relay_token,
        })
    }
}

/// Edge-vantaged WebTunnel draw (additive, 2026-10-14): fetch the canonical
/// BridgeDB WebTunnel pages through the authenticated probe-relay Worker's
/// `POST /page` endpoint instead of the runner's own egress.
///
/// WHY: BridgeDB gates its HTML interface per client vantage (IP reputation,
/// rate limiting, k-anonymity throttles). The GitHub Actions vantage
/// consistently receives an HTTP 200 interstitial with no bridge lines
/// (measured run 38574505786: `parsed_lines=0` on every attempt), while the
/// same URL serves real bridge lines from other vantages. The Worker runs on
/// Cloudflare's edge — a different IP class — so a relay-fetched page has a
/// materially different gating outcome.
///
/// SAFETY: the Worker only serves a fixed allowlist of public documentation
/// pages (see `probe-relay/src/index.ts`), requires the same `X-Probe-Token`
/// secret as `/probe`, caps the response size, and never follows redirects
/// off the allowlist. This client sends no bridge data anywhere — it only
/// receives page text and parses it through the exact same validation chain
/// as the direct draws ([`crate::scraper::parse_bridgelines_html`]).
///
/// Failures are typed, logged, and skipped: the fallback is strictly
/// additive and can never replace or falsify the direct draw's evidence.
#[must_use]
pub fn fetch_webtunnel_html_via_edge(
    client: &dyn HttpFetch,
    relay_base_url: &str,
    relay_token: &str,
    draws: usize,
) -> SourceLines {
    let plan = webtunnel_html_plan(draws);
    let mut group = SourceLines {
        source: SOURCE_WEBTUNNEL_HTML_EDGE,
        requests: 0,
        responses_ok: 0,
        lines: Vec::new(),
    };
    let base = relay_base_url.trim_end_matches('/');
    let endpoint = format!("{}/page", base.trim_end_matches("/probe"));
    let headers = vec![("X-Probe-Token".to_string(), relay_token.to_string())];

    for (index, &(url, transport, ip_version)) in plan.iter().enumerate() {
        if index > 0 {
            pace_request();
        }
        group.requests += 1;
        let body = json!({ "url": url });
        match client.post_json(&endpoint, &body, &headers, REQUEST_TIMEOUT) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                let parsed: Value = serde_json::from_str(&resp.text).unwrap_or(Value::Null);
                let page_status = parsed.get("status").and_then(Value::as_u64).unwrap_or(0);
                let page_text = parsed
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let mut lines = Vec::new();
                if (200..300).contains(&page_status) && !page_text.is_empty() {
                    lines = parse_bridgelines_html(page_text);
                }
                group.responses_ok += 1;
                // Envelope-shape diagnosis (additive, 2026-10-14): run
                // 38600087512 saw relay 200 with a body that was NOT the
                // expected {url,status,bytes,truncated,text} JSON envelope
                // (page_status=0, empty page). Classify the shape — typed
                // classes only, never body content — so the next run pins
                // down whether the relay path returned HTML (e.g. a
                // redirect/interstitial followed by the HTTP client), an
                // error envelope, or an unexpected JSON shape.
                let envelope_shape = if parsed.is_null() {
                    relay_envelope_shape_class(&resp.text)
                } else if parsed.get("status").is_some() && parsed.get("text").is_some() {
                    "expected_envelope"
                } else if parsed.as_object().is_some() {
                    "unexpected_json_object"
                } else {
                    "unexpected_json_value"
                };
                println!(
                    "webtunnel_supply_advanced edge draw: url={url} via=probe-relay-page relay_status={} envelope_shape={} page_status={} parsed_lines={} page_variant={} source={}",
                    resp.status,
                    envelope_shape,
                    page_status,
                    lines.len(),
                    bridgedb_page_variant(page_text),
                    group.source,
                );
                for line in lines {
                    group
                        .lines
                        .push((line, transport.to_string(), ip_version.to_string()));
                }
            }
            Ok(resp) => {
                eprintln!(
                    "webtunnel_supply_advanced edge draw: url={url} via=probe-relay-page relay_status={} source={} (non-2xx; skipping)",
                    resp.status, group.source,
                );
            }
            Err(err) => {
                eprintln!(
                    "webtunnel_supply_advanced edge draw: url={url} via=probe-relay-page error={} source={} (skipping)",
                    err, group.source,
                );
            }
        }
    }
    group
}

/// Scan a document body for known distributor mechanism tokens.
///
/// Returns the sorted list of tokens present in `text` (each occurrence
/// counted once per document). Pure string scan over official docs; used by
/// the canonical-mechanism audit.
#[must_use]
pub fn scan_mechanism_tokens(text: &str) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    let mut found: Vec<String> = MECHANISM_TOKENS
        .iter()
        .filter(|token| lowered.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Fetch and scan the official documentation endpoints.
///
/// Best-effort: every entry records `status` and the tokens found (or the
/// fetch error). A fetch failure is recorded, never fatal.
///
/// ADDITIVE 403 EXPERIMENT (2026-09-07): three of the four
/// gitlab.torproject.org targets have returned HTTP 403 in every recorded
/// run while bridges.torproject.org returns 200. On any non-2xx (or
/// transport-error) first response the audit now — still best-effort and
/// non-fatal exactly as before — retries with:
///
///   1. a full real-browser header bundle (Chrome UA + Sec-Fetch-* — see
///      [`DOCS_AUDIT_BROWSER_HEADERS`]);
///   2. a HEAD request, to distinguish a GET-specific block from a
///      blanket method-independent (IP/challenge) block.
///
/// Every attempt is recorded in an additive `attempts` array, and a
/// successful retry adds a `resolved_by` field. When the first attempt
/// succeeds, the entry shape and the log line are byte-identical to the
/// pre-experiment behaviour (plus the `attempts` array).
pub fn audit_canonical_docs(client: &dyn HttpFetch) -> Vec<Value> {
    let mut entries = Vec::new();
    for (label, url) in DOC_AUDIT_TARGETS {
        // Attempt 1 — the pre-existing request, unchanged.
        let first = client.get(url, REQUEST_TIMEOUT);
        let mut attempts = vec![match &first {
            Ok(resp) => json!({ "attempt": 1, "method": "GET", "status": resp.status }),
            Err(err) => json!({ "attempt": 1, "method": "GET", "error": err.to_string() }),
        }];

        if let Ok(resp) = &first {
            if (200..300).contains(&resp.status) {
                let tokens = scan_mechanism_tokens(&resp.text);
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "status": resp.status,
                    "bytes": resp.text.len(),
                    "mechanism_tokens": tokens,
                    "attempts": attempts,
                }));
                println!(
                    "webtunnel_supply_advanced docs audit: doc={label} url={url} status={} bytes={} tokens={tokens:?}",
                    resp.status,
                    resp.text.len(),
                );
                continue;
            }
        }

        // Non-2xx (or transport error) — run the additive experiment.
        let browser_headers: Vec<(String, String)> = DOCS_AUDIT_BROWSER_HEADERS
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let retry = client.get_with_headers(url, &browser_headers, REQUEST_TIMEOUT);
        attempts.push(match &retry {
            Ok(resp) => json!({
                "attempt": 2,
                "method": "GET+browser-headers",
                "status": resp.status
            }),
            Err(err) => json!({
                "attempt": 2,
                "method": "GET+browser-headers",
                "error": err.to_string()
            }),
        });
        let head = client.head(url, REQUEST_TIMEOUT);
        attempts.push(match &head {
            Ok(resp) => json!({ "attempt": 3, "method": "HEAD", "status": resp.status }),
            Err(err) => json!({ "attempt": 3, "method": "HEAD", "error": err.to_string() }),
        });

        // If the browser-header retry succeeded, scan it exactly like the
        // base case would have (success-shaped entry + experiment fields).
        if let Ok(resp) = &retry {
            if (200..300).contains(&resp.status) {
                let tokens = scan_mechanism_tokens(&resp.text);
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "status": resp.status,
                    "bytes": resp.text.len(),
                    "mechanism_tokens": tokens,
                    "resolved_by": "browser-headers-retry",
                    "attempts": attempts,
                }));
                println!(
                    "webtunnel_supply_advanced docs audit: doc={label} url={url} status={} bytes={} tokens={tokens:?} resolved_by=browser-headers-retry",
                    resp.status,
                    resp.text.len(),
                );
                continue;
            }
        }

        // Still failing — record exactly the pre-existing failure shape,
        // plus the additive attempts array documenting the experiment.
        match first {
            Ok(resp) => {
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "status": resp.status,
                    "error": "non-2xx",
                    "attempts": attempts,
                }));
                eprintln!(
                    "webtunnel_supply_advanced docs audit: doc={label} url={url} status={} error=non-2xx",
                    resp.status
                );
            }
            Err(err) => {
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "error": err.to_string(),
                    "attempts": attempts,
                }));
                eprintln!(
                    "webtunnel_supply_advanced docs audit: doc={label} url={url} error={err}"
                );
            }
        }
    }
    entries
}

#[cfg(test)]
impl EdgeFetchConfig {
    /// Deterministic constructor mirroring `from_env` validation for tests.
    fn from_env_struct(relay_base_url: &str, relay_token: &str) -> Option<Self> {
        if !relay_base_url.starts_with("https://")
            || relay_base_url.contains(['?', '#', '@', '"', '\\'])
            || relay_base_url.chars().any(char::is_whitespace)
            || relay_token.len() < 16
            || relay_token.len() > 1024
            || relay_token.chars().any(|c| c.is_control())
        {
            return None;
        }
        Some(Self {
            enabled: true,
            relay_base_url: relay_base_url.to_string(),
            relay_token: relay_token.to_string(),
        })
    }
}

/// Read `data/pt_results.json` (written by Stage 4) into a vector of JSON
/// entries. Missing/invalid files degrade to an empty vector.
#[must_use]
pub fn read_pt_results() -> Vec<Value> {
    match fs::read_to_string("data/pt_results.json") {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Normalise a probe-record transport label into the canonical diagnostic
/// family key.
///
/// The relay-side probe (`scripts/probe_relay.sh`) labels a descriptor by
/// the first token of the source line verbatim, so a vanilla bridge line
/// carrying the optional `Bridge `/`bridge ` prefix surfaces as
/// `transport:"Bridge"` or `transport:"bridge"` instead of `vanilla`. The
/// split buckets showed up in every PROBE_RELAY notice as
/// `Bridge=0/2 bridge=160/486 …` — two phantom transports with misleading
/// zero-success rates next to the real ones. A line whose only transport
/// marker is the generic bridge prefix is a vanilla bridge: collapse the
/// case variants onto `vanilla`, lowercase everything else, and keep
/// already-canonical labels byte-identical.
fn normalize_transport_label(transport: &str) -> String {
    let lowered = transport.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "bridge" => "vanilla".to_string(),
        _ => lowered,
    }
}

/// Summarise relay probe observations per transport and per host.
///
/// Each result entry is expected to carry `transport`, `success`, `host`,
/// and `port` (the schema written by probe-relay and merged by
/// `scripts/probe_relay.sh`). The summary is purely diagnostic.
#[must_use]
pub fn summarize_pt_results(results: &[Value]) -> Value {
    let mut by_transport: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut by_host: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    for entry in results {
        let Some(transport) = entry.get("transport").and_then(Value::as_str) else {
            continue;
        };
        let Some(host) = entry.get("host").and_then(Value::as_str) else {
            continue;
        };
        let success = entry
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transport_key = normalize_transport_label(transport);
        let counter = by_transport.entry(transport_key.clone()).or_default();
        *counter.entry("attempted").or_insert(0) += 1;
        if success {
            *counter.entry("success").or_insert(0) += 1;
        }
        let host_key = format!("{transport_key}|{host}");
        let host_counter = by_host.entry(host_key).or_default();
        *host_counter.entry("attempted").or_insert(0) += 1;
        if success {
            *host_counter.entry("success").or_insert(0) += 1;
        }
    }
    json!({
        "by_transport": by_transport,
        "by_host": by_host,
        "entries": results.len(),
    })
}

/// Load the append-only probe-history sidecar (`{ "runs": [...] }`),
/// returning an empty document when the file is missing or unparsable.
#[must_use]
pub fn load_probe_history() -> Value {
    match fs::read_to_string(PROBE_HISTORY_FILE) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| json!({ "runs": [] })),
        Err(_) => json!({ "runs": [] }),
    }
}

/// Append one per-run record to the probe-history sidecar, keeping at most
/// [`PROBE_HISTORY_CAP`] records. Best-effort: failures are logged, never
/// fatal.
pub fn push_probe_history_record(record: Value) {
    let mut history = load_probe_history();
    let mut runs: Vec<Value> = match history.get_mut("runs").and_then(Value::as_array_mut) {
        Some(runs) => std::mem::take(runs),
        None => Vec::new(),
    };
    runs.push(record);
    if runs.len() > PROBE_HISTORY_CAP {
        let overflow = runs.len() - PROBE_HISTORY_CAP;
        runs.drain(..overflow);
    }
    match serde_json::to_vec_pretty(&json!({ "runs": runs })) {
        Ok(buf) => {
            if let Err(err) = fs::write(PROBE_HISTORY_FILE, buf) {
                eprintln!("webtunnel probe history: could not write: {err}");
            }
        }
        Err(err) => eprintln!("webtunnel probe history: could not serialize: {err}"),
    }
}

/// Write the per-run diagnostics report (new file, best-effort).
pub fn write_report(payload: &Value) {
    if let Err(err) = fs::create_dir_all("data") {
        eprintln!("webtunnel supply: could not create data directory: {err}");
        return;
    }
    match serde_json::to_vec_pretty(payload) {
        Ok(buf) => {
            if let Err(err) = fs::write(REPORT_FILE, buf) {
                eprintln!("webtunnel supply: could not write {REPORT_FILE}: {err}");
            }
        }
        Err(err) => eprintln!("webtunnel supply: could not serialize report: {err}"),
    }
}

/// The per-run source groups feeding the step summary: the direct
/// runner-vantage draw plus the optional edge-vantage fallback draw.
pub struct SupplySources<'a> {
    pub direct: &'a SourceLines,
    pub edge: Option<&'a SourceLines>,
}

/// Append the module's markdown section to `$GITHUB_STEP_SUMMARY` when
/// running inside GitHub Actions (best-effort; ignored elsewhere). This
/// *extends* the job's existing supply-diagnostics summary from Stage 1x
/// with a new per-channel table — it never replaces or edits that table.
pub fn emit_step_summary(
    config: &WebtunnelAdvConfig,
    sources: SupplySources<'_>,
    before: &BTreeMap<String, usize>,
    after: &BTreeMap<String, usize>,
    added: &BTreeMap<String, usize>,
    relay: &Value,
    docs_audit: &[Value],
) {
    let SupplySources { direct: html, edge } = sources;
    let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let get = |map: &BTreeMap<String, usize>, family: &str| -> u64 {
        u64::try_from(map.get(family).copied().unwrap_or(0)).unwrap_or(u64::MAX)
    };
    let mut rows = String::from("### WebTunnel supply automation (advanced module, additive)\n\n");
    rows.push_str(&format!(
        "config: webtunnel html extra draws = {}, docs audit = {};\n",
        config.webtunnel_draws, config.docs_audit
    ));
    rows.push_str("new history records added by this module's draws = ");
    let module_added: usize = added.values().sum();
    rows.push_str(&format!("{module_added}\n\n"));
    rows.push_str(
        "| channel | requests | responses_ok | fetched_lines | added_records |\n\
         |---|---|---|---|---|\n",
    );
    rows.push_str(&format!(
        "| {source} | {requests} | {ok} | {fetched} | {added_records} |\n",
        source = html.source,
        requests = html.requests,
        ok = html.responses_ok,
        fetched = html.lines.len(),
        added_records = added.values().sum::<usize>(),
    ));
    if let Some(edge_group) = edge {
        rows.push_str(&format!(
            "| {source} | {requests} | {ok} | {fetched} | {added_records} |\n",
            source = edge_group.source,
            requests = edge_group.requests,
            ok = edge_group.responses_ok,
            fetched = edge_group.lines.len(),
            added_records = added.values().sum::<usize>(),
        ));
    }
    rows.push_str("\n| webtunnel family | before | after | added |\n|---|---|---|---|\n");
    for family in ["webtunnel", "webtunnel_ipv6"] {
        rows.push_str(&format!(
            "| {family} | {b} | {a} | {d} |\n",
            b = get(before, family),
            a = get(after, family),
            d = get(added, family),
        ));
    }
    if let Some(by_transport) = relay.get("by_transport").and_then(Value::as_object) {
        if !by_transport.is_empty() {
            rows.push_str("\n| relay transport | attempted | success |\n|---|---|---|\n");
            for (transport, counters) in by_transport {
                let attempted = counters
                    .get("attempted")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let success = counters.get("success").and_then(Value::as_u64).unwrap_or(0);
                rows.push_str(&format!("| {transport} | {attempted} | {success} |\n"));
            }
        }
    }
    if !docs_audit.is_empty() {
        rows.push_str("\n| docs audit | status | mechanism tokens |\n|---|---|---|\n");
        for entry in docs_audit {
            let doc = entry.get("doc").and_then(Value::as_str).unwrap_or("?");
            let status = entry.get("status").and_then(Value::as_u64).unwrap_or(0);
            let error = entry.get("error").and_then(Value::as_str).unwrap_or("");
            let tokens = entry
                .get("mechanism_tokens")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|| error.to_string());
            rows.push_str(&format!("| {doc} | {status} | {tokens} |\n"));
        }
    }
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(summary_path)
    {
        use std::io::Write;
        let _ = file.write_all(rows.as_bytes());
    }
}

/// Emit `::notice` workflow annotations for this module's headline numbers
/// so they are visible on the run page without log access.
pub fn emit_workflow_notices(
    after: &BTreeMap<String, usize>,
    html: &SourceLines,
    edge: Option<&SourceLines>,
    added_total: usize,
) {
    for family in ["webtunnel", "webtunnel_ipv6"] {
        let count = after.get(family).copied().unwrap_or(0);
        println!("::notice title=WEBTUNNEL_SUPPLY::{family}::history_count_after={count}");
    }
    println!(
        "::notice title=WEBTUNNEL_SUPPLY::webtunnel_html_rotation::fetched_lines={} added_records={}",
        html.lines.len(),
        added_total
    );
    if let Some(edge_group) = edge {
        println!(
            "::notice title=WEBTUNNEL_SUPPLY::webtunnel_html_edge::relay_fetched_lines={} added_records={}",
            edge_group.lines.len(),
            added_total
        );
    }
}

/// Additive (2026-09-07): surface the probe-relay per-transport outcome
/// summary and the docs-audit experiment results as GitHub Actions notice
/// annotations, so the fronted-transport success rates (webtunnel / meek /
/// conjure / snowflake - previously a permanent 0-success signature) and
/// the docs-audit 403 experiment results are visible on the run page and
/// through the Checks API without log or artifact access. Purely
/// diagnostic - never fatal, never counted anywhere.
pub fn emit_relay_and_docs_notices(relay: &Value, docs_audit: &[Value]) {
    if let Some(by_transport) = relay.get("by_transport").and_then(Value::as_object) {
        if !by_transport.is_empty() {
            let mut parts: Vec<String> = Vec::new();
            for (transport, counters) in by_transport {
                let attempted = counters
                    .get("attempted")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let success = counters.get("success").and_then(Value::as_u64).unwrap_or(0);
                parts.push(format!("{transport}={success}/{attempted}"));
            }
            println!(
                "::notice title=PROBE_RELAY::per-transport success/attempted: {}",
                parts.join(" ")
            );
        }
    }
    if !docs_audit.is_empty() {
        let mut parts: Vec<String> = Vec::new();
        for entry in docs_audit {
            let doc = entry.get("doc").and_then(Value::as_str).unwrap_or("?");
            let status = entry
                .get("status")
                .and_then(Value::as_u64)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "err".to_string());
            parts.push(format!("{doc}={status}"));
        }
        println!(
            "::notice title=DOC_AUDIT::statuses (first-attempt): {}",
            parts.join(" ")
        );
    }
}

/// Core driver shared by the binary: load history, optionally fetch the
/// extra WebTunnel draws and the docs audit, merge through the canonical
/// pipeline, and emit all diagnostics.
///
/// `network_available` mirrors the binary's `#[cfg(feature = "network")]`
/// gate so the offline path (all counters zero) stays testable.
pub fn run_advanced_supply(
    network_available: bool,
    client: Option<&dyn HttpFetch>,
    generated_at: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = WebtunnelAdvConfig::from_env();

    let history_path = std::path::Path::new(DEFAULT_BRIDGE_DIR).join("bridge_history.json");
    let mut history = load_history(&history_path)?;
    let before = history_family_counts(&history);

    let (html, docs_audit) = if network_available {
        let client = client.expect("network_available implies a client");
        let html = fetch_webtunnel_html(client, config.webtunnel_draws);
        let docs_audit = if config.docs_audit {
            audit_canonical_docs(client)
        } else {
            Vec::new()
        };
        (html, docs_audit)
    } else {
        let html = SourceLines {
            source: SOURCE_WEBTUNNEL_HTML_ROTATION,
            requests: 0,
            responses_ok: 0,
            lines: Vec::new(),
        };
        (html, Vec::new())
    };

    // Edge-vantage fallback (additive, 2026-10-14): when the direct runner
    // draw was vantage-gated (BridgeDB served an interstitial / empty page),
    // re-draw the same canonical pages through the authenticated probe-relay
    // Worker's `POST /page` endpoint. Strictly additive: it only runs when the
    // direct draw produced zero validated lines, and it merges through the
    // exact same validation chain. Never runs when the relay secrets are
    // absent from the environment.
    let mut edge: Option<SourceLines> = None;
    if network_available && html.lines.is_empty() {
        if let Some(edge_config) = EdgeFetchConfig::from_env() {
            let client = client.expect("network_available implies a client");
            let group = fetch_webtunnel_html_via_edge(
                client,
                &edge_config.relay_base_url,
                &edge_config.relay_token,
                config.webtunnel_draws,
            );
            edge = Some(group);
        }
    }

    // Combined per-line view across both vantages for counting/merging.
    let mut combined_lines = html.lines.clone();
    if let Some(edge_group) = &edge {
        combined_lines.extend(edge_group.lines.iter().cloned());
    }

    let added = count_added_lines(&history, &combined_lines);
    let added_total: usize = added.values().sum();

    // Per-line audit trace (additive diagnostics), mirroring the
    // supply_extender trace so fetched/new is auditable line-by-line.
    for (line, transport, ip_version) in &html.lines {
        let key = normalize_for_history(line, transport);
        let known = history
            .as_object()
            .is_some_and(|object| object.contains_key(&key));
        println!(
            "webtunnel_supply_advanced trace: source={} transport={} ip_version={} known={} line={}",
            html.source, transport, ip_version, known, line,
        );
    }
    if let Some(edge_group) = &edge {
        for (line, transport, ip_version) in &edge_group.lines {
            let key = normalize_for_history(line, transport);
            let known = history
                .as_object()
                .is_some_and(|object| object.contains_key(&key));
            println!(
                "webtunnel_supply_advanced trace: source={} transport={} ip_version={} known={} line={}",
                edge_group.source, transport, ip_version, known, line,
            );
        }
    }

    // Merge through the canonical history writer (same validation,
    // deduplication, and last_seen refresh as every other source).
    let pruned = if combined_lines.is_empty() {
        0
    } else {
        merge_raw_into_history(&mut history, &combined_lines)?;
        prune_history(&mut history)?
    };
    save_history(&history, &history_path)?;
    let after = history_family_counts(&history);

    let relay = summarize_pt_results(&read_pt_results());

    let mut sources_json = vec![json!({
        "source": html.source,
        "requests": html.requests,
        "responses_ok": html.responses_ok,
        "fetched_lines": html.lines.len(),
        "added_records": added_total,
    })];
    if let Some(edge_group) = &edge {
        sources_json.push(json!({
            "source": edge_group.source,
            "requests": edge_group.requests,
            "responses_ok": edge_group.responses_ok,
            "fetched_lines": edge_group.lines.len(),
            "added_records": added_total,
        }));
    }
    let payload = json!({
        "generated_at": generated_at,
        "config": {
            "webtunnel_html_draws": config.webtunnel_draws,
            "docs_audit": config.docs_audit,
        },
        "sources": sources_json,
        "webtunnel_family_counts": {
            "before": family_counts_to_json(&before, &["webtunnel", "webtunnel_ipv6"]),
            "after": family_counts_to_json(&after, &["webtunnel", "webtunnel_ipv6"]),
            "added_by_webtunnel_source": family_counts_to_json(&added, &["webtunnel", "webtunnel_ipv6"]),
        },
        "relay_observations": relay,
        "docs_audit": docs_audit,
    });

    write_report(&payload);
    let generated_at_value = payload.get("generated_at").cloned().unwrap_or(Value::Null);
    let config_value = payload.get("config").cloned().unwrap_or(Value::Null);
    let relay_transport_value = relay.get("by_transport").cloned().unwrap_or(Value::Null);
    push_probe_history_record(json!({
        "generated_at": generated_at_value,
        "config": config_value,
        "webtunnel_html_fetched_lines": html.lines.len(),
        "webtunnel_html_edge_fetched_lines": edge.as_ref().map_or(0, |group| group.lines.len()),
        "webtunnel_html_added_records": added_total,
        "relay_per_transport": relay_transport_value,
    }));
    emit_step_summary(
        &config,
        SupplySources {
            direct: &html,
            edge: edge.as_ref(),
        },
        &before,
        &after,
        &added,
        &relay,
        &docs_audit,
    );
    emit_workflow_notices(&after, &html, edge.as_ref(), added_total);
    emit_relay_and_docs_notices(&relay, &docs_audit);

    println!(
        "webtunnel_supply_advanced: config draws={} docs_audit={} fetched_lines={} new_history_records={} pruned={}",
        config.webtunnel_draws,
        config.docs_audit,
        html.lines.len(),
        added_total,
        pruned,
    );
    Ok(())
}

/// Render a counts map as a JSON object, restricted to `families`.
fn family_counts_to_json(counts: &BTreeMap<String, usize>, families: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for family in families {
        if let Some(count) = counts.get(*family) {
            map.insert((*family).to_string(), json!(count));
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bounded_clamps_and_defaults() {
        assert_eq!(parse_bounded(None, 1, 4), 1);
        assert_eq!(parse_bounded(Some(""), 1, 4), 1);
        assert_eq!(parse_bounded(Some("0"), 1, 4), 0);
        assert_eq!(parse_bounded(Some("99"), 1, 4), 4);
        assert_eq!(parse_bounded(Some("abc"), 1, 4), 1);
    }

    #[test]
    fn parse_bool_value_disables_on_false_like() {
        assert!(parse_bool_value(None, true));
        assert!(parse_bool_value(Some("1"), true));
        assert!(!parse_bool_value(Some("0"), true));
        assert!(!parse_bool_value(Some("false"), true));
        assert!(!parse_bool_value(Some("no"), true));
    }

    #[test]
    fn webtunnel_html_plan_is_bounded_draws_of_two_pages() {
        let plan = webtunnel_html_plan(2);
        assert_eq!(plan.len(), 2 * WEBTUNNEL_HTML_TARGETS.len());
        let zero = webtunnel_html_plan(0);
        assert!(zero.is_empty());
        let huge = webtunnel_html_plan(WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS + 10);
        assert_eq!(
            huge.len(),
            WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS * WEBTUNNEL_HTML_TARGETS.len()
        );
    }

    #[test]
    fn scan_mechanism_tokens_finds_known_tokens_only() {
        let text = "rdsys distributors: moat, https and email. webtunnel resources.";
        let found = scan_mechanism_tokens(text);
        assert!(found.contains(&"moat".to_string()));
        assert!(found.contains(&"https".to_string()));
        assert!(found.contains(&"webtunnel".to_string()));
        assert!(!found.contains(&"gettor".to_string()));
        let none = scan_mechanism_tokens("no tokens here");
        assert!(none.is_empty());
    }

    use crate::scraper::{HttpFetch, HttpResponse, ScraperError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock for WebTunnel HTML ingestion: the first request can return a
    /// challenge/empty page while the bounded browser-header retry returns
    /// a parser-valid bridge line. It tracks retries without touching the
    /// network.
    struct WebTunnelHtmlRetryMock {
        initial_status: u16,
        initial_body: &'static str,
        retry_status: u16,
        retry_body: &'static str,
        retry_calls: AtomicUsize,
    }

    impl HttpFetch for WebTunnelHtmlRetryMock {
        fn get(&self, _url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            Ok(mock_response(self.initial_status, self.initial_body))
        }

        fn post_json(
            &self,
            _url: &str,
            _body: &Value,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            Err(ScraperError::Http {
                url: String::new(),
                message: "POST not supported by WebTunnel retry mock".to_string(),
            })
        }

        fn get_with_headers(
            &self,
            _url: &str,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            self.retry_calls.fetch_add(1, Ordering::SeqCst);
            Ok(mock_response(self.retry_status, self.retry_body))
        }
    }

    #[test]
    fn webtunnel_html_retries_empty_200_once_with_browser_headers() {
        let mock = WebTunnelHtmlRetryMock {
            initial_status: 200,
            initial_body: "<html><body>challenge page, no bridge lines</body></html>",
            retry_status: 200,
            retry_body: r#"<div id="bridgelines">
webtunnel url=https://example.com/ abcdef0123456789
</div>"#,
            retry_calls: AtomicUsize::new(0),
        };

        // One draw contains two canonical pages. Each empty 200 gets exactly
        // one paced retry; only parser- and safety-validated lines are returned.
        let source = fetch_webtunnel_html(&mock, 1);
        assert_eq!(source.requests, 4);
        assert_eq!(source.responses_ok, 4);
        assert_eq!(mock.retry_calls.load(Ordering::SeqCst), 2);
        assert_eq!(source.lines.len(), 2);
        assert!(source.lines.iter().all(|(line, transport, _)| {
            transport == "webtunnel" && line.contains("url=https://example.com/")
        }));
        assert_eq!(source.lines[0].2, "ipv4");
        assert_eq!(source.lines[1].2, "ipv6");
    }

    #[test]
    fn webtunnel_html_does_not_fabricate_lines_when_both_attempts_are_empty() {
        let mock = WebTunnelHtmlRetryMock {
            initial_status: 200,
            initial_body: "<html><body>challenge page</body></html>",
            retry_status: 200,
            retry_body: "<html><body>still no bridge lines</body></html>",
            retry_calls: AtomicUsize::new(0),
        };

        let source = fetch_webtunnel_html(&mock, 1);
        assert_eq!(source.requests, 4);
        assert_eq!(source.responses_ok, 4);
        assert_eq!(mock.retry_calls.load(Ordering::SeqCst), 2);
        assert!(
            source.lines.is_empty(),
            "empty/unvalidated responses must not create bridge records"
        );
    }

    /// Mock client for the additive docs-audit 403 experiment: configurable
    /// outcomes for the base GET, the browser-header retry, and the HEAD.
    struct DocsAuditMock {
        get: Option<u16>,
        retry: Option<u16>,
        head: Option<u16>,
    }

    fn mock_response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            text: body.to_string(),
        }
    }

    impl HttpFetch for DocsAuditMock {
        fn get(&self, url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            match self.get {
                Some(status) => Ok(mock_response(status, "unused first-attempt body")),
                None => Err(ScraperError::Http {
                    url: url.to_string(),
                    message: "mock transport failure".to_string(),
                }),
            }
        }
        fn post_json(
            &self,
            _url: &str,
            _body: &Value,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            Err(ScraperError::Http {
                url: String::new(),
                message: "POST not supported".to_string(),
            })
        }
        fn get_with_headers(
            &self,
            url: &str,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            match self.retry {
                Some(status) => Ok(mock_response(
                    status,
                    "# rdsys readme\n\ndistributors: moat, https\n",
                )),
                None => Err(ScraperError::Http {
                    url: url.to_string(),
                    message: "mock retry transport failure".to_string(),
                }),
            }
        }
        fn head(&self, url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            match self.head {
                Some(status) => Ok(mock_response(status, "")),
                None => Err(ScraperError::Http {
                    url: url.to_string(),
                    message: "mock HEAD transport failure".to_string(),
                }),
            }
        }
    }

    #[test]
    fn docs_audit_experiment_records_all_attempts_on_persistent_403() {
        let mock = DocsAuditMock {
            get: Some(403),
            retry: Some(403),
            head: Some(403),
        };
        let entries = audit_canonical_docs(&mock);
        assert_eq!(entries.len(), DOC_AUDIT_TARGETS.len());
        for entry in &entries {
            // Pre-existing failure shape is preserved …
            assert_eq!(entry.get("status").and_then(Value::as_u64), Some(403));
            assert_eq!(entry.get("error").and_then(Value::as_str), Some("non-2xx"));
            // … and the additive attempts array documents the experiment.
            let attempts = entry.get("attempts").and_then(Value::as_array).unwrap();
            assert_eq!(attempts.len(), 3);
            assert_eq!(
                attempts[0].get("method").and_then(Value::as_str),
                Some("GET")
            );
            assert_eq!(attempts[0].get("status").and_then(Value::as_u64), Some(403));
            assert_eq!(
                attempts[1].get("method").and_then(Value::as_str),
                Some("GET+browser-headers")
            );
            assert_eq!(attempts[1].get("status").and_then(Value::as_u64), Some(403));
            assert_eq!(
                attempts[2].get("method").and_then(Value::as_str),
                Some("HEAD")
            );
            assert_eq!(attempts[2].get("status").and_then(Value::as_u64), Some(403));
        }
    }

    #[test]
    fn docs_audit_resolves_via_browser_headers_retry() {
        let mock = DocsAuditMock {
            get: Some(403),
            retry: Some(200),
            head: Some(403),
        };
        let entries = audit_canonical_docs(&mock);
        for entry in &entries {
            assert_eq!(entry.get("status").and_then(Value::as_u64), Some(200));
            assert_eq!(
                entry.get("resolved_by").and_then(Value::as_str),
                Some("browser-headers-retry")
            );
            assert!(entry.get("error").is_none());
            let tokens = entry
                .get("mechanism_tokens")
                .and_then(Value::as_array)
                .unwrap();
            assert!(tokens.iter().any(|t| t.as_str() == Some("moat")));
        }
    }

    #[test]
    fn docs_audit_first_attempt_success_keeps_entry_shape() {
        let mock = DocsAuditMock {
            get: Some(200),
            retry: Some(403),
            head: Some(403),
        };
        let entries = audit_canonical_docs(&mock);
        for entry in &entries {
            assert_eq!(entry.get("status").and_then(Value::as_u64), Some(200));
            assert!(entry.get("bytes").and_then(Value::as_u64).unwrap_or(0) > 0);
            assert!(entry
                .get("mechanism_tokens")
                .and_then(Value::as_array)
                .is_some());
            // No retry was needed: exactly one attempt, no resolved_by.
            assert!(entry.get("resolved_by").is_none());
            let attempts = entry.get("attempts").and_then(Value::as_array).unwrap();
            assert_eq!(attempts.len(), 1);
        }
    }

    /// Minimal client that only implements the two original trait methods,
    /// locking in the additive defaults: get_with_headers delegates to get
    /// (ignoring the extra headers) and head reports itself unsupported.
    struct DefaultsOnlyMock;

    impl HttpFetch for DefaultsOnlyMock {
        fn get(&self, _url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            Ok(mock_response(200, "ok"))
        }
        fn post_json(
            &self,
            _url: &str,
            _body: &Value,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            Err(ScraperError::Http {
                url: String::new(),
                message: "POST not supported".to_string(),
            })
        }
    }

    #[test]
    fn http_fetch_additive_defaults_delegate_and_report_head_unsupported() {
        let client = DefaultsOnlyMock;
        let resp = client
            .get_with_headers(
                "https://example.com/",
                &[("User-Agent".to_string(), "probe-test".to_string())],
                Duration::from_secs(1),
            )
            .expect("default get_with_headers delegates to get");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text, "ok");
        let err = client
            .head("https://example.com/", Duration::from_secs(1))
            .expect_err("default head reports unsupported");
        assert!(err.to_string().contains("HEAD requests are not supported"));
    }

    #[test]
    fn summarize_pt_results_groups_by_transport_and_host() {
        let results = vec![
            json!({"transport": "webtunnel", "host": "cdn-a.example", "port": 443, "success": true}),
            json!({"transport": "webtunnel", "host": "cdn-a.example", "port": 443, "success": false}),
            json!({"transport": "webtunnel", "host": "cdn-b.example", "port": 443, "success": true}),
            json!({"transport": "snowflake", "host": "sf.example", "port": 443, "success": false}),
        ];
        let summary = summarize_pt_results(&results);
        assert_eq!(summary.get("entries").and_then(Value::as_u64), Some(4));
        let wt = summary.pointer("/by_transport/webtunnel").unwrap();
        assert_eq!(wt.get("attempted").and_then(Value::as_u64), Some(3));
        assert_eq!(wt.get("success").and_then(Value::as_u64), Some(2));
        let host_a = summary.pointer("/by_host/webtunnel|cdn-a.example").unwrap();
        assert_eq!(host_a.get("attempted").and_then(Value::as_u64), Some(2));
    }

    // Regression (run 38680880616 PROBE_RELAY notice "Bridge=0/2
    // bridge=160/486"): the relay labels a `Bridge ` / `bridge `-prefixed
    // vanilla line by its first token, so the summary split vanilla into two
    // phantom buckets with misleading rates. Both case variants must fold
    // into the single `vanilla` family; canonical labels stay unchanged.
    #[test]
    fn summarize_pt_results_normalizes_bridge_prefix_labels() {
        let results = vec![
            json!({"transport": "Bridge", "host": "104.152.210.181", "port": 1105, "success": false}),
            json!({"transport": "bridge", "host": "103.17.153.46", "port": 36287, "success": true}),
            json!({"transport": "bridge", "host": "103.17.153.46", "port": 36287, "success": false}),
            json!({"transport": "WebTunnel", "host": "cdn-a.example", "port": 443, "success": true}),
        ];
        let summary = summarize_pt_results(&results);
        assert_eq!(summary.get("entries").and_then(Value::as_u64), Some(4));
        let vanilla = summary.pointer("/by_transport/vanilla").unwrap();
        assert_eq!(vanilla.get("attempted").and_then(Value::as_u64), Some(3));
        assert_eq!(vanilla.get("success").and_then(Value::as_u64), Some(1));
        // The two phantom buckets no longer exist.
        assert!(summary.pointer("/by_transport/Bridge").is_none());
        assert!(summary.pointer("/by_transport/bridge").is_none());
        // Case variants of real transports collapse onto the canonical key.
        let wt = summary.pointer("/by_transport/webtunnel").unwrap();
        assert_eq!(wt.get("attempted").and_then(Value::as_u64), Some(1));
    }

    #[test]
    fn family_counts_to_json_restricts_families() {
        let mut counts = BTreeMap::new();
        counts.insert("webtunnel".to_string(), 4usize);
        counts.insert("obfs4".to_string(), 10usize);
        let value = family_counts_to_json(&counts, &["webtunnel"]);
        assert_eq!(value.pointer("/webtunnel").and_then(Value::as_u64), Some(4));
        assert!(value.get("obfs4").is_none());
    }

    /// Edge-fallback mock: records every `POST /page` call (endpoint, token
    /// header, body) and replies with a canned relay JSON envelope.
    struct EdgePageMock {
        relay_body: String,
        relay_status: u16,
        calls: AtomicUsize,
        seen_endpoints: std::sync::Mutex<Vec<String>>,
        seen_tokens: std::sync::Mutex<Vec<String>>,
        seen_urls: std::sync::Mutex<Vec<String>>,
    }

    impl EdgePageMock {
        fn success(page_text: &str) -> Self {
            Self {
                relay_body: serde_json::json!({
                    "url": "https://bridges.torproject.org/bridges?transport=webtunnel",
                    "status": 200,
                    "bytes": page_text.len(),
                    "truncated": false,
                    "text": page_text,
                })
                .to_string(),
                relay_status: 200,
                calls: AtomicUsize::new(0),
                seen_endpoints: std::sync::Mutex::new(Vec::new()),
                seen_tokens: std::sync::Mutex::new(Vec::new()),
                seen_urls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpFetch for EdgePageMock {
        fn get(&self, _url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            Err(ScraperError::Http {
                url: String::new(),
                message: "GET not used by the edge fallback".to_string(),
            })
        }

        fn post_json(
            &self,
            url: &str,
            body: &Value,
            headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen_endpoints.lock().unwrap().push(url.to_string());
            self.seen_tokens.lock().unwrap().extend(
                headers
                    .iter()
                    .filter(|(name, _)| name == "X-Probe-Token")
                    .map(|(_, value)| value.clone()),
            );
            self.seen_urls.lock().unwrap().push(
                body.get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            );
            Ok(mock_response(self.relay_status, &self.relay_body))
        }

        fn get_with_headers(
            &self,
            _url: &str,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, ScraperError> {
            Err(ScraperError::Http {
                url: String::new(),
                message: "GET not used by the edge fallback".to_string(),
            })
        }
    }

    #[test]
    fn bridgedb_page_variant_distinguishes_real_page_from_interstitial() {
        assert_eq!(
            bridgedb_page_variant(r#"<div id="bridgelines">lines</div>"#),
            "bridgelines_div_present"
        );
        assert_eq!(
            bridgedb_page_variant("<html><body>rate limit interstitial</body></html>"),
            "no_bridgelines_div"
        );
        assert_eq!(bridgedb_page_variant("   \n\t"), "empty_body");
    }

    #[test]
    fn edge_fetch_posts_to_page_endpoint_with_token_and_parses_lines() {
        let page_text = r#"<div id="bridgelines">
webtunnel url=https://front-cdn.example.com/Cn4J4GAUglhVcUKeMEkQJt7L abcdef0123456789
</div>"#;
        let mock = EdgePageMock::success(page_text);
        let group = fetch_webtunnel_html_via_edge(
            &mock,
            "https://relay.example/private-path/",
            "edge-secret-value-0123456789",
            1,
        );
        assert_eq!(group.source, SOURCE_WEBTUNNEL_HTML_EDGE);
        assert_eq!(group.requests, 2);
        assert_eq!(group.responses_ok, 2);
        assert_eq!(group.lines.len(), 2);
        let endpoints = mock.seen_endpoints.lock().unwrap();
        assert!(
            endpoints
                .iter()
                .all(|endpoint| endpoint == "https://relay.example/private-path/page"),
            "edge fetch must hit POST /page on the relay base URL: {endpoints:?}"
        );
        let tokens = mock.seen_tokens.lock().unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens
            .iter()
            .all(|token| token == "edge-secret-value-0123456789"));
        let urls = mock.seen_urls.lock().unwrap();
        assert_eq!(urls[0], WEBTUNNEL_HTML_TARGETS[0].0);
        assert_eq!(urls[1], WEBTUNNEL_HTML_TARGETS[1].0);
        assert!(group
            .lines
            .iter()
            .all(|(_, transport, _)| transport == "webtunnel"));
    }

    #[test]
    fn edge_fetch_skips_non_200_relay_envelopes_without_fabricating_lines() {
        let mut mock = EdgePageMock::success("<div id=\"bridgelines\">x</div>");
        mock.relay_status = 502;
        mock.relay_body = "{\"error\":\"page_fetch_failed\"}".to_string();
        let group = fetch_webtunnel_html_via_edge(
            &mock,
            "https://relay.example",
            "edge-secret-value-0123456789",
            1,
        );
        assert_eq!(group.requests, 2);
        assert_eq!(group.responses_ok, 0);
        assert!(group.lines.is_empty());
    }

    #[test]
    fn edge_fetch_ignores_interstitial_pages_served_through_the_relay() {
        let mock = EdgePageMock::success("<html><body>consent page</body></html>");
        let group = fetch_webtunnel_html_via_edge(
            &mock,
            "https://relay.example",
            "edge-secret-value-0123456789",
            1,
        );
        assert_eq!(group.requests, 2);
        assert_eq!(group.responses_ok, 2);
        assert!(
            group.lines.is_empty(),
            "an interstitial page must not yield fabricated lines"
        );
    }

    #[test]
    fn edge_fetch_config_requires_https_endpoint_and_long_token() {
        // Absent env -> None (the fallback silently stays off).
        // (Cannot unset parent env in-process reliably; probe the validator
        // logic through deliberately invalid values instead.)
        let invalid = EdgeFetchConfig::from_env_struct("http://relay.example", "short");
        assert!(invalid.is_none());
        let query_injected = EdgeFetchConfig::from_env_struct(
            "https://relay.example/path?steal=1",
            "edge-secret-value-0123456789",
        );
        assert!(query_injected.is_none());
        let control_char = EdgeFetchConfig::from_env_struct(
            "https://relay.example/path",
            "edge-secret-value-0123456789\ninjected",
        );
        assert!(control_char.is_none());
        let valid = EdgeFetchConfig::from_env_struct(
            "https://relay.example/private-path",
            "edge-secret-value-0123456789",
        );
        assert!(valid.is_some());
    }
}
