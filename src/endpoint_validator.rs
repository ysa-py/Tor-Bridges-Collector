//! Parity port of `core/endpoint_validator.py`.
//!
//! Validates Cloudflare AI Gateway slot URLs, auto-detects `/compat/` vs.
//! `/workers-ai/` suffix (the latter causes real HTTP 400s), builds a
//! corrected URL, and probes reachability with a lightweight HEAD request.
//!
//! ## Fully synchronous — no `tokio` here, unlike `censorship_monitor.rs`
//!
//! `core/endpoint_validator.py` has no `asyncio` import at all (confirmed
//! by grepping the source) — every probe is one sequential
//! `urllib.request` call. An earlier session summary assumed this module
//! would reuse `censorship_monitor.rs`'s `tokio` pattern directly; reading
//! the actual source first showed that assumption was wrong before any
//! code was written. This port uses `reqwest::blocking::Client` instead,
//! matching the pattern `scraper.rs` already established for exactly this
//! kind of single-request-at-a-time HTTP call, and staying genuinely
//! synchronous end to end like the Python original.
//!
//! ## Fixed, in the course of building this: the `network` Cargo feature
//! had never actually been successfully compiled in this environment
//!
//! Getting `cargo build --features network` to succeed at all (needed to
//! use `reqwest` for the probe) surfaced a chain of pre-existing issues,
//! none introduced by this module:
//! - `idna_adapter` (pinned in Session 5 to `1.2.1`, the ICU4X backend
//!   stream) and its transitive `icu4x`-family dependencies had drifted
//!   to versions requiring rustc 1.81-1.86; this sandbox's rustc is
//!   pinned to 1.75.0 with no upgrade path available (only rustc 1.75.0
//!   is offered via `apt`; `rustup`'s distribution domain isn't in this
//!   environment's network allowlist — confirmed, not assumed). Repinned
//!   `idna_adapter` to `1.2.0`, which resolves against the older, lower-MSRV
//!   `icu4x` 1.5.x generation rather than 2.x — still the ICU4X backend
//!   (full Unicode/IDNA correctness), not the lower-fidelity `1.1.x`
//!   (unicode-rs) or `1.0.x` (stub, no real IDNA processing — confirmed
//!   `1.2.0`/`1.2.1` are not that) streams.
//! - `hyper-rustls` had drifted similarly; repinned to `0.27.2`.
//! - `reqwest`'s Cargo.toml feature list was missing `blocking` entirely —
//!   `scraper.rs` already calls `reqwest::blocking::Client`, so this
//!   means the `network` feature had apparently never actually been
//!   built successfully in this exact dependency configuration before.
//!   Added the feature; `cargo test --workspace --features network` and
//!   `cargo clippy --workspace --all-targets --features network -- -D
//!   warnings` both now pass clean, including `scraper.rs`'s and
//!   `ooni_correlator.rs`'s own network-gated tests, which is new
//!   verification coverage, not just newly-enabled code for this module.
//!
//! Every prior session's "N/N Rust tests passing" figure implicitly
//! excluded all `#[cfg(feature = "network")]` code, since `network` isn't
//! in `default = []` and no prior verification command included
//! `--features network` explicitly. Worth knowing when reading those
//! figures, not a claim any of them were wrong for what they actually
//! tested.
//!
//! ## `validate_slot_url` is infallible here, unlike in Python
//!
//! Python's version wraps its body in `try/except Exception`, but tracing
//! every call it makes shows nothing in the "happy path" logic
//! (`_detect_endpoint_type`, `_validate_url_format`,
//! `_build_recommended_url`, `_extract_suffix`) can actually raise for a
//! genuine `str` input — `_probe_endpoint` already has its own internal
//! catch-all — and the outer `except` is only reachable if `gateway_url`
//! itself isn't a string (e.g. `None`, despite the type hint), which
//! Rust's `&str` parameter makes structurally unreachable. Same pattern
//! as `nin_survival_pack.rs`'s `all_bridges or []` guard.
//!
//! ## Results are kept in insertion order, not sorted by slot number
//!
//! `self._results` is a plain Python dict, preserving insertion order.
//! `get_validation_summary`'s `results` dict iterates in that order, which
//! in the normal call pattern (`validate_all_slots`, looping 1..=11) is
//! ascending anyway — but a caller invoking `validate_slot_url` directly
//! out of order would see Python preserve *call* order, not numeric
//! order. Modeled as `Vec<(i64, EndpointValidationResult)>` rather than
//! `BTreeMap<i64, _>` specifically to avoid repeating the exact class of
//! mistake already flagged for `history.rs`'s `BTreeMap` in an earlier
//! session (documented in `MIGRATION_STATUS.md`'s behavioral-differences
//! list) — a keyed, sorted map would silently reorder results relative
//! to Python whenever slots are validated out of sequence.
//!
//! ## `validated_at` / `probe_latency_ms` are wall-clock, not compared
//! byte-for-byte in parity tests, same handling as timestamp fields
//! elsewhere in this codebase.

use std::path::Path;
use std::time::Duration;
#[cfg(feature = "network")]
use std::time::Instant;

use serde_json::{json, Value};

/// Mirrors `EndpointType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    Compat,
    WorkersAi,
    Direct,
    Unknown,
}

impl EndpointType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointType::Compat => "compat",
            EndpointType::WorkersAi => "workers-ai",
            EndpointType::Direct => "direct",
            EndpointType::Unknown => "unknown",
        }
    }
}

pub const COMPAT_SUFFIX: &str = "/compat/chat/completions";
pub const WORKERS_AI_SUFFIX: &str = "/workers-ai/v1/chat/completions";

fn gateway_url_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::RegexBuilder::new(
            r"^https://gateway\.ai\.cloudflare\.com/v1/([0-9a-f]{32})/([a-zA-Z0-9_-]+)",
        )
        .case_insensitive(true)
        .build()
        .unwrap()
    })
}

fn direct_url_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::RegexBuilder::new(
            r"^https://api\.cloudflare\.com/client/v4/accounts/([0-9a-f]{32})/ai",
        )
        .case_insensitive(true)
        .build()
        .unwrap()
    })
}

/// Mirrors `EndpointValidationResult`.
#[derive(Debug, Clone)]
pub struct EndpointValidationResult {
    pub slot_index: i64,
    pub url: String,
    pub endpoint_type: EndpointType,
    pub is_valid: bool,
    pub is_reachable: bool,
    pub detected_suffix: String,
    pub recommended_url: String,
    pub error_message: String,
    pub probe_latency_ms: f64,
    pub validated_at: f64,
}

impl EndpointValidationResult {
    pub fn to_json(&self) -> Value {
        json!({
            "slot_index": self.slot_index,
            "url": self.url,
            "endpoint_type": self.endpoint_type.as_str(),
            "is_valid": self.is_valid,
            "is_reachable": self.is_reachable,
            "detected_suffix": self.detected_suffix,
            "recommended_url": self.recommended_url,
            "error_message": self.error_message,
            "probe_latency_ms": self.probe_latency_ms,
        })
    }
}

/// Mirrors Python's `s[-n:]` — the last `n` Unicode codepoints (or the
/// whole string, if shorter), not the last `n` bytes.
fn python_str_suffix(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let start = chars.len().saturating_sub(n);
    chars[start..].iter().collect()
}

/// Mirror of Python's `round(x, 1)` (banker's rounding), same pattern as
/// `smart_iran_scorer.rs`/`censorship_monitor.rs`.
fn python_round_1(x: f64) -> f64 {
    format!("{x:.1}").parse::<f64>().unwrap_or(x)
}

fn unix_time_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Mirrors `_detect_endpoint_type`.
fn detect_endpoint_type(url: &str) -> EndpointType {
    let url_lower = url.to_lowercase();
    if url_lower.contains("gateway.ai.cloudflare.com") {
        if url_lower.contains("/compat/") {
            EndpointType::Compat
        } else if url_lower.contains("/workers-ai/") {
            EndpointType::WorkersAi
        } else {
            // Bare gateway URL, normalized later — defaults to Compat,
            // not Unknown, matching Python exactly.
            EndpointType::Compat
        }
    } else if url_lower.contains("api.cloudflare.com") {
        EndpointType::Direct
    } else {
        EndpointType::Unknown
    }
}

/// Mirrors `_validate_url_format`.
fn validate_url_format(url: &str, endpoint_type: EndpointType) -> (bool, String) {
    if !url.starts_with("https://") {
        return (false, "URL must start with https://".to_string());
    }
    match endpoint_type {
        EndpointType::Compat | EndpointType::WorkersAi => {
            // Mirrors url.split("/compat/")[0].split("/workers-ai/")[0] —
            // strip whichever suffix marker is present (str::split on an
            // absent separator returns the whole string unchanged, so
            // this is safe regardless of which markers appear).
            let base = url.split("/compat/").next().unwrap_or(url);
            let base = base.split("/workers-ai/").next().unwrap_or(base);
            if gateway_url_re().is_match(base) {
                (true, String::new())
            } else {
                (
                    false,
                    "Gateway URL doesn't match CF AI Gateway pattern".to_string(),
                )
            }
        }
        EndpointType::Direct => {
            if direct_url_re().is_match(url) {
                (true, String::new())
            } else {
                (
                    false,
                    "Direct URL doesn't match CF Workers AI pattern".to_string(),
                )
            }
        }
        EndpointType::Unknown => (true, String::new()),
    }
}

/// Mirrors `_build_recommended_url`.
fn build_recommended_url(url: &str, endpoint_type: EndpointType) -> String {
    match endpoint_type {
        EndpointType::Direct | EndpointType::Compat => url.to_string(),
        EndpointType::WorkersAi => {
            let base = url.split("/workers-ai").next().unwrap_or(url);
            format!("{base}{COMPAT_SUFFIX}")
        }
        EndpointType::Unknown => {
            if url.contains("gateway.ai.cloudflare.com") {
                if let Some(caps) = gateway_url_re().captures(url) {
                    let account_id = &caps[1];
                    let slug = &caps[2];
                    return format!(
                        "https://gateway.ai.cloudflare.com/v1/{account_id}/{slug}{COMPAT_SUFFIX}"
                    );
                }
            }
            url.to_string()
        }
    }
}

/// Mirrors `_extract_suffix`.
fn extract_suffix(url: &str) -> String {
    if url.contains("/compat/chat/completions") {
        return "/compat/chat/completions".to_string();
    }
    if url.contains("/workers-ai/v1/chat/completions") {
        return "/workers-ai/v1/chat/completions".to_string();
    }
    if let Some(idx) = url.find("/workers-ai") {
        return url[idx..].to_string();
    }
    "<bare>".to_string()
}

/// Mirrors `_probe_endpoint`. Only available with the `network` feature —
/// see module doc comment. Uses `reqwest::blocking`, matching Python's
/// fully-synchronous original and `scraper.rs`'s established pattern for
/// this kind of single HTTP call.
#[cfg(feature = "network")]
pub fn probe_endpoint(url: &str, api_token: &str, timeout: Duration) -> (bool, f64) {
    let probe_url = url.replace("/chat/completions", "");
    let probe_url = probe_url.trim_end_matches('/');

    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(_) => return (false, 0.0),
    };

    let mut req = client
        .request(reqwest::Method::HEAD, probe_url)
        .header("User-Agent", "TorShield-EndpointValidator/1.0");
    if !api_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {api_token}"));
    }

    let t0 = Instant::now();
    match req.send() {
        // Any response at all — including HTTP error status codes —
        // means the endpoint is reachable, matching Python's explicit
        // "any HTTP response means reachable" comment: reqwest's
        // blocking client doesn't raise on 4xx/5xx by default (unlike
        // Python's urlopen, which raises HTTPError for those), so there
        // is no separate "Ok but error status" branch to distinguish —
        // both land here as Ok(response).
        Ok(_response) => (true, t0.elapsed().as_secs_f64() * 1000.0),
        Err(_) => (false, t0.elapsed().as_secs_f64() * 1000.0),
    }
}

/// Validates and auto-detects CF AI Gateway endpoint formats.
///
/// Mirrors `EndpointValidator`. See module doc comment for why this is
/// infallible (no `Result`) and why results preserve insertion order.
pub struct EndpointValidator {
    results: Vec<(i64, EndpointValidationResult)>,
    enabled: bool,
    probe_timeout: Duration,
}

impl Default for EndpointValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointValidator {
    #[must_use]
    pub fn new() -> Self {
        let enabled = std::env::var("ENABLE_ENDPOINT_VALIDATION")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true); // mirrors os.getenv(..., "true")
        Self {
            results: Vec::new(),
            enabled,
            probe_timeout: Duration::from_secs(8),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn results(&self) -> &[(i64, EndpointValidationResult)] {
        &self.results
    }

    /// Mirrors `validate_slot_url`. `account_id` is accepted for
    /// signature fidelity with the Python original but — confirmed by
    /// reading the full method body, not assumed — is never actually
    /// referenced anywhere inside it; this port doesn't use it for
    /// anything either, matching Python's own behavior exactly (an
    /// initial draft of this port omitted the parameter entirely before
    /// re-reading the source turned up the mismatch with
    /// `validate_all_slots`'s call site).
    ///
    /// When the `network` feature isn't enabled, reachability is
    /// reported as `false` with latency `0.0` rather than performing a
    /// probe — there is no meaningful non-network fallback for "is this
    /// endpoint reachable", so this isn't attempting to approximate
    /// Python's behavior, just avoiding a hard compile error when the
    /// feature is off.
    pub fn validate_slot_url(
        &mut self,
        slot_index: i64,
        gateway_url: &str,
        account_id: &str,
        api_token: &str,
    ) -> EndpointValidationResult {
        let _ = account_id; // see doc comment: genuinely unused in Python too
        if !self.enabled {
            let result = EndpointValidationResult {
                slot_index,
                url: gateway_url.to_string(),
                endpoint_type: EndpointType::Unknown,
                is_valid: true,
                is_reachable: true,
                detected_suffix: "validation_disabled".to_string(),
                recommended_url: String::new(),
                error_message: String::new(),
                probe_latency_ms: 0.0,
                validated_at: unix_time_now(),
            };
            return result;
        }

        let url = gateway_url.trim_end_matches('/');
        let endpoint_type = detect_endpoint_type(url);
        let (is_valid, format_error) = validate_url_format(url, endpoint_type);
        let recommended_url = build_recommended_url(url, endpoint_type);

        let probe_target = if recommended_url.is_empty() {
            url
        } else {
            &recommended_url
        };
        #[cfg(all(feature = "network", not(test)))]
        let (is_reachable, probe_latency) =
            probe_endpoint(probe_target, api_token, self.probe_timeout);
        #[cfg(any(not(feature = "network"), test))]
        let (is_reachable, probe_latency): (bool, f64) = {
            let _ = (probe_target, api_token, self.probe_timeout);
            (false, 0.0)
        };

        let result = EndpointValidationResult {
            slot_index,
            url: url.to_string(),
            endpoint_type,
            is_valid,
            is_reachable,
            detected_suffix: extract_suffix(url),
            recommended_url,
            error_message: format_error,
            probe_latency_ms: probe_latency,
            validated_at: unix_time_now(),
        };

        if let Some(existing) = self.results.iter_mut().find(|(k, _)| *k == slot_index) {
            existing.1 = result.clone();
        } else {
            self.results.push((slot_index, result.clone()));
        }

        result
    }

    /// Mirrors `validate_all_slots`. Reads `CF_AI_GATEWAY_URL_{1..11}` /
    /// `CF_ACCOUNT_ID_{1..11}` / `CF_API_TOKEN_{1..11}` from the process
    /// environment.
    pub fn validate_all_slots(&mut self) -> &[(i64, EndpointValidationResult)] {
        for i in 1..=11i64 {
            let gateway_url = std::env::var(format!("CF_AI_GATEWAY_URL_{i}")).unwrap_or_default();
            let gateway_url = gateway_url.trim();
            let account_id = std::env::var(format!("CF_ACCOUNT_ID_{i}")).unwrap_or_default();
            let account_id = account_id.trim();
            let api_token = std::env::var(format!("CF_API_TOKEN_{i}")).unwrap_or_default();
            let api_token = api_token.trim();
            if !gateway_url.is_empty() {
                self.validate_slot_url(i, gateway_url, account_id, api_token);
            }
        }
        &self.results
    }

    /// Mirrors `get_recommended_url`.
    pub fn get_recommended_url(&self, slot_index: i64) -> Option<&str> {
        self.results
            .iter()
            .find(|(k, _)| *k == slot_index)
            .map(|(_, r)| r.recommended_url.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Mirrors `get_validation_summary`.
    pub fn get_validation_summary(&self) -> Value {
        let total = self.results.len();
        let valid = self.results.iter().filter(|(_, r)| r.is_valid).count();
        let reachable = self.results.iter().filter(|(_, r)| r.is_reachable).count();
        let workers_ai_bug = self
            .results
            .iter()
            .filter(|(_, r)| r.endpoint_type == EndpointType::WorkersAi)
            .count();

        let mut results_obj = serde_json::Map::new();
        for (i, r) in &self.results {
            results_obj.insert(
                i.to_string(),
                json!({
                    "slot": r.slot_index,
                    "type": r.endpoint_type.as_str(),
                    "valid": r.is_valid,
                    "reachable": r.is_reachable,
                    "suffix": r.detected_suffix,
                    "recommended": if r.recommended_url.is_empty() { String::new() } else { python_str_suffix(&r.recommended_url, 50) },
                    "latency_ms": python_round_1(r.probe_latency_ms),
                }),
            );
        }

        json!({
            "total_slots_validated": total,
            "valid_urls": valid,
            "reachable_endpoints": reachable,
            "workers_ai_bug_detected": workers_ai_bug,
            "fix_applied": workers_ai_bug > 0,
            "results": Value::Object(results_obj),
        })
    }
}

#[allow(dead_code)]
fn unused_path_anchor(p: &Path) -> bool {
    p.exists()
}

/// Mirrors the module-level `_validator_instance` global + `get_validator()`.
/// Confirmed via grep to be a real, exercised dependency — not just an
/// unused convenience wrapper — of two not-yet-ported modules
/// (`reports/report_generator.py`, `recovery/self_healing_engine.py`,
/// both call `get_validator()` specifically to share one accumulated
/// `EndpointValidator` instance across callers) plus `core/__init__.py`'s
/// public re-export. `std::sync::OnceLock<Mutex<_>>` is the standard
/// Rust equivalent of Python's lazily-initialized module global.
static VALIDATOR_SINGLETON: std::sync::OnceLock<std::sync::Mutex<EndpointValidator>> =
    std::sync::OnceLock::new();

pub fn get_validator() -> &'static std::sync::Mutex<EndpointValidator> {
    VALIDATOR_SINGLETON.get_or_init(|| std::sync::Mutex::new(EndpointValidator::new()))
}

/// Mirrors the module-level `validate_slot` convenience function.
pub fn validate_slot(
    slot_index: i64,
    url: &str,
    account_id: &str,
    token: &str,
) -> EndpointValidationResult {
    get_validator()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .validate_slot_url(slot_index, url, account_id, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_endpoint_type_variants() {
        assert_eq!(
            detect_endpoint_type(
                "https://gateway.ai.cloudflare.com/v1/abc/slug/compat/chat/completions"
            ),
            EndpointType::Compat
        );
        assert_eq!(
            detect_endpoint_type(
                "https://gateway.ai.cloudflare.com/v1/abc/slug/workers-ai/v1/chat/completions"
            ),
            EndpointType::WorkersAi
        );
        assert_eq!(
            detect_endpoint_type("https://gateway.ai.cloudflare.com/v1/abc/slug"),
            EndpointType::Compat
        );
        assert_eq!(
            detect_endpoint_type("https://api.cloudflare.com/client/v4/accounts/abc/ai"),
            EndpointType::Direct
        );
        assert_eq!(
            detect_endpoint_type("https://example.com/foo"),
            EndpointType::Unknown
        );
    }

    #[test]
    fn build_recommended_url_fixes_workers_ai_suffix() {
        let url = "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug/workers-ai/v1/chat/completions";
        let rec = build_recommended_url(url, EndpointType::WorkersAi);
        assert_eq!(
            rec,
            "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug/compat/chat/completions"
        );
    }

    #[test]
    fn build_recommended_url_compat_unchanged() {
        let url = "https://gateway.ai.cloudflare.com/v1/abc/slug/compat/chat/completions";
        assert_eq!(build_recommended_url(url, EndpointType::Compat), url);
    }

    #[test]
    fn extract_suffix_priority_order() {
        assert_eq!(
            extract_suffix("foo/compat/chat/completions"),
            "/compat/chat/completions"
        );
        assert_eq!(
            extract_suffix("foo/workers-ai/v1/chat/completions"),
            "/workers-ai/v1/chat/completions"
        );
        assert_eq!(extract_suffix("foo/workers-ai/other"), "/workers-ai/other");
        assert_eq!(extract_suffix("https://example.com/bare"), "<bare>");
    }

    #[test]
    fn python_str_suffix_matches_negative_slice_semantics() {
        assert_eq!(python_str_suffix("hello world", 5), "world");
        assert_eq!(python_str_suffix("hi", 5), "hi");
        assert_eq!(python_str_suffix("", 5), "");
    }

    fn validator_with_enabled(enabled: bool) -> EndpointValidator {
        EndpointValidator {
            results: Vec::new(),
            enabled,
            probe_timeout: Duration::from_secs(8),
        }
    }

    #[test]
    fn validate_slot_url_disabled_short_circuits() {
        let mut v = validator_with_enabled(false);
        let r = v.validate_slot_url(1, "https://example.com", "", "");
        assert!(r.is_valid);
        assert!(r.is_reachable);
        assert_eq!(r.detected_suffix, "validation_disabled");
    }

    #[test]
    fn validate_slot_url_rejects_non_https() {
        let mut v = validator_with_enabled(true);
        let r = v.validate_slot_url(1, "http://example.com", "", "");
        assert!(!r.is_valid);
        assert_eq!(r.error_message, "URL must start with https://");
    }

    #[test]
    fn results_preserve_insertion_order_not_numeric_order() {
        let mut v = validator_with_enabled(true);
        v.validate_slot_url(
            5,
            "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai",
            "",
            "",
        );
        v.validate_slot_url(
            2,
            "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai",
            "",
            "",
        );
        let indices: Vec<i64> = v.results().iter().map(|(k, _)| *k).collect();
        assert_eq!(indices, vec![5, 2]); // call order, not sorted
    }

    #[test]
    fn get_recommended_url_none_when_unset() {
        let mut v = validator_with_enabled(true);
        v.validate_slot_url(
            1,
            "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai",
            "",
            "",
        );
        // DIRECT endpoints return the URL unchanged as "recommended", so
        // this is testing a slot that was never validated at all.
        assert_eq!(v.get_recommended_url(99), None);
    }

    #[test]
    fn get_validation_summary_counts() {
        let mut v = validator_with_enabled(true);
        v.validate_slot_url(
            1,
            "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/s/workers-ai/v1/chat/completions",
            "",
            "",
        );
        let summary = v.get_validation_summary();
        assert_eq!(summary["total_slots_validated"], json!(1));
        assert_eq!(summary["workers_ai_bug_detected"], json!(1));
        assert_eq!(summary["fix_applied"], json!(true));
    }
}
