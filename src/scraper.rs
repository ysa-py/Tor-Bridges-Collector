//! Parity port of `scraper.py`.
//!
//! TorShield-IR bridge scraper and history manager. Collects Tor bridges
//! from all available sources (bridges.torproject.org, MOAT API, static
//! built-ins), maintains a 30-day rolling history, writes categorised output
//! files, and emits `bridge_list_for_testing.json` for the Go `iran_tester`
//! binary.
//!
//! # Behavior traced to `scraper.py`
//!
//! * [`normalize_for_history`] / [`normalize_for_file`] — canonical
//!   normalisation helpers (Bug 1 fix: vanilla prefixes are idempotent).
//! * [`is_valid_line`] — line validation regex (`_VALID_LINE_RE`).
//! * [`parse_bridgelines_html`] — minimal HTML extractor mirroring
//!   BeautifulSoup's `find("div", id="bridgelines").get_text("\n")` with
//!   fallback to all `<pre>`/`<code>` text content.
//! * [`parse_moat_response`] — `_parse_moat_response` dict walker.
//! * [`fetch_torproject`] / [`fetch_moat`] — network fetchers that take an
//!   injectable [`HttpFetch`] client. The production [`ReqwestHttpFetch`]
//!   impl is gated behind the `network` Cargo feature.
//! * [`get_static`] — `_STATIC_BRIDGES` constant list.
//! * [`tcp_reachable`] / [`tcp_reachable_with_probe`] — TCP reachability
//!   probe (Bug 2 fix: never sends bytes; Bug 3 fix: labelled
//!   `tcp_reachable`, not "working"). Takes an injectable [`TcpProbe`].
//! * [`infer_transport`] / [`infer_ip_version`] — best-effort key inspectors.
//! * [`load_history`] / [`save_history`] — file I/O with injectable `&Path`.
//!   Legacy string-format entries are transparently upgraded to dict format.
//! * [`update_history_with_now`] / [`prune_history_with_now`] — in-place
//!   history mutation with injectable `now` for deterministic testing.
//! * [`write_sorted`] / [`write_bridge_files`] / [`write_testing_json`] /
//!   [`update_readme`] — file writers with injectable `&Path` arguments.
//!
//! # Side effects not ported
//!
//! * `build_zip` requires a `zip` crate which is not in the workspace
//!   dependency set. The pure decision logic (folder classification) is
//!   ported in [`classify_zip_folder`]; the actual ZIP archive write is
//!   flagged in `MIGRATION_NOTES.md`.
//! * `main()` orchestration including GitHub `asyncio` fetch is not ported
//!   as a single entry point. Callers compose the public functions above.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::adaptive_selector::AdaptiveBridgeSelector;
use crate::dt_utils;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (mirrors module-level constants in scraper.py)
// ─────────────────────────────────────────────────────────────────────────────

/// Default recent-window length in hours. Mirrors `RECENT_HOURS` env default.
pub const DEFAULT_RECENT_HOURS: i64 = 72;

/// Default history retention in days. Mirrors `RETENTION_DAYS` env default.
pub const DEFAULT_RETENTION_DAYS: i64 = 30;

/// Default bridge directory name. Mirrors `BRIDGE_DIR` env default.
pub const DEFAULT_BRIDGE_DIR: &str = "bridge";

/// Default repo URL placeholder. Mirrors `REPO_URL` env default.
pub const DEFAULT_REPO_URL: &str =
    "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main";

/// User-Agent sent on every HTTP request by the production client.
pub const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0";

/// MOAT API endpoint for the built-in bridge list.
pub const MOAT_BUILTIN_URL: &str = "https://bridges.torproject.org/moat/circumvention/builtin";

/// MOAT API endpoint for the country-specific settings.
pub const MOAT_SETTINGS_URL: &str = "https://bridges.torproject.org/moat/circumvention/settings";

/// Default TCP reachability probe timeout in seconds.
pub const DEFAULT_TCP_TIMEOUT_SECS: f64 = 6.0;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `scraper.py` parity port.
#[derive(Debug, Error)]
pub enum ScraperError {
    /// File I/O failure on a history read/write path.
    #[error("scraper I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// History file content was not a JSON object.
    #[error("scraper history root must be a JSON object, got {actual}")]
    HistoryNotObject { actual: &'static str },

    /// MOAT response body was not a JSON object.
    #[error("scraper MOAT response must be a JSON object, got {actual}")]
    MoatNotObject { actual: &'static str },

    /// Underlying HTTP client error (production `reqwest` path only).
    #[error("scraper HTTP error for {url}: {message}")]
    Http { url: String, message: String },

    /// Underlying HTTP client returned a body that was not valid UTF-8.
    #[error("scraper HTTP response for {url} was not valid UTF-8")]
    HttpNotUtf8 { url: String },

    /// JSON serialization failure.
    #[error("scraper JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Adaptive selector scoring failure.
    #[error("scraper adaptive selector error: {0}")]
    Adaptive(#[from] crate::adaptive_selector::AdaptiveSelectorError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable HTTP client trait
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal HTTP response shape used by [`HttpFetch`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404).
    pub status: u16,
    /// Response body decoded as UTF-8 text.
    pub text: String,
}

impl HttpResponse {
    /// Parse the response body as JSON, returning [`Value::Null`] on failure.
    /// Mirrors Python's `r.json()` semantics which raise on invalid JSON;
    /// callers should use [`HttpResponse::json`] when the body is expected
    /// to be valid JSON.
    pub fn json(&self) -> Result<Value, ScraperError> {
        serde_json::from_str(&self.text).map_err(ScraperError::Json)
    }
}

/// Injectable HTTP client used by [`fetch_torproject`] and [`fetch_moat`].
///
/// Production code uses [`ReqwestHttpFetch`] (gated behind the `network`
/// Cargo feature); tests substitute a mock implementation that returns
/// canned responses.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to support concurrent fetching
/// via scoped threads in `sources_torproject::fetch_all_with_client`.
pub trait HttpFetch: Send + Sync {
    /// Issue a GET request with the given timeout and return the response.
    fn get(&self, url: &str, timeout: Duration) -> Result<HttpResponse, ScraperError>;

    /// Issue a POST request with a JSON body and custom headers, returning
    /// the response. The `headers` slice is a list of `(name, value)` pairs.
    fn post_json(
        &self,
        url: &str,
        body: &Value,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, ScraperError>;
}

/// Injectable TCP reachability probe used by [`tcp_reachable_with_probe`].
///
/// Production code uses [`StdTcpProbe`]; tests substitute a mock
/// implementation that returns canned results without opening sockets.
pub trait TcpProbe {
    /// Return `true` if a TCP connection to `(host, port)` succeeds within
    /// `timeout_s` seconds. Never sends any bytes (Bug 2 fix).
    fn tcp_reachable(&self, host: &str, port: u16, timeout_s: f64) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// Module-level helpers (mirror Python constants and regexes)
// ─────────────────────────────────────────────────────────────────────────────

/// Compiled form of `_VALID_LINE_RE` from `scraper.py`.
fn valid_line_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9a-fA-F:]+\]:\d+|https?://[^\s]+)")
            .expect("valid_line_re compiles")
    })
}

/// Compiled form of `_IP4_PORT_RE` from `scraper.py`.
fn ip4_port_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})").expect("ip4_port_re compiles")
    })
}

/// Compiled form of the IPv6 bracketed-address regex used by
/// `_infer_ip_version` in `scraper.py`.
fn ipv6_bracket_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[0-9a-fA-F:]{2,39}\]").expect("ipv6_bracket_re compiles"))
}

/// Mirror of `normalize_for_history(line, transport)`.
///
/// Stores vanilla bridges WITH the `Bridge ` prefix; all other transports
/// are stored as-is (Bug 1 fix: idempotent on already-prefixed lines).
pub fn normalize_for_history(line: &str, transport: &str) -> String {
    if transport == "vanilla" {
        if line.starts_with("Bridge ") {
            line.to_string()
        } else {
            format!("Bridge {}", line)
        }
    } else {
        line.trim().to_string()
    }
}

/// Mirror of `normalize_for_file(line, transport)`.
///
/// Strips the `Bridge ` prefix for vanilla bridges written to `.txt` files.
pub fn normalize_for_file(line: &str, transport: &str) -> String {
    if transport == "vanilla" {
        if let Some(stripped) = line.strip_prefix("Bridge ") {
            stripped.trim().to_string()
        } else {
            line.trim().to_string()
        }
    } else {
        line.trim().to_string()
    }
}

/// Mirror of `is_valid_line(line)`.
///
/// Returns `true` when the line is at least 20 chars, does not contain
/// `"No bridges available"`, does not start with `#`, and matches
/// `_VALID_LINE_RE`.
pub fn is_valid_line(line: &str) -> bool {
    if line.is_empty() || line.len() < 20 {
        return false;
    }
    if line.contains("No bridges available") || line.starts_with('#') {
        return false;
    }
    valid_line_re().is_match(line)
}

/// Mirror of `_infer_transport(key)`.
pub fn infer_transport(key: &str) -> String {
    let low = key.to_lowercase();
    if low.contains("snowflake") {
        "snowflake".to_string()
    } else if low.contains("webtunnel") || low.contains("url=https") {
        "webtunnel".to_string()
    } else if low.contains("obfs4") {
        "obfs4".to_string()
    } else if low.contains("meek") {
        "meek_lite".to_string()
    } else {
        "vanilla".to_string()
    }
}

/// Mirror of `_infer_ip_version(key)`.
pub fn infer_ip_version(key: &str) -> String {
    if ipv6_bracket_re().is_match(key) {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal HTML extractor (mirrors _parse_bridgelines_html)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_parse_bridgelines_html(html)`.
///
/// Reproduces BeautifulSoup's behavior for the specific case of:
/// 1. Find the first `<div id="bridgelines">...</div>` and extract its text
///    content with tag boundaries replaced by `\n`.
/// 2. If no such div exists, find all `<pre>...</pre>` and `<code>...</code>`
///    elements and join their text content with a single space separator.
/// 3. Split the resulting text by `\n`, strip each line, and return the
///    list of lines that pass [`is_valid_line`].
///
/// The extractor is intentionally minimal — it handles the well-formed HTML
/// returned by `bridges.torproject.org` and the test fixtures used in the
/// parity tests. Malformed HTML may produce different output from
/// BeautifulSoup; such cases are flagged in `MIGRATION_NOTES.md`.
pub fn parse_bridgelines_html(html: &str) -> Vec<String> {
    let raw = extract_bridgelines_text(html);
    raw.split('\n')
        .map(|l| l.trim())
        .filter(|l| is_valid_line(l))
        .map(|l| l.to_string())
        .collect()
}

/// Extract the text content used by [`parse_bridgelines_html`].
fn extract_bridgelines_text(html: &str) -> String {
    if let Some(div_text) = find_element_text_by_id(html, "div", "bridgelines") {
        return div_text;
    }
    // Fallback: join all <pre> and <code> text content with a single space.
    let pre_texts = find_all_elements_text(html, &["pre", "code"]);
    pre_texts.join(" ")
}

/// Find the first element with `tag` name and `id` attribute equal to
/// `id_value`, returning its text content with tag boundaries replaced
/// by `\n`. Returns `None` when no such element exists.
fn find_element_text_by_id(html: &str, tag: &str, id_value: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let needle_open = format!("<{}", tag.to_lowercase());
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(rel) = find_subslice(&lower[i..], &needle_open) {
            i += rel;
            // Find end of opening tag.
            let tag_end = match lower[i..].find('>') {
                Some(p) => i + p,
                None => break,
            };
            // Parse attributes between i and tag_end.
            let attrs = &html[i + needle_open.len()..tag_end];
            if attr_has_id(attrs, id_value) {
                // Check if self-closing.
                let opening_self_closing = attrs.trim_end().ends_with('/');
                if opening_self_closing {
                    return Some(String::new());
                }
                // Find matching close tag, accounting for nested same-tag elements.
                let body_start = tag_end + 1;
                let close = find_matching_close_tag(&lower, body_start, tag.to_lowercase());
                let body_end = close.unwrap_or(lower.len());
                let body = &html[body_start..body_end];
                return Some(strip_tags_to_text(body));
            }
            i = tag_end + 1;
        } else {
            break;
        }
    }
    None
}

/// Find all elements with tag name in `tags` and return their text content
/// in document order.
fn find_all_elements_text(html: &str, tags: &[&str]) -> Vec<String> {
    let lower = html.to_lowercase();
    let lower_tags: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < lower.len() {
        let mut found = false;
        for tag in &lower_tags {
            let needle_open = format!("<{}", tag);
            if let Some(rel) = find_subslice(&lower[i..], &needle_open) {
                let abs = i + rel;
                let tag_end = match lower[abs..].find('>') {
                    Some(p) => abs + p,
                    None => {
                        i = lower.len();
                        break;
                    }
                };
                let attrs = &html[abs + needle_open.len()..tag_end];
                if attrs.trim_end().ends_with('/') {
                    results.push(String::new());
                    i = tag_end + 1;
                    found = true;
                    break;
                }
                let body_start = tag_end + 1;
                let close =
                    find_matching_close_tag(&lower, body_start, tag.clone()).unwrap_or(lower.len());
                let body = &html[body_start..close];
                results.push(strip_tags_to_text(body));
                i = close;
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
    }
    results
}

/// Return `true` when the attribute slice `attrs` contains an `id`
/// attribute equal to `id_value`. Handles single-quoted, double-quoted, and
/// unquoted attribute values, and case-insensitive attribute name matching.
fn attr_has_id(attrs: &str, id_value: &str) -> bool {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Read attribute name.
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
            && bytes[i] != b'>'
        {
            i += 1;
        }
        let name = &attrs[name_start..i];
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // Optional = value.
        let mut value = "";
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let v_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = &attrs[v_start..i];
                if i < bytes.len() {
                    i += 1; // skip closing quote
                }
            } else {
                let v_start = i;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && bytes[i] != b'>'
                    && bytes[i] != b'/'
                {
                    i += 1;
                }
                value = &attrs[v_start..i];
            }
        }
        if name.eq_ignore_ascii_case("id") && value == id_value {
            return true;
        }
    }
    false
}

/// Find the position of the closing `</tag>` that matches the next opening
/// `<tag>` at or after `start`, accounting for nested same-tag elements.
/// Returns the byte offset of the `</tag>` opening `<` character.
fn find_matching_close_tag(lower: &str, start: usize, tag: String) -> Option<usize> {
    let open = format!("<{}", tag);
    let close = format!("</{}", tag);
    let mut depth: i32 = 1;
    let mut i = start;
    while i < lower.len() {
        let next_open = find_subslice(&lower[i..], &open);
        let next_close = find_subslice(&lower[i..], &close);
        match (next_open, next_close) {
            (Some(no), Some(nc)) => {
                if no < nc {
                    // Found another opening tag at i+no. Check it's not a
                    // different tag whose name starts with the same prefix
                    // (e.g. `<div` vs `<divider`). The character at i+no+open.len()
                    // must be whitespace, `>`, `/`, or end-of-string.
                    let after = i + no + open.len();
                    let boundary_ok = after >= lower.len() || {
                        let c = lower.as_bytes()[after];
                        c.is_ascii_whitespace() || c == b'>' || c == b'/'
                    };
                    if boundary_ok {
                        depth += 1;
                    }
                    i = after;
                } else {
                    let after = i + nc + close.len();
                    // Ensure the tag name ends at a boundary.
                    let boundary_ok = after >= lower.len() || {
                        let c = lower.as_bytes()[after.min(lower.len() - 1)];
                        c.is_ascii_whitespace() || c == b'>'
                    };
                    if boundary_ok {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + nc);
                        }
                    }
                    i = after;
                }
            }
            (Some(_), None) => break,
            (None, Some(nc)) => {
                let after = i + nc + close.len();
                let boundary_ok = after >= lower.len() || {
                    let c = lower.as_bytes()[after.min(lower.len() - 1)];
                    c.is_ascii_whitespace() || c == b'>'
                };
                if boundary_ok {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + nc);
                    }
                }
                i = after;
            }
            (None, None) => break,
        }
    }
    None
}

/// Strip all HTML tags from `body`, replacing tag boundaries with `\n`.
/// HTML entities are left as-is (BeautifulSoup would decode them, but the
/// bridge-line content does not contain entities in practice).
fn strip_tags_to_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_tag = false;
    let mut last_was_tag = false;
    for c in body.chars() {
        if !in_tag && c == '<' {
            in_tag = true;
            if !last_was_tag && !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            last_was_tag = true;
        } else if in_tag && c == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(c);
            last_was_tag = false;
        }
    }
    // Collapse runs of whitespace inside a text node to match
    // BeautifulSoup's NavigableString handling. Each text node becomes a
    // single line in the output.
    out.split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Find the next occurrence of `needle` in `haystack`, returning the byte
/// offset relative to `haystack`'s start.
fn find_subslice(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Source 1 — bridges.torproject.org
// ─────────────────────────────────────────────────────────────────────────────

/// One row of `_TARGETS` from `scraper.py` (url, hint, transport, ip_version).
/// The `hint` field is preserved for parity but unused by the fetcher logic.
pub const TORPROJECT_TARGETS: &[(&str, &str, &str, &str)] = &[
    (
        "https://bridges.torproject.org/bridges?transport=obfs4",
        "obfs4",
        "obfs4",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",
        "obfs4_ipv6",
        "obfs4",
        "ipv6",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel",
        "webtunnel",
        "webtunnel",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes",
        "webtunnel_ipv6",
        "webtunnel",
        "ipv6",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=vanilla",
        "vanilla",
        "vanilla",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes",
        "vanilla_ipv6",
        "vanilla",
        "ipv6",
    ),
];

/// Mirror of `fetch_torproject(session)`.
///
/// Fetches each URL in [`TORPROJECT_TARGETS`] via the injectable
/// [`HttpFetch`] client and returns a list of `(bridge_line, transport,
/// ip_version)` tuples. Errors per-URL are logged via `tracing::warn!` and
/// skipped, mirroring the Python `except Exception` swallow.
pub fn fetch_torproject(client: &dyn HttpFetch) -> Vec<(String, String, String)> {
    let timeout = Duration::from_secs(30);
    let mut results = Vec::new();
    for (url, _hint, transport, ip_ver) in TORPROJECT_TARGETS {
        match client.get(url, timeout) {
            Ok(resp) => {
                if !(200..300).contains(&resp.status) {
                    tracing::warn!(
                        "torproject.org [{}/{}]: HTTP {}",
                        transport,
                        ip_ver,
                        resp.status
                    );
                    continue;
                }
                let lines = parse_bridgelines_html(&resp.text);
                tracing::info!(
                    "torproject.org [{}/{}]: {} bridges",
                    transport,
                    ip_ver,
                    lines.len()
                );
                for line in lines {
                    results.push((line, transport.to_string(), ip_ver.to_string()));
                }
            }
            Err(err) => {
                tracing::warn!("torproject.org [{}]: {}", transport, err);
            }
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Source 2 — MOAT API
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_MOAT_TRANSPORT_MAP`.
pub fn moat_transport_map() -> &'static [(&'static str, &'static str)] {
    &[
        ("obfs4", "obfs4"),
        ("webTunnel", "webtunnel"),
        ("WebTunnel", "webtunnel"),
        ("webtunnel", "webtunnel"),
        ("snowflake", "snowflake"),
        ("meek_lite", "meek_lite"),
    ]
}

/// Mirror of `_MOAT_HEADERS`. Returns a fresh `Vec` so callers can extend.
pub fn moat_headers() -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_string(),
            "application/vnd.api+json".to_string(),
        ),
        ("Accept".to_string(), "application/vnd.api+json".to_string()),
        (
            "User-Agent".to_string(),
            "Tor Browser/13.5 (Windows NT 10.0; rv:115.0)".to_string(),
        ),
    ]
}

/// Mirror of `_parse_moat_response(data)`.
///
/// Walks `data["bridges"]` (a dict of `transport_name -> list[str]`) and
/// returns `[(line, transport)]` for each valid line. Non-list values and
/// non-string elements are skipped.
pub fn parse_moat_response(data: &Value) -> Result<Vec<(String, String)>, ScraperError> {
    let empty_map_holder = Map::new();
    let bridges_section: &Map<String, Value> = match data.get("bridges") {
        Some(Value::Object(map)) => map,
        Some(Value::Null) | None => &empty_map_holder,
        Some(other) => {
            return Err(ScraperError::MoatNotObject {
                actual: type_name_of_value(other),
            });
        }
    };
    let mut results = Vec::new();
    for (key, bridge_list) in bridges_section {
        let transport = moat_transport_map()
            .iter()
            .find(|(k, _)| *k == key.as_str())
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(arr) = bridge_list.as_array() {
            for line in arr {
                if let Some(s) = line.as_str() {
                    if is_valid_line(s) {
                        results.push((s.trim().to_string(), transport.clone()));
                    }
                }
            }
        }
    }
    Ok(results)
}

/// Mirror of `fetch_moat(session)`.
///
/// POSTs the standard Iran payload to both MOAT endpoints and returns
/// `(bridge_line, transport, ip_version)` tuples. `ip_version` is
/// `"ipv6"` when the line contains `[`, else `"ipv4"`.
pub fn fetch_moat(client: &dyn HttpFetch) -> Vec<(String, String, String)> {
    let timeout = Duration::from_secs(30);
    let payload = json!({
        "version": "0.1.0",
        "transports": ["obfs4", "webTunnel", "snowflake"],
        "country": "ir",
    });
    let headers = moat_headers();
    let mut results = Vec::new();
    for url in [MOAT_BUILTIN_URL, MOAT_SETTINGS_URL] {
        match client.post_json(url, &payload, &headers, timeout) {
            Ok(resp) if resp.status == 200 => match resp.json() {
                Ok(data) => match parse_moat_response(&data) {
                    Ok(pairs) => {
                        let label = url.rsplit('/').next().unwrap_or(url);
                        tracing::info!("MOAT [{}]: {} bridges", label, pairs.len());
                        for (line, transport) in pairs {
                            let ip_ver = if line.contains('[') { "ipv6" } else { "ipv4" };
                            results.push((line, transport, ip_ver.to_string()));
                        }
                    }
                    Err(err) => tracing::warn!("MOAT [{}]: {}", url, err),
                },
                Err(err) => tracing::warn!("MOAT [{}]: {}", url, err),
            },
            Ok(resp) => tracing::debug!("MOAT [{}]: HTTP {}", url, resp.status),
            Err(err) => tracing::warn!("MOAT [{}]: {}", url, err),
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Source 3 — Static built-in bridges
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_STATIC_BRIDGES` in `scraper.py`. Each entry is
/// `(bridge_line, transport)`.
pub fn static_bridges() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=ftls.googlevideo.com \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 \
utls-imitate=hellorandomizedalpn",
            "snowflake",
        ),
        (
            "snowflake 192.0.2.4:1 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://snowflake-broker.torproject.net/ \
fronts=snowflake-broker.torproject.net.global.prod.fastly.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 \
utls-imitate=hellorandomizedalpn",
            "snowflake",
        ),
        (
            "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 \
url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
            "meek_lite",
        ),
        (
            "meek_lite 192.0.2.16:80 0AC9589027B0B1F3B1D1D94C63CD9E8D05CD6D77 \
url=https://a0.awsstatic.com/ front=a0.awsstatic.com",
            "meek_lite",
        ),
    ]
}

/// Mirror of `get_static()`. Returns `(line, transport, "ipv4")` tuples.
pub fn get_static() -> Vec<(&'static str, &'static str, &'static str)> {
    static_bridges()
        .iter()
        .map(|(line, transport)| (*line, *transport, "ipv4"))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP reachability probe
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `tcp_reachable(line, timeout_s=6.0)` using a default
/// [`StdTcpProbe`]. Returns `false` for non-IPv4 bridge lines.
pub fn tcp_reachable(line: &str, timeout_s: f64) -> bool {
    let probe = StdTcpProbe;
    tcp_reachable_with_probe(line, timeout_s, &probe)
}

/// Injectable variant of [`tcp_reachable`] that accepts any [`TcpProbe`].
/// Mirror of the body of `tcp_reachable`:
/// 1. Search for `(\d{1,3}(\.\d{1,3}){3}):(\d{1,5})`.
/// 2. If no match, return `false` (non-IPv4 bridges are skipped).
/// 3. Otherwise, attempt a TCP connect with the given timeout.
pub fn tcp_reachable_with_probe(line: &str, timeout_s: f64, probe: &dyn TcpProbe) -> bool {
    let caps = match ip4_port_re().captures(line) {
        Some(c) => c,
        None => return false,
    };
    let host = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let port_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    probe.tcp_reachable(host, port, timeout_s)
}

/// Production [`TcpProbe`] impl using `std::net::TcpStream::connect_timeout`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdTcpProbe;

impl TcpProbe for StdTcpProbe {
    fn tcp_reachable(&self, host: &str, port: u16, timeout_s: f64) -> bool {
        let addr = format!("{}:{}", host, port);
        let dur = if timeout_s.is_finite() && timeout_s > 0.0 {
            Duration::from_secs_f64(timeout_s)
        } else {
            Duration::from_secs(DEFAULT_TCP_TIMEOUT_SECS as u64)
        };
        std::net::TcpStream::connect_timeout(
            &match addr.parse() {
                Ok(sock_addr) => sock_addr,
                Err(_) => return false,
            },
            dur,
        )
        .is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// History management
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `load_history()` with injectable `&Path`.
///
/// Reads `path` as UTF-8 JSON. Legacy string-valued entries are transparently
/// upgraded to dict format using [`infer_transport`] and [`infer_ip_version`].
/// Returns an empty JSON object when the file does not exist; on parse
/// failure, returns [`ScraperError::Json`].
pub fn load_history(path: &Path) -> Result<Value, ScraperError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(err) => {
            return Err(ScraperError::Io {
                path: path.display().to_string(),
                source: err,
            });
        }
    };
    let raw: Value = serde_json::from_str(&text).map_err(ScraperError::Json)?;
    let raw_map = match raw.as_object() {
        Some(m) => m,
        None => {
            return Err(ScraperError::HistoryNotObject {
                actual: type_name_of_value(&raw),
            });
        }
    };
    let mut normalised = Map::new();
    for (k, v) in raw_map {
        match v {
            Value::String(s) => {
                // Legacy / onionhop format — v is an ISO timestamp string.
                normalised.insert(
                    k.clone(),
                    json!({
                        "raw":           k,
                        "transport":     infer_transport(k),
                        "ip_version":    infer_ip_version(k),
                        "first_seen":    s,
                        "last_seen":     s,
                        "tcp_reachable": Value::Null,
                    }),
                );
            }
            Value::Object(_) => {
                normalised.insert(k.clone(), v.clone());
            }
            // Skip any unexpected types silently.
            _ => {}
        }
    }
    Ok(Value::Object(normalised))
}

/// Mirror of `save_history(history)` with injectable `&Path`.
///
/// Writes the history as pretty-printed JSON with `ensure_ascii=False`.
/// Uses 2-space indentation to match Python's `json.dumps(indent=2)`.
pub fn save_history(history: &Value, path: &Path) -> Result<(), ScraperError> {
    let serialized = serde_json::to_string_pretty(history)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ScraperError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, serialized).map_err(|source| ScraperError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Mirror of `update_history(history, lines)` with injectable `now`.
///
/// For each `(raw_line, transport, ip_version)` tuple, computes the history
/// key via [`normalize_for_history`] and either inserts a fresh entry or
/// updates `last_seen` on the existing entry. Mirrors the Python behavior
/// of NOT touching `raw` in `update_history` (the `main()` function
/// attaches `raw` separately; see [`merge_raw_into_history`]).
pub fn update_history_with_now(
    history: &mut Value,
    lines: &[(String, String, String)],
    now: DateTime<Utc>,
) -> Result<(), ScraperError> {
    let actual = type_name_of_value(history);
    let map = history
        .as_object_mut()
        .ok_or(ScraperError::HistoryNotObject { actual })?;
    let now_iso = now.to_rfc3339();
    for (raw_line, transport, ip_version) in lines {
        let key = normalize_for_history(raw_line, transport);
        if !map.contains_key(&key) {
            map.insert(
                key,
                json!({
                    "transport":     transport,
                    "ip_version":    ip_version,
                    "first_seen":    now_iso,
                    "last_seen":     now_iso,
                    "tcp_reachable": Value::Null,
                }),
            );
        } else {
            let entry = map.get_mut(&key).expect("present");
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("last_seen".to_string(), Value::String(now_iso.clone()));
            }
        }
    }
    Ok(())
}

/// Production wrapper around [`update_history_with_now`] using `Utc::now()`.
pub fn update_history(
    history: &mut Value,
    lines: &[(String, String, String)],
) -> Result<(), ScraperError> {
    update_history_with_now(history, lines, Utc::now())
}

/// Mirror of the `main()` raw-attach loop with injectable `now`.
///
/// For each `(raw_line, transport, ip_version)` tuple:
/// - Computes the history key via [`normalize_for_history`].
/// - Inserts a fresh entry (with `raw` field) when the key is new.
/// - If the existing entry is not a dict, replaces it with a fresh dict.
/// - Otherwise updates `last_seen` and `raw` on the existing entry.
pub fn merge_raw_into_history_with_now(
    history: &mut Value,
    lines: &[(String, String, String)],
    now: DateTime<Utc>,
) -> Result<(), ScraperError> {
    let actual = type_name_of_value(history);
    let map = history
        .as_object_mut()
        .ok_or(ScraperError::HistoryNotObject { actual })?;
    let now_iso = now.to_rfc3339();
    for (raw_line, transport, ip_version) in lines {
        let key = normalize_for_history(raw_line, transport);
        let raw_stripped = raw_line.trim();
        let needs_insert = match map.get(&key) {
            None => true,
            Some(Value::Object(_)) => false,
            Some(_) => true,
        };
        if needs_insert {
            map.insert(
                key,
                json!({
                    "raw":           raw_stripped,
                    "transport":     transport,
                    "ip_version":    ip_version,
                    "first_seen":    now_iso,
                    "last_seen":     now_iso,
                    "tcp_reachable": Value::Null,
                }),
            );
        } else {
            let entry = map.get_mut(&key).expect("present");
            let actual = type_name_of_value(entry);
            let obj = entry
                .as_object_mut()
                .ok_or(ScraperError::HistoryNotObject { actual })?;
            obj.insert("last_seen".to_string(), Value::String(now_iso.clone()));
            obj.insert("raw".to_string(), Value::String(raw_stripped.to_string()));
        }
    }
    Ok(())
}

/// Production wrapper around [`merge_raw_into_history_with_now`] using
/// `Utc::now()`.
pub fn merge_raw_into_history(
    history: &mut Value,
    lines: &[(String, String, String)],
) -> Result<(), ScraperError> {
    merge_raw_into_history_with_now(history, lines, Utc::now())
}

/// Mirror of `prune_history(history)` with injectable `now` and
/// `retention_days`.
///
/// Removes any entry whose `last_seen` parses (via [`dt_utils::parse_dt`])
/// to a UTC datetime older than `now - retention_days`. Missing `last_seen`
/// defaults to `"2000-01-01T00:00:00+00:00"`. Returns the number of
/// entries removed.
pub fn prune_history_with_now(
    history: &mut Value,
    retention_days: i64,
    now: DateTime<Utc>,
) -> Result<usize, ScraperError> {
    let cutoff = now - ChronoDuration::days(retention_days);
    let actual = type_name_of_value(history);
    let map = history
        .as_object_mut()
        .ok_or(ScraperError::HistoryNotObject { actual })?;
    let to_delete: Vec<String> = map
        .iter()
        .filter_map(|(k, v)| {
            let last_seen = v
                .get("last_seen")
                .and_then(Value::as_str)
                .unwrap_or("2000-01-01T00:00:00+00:00");
            let parsed = dt_utils::parse_dt(last_seen);
            if parsed < cutoff {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    let removed = to_delete.len();
    for k in to_delete {
        map.remove(&k);
    }
    if removed > 0 {
        tracing::info!(
            "Pruned {} entries older than {} days.",
            removed,
            retention_days
        );
    }
    Ok(removed)
}

/// Production wrapper around [`prune_history_with_now`] using `Utc::now()`
/// and [`DEFAULT_RETENTION_DAYS`].
pub fn prune_history(history: &mut Value) -> Result<usize, ScraperError> {
    prune_history_with_now(history, DEFAULT_RETENTION_DAYS, Utc::now())
}

// ─────────────────────────────────────────────────────────────────────────────
// File writers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_write_sorted(path, lines, preserve_order=False)`.
///
/// When `preserve_order` is `false`, lines are deduplicated, sorted, and
/// filtered for non-empty content. When `preserve_order` is `true`, lines
/// are deduplicated while preserving first-occurrence order, and empty
/// lines are dropped.
///
/// The output file is written as `\n`-joined lines with a trailing newline
/// when at least one line is present, mirroring the Python
/// `"\n".join(clean) + ("\n" if clean else "")` behavior.
pub fn write_sorted(
    path: &Path,
    lines: &[String],
    preserve_order: bool,
) -> Result<(), ScraperError> {
    let clean: Vec<String> = if preserve_order {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for line in lines {
            if !line.trim().is_empty() && seen.insert(line.clone()) {
                out.push(line.clone());
            }
        }
        out
    } else {
        let mut set: BTreeSet<String> = BTreeSet::new();
        for line in lines {
            if !line.trim().is_empty() {
                set.insert(line.clone());
            }
        }
        set.into_iter().collect()
    };
    let mut content = clean.join("\n");
    if !clean.is_empty() {
        content.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ScraperError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, content).map_err(|source| ScraperError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Mirror of `write_bridge_files(history)` with injectable `bridge_dir`,
/// `recent_hours`, and [`AdaptiveBridgeSelector`].
///
/// For each transport in `["obfs4", "webtunnel", "vanilla", "snowflake",
/// "meek_lite"]`, partitions the history by `ip_version` and recency, then
/// writes four files: `{transport}.txt`, `{transport}_ipv6.txt`,
/// `{transport}_{recent_hours}h.txt`, `{transport}_{recent_hours}h_ipv6.txt`.
///
/// Returns a stats dict mapping file name to bridge count.
pub fn write_bridge_files(
    history: &Value,
    bridge_dir: &Path,
    recent_hours: i64,
    selector: &AdaptiveBridgeSelector,
) -> Result<Value, ScraperError> {
    let now = Utc::now();
    let cutoff_72 = now - ChronoDuration::hours(recent_hours);
    let mut stats = Map::new();
    let transports = ["obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"];

    for transport in transports {
        let fname = transport;
        let records: Vec<&Value> = history
            .as_object()
            .map(|m| {
                m.values()
                    .filter(|v| v.get("transport").and_then(Value::as_str) == Some(transport))
                    .collect()
            })
            .unwrap_or_default();

        let ipv4 = selected_lines(&records, transport, selector, |v| {
            v.get("ip_version")
                .and_then(Value::as_str)
                .unwrap_or("ipv4")
                != "ipv6"
        });
        let ipv6 = selected_lines(&records, transport, selector, |v| {
            v.get("ip_version").and_then(Value::as_str) == Some("ipv6")
        });
        let ipv4_72h = selected_lines(&records, transport, selector, |v| {
            v.get("ip_version")
                .and_then(Value::as_str)
                .unwrap_or("ipv4")
                != "ipv6"
                && parse_dt_from_field(v.get("first_seen")) > cutoff_72
        });
        let ipv6_72h = selected_lines(&records, transport, selector, |v| {
            v.get("ip_version").and_then(Value::as_str) == Some("ipv6")
                && parse_dt_from_field(v.get("first_seen")) > cutoff_72
        });

        let preserve_rank = selector.config.enabled;
        write_sorted(
            &bridge_dir.join(format!("{}.txt", fname)),
            &ipv4,
            preserve_rank,
        )?;
        write_sorted(
            &bridge_dir.join(format!("{}_ipv6.txt", fname)),
            &ipv6,
            preserve_rank,
        )?;
        write_sorted(
            &bridge_dir.join(format!("{}_{}h.txt", fname, recent_hours)),
            &ipv4_72h,
            preserve_rank,
        )?;
        write_sorted(
            &bridge_dir.join(format!("{}_{}h_ipv6.txt", fname, recent_hours)),
            &ipv6_72h,
            preserve_rank,
        )?;

        stats.insert(format!("{}.txt", fname), json!(ipv4.len()));
        stats.insert(format!("{}_ipv6.txt", fname), json!(ipv6.len()));
        stats.insert(
            format!("{}_{}h.txt", fname, recent_hours),
            json!(ipv4_72h.len()),
        );
        stats.insert(
            format!("{}_{}h_ipv6.txt", fname, recent_hours),
            json!(ipv6_72h.len()),
        );
    }

    Ok(Value::Object(stats))
}

/// Mirror of the `selected_lines` closure inside `write_bridge_files`.
fn selected_lines(
    candidates: &[&Value],
    transport: &str,
    selector: &AdaptiveBridgeSelector,
    filter: impl Fn(&Value) -> bool,
) -> Vec<String> {
    let items: Vec<(String, Value)> = candidates
        .iter()
        .copied()
        .filter(|v| filter(v))
        .filter_map(|v| {
            v.get("raw")
                .and_then(Value::as_str)
                .map(|raw| (normalize_for_history(raw, transport), v.clone()))
        })
        .collect();
    match selector.select(&items) {
        Ok(selected) => selected
            .into_iter()
            .filter_map(|(_, v)| {
                v.get("raw")
                    .and_then(Value::as_str)
                    .map(|raw| normalize_for_file(raw, transport))
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Parse a `first_seen` field value via [`dt_utils::parse_dt`], defaulting
/// to the Python `2000-01-01T00:00:00+00:00` sentinel when missing.
fn parse_dt_from_field(field: Option<&Value>) -> DateTime<Utc> {
    match field {
        Some(Value::String(s)) => dt_utils::parse_dt(s),
        _ => dt_utils::parse_dt("2000-01-01T00:00:00+00:00"),
    }
}

/// Mirror of `write_testing_json(history)` with injectable `path` and
/// [`AdaptiveBridgeSelector`]. Returns the number of entries written.
pub fn write_testing_json(
    history: &Value,
    path: &Path,
    selector: &AdaptiveBridgeSelector,
) -> Result<usize, ScraperError> {
    let items: Vec<(String, Value)> = history
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let all_lines: Vec<String> = selector
        .select(&items)
        .map_err(ScraperError::Adaptive)?
        .into_iter()
        .map(|(line, _)| line)
        .collect();
    let count = all_lines.len();
    let serialized = serde_json::to_string_pretty(&all_lines)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ScraperError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, serialized).map_err(|source| ScraperError::Io {
        path: path.display().to_string(),
        source,
    })?;
    tracing::info!("bridge_list_for_testing.json: {} entries", count);
    Ok(count)
}

/// Pure decision logic extracted from `build_zip`. Returns the folder name
/// inside the ZIP archive for a given `.txt` file name, mirroring the
/// Python branch order:
/// 1. `"_tested" in name or "likely_working" in name` → `"Tor Bridges/Verified"`
/// 2. `f"_{RECENT_HOURS}h" in name` → `"Tor Bridges/Fresh ({RECENT_HOURS}h)"`
/// 3. otherwise → `"Tor Bridges/Full Archive"`
pub fn classify_zip_folder(name: &str, recent_hours: i64) -> String {
    if name.contains("_tested") || name.contains("likely_working") {
        "Tor Bridges/Verified".to_string()
    } else if name.contains(&format!("_{}h", recent_hours)) {
        format!("Tor Bridges/Fresh ({}h)", recent_hours)
    } else {
        "Tor Bridges/Full Archive".to_string()
    }
}

/// Mirror of `update_readme(stats)` with injectable `path`, `repo_url`, and
/// `recent_hours`. Reproduces the Python template and `.format_map()` call
/// byte-for-byte.
pub fn update_readme(
    stats: &Value,
    path: &Path,
    repo_url: &str,
    recent_hours: i64,
) -> Result<(), ScraperError> {
    let now = Utc::now();
    let ts = now.format("%Y-%m-%d %H:%M UTC").to_string();

    let lnk = |fname: &str| format!("[{}]({}/bridge/{})", fname, repo_url, fname);
    let cnt = |key: &str| {
        format!(
            "**{}**",
            stats.get(key).and_then(Value::as_i64).unwrap_or(0)
        )
    };

    let template = format!(
        "\
# 🌐 TorShield-IR — Tor Bridges for Iran

> Production-grade, Iran-optimised bridge collection with OONI intelligence.
> **Last update:** `{ts}`
> Pipeline: Python scraper → Go iran_tester (OONI + ASN + 8-layer DPI analysis) → Rust bridge-probe

## ⚠️ For Iran Users (برای کاربران ایران)

- **شبکه ملی (NIN active):** Use `export/iran_cut_pack.txt` — Snowflake and CDN-fronted WebTunnel survive cuts.
- **Normal censorship:** Use `export/iran_pack.txt` — OONI-verified bridges ranked by Iran score.
- **Port 443 bridges** are highest priority — Iran cannot block HTTPS without breaking banking.

## ✅ OONI-Verified Working (Iran)

| File | Bridges |
| :--- | :--- |
| [iran_likely_working_obfs4.txt]({repo}/bridge/iran_likely_working_obfs4.txt) | Auto |
| [iran_likely_working_webtunnel.txt]({repo}/bridge/iran_likely_working_webtunnel.txt) | Auto |
| [iran_likely_working_all.txt]({repo}/bridge/iran_likely_working_all.txt) | Auto |

## 📦 Full Archive

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {lnk_obfs4} | {cnt_obfs4} | {lnk_obfs4_v6} | {cnt_obfs4_v6} |
| **WebTunnel** | {lnk_wt} | {cnt_wt} | {lnk_wt_v6} | {cnt_wt_v6} |
| **Snowflake** | {lnk_sf} | {cnt_sf} | — | — |
| **Vanilla** | {lnk_va} | {cnt_va} | {lnk_va_v6} | {cnt_va_v6} |
| **meek-lite** | {lnk_ml} | {cnt_ml} | — | — |

## 🇮🇷 Iran Packs

| Pack | Description |
| :--- | :--- |
| [iran_pack.txt]({repo}/export/iran_pack.txt) | Top 100 bridges by Iran composite score |
| [iran_cut_pack.txt]({repo}/export/iran_cut_pack.txt) | Bridges for internet cut / NIN scenarios |

## 📊 DPI Resistance Guide

| Transport | Iran DPI | Survives Cut | Port 443 |
| :--- | :--- | :--- | :--- |
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | N/A |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | ✅ |
| obfs4 | ⭐⭐⭐⭐ | ❌ | ✅ |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | ✅ |
| Vanilla | ⭐ | ❌ | ⚠️ |
",
        ts = ts,
        repo = repo_url,
        lnk_obfs4 = lnk("obfs4.txt"),
        cnt_obfs4 = cnt("obfs4.txt"),
        lnk_obfs4_v6 = lnk("obfs4_ipv6.txt"),
        cnt_obfs4_v6 = cnt("obfs4_ipv6.txt"),
        lnk_wt = lnk("webtunnel.txt"),
        cnt_wt = cnt("webtunnel.txt"),
        lnk_wt_v6 = lnk("webtunnel_ipv6.txt"),
        cnt_wt_v6 = cnt("webtunnel_ipv6.txt"),
        lnk_sf = lnk("snowflake.txt"),
        cnt_sf = cnt("snowflake.txt"),
        lnk_va = lnk("vanilla.txt"),
        cnt_va = cnt("vanilla.txt"),
        lnk_va_v6 = lnk("vanilla_ipv6.txt"),
        cnt_va_v6 = cnt("vanilla_ipv6.txt"),
        lnk_ml = lnk("meek_lite.txt"),
        cnt_ml = cnt("meek_lite.txt"),
    );

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ScraperError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, template).map_err(|source| ScraperError::Io {
        path: path.display().to_string(),
        source,
    })?;
    tracing::info!("README.md updated.");
    // Suppress unused-variable warning for `recent_hours` — the Python
    // original also noisily references `rh` solely to satisfy pyflakes.
    let _ = recent_hours;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Production HTTP client (network feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Production [`HttpFetch`] implementation backed by `reqwest::blocking`.
///
/// Only available when the `network` Cargo feature is enabled. Uses a
/// shared `reqwest::blocking::Client` with the default `scraper.py` headers
/// and explicit per-request timeouts.
#[cfg(feature = "network")]
#[derive(Debug, Clone)]
pub struct ReqwestHttpFetch {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "network")]
impl Default for ReqwestHttpFetch {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

#[cfg(feature = "network")]
impl ReqwestHttpFetch {
    /// Construct a new client with the given default request timeout and
    /// the `scraper.py` User-Agent / Accept headers.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent(USER_AGENT)
            .default_headers(reqwest::header::HeaderMap::from_iter([
                (
                    reqwest::header::ACCEPT,
                    "text/html,application/xhtml+xml"
                        .parse()
                        .expect("static header value"),
                ),
                (
                    reqwest::header::ACCEPT_LANGUAGE,
                    "en-US,en;q=0.9".parse().expect("static header value"),
                ),
                (
                    reqwest::header::ACCEPT_ENCODING,
                    "gzip, deflate, br".parse().expect("static header value"),
                ),
            ]))
            .build()
            .expect("reqwest client builds with valid defaults");
        Self { client }
    }
}

#[cfg(feature = "network")]
impl HttpFetch for ReqwestHttpFetch {
    fn get(&self, url: &str, timeout: Duration) -> Result<HttpResponse, ScraperError> {
        let resp = self
            .client
            .get(url)
            .timeout(timeout)
            .send()
            .map_err(|err| ScraperError::Http {
                url: url.to_string(),
                message: err.to_string(),
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|_| ScraperError::HttpNotUtf8 {
            url: url.to_string(),
        })?;
        Ok(HttpResponse { status, text })
    }

    fn post_json(
        &self,
        url: &str,
        body: &Value,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, ScraperError> {
        let mut req = self.client.post(url).timeout(timeout).json(body);
        for (name, value) in headers {
            let name_parsed =
                name.parse::<reqwest::header::HeaderName>()
                    .map_err(|err| ScraperError::Http {
                        url: url.to_string(),
                        message: format!("invalid header name {name:?}: {err}"),
                    })?;
            let value_parsed = value
                .parse::<reqwest::header::HeaderValue>()
                .map_err(|err| ScraperError::Http {
                    url: url.to_string(),
                    message: format!("invalid header value {value:?}: {err}"),
                })?;
            req = req.header(name_parsed, value_parsed);
        }
        let resp = req.send().map_err(|err| ScraperError::Http {
            url: url.to_string(),
            message: err.to_string(),
        })?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|_| ScraperError::HttpNotUtf8 {
            url: url.to_string(),
        })?;
        Ok(HttpResponse { status, text })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn type_name_of_value(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_for_history_vanilla_is_idempotent() {
        assert_eq!(
            normalize_for_history("1.2.3.4:443 abc", "vanilla"),
            "Bridge 1.2.3.4:443 abc"
        );
        assert_eq!(
            normalize_for_history("Bridge 1.2.3.4:443 abc", "vanilla"),
            "Bridge 1.2.3.4:443 abc"
        );
    }

    #[test]
    fn normalize_for_history_non_vanilla_is_trimmed() {
        assert_eq!(
            normalize_for_history("  obfs4 1.2.3.4:443 cert=abc  ", "obfs4"),
            "obfs4 1.2.3.4:443 cert=abc"
        );
    }

    #[test]
    fn normalize_for_file_strips_bridge_prefix_for_vanilla() {
        assert_eq!(
            normalize_for_file("Bridge 1.2.3.4:443 abc", "vanilla"),
            "1.2.3.4:443 abc"
        );
        assert_eq!(
            normalize_for_file("1.2.3.4:443 abc", "vanilla"),
            "1.2.3.4:443 abc"
        );
    }

    #[test]
    fn is_valid_line_rejects_short_and_marker_lines() {
        assert!(!is_valid_line(""));
        assert!(!is_valid_line("short"));
        assert!(!is_valid_line("# comment line here is long enough"));
        assert!(!is_valid_line("No bridges available at all here!"));
    }

    #[test]
    fn is_valid_line_accepts_ipv4_ipv6_and_url() {
        assert!(is_valid_line(
            "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"
        ));
        assert!(is_valid_line(
            "obfs4 [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567"
        ));
        assert!(is_valid_line(
            "webtunnel url=https://example.com/ abcdef0123456789"
        ));
    }

    #[test]
    fn infer_transport_and_ip_version_match_python() {
        assert_eq!(infer_transport("snowflake 192.0.2.3:1 ABC"), "snowflake");
        assert_eq!(infer_transport("obfs4 1.2.3.4:443 ABC"), "obfs4");
        assert_eq!(
            infer_transport("webtunnel url=https://example.com/ ABC"),
            "webtunnel"
        );
        assert_eq!(infer_transport("meek_lite 192.0.2.18:80 ABC"), "meek_lite");
        assert_eq!(infer_transport("1.2.3.4:443 ABC"), "vanilla");

        assert_eq!(infer_ip_version("[2001:db8::1]:443 ABC"), "ipv6");
        assert_eq!(infer_ip_version("1.2.3.4:443 ABC"), "ipv4");
    }

    #[test]
    fn parse_bridgelines_html_extracts_div_text() {
        let html = r#"<html><body>
<div id="bridgelines">
obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567
</div></body></html>"#;
        let lines = parse_bridgelines_html(html);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("obfs4 1.2.3.4:443"));
        assert!(lines[1].starts_with("obfs4 5.6.7.8:443"));
    }

    #[test]
    fn parse_bridgelines_html_falls_back_to_pre_and_code() {
        // When there is no `#bridgelines` div, the Python original joins
        // all `<pre>` and `<code>` text content with a single space. The
        // resulting joined string is split by `\n` and filtered, so two
        // single-line bridges joined with a space collapse to ONE valid
        // line (the regex matches the first IPv4:port).
        let html = r#"<html><body>
<pre>obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567</pre>
<code>obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567</code>
</body></html>"#;
        let lines = parse_bridgelines_html(html);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("1.2.3.4:443"));
        assert!(lines[0].contains("5.6.7.8:443"));
    }

    #[test]
    fn parse_moat_response_walks_bridges_section() {
        let data = json!({
            "bridges": {
                "obfs4": ["obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"],
                "webTunnel": ["webtunnel url=https://example.com/ abcdef0123456789"],
                "snowflake": ["snowflake 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567"],
                "unknown_transport": ["short"],
            }
        });
        let pairs = parse_moat_response(&data).unwrap();
        assert_eq!(pairs.len(), 3);
        // serde_json::Map iterates in BTreeMap-sorted key order, so the
        // resulting transport labels are: obfs4, snowflake, webtunnel.
        let transports: Vec<&str> = pairs.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(transports, vec!["obfs4", "snowflake", "webtunnel"]);
    }

    #[test]
    fn get_static_returns_four_entries() {
        let s = get_static();
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].1, "snowflake");
        assert_eq!(s[1].1, "snowflake");
        assert_eq!(s[2].1, "meek_lite");
        assert_eq!(s[3].1, "meek_lite");
    }

    #[test]
    fn tcp_reachable_returns_false_for_non_ipv4() {
        struct AlwaysTrue;
        impl TcpProbe for AlwaysTrue {
            fn tcp_reachable(&self, _host: &str, _port: u16, _timeout_s: f64) -> bool {
                true
            }
        }
        let probe = AlwaysTrue;
        // No IPv4:port match → returns false without consulting the probe.
        assert!(!tcp_reachable_with_probe(
            "snowflake url=https://example.com/",
            1.0,
            &probe
        ));
        // IPv4:port match → consults the probe.
        assert!(tcp_reachable_with_probe(
            "obfs4 1.2.3.4:443 ABC",
            1.0,
            &probe
        ));
    }

    #[test]
    fn load_history_upgrades_legacy_string_entries() {
        let tmp = std::env::temp_dir().join("scraper_parity_load_history.json");
        std::fs::write(
            &tmp,
            r#"{"obfs4 1.2.3.4:443 ABC":"2026-01-01T00:00:00+00:00"}"#,
        )
        .unwrap();
        let history = load_history(&tmp).unwrap();
        let entry = history.get("obfs4 1.2.3.4:443 ABC").unwrap();
        assert_eq!(entry["transport"], "obfs4");
        assert_eq!(entry["ip_version"], "ipv4");
        assert_eq!(entry["first_seen"], "2026-01-01T00:00:00+00:00");
        assert_eq!(entry["last_seen"], "2026-01-01T00:00:00+00:00");
        assert!(entry["tcp_reachable"].is_null());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_history_returns_empty_object_when_missing() {
        let tmp = std::env::temp_dir().join("scraper_parity_missing_history.json");
        let _ = std::fs::remove_file(&tmp);
        let history = load_history(&tmp).unwrap();
        assert!(history.as_object().map(|m| m.is_empty()).unwrap_or(false));
    }

    #[test]
    fn prune_history_with_now_removes_old_entries() {
        let mut history = json!({
            "old": {"transport": "obfs4", "last_seen": "2000-01-01T00:00:00+00:00"},
            "new": {"transport": "obfs4", "last_seen": "2026-06-09T00:00:00+00:00"},
        });
        let now = DateTime::parse_from_rfc3339("2026-06-10T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        let removed = prune_history_with_now(&mut history, 30, now).unwrap();
        assert_eq!(removed, 1);
        assert!(history.get("old").is_none());
        assert!(history.get("new").is_some());
    }

    #[test]
    fn classify_zip_folder_matches_python_branch_order() {
        assert_eq!(
            classify_zip_folder("obfs4_tested.txt", 72),
            "Tor Bridges/Verified"
        );
        assert_eq!(
            classify_zip_folder("iran_likely_working_obfs4.txt", 72),
            "Tor Bridges/Verified"
        );
        assert_eq!(
            classify_zip_folder("obfs4_72h.txt", 72),
            "Tor Bridges/Fresh (72h)"
        );
        assert_eq!(
            classify_zip_folder("obfs4.txt", 72),
            "Tor Bridges/Full Archive"
        );
    }
}
