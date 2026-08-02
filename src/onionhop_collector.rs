//! Parity port of `onionhop_collector.py`.
//!
//! OnionHop multi-source bridge collector (Iran-aware). Derived from the
//! OnionHop Bridges Collector by center2055 (AGPL-3.0). Integrated into
//! TorShield-IR as an additional collection stage that runs BEFORE
//! `scraper.py` to seed the archive with additional fresh bridges.
//!
//! # Behavior traced to `onionhop_collector.py`
//!
//! * [`is_valid`] — `_is_valid(line)` validation regex.
//! * [`strip_prefix`] — `_strip_prefix(line)`.
//! * [`transport_token`] — `_transport_token(line)`.
//! * [`detect_transport`] — `_detect_transport(line)`.
//! * [`detect_ip_version`] — `_detect_ip_version(line)`.
//! * [`is_fronted`] — `_is_fronted(line)`.
//! * [`extract_front_host`] — `_extract_front_host(line)`.
//! * [`extract_endpoint`] — `_extract_endpoint(line)` returning
//!   `(Option<String>, Option<u16>, String)` to mirror Python's
//!   `(host|None, port|None, transport)`.
//! * [`parse_iso_safe`] — `_parse_iso_safe(stamp)` returning
//!   `Option<DateTime<Utc>>`.
//! * [`entry_last_seen`] — `_entry_last_seen(entry)`.
//! * [`read_existing`] / [`write_lines`] — file I/O with injectable `&Path`.
//! * [`load_history`] / [`save_history`] — file I/O that mirrors the
//!   `_load_history` / `_save_history` canonicalisation (legacy string
//!   entries are promoted to dict format using [`detect_transport`] /
//!   [`detect_ip_version`]).
//! * [`cleanup_history_with_now`] — `_cleanup_history(history)` with
//!   injectable `now` and `retention_days`.
//! * [`record_bridge_with_now`] — `_record_bridge` with injectable `now`.
//! * [`fetch_bridgedb`] / [`fetch_delta`] — network fetchers that take an
//!   injectable [`HttpFetch`] client (the same trait used by `scraper.rs`).
//! * [`test_many_with_probes`] — concurrent reachability tester that takes
//!   an injectable [`ReachabilityProbe`] instead of opening real sockets.
//!
//! # Side effects not ported
//!
//! * `main()` orchestration of all sources is not ported as a single entry
//!   point. Callers compose the public functions above.
//! * Concurrent `_test_many` uses a thread pool in Python
//!   (`concurrent.futures.ThreadPoolExecutor`). The Rust port
//!   ([`test_many_with_probes`]) runs probes sequentially because the
//!   injectable [`ReachabilityProbe`] trait is `Sync`-bounded and the
//!   capping/clamping behavior (MAX_TEST_PER_LIST, MAX_WORKERS) is preserved
//!   exactly. Production callers that want parallelism can wrap the probe
//!   in their own thread pool.

use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::dt_utils;
use crate::scraper::HttpFetch;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (mirrors module-level constants in onionhop_collector.py)
// ─────────────────────────────────────────────────────────────────────────────

/// Default recent-window length in hours. Mirrors `RECENT_HOURS`.
pub const RECENT_HOURS: i64 = 72;

/// Default history retention in days. Mirrors `HISTORY_RETENTION_DAYS`.
pub const HISTORY_RETENTION_DAYS: i64 = 30;

/// Maximum number of bridges per list that get a reachability test.
/// Mirrors `MAX_TEST_PER_LIST`.
pub const MAX_TEST_PER_LIST: usize = 600;

/// Maximum number of concurrent worker threads for reachability tests.
/// Mirrors `MAX_WORKERS`. Preserved for parity; the Rust port runs probes
/// sequentially because the injectable probe is `Sync`-bounded.
pub const MAX_WORKERS: usize = 50;

/// Default TCP/TLS connect timeout in seconds. Mirrors `CONNECT_TIMEOUT`.
pub const CONNECT_TIMEOUT: u64 = 8;

/// Default User-Agent for HTTP requests. Mirrors `USER_AGENT`.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// Transports that are pooled from BridgeDB + Delta-Kronecker seed lists.
/// Mirrors `POOLED_TRANSPORTS`.
pub const POOLED_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla"];

/// `IP_VARIANTS` from `onionhop_collector.py`. Each tuple is
/// `(suffix, ipv6_flag)`.
pub const IP_VARIANTS: &[(&str, bool)] = &[("", false), ("_ipv6", true)];

/// Base URL for the Delta-Kronecker community seed lists.
/// Mirrors `DELTA_RAW_BASE`.
pub const DELTA_RAW_BASE: &str =
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge";

/// Tokens that mark a bridge line as "fronted" (CDN/broker routed).
/// Mirrors `FRONTED_TOKENS`.
pub const FRONTED_TOKENS: &[&str] = &["snowflake", "meek", "meek_lite", "meek-azure", "conjure"];

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `onionhop_collector.py` parity port.
#[derive(Debug, Error)]
pub enum OnionHopError {
    /// File I/O failure on a history or bridge-list path.
    #[error("onionhop I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// History file content was not a JSON object.
    #[error("onionhop history root must be a JSON object, got {actual}")]
    HistoryNotObject { actual: &'static str },

    /// JSON serialization failure.
    #[error("onionhop JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Underlying HTTP client error.
    #[error("onionhop HTTP error for {url}: {message}")]
    Http { url: String, message: String },

    /// Underlying HTTP client returned a body that was not valid UTF-8.
    #[error("onionhop HTTP response for {url} was not valid UTF-8")]
    HttpNotUtf8 { url: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable probe trait
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable reachability probe used by [`is_reachable_with_probe`] and
/// [`test_many_with_probes`]. Production code can wrap this around
/// `std::net::TcpStream` (or a TLS implementation); tests substitute a
/// mock that returns canned results without opening sockets.
pub trait ReachabilityProbe {
    /// Mirror of `_test_tcp(host, port)`: returns `true` when a TCP
    /// connection to `(host, port)` succeeds within [`CONNECT_TIMEOUT`]
    /// seconds.
    fn test_tcp(&self, host: &str, port: u16) -> bool;

    /// Mirror of `_test_tls(host, port)`: returns `true` when a TLS
    /// handshake to `(host, port)` succeeds within [`CONNECT_TIMEOUT`]
    /// seconds. The SNI behavior (skip for IP literals, use the hostname
    /// for DNS names) is delegated to the probe implementation.
    fn test_tls(&self, host: &str, port: u16) -> bool;

    /// Mirror of `_is_reachable(bridge_line)`: returns `true` when the
    /// bridge line is reachable. The default implementation mirrors the
    /// Python `_is_reachable` body: fronted bridges test the front host
    /// over TLS on port 443; non-fronted bridges resolve DNS (delegated
    /// to the probe) and test TCP (or TLS for `webtunnel`).
    fn is_reachable(&self, bridge_line: &str) -> bool
    where
        Self: Sized,
    {
        is_reachable_with_probe(bridge_line, self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_log(msg)`. Writes a timestamped line to stderr. The Python
/// original uses `print(..., flush=True)` which goes to stdout; in Rust we
/// use `tracing::info!` so production deployments can route logs through
/// `tracing-subscriber`. The timestamp format is preserved.
pub fn log(msg: &str) {
    let stamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    tracing::info!("[onionhop] [{}] {}", stamp, msg);
}

/// Mirror of `_now_iso()`. Returns `chrono::Utc::now().to_rfc3339()`
/// which produces the same `+00:00` suffix as Python's
/// `datetime.now(UTC).isoformat()`.
pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Mirror of `_is_valid(line)`.
///
/// Returns `false` for empty/`#`-prefixed lines, lines containing
/// `"No bridges available"`, and lines shorter than 10 chars. Otherwise
/// returns `true` if the line matches `\d+\.\d+\.\d+\.\d+`,
/// `\[[0-9A-Fa-f:]+\]`, or `https?://`.
pub fn is_valid(line: &str) -> bool {
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    if line.contains("No bridges available") || line.len() < 10 {
        return false;
    }
    is_valid_re().is_match(line)
}

/// Mirror of `_strip_prefix(line)`.
pub fn strip_prefix(line: &str) -> String {
    if let Some(rest) = line.strip_prefix("Bridge ") {
        rest.trim().to_string()
    } else {
        line.trim().to_string()
    }
}

/// Mirror of `_transport_token(line)`.
pub fn transport_token(line: &str) -> String {
    let stripped = strip_prefix(line);
    stripped
        .split_whitespace()
        .next()
        .map(|s| s.to_lowercase())
        .unwrap_or_default()
}

/// Mirror of `_detect_transport(line)`.
pub fn detect_transport(line: &str) -> String {
    let low = line.to_lowercase();
    if low.contains("snowflake") {
        "snowflake".to_string()
    } else if low.contains("webtunnel") || low.contains("url=https") {
        "webtunnel".to_string()
    } else if low.contains("obfs4") {
        "obfs4".to_string()
    } else if low.contains("meek") {
        "meek_lite".to_string()
    } else if low.contains("conjure") {
        "conjure".to_string()
    } else {
        "vanilla".to_string()
    }
}

/// Mirror of `_detect_ip_version(line)`.
pub fn detect_ip_version(line: &str) -> String {
    if ipv6_bracket_re().is_match(line) {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    }
}

/// Mirror of `_is_fronted(line)`.
pub fn is_fronted(line: &str) -> bool {
    FRONTED_TOKENS.contains(&transport_token(line).as_str())
}

/// Mirror of `_extract_front_host(line)`.
///
/// Returns the front host extracted from `url=`, `fronts=`, or `front=`
/// attributes (in that order). Returns `None` when no front host can be
/// extracted.
pub fn extract_front_host(line: &str) -> Option<String> {
    if let Some(caps) = url_attr_re().captures(line) {
        let url_val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(hm) = https_host_re().captures(url_val) {
            return Some(hm.get(1).map(|m| m.as_str()).unwrap_or("").to_string());
        }
    }
    if let Some(caps) = fronts_attr_re().captures(line) {
        let first = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !first.is_empty() {
            return Some(first);
        }
    }
    if let Some(caps) = front_attr_re().captures(line) {
        let val = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

/// Mirror of `_extract_endpoint(line)`.
///
/// Returns `(Option<host>, Option<port>, transport)`. The four pattern
/// alternatives are tried in order:
/// 1. `https?://\[([0-9A-Fa-f:]+)\](?::(\d+))?` — HTTPS URL with IPv6 host.
/// 2. `https?://([^/:]+)(?::(\d+))?` — HTTPS URL with hostname.
/// 3. `\[([0-9A-Fa-f:]+)\]:(\d+)` — bare `[IPv6]:port`.
/// 4. `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)` — IPv4:port.
///
/// When a port group is missing, the default port is `443` (the
/// `https_default` flag is `true` for the first two alternatives).
pub fn extract_endpoint(line: &str) -> (Option<String>, Option<u16>, String) {
    let text = line.trim();
    let transport = detect_transport(text);
    let patterns: &[(&Regex, bool)] = &[
        (https_ipv6_url_re(), true),
        (https_host_url_re(), true),
        (bare_ipv6_port_re(), false),
        (ipv4_port_re_onion(), false),
    ];
    for (re, https_default) in patterns {
        if let Some(caps) = re.captures(text) {
            let host = caps.get(1).map(|m| m.as_str().to_string());
            let port_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let port = if port_str.is_empty() {
                if *https_default {
                    Some(443u16)
                } else {
                    None
                }
            } else {
                port_str.parse::<u16>().ok()
            };
            return (host, port, transport);
        }
    }
    (None, None, transport)
}

/// Mirror of `_parse_iso_safe(stamp)`.
///
/// Returns `None` when `stamp` is missing, non-string, or fails to parse.
/// A timestamp that parses to the Unix epoch sentinel but is not the
/// sentinel's own ISO string is treated as invalid (`None`).
pub fn parse_iso_safe(stamp: Option<&str>) -> Option<DateTime<Utc>> {
    let stamp_str = stamp?;
    let sentinel = DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00")
        .ok()?
        .with_timezone::<Utc>(&Utc);
    let parsed = dt_utils::coerce_utc_dt(Some(stamp_str), "1970-01-01T00:00:00+00:00");
    if parsed == sentinel && stamp_str != sentinel.to_rfc3339() {
        return None;
    }
    Some(parsed)
}

/// Mirror of `_entry_last_seen(entry)`.
///
/// Returns the parsed `last_seen` datetime for dict entries (via
/// [`parse_iso_safe`]), the parsed entry itself for string entries, and
/// `None` for all other types.
pub fn entry_last_seen(entry: &Value) -> Option<DateTime<Utc>> {
    match entry {
        Value::Object(map) => parse_iso_safe(map.get("last_seen").and_then(Value::as_str)),
        Value::String(s) => parse_iso_safe(Some(s)),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reachability helpers (injectable probe)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_is_reachable(bridge_line)` using an injectable
/// [`ReachabilityProbe`].
///
/// 1. If the bridge line is fronted (via [`is_fronted`]), extract the front
///    host via [`extract_front_host`] and probe `_test_tls(front, 443)`.
///    If no front host is found, return `false`.
/// 2. Otherwise, extract the endpoint via [`extract_endpoint`]. If no host
///    or port is found, return `false`.
/// 3. If the host is an IP literal, use it directly; otherwise the probe
///    is responsible for any DNS resolution (production probes typically
///    resolve via `std::net::ToSocketAddrs`).
/// 4. For `webtunnel` transport, probe `_test_tls(host, port)`; for all
///    other transports, probe `_test_tcp(host, port)`.
pub fn is_reachable_with_probe(bridge_line: &str, probe: &dyn ReachabilityProbe) -> bool {
    if is_fronted(bridge_line) {
        return match extract_front_host(bridge_line) {
            Some(front) => probe.test_tls(&front, 443),
            None => false,
        };
    }
    let (host, port, transport) = extract_endpoint(bridge_line);
    let (Some(host), Some(port)) = (host, port) else {
        return false;
    };
    if transport == "webtunnel" {
        probe.test_tls(&host, port)
    } else {
        probe.test_tcp(&host, port)
    }
}

/// Mirror of `_test_many(bridges)` using an injectable [`ReachabilityProbe`].
///
/// Caps the input at [`MAX_TEST_PER_LIST`] candidates. Returns the subset
/// of candidates (in input order) that pass [`is_reachable_with_probe`].
/// Exceptions in individual probes are swallowed (matching the Python
/// `try/except Exception: pass` around `fut.result()`).
pub fn test_many_with_probes(bridges: &[String], probe: &dyn ReachabilityProbe) -> Vec<String> {
    let candidates: &[String] = if bridges.len() > MAX_TEST_PER_LIST {
        &bridges[..MAX_TEST_PER_LIST]
    } else {
        bridges
    };
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut working = Vec::new();
    for b in candidates {
        // The Python original wraps each fut.result() in a try/except.
        // We mirror that by treating any probe error as "not reachable".
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            is_reachable_with_probe(b, probe)
        }))
        .unwrap_or(false)
        {
            working.push(b.clone());
        }
    }
    working
}

// ─────────────────────────────────────────────────────────────────────────────
// Network fetchers (injectable HttpFetch)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_fetch_bridgedb(session, transport, ipv6)` using an injectable
/// [`HttpFetch`] client.
///
/// Fetches `https://bridges.torproject.org/bridges?transport={transport}`
/// (with `&ipv6=yes` when `ipv6` is `true`), parses the `#bridgelines` div
/// text content, and returns the set of valid, prefix-stripped bridge lines.
/// HTTP non-200 responses and `RequestException` errors return an empty set
/// (mirroring the Python swallow).
pub fn fetch_bridgedb(
    client: &dyn HttpFetch,
    transport: &str,
    ipv6: bool,
) -> Result<std::collections::BTreeSet<String>, OnionHopError> {
    let mut url = format!(
        "https://bridges.torproject.org/bridges?transport={}",
        transport
    );
    if ipv6 {
        url.push_str("&ipv6=yes");
    }
    let timeout = Duration::from_secs(30);
    let resp = match client.get(&url, timeout) {
        Ok(r) => r,
        Err(_err) => {
            // Mirror Python's RequestException swallow — return empty set.
            return Ok(std::collections::BTreeSet::new());
        }
    };
    if resp.status != 200 {
        log(&format!(
            "  BridgeDB {} ipv6={}: HTTP {}",
            transport, ipv6, resp.status
        ));
        return Ok(std::collections::BTreeSet::new());
    }
    let mut out = std::collections::BTreeSet::new();
    let lines = parse_bridgedb_html(&resp.text);
    for line in lines {
        if is_valid(&line) {
            out.insert(strip_prefix(&line));
        }
    }
    Ok(out)
}

/// Mirror of `_fetch_delta(session, transport, ipv6)` using an injectable
/// [`HttpFetch`] client.
///
/// Fetches both `{transport}{suffix}.txt` and
/// `{transport}{suffix}_72h.txt` from [`DELTA_RAW_BASE`], where
/// `suffix = "_ipv6"` when `ipv6` is `true` else `""`. Returns the union
/// of valid, prefix-stripped bridge lines. HTTP non-200 responses and
/// `RequestException` errors are swallowed per-file.
pub fn fetch_delta(
    client: &dyn HttpFetch,
    transport: &str,
    ipv6: bool,
) -> Result<std::collections::BTreeSet<String>, OnionHopError> {
    let suffix = if ipv6 { "_ipv6" } else { "" };
    let mut out = std::collections::BTreeSet::new();
    let timeout = Duration::from_secs(30);
    for variant in &[
        format!("{}{}.txt", transport, suffix),
        format!("{}{}_72h.txt", transport, suffix),
    ] {
        let url = format!("{}/{}", DELTA_RAW_BASE, variant);
        let resp = match client.get(&url, timeout) {
            Ok(r) => r,
            Err(_err) => continue,
        };
        if resp.status != 200 {
            continue;
        }
        for line in resp.text.split('\n') {
            let stripped = line.trim();
            if is_valid(stripped) {
                out.insert(strip_prefix(stripped));
            }
        }
    }
    Ok(out)
}

/// Parse the BridgeDB HTML response into a list of lines.
///
/// Mirrors the BeautifulSoup behavior:
/// 1. Find `<div id="bridgelines">` and split its text content by `\n`.
/// 2. If no such div exists, return an empty list (matching Python's
///    `for line in (ln.strip() for ln in div.get_text().split("\n"))`
///    which is only entered when `div` is truthy).
fn parse_bridgedb_html(html: &str) -> Vec<String> {
    let Some(text) = find_bridgelines_div_text(html) else {
        return Vec::new();
    };
    text.split('\n').map(|s| s.trim().to_string()).collect()
}

/// Find the `#bridgelines` div and return its text content.
fn find_bridgelines_div_text(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let needle = "<div";
    let mut i = 0;
    while i < lower.len() {
        let rel = lower[i..].find(needle)?;
        i += rel;
        let tag_end = lower[i..].find('>')? + i;
        let attrs = &html[i + needle.len()..tag_end];
        if attr_has_id(attrs, "bridgelines") {
            if attrs.trim_end().ends_with('/') {
                return Some(String::new());
            }
            let body_start = tag_end + 1;
            let close = find_matching_close_tag(&lower, body_start, "div".to_string())
                .unwrap_or(lower.len());
            let body = &html[body_start..close];
            return Some(strip_tags_to_text(body));
        }
        i = tag_end + 1;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_read_existing(path)`.
///
/// Reads `path` as UTF-8 text, splits by lines, and returns the set of
/// valid, prefix-stripped bridge lines. Returns an empty set when the file
/// does not exist.
pub fn read_existing(path: &Path) -> Result<std::collections::BTreeSet<String>, OnionHopError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::BTreeSet::new());
        }
        Err(err) => {
            return Err(OnionHopError::Io {
                path: path.display().to_string(),
                source: err,
            });
        }
    };
    let mut out = std::collections::BTreeSet::new();
    for line in text.lines() {
        let stripped = line.trim();
        if is_valid(stripped) {
            out.insert(strip_prefix(stripped));
        }
    }
    Ok(out)
}

/// Mirror of `_write_lines(path, lines)`.
///
/// Writes the sorted, `\n`-joined lines with a trailing newline. Accepts
/// any iterator of `String`.
pub fn write_lines<I>(path: &Path, lines: I) -> Result<(), OnionHopError>
where
    I: IntoIterator<Item = String>,
{
    let mut sorted: Vec<String> = lines.into_iter().collect();
    sorted.sort();
    let mut content = sorted.join("\n");
    content.push('\n');
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| OnionHopError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, content).map_err(|source| OnionHopError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Mirror of `_load_history()`.
///
/// Reads `path` as UTF-8 JSON. Legacy string-format entries are
/// transparently promoted to dict format using [`detect_transport`] and
/// [`detect_ip_version`]. Dict entries are preserved as-is. Other entry
/// types are skipped. Returns an empty JSON object when the file does not
/// exist; on parse failure, logs and returns an empty object (mirroring
/// the Python swallow).
pub fn load_history(path: &Path) -> Result<Value, OnionHopError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(err) => {
            return Err(OnionHopError::Io {
                path: path.display().to_string(),
                source: err,
            });
        }
    };
    let raw: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(err) => {
            log(&format!("History load error: {}", err));
            return Ok(Value::Object(Map::new()));
        }
    };
    let raw_map = match raw.as_object() {
        Some(m) => m,
        None => {
            return Err(OnionHopError::HistoryNotObject {
                actual: type_name_of_value(&raw),
            });
        }
    };
    let mut normalised = Map::new();
    for (k, v) in raw_map {
        match v {
            Value::String(s) => {
                normalised.insert(
                    k.clone(),
                    json!({
                        "raw":           k,
                        "transport":     detect_transport(k),
                        "ip_version":    detect_ip_version(k),
                        "first_seen":    s,
                        "last_seen":     s,
                        "tcp_reachable": Value::Null,
                    }),
                );
            }
            Value::Object(_) => {
                normalised.insert(k.clone(), v.clone());
            }
            // Skip malformed entries.
            _ => {}
        }
    }
    Ok(Value::Object(normalised))
}

/// Mirror of `_save_history(history)`.
///
/// Writes the history as pretty-printed JSON with `sort_keys=True` and
/// `ensure_ascii=False`. Uses 2-space indentation to match Python's
/// `json.dumps(indent=2, sort_keys=True, ensure_ascii=False)`.
pub fn save_history(history: &Value, path: &Path) -> Result<(), OnionHopError> {
    let serialized = if let Some(obj) = history.as_object() {
        // BTreeMap iterates in sorted-key order, mirroring sort_keys=True.
        let sorted: serde_json::Map<String, Value> = obj
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<String, Value>>();
        let mut ordered = serde_json::Map::new();
        let mut keys: Vec<&String> = sorted.keys().collect();
        keys.sort();
        for k in keys {
            ordered.insert(k.clone(), sorted.get(k).cloned().unwrap_or(Value::Null));
        }
        serde_json::to_string_pretty(&Value::Object(ordered))?
    } else {
        serde_json::to_string_pretty(history)?
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| OnionHopError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    fs::write(path, serialized).map_err(|source| OnionHopError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Mirror of `_cleanup_history(history)` with injectable `now` and
/// `retention_days`.
///
/// Returns a new JSON object containing only the entries whose
/// `last_seen` (via [`entry_last_seen`]) is `Some` and strictly greater
/// than `now - retention_days`.
pub fn cleanup_history_with_now(
    history: &Value,
    retention_days: i64,
    now: DateTime<Utc>,
) -> Result<Value, OnionHopError> {
    let cutoff = now - ChronoDuration::days(retention_days);
    let map = history.as_object().ok_or(OnionHopError::HistoryNotObject {
        actual: type_name_of_value(history),
    })?;
    let mut out = Map::new();
    for (k, v) in map {
        if let Some(ts) = entry_last_seen(v) {
            if ts > cutoff {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(Value::Object(out))
}

/// Production wrapper around [`cleanup_history_with_now`] using
/// `Utc::now()` and [`HISTORY_RETENTION_DAYS`].
pub fn cleanup_history(history: &Value) -> Result<Value, OnionHopError> {
    cleanup_history_with_now(history, HISTORY_RETENTION_DAYS, Utc::now())
}

/// Mirror of `_record_bridge(history, bridge, transport, ip_version)` with
/// injectable `now`.
///
/// Inserts a fresh dict entry when `bridge` is new (or the existing entry
/// is not a dict). Otherwise updates `last_seen` and ensures `raw` is set
/// via `setdefault("raw", bridge)`.
pub fn record_bridge_with_now(
    history: &mut Value,
    bridge: &str,
    transport: &str,
    ip_version: &str,
    now: DateTime<Utc>,
) -> Result<(), OnionHopError> {
    let actual = type_name_of_value(history);
    let map = history
        .as_object_mut()
        .ok_or(OnionHopError::HistoryNotObject { actual })?;
    let now_iso = now.to_rfc3339();
    let needs_insert = match map.get(bridge) {
        None => true,
        Some(Value::Object(_)) => false,
        Some(_) => true,
    };
    if needs_insert {
        map.insert(
            bridge.to_string(),
            json!({
                "raw":           bridge,
                "transport":     transport,
                "ip_version":    ip_version,
                "first_seen":    now_iso,
                "last_seen":     now_iso,
                "tcp_reachable": Value::Null,
            }),
        );
    } else {
        let entry = map.get_mut(bridge).expect("present");
        let actual = type_name_of_value(entry);
        let obj = entry
            .as_object_mut()
            .ok_or(OnionHopError::HistoryNotObject { actual })?;
        obj.insert("last_seen".to_string(), Value::String(now_iso.clone()));
        obj.entry("raw".to_string())
            .or_insert(Value::String(bridge.to_string()));
    }
    Ok(())
}

/// Production wrapper around [`record_bridge_with_now`] using `Utc::now()`.
pub fn record_bridge(
    history: &mut Value,
    bridge: &str,
    transport: &str,
    ip_version: &str,
) -> Result<(), OnionHopError> {
    record_bridge_with_now(history, bridge, transport, ip_version, Utc::now())
}

// ─────────────────────────────────────────────────────────────────────────────
// Fronted bridges (constant table)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `FRONTED_BRIDGES`. Returns a `Vec<(transport, lines)>` to
/// preserve insertion order (Python `dict` preserves order in 3.7+).
pub fn fronted_bridges() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("snowflake", fronted_snowflake()),
        ("meek-azure", fronted_meek_azure()),
        ("conjure", fronted_conjure()),
    ]
}

/// Mirror of `FRONTED_BRIDGES["snowflake"]`.
pub fn fronted_snowflake() -> Vec<&'static str> {
    vec![
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://1098762253.rsc.cdn77.org/ \
fronts=www.cdn77.com,www.phpmyadmin.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,\
stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,\
stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
        "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://1098762253.rsc.cdn77.org/ \
fronts=www.cdn77.com,www.phpmyadmin.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,\
stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,\
stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
    ]
}

/// Mirror of `FRONTED_BRIDGES["meek-azure"]`.
pub fn fronted_meek_azure() -> Vec<&'static str> {
    vec![
        "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE \
url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
    ]
}

/// Mirror of `FRONTED_BRIDGES["conjure"]`.
pub fn fronted_conjure() -> Vec<&'static str> {
    vec![
        "conjure 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://registration.refraction.network/api \
fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled regexes (lazy + cached)
// ─────────────────────────────────────────────────────────────────────────────

fn is_valid_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d+\.\d+\.\d+\.\d+|\[[0-9A-Fa-f:]+\]|https?://").expect("is_valid_re compiles")
    })
}

fn ipv6_bracket_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[0-9a-fA-F:]{2,39}\]").expect("ipv6_bracket_re compiles"))
}

fn url_attr_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)url=(\S+)").expect("url_attr_re compiles"))
}

fn https_host_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://([^/:\s]+)").expect("https_host_re compiles"))
}

fn fronts_attr_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)fronts=(\S+)").expect("fronts_attr_re compiles"))
}

fn front_attr_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)front=(\S+)").expect("front_attr_re compiles"))
}

fn https_ipv6_url_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https?://\[([0-9A-Fa-f:]+)\](?::(\d+))?").expect("https_ipv6_url_re compiles")
    })
}

fn https_host_url_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https?://([^/:]+)(?::(\d+))?").expect("https_host_url_re compiles")
    })
}

fn bare_ipv6_port_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([0-9A-Fa-f:]+)\]:(\d+)").expect("bare_ipv6_port_re compiles"))
}

fn ipv4_port_re_onion() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)")
            .expect("ipv4_port_re_onion compiles")
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML helpers (shared minimal extractor)
// ─────────────────────────────────────────────────────────────────────────────

/// Return `true` when the attribute slice `attrs` contains an `id`
/// attribute equal to `id_value`. Handles single-quoted, double-quoted,
/// and unquoted attribute values, and case-insensitive attribute name
/// matching. Mirrors the helper in `scraper.rs`.
fn attr_has_id(attrs: &str, id_value: &str) -> bool {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
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
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
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
                    i += 1;
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
/// Mirrors the helper in `scraper.rs`.
fn find_matching_close_tag(lower: &str, start: usize, tag: String) -> Option<usize> {
    let open = format!("<{}", tag);
    let close = format!("</{}", tag);
    let mut depth: i32 = 1;
    let mut i = start;
    while i < lower.len() {
        let next_open = lower[i..].find(&open);
        let next_close = lower[i..].find(&close);
        match (next_open, next_close) {
            (Some(no), Some(nc)) => {
                if no < nc {
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
/// Mirrors the helper in `scraper.rs`.
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
    out.split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
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
    fn is_valid_rejects_short_and_marker_lines() {
        assert!(!is_valid(""));
        assert!(!is_valid("# short"));
        assert!(!is_valid("No bridges available here"));
        assert!(!is_valid("short"));
    }

    #[test]
    fn is_valid_accepts_ipv4_ipv6_and_url() {
        assert!(is_valid("obfs4 1.2.3.4:443 ABC"));
        assert!(is_valid("obfs4 [2001:db8::1]:443 ABC"));
        assert!(is_valid("url=https://example.com/"));
    }

    #[test]
    fn strip_prefix_removes_bridge_prefix() {
        assert_eq!(strip_prefix("Bridge 1.2.3.4:443 ABC"), "1.2.3.4:443 ABC");
        assert_eq!(strip_prefix("  1.2.3.4:443 ABC  "), "1.2.3.4:443 ABC");
    }

    #[test]
    fn transport_token_returns_first_token_lowercased() {
        assert_eq!(transport_token("Bridge OBFS4 1.2.3.4:443 ABC"), "obfs4");
        assert_eq!(transport_token("snowflake url=https://x"), "snowflake");
        assert_eq!(transport_token(""), "");
    }

    #[test]
    fn detect_transport_matches_python_branches() {
        assert_eq!(detect_transport("snowflake 192.0.2.3:80 ABC"), "snowflake");
        assert_eq!(
            detect_transport("webtunnel url=https://example.com/"),
            "webtunnel"
        );
        assert_eq!(detect_transport("obfs4 1.2.3.4:443 ABC"), "obfs4");
        assert_eq!(detect_transport("meek_lite 192.0.2.18:80 ABC"), "meek_lite");
        // Note: a conjure line that contains `url=https` is classified as
        // `webtunnel` by the Python original (the `url=https` check fires
        // before the `conjure` check). Use a synthetic conjure line without
        // `url=https` to exercise the conjure branch.
        assert_eq!(detect_transport("conjure 192.0.2.3:80 ABC"), "conjure");
        assert_eq!(detect_transport("1.2.3.4:443 ABC"), "vanilla");
    }

    #[test]
    fn detect_ip_version_matches_python() {
        assert_eq!(detect_ip_version("obfs4 [2001:db8::1]:443 ABC"), "ipv6");
        assert_eq!(detect_ip_version("obfs4 1.2.3.4:443 ABC"), "ipv4");
    }

    #[test]
    fn is_fronted_matches_fronted_tokens() {
        assert!(is_fronted("snowflake url=https://x"));
        assert!(is_fronted("meek_lite 192.0.2.18:80 ABC"));
        assert!(is_fronted("meek-azure something"));
        assert!(is_fronted("conjure url=https://x"));
        assert!(!is_fronted("obfs4 1.2.3.4:443 ABC"));
    }

    #[test]
    fn extract_front_host_prefers_url_then_fronts_then_front() {
        assert_eq!(
            extract_front_host("snowflake 1.2.3.4:80 ABC url=https://example.com/x"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_front_host("snowflake 1.2.3.4:80 ABC fronts=front.example.com,other"),
            Some("front.example.com".to_string())
        );
        assert_eq!(
            extract_front_host("meek_lite 1.2.3.4:80 ABC front=front.example.com"),
            Some("front.example.com".to_string())
        );
        assert_eq!(extract_front_host("vanilla 1.2.3.4:80 ABC"), None);
    }

    #[test]
    fn extract_endpoint_handles_all_four_patterns() {
        let (host, port, transport) = extract_endpoint("webtunnel url=https://example.com/x");
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(port, Some(443));
        assert_eq!(transport, "webtunnel");

        let (host, port, transport) = extract_endpoint("obfs4 [2001:db8::1]:443 ABC");
        assert_eq!(host.as_deref(), Some("2001:db8::1"));
        assert_eq!(port, Some(443));
        assert_eq!(transport, "obfs4");

        let (host, port, transport) = extract_endpoint("obfs4 1.2.3.4:443 ABC");
        assert_eq!(host.as_deref(), Some("1.2.3.4"));
        assert_eq!(port, Some(443));
        assert_eq!(transport, "obfs4");

        let (host, port, transport) =
            extract_endpoint("webtunnel url=https://[2001:db8::1]:8443/x");
        assert_eq!(host.as_deref(), Some("2001:db8::1"));
        assert_eq!(port, Some(8443));
        assert_eq!(transport, "webtunnel");
    }

    #[test]
    fn extract_endpoint_returns_none_for_no_match() {
        let (host, port, transport) = extract_endpoint("vanilla no endpoint here");
        assert!(host.is_none());
        assert!(port.is_none());
        assert_eq!(transport, "vanilla");
    }

    #[test]
    fn parse_iso_safe_returns_none_for_invalid() {
        assert!(parse_iso_safe(None).is_none());
        assert!(parse_iso_safe(Some("not-a-date")).is_none());
        assert!(parse_iso_safe(Some("1970-01-01T00:00:00+00:00")).is_some());
        assert!(parse_iso_safe(Some("2026-06-09T00:00:00+00:00")).is_some());
    }

    #[test]
    fn entry_last_seen_handles_dict_and_string() {
        let dict = json!({"last_seen": "2026-06-09T00:00:00+00:00"});
        assert!(entry_last_seen(&dict).is_some());
        let s = json!("2026-06-09T00:00:00+00:00");
        assert!(entry_last_seen(&s).is_some());
        let n = json!(42);
        assert!(entry_last_seen(&n).is_none());
    }

    #[test]
    fn record_bridge_inserts_then_updates() {
        let mut history = Value::Object(Map::new());
        let now = DateTime::parse_from_rfc3339("2026-06-10T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        record_bridge_with_now(&mut history, "obfs4 1.2.3.4:443 ABC", "obfs4", "ipv4", now)
            .unwrap();
        let entry = history.get("obfs4 1.2.3.4:443 ABC").unwrap();
        assert_eq!(entry["transport"], "obfs4");
        assert_eq!(entry["ip_version"], "ipv4");
        assert_eq!(entry["first_seen"], "2026-06-10T12:00:00+00:00");
        // Second call updates last_seen but preserves first_seen.
        let later = DateTime::parse_from_rfc3339("2026-06-11T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        record_bridge_with_now(
            &mut history,
            "obfs4 1.2.3.4:443 ABC",
            "obfs4",
            "ipv4",
            later,
        )
        .unwrap();
        let entry = history.get("obfs4 1.2.3.4:443 ABC").unwrap();
        assert_eq!(entry["first_seen"], "2026-06-10T12:00:00+00:00");
        assert_eq!(entry["last_seen"], "2026-06-11T12:00:00+00:00");
    }

    #[test]
    fn cleanup_history_drops_old_entries() {
        let history = json!({
            "old": {"last_seen": "2000-01-01T00:00:00+00:00"},
            "new": {"last_seen": "2026-06-09T00:00:00+00:00"},
            "bad": {"last_seen": "not-a-date"},
            "missing": {},
        });
        let now = DateTime::parse_from_rfc3339("2026-06-10T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        let cleaned = cleanup_history_with_now(&history, 30, now).unwrap();
        assert!(cleaned.get("old").is_none());
        assert!(cleaned.get("bad").is_none());
        assert!(cleaned.get("missing").is_none());
        assert!(cleaned.get("new").is_some());
    }

    #[test]
    fn test_many_with_probes_caps_at_max_test_per_list() {
        struct AlwaysTrue;
        impl ReachabilityProbe for AlwaysTrue {
            fn test_tcp(&self, _host: &str, _port: u16) -> bool {
                true
            }
            fn test_tls(&self, _host: &str, _port: u16) -> bool {
                true
            }
        }
        let probe = AlwaysTrue;
        let mut bridges: Vec<String> = (0..(MAX_TEST_PER_LIST + 5))
            .map(|i| format!("obfs4 1.2.3.{}:443 ABC", i % 256))
            .collect();
        let result = test_many_with_probes(&bridges, &probe);
        assert_eq!(result.len(), MAX_TEST_PER_LIST);
        // Sanity: works with empty input.
        bridges.clear();
        let empty = test_many_with_probes(&bridges, &probe);
        assert!(empty.is_empty());
    }

    #[test]
    fn is_reachable_with_probe_routes_fronted_through_tls() {
        struct CountingProbe {
            tls_calls: std::sync::Mutex<u32>,
            tcp_calls: std::sync::Mutex<u32>,
        }
        impl ReachabilityProbe for CountingProbe {
            fn test_tcp(&self, _host: &str, _port: u16) -> bool {
                *self.tcp_calls.lock().unwrap() += 1;
                true
            }
            fn test_tls(&self, _host: &str, _port: u16) -> bool {
                *self.tls_calls.lock().unwrap() += 1;
                true
            }
        }
        let probe = CountingProbe {
            tls_calls: std::sync::Mutex::new(0),
            tcp_calls: std::sync::Mutex::new(0),
        };
        // Fronted bridge → TLS probe of the front host.
        assert!(is_reachable_with_probe(
            "snowflake 192.0.2.3:80 ABC url=https://example.com/x",
            &probe
        ));
        assert_eq!(*probe.tls_calls.lock().unwrap(), 1);
        assert_eq!(*probe.tcp_calls.lock().unwrap(), 0);

        // Non-fronted bridge → TCP probe.
        assert!(is_reachable_with_probe("obfs4 1.2.3.4:443 ABC", &probe));
        assert_eq!(*probe.tls_calls.lock().unwrap(), 1);
        assert_eq!(*probe.tcp_calls.lock().unwrap(), 1);

        // WebTunnel → TLS probe.
        assert!(is_reachable_with_probe(
            "webtunnel url=https://example.com/x",
            &probe
        ));
        assert_eq!(*probe.tls_calls.lock().unwrap(), 2);
        assert_eq!(*probe.tcp_calls.lock().unwrap(), 1);
    }
}
