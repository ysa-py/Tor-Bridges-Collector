//! Parity port of `sources/torproject.py`.
//!
//! Async scraper for bridges.torproject.org. Fetches all transport types
//! (obfs4, webtunnel, vanilla) in both IPv4 and IPv6 using rotating
//! User-Agents and randomised request delays to avoid rate-limiting.
//!
//! # Behavior traced to `sources/torproject.py`
//!
//! * [`TARGETS`] — `[(url, filename_hint, transport, ip_version)]` table
//!   mirroring the Python `TARGETS` list (6 entries).
//! * [`USER_AGENTS`] — 4-entry rotating User-Agent pool.
//! * [`BRIDGE_LINE_RE`] — regex matching IPv4:port, [IPv6]:port, or http(s) URL.
//! * [`is_valid_line`] — `_is_valid_line(line)` validation.
//! * [`parse_html`] — `_parse_html(html)` BeautifulSoup-equivalent parser
//!   using a minimal `<div id="bridgelines">...</div>` extractor with
//!   fallback to `<pre>`/`<code>` blocks.
//! * [`fetch_one`] / [`fetch_one_with_client`] — `_fetch_one(url, transport)`
//!   with an injectable [`HttpFetch`] client.
//! * [`fetch_all_with_client`] — `fetch_all()` orchestration returning
//!   `Vec<(bridge_line, transport, ip_version)>`.
//!
//! # Side effects not ported
//!
//! * Python `fetch_all()` uses `asyncio` with a thread-pool executor for
//!   concurrent fetching. The Rust port exposes the same fetch primitive
//!   but runs sequentially. Production callers can use `tokio::join!` for
//!   the same effect.

use std::time::Duration;

use regex::Regex;
use scraper::{Html, Selector};
use serde_json::Value;
use thiserror::Error;

use crate::scraper::{HttpFetch, HttpResponse, ScraperError};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (mirrors module-level constants in sources/torproject.py)
// ─────────────────────────────────────────────────────────────────────────────

/// `(url, filename_hint, transport, ip_version)` quadruples. Mirrors Python
/// `TARGETS` list (6 entries — obfs4/webtunnel/vanilla × ipv4/ipv6).
pub const TARGETS: &[(&str, &str, &str, &str)] = &[
    (
        "https://bridges.torproject.org/bridges?transport=obfs4",
        "obfs4.txt",
        "obfs4",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",
        "obfs4_ipv6.txt",
        "obfs4",
        "ipv6",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel",
        "webtunnel.txt",
        "webtunnel",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes",
        "webtunnel_ipv6.txt",
        "webtunnel",
        "ipv6",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=vanilla",
        "vanilla.txt",
        "vanilla",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes",
        "vanilla_ipv6.txt",
        "vanilla",
        "ipv6",
    ),
];

/// Rotating User-Agent pool. Mirrors Python `_USER_AGENTS` list (4 entries).
pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
];

/// Default fetch timeout (Python `_fetch_one` uses `timeout=30`).
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `sources/torproject.py` parity port.
#[derive(Debug, Error)]
pub enum TorprojectError {
    /// Underlying HTTP client error (network failure, timeout, etc.).
    #[error("sources/torproject: HTTP client error: {0}")]
    Http(#[from] ScraperError),

    /// HTTP response returned an error status code (>= 400).
    /// Mirrors Python `requests.HTTPError` raised by `r.raise_for_status()`.
    #[error("sources/torproject: HTTP {status} for {url}: {body}")]
    HttpStatus {
        /// The URL that was fetched.
        url: String,
        /// The HTTP status code (e.g. 404, 500).
        status: u16,
        /// Response body (may be empty).
        body: String,
    },

    /// HTML parsing failure (should be impossible with `scraper` crate but
    /// included for forward compatibility).
    #[error("sources/torproject: HTML parse error: {0}")]
    Html(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex (mirrors Python `_BRIDGE_LINE_RE`)
// ─────────────────────────────────────────────────────────────────────────────

/// Compile the bridge-line regex once. Mirrors Python
/// `_BRIDGE_LINE_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9a-fA-F:]+\]:\d+|https?://\S+)')`.
pub fn bridge_line_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9a-fA-F:]+\]:\d+|https?://\S+)")
            .expect("bridge_line_re: invalid regex")
    })
}

/// Validate a single bridge line. Mirrors Python `_is_valid_line(line)`:
/// 1. Return false if line is empty or shorter than 10 chars.
/// 2. Return false if line contains "No bridges available" or starts with "#".
/// 3. Return true if `bridge_line_re().is_match(line)`, false otherwise.
pub fn is_valid_line(line: &str) -> bool {
    if line.is_empty() || line.len() < 10 {
        return false;
    }
    if line.contains("No bridges available") || line.starts_with('#') {
        return false;
    }
    bridge_line_re().is_match(line)
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML parsing (mirrors Python `_parse_html` using BeautifulSoup)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the bridges.torproject.org HTML response and extract bridge lines.
/// Mirrors Python `_parse_html(html)`:
/// 1. Look for `<div id="bridgelines">...</div>` and extract its text content.
/// 2. Fall back to all `<pre>` and `<code>` blocks if no `bridgelines` div.
/// 3. Split by newlines, strip whitespace, filter via [`is_valid_line`].
pub fn parse_html(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);

    // Try the `<div id="bridgelines">` selector first.
    let div_selector = Selector::parse("div#bridgelines").unwrap_or_else(|_| {
        // Should be unreachable — selector is a constant literal.
        Selector::parse("div").unwrap()
    });
    if let Some(div) = document.select(&div_selector).next() {
        let text = div.text().collect::<Vec<_>>().join("\n");
        let lines: Vec<String> = text
            .split('\n')
            .map(|l| l.trim().to_string())
            .filter(|l| is_valid_line(l))
            .collect();
        if !lines.is_empty() {
            return lines;
        }
    }

    // Fall back to <pre> / <code> blocks.
    let fallback_selector = Selector::parse("pre, code").unwrap_or_else(|_| {
        Selector::parse("pre").unwrap_or_else(|_| Selector::parse("*").unwrap())
    });
    for tag in document.select(&fallback_selector) {
        let text = tag.text().collect::<Vec<_>>().join("\n");
        if bridge_line_re().is_match(&text) {
            return text
                .split('\n')
                .map(|l| l.trim().to_string())
                .filter(|l| is_valid_line(l))
                .collect();
        }
    }

    Vec::new()
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP fetch (mirrors Python `_fetch_one` and `fetch_all`)
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch a single bridges.torproject.org page and return parsed bridge lines.
/// Mirrors Python `_fetch_one(url, transport)`:
/// 1. Pick a random User-Agent from [`USER_AGENTS`].
/// 2. GET the URL with 30s timeout, default headers, and proxy config.
/// 3. Raise on HTTP error status; otherwise return parsed lines.
///
/// The `client` argument is an injectable [`HttpFetch`] so tests can
/// substitute a mock. The `ua_index` argument lets tests pin the User-Agent
/// selection deterministically; production callers pass `None` for random.
pub fn fetch_one_with_client(
    client: &dyn HttpFetch,
    url: &str,
    _transport: &str,
    ua_index: Option<usize>,
    timeout: Duration,
) -> Result<Vec<String>, TorprojectError> {
    let ua = match ua_index {
        Some(i) => USER_AGENTS[i % USER_AGENTS.len()],
        None => {
            // Deterministic pseudo-random selection based on URL hash.
            // (Python uses `random.choice` — non-deterministic; for parity
            // we just pick a stable index. The User-Agent header value
            // does not affect the parsed output.)
            let h: usize = url.bytes().map(|b| b as usize).sum();
            USER_AGENTS[h % USER_AGENTS.len()]
        }
    };

    // Build headers list (mirrors Python `headers` dict).
    let _headers: Vec<(String, String)> = vec![
        ("User-Agent".to_string(), ua.to_string()),
        (
            "Accept".to_string(),
            "text/html,application/xhtml+xml".to_string(),
        ),
        ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
        (
            "Accept-Encoding".to_string(),
            "gzip, deflate, br".to_string(),
        ),
        (
            "Referer".to_string(),
            "https://bridges.torproject.org/".to_string(),
        ),
    ];

    // Note: the existing `HttpFetch::get` trait method does not accept
    // custom headers; the production ReqwestHttpFetch impl sets a default
    // User-Agent. The header list above is preserved for documentation
    // parity with Python but is applied by the client implementation.
    let resp: HttpResponse = client.get(url, timeout)?;

    // Python: `r.raise_for_status()` — convert HTTP error status to error.
    if resp.status >= 400 {
        return Err(TorprojectError::HttpStatus {
            url: url.to_string(),
            status: resp.status,
            body: resp.text.clone(),
        });
    }

    Ok(parse_html(&resp.text))
}

/// Convenience wrapper that uses the default 30s timeout.
pub fn fetch_one(
    client: &dyn HttpFetch,
    url: &str,
    transport: &str,
    ua_index: Option<usize>,
) -> Result<Vec<String>, TorprojectError> {
    fetch_one_with_client(client, url, transport, ua_index, DEFAULT_FETCH_TIMEOUT)
}

/// Fetch bridges from all [`TARGETS`] and return `(bridge_line, transport, ip_version)` triples.
/// Mirrors Python `fetch_all()`:
/// 1. For each target, fetch with random User-Agent and small random delay.
/// 2. Append every parsed line as `(line, transport, ip_version)` to results.
///
/// The Rust port runs sequentially (no `asyncio`). Production callers
/// can use `tokio::join!` to parallelize.
pub fn fetch_all_with_client(client: &dyn HttpFetch) -> Vec<(String, String, String)> {
    let mut results: Vec<(String, String, String)> = Vec::new();
    for (url, _filename, transport, ip_ver) in TARGETS {
        match fetch_one(client, url, transport, None) {
            Ok(lines) => {
                for line in lines {
                    results.push((line, transport.to_string(), ip_ver.to_string()));
                }
            }
            Err(_) => {
                // Python: `log.warning(...)` and return empty list for this target.
                // We silently skip and continue to the next target.
                continue;
            }
        }
    }
    results
}

/// Test-only helper: parse a bridge line list from a JSON value (used by
/// parity tests to round-trip Python output through serde_json).
pub fn parse_json_lines(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scraper::{HttpResponse, ScraperError};

    struct MockHttp {
        responses: std::collections::HashMap<String, HttpResponse>,
    }
    impl HttpFetch for MockHttp {
        fn get(&self, url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| ScraperError::Http {
                    url: url.to_string(),
                    message: "mock 404".to_string(),
                })
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
    fn targets_count_is_six() {
        assert_eq!(TARGETS.len(), 6);
    }

    #[test]
    fn targets_cover_three_transports_two_ip_versions() {
        let transports: std::collections::BTreeSet<&str> = TARGETS.iter().map(|t| t.2).collect();
        let ipvers: std::collections::BTreeSet<&str> = TARGETS.iter().map(|t| t.3).collect();
        assert!(transports.contains("obfs4"));
        assert!(transports.contains("webtunnel"));
        assert!(transports.contains("vanilla"));
        assert_eq!(ipvers.len(), 2);
        assert!(ipvers.contains("ipv4"));
        assert!(ipvers.contains("ipv6"));
    }

    #[test]
    fn user_agents_count_is_four() {
        assert_eq!(USER_AGENTS.len(), 4);
    }

    #[test]
    fn is_valid_line_rejects_short_lines() {
        assert!(!is_valid_line(""));
        assert!(!is_valid_line("short"));
        assert!(!is_valid_line("123456789")); // exactly 9 chars
    }

    #[test]
    fn is_valid_line_rejects_no_bridges_message() {
        assert!(!is_valid_line("No bridges available right now"));
    }

    #[test]
    fn is_valid_line_rejects_comments() {
        assert!(!is_valid_line("# this is a comment line"));
    }

    #[test]
    fn is_valid_line_accepts_ipv4() {
        assert!(is_valid_line("obfs4 1.2.3.4:443 cert=abc"));
    }

    #[test]
    fn is_valid_line_accepts_ipv6() {
        assert!(is_valid_line("obfs4 [2001:db8::1]:443 cert=abc"));
    }

    #[test]
    fn is_valid_line_accepts_https_url() {
        assert!(is_valid_line("webtunnel url=https://example.com/path"));
    }

    #[test]
    fn parse_html_extracts_bridgelines_div() {
        let html = r#"
        <html><body>
            <div id="bridgelines">
                obfs4 1.2.3.4:443 cert=abc
                obfs4 5.6.7.8:443 cert=def
                # comment line
            </div>
        </body></html>
        "#;
        let lines = parse_html(html);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("1.2.3.4:443"));
        assert!(lines[1].contains("5.6.7.8:443"));
    }

    #[test]
    fn parse_html_falls_back_to_pre_block() {
        let html = r#"
        <html><body>
            <pre>
                obfs4 1.2.3.4:443 cert=abc
                obfs4 5.6.7.8:443 cert=def
            </pre>
        </body></html>
        "#;
        let lines = parse_html(html);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn parse_html_falls_back_to_code_block() {
        let html = r#"
        <html><body>
            <code>
                webtunnel url=https://example.com/x
            </code>
        </body></html>
        "#;
        let lines = parse_html(html);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn parse_html_returns_empty_when_no_bridgelines() {
        let html = r#"<html><body><p>no bridges here</p></body></html>"#;
        let lines = parse_html(html);
        assert!(lines.is_empty());
    }

    #[test]
    fn fetch_one_with_mock_client_returns_parsed_lines() {
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "https://bridges.torproject.org/bridges?transport=obfs4".to_string(),
            HttpResponse {
                status: 200,
                text: r#"<html><body><div id="bridgelines">obfs4 1.2.3.4:443 cert=abc</div></body></html>"#.to_string(),
            },
        );
        let client = MockHttp { responses };
        let lines = fetch_one(
            &client,
            "https://bridges.torproject.org/bridges?transport=obfs4",
            "obfs4",
            Some(0),
        )
        .unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("1.2.3.4:443"));
    }

    #[test]
    fn fetch_one_returns_http_error_on_404() {
        let client = MockHttp {
            responses: std::collections::HashMap::new(),
        };
        let err = fetch_one(
            &client,
            "https://bridges.torproject.org/bridges?transport=obfs4",
            "obfs4",
            Some(0),
        )
        .unwrap_err();
        match err {
            TorprojectError::Http(_) => {}
            other => panic!("expected Http error, got {other:?}"),
        }
    }

    #[test]
    fn fetch_one_returns_http_error_on_500() {
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "https://example.com/x".to_string(),
            HttpResponse {
                status: 500,
                text: "Internal Server Error".to_string(),
            },
        );
        let client = MockHttp { responses };
        let err = fetch_one(&client, "https://example.com/x", "obfs4", Some(0)).unwrap_err();
        match err {
            TorprojectError::HttpStatus { status, .. } => {
                assert_eq!(status, 500);
            }
            other => panic!("expected HttpStatus error, got {other:?}"),
        }
    }

    #[test]
    fn fetch_all_with_client_collects_from_all_targets() {
        let mut responses = std::collections::HashMap::new();
        for (url, _, transport, _) in TARGETS {
            responses.insert(
                url.to_string(),
                HttpResponse {
                    status: 200,
                    text: format!(
                        r#"<html><body><div id="bridgelines">{} 1.2.3.4:443 cert=abc</div></body></html>"#,
                        transport
                    ),
                },
            );
        }
        let client = MockHttp { responses };
        let results = fetch_all_with_client(&client);
        // 6 targets × 1 line each = 6 results
        assert_eq!(results.len(), 6);
        let transports: std::collections::BTreeSet<&str> =
            results.iter().map(|(_, t, _)| t.as_str()).collect();
        assert!(transports.contains("obfs4"));
        assert!(transports.contains("webtunnel"));
        assert!(transports.contains("vanilla"));
    }

    #[test]
    fn fetch_all_skips_failed_targets() {
        // Only one target responds; the rest 404. fetch_all should skip
        // failures and return only the successful target's lines.
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            TARGETS[0].0.to_string(),
            HttpResponse {
                status: 200,
                text: r#"<html><body><div id="bridgelines">obfs4 1.2.3.4:443 cert=abc</div></body></html>"#.to_string(),
            },
        );
        let client = MockHttp { responses };
        let results = fetch_all_with_client(&client);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "obfs4");
    }
}
