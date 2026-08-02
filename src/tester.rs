//! Parity port of `core/tester.py` (parsing functions only).
//!
//! The Python original also contains async TCP/SSL probing functions that
//! perform real network I/O. Those are NOT ported here — they're
//! environment-specific and would require `tokio` + `tokio-rustls` which
//! are out of scope for the current migration phase. The pure parsing
//! functions (`detect_transport`, `extract_endpoint`, `is_ip`) ARE ported
//! with byte-identical parity.
//!
//! Network-dependent functions (`probe_vanilla`, `probe_obfs4`,
//! `probe_webtunnel`, `test_bridge`) are flagged in MIGRATION_NOTES.md as
//! "pending — requires tokio + tokio-rustls". Callers needing live probing
//! should use the `bridge-probe` binary (already in Rust) which covers the
//! same functionality.

use regex::Regex;

/// Mirror of `detect_transport(line)`. Returns one of:
/// "snowflake", "webtunnel", "obfs4", "meek_lite", "vanilla".
///
/// Branch order matches Python exactly:
/// 1. "snowflake" → "snowflake"
/// 2. "webtunnel" OR "url=https" → "webtunnel"
/// 3. "obfs4" → "obfs4"
/// 4. "meek" → "meek_lite"
/// 5. fallback → "vanilla"
pub fn detect_transport(line: &str) -> &'static str {
    let l = line.to_ascii_lowercase();
    if l.contains("snowflake") {
        return "snowflake";
    }
    if l.contains("webtunnel") || l.contains("url=https") {
        return "webtunnel";
    }
    if l.contains("obfs4") {
        return "obfs4";
    }
    if l.contains("meek") {
        return "meek_lite";
    }
    "vanilla"
}

/// Mirror of `extract_endpoint(line)`. Returns `(host, port, transport)`.
/// Strips a leading `"Bridge "` prefix before parsing.
///
/// Parsing order matches Python exactly:
/// 1. For webtunnel/meek_lite/snowflake: prefer HTTPS URL host (`https?://host[:port]`)
/// 2. IPv6 `[addr]:port`
/// 3. IPv4 `addr:port`
/// 4. Domain:port (`.net/.com/.org/.io/.dev`)
/// 5. Fallback: `(None, None, transport)`
pub fn extract_endpoint(line: &str) -> (Option<String>, Option<u16>, &'static str) {
    let mut line = line.trim().to_string();
    if line.starts_with("Bridge ") {
        line = line[7..].to_string();
    }

    let transport = detect_transport(&line);

    // WebTunnel / meek / snowflake: prefer HTTPS URL host
    if transport == "webtunnel" || transport == "meek_lite" || transport == "snowflake" {
        let https_re = Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").unwrap();
        if let Some(caps) = https_re.captures(&line) {
            let host = caps.get(1).map(|m| m.as_str().to_string());
            let port = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<u16>().ok())
                .or(Some(443));
            return (host, port, transport);
        }
    }

    // IPv6 [addr]:port
    let ip6_re = Regex::new(r"\[([0-9a-fA-F:]+)\]:(\d+)").unwrap();
    if let Some(caps) = ip6_re.captures(&line) {
        let host = caps.get(1).map(|m| m.as_str().to_string());
        let port = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok());
        return (host, port, transport);
    }

    // IPv4 addr:port
    let ip4_re = Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})").unwrap();
    if let Some(caps) = ip4_re.captures(&line) {
        let host = caps.get(1).map(|m| m.as_str().to_string());
        let port = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok());
        return (host, port, transport);
    }

    // Domain:port (fallback)
    let domain_re = Regex::new(r"([a-zA-Z0-9._-]+\.(?:net|com|org|io|dev)):(\d+)").unwrap();
    if let Some(caps) = domain_re.captures(&line) {
        let host = caps.get(1).map(|m| m.as_str().to_string());
        let port = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok());
        return (host, port, transport);
    }

    (None, None, transport)
}

/// Mirror of `is_ip(host)`. Returns `true` if `host` is a valid IPv4 or
/// IPv6 address.
pub fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_transport_branches() {
        assert_eq!(
            detect_transport("snowflake 192.0.2.3:1 url=https://x"),
            "snowflake"
        );
        assert_eq!(
            detect_transport("webtunnel 192.0.2.4:443 url=https://y"),
            "webtunnel"
        );
        assert_eq!(detect_transport("obfs4 1.2.3.4:443 cert=abc"), "obfs4");
        assert_eq!(
            detect_transport("meek_lite 192.0.2.5:80 url=https://y"),
            "webtunnel"
        ); // url=https wins
        assert_eq!(
            detect_transport("meek_lite 192.0.2.5:80 front=z"),
            "meek_lite"
        );
        assert_eq!(detect_transport("vanilla 1.2.3.4:9001"), "vanilla");
    }

    #[test]
    fn extract_endpoint_strips_bridge_prefix() {
        let (h, p, t) = extract_endpoint("Bridge obfs4 1.2.3.4:443 cert=abc");
        assert_eq!(h.as_deref(), Some("1.2.3.4"));
        assert_eq!(p, Some(443));
        assert_eq!(t, "obfs4");
    }

    #[test]
    fn extract_endpoint_https_url_default_port() {
        let (h, p, t) = extract_endpoint("webtunnel x url=https://example.com/path");
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(p, Some(443));
        assert_eq!(t, "webtunnel");
    }

    #[test]
    fn extract_endpoint_https_url_explicit_port() {
        let (h, p, t) = extract_endpoint("webtunnel x url=https://example.com:8443/path");
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(p, Some(8443));
        assert_eq!(t, "webtunnel");
    }

    #[test]
    fn extract_endpoint_ipv6() {
        let (h, p, t) = extract_endpoint("obfs4 [2001:db8::1]:443 cert=abc");
        assert_eq!(h.as_deref(), Some("2001:db8::1"));
        assert_eq!(p, Some(443));
        assert_eq!(t, "obfs4");
    }

    #[test]
    fn extract_endpoint_ipv4() {
        let (h, p, t) = extract_endpoint("obfs4 1.2.3.4:443 cert=abc");
        assert_eq!(h.as_deref(), Some("1.2.3.4"));
        assert_eq!(p, Some(443));
        assert_eq!(t, "obfs4");
    }

    #[test]
    fn extract_endpoint_domain_port() {
        let (h, p, t) = extract_endpoint("obfs4 example.com:443 cert=abc");
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(p, Some(443));
        assert_eq!(t, "obfs4");
    }

    #[test]
    fn extract_endpoint_no_match_returns_none_with_transport() {
        let (h, p, t) = extract_endpoint("just a plain string");
        assert_eq!(h, None);
        assert_eq!(p, None);
        assert_eq!(t, "vanilla");
    }

    #[test]
    fn is_ip_validates_ipv4_and_ipv6() {
        assert!(is_ip("1.2.3.4"));
        assert!(is_ip("2001:db8::1"));
        assert!(!is_ip("example.com"));
        assert!(!is_ip("not-an-ip"));
    }
}
