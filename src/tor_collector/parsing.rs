//! Bridge-line validation, normalization, and endpoint extraction.
//!
//! The routines in this module intentionally accept the forms emitted by both
//! legacy collectors: raw vanilla lines, `Bridge `-prefixed historical lines,
//! bracketed IPv6 endpoints, and `url=https://…` WebTunnel/fronted lines.

use std::net::IpAddr;

use regex::Regex;
use url::Url;

use super::config::Transport;

/// Parsed host/port endpoint extracted from a bridge line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// Literal IP address or DNS hostname.
    pub host: String,
    /// TCP port to contact.
    pub port: u16,
    /// Address family for the literal endpoint, if it can be determined.
    pub address_family: String,
}

/// Parsed IPv4 obfs4 client arguments for the SOCKS harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Obfs4Endpoint {
    /// IPv4 bridge address.
    pub host: String,
    /// Bridge TCP port.
    pub port: u16,
    /// `cert=…;iat-mode=…` SOCKS username payload expected by obfs4proxy.
    pub socks_args: String,
}

/// Return whether `line` is a potentially usable bridge line.
///
/// This is deliberately regex-equivalent to the Python checks: a line must
/// contain an IPv4 literal, bracketed IPv6 literal, or HTTP(S) endpoint. More
/// detailed validation happens when an endpoint is extracted.
pub fn is_valid_bridge_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.contains("No bridges available")
        || trimmed.len() < 10
    {
        return false;
    }

    if contains_documentation_or_reserved_endpoint(trimmed) {
        return false;
    }

    if transport_token(trimmed) == "webtunnel" {
        // Accept any ver= version (0.0.1 through 0.0.4+), not just 0.0.4.
        let ver = token_value(trimmed, "ver");
        if ver.is_none() {
            return false;
        }
        // v2.6.1: Domain-only WebTunnel bridges (no literal IP endpoint, only
        // url=https://front/path) are now accepted. Downstream testers must
        // perform TLS+WebSocket Upgrade probes against the URL front domain
        // instead of raw TCP to a nonexistent endpoint.
    }

    if let Some(ref token) = first_fingerprint_like_token(trimmed) {
        if !is_canonical_fingerprint(token) {
            return false;
        }
    }

    Regex::new(r"\d+\.\d+\.\d+\.\d+|\[[0-9A-Fa-f:]+\]|https?://")
        .map(|regex| regex.is_match(trimmed))
        .unwrap_or(false)
}

/// Remove the optional `Bridge ` prefix and normalize surrounding whitespace.
pub fn strip_bridge_prefix(line: &str) -> String {
    let trimmed = line.trim();
    trimmed
        .strip_prefix("Bridge ")
        .unwrap_or(trimmed)
        .trim()
        .to_owned()
}

/// Normalize a line for clean, raw bridge-list files.
pub fn clean_output_line(line: &str) -> String {
    strip_bridge_prefix(line)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalize a vanilla line for the legacy history convention.
///
/// `vip.py` uses a `Bridge ` prefix for vanilla history keys while output files
/// contain raw endpoint lines. Keeping this distinction avoids turning raw
/// vanilla files into Tor configuration fragments.
pub fn normalize_vanilla_for_history(line: &str) -> String {
    let raw = clean_output_line(line);
    if raw.is_empty() {
        String::new()
    } else {
        format!("Bridge {raw}")
    }
}

/// Return the leading bridge transport token, lowercased.
pub fn transport_token(line: &str) -> String {
    strip_bridge_prefix(line)
        .split_whitespace()
        .next()
        .map(|token| token.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Infer the transport family from the first whitespace-delimited token.
///
/// This is intentionally token-based rather than substring-contains so it
/// never misclassifies a bridge line whose fingerprint, certificate, or URL
/// happens to contain a transport name.  When the first token looks like an
/// endpoint (contains `:` or is an IP-like dotted quad) rather than a
/// transport name, the line is classified as `Vanilla`.
pub fn detect_transport(line: &str) -> Transport {
    let token = transport_token(line);
    if token.is_empty() {
        if line.to_ascii_lowercase().contains("url=https") {
            return Transport::WebTunnel;
        }
        return Transport::Vanilla;
    }
    match token.as_str() {
        "vanilla" => Transport::Vanilla,
        "obfs4" => Transport::Obfs4,
        "webtunnel" => Transport::WebTunnel,
        "snowflake" => Transport::Snowflake,
        "meek_lite" | "meek" | "meek-azure" => Transport::MeekAzure,
        "conjure" => Transport::Conjure,
        "vless" | "vless+reality" | "reality" => Transport::VlessReality,
        "hysteria2" | "hysteria" => Transport::Hysteria2,
        "tuic" => Transport::Tuic,
        "shadowtls" => Transport::ShadowTls,
        "anytls" => Transport::Anytls,
        "http-upgrade" | "httpupgrade" => Transport::HttpUpgrade,
        "grpc" => Transport::Grpc,
        _ => {
            // The first token didn't match any known transport.  If it looks
            // like a literal endpoint (contains ':' port separator, or is a
            // dotted quad), treat the line as a bare Vanilla endpoint.
            if token.contains(':') || looks_like_ipv4(&token) {
                Transport::Vanilla
            } else {
                Transport::Unknown
            }
        }
    }
}

/// Heuristic: the token matches an IPv4 dotted-quad pattern.
fn looks_like_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Return whether a line has a fronted transport token.
pub fn is_fronted_line(line: &str) -> bool {
    detect_transport(line).is_fronted()
}

// ── Unified parsed bridge line ────────────────────────────────────────────

/// All extractable fields from a bridge line, parsed generically without
/// transport-specific field-position assumptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedBridgeLine {
    /// Detected transport family.
    pub transport: String,
    /// SNI / TLS server name (from `url=` host, `front=`, `fronts=`, or `sni=`).
    pub sni: Option<String>,
    /// First IPv4 endpoint address, if any.
    pub ipv4: Option<String>,
    /// First IPv6 endpoint address, if any.
    pub ipv6: Option<String>,
    /// TCP port extracted from the primary endpoint or URL.
    pub port: Option<u16>,
    /// Protocol version (`ver=` field).
    pub version: Option<String>,
    /// Full `url=` value, if present.
    pub url: Option<String>,
    /// Canonical bridge fingerprint, if present.
    pub fingerprint: Option<String>,
    /// Raw transport token (first word).
    pub transport_token: Option<String>,
    /// All key=value pairs found on the line.
    pub kv_pairs: std::collections::BTreeMap<String, String>,
}

impl ParsedBridgeLine {
    /// Return the effective connection host: the SNI/host to dial for a
    /// transport handshake.  For domain-fronted lines this is the front
    /// domain; for direct lines it is the literal endpoint.
    pub fn dial_host(&self) -> Option<&str> {
        self.sni
            .as_deref()
            .or(self.ipv4.as_deref())
            .or(self.ipv6.as_deref())
    }

    /// Return the effective connection port.
    pub fn dial_port(&self) -> Option<u16> {
        self.port
    }
}

/// Parse a bridge line into all known fields dynamically.
///
/// The parser scans every whitespace-delimited token exactly once and
/// classifies each as either a key=value pair (stored in `kv_pairs` plus
/// extracted into typed fields), a literal endpoint (IPv4, IPv6, or DNS
/// name with port), a fingerprint, or the transport token.  No token is
/// hardcoded to a particular position, and the function never assumes a
/// transport-specific field layout — it works uniformly for every line
/// format the project has encountered and any future format that follows
/// the same token conventions.
pub fn parse_bridge_line(line: &str) -> ParsedBridgeLine {
    let mut parsed = ParsedBridgeLine::default();
    let raw = strip_bridge_prefix(line);
    if raw.is_empty() {
        return parsed;
    }

    let mut tokens = raw.split_whitespace().peekable();

    // ── Transport token (first word) ──
    if let Some(first) = tokens.next() {
        // A first token that is not a key=value and is not an endpoint
        // is the transport name.
        if !first.contains('=')
            && !first.contains(':')
            && !first.starts_with("http://")
            && !first.starts_with("https://")
        {
            parsed.transport_token = Some(first.to_ascii_lowercase());
        } else {
            // Put it back — it's not a transport token, re-process below.
            // We work around this by collecting all tokens upfront.
        }
    }

    // ── Scan all tokens ──
    let all_tokens: Vec<&str> = {
        let v: Vec<&str> = raw.split_whitespace().collect();
        // If the first token was a transport name, it's already consumed;
        // the remaining tokens start from index 1.
        if parsed.transport_token.is_some() && v.len() > 1 {
            v[1..].to_vec()
        } else {
            v
        }
    };

    let mut seen_endpoint = false;
    for token in &all_tokens {
        // ── key=value pairs ──
        if let Some((key, value)) = token.split_once('=') {
            let key_lower = key.trim_matches('"').to_ascii_lowercase();
            let val = value.trim_matches('"').to_string();

            // Track every key=value generically
            parsed.kv_pairs.insert(key_lower.clone(), val.clone());

            // Extract well-known fields
            match key_lower.as_str() {
                "url" => {
                    if val.starts_with("https://") || val.starts_with("http://") {
                        parsed.url = Some(val.clone());
                    }
                }
                "ver" | "version" => {
                    parsed.version = Some(val.clone());
                }
                "sni" => {
                    parsed.sni = Some(val.clone());
                }
                "front" => {
                    parsed.sni = Some(val.clone());
                }
                "fronts" => {
                    // Use first front from comma-separated list
                    parsed.sni = val
                        .split(',')
                        .map(str::trim)
                        .find(|h| !h.is_empty())
                        .map(String::from);
                }
                "fingerprint" | "cert" | "iat-mode" | "ice" | "utls-imitate" | "transport"
                | "path" | "host" | "alpn" | "quic" | "password" | "uuid" | "aid" | "security"
                | "encryption" | "flow" | "headerType" | "requestHost" | "serviceName" | "mode" => {
                    // These are tracked in kv_pairs but have no typed field
                }
                _ => {}
            }
            continue;
        }

        // ── URL tokens (bare https://…) ──
        if token.starts_with("https://") || token.starts_with("http://") {
            parsed.url = Some(token.to_string());
            if let Ok(u) = url::Url::parse(token) {
                if let Some(host) = u.host_str() {
                    if parsed.sni.is_none() {
                        parsed.sni = Some(host.to_owned());
                    }
                }
                if parsed.port.is_none() {
                    parsed.port = u.port_or_known_default();
                }
            }
            continue;
        }

        // ── Fingerprint ──
        if parsed.fingerprint.is_none() && is_canonical_fingerprint(token) {
            parsed.fingerprint = Some(token.to_ascii_uppercase());
            continue;
        }

        // ── Literal endpoint (IP:port or [IPv6]:port or DNS:port) ──
        if !seen_endpoint {
            if let Some(ep) = endpoint_from_token(token) {
                seen_endpoint = true;
                match ep.address_family.as_str() {
                    "ipv4" => {
                        parsed.ipv4 = Some(ep.host);
                        parsed.port = Some(ep.port);
                    }
                    "ipv6" => {
                        parsed.ipv6 = Some(ep.host);
                        parsed.port = Some(ep.port);
                    }
                    "dns" => {
                        parsed.sni = Some(ep.host);
                        parsed.port = Some(ep.port);
                    }
                    _ => {}
                }
                continue;
            }
        }
    }

    // ── Post-processing: extract SNI/port from URL if not yet set ──
    if let Some(ref u) = parsed.url {
        if parsed.sni.is_none() {
            if let Ok(parsed_url) = url::Url::parse(u) {
                if let Some(host) = parsed_url.host_str() {
                    parsed.sni = Some(host.to_owned());
                }
            }
        }
        if parsed.port.is_none() {
            if let Ok(parsed_url) = url::Url::parse(u) {
                parsed.port = parsed_url.port_or_known_default();
            }
        }
    }

    // ── Transport ──
    parsed.transport = if let Some(ref token) = parsed.transport_token {
        detect_transport_from_token(token)
    } else {
        detect_transport(line).to_string()
    };

    parsed
}

/// Map a transport token string to the canonical transport name,
/// without requiring the full Transport enum import at call sites.
fn detect_transport_from_token(token: &str) -> String {
    match token {
        "vanilla" => "vanilla",
        "obfs4" => "obfs4",
        "webtunnel" => "webtunnel",
        "snowflake" => "snowflake",
        "meek_lite" | "meek" | "meek-azure" => "meek-azure",
        "conjure" => "conjure",
        "vless" | "vless+reality" | "reality" => "vless-reality",
        "hysteria2" | "hysteria" => "hysteria2",
        "tuic" => "tuic",
        "shadowtls" => "shadowtls",
        "anytls" => "anytls",
        "http-upgrade" | "httpupgrade" => "http-upgrade",
        "grpc" => "grpc",
        _ => "unknown",
    }
    .to_string()
}

/// Extract the exact `url=` value, if any.
pub fn extract_url(line: &str) -> Option<Url> {
    token_value(line, "url").and_then(|value| Url::parse(&value).ok())
}

/// Extract a front/broker host. `url=` takes precedence over `fronts=` and
/// `front=`, matching OnionHop.py.
pub fn extract_front_host(line: &str) -> Option<String> {
    if let Some(url) = extract_url(line) {
        if let Some(host) = url.host_str() {
            return Some(host.to_owned());
        }
    }

    if let Some(fronts) = token_value(line, "fronts") {
        if let Some(first) = fronts
            .split(',')
            .map(str::trim)
            .find(|host| !host.is_empty())
        {
            return Some(first.to_owned());
        }
    }

    token_value(line, "front").filter(|host| !host.trim().is_empty())
}

/// Extract a host and port from a literal endpoint or URL.
///
/// A literal `IP:PORT` token wins over the `url=` host. This is required for
/// WebTunnel, where `url=` identifies the registration/WebSocket route while
/// the preceding socket endpoint is the address a client must contact.
/// URL endpoints default to port 443; raw endpoints must include an explicit
/// valid port, as they do in bridge descriptors.
pub fn extract_endpoint(line: &str) -> Option<Endpoint> {
    let raw = strip_bridge_prefix(line);
    for token in raw.split_whitespace() {
        if let Some(endpoint) = endpoint_from_token(token) {
            return Some(endpoint);
        }
    }

    extract_url(line).and_then(|url| {
        let host = url.host_str()?.to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let address_family = if host.parse::<std::net::Ipv4Addr>().is_ok() {
            "ipv4".to_owned()
        } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
            "ipv6".to_owned()
        } else {
            "dns".to_owned()
        };
        Some(Endpoint {
            host,
            port,
            address_family,
        })
    })
}

/// Return `true` when a bridge line's direct endpoint is IPv6.
pub fn is_ipv6_line(line: &str) -> bool {
    extract_endpoint(line)
        .and_then(|endpoint| endpoint.host.parse::<IpAddr>().ok())
        .map(|address| address.is_ipv6())
        .unwrap_or_else(|| line.contains('[') && line.contains(']'))
}

/// Return `true` for valid IPv4 or IPv6 literal strings.
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Parse an IPv4 obfs4 line into the SOCKS-auth arguments required by a real
/// obfs4proxy/lyrebird client harness.
pub fn parse_obfs4_ipv4(line: &str) -> Option<Obfs4Endpoint> {
    if !line.to_ascii_lowercase().contains("obfs4") {
        return None;
    }
    let endpoint = extract_endpoint(line)?;
    if endpoint.host.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }
    let certificate = token_value(line, "cert")?;
    let iat_mode = token_value(line, "iat-mode").unwrap_or_else(|| "0".to_owned());
    Some(Obfs4Endpoint {
        host: endpoint.host,
        port: endpoint.port,
        socks_args: format!("cert={certificate};iat-mode={iat_mode}"),
    })
}

/// Return the durable history key used for this line.
pub fn history_key(line: &str, transport: Transport) -> String {
    match transport {
        Transport::Vanilla => normalize_vanilla_for_history(line),
        _ => clean_output_line(line),
    }
}

/// Extract a `key=value` token without allowing substring matches in another
/// value. Values in standard bridge lines cannot contain unescaped whitespace.
pub fn token_value(line: &str, key: &str) -> Option<String> {
    strip_bridge_prefix(line)
        .split_whitespace()
        .find_map(|token| {
            let (token_key, value) = token.split_once('=')?;
            if token_key.eq_ignore_ascii_case(key) {
                Some(value.trim_matches('"').to_owned())
            } else {
                None
            }
        })
}

#[allow(dead_code)]
fn has_webtunnel_literal_endpoint(line: &str) -> bool {
    strip_bridge_prefix(line)
        .split_whitespace()
        .filter_map(endpoint_from_token)
        .any(|endpoint| matches!(endpoint.address_family.as_str(), "ipv4" | "ipv6"))
}

fn endpoint_from_token(token: &str) -> Option<Endpoint> {
    let token = token.trim_matches(|character| matches!(character, ',' | ';' | '"'));
    if token.is_empty()
        || token.contains('=')
        || token.starts_with("http://")
        || token.starts_with("https://")
    {
        return None;
    }

    if let Some(rest) = token.strip_prefix('[') {
        let (host, port_with_separator) = rest.split_once("]:")?;
        let port = parse_port(port_with_separator)?;
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return Some(Endpoint {
                host: host.to_owned(),
                port,
                address_family: "ipv6".to_owned(),
            });
        }
        return None;
    }

    let (host, port_text) = token.rsplit_once(':')?;
    let port = parse_port(port_text)?;
    if host.is_empty() || host.contains(':') || host.contains('/') {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(Endpoint {
            host: host.to_owned(),
            port,
            address_family: "ipv4".to_owned(),
        });
    }
    if is_dns_name(host) {
        return Some(Endpoint {
            host: host.to_owned(),
            port,
            address_family: "dns".to_owned(),
        });
    }
    None
}

fn parse_port(value: &str) -> Option<u16> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

fn is_documentation_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 0
                || octets[0] == 10
                || octets[0] == 127
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || octets[0] >= 224
        }
        IpAddr::V6(ipv6) => {
            let seg = ipv6.segments();
            ipv6.is_unspecified()
                || ipv6.is_loopback()
                || (seg[0] & 0xffc0) == 0xfe80
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xff00) == 0xff00
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        }
    }
}

pub fn contains_documentation_or_reserved_endpoint(line: &str) -> bool {
    let trimmed = strip_bridge_prefix(line);
    for token in trimmed.split_whitespace() {
        if let Some(endpoint) = endpoint_from_token(token) {
            if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
                if is_documentation_or_reserved_ip(ip) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn is_canonical_fingerprint(value: &str) -> bool {
    let cleaned = value.trim().trim_matches(|c| matches!(c, ',' | ';' | '"'));
    (cleaned.len() == 40 || cleaned.len() == 64) && cleaned.bytes().all(|b| b.is_ascii_hexdigit())
}

fn first_fingerprint_like_token(line: &str) -> Option<String> {
    strip_bridge_prefix(line)
        .split_whitespace()
        .find_map(|token| {
            let cleaned = token.trim_matches(|c| matches!(c, ',' | ';' | '"'));
            (cleaned.len() == 40 || cleaned.len() == 64).then(|| cleaned.to_owned())
        })
}

fn is_dns_name(host: &str) -> bool {
    host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_covers_ipv4_ipv6_and_url_forms() {
        assert!(is_valid_bridge_line("obfs4 1.2.3.4:443 cert=abc"));
        assert!(is_valid_bridge_line(
            "obfs4 [2606:4700:4700::1111]:443 cert=abc"
        ));
        assert!(is_valid_bridge_line(
            "webtunnel 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/x ver=0.0.4"
        ));
        assert!(is_valid_bridge_line(
            "webtunnel [2606:4700:4700::1111]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/x ver=0.0.4"
        ));
        assert!(!is_valid_bridge_line(
            "webtunnel 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/x"
        ));
        assert!(!is_valid_bridge_line("# 1.2.3.4:443"));
        assert!(!is_valid_bridge_line("No bridges available"));
        assert!(!is_valid_bridge_line("tiny"));
    }

    #[test]
    fn endpoint_extraction_handles_every_supported_family() {
        assert_eq!(
            extract_endpoint("Bridge 1.2.3.4:9001 FINGERPRINT"),
            Some(Endpoint {
                host: "1.2.3.4".to_owned(),
                port: 9001,
                address_family: "ipv4".to_owned(),
            })
        );
        assert_eq!(
            extract_endpoint("obfs4 [2001:db8::1]:443 cert=x"),
            Some(Endpoint {
                host: "2001:db8::1".to_owned(),
                port: 443,
                address_family: "ipv6".to_owned(),
            })
        );
        assert_eq!(
            extract_endpoint("webtunnel 1.2.3.4:443 url=https://example.org/path"),
            Some(Endpoint {
                host: "1.2.3.4".to_owned(),
                port: 443,
                address_family: "ipv4".to_owned(),
            })
        );
        assert_eq!(
            extract_endpoint("webtunnel [2001:db8::1]:443 url=https://example.org/path"),
            Some(Endpoint {
                host: "2001:db8::1".to_owned(),
                port: 443,
                address_family: "ipv6".to_owned(),
            })
        );
        assert_eq!(
            extract_endpoint("obfs4 bridge.example.net:8443 cert=x"),
            Some(Endpoint {
                host: "bridge.example.net".to_owned(),
                port: 8443,
                address_family: "dns".to_owned(),
            })
        );
    }

    #[test]
    fn transport_detection_and_front_host_precedence_are_stable() {
        assert_eq!(detect_transport("obfs4 1.2.3.4:443"), Transport::Obfs4);
        assert_eq!(
            detect_transport("meek_lite 1.2.3.4:80"),
            Transport::MeekAzure
        );
        assert_eq!(detect_transport("conjure 1.2.3.4:80"), Transport::Conjure);
        assert!(is_fronted_line(
            "snowflake 192.0.2.3:80 url=https://broker.example"
        ));
        assert_eq!(
            extract_front_host(
                "snowflake 192.0.2.3:80 url=https://broker.example/a fronts=front.example"
            ),
            Some("broker.example".to_owned())
        );
        assert_eq!(
            extract_front_host("meek_lite 192.0.2.3:80 front=ajax.aspnetcdn.com"),
            Some("ajax.aspnetcdn.com".to_owned())
        );
    }

    #[test]
    fn vanilla_history_prefix_is_not_written_to_raw_lists() {
        let line = "Bridge 1.2.3.4:443 AABB";
        assert_eq!(clean_output_line(line), "1.2.3.4:443 AABB");
        assert_eq!(
            normalize_vanilla_for_history(line),
            "Bridge 1.2.3.4:443 AABB"
        );
        assert_eq!(
            history_key(line, Transport::Vanilla),
            "Bridge 1.2.3.4:443 AABB"
        );
    }

    #[test]
    fn obfs4_harness_parser_requires_ipv4_and_cert() {
        let parsed = parse_obfs4_ipv4("obfs4 203.0.113.7:443 FINGER cert=abc iat-mode=2");
        assert_eq!(
            parsed,
            Some(Obfs4Endpoint {
                host: "203.0.113.7".to_owned(),
                port: 443,
                socks_args: "cert=abc;iat-mode=2".to_owned(),
            })
        );
        assert!(parse_obfs4_ipv4("obfs4 [2001:db8::1]:443 FINGER cert=abc").is_none());
        assert!(parse_obfs4_ipv4("obfs4 203.0.113.7:443 FINGER").is_none());
    }

    // ── Dynamic parser tests ──────────────────────────────────────────────

    #[test]
    fn dynamic_parser_handles_obfs4_ipv4() {
        let p = parse_bridge_line(
            "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=2",
        );
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.port, Some(443));
        assert!(p.fingerprint.is_some());
        assert_eq!(p.kv_pairs.get("cert").map(|s| s.as_str()), Some("abc"));
        assert_eq!(p.kv_pairs.get("iat-mode").map(|s| s.as_str()), Some("2"));
    }

    #[test]
    fn dynamic_parser_handles_obfs4_ipv6() {
        let p = parse_bridge_line(
            "obfs4 [2001:db8::1]:8443 0123456789ABCDEF0123456789ABCDEF01234567 cert=xyz iat-mode=0",
        );
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ipv6.as_deref(), Some("2001:db8::1"));
        assert_eq!(p.port, Some(8443));
    }

    #[test]
    fn dynamic_parser_handles_webtunnel_with_literal_endpoint() {
        let p = parse_bridge_line(
            "webtunnel 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/path ver=0.0.4",
        );
        assert_eq!(p.transport, "webtunnel");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.port, Some(443));
        assert_eq!(p.sni.as_deref(), Some("example.com"));
        assert_eq!(p.url.as_deref(), Some("https://example.com/path"));
        assert_eq!(p.version.as_deref(), Some("0.0.4"));
    }

    #[test]
    fn dynamic_parser_handles_domain_only_webtunnel() {
        let p =
            parse_bridge_line("webtunnel 0123456789ABCDEF0123456789ABCDEF01234567 url=https://vault.example.xyz/path ver=0.0.3");
        assert_eq!(p.transport, "webtunnel");
        assert_eq!(p.sni.as_deref(), Some("vault.example.xyz"));
        assert_eq!(p.url.as_deref(), Some("https://vault.example.xyz/path"));
        assert_eq!(p.version.as_deref(), Some("0.0.3"));
        assert!(p.ipv4.is_none());
        assert!(p.ipv6.is_none());
        // port defaults to 443 for HTTPS URLs
        assert_eq!(p.port, Some(443));
    }

    #[test]
    fn dynamic_parser_handles_vanilla_ipv4() {
        let p = parse_bridge_line("1.2.3.4:9001 0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(p.transport, "vanilla");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.port, Some(9001));
    }

    #[test]
    fn dynamic_parser_handles_vanilla_ipv6() {
        let p = parse_bridge_line("[2001:db8::1]:9001 0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(p.transport, "vanilla");
        assert_eq!(p.ipv6.as_deref(), Some("2001:db8::1"));
        assert_eq!(p.port, Some(9001));
    }

    #[test]
    fn dynamic_parser_handles_snowflake() {
        let p = parse_bridge_line(
            "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302",
        );
        assert_eq!(p.transport, "snowflake");
        assert_eq!(p.ipv4.as_deref(), Some("192.0.2.3"));
        assert_eq!(p.port, Some(80));
        assert_eq!(p.sni.as_deref(), Some("www.cdn77.com"));
    }

    #[test]
    fn dynamic_parser_handles_meek() {
        let p = parse_bridge_line(
            "meek_lite 0.0.3.0:1 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
        );
        assert_eq!(p.transport, "meek-azure");
        assert_eq!(p.sni.as_deref(), Some("ajax.aspnetcdn.com"));
    }

    #[test]
    fn dynamic_parser_handles_conjure() {
        let p = parse_bridge_line(
            "conjure 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://registration.refraction.network/api fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min",
        );
        assert_eq!(p.transport, "conjure");
        assert_eq!(p.sni.as_deref(), Some("cdn.sstatic.net"));
        assert_eq!(p.kv_pairs.get("transport").map(|s| s.as_str()), Some("min"));
    }

    #[test]
    fn dynamic_parser_handles_vless_reality() {
        let p = parse_bridge_line(
            "vless abc123-def uuid=550e8400-e29b-41d4-a716-446655440000 reality=on flow=xtls-rprx-vision security=reality sni=discord.com",
        );
        assert_eq!(p.transport, "vless-reality");
        assert_eq!(p.sni.as_deref(), Some("discord.com"));
        assert_eq!(
            p.kv_pairs.get("uuid").map(|s| s.as_str()),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn dynamic_parser_handles_hysteria2() {
        let p = parse_bridge_line(
            "hysteria2 1.2.3.4:8443 password=secret123 sni=cloudflare.com alpn=h3",
        );
        assert_eq!(p.transport, "hysteria2");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.sni.as_deref(), Some("cloudflare.com"));
    }

    #[test]
    fn dynamic_parser_handles_tuic() {
        let p = parse_bridge_line(
            "tuic 1.2.3.4:443 password=secret uuid=abc sni=example.com alpn=h3 congestion_control=bbr",
        );
        assert_eq!(p.transport, "tuic");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn dynamic_parser_handles_shadowtls() {
        let p = parse_bridge_line(
            "shadowtls 1.2.3.4:443 password=secret sni=www.microsoft.com version=3",
        );
        assert_eq!(p.transport, "shadowtls");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(p.version.as_deref(), Some("3"));
    }

    #[test]
    fn dynamic_parser_handles_http_upgrade() {
        let p = parse_bridge_line(
            "http-upgrade 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 host=example.com path=/ws alpn=http/1.1",
        );
        assert_eq!(p.transport, "http-upgrade");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(
            p.kv_pairs.get("host").map(|s| s.as_str()),
            Some("example.com")
        );
    }

    #[test]
    fn dynamic_parser_handles_grpc() {
        let p = parse_bridge_line(
            "grpc 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 serviceName=tor",
        );
        assert_eq!(p.transport, "grpc");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(
            p.kv_pairs.get("servicename").map(|s| s.as_str()),
            Some("tor")
        );
    }

    #[test]
    fn dynamic_parser_unknown_transport_defaults() {
        let p = parse_bridge_line("fancynew 1.2.3.4:443 secret=abc");
        assert_eq!(p.transport, "unknown");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.port, Some(443));
        assert_eq!(p.kv_pairs.get("secret").map(|s| s.as_str()), Some("abc"));
    }

    #[test]
    fn dynamic_parser_dial_host_prefers_sni() {
        let p = parse_bridge_line(
            "webtunnel 1.2.3.4:443 FINGER url=https://example.com/path ver=0.0.4",
        );
        assert_eq!(p.dial_host(), Some("example.com"));
        assert_eq!(p.dial_port(), Some(443));
    }

    #[test]
    fn dynamic_parser_dial_host_falls_back_to_ipv4() {
        let p = parse_bridge_line("obfs4 1.2.3.4:443 FINGER cert=abc");
        assert_eq!(p.dial_host(), Some("1.2.3.4"));
    }

    #[test]
    fn detect_transport_uses_token_not_substring() {
        // A bridge line whose URL/params contain "snowflake" must not be
        // classified as Snowflake when the transport token is different.
        assert_eq!(
            detect_transport("obfs4 1.2.3.4:443 cert=snowflake"),
            Transport::Obfs4
        );
        assert_eq!(
            detect_transport("webtunnel 1.2.3.4:443 url=https://snowflake.example.com"),
            Transport::WebTunnel
        );
        // Bare endpoint falls to vanilla because the first token "1.2.3.4:443"
        // contains ':' (port separator) — it's an endpoint, not a transport name.
        assert_eq!(
            detect_transport("1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://snowflake.example.com"),
            Transport::Vanilla
        );
        assert_eq!(
            detect_transport("webtunnel 0123456789ABCDEF0123456789ABCDEF01234567 url=https://conjure.example.com ver=0.0.4"),
            Transport::WebTunnel
        );
    }

    #[test]
    fn detect_transport_handles_new_types() {
        assert_eq!(
            detect_transport("vless abc123-def uuid=550e8400 sni=discord.com"),
            Transport::VlessReality
        );
        assert_eq!(
            detect_transport("hysteria2 1.2.3.4:443 password=secret"),
            Transport::Hysteria2
        );
        assert_eq!(
            detect_transport("tuic 1.2.3.4:443 password=secret"),
            Transport::Tuic
        );
        assert_eq!(
            detect_transport("shadowtls 1.2.3.4:443 password=secret sni=ms.com"),
            Transport::ShadowTls
        );
        assert_eq!(detect_transport("anytls 1.2.3.4:443"), Transport::Anytls);
        assert_eq!(
            detect_transport("http-upgrade 1.2.3.4:443 host=example.com"),
            Transport::HttpUpgrade
        );
        assert_eq!(
            detect_transport("grpc 1.2.3.4:443 serviceName=tor"),
            Transport::Grpc
        );
        assert_eq!(detect_transport("fancynew 1.2.3.4:443"), Transport::Unknown);
    }
    #[test]
    fn transport_from_name_handles_aliases() {
        assert_eq!(
            Transport::from_name("vless+reality"),
            Some(Transport::VlessReality)
        );
        assert_eq!(Transport::from_name("vless"), Some(Transport::VlessReality));
        assert_eq!(
            Transport::from_name("hysteria2"),
            Some(Transport::Hysteria2)
        );
        assert_eq!(Transport::from_name("hysteria"), Some(Transport::Hysteria2));
        assert_eq!(Transport::from_name("tuic"), Some(Transport::Tuic));
        assert_eq!(
            Transport::from_name("shadowtls"),
            Some(Transport::ShadowTls)
        );
        assert_eq!(Transport::from_name("anytls"), Some(Transport::Anytls));
        assert_eq!(
            Transport::from_name("http-upgrade"),
            Some(Transport::HttpUpgrade)
        );
        assert_eq!(Transport::from_name("grpc"), Some(Transport::Grpc));
        assert_eq!(Transport::from_name("bogus"), None);
    }

    // ── Edge case & error handling tests ───────────────────────────────────

    #[test]
    fn parse_empty_line_produces_default() {
        let p = parse_bridge_line("");
        assert!(p.transport.is_empty());
        assert!(p.ipv4.is_none());
        assert!(p.ipv6.is_none());
        assert!(p.sni.is_none());
        assert!(p.port.is_none());
    }

    #[test]
    fn parse_whitespace_only_is_benign() {
        let p = parse_bridge_line("   ");
        // Should not panic; edge case gracefully handled
        assert!(p.transport.is_empty());
    }

    #[test]
    fn parse_comment_lines_are_not_bridge_lines() {
        assert!(!is_valid_bridge_line("# obfs4 1.2.3.4:443 cert=abc"));
        assert!(!is_valid_bridge_line("    #"));
    }

    #[test]
    fn parse_bridge_prefix_is_stripped_correctly() {
        let p = parse_bridge_line("Bridge obfs4 1.2.3.4:443 cert=abc");
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ipv4.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn detect_transport_handles_leading_whitespace() {
        assert_eq!(detect_transport("  obfs4 1.2.3.4:443"), Transport::Obfs4);
        assert_eq!(
            detect_transport("\tvanilla 1.2.3.4:443"),
            Transport::Vanilla
        );
    }

    #[test]
    fn parse_bridge_line_handles_url_without_scheme() {
        // A URL without https:// should still be captured
        let p = parse_bridge_line("webtunnel FINGER url=example.com/path ver=0.0.3");
        // url= is captured as key-value but won't be parsed as a URL for SNI
        // because it doesn't start with https://
        assert_eq!(
            p.kv_pairs.get("url").map(|s| s.as_str()),
            Some("example.com/path")
        );
    }

    #[test]
    fn parse_bridge_line_isolates_transport_from_endpoint() {
        // obfs4's cert can contain 'obfs4' - detect_transport uses token, not substring
        let p = parse_bridge_line("obfs4 1.2.3.4:443 FINGER cert=obfs4test-abc iat-mode=0");
        assert_eq!(p.transport, "obfs4");
    }
}
