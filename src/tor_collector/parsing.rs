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
        if token_value(trimmed, "ver").as_deref() != Some("0.0.4") {
            return false;
        }
        if !has_webtunnel_literal_endpoint(trimmed) {
            if extract_url(trimmed).is_some() {
                return false;
            }
        }
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

/// Infer the transport family using the precedence of the Python scripts.
pub fn detect_transport(line: &str) -> Transport {
    let lower = line.to_ascii_lowercase();
    if lower.contains("snowflake") {
        Transport::Snowflake
    } else if lower.contains("webtunnel") {
        Transport::WebTunnel
    } else if lower.contains("obfs4") {
        Transport::Obfs4
    } else if lower.contains("meek") {
        Transport::MeekAzure
    } else if lower.contains("conjure") {
        Transport::Conjure
    } else if lower.contains("url=https") {
        // A bare `url=https` line is a WebTunnel line in both Python scripts.
        Transport::WebTunnel
    } else {
        Transport::Vanilla
    }
}

/// Return whether a line has a fronted transport token.
pub fn is_fronted_line(line: &str) -> bool {
    matches!(
        transport_token(line).as_str(),
        "snowflake" | "meek" | "meek_lite" | "meek-azure" | "conjure"
    )
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
    if cleaned.len() == 40 {
        return Regex::new(r"\b[A-Fa-f0-9]{40}\b")
            .ok()
            .and_then(|re| re.is_match(cleaned).then_some(()))
            .is_some();
    }
    if cleaned.len() == 64 {
        return Regex::new(r"\b[A-Fa-f0-9]{64}\b")
            .ok()
            .and_then(|re| re.is_match(cleaned).then_some(()))
            .is_some();
    }
    false
}

fn first_fingerprint_like_token(line: &str) -> Option<String> {
    strip_bridge_prefix(line).split_whitespace().find_map(|token| {
        let cleaned = token.trim_matches(|c| matches!(c, ',' | ';' | '"'));
        (cleaned.len() == 40 || cleaned.len() == 64)
            .then(|| cleaned.to_owned())
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
        assert!(is_valid_bridge_line("obfs4 [2001:db8::7]:443 cert=abc"));
        assert!(is_valid_bridge_line(
            "webtunnel 1.2.3.4:443 url=https://example.org/x"
        ));
        assert!(is_valid_bridge_line(
            "webtunnel [2001:db8::7]:443 FINGER url=https://example.org/x ver=0.0.4"
        ));
        assert!(!is_valid_bridge_line("webtunnel FINGER url=https://example.org/x"));
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
}
