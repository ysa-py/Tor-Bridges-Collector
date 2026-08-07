//! WebTunnel v0.0.4 dual-stack transport helpers.
//!
//! The implementation is intentionally small and deterministic: it exposes a
//! parsing helper plus a compact recommendation payload so the pipeline and
//! probe layers can share the same transport semantics without pulling in the
//! full network stack.

use serde_json::{json, Value};

/// Minimal parsing result for a WebTunnel v0.0.4 bridge line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTunnelV2Info {
    pub host: String,
    pub port: u16,
    pub family: String,
    pub url: Option<String>,
    pub version: String,
}

impl Default for WebTunnelV2Info {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            family: "unknown".to_string(),
            url: None,
            version: "0.0.4".to_string(),
        }
    }
}

/// Parse a WebTunnel bridge line into a stable metadata payload.
pub fn parse_line(line: &str) -> Option<WebTunnelV2Info> {
    let normalized = line.trim();
    if normalized.is_empty() || !normalized.to_ascii_lowercase().contains("webtunnel") {
        return None;
    }

    let mut info = WebTunnelV2Info::default();
    info.version = "0.0.4".to_string();

    let mut found_endpoint = false;
    for token in normalized.split_whitespace() {
        if token.starts_with("url=") {
            info.url = Some(
                token
                    .trim_start_matches("url=")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if token.starts_with("ver=") {
            info.version = token
                .trim_start_matches("ver=")
                .trim_matches('"')
                .to_string();
        } else if !found_endpoint && token.contains(':') && !token.contains('=') {
            let (host, port) = token.rsplit_once(':')?;
            if !host.is_empty() && port.parse::<u16>().ok().is_some() {
                info.host = host.trim_matches(|c| c == '[' || c == ']').to_string();
                info.port = port.parse().ok()?;
                if info.host.contains(':') {
                    info.family = "ipv6".to_string();
                } else if info.host.parse::<std::net::Ipv4Addr>().is_ok() {
                    info.family = "ipv4".to_string();
                } else {
                    info.family = "dns".to_string();
                }
                found_endpoint = true;
            }
        }
    }

    Some(info)
}

/// Build a compact JSON recommendation payload for the pipeline.
pub fn as_json(info: &WebTunnelV2Info) -> Value {
    json!({
        "host": info.host,
        "port": info.port,
        "family": info.family,
        "url": info.url,
        "version": info.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v0_0_4_dual_stack_payload() {
        let info =
            parse_line("webtunnel [2001:db8::4]:443 FINGERPRINT url=https://example.com ver=0.0.4")
                .expect("expected parse");
        assert_eq!(info.family, "ipv6");
        assert_eq!(info.port, 443);
        assert_eq!(info.version, "0.0.4");

        let encoded = as_json(&info);
        assert_eq!(encoded["family"].as_str(), Some("ipv6"));
    }
}
