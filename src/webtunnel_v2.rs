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

    let mut info = WebTunnelV2Info {
        version: "0.0.4".to_string(),
        ..Default::default()
    };

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

// ─────────────────────────────────────────────────────────────────────────────
// ADDITIVE (2026-09-08): evidence-driven front-domain health advisory.
//
// This extension is deliberately built ONLY on real reachability signals:
// the per-descriptor relay observations written by the probe-relay Worker
// (`data/pt_results.json` — live TCP/TLS/WebSocket probes executed from
// Cloudflare's network). No simulated or heuristic "health" is produced;
// front domains with zero relay observations are reported as
// `observations: 0, classification: "no_evidence"` instead of receiving an
// invented score.
// ─────────────────────────────────────────────────────────────────────────────

/// Front-domain health derived exclusively from relay observations.
#[derive(Debug, Clone, Default)]
pub struct FrontHealth {
    /// The front/url host webtunnel clients dial (TLS SNI target).
    pub front: String,
    /// Number of relay observations for this front (tcp/tls/websocket
    /// classes combined).
    pub observations: usize,
    /// Relay probes that succeeded (handshake completed).
    pub successes: usize,
    /// Whether the endpoint inside the line is a non-routable
    /// documentation/reserved address (BridgeDB publishes such placeholders
    /// for url-only bridges; clients must dial the url, never the endpoint).
    pub endpoint_is_placeholder: bool,
}

impl FrontHealth {
    /// Evidence classification. `healthy` / `degraded` require at least one
    /// relay observation; anything else is explicitly `no_evidence`.
    #[must_use]
    pub fn classification(&self) -> &'static str {
        if self.observations == 0 {
            "no_evidence"
        } else if self.successes == self.observations {
            "healthy"
        } else if self.successes > 0 {
            "degraded"
        } else {
            "unreachable_from_relay"
        }
    }

    /// Serializable form used in the advisory report.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "front": self.front,
            "observations": self.observations,
            "successes": self.successes,
            "endpoint_is_placeholder": self.endpoint_is_placeholder,
            "classification": self.classification(),
        })
    }
}

/// Extract the url-host (the host a webtunnel client actually dials) from a
/// webtunnel line, falling back to the literal endpoint when no `url=` is
/// present.
#[must_use]
pub fn front_host_of(line: &str) -> Option<String> {
    let info = parse_line(line)?;
    if let Some(url) = &info.url {
        let host = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }
    if info.host.is_empty() {
        None
    } else {
        Some(info.host)
    }
}

/// Build the front-domain health advisory for a set of webtunnel lines from
/// REAL relay observations only.
///
/// `relay_results` entries follow the probe-relay schema
/// (`{host, port, transport, success, probe_type}`). The url-host of each
/// line is joined against observations by host so that every claim of
/// reachability is backed by an actual probe outcome. Lines whose endpoint
/// is a documentation/reserved placeholder are counted separately: their
/// published `url=` may still be live, but the endpoint itself is
/// unroutable by design.
#[must_use]
pub fn front_health_advisory(lines: &[String], relay_results: &[Value]) -> Value {
    use std::collections::BTreeMap;

    let mut by_front: BTreeMap<String, FrontHealth> = BTreeMap::new();
    let mut placeholder_endpoints = 0_usize;

    for line in lines {
        let Some(front) = front_host_of(line) else {
            continue;
        };
        let entry = by_front
            .entry(front.clone())
            .or_insert_with(|| FrontHealth {
                front,
                ..FrontHealth::default()
            });
        if crate::ip_guard::contains_documentation_or_reserved_endpoint(line) {
            entry.endpoint_is_placeholder = true;
            placeholder_endpoints += 1;
        }
    }

    for observation in relay_results {
        let Some(host) = observation.get("host").and_then(Value::as_str) else {
            continue;
        };
        let Some(entry) = by_front.get_mut(host) else {
            continue;
        };
        entry.observations += 1;
        if observation
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            entry.successes += 1;
        }
    }

    let fronts: Vec<&FrontHealth> = by_front.values().collect();
    let healthy = fronts
        .iter()
        .filter(|f| f.classification() == "healthy")
        .count();
    let degraded = fronts
        .iter()
        .filter(|f| f.classification() == "degraded")
        .count();
    let unreachable = fronts
        .iter()
        .filter(|f| f.classification() == "unreachable_from_relay")
        .count();
    let no_evidence = fronts
        .iter()
        .filter(|f| f.classification() == "no_evidence")
        .count();

    json!({
        "generated_by": "webtunnel_v2::front_health_advisory",
        "evidence_source": "data/pt_results.json (live probe-relay observations from Cloudflare)",
        "lines_examined": lines.len(),
        "unique_fronts": by_front.len(),
        "fronts_with_placeholder_endpoints": placeholder_endpoints,
        "summary": {
            "healthy": healthy,
            "degraded": degraded,
            "unreachable_from_relay": unreachable,
            "no_evidence": no_evidence,
        },
        "fronts": fronts.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        "advisory_only": true,
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

    #[test]
    fn front_host_prefers_url_over_placeholder_endpoint() {
        let line = "webtunnel [2001:db8:1169:5d59:447d:1feb:3595:b174]:443 9E22636EA817AD4FE43F2EC14DEED5131FED1CB0 url=https://cdn-40.triplebit.dev/aif5ohWa4aWiephu ver=0.0.2";
        assert_eq!(
            front_host_of(line),
            Some("cdn-40.triplebit.dev".to_string())
        );
    }

    #[test]
    fn front_health_classifies_only_with_real_observations() {
        let lines = vec![
            "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4".to_string(),
            "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://no-evidence.example.com ver=0.0.4".to_string(),
        ];
        let relay = vec![
            serde_json::json!({"host": "vika7.space", "port": 443, "transport": "webtunnel", "success": true}),
            serde_json::json!({"host": "vika7.space", "port": 443, "transport": "webtunnel", "success": true}),
        ];
        let advisory = front_health_advisory(&lines, &relay);
        assert_eq!(advisory["lines_examined"], 2);
        assert_eq!(advisory["summary"]["healthy"], 1);
        assert_eq!(advisory["summary"]["no_evidence"], 1);
        assert_eq!(advisory["fronts_with_placeholder_endpoints"], 1);
        // The no-evidence front must never be classified as reachable.
        let no_evidence = advisory["fronts"]
            .as_array()
            .expect("fronts array")
            .iter()
            .find(|f| f["front"] == "no-evidence.example.com")
            .expect("no-evidence front present");
        assert_eq!(no_evidence["classification"], "no_evidence");
        assert_eq!(no_evidence["observations"], 0);
    }

    #[test]
    fn front_health_reports_unreachable_when_observations_all_fail() {
        let lines = vec![
            "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://dead.example.com/x ver=0.0.4".to_string(),
        ];
        let relay = vec![serde_json::json!({"host": "dead.example.com", "success": false})];
        let advisory = front_health_advisory(&lines, &relay);
        assert_eq!(advisory["summary"]["unreachable_from_relay"], 1);
    }
}
