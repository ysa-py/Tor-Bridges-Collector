//! Protocol Extensibility Framework (§7 of the 10-point spec).
//!
//! Plugin-based transport architecture. New transports added through
//! interfaces rather than core rewrites. Modular transport handlers,
//! versioned definitions, independent tests, backward compatibility.

use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

/// Censorship-aware ranking priority of a transport.
///
/// `normal` is the preference rank at censorship levels 1–3; `escalated` is
/// the rank at levels 4–5 (SIAM escalation / NIN internet-cut), where
/// fronting- and traffic-morphing-capable transports are promoted. Lower
/// sorts earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPriority {
    pub normal: usize,
    pub escalated: usize,
}

impl TransportPriority {
    pub const fn new(normal: usize, escalated: usize) -> Self {
        Self { normal, escalated }
    }

    /// The priority to use at a given censorship level.
    pub fn for_level(&self, censorship_level: u8) -> usize {
        if censorship_level >= 4 {
            self.escalated
        } else {
            self.normal
        }
    }
}

/// A versioned transport protocol definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportVersion {
    pub transport: String,
    pub version: String,
}

impl TransportVersion {
    pub fn new(transport: &str, version: &str) -> Self {
        Self {
            transport: transport.to_string(),
            version: version.to_string(),
        }
    }
    pub fn fqn(&self) -> String {
        format!("{}@{}", self.transport, self.version)
    }
    pub fn parse_semver(&self) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = self.version.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ))
    }
}

/// Capabilities a transport plugin declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCapabilities {
    pub domain_fronting: bool,
    pub ipv6_support: bool,
    pub provides_encryption: bool,
    pub requires_tls: bool,
    pub uses_ip_literal: bool,
    pub required_fields: Vec<String>,
    pub optional_fields: Vec<String>,
    pub supported_versions: Vec<String>,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            domain_fronting: false,
            ipv6_support: false,
            provides_encryption: false,
            requires_tls: false,
            uses_ip_literal: true,
            required_fields: vec![],
            optional_fields: vec![],
            supported_versions: vec![],
        }
    }
}

/// A parsed bridge endpoint.
#[derive(Debug, Clone)]
pub struct BridgeEndpoint {
    pub host: String,
    pub port: u16,
    pub fingerprint: Option<String>,
    pub params: BTreeMap<String, String>,
}

/// The core transport plugin interface.
pub trait TransportPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> TransportVersion;
    fn capabilities(&self) -> TransportCapabilities;
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint>;
    fn validate_bridge_line(&self, line: &str) -> Result<(), String>;
    fn extract_front_domain(&self, line: &str) -> Option<String>;
    fn format_bridge_line(&self, endpoint: &BridgeEndpoint) -> String;
    fn is_compatible_with(&self, version: &str) -> bool;
    fn description(&self) -> &str;

    /// Censorship-aware ranking priority for this transport, if it should
    /// participate in the rotation planner's transport preference order.
    ///
    /// `None` (the default) means the transport is detected/validated but not
    /// ranked — it sorts after every ranked transport. Override this in a
    /// plugin to have it picked up by the ranking logic without touching the
    /// core dispatch/ranking code.
    fn priority(&self) -> Option<TransportPriority> {
        None
    }
}

// ─── Built-in plugins ─────────────────────────────────────────────────

pub struct Obfs4Plugin;
impl TransportPlugin for Obfs4Plugin {
    fn name(&self) -> &str {
        "obfs4"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("obfs4", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provides_encryption: true,
            ipv6_support: true,
            uses_ip_literal: true,
            required_fields: vec!["fingerprint".into(), "cert".into()],
            optional_fields: vec!["iat-mode".into()],
            supported_versions: vec!["1.0.0".into()],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("obfs4 ")?.trim();
        let mut parts = body.splitn(3, ' ');
        let addr = parts.next()?;
        let fingerprint = parts.next().map(|s| s.to_string());
        let rest = parts.next().unwrap_or("");
        let (host, port) = parse_addr_port(addr)?;
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        if let Some(cert) = rest.strip_prefix("cert=") {
            params.insert(
                "cert".to_string(),
                cert.split_whitespace().next()?.to_string(),
            );
        }
        if let Some(idx) = rest.find("iat-mode=") {
            let v = &rest[idx + 9..];
            params.insert(
                "iat-mode".to_string(),
                v.split_whitespace().next()?.to_string(),
            );
        }
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint,
            params,
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        let body = line
            .strip_prefix("obfs4 ")
            .ok_or_else(|| "not obfs4".to_string())?
            .trim();
        if body.is_empty() {
            return Err("empty obfs4 body".into());
        }
        let parts: Vec<&str> = body.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!(
                "obfs4 line needs IP:PORT and fingerprint, got {} parts",
                parts.len()
            ));
        }
        if parse_addr_port(parts[0]).is_none() {
            return Err(format!("invalid obfs4 address: {}", parts[0]));
        }
        let fp = parts[1];
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid obfs4 fingerprint: {fp}"));
        }
        Ok(())
    }
    fn extract_front_domain(&self, _: &str) -> Option<String> {
        None
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        let mut line = format!("obfs4 {}:{}", ep.host, ep.port);
        if let Some(ref fp) = ep.fingerprint {
            line.push_str(&format!(" {fp}"));
        }
        if let Some(cert) = ep.params.get("cert") {
            line.push_str(&format!(" cert={cert}"));
        }
        if let Some(iat) = ep.params.get("iat-mode") {
            line.push_str(&format!(" iat-mode={iat}"));
        }
        line
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        v == "1.0.0"
    }
    fn description(&self) -> &str {
        "obfs4 — Tor obfuscation layer 4"
    }
    fn priority(&self) -> Option<TransportPriority> {
        Some(TransportPriority::new(0, 3))
    }
}

pub struct WebTunnelPlugin;
impl TransportPlugin for WebTunnelPlugin {
    fn name(&self) -> &str {
        "webtunnel"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("webtunnel", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            domain_fronting: true,
            ipv6_support: true,
            requires_tls: true,
            uses_ip_literal: false,
            required_fields: vec!["fingerprint".into(), "url".into()],
            optional_fields: vec!["ver".into()],
            supported_versions: vec![
                "0.0.1".into(),
                "0.0.2".into(),
                "0.0.3".into(),
                "0.0.4".into(),
                "0.0.5".into(),
                "0.0.6".into(),
                "1.0.0".into(),
            ],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("webtunnel ")?.trim();
        let mut parts = body.split_whitespace();
        let first = parts.next()?;
        let (host, port, fp, remaining): (String, u16, Option<String>, String) =
            if first.contains(':') && !first.starts_with("url=") {
                let (h, p) = parse_addr_port(first)?;
                let fp = parts.next().map(|s| s.to_string());
                (h, p, fp, parts.collect::<Vec<_>>().join(" "))
            } else {
                let fp = Some(first.to_string());
                ("".into(), 443, fp, parts.collect::<Vec<_>>().join(" "))
            };
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        for tok in remaining.split_whitespace() {
            if let Some((k, v)) = tok.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }
        let (host, port) = if host.is_empty() {
            if let Some(url) = params.get("url") {
                extract_url_host_port(url).unwrap_or((host, port))
            } else {
                (host, port)
            }
        } else {
            (host, port)
        };
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint: fp,
            params,
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        let body = line
            .strip_prefix("webtunnel ")
            .ok_or_else(|| "not webtunnel".to_string())?
            .trim();
        if body.is_empty() {
            return Err("empty webtunnel body".into());
        }
        if !body.contains("url=") {
            return Err("webtunnel missing url=".into());
        }
        for part in body.split_whitespace() {
            if !part.contains('=')
                && part.len() == 40
                && part.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Ok(());
            }
        }
        Err("webtunnel missing 40-char hex fingerprint".into())
    }
    fn extract_front_domain(&self, line: &str) -> Option<String> {
        let url_start = line.find("url=")?;
        extract_url_host(line[url_start + 4..].split_whitespace().next()?)
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        let mut line = String::from("webtunnel ");
        if !ep.host.is_empty() {
            let hs = if ep.host.contains(':') {
                format!("[{}]", ep.host)
            } else {
                ep.host.clone()
            };
            line.push_str(&format!("{hs}:{} ", ep.port));
        }
        if let Some(ref fp) = ep.fingerprint {
            line.push_str(fp);
        }
        for (k, v) in &ep.params {
            line.push_str(&format!(" {k}={v}"));
        }
        line
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        self.capabilities()
            .supported_versions
            .contains(&v.to_string())
    }
    fn description(&self) -> &str {
        "WebTunnel — Tor bridge via WebSocket domain fronting"
    }
    fn priority(&self) -> Option<TransportPriority> {
        Some(TransportPriority::new(1, 1))
    }
}

pub struct SnowflakePlugin;
impl TransportPlugin for SnowflakePlugin {
    fn name(&self) -> &str {
        "snowflake"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("snowflake", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            domain_fronting: true,
            ipv6_support: true,
            requires_tls: true,
            uses_ip_literal: false,
            supported_versions: vec!["1.0.0".into()],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("snowflake ")?.trim();
        let mut parts = body.split_whitespace();
        let addr = parts.next()?;
        let (host, port) = parse_addr_port(addr).unwrap_or((addr.to_string(), 443));
        let fp = parts.next().map(|s| s.to_string());
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        for p in parts {
            if let Some((k, v)) = p.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint: fp,
            params,
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        if !line.starts_with("snowflake ") {
            return Err("not snowflake".into());
        }
        Ok(())
    }
    fn extract_front_domain(&self, line: &str) -> Option<String> {
        line.find("url=")
            .and_then(|i| extract_url_host(line[i + 4..].split_whitespace().next()?))
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        let mut line = format!("snowflake {}:{}", ep.host, ep.port);
        if let Some(ref fp) = ep.fingerprint {
            line.push_str(&format!(" {fp}"));
        }
        for (k, v) in &ep.params {
            line.push_str(&format!(" {k}={v}"));
        }
        line
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        v == "1.0.0"
    }
    fn description(&self) -> &str {
        "Snowflake — Tor bridge via WebRTC"
    }
    fn priority(&self) -> Option<TransportPriority> {
        Some(TransportPriority::new(2, 0))
    }
}

pub struct VanillaPlugin;
impl TransportPlugin for VanillaPlugin {
    fn name(&self) -> &str {
        "vanilla"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("vanilla", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            ipv6_support: true,
            requires_tls: true,
            uses_ip_literal: true,
            supported_versions: vec!["1.0.0".into()],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("vanilla ")?.trim();
        let body = body.strip_prefix("Bridge ").unwrap_or(body);
        let (host, port) = parse_addr_port(body)?;
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint: None,
            params: BTreeMap::new(),
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        if !line.contains("vanilla ") && !line.contains(':') {
            return Err("not vanilla".into());
        }
        Ok(())
    }
    fn extract_front_domain(&self, _: &str) -> Option<String> {
        None
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        format!("Bridge vanilla {}:{}", ep.host, ep.port)
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        v == "1.0.0"
    }
    fn description(&self) -> &str {
        "Vanilla — plain Tor relay"
    }
    fn priority(&self) -> Option<TransportPriority> {
        Some(TransportPriority::new(4, 4))
    }
}

pub struct MeekPlugin;
impl TransportPlugin for MeekPlugin {
    fn name(&self) -> &str {
        "meek_lite"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("meek_lite", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            domain_fronting: true,
            ipv6_support: true,
            requires_tls: true,
            uses_ip_literal: false,
            required_fields: vec!["url".into()],
            optional_fields: vec!["front".into()],
            supported_versions: vec!["1.0.0".into()],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("meek_lite ")?.trim();
        let mut parts = body.split_whitespace();
        let addr = parts.next()?;
        let (host, port) = parse_addr_port(addr)?;
        let fp = parts.next().map(|s| s.to_string());
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        for p in parts {
            if let Some((k, v)) = p.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint: fp,
            params,
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        if !line.starts_with("meek_lite ") {
            return Err("not meek_lite".into());
        }
        if !line.contains("url=") {
            return Err("meek_lite missing url=".into());
        }
        Ok(())
    }
    fn extract_front_domain(&self, line: &str) -> Option<String> {
        line.find("url=")
            .and_then(|i| extract_url_host(line[i + 4..].split_whitespace().next()?))
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        let mut line = format!("meek_lite {}:{}", ep.host, ep.port);
        if let Some(ref fp) = ep.fingerprint {
            line.push_str(&format!(" {fp}"));
        }
        for (k, v) in &ep.params {
            line.push_str(&format!(" {k}={v}"));
        }
        line
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        v == "1.0.0"
    }
    fn description(&self) -> &str {
        "Meek Lite — domain-fronted HTTP bridge"
    }
    fn priority(&self) -> Option<TransportPriority> {
        Some(TransportPriority::new(3, 2))
    }
}

pub struct ConjurePlugin;
impl TransportPlugin for ConjurePlugin {
    fn name(&self) -> &str {
        "conjure"
    }
    fn version(&self) -> TransportVersion {
        TransportVersion::new("conjure", "1.0.0")
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provides_encryption: true,
            ipv6_support: true,
            uses_ip_literal: true,
            supported_versions: vec!["1.0.0".into()],
            ..Default::default()
        }
    }
    fn parse_bridge_line(&self, line: &str) -> Option<BridgeEndpoint> {
        let body = line.strip_prefix("conjure ")?.trim();
        let (host, port) = parse_addr_port(body)?;
        Some(BridgeEndpoint {
            host,
            port,
            fingerprint: None,
            params: BTreeMap::new(),
        })
    }
    fn validate_bridge_line(&self, line: &str) -> Result<(), String> {
        if !line.starts_with("conjure ") {
            Err("not conjure".into())
        } else {
            Ok(())
        }
    }
    fn extract_front_domain(&self, _: &str) -> Option<String> {
        None
    }
    fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
        format!("conjure {}:{}", ep.host, ep.port)
    }
    fn is_compatible_with(&self, v: &str) -> bool {
        v == "1.0.0"
    }
    fn description(&self) -> &str {
        "Conjure — decoy routing bridge"
    }
}

// ─── Registry ────────────────────────────────────────────────────────

pub struct TransportRegistry {
    plugins: BTreeMap<String, Box<dyn TransportPlugin>>,
    order: Vec<String>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            plugins: BTreeMap::new(),
            order: Vec::new(),
        }
    }
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Box::new(Obfs4Plugin));
        r.register(Box::new(WebTunnelPlugin));
        r.register(Box::new(SnowflakePlugin));
        r.register(Box::new(VanillaPlugin));
        r.register(Box::new(MeekPlugin));
        r.register(Box::new(ConjurePlugin));
        r
    }
    pub fn register(&mut self, plugin: Box<dyn TransportPlugin>) {
        let name = plugin.name().to_string();
        self.order.push(name.clone());
        self.plugins.insert(name, plugin);
    }
    /// Deregister a transport by name, returning the removed plugin if it was
    /// registered. Primarily used by tests that register a fake transport.
    pub fn unregister(&mut self, name: &str) -> Option<Box<dyn TransportPlugin>> {
        let removed = self.plugins.remove(name);
        self.order.retain(|s| s != name);
        removed
    }
    pub fn get(&self, name: &str) -> Option<&dyn TransportPlugin> {
        self.plugins.get(name).map(|p| p.as_ref())
    }
    pub fn transports(&self) -> Vec<&str> {
        self.order.iter().map(|s| s.as_str()).collect()
    }
    pub fn detect(&self, line: &str) -> Option<(String, BridgeEndpoint)> {
        for name in &self.order {
            if let Some(ep) = self
                .plugins
                .get(name)
                .and_then(|p| p.parse_bridge_line(line))
            {
                return Some((name.clone(), ep));
            }
        }
        None
    }
    pub fn validate(&self, line: &str) -> Result<String, String> {
        let (t, _) = self
            .detect(line)
            .ok_or_else(|| format!("could not detect transport for: {line}"))?;
        self.plugins
            .get(&t)
            .ok_or_else(|| format!("unknown: {t}"))?
            .validate_bridge_line(line)?;
        Ok(t)
    }
    pub fn capabilities(&self, transport: &str) -> Option<TransportCapabilities> {
        self.plugins.get(transport).map(|p| p.capabilities())
    }
    pub fn len(&self) -> usize {
        self.plugins.len()
    }
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The ranking priority of a transport at the given censorship level, or
    /// `None` if the transport is not registered or declares no priority
    /// (i.e. it is not ranked). This is the ranking lookup consumed by the
    /// rotation planner.
    pub fn rank_of(&self, name: &str, censorship_level: u8) -> Option<usize> {
        self.plugins
            .get(name)
            .and_then(|p| p.priority())
            .map(|p| p.for_level(censorship_level))
    }

    /// The rank assigned to any unranked transport at the given level: one
    /// past the highest declared priority, so unranked transports sort after
    /// every ranked one.
    pub fn fallback_rank(&self, censorship_level: u8) -> usize {
        self.plugins
            .values()
            .filter_map(|p| p.priority())
            .map(|p| p.for_level(censorship_level))
            .max()
            .map_or(0, |m| m + 1)
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

// ─── Process-wide registry (ranking source of truth) ───────────────────────

static GLOBAL_REGISTRY: OnceLock<RwLock<TransportRegistry>> = OnceLock::new();

/// The process-wide transport registry used by ranking/dispatch code, seeded
/// with the built-in plugins. New transports register here at startup so the
/// ranking logic picks them up without editing the core dispatch code.
pub fn global_registry() -> &'static RwLock<TransportRegistry> {
    GLOBAL_REGISTRY.get_or_init(|| RwLock::new(TransportRegistry::with_builtins()))
}

// ─── Shared helpers ──────────────────────────────────────────────────

fn parse_addr_port(addr: &str) -> Option<(String, u16)> {
    if let Some(bracket_end) = addr.rfind("]:") {
        let ip = &addr[1..bracket_end];
        let port: u16 = addr[bracket_end + 2..].parse().ok()?;
        if !ip.is_empty() && (1..=65535).contains(&port) {
            return Some((format!("[{ip}]"), port));
        }
    }
    if let Some(colon) = addr.rfind(':') {
        let host = &addr[..colon];
        let port: u16 = addr[colon + 1..].parse().ok()?;
        if !host.is_empty() && (1..=65535).contains(&port) {
            return Some((host.to_string(), port));
        }
    }
    None
}

fn extract_url_host(url_str: &str) -> Option<String> {
    let s = url_str.trim();
    let after = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let hp = after.split('/').next()?;
    let host = hp.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn extract_url_host_port(url_str: &str) -> Option<(String, u16)> {
    let s = url_str.trim();
    let after = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let hp = after.split('/').next()?;
    if let Some((host, port_str)) = hp.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((host.to_string(), port));
        }
    }
    if hp.is_empty() {
        None
    } else {
        Some((hp.to_string(), 443))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_builtins() {
        let r = TransportRegistry::with_builtins();
        assert!(r.len() >= 6);
        for t in [
            "obfs4",
            "webtunnel",
            "snowflake",
            "vanilla",
            "meek_lite",
            "conjure",
        ] {
            assert!(r.get(t).is_some(), "missing {t}");
        }
    }

    #[test]
    fn detect_obfs4() {
        let r = TransportRegistry::with_builtins();
        let (t, ep) = r
            .detect(
                "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF012 cert=abc iat-mode=0",
            )
            .unwrap();
        assert_eq!(t, "obfs4");
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn detect_webtunnel_url_only() {
        let r = TransportRegistry::with_builtins();
        let (t, ep) = r.detect("webtunnel ABCDEF0123456789ABCDEF0123456789ABCDEF012 url=https://cdn.example.com/path ver=0.0.4").unwrap();
        assert_eq!(t, "webtunnel");
        assert_eq!(ep.host, "cdn.example.com");
    }

    #[test]
    fn detect_webtunnel_with_ip() {
        let r = TransportRegistry::with_builtins();
        let (t, ep) = r.detect("webtunnel 1.2.3.4:443 FINGERPRINT1234567890123456789012345678901234 url=https://x.com ver=0.0.3").unwrap();
        assert_eq!(t, "webtunnel");
        assert_eq!(ep.host, "1.2.3.4");
    }

    #[test]
    fn detect_snowflake() {
        let r = TransportRegistry::with_builtins();
        let (t, _) = r
            .detect("snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72")
            .unwrap();
        assert_eq!(t, "snowflake");
    }

    #[test]
    fn detect_vanilla() {
        let (t, ep) = TransportRegistry::with_builtins()
            .detect("vanilla 1.2.3.4:9001")
            .unwrap();
        assert_eq!(t, "vanilla");
        assert_eq!(ep.port, 9001);
    }

    #[test]
    fn detect_meek() {
        let (t, _) = TransportRegistry::with_builtins()
            .detect(
                "meek_lite 192.0.2.2:2 FP url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
            )
            .unwrap();
        assert_eq!(t, "meek_lite");
    }

    #[test]
    fn detect_conjure() {
        let (t, _) = TransportRegistry::with_builtins()
            .detect("conjure 1.2.3.4:443")
            .unwrap();
        assert_eq!(t, "conjure");
    }

    #[test]
    fn unknown_line() {
        assert!(TransportRegistry::with_builtins()
            .detect("garbage")
            .is_none());
    }

    #[test]
    fn obfs4_validate_good() {
        Obfs4Plugin
            .validate_bridge_line(
                "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=abc iat-mode=0",
            )
            .unwrap();
    }

    #[test]
    fn obfs4_validate_bad_fp() {
        assert!(Obfs4Plugin
            .validate_bridge_line("obfs4 1.2.3.4:443 short")
            .is_err());
    }

    #[test]
    fn webtunnel_validate_good() {
        WebTunnelPlugin
            .validate_bridge_line(
                "webtunnel ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://x.com ver=0.0.4",
            )
            .unwrap();
    }

    #[test]
    fn webtunnel_validate_no_url() {
        assert!(WebTunnelPlugin
            .validate_bridge_line("webtunnel 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF012")
            .is_err());
    }

    #[test]
    fn front_domain() {
        let f = WebTunnelPlugin.extract_front_domain("webtunnel ABCDEF0123456789ABCDEF0123456789ABCDEF012 url=https://cdn.example.com/path ver=0.0.4").unwrap();
        assert_eq!(f, "cdn.example.com");
    }

    #[test]
    fn parse_ipv4() {
        let (h, p) = parse_addr_port("1.2.3.4:443").unwrap();
        assert_eq!(h, "1.2.3.4");
        assert_eq!(p, 443);
    }
    #[test]
    fn parse_ipv6() {
        let (h, p) = parse_addr_port("[2001:db8::1]:443").unwrap();
        assert_eq!(h, "[2001:db8::1]");
        assert_eq!(p, 443);
    }
    #[test]
    fn parse_bad_port() {
        assert!(parse_addr_port("1.2.3.4:99999").is_none());
    }
    #[test]
    fn semver() {
        assert_eq!(
            TransportVersion::new("w", "0.0.4").parse_semver(),
            Some((0, 0, 4))
        );
    }
    #[test]
    fn semver_bad() {
        assert!(TransportVersion::new("x", "bad").parse_semver().is_none());
    }

    #[test]
    fn caps_consistent() {
        let r = TransportRegistry::with_builtins();
        for t in r.transports() {
            assert_eq!(r.capabilities(t).unwrap(), r.get(t).unwrap().capabilities());
        }
    }

    #[test]
    fn custom_registration() {
        let mut r = TransportRegistry::new();
        r.register(Box::new(Obfs4Plugin));
        assert_eq!(r.len(), 1);
        assert!(r.get("webtunnel").is_none());
    }

    struct FakeRankedPlugin;
    impl TransportPlugin for FakeRankedPlugin {
        fn name(&self) -> &str {
            "fake_pt"
        }
        fn version(&self) -> TransportVersion {
            TransportVersion::new("fake_pt", "1.0.0")
        }
        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities::default()
        }
        fn parse_bridge_line(&self, _line: &str) -> Option<BridgeEndpoint> {
            None
        }
        fn validate_bridge_line(&self, _line: &str) -> Result<(), String> {
            Ok(())
        }
        fn extract_front_domain(&self, _line: &str) -> Option<String> {
            None
        }
        fn format_bridge_line(&self, ep: &BridgeEndpoint) -> String {
            format!("fake_pt {}:{}", ep.host, ep.port)
        }
        fn is_compatible_with(&self, _v: &str) -> bool {
            true
        }
        fn description(&self) -> &str {
            "fake ranked transport"
        }
        fn priority(&self) -> Option<TransportPriority> {
            Some(TransportPriority::new(0, 0))
        }
    }

    #[test]
    fn rank_of_reads_plugin_priority() {
        let r = TransportRegistry::with_builtins();
        // Normal order: obfs4=0, webtunnel=1, snowflake=2, meek_lite=3, vanilla=4
        assert_eq!(r.rank_of("obfs4", 3), Some(0));
        assert_eq!(r.rank_of("webtunnel", 3), Some(1));
        // Escalated order: snowflake=0, webtunnel=1, meek_lite=2, obfs4=3, vanilla=4
        assert_eq!(r.rank_of("snowflake", 5), Some(0));
        assert_eq!(r.rank_of("obfs4", 5), Some(3));
        // Conjure is registered but declares no priority → unranked.
        assert_eq!(r.rank_of("conjure", 3), None);
        // Unknown transports are not ranked either.
        assert_eq!(r.rank_of("nope", 3), None);
    }

    #[test]
    fn fallback_rank_is_one_past_highest_priority() {
        let r = TransportRegistry::with_builtins();
        // Highest declared priority in both levels is 4 (vanilla) → fallback 5.
        assert_eq!(r.fallback_rank(3), 5);
        assert_eq!(r.fallback_rank(5), 5);
    }

    #[test]
    fn registering_a_plugin_makes_its_priority_ranked() {
        let mut r = TransportRegistry::with_builtins();
        assert_eq!(r.rank_of("fake_pt", 3), None);
        r.register(Box::new(FakeRankedPlugin));
        assert_eq!(r.rank_of("fake_pt", 3), Some(0));
        r.unregister("fake_pt");
        assert!(r.get("fake_pt").is_none());
        assert_eq!(r.rank_of("fake_pt", 3), None);
    }

    #[test]
    fn obfs4_roundtrip() {
        let line =
            "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF012 cert=abc iat-mode=0";
        let ep = Obfs4Plugin.parse_bridge_line(line).unwrap();
        let fmt = Obfs4Plugin.format_bridge_line(&ep);
        let (t, ep2) = TransportRegistry::with_builtins().detect(&fmt).unwrap();
        assert_eq!(t, "obfs4");
        assert_eq!(ep.host, ep2.host);
        assert_eq!(ep.port, ep2.port);
    }
}
