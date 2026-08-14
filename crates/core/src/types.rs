//! Phase 2 domain types: transports, bridge lines, observations, and scores.
//!
//! These types implement the master spec's data model exactly:
//! [`TransportKind`], [`BridgeLine`], [`Observation`], and [`BridgeScore`],
//! together with strict syntactic and semantic validation and a canonical
//! dedupe key. All types serialize to versioned JSON (`serde`), and every
//! enum round-trips as a stable lower-case token so diffs stay meaningful.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ModelError;
use crate::validate;

// ── TransportKind ─────────────────────────────────────────────────────────

/// The pluggable-transport family of a bridge line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Obfs4,
    WebTunnel,
    Vanilla,
    Snowflake,
    Meek,
    Conjure,
    /// Any transport outside the canonical six (for example `vless`,
    /// `hysteria2`, `tuic`, `shadowtls`, `http-upgrade`, `grpc`).
    Other(String),
}

impl TransportKind {
    /// The canonical lower-case token used in bridge lines and file names.
    pub fn to_token(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for TransportKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Obfs4 => formatter.write_str("obfs4"),
            Self::WebTunnel => formatter.write_str("webtunnel"),
            Self::Vanilla => formatter.write_str("vanilla"),
            Self::Snowflake => formatter.write_str("snowflake"),
            Self::Meek => formatter.write_str("meek"),
            Self::Conjure => formatter.write_str("conjure"),
            Self::Other(token) => formatter.write_str(token),
        }
    }
}

impl std::str::FromStr for TransportKind {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "obfs4" => Ok(Self::Obfs4),
            "webtunnel" | "web-tunnel" => Ok(Self::WebTunnel),
            "vanilla" => Ok(Self::Vanilla),
            "snowflake" => Ok(Self::Snowflake),
            "meek" | "meek_lite" | "meek-azure" => Ok(Self::Meek),
            "conjure" => Ok(Self::Conjure),
            other => Ok(Self::Other(other.to_owned())),
        }
    }
}

impl Serialize for TransportKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TransportKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(DeError::custom)
    }
}

// ── BridgeParams ──────────────────────────────────────────────────────────

/// Transport-specific parameters extracted from a bridge line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeParams {
    /// obfs4 `cert=` base64 value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// obfs4 `iat-mode=` value (`0`, `1`, or `2`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_mode: Option<String>,
    /// WebTunnel / Snowflake / Conjure registration URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// TLS server name / front domain (`sni=`, `front=`, `fronts=`, or URL host).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    /// uTLS mimicry profile (`utls=` / `utls-imitate=`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utls: Option<String>,
    /// Protocol version token (`ver=` / `version=`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
}

// ── BridgeLine ────────────────────────────────────────────────────────────

/// A fully parsed and validated bridge line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLine {
    /// The original, unmodified bridge line.
    pub raw: String,
    /// The detected transport family.
    pub transport: TransportKind,
    /// The contact host: an IP literal (without brackets) or a DNS name.
    pub host: String,
    /// The contact TCP port (1..=65535).
    pub port: u16,
    /// The canonical 40-hex fingerprint, if the line carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Transport-specific parameters.
    #[serde(default)]
    pub params: BridgeParams,
    /// When this bridge was first observed by the collector.
    pub first_seen: DateTime<Utc>,
    /// When this bridge was most recently observed.
    pub last_seen: DateTime<Utc>,
    /// The set of sources that reported this bridge.
    #[serde(default)]
    pub sources: BTreeSet<String>,
}

impl BridgeLine {
    /// Parse and strictly validate a bridge line, timestamping it with `now`.
    ///
    /// Fails with a [`ModelError`] if the line is empty, a comment, missing an
    /// endpoint, or violates a syntactic/semantic rule.
    pub fn parse(line: &str, now: DateTime<Utc>) -> Result<Self, ModelError> {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.contains("No bridges available")
            || trimmed.len() < 10
        {
            return Err(ModelError::NotABridgeLine(
                "empty, comment, or too short to be a bridge line",
            ));
        }

        let stripped = strip_bridge_prefix(trimmed);
        let tokens: Vec<&str> = stripped.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(ModelError::NotABridgeLine("no tokens after prefix strip"));
        }

        let transport = detect_transport_token(tokens[0]);

        let mut host: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut fingerprint: Option<String> = None;
        let mut params = BridgeParams::default();

        for token in &tokens {
            if let Some((key, value)) = token.split_once('=') {
                let key = key.trim_matches('"').to_ascii_lowercase();
                let value = value.trim_matches('"').to_string();
                match key.as_str() {
                    "cert" => params.cert = Some(value),
                    "iat-mode" => params.iat_mode = Some(value),
                    "url" => {
                        if validate::is_http_scheme(&value) {
                            params.url = Some(value);
                        }
                    }
                    "ver" | "version" => params.ver = Some(value),
                    "sni" | "front" => params.servername = Some(value),
                    "fronts" => {
                        if params.servername.is_none() {
                            params.servername = first_of_csv(&value);
                        }
                    }
                    "utls" | "utls-imitate" => params.utls = Some(value),
                    _ => {}
                }
                continue;
            }

            if validate::is_http_scheme(token) {
                if params.url.is_none() {
                    params.url = Some(token.to_string());
                }
                continue;
            }

            if fingerprint.is_none() {
                if let Some(normalized) = validate::normalize_fingerprint(token) {
                    fingerprint = Some(normalized);
                    continue;
                }
            }

            if host.is_none() {
                if let Some((endpoint_host, endpoint_port)) = endpoint_from_token(token) {
                    host = Some(endpoint_host);
                    port = Some(endpoint_port);
                }
            }
        }

        // Domain-only fronted lines have no literal endpoint; fall back to the
        // URL's host and port.
        if host.is_none() {
            if let Some(ref url_value) = params.url {
                if let Some((url_host, url_port)) = url_host_port(url_value) {
                    host = Some(url_host);
                    port = Some(url_port);
                }
            }
        }

        if params.servername.is_none() {
            if let Some(ref url_value) = params.url {
                if let Some((url_host, _)) = url_host_port(url_value) {
                    params.servername = Some(url_host);
                }
            }
        }

        let host = host.ok_or(ModelError::MissingField("host"))?;
        let port = port.ok_or(ModelError::MissingField("port"))?;

        let bridge = Self {
            raw: line.to_string(),
            transport,
            host,
            port,
            fingerprint,
            params,
            first_seen: now,
            last_seen: now,
            sources: BTreeSet::new(),
        };
        bridge.validate()?;
        Ok(bridge)
    }

    /// Re-validate an already-constructed (or JSON-loaded) bridge line.
    pub fn validate(&self) -> Result<(), ModelError> {
        if validate::validate_ip(&self.host).is_err() && !is_dns_name(&self.host) {
            return Err(ModelError::InvalidHost(self.host.clone()));
        }
        if let Some(ref fingerprint) = self.fingerprint {
            validate::validate_fingerprint(fingerprint)?;
        }
        if let Some(ref cert) = self.params.cert {
            validate::validate_obfs4_cert(cert)?;
        }
        if let Some(ref url_value) = self.params.url {
            if !validate::is_http_scheme(url_value) {
                return Err(ModelError::InvalidUrl(url_value.clone()));
            }
        }
        if self.transport == TransportKind::WebTunnel {
            match &self.params.url {
                Some(url_value) if validate::is_http_scheme(url_value) => {}
                Some(url_value) => return Err(ModelError::InvalidUrl(url_value.clone())),
                None => return Err(ModelError::MissingField("url")),
            }
        }
        Ok(())
    }

    /// A stable, canonical dedupe key: transport, host, port, fingerprint, and
    /// front domain. Two lines describing the same bridge produce the same key
    /// regardless of whitespace, quoting, or field order.
    pub fn canonical_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.transport,
            self.host.to_ascii_lowercase(),
            self.port,
            self.fingerprint.as_deref().unwrap_or(""),
            self.params.servername.as_deref().unwrap_or(""),
        )
    }

    /// The parsed IP address of the contact host, if it is an IP literal.
    pub fn host_ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Whether the contact host is an IPv6 literal.
    pub fn is_ipv6(&self) -> bool {
        self.host_ip()
            .map(|address| address.is_ipv6())
            .unwrap_or(false)
    }

    /// Record that `source` reported this bridge.
    pub fn add_source(&mut self, source: impl Into<String>) {
        self.sources.insert(source.into());
    }
}

// ── Observation model ─────────────────────────────────────────────────────

/// The kind of vantage point that produced an observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VantageKind {
    /// An out-of-country CI runner.
    Runner,
    /// An OONI probe (open data).
    Ooni,
    /// A RIPE Atlas measurement.
    RipeAtlas,
    /// A Globalping measurement.
    Globalping,
    /// A volunteer in-country agent.
    VolunteerAgent,
    /// Any other vantage kind.
    Other(String),
}

impl fmt::Display for VantageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runner => formatter.write_str("runner"),
            Self::Ooni => formatter.write_str("ooni"),
            Self::RipeAtlas => formatter.write_str("ripe_atlas"),
            Self::Globalping => formatter.write_str("globalping"),
            Self::VolunteerAgent => formatter.write_str("volunteer_agent"),
            Self::Other(token) => formatter.write_str(token),
        }
    }
}

impl std::str::FromStr for VantageKind {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "runner" => Ok(Self::Runner),
            "ooni" => Ok(Self::Ooni),
            "ripe_atlas" | "ripe-atlas" | "ripe" => Ok(Self::RipeAtlas),
            "globalping" | "global_ping" => Ok(Self::Globalping),
            "volunteer_agent" | "volunteer-agent" | "agent" => Ok(Self::VolunteerAgent),
            other => Ok(Self::Other(other.to_owned())),
        }
    }
}

impl Serialize for VantageKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VantageKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(DeError::custom)
    }
}

/// Metadata about where and how an observation was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vantage {
    /// The measurement platform.
    pub kind: VantageKind,
    /// ISO 3166-1 alpha-2 country code, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Autonomous-system number, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Autonomous-system name, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    /// Whether the vantage point is on a mobile network.
    pub is_mobile: bool,
}

/// The kind of probe that produced an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    TcpConnect,
    Obfs4Handshake,
    WebTunnelUpgrade,
    TorBootstrap,
    TlsSni,
    TcpTraceroute,
}

/// The evasion profile applied while probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionProfile {
    /// No evasion applied.
    None,
    /// TCP segmentation with a fixed number of fragments and inter-segment delay.
    Fragment {
        /// Number of segments to split the ClientHello/stream into.
        n: usize,
        /// Inter-segment delay in milliseconds.
        delay: u64,
    },
    /// An alternative TLS ClientHello fingerprint profile.
    AltClientHello {
        /// The uTLS-style profile name (e.g. `chrome`, `firefox`, `safari`).
        profile: String,
    },
}

/// The outcome of a single probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Reachable,
    Refused,
    Timeout,
    ResetInjected,
    TlsAlert,
    HandshakeAuthFail,
    HttpError { code: u16 },
    DnsFailure,
    Blocked { evidence: String },
    Inconclusive,
}

/// A single, time-stamped measurement of one bridge from one vantage point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The canonical key of the bridge that was measured.
    pub bridge_key: String,
    /// Where and how the measurement was taken.
    pub vantage: Vantage,
    /// The kind of probe that was run.
    pub probe_kind: ProbeKind,
    /// The evasion profile applied, if any.
    pub evasion_profile: EvasionProfile,
    /// The probe outcome.
    pub verdict: Verdict,
    /// Round-trip time in milliseconds, if measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// Tor bootstrap percentage reached, if a bootstrap probe ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_pct: Option<u8>,
    /// A classified error code (see the error taxonomy), if the probe failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Raw, unredacted evidence from the platform, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_evidence: Option<String>,
    /// When the measurement was taken.
    pub measured_at: DateTime<Utc>,
    /// The external platform's measurement identifier, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_ref: Option<String>,
}

// ── Scoring model ─────────────────────────────────────────────────────────

/// A bridge quality tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    S,
    A,
    B,
    C,
    D,
}

/// A `k`-of-`n` confidence value (k agreements among n independent observers).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confidence {
    /// Number of agreeing observations.
    pub k: u32,
    /// Total number of observations considered.
    pub n: u32,
}

impl Confidence {
    /// Construct a confidence value, rejecting `k > n`.
    pub fn new(k: u32, n: u32) -> Result<Self, ModelError> {
        if k > n {
            return Err(ModelError::InvalidConfidence { k, n });
        }
        Ok(Self { k, n })
    }

    /// The agreement fraction in `0.0..=1.0` (0 when there are no observations).
    pub fn fraction(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.k as f64 / self.n as f64
        }
    }
}

/// A scored bridge: global score, per-ASN scores, tier, and lifetime metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgeScore {
    /// Global quality score in `0.0..=100.0`.
    pub global: f64,
    /// Per-ASN scores keyed by autonomous-system number.
    #[serde(default)]
    pub per_asn: std::collections::BTreeMap<u32, f64>,
    /// The assigned tier.
    pub tier: Tier,
    /// Confidence in the score (k-of-n).
    pub confidence: Confidence,
    /// When the bridge was first confirmed working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_confirmed_working_at: Option<DateTime<Utc>>,
    /// When the bridge was first confirmed blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_blocked_at: Option<DateTime<Utc>>,
    /// Seconds between first confirmed working and first confirmed blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burn_seconds: Option<u64>,
    /// Median observed lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_lifetime_seconds: Option<u64>,
    /// Age in seconds of the freshest evidence feeding this score.
    pub freshness_age_seconds: u64,
}

impl BridgeScore {
    /// Validate score ranges and confidence consistency.
    pub fn validate(&self) -> Result<(), ModelError> {
        if !(0.0..=100.0).contains(&self.global) {
            return Err(ModelError::InvalidScore(self.global));
        }
        for score in self.per_asn.values() {
            if !(0.0..=100.0).contains(score) {
                return Err(ModelError::InvalidScore(*score));
            }
        }
        if self.confidence.k > self.confidence.n {
            return Err(ModelError::InvalidConfidence {
                k: self.confidence.k,
                n: self.confidence.n,
            });
        }
        Ok(())
    }
}

// ── Parsing helpers ───────────────────────────────────────────────────────

fn strip_bridge_prefix(line: &str) -> &str {
    let trimmed = line.trim();
    trimmed
        .strip_prefix("Bridge ")
        .map(str::trim)
        .unwrap_or(trimmed)
}

fn detect_transport_token(first: &str) -> TransportKind {
    if let Some(kind) = transport_keyword(first) {
        return kind;
    }
    if first.contains(':')
        || first.contains('=')
        || looks_like_ipv4(first)
        || first.starts_with("http://")
        || first.starts_with("https://")
    {
        TransportKind::Vanilla
    } else {
        TransportKind::Other(first.to_ascii_lowercase())
    }
}

fn transport_keyword(token: &str) -> Option<TransportKind> {
    match token.to_ascii_lowercase().as_str() {
        "obfs4" => Some(TransportKind::Obfs4),
        "webtunnel" | "web-tunnel" => Some(TransportKind::WebTunnel),
        "vanilla" => Some(TransportKind::Vanilla),
        "snowflake" => Some(TransportKind::Snowflake),
        "meek" | "meek_lite" | "meek-azure" => Some(TransportKind::Meek),
        "conjure" => Some(TransportKind::Conjure),
        _ => None,
    }
}

fn looks_like_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_dns_name(host: &str) -> bool {
    host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn first_of_csv(value: &str) -> Option<String> {
    value
        .split(',')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .map(String::from)
}

fn endpoint_from_token(token: &str) -> Option<(String, u16)> {
    let token = token.trim_matches(|character: char| matches!(character, ',' | ';' | '"'));
    if token.is_empty()
        || token.contains('=')
        || token.starts_with("http://")
        || token.starts_with("https://")
    {
        return None;
    }

    if let Some(rest) = token.strip_prefix('[') {
        let (host, port_text) = rest.split_once("]:")?;
        let port = parse_port_text(port_text).ok()?;
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return Some((host.to_owned(), port));
        }
        return None;
    }

    let (host, port_text) = token.rsplit_once(':')?;
    let port = parse_port_text(port_text).ok()?;
    if host.is_empty() || host.contains(':') || host.contains('/') {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || is_dns_name(host) {
        return Some((host.to_owned(), port));
    }
    None
}

fn parse_port_text(value: &str) -> Result<u16, ModelError> {
    validate::validate_port(value)
}

fn url_host_port(value: &str) -> Option<(String, u16)> {
    let parsed = url::Url::parse(value).ok()?;
    let host = parsed.host_str()?.to_owned();
    let port = parsed.port_or_known_default()?;
    Some((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-13T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn cert52() -> String {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use base64::Engine as _;
        STANDARD_NO_PAD.encode([0x5au8; 52])
    }

    fn fp() -> &'static str {
        "0123456789ABCDEF0123456789ABCDEF01234567"
    }

    #[test]
    fn parses_obfs4_ipv4_with_real_cert() {
        let line = format!("obfs4 1.2.3.4:443 {} cert={} iat-mode=0", fp(), cert52());
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert_eq!(bridge.transport, TransportKind::Obfs4);
        assert_eq!(bridge.host, "1.2.3.4");
        assert_eq!(bridge.port, 443);
        assert_eq!(bridge.fingerprint.as_deref(), Some(fp()));
        assert_eq!(bridge.params.cert.as_deref(), Some(cert52().as_str()));
        assert!(!bridge.is_ipv6());
    }

    #[test]
    fn parses_obfs4_ipv6() {
        let line = format!(
            "obfs4 [2001:db8::1]:8443 {} cert={} iat-mode=2",
            fp(),
            cert52()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert_eq!(bridge.host, "2001:db8::1");
        assert_eq!(bridge.port, 8443);
        assert!(bridge.is_ipv6());
    }

    #[test]
    fn parses_webtunnel_with_literal_endpoint() {
        let line = format!(
            "webtunnel 1.2.3.4:443 {} url=https://example.com/path ver=0.0.4",
            fp()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert_eq!(bridge.transport, TransportKind::WebTunnel);
        assert_eq!(bridge.host, "1.2.3.4");
        assert_eq!(bridge.port, 443);
        assert_eq!(bridge.params.servername.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_webtunnel_domain_only() {
        let line = format!(
            "webtunnel {} url=https://vault.example.xyz/path ver=0.0.3",
            fp()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert_eq!(bridge.host, "vault.example.xyz");
        assert_eq!(bridge.port, 443);
    }

    #[test]
    fn parses_vanilla_ipv4_and_ipv6() {
        let v4 = BridgeLine::parse(&format!("1.2.3.4:9001 {}", fp()), now()).unwrap();
        assert_eq!(v4.transport, TransportKind::Vanilla);
        let v6 = BridgeLine::parse(&format!("[2001:db8::1]:9001 {}", fp()), now()).unwrap();
        assert!(v6.is_ipv6());
    }

    #[test]
    fn parses_fronted_snowflake() {
        let line = format!(
            "snowflake 192.0.2.3:80 {} url=https://broker.example/ fronts=www.cdn77.com ice=stun:stun.l.google.com:19302",
            fp()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert_eq!(bridge.transport, TransportKind::Snowflake);
        assert_eq!(bridge.params.servername.as_deref(), Some("www.cdn77.com"));
    }

    #[test]
    fn unknown_transport_maps_to_other() {
        let bridge = BridgeLine::parse("vless 1.2.3.4:443 sni=example.com", now()).unwrap();
        assert_eq!(bridge.transport, TransportKind::Other("vless".to_owned()));
    }

    #[test]
    fn rejects_empty_and_comment_lines() {
        assert!(BridgeLine::parse("", now()).is_err());
        assert!(BridgeLine::parse("# obfs4 1.2.3.4:443 cert=abc", now()).is_err());
        assert!(BridgeLine::parse("No bridges available", now()).is_err());
    }

    #[test]
    fn rejects_port_zero() {
        let line = format!("obfs4 1.2.3.4:0 {} cert={}", fp(), cert52());
        let err = BridgeLine::parse(&line, now()).unwrap_err();
        assert!(matches!(err, ModelError::MissingField(_)));
    }

    #[test]
    fn rejects_truncated_cert() {
        let truncated = cert52()[..66].to_string();
        let line = format!("obfs4 1.2.3.4:443 {} cert={}", fp(), truncated);
        let err = BridgeLine::parse(&line, now()).unwrap_err();
        assert!(matches!(err, ModelError::InvalidCertLength(_)));
    }

    #[test]
    fn rejects_webtunnel_without_url() {
        let line = format!("webtunnel 1.2.3.4:443 {}", fp());
        let err = BridgeLine::parse(&line, now()).unwrap_err();
        assert!(matches!(err, ModelError::MissingField("url")));
    }

    #[test]
    fn non_hex_40_char_token_is_not_a_fingerprint() {
        let line = format!(
            "obfs4 1.2.3.4:443 ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ cert={} iat-mode=0",
            cert52()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        assert!(bridge.fingerprint.is_none());
    }

    #[test]
    fn canonical_key_dedupes_equivalent_lines() {
        let a = format!("obfs4 1.2.3.4:443 {} cert={} iat-mode=0", fp(), cert52());
        let b = format!(
            "   Bridge obfs4   1.2.3.4:443   {} cert={} iat-mode=0",
            fp(),
            cert52()
        );
        let key_a = BridgeLine::parse(&a, now()).unwrap().canonical_key();
        let key_b = BridgeLine::parse(&b, now()).unwrap().canonical_key();
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn sources_are_a_set() {
        let line = format!("obfs4 1.2.3.4:443 {} cert={} iat-mode=0", fp(), cert52());
        let mut bridge = BridgeLine::parse(&line, now()).unwrap();
        bridge.add_source("bridgedb");
        bridge.add_source("bridgedb");
        bridge.add_source("delta");
        assert_eq!(bridge.sources.len(), 2);
    }

    #[test]
    fn confidence_rejects_k_greater_than_n() {
        assert!(Confidence::new(1, 3).is_ok());
        assert!(Confidence::new(4, 3).is_err());
        assert_eq!(Confidence::new(2, 4).unwrap().fraction(), 0.5);
        assert_eq!(Confidence::default().fraction(), 0.0);
    }

    #[test]
    fn bridge_score_validation_enforces_ranges() {
        let mut score = BridgeScore {
            global: 95.0,
            per_asn: std::collections::BTreeMap::new(),
            tier: Tier::S,
            confidence: Confidence::new(3, 3).unwrap(),
            first_confirmed_working_at: None,
            first_blocked_at: None,
            burn_seconds: None,
            median_lifetime_seconds: None,
            freshness_age_seconds: 60,
        };
        assert!(score.validate().is_ok());
        score.global = 101.0;
        assert!(score.validate().is_err());
    }

    #[test]
    fn observation_serde_round_trips() {
        let observation = Observation {
            bridge_key: "obfs4|1.2.3.4|443|FINGER|".to_owned(),
            vantage: Vantage {
                kind: VantageKind::Ooni,
                country: Some("IR".to_owned()),
                asn: Some(197_207),
                as_name: Some("MCCI".to_owned()),
                is_mobile: true,
            },
            probe_kind: ProbeKind::Obfs4Handshake,
            evasion_profile: EvasionProfile::Fragment { n: 2, delay: 30 },
            verdict: Verdict::Blocked {
                evidence: "SYN drop after ClientHello".to_owned(),
            },
            rtt_ms: Some(250),
            bootstrap_pct: None,
            error_class: Some("reset_injected".to_owned()),
            raw_evidence: None,
            measured_at: now(),
            measurement_ref: Some("atlas-123".to_owned()),
        };
        let json = serde_json::to_string(&observation).unwrap();
        let decoded: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(observation, decoded);
        // Stable enum tokens.
        assert!(json.contains("\"obfs4_handshake\""));
        assert!(json.contains("\"ooni\""));
        assert!(json.contains("\"blocked\""));
    }

    #[test]
    fn transport_kind_serde_is_a_plain_string() {
        let json =
            serde_json::to_string(&TransportKind::Other("vless-reality".to_owned())).unwrap();
        assert_eq!(json, "\"vless-reality\"");
        let back: TransportKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TransportKind::Other("vless-reality".to_owned()));
    }
}
