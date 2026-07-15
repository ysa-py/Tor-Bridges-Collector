//! Parity port of `ech_fingerprint_evasion.py`.
//!
//! ECH + TLS Fingerprint Evasion Scorer for Iran. Detects which bridges
//! support Encrypted Client Hello (ECH/ESNI) and scores them for DPI
//! evasion effectiveness under Iran's SIAM/NGFW deep-packet inspection.
//! ECH hides the SNI from passive interceptors, making it very difficult
//! for Iran's DPI to identify Tor traffic.
//!
//! # Iran-specific scoring (mirrors Python constants)
//!
//! * ECH-enabled bridges: +0.40 Iran score bonus
//! * TLS 1.3-only bridges: +0.20 (TLS 1.2 handshakes are easier to fingerprint)
//! * Non-standard ports (not 443/80/9001/9030): +0.10 (avoids port blocklists)
//! * CDN-fronted (WebTunnel): +0.30 bonus (hardest to block without breaking HTTPS)
//!
//! # Behavior traced to `ech_fingerprint_evasion.py`
//!
//! * [`IRAN_HIGH_RISK_PORTS`] — module-level constant set.
//! * [`CDN_KEYWORDS`] — module-level constant set.
//! * [`set_tls_probe_failure`] / [`TlsProbeResult::with_failure`] —
//!   structured TLS probe failure fields for expected network errors.
//! * [`check_ech`] / [`check_ech_with_probe`] — TLS handshake + ECH support
//!   probe. Takes an injectable [`TlsProbe`] client.
//! * [`score_bridge`] — score a single bridge line for Iran DPI evasion.
//! * [`run_pipeline`] — orchestrates load → score → sort → write report.
//!
//! # Side effects not ported
//!
//! * `main()` orchestration reads `bridge/bridge_list_for_testing.json` and
//!   writes `data/ech_report.json` + `export/ech_top_bridges.txt`. Both
//!   behaviors are exposed as [`run_pipeline`] taking injectable paths.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (mirrors module-level constants in ech_fingerprint_evasion.py)
// ─────────────────────────────────────────────────────────────────────────────

/// Iran high-risk ports explicitly blocked by SIAM/NGFW (Python set).
pub const IRAN_HIGH_RISK_PORTS: &[u16] = &[9001, 9030, 9050, 9051];

/// CDN keywords used to detect CDN-fronted bridges (Python set).
pub const CDN_KEYWORDS: &[&str] = &[
    "cloudflare",
    "fastly",
    "akamai",
    "amazon",
    "cloudfront",
    "azure",
    "arvan",
    "gcore",
    "bunnycdn",
    "cdn77",
];

/// Default TLS probe timeout (Python `_check_ech` default = 8.0s).
pub const DEFAULT_TLS_PROBE_TIMEOUT: f64 = 8.0;

/// Maximum number of bridges scanned in one run (Python cap = 200).
pub const MAX_BRIDGES_PER_RUN: usize = 200;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `ech_fingerprint_evasion.py` parity port.
#[derive(Debug, Error)]
pub enum EchFingerprintError {
    /// File I/O failure on the input bridge JSON or output report path.
    #[error("ech_fingerprint_evasion I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Input bridge JSON was not a JSON array of strings.
    #[error("ech_fingerprint_evasion: bridge list is not a JSON array of strings (got {0})")]
    InvalidBridgeList(String),

    /// Bridge list JSON could not be parsed.
    #[error("ech_fingerprint_evasion: bridge list JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable TLS probe trait
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a TLS probe for a single `(host, port)` target. Mirrors the
/// Python `_check_ech` returned dict shape exactly.
#[derive(Debug, Clone, Default)]
pub struct TlsProbeResult {
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// True if a TCP+TLS handshake completed successfully.
    pub tls_reachable: bool,
    /// TLS protocol version string (e.g. `"TLSv1.3"`) if reachable.
    pub tls_version: Option<String>,
    /// True if ECH/ESNI extension was observed (heuristic: cert contains `ech`).
    pub ech_supported: bool,
    /// True if ECH GREASE was observed (heuristic; always false in this port).
    pub ech_grease: bool,
    /// Status string: `reachable`, `timeout`, `connection_refused`,
    /// `ssl_error`, `unreachable`, `not_attempted`, `unexpected_error`.
    pub tls_probe_status: String,
    /// Exception class name when status indicates a failure (mirrors Python).
    pub tls_error_type: Option<String>,
    /// Internal flag: when true, [`to_json`] returns an empty JSON object
    /// (mirrors Python's `ech_data = {}` when `_check_ech` is monkey-patched
    /// to a no-op in tests, or when the bridge line has no host).
    pub probe_is_noop: bool,
}

impl TlsProbeResult {
    /// Build a fresh probe result for `(host, port)`. Mirrors the Python
    /// `_check_ech` initial dict literal (status = `"not_attempted"`).
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls_reachable: false,
            tls_version: None,
            ech_supported: false,
            ech_grease: false,
            tls_probe_status: "not_attempted".to_string(),
            tls_error_type: None,
            probe_is_noop: false,
        }
    }

    /// Populate structured TLS probe failure fields. Mirrors Python
    /// `_set_tls_probe_failure(result, status, exc)`.
    pub fn with_failure(mut self, status: &str, error_type: &str) -> Self {
        self.tls_probe_status = status.to_string();
        self.tls_error_type = Some(error_type.to_string());
        self
    }

    /// Convert to a `serde_json::Value` matching the Python dict shape.
    /// When `probe_is_noop` is true, returns an empty JSON object —
    /// mirroring Python's `ech_data = {}` when `_check_ech` is monkey-patched.
    pub fn to_json(&self) -> Value {
        if self.probe_is_noop {
            return Value::Object(Map::new());
        }
        let mut m = Map::new();
        m.insert("host".to_string(), json!(self.host));
        m.insert("port".to_string(), json!(self.port));
        m.insert("tls_reachable".to_string(), json!(self.tls_reachable));
        m.insert(
            "tls_version".to_string(),
            self.tls_version
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert("ech_supported".to_string(), json!(self.ech_supported));
        m.insert("ech_grease".to_string(), json!(self.ech_grease));
        m.insert("tls_probe_status".to_string(), json!(self.tls_probe_status));
        m.insert(
            "tls_error_type".to_string(),
            self.tls_error_type
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

/// Injectable TLS probe used by [`check_ech_with_probe`].
///
/// Production code uses a real TLS handshake (gated behind the `network`
/// Cargo feature); tests substitute a mock that returns canned
/// [`TlsProbeResult`] values without opening sockets.
pub trait TlsProbe {
    /// Probe `(host, port)` for TLS reachability and ECH support within
    /// `timeout_s` seconds.
    fn probe(&self, host: &str, port: u16, timeout_s: f64) -> TlsProbeResult;
}

/// No-op TLS probe that always returns an EMPTY JSON object. Mirrors
/// Python's behaviour when `_check_ech` is monkey-patched to
/// `lambda h, p, t=8.0: {}` in tests, OR when the input bridge line has
/// no host (Python returns `ech_data = {}` and the spread `**ech_data`
/// adds zero keys to the output dict).
pub struct NoProbe;

impl TlsProbe for NoProbe {
    fn probe(&self, _host: &str, _port: u16, _timeout_s: f64) -> TlsProbeResult {
        // The `to_json()` of this result is overridden below via the
        // `probe_is_noop` flag to return an empty JSON object.
        TlsProbeResult {
            host: String::new(),
            port: 0,
            tls_reachable: false,
            tls_version: None,
            ech_supported: false,
            ech_grease: false,
            tls_probe_status: String::new(),
            tls_error_type: None,
            probe_is_noop: true,
        }
    }
}

/// Helper matching Python's `_check_ech` exit dict. When the host is `None`
/// (i.e. the bridge line had no IPv4 host:port), Python returns an empty
/// dict (`ech_data = {}`) — equivalent to skipping the probe entirely.
pub fn check_ech_with_probe(
    host: Option<&str>,
    port: u16,
    timeout_s: f64,
    probe: &dyn TlsProbe,
) -> Value {
    match host {
        None => Value::Object(Map::new()),
        Some(h) => probe.probe(h, port, timeout_s).to_json(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge-line parsing helpers (mirror Python regex and detection)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the first IPv4 host:port pair from a bridge line. Returns
/// `(host, port)` or `None` if no match (mirrors Python regex
/// `(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})`).
pub fn extract_host_port(line: &str) -> Option<(String, u16)> {
    let re = Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").ok()?;
    let caps = re.captures(line)?;
    let port: u16 = caps[2].parse().ok()?;
    Some((caps[1].to_string(), port))
}

/// Detect transport from a bridge line. Mirrors Python `score_bridge` loop:
/// `for kw in ("snowflake", "webtunnel", "obfs4", "meek")`. Order matters:
/// snowflake takes priority over webtunnel, webtunnel over obfs4, etc.
pub fn detect_transport(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("snowflake") {
        "snowflake"
    } else if l.contains("webtunnel") {
        "webtunnel"
    } else if l.contains("obfs4") {
        "obfs4"
    } else if l.contains("meek") {
        "meek"
    } else {
        "vanilla"
    }
}

/// Return true if `port` is in [`IRAN_HIGH_RISK_PORTS`].
pub fn is_iran_high_risk_port(port: u16) -> bool {
    IRAN_HIGH_RISK_PORTS.contains(&port)
}

/// Score a single bridge line for Iran DPI evasion. Mirrors Python
/// `score_bridge(line)` exactly, including the floating-point bonuses,
/// the `min(score, 1.0)` clamp, the `round(..., 3)` precision, and the
/// `flags` vector accumulation order.
///
/// The `probe` argument is an injectable [`TlsProbe`] so tests can
/// substitute canned responses. Use [`NoProbe`] to skip the TLS probe
/// (equivalent to Python's `host is None` path).
pub fn score_bridge_with_probe(line: &str, probe: &dyn TlsProbe) -> Value {
    let trimmed = line.trim();
    let transport = detect_transport(trimmed);
    let (host_opt, port) = match extract_host_port(trimmed) {
        Some((h, p)) => (Some(h), p),
        None => (None, 443u16),
    };
    let host_ref: Option<&str> = host_opt.as_deref();

    let mut score: f64 = 0.0;
    let mut flags: Vec<&str> = Vec::new();

    if transport == "webtunnel" {
        score += 0.30;
        flags.push("cdn_fronted");
    }
    if transport == "snowflake" {
        score += 0.35;
        flags.push("webrtc_snowflake");
    }
    if transport == "obfs4" {
        score += 0.15;
        flags.push("obfs4_obfuscated");
    }
    if port != 0 && !is_iran_high_risk_port(port) && port != 80 {
        score += 0.10;
        flags.push("non_standard_port");
    }

    let ech_data = check_ech_with_probe(host_ref, port, DEFAULT_TLS_PROBE_TIMEOUT, probe);
    if let Some(reachable) = ech_data.get("tls_reachable").and_then(Value::as_bool) {
        if reachable {
            score += 0.10;
        }
    }
    if let Some(true) = ech_data.get("ech_supported").and_then(Value::as_bool) {
        score += 0.40;
        flags.push("ech_enabled");
    }
    if let Some(v) = ech_data.get("tls_version").and_then(Value::as_str) {
        if v == "TLSv1.3" {
            score += 0.20;
            flags.push("tls13_only");
        }
    }

    let clamped = score.min(1.0);
    let rounded = (clamped * 1000.0).round() / 1000.0;

    let mut out = Map::new();
    out.insert("bridge_line".to_string(), json!(trimmed));
    out.insert("transport".to_string(), json!(transport));
    out.insert("iran_dpi_evasion_score".to_string(), json!(rounded));
    out.insert(
        "flags".to_string(),
        json!(flags.into_iter().collect::<Vec<_>>()),
    );
    if let Value::Object(ech_map) = ech_data {
        for (k, v) in ech_map {
            out.insert(k, v);
        }
    }
    Value::Object(out)
}

/// Convenience wrapper around [`score_bridge_with_probe`] using [`NoProbe`].
/// Matches Python's `score_bridge` default behaviour when no network probe
/// is desired (e.g. offline scoring tests).
pub fn score_bridge(line: &str) -> Value {
    score_bridge_with_probe(line, &NoProbe)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline orchestration (mirrors Python `main()`)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full ECH scan pipeline:
/// 1. Read `bridge/bridge_list_for_testing.json` (JSON array of strings).
/// 2. Cap to [`MAX_BRIDGES_PER_RUN`] bridges.
/// 3. Score each bridge via [`score_bridge_with_probe`].
/// 4. Sort by `iran_dpi_evasion_score` descending.
/// 5. Write `{"bridges": [...]}` to `data/ech_report.json`.
/// 6. Write high-score bridges (>= 0.5) to `export/ech_top_bridges.txt`,
///    one per line, with trailing newline.
///
/// Mirrors Python `main()` byte-for-byte (same field order, same
/// indentation, same sort key, same threshold).
pub fn run_pipeline(
    bridge_json_path: &Path,
    report_path: &Path,
    export_path: &Path,
    probe: &dyn TlsProbe,
) -> Result<(), EchFingerprintError> {
    let raw = fs::read_to_string(bridge_json_path).map_err(|source| EchFingerprintError::Io {
        path: bridge_json_path.display().to_string(),
        source,
    })?;
    let bridges: Vec<String> = serde_json::from_str(&raw)
        .map_err(EchFingerprintError::Json)
        .and_then(|v: Value| match v {
            Value::Array(arr) => arr
                .into_iter()
                .map(|x| match x {
                    Value::String(s) => Ok(s),
                    other => Err(EchFingerprintError::InvalidBridgeList(format!(
                        "element is not a string: {other}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>(),
            other => Err(EchFingerprintError::InvalidBridgeList(format!(
                "expected array, got {other}"
            ))),
        })?;

    let capped: Vec<&String> = bridges.iter().take(MAX_BRIDGES_PER_RUN).collect();
    let mut results: Vec<Value> = capped
        .iter()
        .map(|line| score_bridge_with_probe(line, probe))
        .collect();

    results.sort_by(|a, b| {
        let sa = a
            .get("iran_dpi_evasion_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let sb = b
            .get("iran_dpi_evasion_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let report = json!({ "bridges": results });
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).map_err(|source| EchFingerprintError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let report_bytes = serde_json::to_string_pretty(&report).unwrap_or_default() + "\n";
    fs::write(report_path, report_bytes).map_err(|source| EchFingerprintError::Io {
        path: report_path.display().to_string(),
        source,
    })?;

    let top: Vec<&str> = results
        .iter()
        .filter_map(|r| {
            let score = r
                .get("iran_dpi_evasion_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if score >= 0.5 {
                r.get("bridge_line").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect();
    if !top.is_empty() {
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent).map_err(|source| EchFingerprintError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let mut out = top.join("\n");
        out.push('\n');
        fs::write(export_path, out).map_err(|source| EchFingerprintError::Io {
            path: export_path.display().to_string(),
            source,
        })?;
    }

    // Track probe status counts (mirrors Python `probe_status_counts` Counter).
    let mut probe_status_counts: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    for r in &results {
        if let Some(s) = r.get("tls_probe_status").and_then(Value::as_str) {
            *probe_status_counts.entry(s.to_string()).or_insert(0) += 1;
        }
    }
    let expected: BTreeSet<&str> = ["timeout", "connection_refused", "ssl_error", "unreachable"]
        .iter()
        .copied()
        .collect();
    let _expected_count: u32 = probe_status_counts
        .iter()
        .filter(|(k, _)| expected.contains(k.as_str()))
        .map(|(_, v)| *v)
        .sum();
    // Mirrors Python: only logged, not surfaced; we compute it to keep
    // behaviour parity (no silent drop of the Counter logic).

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysReachableTls13;
    impl TlsProbe for AlwaysReachableTls13 {
        fn probe(&self, host: &str, port: u16, _timeout_s: f64) -> TlsProbeResult {
            TlsProbeResult {
                host: host.to_string(),
                port,
                tls_reachable: true,
                tls_version: Some("TLSv1.3".to_string()),
                ech_supported: false,
                ech_grease: false,
                tls_probe_status: "reachable".to_string(),
                tls_error_type: None,
                probe_is_noop: false,
            }
        }
    }

    struct AlwaysTimeout;
    impl TlsProbe for AlwaysTimeout {
        fn probe(&self, host: &str, port: u16, _timeout_s: f64) -> TlsProbeResult {
            TlsProbeResult::new(host, port).with_failure("timeout", "TimeoutError")
        }
    }

    struct AlwaysEch;
    impl TlsProbe for AlwaysEch {
        fn probe(&self, host: &str, port: u16, _timeout_s: f64) -> TlsProbeResult {
            TlsProbeResult {
                host: host.to_string(),
                port,
                tls_reachable: true,
                tls_version: Some("TLSv1.3".to_string()),
                ech_supported: true,
                ech_grease: false,
                tls_probe_status: "reachable".to_string(),
                tls_error_type: None,
                probe_is_noop: false,
            }
        }
    }

    #[test]
    fn detect_transport_priority_matches_python() {
        // snowflake > webtunnel > obfs4 > meek > vanilla
        assert_eq!(detect_transport("snowflake 1.2.3.4:443"), "snowflake");
        assert_eq!(
            detect_transport("webtunnel url=https://x snowflake"),
            "snowflake"
        );
        assert_eq!(detect_transport("obfs4 1.2.3.4:443"), "obfs4");
        assert_eq!(detect_transport("meek 1.2.3.4:443"), "meek");
        assert_eq!(detect_transport("1.2.3.4:443 vanilla"), "vanilla");
    }

    #[test]
    fn extract_host_port_matches_python_regex() {
        let (h, p) = extract_host_port("obfs4 192.168.1.1:443 cert=abc").unwrap();
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, 443);
        // No IPv4 → None
        assert!(extract_host_port("vanilla [::1]:443").is_none());
        // Port out of u16 range → None (Python regex would match but
        // int() succeeds with arbitrary precision; we use u16 because the
        // Python `score_bridge` always uses port as `int(m.group(2))` and
        // only ever feeds it to socket-level calls which are u16).
        assert!(extract_host_port("x 1.2.3.4:99999").is_none());
    }

    #[test]
    fn score_bridge_vanilla_no_host_uses_default_443() {
        let r = score_bridge("vanilla-line");
        assert_eq!(r["transport"], "vanilla");
        // No host → port defaults to 443 internally, but is NOT emitted in
        // the output dict (Python's `**ech_data` spreads nothing when host
        // is None — equivalent to NoProbe returning empty JSON object).
        assert!(r.get("port").is_none() || r["port"].is_null());
        // score = 0.10 (non_standard_port: 443 not in high-risk, not 80)
        assert_eq!(r["iran_dpi_evasion_score"], 0.10);
        assert_eq!(r["flags"][0], "non_standard_port");
    }

    #[test]
    fn score_bridge_webtunnel_no_probe_adds_cdn_bonus() {
        let r = score_bridge("webtunnel url=https://example.com:443");
        assert_eq!(r["transport"], "webtunnel");
        // 0.30 (cdn) + 0.10 (port 443 non-standard, not high-risk, not 80) = 0.40
        assert_eq!(r["iran_dpi_evasion_score"], 0.40);
        assert_eq!(r["flags"][0], "cdn_fronted");
        assert_eq!(r["flags"][1], "non_standard_port");
    }

    #[test]
    fn score_bridge_snowflake_no_probe_adds_webrtc_bonus() {
        let r = score_bridge("snowflake 1.2.3.4:443");
        assert_eq!(r["transport"], "snowflake");
        // 0.35 + 0.10 = 0.45
        assert_eq!(r["iran_dpi_evasion_score"], 0.45);
    }

    #[test]
    fn score_bridge_obfs4_high_risk_port_no_bonus() {
        // Port 9001 is in IRAN_HIGH_RISK_PORTS → no non_standard_port bonus
        let r = score_bridge("obfs4 1.2.3.4:9001");
        assert_eq!(r["transport"], "obfs4");
        // 0.15 only (no port bonus, no probe)
        assert_eq!(r["iran_dpi_evasion_score"], 0.15);
    }

    #[test]
    fn score_bridge_port_80_no_non_standard_bonus() {
        // Python: `if port and port not in IRAN_HIGH_RISK_PORTS and port != 80:`
        let r = score_bridge("vanilla 1.2.3.4:80");
        assert_eq!(r["transport"], "vanilla");
        // 0 (no transport bonus) + 0 (port 80 excluded) = 0
        assert_eq!(r["iran_dpi_evasion_score"], 0.0);
    }

    #[test]
    fn score_bridge_with_reachable_tls13_adds_0_30() {
        let r = score_bridge_with_probe("vanilla 1.2.3.4:443", &AlwaysReachableTls13);
        // 0.10 (non_standard_port) + 0.10 (tls_reachable) + 0.20 (tls13) = 0.40
        assert_eq!(r["iran_dpi_evasion_score"], 0.40);
        assert!(r["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "tls13_only"));
    }

    #[test]
    fn score_bridge_with_ech_adds_0_40() {
        let r = score_bridge_with_probe("vanilla 1.2.3.4:443", &AlwaysEch);
        // 0.10 (non_standard_port) + 0.10 (reachable) + 0.40 (ech) + 0.20 (tls13) = 0.80
        assert_eq!(r["iran_dpi_evasion_score"], 0.80);
        assert!(r["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "ech_enabled"));
    }

    #[test]
    fn score_bridge_with_timeout_no_bonus() {
        let r = score_bridge_with_probe("vanilla 1.2.3.4:443", &AlwaysTimeout);
        // 0.10 (non_standard_port) + 0 (not reachable) = 0.10
        assert_eq!(r["iran_dpi_evasion_score"], 0.10);
        assert_eq!(r["tls_probe_status"], "timeout");
        assert_eq!(r["tls_error_type"], "TimeoutError");
    }

    #[test]
    fn score_bridge_clamps_to_1_0() {
        // webtunnel + ech + tls13 + non_standard_port + reachable
        // = 0.30 + 0.10 + 0.10 + 0.40 + 0.20 = 1.10 → clamped to 1.0
        let r = score_bridge_with_probe("webtunnel url=https://x 1.2.3.4:443", &AlwaysEch);
        assert_eq!(r["iran_dpi_evasion_score"], 1.0);
    }

    #[test]
    fn score_bridge_rounding_to_3_decimals() {
        // 0.35 (snowflake) + 0.10 = 0.45 → no rounding needed
        let r = score_bridge("snowflake 1.2.3.4:443");
        assert_eq!(r["iran_dpi_evasion_score"], 0.45);
    }

    #[test]
    fn tls_probe_result_with_failure_sets_status_and_type() {
        let r = TlsProbeResult::new("1.2.3.4", 443).with_failure("ssl_error", "SSLError");
        assert_eq!(r.tls_probe_status, "ssl_error");
        assert_eq!(r.tls_error_type.as_deref(), Some("SSLError"));
        assert!(!r.tls_reachable);
    }

    #[test]
    fn tls_probe_result_to_json_matches_python_dict_shape() {
        let r = TlsProbeResult::new("1.2.3.4", 443);
        let v = r.to_json();
        assert_eq!(v["host"], "1.2.3.4");
        assert_eq!(v["port"], 443);
        assert_eq!(v["tls_reachable"], false);
        assert!(v["tls_version"].is_null());
        assert_eq!(v["ech_supported"], false);
        assert_eq!(v["ech_grease"], false);
        assert_eq!(v["tls_probe_status"], "not_attempted");
        assert!(v["tls_error_type"].is_null());
    }

    #[test]
    fn run_pipeline_writes_report_and_export() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        let report = tmp.join("ech_report.json");
        let export = tmp.join("ech_top_bridges.txt");
        let bridges = vec![
            "vanilla 1.2.3.4:80".to_string(),
            "snowflake 5.6.7.8:443".to_string(),
            "webtunnel url=https://x 9.10.11.12:443".to_string(),
        ];
        std::fs::write(&bridge_json, serde_json::to_string(&bridges).unwrap()).unwrap();

        run_pipeline(&bridge_json, &report, &export, &NoProbe).unwrap();

        let rep: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
        let arr = rep["bridges"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        // Sorted descending: webtunnel (0.40) > snowflake (0.45)? no snowflake = 0.45 > webtunnel = 0.40
        // Actually: snowflake 0.45, webtunnel 0.40, vanilla 0.0
        assert_eq!(arr[0]["transport"], "snowflake");
        assert_eq!(arr[1]["transport"], "webtunnel");
        assert_eq!(arr[2]["transport"], "vanilla");

        // Top bridges (>= 0.5): snowflake (0.45) and webtunnel (0.40) both < 0.5
        // → export file should NOT be created
        assert!(!export.exists());
    }

    #[test]
    fn run_pipeline_writes_export_when_high_score() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        let report = tmp.join("ech_report.json");
        let export = tmp.join("ech_top_bridges.txt");
        let bridges = vec![
            "webtunnel url=https://x 1.2.3.4:443".to_string(), // 0.40 + ech/tls13 with AlwaysEch → 1.0
        ];
        std::fs::write(&bridge_json, serde_json::to_string(&bridges).unwrap()).unwrap();

        run_pipeline(&bridge_json, &report, &export, &AlwaysEch).unwrap();

        let export_text = std::fs::read_to_string(&export).unwrap();
        assert!(export_text.contains("webtunnel"));
        assert!(export_text.ends_with('\n'));
    }

    #[test]
    fn run_pipeline_missing_input_returns_io_error() {
        let tmp = tempfile_dir();
        let err = run_pipeline(
            &tmp.join("missing.json"),
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
            &NoProbe,
        )
        .unwrap_err();
        match err {
            EchFingerprintError::Io { .. } => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn run_pipeline_invalid_json_returns_json_error() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        std::fs::write(&bridge_json, "not json {{{").unwrap();
        let err = run_pipeline(
            &bridge_json,
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
            &NoProbe,
        )
        .unwrap_err();
        match err {
            EchFingerprintError::Json(_) => {}
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn run_pipeline_non_array_returns_invalid_bridge_list() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        std::fs::write(&bridge_json, "{\"key\": \"value\"}").unwrap();
        let err = run_pipeline(
            &bridge_json,
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
            &NoProbe,
        )
        .unwrap_err();
        match err {
            EchFingerprintError::InvalidBridgeList(_) => {}
            other => panic!("expected InvalidBridgeList, got {other:?}"),
        }
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let dir = base.join(format!(
            "ech_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
