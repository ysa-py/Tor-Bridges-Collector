//! Parity port of `nin_internet_cut_classifier.py` — Stage 8p: NIN Internet-Cut
//! Bridge Classifier.
//!
//! Classifies known bridges into GREEN / YELLOW / RED tiers for the worst-case
//! scenario of a complete international internet blackout where only traffic
//! through Iranian domestic ASNs remains reachable.
//!
//! Behavior traced to `nin_internet_cut_classifier.py`:
//! * `_parse_bridge(line)` — pure helper exposed as [`parse_bridge`] (and as a
//!   method on [`NINInternetCutClassifier`]). Returns `None` for empty or
//!   `#`-prefixed lines. The Python regex parsing is reproduced without any
//!   external regex crate by hand-rolled scanners that match the Python
//!   `re` semantics for the specific patterns in use.
//! * `_classify(bridge)` — pure helper exposed as [`classify`] (and as a
//!   method on [`NINInternetCutClassifier`]). Branch order, comparison
//!   operators, and threshold values match the Python original verbatim.
//! * `_load_all_bridges()` — method on [`NINInternetCutClassifier`] that
//!   reads the configured source files (injectable for tests) and returns
//!   the deduplicated bridge lines in first-seen order.
//! * `main()` / `_write_empty()` — methods on [`NINInternetCutClassifier`]
//!   that orchestrate the full classification pipeline. File paths are
//!   injectable so tests can target a temp directory, and the clock is
//!   injectable so the `generated_at` timestamp is deterministic.
//!
//! The Python original calls `monitoring.structured_logger.record_silent_failure`
//! on parse failures (CIDR + IPv4Address). The Rust port routes those side
//! effects through `eprintln!` — no extra crates required. The Python
//! `logging.basicConfig(...)` call at import time is a no-op in Rust.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Module-level constants (mirror Python `nin_internet_cut_classifier.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Default bridge source files scanned by [`NINInternetCutClassifier::load_all_bridges`].
pub const BRIDGE_SOURCES: &[&str] = &[
    "bridge/iran_likely_working_all.txt",
    "bridge/iran_likely_working_obfs4.txt",
    "bridge/iran_likely_working_webtunnel.txt",
    "bridge/iran_likely_working_snowflake.txt",
    "bridge/snowflake.txt",
    "bridge/webtunnel.txt",
    "bridge/meek_lite.txt",
];

/// Default output path for GREEN bridges.
pub const GREEN_OUT: &str = "export/nin_cut_bridges.txt";
/// Default output path for YELLOW bridges.
pub const YELLOW_OUT: &str = "export/nin_yellow_bridges.txt";
/// Default output path for combined GREEN+YELLOW bridges.
pub const COMBINED_OUT: &str = "bridge/iran_likely_working_nin.txt";
/// Default output path for the classification report JSON.
pub const REPORT_OUT: &str = "data/nin_cut_classifier_report.json";

/// CDN SNI domains with Iranian edge PoPs that classify a WebTunnel as GREEN.
pub const GREEN_SNIS: &[&str] = &[
    "www.aparat.com",
    "aparat.com",
    "www.digikala.com",
    "digikala.com",
    "cdn.telewebion.com",
    "telewebion.com",
    "arvancloud.ir",
    "arvancloud.com",
    "ajax.cloudflare.com",
    "cloudflare.com",
];

/// CDN SNI domains with some Iranian edge presence that classify a WebTunnel
/// as YELLOW.
pub const YELLOW_SNIS: &[&str] = &[
    "akamaiedge.net",
    "akamaitechnologies.com",
    "fastly.net",
    "fastly.com",
    "cloudfront.net",
    "amazonaws.com",
    "azureedge.net",
    "windows.net",
];

/// Transports that are always GREEN (CDN-routed by design).
pub const GREEN_TRANSPORTS: &[&str] = &["snowflake", "meek_lite", "meek-lite"];
/// Transports that depend on SNI for classification.
pub const YELLOW_TRANSPORTS: &[&str] = &["webtunnel"];
/// Transports that are always RED.
pub const RED_TRANSPORTS: &[&str] = &["vanilla", "obfs3"];

/// Ports considered NIN-safe for obfs4 classification.
pub const NIN_SAFE_PORTS: &[u32] = &[80, 443, 8080, 8443];

/// Raw CIDR strings for known Iranian domestic CDN ASN ranges. Parsed by
/// [`IranCidrTable`] at construction time. Malformed entries are skipped with
/// an `eprintln!` (matching the Python `record_silent_failure` no-op pattern).
pub const IRAN_CDN_CIDR_RAW: &[&str] = &[
    "185.143.232.0/22",
    "185.215.232.0/22",
    "179.43.145.0/24",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "5.200.64.0/18",
    "78.38.0.0/15",
    "85.185.0.0/16",
    "91.186.188.0/22",
    "94.182.0.0/16",
];

/// Scenario description written into the report JSON.
pub const SCENARIO_TEXT: &str = "Complete international internet blackout. Only traffic through Iranian domestic ASNs reachable. GREEN = high confidence reachable, YELLOW = CDN-dependent, RED = blocked.";

/// GREEN classification logic description written into the report JSON.
pub const CLASSIFICATION_LOGIC_GREEN: &str =
    "Snowflake, meek_lite (CDN by design) OR WebTunnel via Iranian/Cloudflare CDN SNI";
/// YELLOW classification logic description written into the report JSON.
pub const CLASSIFICATION_LOGIC_YELLOW: &str =
    "WebTunnel via Akamai/Fastly/CloudFront OR obfs4 on port 443";
/// RED classification logic description written into the report JSON.
pub const CLASSIFICATION_LOGIC_RED: &str =
    "obfs4 on non-standard port, vanilla, or bridge with no CDN routing";

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `nin_internet_cut_classifier.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum NINError {
    /// A bridge source file exists but could not be read as UTF-8 text.
    #[error("failed to read bridge source {path}: {source}")]
    ReadBridge {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Creating a parent directory for an output file failed.
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Writing an output file (bridge list or report JSON) failed.
    #[error("failed to write output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Serializing the report JSON failed.
    #[error("failed to serialize report: {source}")]
    SerializeReport { source: serde_json::Error },
}

// ─────────────────────────────────────────────────────────────────────────────
// ParsedBridge
// ─────────────────────────────────────────────────────────────────────────────

/// Structured representation of a parsed bridge line.
///
/// Field set matches the Python `_parse_bridge` return dict. JSON field
/// order is `raw`, `transport`, `ip`, `port`, `sni` to match the Python
/// dict insertion order (visible when serializing with `sort_keys=False`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBridge {
    /// The original (trimmed) bridge line.
    pub raw: String,
    /// Transport name (lowercased). Defaults to `"vanilla"` if no transport
    /// prefix is matched.
    pub transport: String,
    /// IPv4 or IPv6 address string extracted from the line, or empty if
    /// no `ip:port` pattern was found.
    pub ip: String,
    /// Port number (2-5 digit integer). `0` if no port was found.
    pub port: u32,
    /// SNI / host keyword extracted from `url=`/`host=`/`sni=`/`server=`
    /// prefixes, lowercased. Empty if no SNI was found.
    pub sni: String,
}

impl ParsedBridge {
    /// Serialize the parsed bridge (without tier) to a JSON value.
    pub fn to_json(&self) -> Value {
        json!({
            "raw": self.raw,
            "transport": self.transport,
            "ip": self.ip,
            "port": self.port,
            "sni": self.sni,
        })
    }

    /// Serialize the parsed bridge with an added `tier` field. Field order
    /// matches the Python `{**parsed, "tier": tier}` insertion order.
    pub fn to_json_with_tier(&self, tier: &str) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("raw".to_string(), Value::String(self.raw.clone()));
        obj.insert(
            "transport".to_string(),
            Value::String(self.transport.clone()),
        );
        obj.insert("ip".to_string(), Value::String(self.ip.clone()));
        obj.insert("port".to_string(), json!(self.port));
        obj.insert("sni".to_string(), Value::String(self.sni.clone()));
        obj.insert("tier".to_string(), Value::String(tier.to_string()));
        Value::Object(obj)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers (parity with Python module-level `_parse_bridge` / `_classify`)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python's `_parse_bridge(line)`. Returns `None` for empty or
/// `#`-prefixed lines after trimming.
///
/// The transport prefix regex
/// `^(obfs4|webtunnel|snowflake|meek_lite|meek-lite|obfs3|vanilla)\s+` (case
/// insensitive) is reproduced by [`parse_transport_prefix`]. The IPv4 regex
/// `\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b` is reproduced by
/// [`find_ipv4_port`]. The IPv6 regex `\[([0-9a-fA-F:]+)\]:(\d{2,5})` is
/// reproduced by [`find_ipv6_port`]. The SNI regex
/// `(?:url=https?://|host=|sni=|server=)([a-zA-Z0-9.-]+)` (case insensitive)
/// is reproduced by [`find_sni`].
pub fn parse_bridge(line: &str) -> Option<ParsedBridge> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let (transport, rest) = match parse_transport_prefix(line) {
        Some((t, r)) => (t, r),
        None => ("vanilla".to_string(), line),
    };

    let (ip, port) = parse_ip_port(rest);
    let sni = find_sni(rest).unwrap_or_default();

    Some(ParsedBridge {
        raw: line.to_string(),
        transport,
        ip,
        port,
        sni,
    })
}

/// Mirror of Python's `_classify(bridge)`. Returns `"GREEN"`, `"YELLOW"`, or
/// `"RED"` based on the transport, SNI, port, and IP containment in the
/// Iranian CDN CIDR table.
///
/// Branch order matches the Python original verbatim:
///
/// 1. `transport in GREEN_TRANSPORTS` → `"GREEN"`
/// 2. `transport == "webtunnel"`:
///    - SNI matches a GREEN SNI (exact or subdomain) → `"GREEN"`
///    - SNI matches a YELLOW SNI (exact or subdomain) → `"YELLOW"`
///    - SNI is truthy → `"YELLOW"`
///    - else → `"RED"`
/// 3. `transport == "obfs4"`:
///    - `port in NIN_SAFE_PORTS`:
///      - IP parses as IPv4 AND is in IRAN_CDN_CIDRS → `"GREEN"`
///      - else → `"YELLOW"`
///    - else → `"RED"`
/// 4. else → `"RED"`
pub fn classify(bridge: &ParsedBridge, cidrs: &IranCidrTable) -> &'static str {
    let transport = bridge.transport.to_lowercase();

    if GREEN_TRANSPORTS.contains(&transport.as_str()) {
        return "GREEN";
    }

    if transport == "webtunnel" {
        if sni_matches(&bridge.sni, GREEN_SNIS) {
            return "GREEN";
        }
        if sni_matches(&bridge.sni, YELLOW_SNIS) {
            return "YELLOW";
        }
        if !bridge.sni.is_empty() {
            return "YELLOW";
        }
        return "RED";
    }

    if transport == "obfs4" {
        if NIN_SAFE_PORTS.contains(&bridge.port) {
            // Mirror Python's `ipaddress.IPv4Address(ip_str)` parse attempt.
            // On parse failure (ValueError), Python silently falls through
            // to YELLOW. We do the same: parse_ipv4_u32 returns None for
            // invalid IPs (octet > 255, leading zeros, IPv6, empty, etc.).
            if let Some(ip_u32) = parse_ipv4_u32(&bridge.ip) {
                if cidrs.contains(ip_u32) {
                    return "GREEN";
                }
            }
            return "YELLOW";
        }
        return "RED";
    }

    "RED"
}

// ─────────────────────────────────────────────────────────────────────────────
// IranCidrTable
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-parsed Iranian CDN CIDR table used by [`classify`] for obfs4 IP
/// containment checks.
#[derive(Debug, Clone)]
pub struct IranCidrTable {
    /// `(network_address, netmask)` pairs in host byte order (u32 big-endian
    /// semantics: octet 0 is the high byte).
    networks: Vec<(u32, u32)>,
}

impl IranCidrTable {
    /// Build the table from the default [`IRAN_CDN_CIDR_RAW`] constants.
    pub fn new() -> Self {
        Self::from_cidrs(IRAN_CDN_CIDR_RAW)
    }

    /// Build the table from an arbitrary list of CIDR strings. Malformed
    /// entries are skipped with an `eprintln!` matching the Python
    /// `record_silent_failure` no-op pattern.
    pub fn from_cidrs(cidrs: &[&str]) -> Self {
        let mut networks = Vec::new();
        for cidr in cidrs {
            match parse_cidr(cidr) {
                Ok(net) => networks.push(net),
                Err(_) => {
                    eprintln!("nin_internet_cut_classifier: skipping invalid CIDR: {cidr}");
                }
            }
        }
        Self { networks }
    }

    /// Returns `true` if the given IPv4 address (in host byte order) falls
    /// within any of the configured CIDR ranges.
    pub fn contains(&self, ip: u32) -> bool {
        self.networks.iter().any(|(net, mask)| (ip & mask) == *net)
    }
}

impl Default for IranCidrTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NINInternetCutClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable clock closure — returns the current UTC time. Tests pass a
/// fixed clock so `generated_at` timestamps are deterministic.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Default clock — returns `chrono::Utc::now()`.
pub fn default_clock() -> Clock {
    Arc::new(Utc::now)
}

/// Stage 8p NIN Internet-Cut Bridge Classifier.
///
/// Holds the injectable bridge source paths, output paths, clock, and
/// pre-parsed Iranian CDN CIDR table. Methods mirror the Python module-level
/// functions `_parse_bridge`, `_classify`, `_load_all_bridges`, `main`, and
/// `_write_empty`.
pub struct NINInternetCutClassifier {
    bridge_sources: Vec<PathBuf>,
    green_out: PathBuf,
    yellow_out: PathBuf,
    combined_out: PathBuf,
    report_out: PathBuf,
    clock: Clock,
    cidrs: IranCidrTable,
}

impl Default for NINInternetCutClassifier {
    fn default() -> Self {
        Self {
            bridge_sources: BRIDGE_SOURCES.iter().map(PathBuf::from).collect(),
            green_out: PathBuf::from(GREEN_OUT),
            yellow_out: PathBuf::from(YELLOW_OUT),
            combined_out: PathBuf::from(COMBINED_OUT),
            report_out: PathBuf::from(REPORT_OUT),
            clock: default_clock(),
            cidrs: IranCidrTable::new(),
        }
    }
}

impl NINInternetCutClassifier {
    /// Production constructor — uses the default module-level paths and
    /// `chrono::Utc::now()` clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Injectable constructor — explicit paths and clock for parity tests.
    pub fn with_paths_and_clock(
        bridge_sources: Vec<PathBuf>,
        green_out: PathBuf,
        yellow_out: PathBuf,
        combined_out: PathBuf,
        report_out: PathBuf,
        clock: Clock,
    ) -> Self {
        Self {
            bridge_sources,
            green_out,
            yellow_out,
            combined_out,
            report_out,
            clock,
            cidrs: IranCidrTable::new(),
        }
    }

    /// Mirror of Python's `_parse_bridge(line)`.
    pub fn parse_bridge(&self, line: &str) -> Option<ParsedBridge> {
        parse_bridge(line)
    }

    /// Mirror of Python's `_classify(bridge)`.
    pub fn classify(&self, bridge: &ParsedBridge) -> &'static str {
        classify(bridge, &self.cidrs)
    }

    /// Mirror of Python's `_load_all_bridges()`. Reads each existing source
    /// file in order, strips lines, skips empty/`#`-prefixed/duplicate lines,
    /// and returns the deduplicated list in first-seen order.
    pub fn load_all_bridges(&self) -> Result<Vec<String>, NINError> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result: Vec<String> = Vec::new();
        for fp in &self.bridge_sources {
            if !fp.exists() {
                continue;
            }
            let text = fs::read_to_string(fp).map_err(|source| NINError::ReadBridge {
                path: fp.clone(),
                source,
            })?;
            for line in text.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') && seen.insert(line.to_string()) {
                    result.push(line.to_string());
                }
            }
        }
        Ok(result)
    }

    /// Mirror of Python's `main()`. Creates parent directories, loads all
    /// bridges, classifies each, writes the output files, and returns the
    /// exit code (`0` on success). If no bridges are loaded, delegates to
    /// [`write_empty`].
    pub fn run(&self) -> Result<i32, NINError> {
        self.ensure_output_dirs()?;

        let all_lines = self.load_all_bridges()?;
        if all_lines.is_empty() {
            self.write_empty()?;
            return Ok(0);
        }

        let mut green: Vec<String> = Vec::new();
        let mut yellow: Vec<String> = Vec::new();
        let mut red: Vec<String> = Vec::new();
        let mut details: Vec<Value> = Vec::new();

        for line in &all_lines {
            let parsed = match self.parse_bridge(line) {
                Some(p) => p,
                None => continue,
            };
            let tier = self.classify(&parsed);
            details.push(parsed.to_json_with_tier(tier));
            match tier {
                "GREEN" => green.push(line.clone()),
                "YELLOW" => yellow.push(line.clone()),
                _ => red.push(line.clone()),
            }
        }

        write_lines(&self.green_out, &green)?;
        write_lines(&self.yellow_out, &yellow)?;
        let combined: Vec<String> = green.iter().chain(yellow.iter()).cloned().collect();
        write_lines(&self.combined_out, &combined)?;

        let now = (self.clock)();
        let report = json!({
            "generated_at": format_iso(&now),
            "total_bridges": details.len(),
            "green_count": green.len(),
            "yellow_count": yellow.len(),
            "red_count": red.len(),
            "scenario": SCENARIO_TEXT,
            "classification_logic": {
                "GREEN": CLASSIFICATION_LOGIC_GREEN,
                "YELLOW": CLASSIFICATION_LOGIC_YELLOW,
                "RED": CLASSIFICATION_LOGIC_RED,
            },
            "bridges": details,
        });

        let serialized = serde_json::to_string_pretty(&report)
            .map_err(|source| NINError::SerializeReport { source })?;
        fs::write(&self.report_out, serialized).map_err(|source| NINError::WriteOutput {
            path: self.report_out.clone(),
            source,
        })?;

        Ok(0)
    }

    /// Mirror of Python's `_write_empty()`. Writes an empty report JSON with
    /// a `note` field explaining that no bridge sources were found, and
    /// truncates the three bridge output files to empty strings.
    pub fn write_empty(&self) -> Result<(), NINError> {
        let now = (self.clock)();
        let empty = json!({
            "generated_at": format_iso(&now),
            "total_bridges": 0,
            "green_count": 0,
            "yellow_count": 0,
            "red_count": 0,
            "note": "No bridge source files found.",
            "bridges": [],
        });
        let serialized = serde_json::to_string_pretty(&empty)
            .map_err(|source| NINError::SerializeReport { source })?;
        fs::write(&self.report_out, serialized).map_err(|source| NINError::WriteOutput {
            path: self.report_out.clone(),
            source,
        })?;
        for fp in [&self.green_out, &self.yellow_out, &self.combined_out] {
            fs::write(fp, "").map_err(|source| NINError::WriteOutput {
                path: fp.clone(),
                source,
            })?;
        }
        Ok(())
    }

    fn ensure_output_dirs(&self) -> Result<(), NINError> {
        for dir in [
            self.green_out.parent(),
            self.yellow_out.parent(),
            self.combined_out.parent(),
            self.report_out.parent(),
        ]
        .into_iter()
        .flatten()
        {
            if !dir.as_os_str().is_empty() && !dir.exists() {
                fs::create_dir_all(dir).map_err(|source| NINError::CreateDir {
                    path: dir.to_path_buf(),
                    source,
                })?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for NINInternetCutClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NINInternetCutClassifier")
            .field("bridge_sources", &self.bridge_sources)
            .field("green_out", &self.green_out)
            .field("yellow_out", &self.yellow_out)
            .field("combined_out", &self.combined_out)
            .field("report_out", &self.report_out)
            .field("cidrs", &self.cidrs)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an ISO-8601 string with microsecond precision
/// and a `+00:00` offset, matching Python's `datetime.now(UTC).isoformat()`
/// for non-zero microseconds.
fn format_iso(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
}

/// Write a list of lines to a file, joined by `\n` with a trailing newline
/// if the list is non-empty (matching Python's `"\n".join(lines) + "\n"`).
fn write_lines(path: &Path, lines: &[String]) -> Result<(), NINError> {
    let mut content = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            content.push('\n');
        }
        content.push_str(line);
    }
    if !lines.is_empty() {
        content.push('\n');
    }
    fs::write(path, content).map_err(|source| NINError::WriteOutput {
        path: path.to_path_buf(),
        source,
    })
}

/// Mirror of Python's `\w` for ASCII strings: `[a-zA-Z0-9_]`.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Parse the transport prefix `^(obfs4|webtunnel|snowflake|meek_lite|meek-lite|obfs3|vanilla)\s+`
/// (case insensitive). Returns `(lowercased_transport, rest_after_whitespace)`.
///
/// The Python regex tries each alternative in order with backtracking. For
/// our specific list, no two transports share a common prefix, so if one
/// alternative matches the prefix but `\s+` fails, no other alternative
/// would match either. We still iterate through all alternatives to mirror
/// the regex backtracking semantics.
fn parse_transport_prefix(line: &str) -> Option<(String, &str)> {
    const TRANSPORTS: &[&str] = &[
        "obfs4",
        "webtunnel",
        "snowflake",
        "meek_lite",
        "meek-lite",
        "obfs3",
        "vanilla",
    ];
    let bytes = line.as_bytes();
    for t in TRANSPORTS {
        let t_bytes = t.as_bytes();
        if bytes.len() < t_bytes.len() {
            continue;
        }
        if !bytes[..t_bytes.len()]
            .iter()
            .zip(t_bytes.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            continue;
        }
        // Prefix matched. Need at least one whitespace char next.
        let rest = &line[t_bytes.len()..];
        let next = rest.chars().next();
        if let Some(c) = next {
            if c.is_whitespace() {
                let trimmed = rest.trim_start();
                let transport: String = line[..t_bytes.len()].to_lowercase();
                return Some((transport, trimmed));
            }
        }
        // Prefix matched but no whitespace follows. Continue to next
        // alternative (matches Python regex backtracking).
    }
    None
}

/// Try the IPv4 regex first; on no match, try the IPv6 regex. Returns
/// `(ip_str, port)`. `(empty, 0)` if neither matches.
fn parse_ip_port(rest: &str) -> (String, u32) {
    if let Some((ip, port)) = find_ipv4_port(rest) {
        return (ip, port);
    }
    if let Some((ip, port)) = find_ipv6_port(rest) {
        return (ip, port);
    }
    (String::new(), 0)
}

/// Find the first (leftmost) match of `\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b`
/// in `s`. Returns `(ip_str, port)`.
fn find_ipv4_port(s: &str) -> Option<(String, u32)> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    for i in 0..len {
        if !bytes[i].is_ascii_digit() {
            continue;
        }
        // Word boundary at position i: previous char must be non-word (or
        // start of string).
        let prev_is_word = i > 0 && is_word_byte(bytes[i - 1]);
        if prev_is_word {
            continue;
        }

        if let Some((ip_str, port_str, port_end)) = try_match_ipv4_port(bytes, i) {
            // Word boundary after the port: next char must be non-word (or
            // end of string).
            let next_is_word = port_end < len && is_word_byte(bytes[port_end]);
            if next_is_word {
                continue;
            }
            let port_val: u32 = port_str.parse().ok()?;
            return Some((ip_str, port_val));
        }
    }
    None
}

/// Try to match the IPv4:port pattern starting at byte position `start`.
/// Returns `(ip_str, port_str, port_end_byte_index)`.
fn try_match_ipv4_port(bytes: &[u8], start: usize) -> Option<(String, String, usize)> {
    let len = bytes.len();
    let mut pos = start;

    let mut octet_strs: [String; 4] = [String::new(), String::new(), String::new(), String::new()];

    for (idx, octet_slot) in octet_strs.iter_mut().enumerate() {
        // Read 1-3 digits (greedy, like Python's \d{1,3}).
        let digit_start = pos;
        let mut digit_count = 0;
        while pos < len && bytes[pos].is_ascii_digit() && digit_count < 3 {
            pos += 1;
            digit_count += 1;
        }
        if digit_count == 0 {
            return None;
        }
        *octet_slot = std::str::from_utf8(&bytes[digit_start..pos])
            .ok()?
            .to_string();

        if idx < 3 {
            // Expect '.'.
            if pos >= len || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        } else {
            // Expect ':'.
            if pos >= len || bytes[pos] != b':' {
                return None;
            }
            pos += 1;
        }
    }

    let ip_str = octet_strs.join(".");

    // Read 2-5 digit port (greedy).
    let port_start = pos;
    let mut port_count = 0;
    while pos < len && bytes[pos].is_ascii_digit() && port_count < 5 {
        pos += 1;
        port_count += 1;
    }
    if !(2..=5).contains(&port_count) {
        return None;
    }
    let port_str = std::str::from_utf8(&bytes[port_start..pos])
        .ok()?
        .to_string();

    Some((ip_str, port_str, pos))
}

/// Find the first (leftmost) match of `\[([0-9a-fA-F:]+)\]:(\d{2,5})` in `s`.
/// Returns `(ip_str, port)`.
fn find_ipv6_port(s: &str) -> Option<(String, u32)> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    for i in 0..len {
        if bytes[i] != b'[' {
            continue;
        }
        if let Some((ip_str, port_str)) = try_match_ipv6_port(bytes, i) {
            let port_val: u32 = port_str.parse().ok()?;
            return Some((ip_str, port_val));
        }
    }
    None
}

/// Try to match the IPv6 `[...]:port` pattern starting at byte position
/// `start` (which must be `[`).
fn try_match_ipv6_port(bytes: &[u8], start: usize) -> Option<(String, String)> {
    let len = bytes.len();
    let mut pos = start;

    if pos >= len || bytes[pos] != b'[' {
        return None;
    }
    pos += 1;

    // Read 1+ hex/colon chars (greedy).
    let content_start = pos;
    while pos < len && (bytes[pos].is_ascii_hexdigit() || bytes[pos] == b':') {
        pos += 1;
    }
    if pos == content_start {
        return None;
    }
    let content_str = std::str::from_utf8(&bytes[content_start..pos])
        .ok()?
        .to_string();

    if pos >= len || bytes[pos] != b']' {
        return None;
    }
    pos += 1;

    if pos >= len || bytes[pos] != b':' {
        return None;
    }
    pos += 1;

    // Read 2-5 digit port.
    let port_start = pos;
    let mut port_count = 0;
    while pos < len && bytes[pos].is_ascii_digit() && port_count < 5 {
        pos += 1;
        port_count += 1;
    }
    if !(2..=5).contains(&port_count) {
        return None;
    }
    let port_str = std::str::from_utf8(&bytes[port_start..pos])
        .ok()?
        .to_string();

    Some((content_str, port_str))
}

/// Find the first (leftmost) match of
/// `(?:url=https?://|host=|sni=|server=)([a-zA-Z0-9.-]+)` (case insensitive)
/// in `s`. Returns the captured hostname, lowercased.
fn find_sni(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Each prefix as raw bytes. We try `url=http://` before `url=https://`
    // so the shorter prefix is checked first (Python regex alternation order
    // is `url=https?://` which means `http` is tried first, then `https`).
    const PREFIXES: &[&[u8]] = &[
        b"url=http://",
        b"url=https://",
        b"host=",
        b"sni=",
        b"server=",
    ];

    for i in 0..len {
        for prefix in PREFIXES {
            if i + prefix.len() > len {
                continue;
            }
            let candidate = &bytes[i..i + prefix.len()];
            if !candidate
                .iter()
                .zip(prefix.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            // Prefix matched. Read 1+ chars from [a-zA-Z0-9.-].
            let mut j = i + prefix.len();
            while j < len
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'.' || bytes[j] == b'-')
            {
                j += 1;
            }
            if j == i + prefix.len() {
                // Captured group is empty — this alternative fails. Move to
                // the next position (no other prefix can match at this
                // position because they all have distinct first chars).
                break;
            }
            let captured = std::str::from_utf8(&bytes[i + prefix.len()..j]).ok()?;
            return Some(captured.to_lowercase());
        }
    }
    None
}

/// Returns `true` if `sni` matches any SNI in `snis` — either exactly, or as
/// a strict subdomain (`.<sni>` suffix). Mirrors Python's
/// `sni in SNIS or any(sni.endswith("." + s) for s in SNIS)`.
fn sni_matches(sni: &str, snis: &[&str]) -> bool {
    snis.iter().any(|s| {
        if sni == *s {
            return true;
        }
        // sni must be longer than s by at least 1 char (the dot), must end
        // with s, and the char before the suffix must be '.'.
        if sni.len() > s.len() && sni.ends_with(s) {
            let dot_pos = sni.len() - s.len() - 1;
            return sni.as_bytes()[dot_pos] == b'.';
        }
        false
    })
}

/// Parse an IPv4 dotted-quad string into a host-order u32. Returns `None`
/// for invalid IPs (wrong octet count, octet > 255, leading zeros, non-digit
/// chars). Mirrors Python's `ipaddress.IPv4Address(s)` acceptance rules.
fn parse_ipv4_u32(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut result: u32 = 0;
    for part in parts {
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Python rejects leading zeros (e.g., "04").
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        let val: u32 = part.parse().ok()?;
        if val > 255 {
            return None;
        }
        result = (result << 8) | val;
    }
    Some(result)
}

/// Parse a CIDR string `"a.b.c.d/prefix"` into `(network_address, netmask)`.
/// The network address is masked (matches Python's `IPv4Network(strict=False)`).
fn parse_cidr(s: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: {s}"));
    }
    let ip = parse_ipv4_u32(parts[0]).ok_or_else(|| format!("invalid CIDR IP: {}", parts[0]))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("invalid CIDR prefix: {}", parts[1]))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix out of range: {prefix}"));
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    Ok((ip & mask, mask))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bridge_handles_empty_and_comment_lines() {
        assert!(parse_bridge("").is_none());
        assert!(parse_bridge("   ").is_none());
        assert!(parse_bridge("# comment").is_none());
        assert!(parse_bridge("   # comment").is_none());
    }

    #[test]
    fn parse_bridge_extracts_transport_and_ip() {
        let p = parse_bridge("obfs4 1.2.3.4:443 cert=abc").unwrap();
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ip, "1.2.3.4");
        assert_eq!(p.port, 443);
        assert_eq!(p.sni, "");
    }

    #[test]
    fn parse_bridge_defaults_to_vanilla_for_unknown_transport() {
        let p = parse_bridge("unknown_transport 1.2.3.4:443").unwrap();
        assert_eq!(p.transport, "vanilla");
    }

    #[test]
    fn parse_bridge_extracts_sni_from_url() {
        let p = parse_bridge("webtunnel 1.2.3.4:443 url=https://www.aparat.com/path").unwrap();
        assert_eq!(p.sni, "www.aparat.com");
    }

    #[test]
    fn classify_snowflake_is_green() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("snowflake 192.0.2.1:443").unwrap();
        assert_eq!(classify(&b, &cidrs), "GREEN");
    }

    #[test]
    fn classify_obfs4_on_safe_port_with_iran_ip_is_green() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("obfs4 5.200.64.5:443 cert=abc").unwrap();
        assert_eq!(classify(&b, &cidrs), "GREEN");
    }

    #[test]
    fn classify_obfs4_on_safe_port_with_non_iran_ip_is_yellow() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("obfs4 1.2.3.4:443 cert=abc").unwrap();
        assert_eq!(classify(&b, &cidrs), "YELLOW");
    }

    #[test]
    fn classify_obfs4_on_non_safe_port_is_red() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("obfs4 1.2.3.4:9001 cert=abc").unwrap();
        assert_eq!(classify(&b, &cidrs), "RED");
    }

    #[test]
    fn classify_webtunnel_with_green_sni_is_green() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("webtunnel 1.2.3.4:443 url=https://www.aparat.com/path").unwrap();
        assert_eq!(classify(&b, &cidrs), "GREEN");
    }

    #[test]
    fn classify_webtunnel_with_unknown_sni_is_yellow() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("webtunnel 1.2.3.4:443 url=https://example.com").unwrap();
        assert_eq!(classify(&b, &cidrs), "YELLOW");
    }

    #[test]
    fn classify_webtunnel_without_sni_is_red() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("webtunnel 1.2.3.4:443").unwrap();
        assert_eq!(classify(&b, &cidrs), "RED");
    }

    #[test]
    fn classify_vanilla_is_red() {
        let cidrs = IranCidrTable::new();
        let b = parse_bridge("vanilla 1.2.3.4:9001").unwrap();
        assert_eq!(classify(&b, &cidrs), "RED");
    }

    #[test]
    fn iran_cidr_table_contains_known_ranges() {
        let t = IranCidrTable::new();
        assert!(t.contains(0xB9_8F_E8_05)); // 185.143.232.5
        assert!(t.contains(0x05_C8_40_01)); // 5.200.64.1
        assert!(t.contains(0x68_14_00_00)); // 104.20.0.0 (in 104.16.0.0/13)
        assert!(t.contains(0x68_17_FF_FF)); // 104.23.255.255 (in 104.16.0.0/13)
        assert!(t.contains(0x68_18_00_00)); // 104.24.0.0 (in 104.24.0.0/14)
        assert!(!t.contains(0x01_02_03_04)); // 1.2.3.4
        assert!(!t.contains(0x68_1C_00_00)); // 104.28.0.0 (outside both Cloudflare ranges)
    }

    #[test]
    fn parse_ipv4_u32_rejects_invalid_inputs() {
        assert_eq!(parse_ipv4_u32("1.2.3.4"), Some(0x01020304));
        assert_eq!(parse_ipv4_u32("999.999.999.999"), None);
        assert_eq!(parse_ipv4_u32("1.2.3.04"), None); // leading zero
        assert_eq!(parse_ipv4_u32("1.2.3"), None);
        assert_eq!(parse_ipv4_u32("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_u32(""), None);
        assert_eq!(parse_ipv4_u32("2001:db8::1"), None);
    }

    #[test]
    fn parse_cidr_handles_known_ranges() {
        let (net, mask) = parse_cidr("185.143.232.0/22").unwrap();
        assert_eq!(net, 0xB9_8F_E8_00);
        assert_eq!(mask, 0xFFFF_FC00);

        let (net, mask) = parse_cidr("5.200.64.0/18").unwrap();
        assert_eq!(net, 0x05_C8_40_00);
        assert_eq!(mask, 0xFFFF_C000);

        // Edge case: /0
        let (net, mask) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(net, 0);
        assert_eq!(mask, 0);
    }
}
