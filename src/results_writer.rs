//! Parity port of `results_writer.py` file-output classification helpers.
//!
//! The Python original remains the source of truth. This module ports the pure
//! bridge categorisation and sorted-file writing path from
//! `results_writer.py::write_result_files`, with typed I/O errors instead of
//! process exits so parity tests can compare every branch deterministically.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;
const WORKING_STATUSES: &[&str] = &["iran_likely_working"];
const UNKNOWN_REACHABLE: &[&str] = &["iran_unknown"];
const BLOCKED_STATUSES: &[&str] = &["iran_likely_blocked", "iran_frequently_blocked"];
const WORKING_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"];
const GLOBAL_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla"];

/// File-generation failures for the Rust `results_writer.py` parity port.
#[derive(Debug)]
pub enum ResultsWriterError {
    /// `iran_results.json` does not exist at the configured path.
    MissingIranResults { path: PathBuf },
    /// Reading `iran_results.json` failed after the file was found.
    ReadIranResults {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Parsing `iran_results.json` as JSON failed.
    ParseIranResults {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// Creating the bridge output directory failed.
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Writing one of the generated bridge files failed.
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Reading back a generated file for the mandatory integrity assertion failed.
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The mandatory sorted/deduplicated/no-blank post-write assertion failed.
    Integrity { path: PathBuf },
}

impl std::fmt::Display for ResultsWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingIranResults { path } => {
                write!(f, "iran_results.json not found at {}", path.display())
            }
            Self::ReadIranResults { path, source } => {
                write!(
                    f,
                    "failed to read iran results {}: {source}",
                    path.display()
                )
            }
            Self::ParseIranResults { path, source } => {
                write!(
                    f,
                    "failed to parse iran results {}: {source}",
                    path.display()
                )
            }
            Self::CreateDir { path, source } => {
                write!(
                    f,
                    "failed to create bridge output directory {}: {source}",
                    path.display()
                )
            }
            Self::WriteFile { path, source } => {
                write!(
                    f,
                    "failed to write generated bridge file {}: {source}",
                    path.display()
                )
            }
            Self::ReadFile { path, source } => {
                write!(
                    f,
                    "failed to read generated bridge file {}: {source}",
                    path.display()
                )
            }
            Self::Integrity { path } => {
                write!(
                    f,
                    "integrity assertion failed for {}: file is not sorted and deduplicated",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ResultsWriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadIranResults { source, .. } => Some(source),
            Self::ParseIranResults { source, .. } => Some(source),
            Self::CreateDir { source, .. }
            | Self::WriteFile { source, .. }
            | Self::ReadFile { source, .. } => Some(source),
            Self::MissingIranResults { .. } | Self::Integrity { .. } => None,
        }
    }
}

/// Load the Go tester JSON output that `results_writer.py` reads from
/// `BRIDGE_DIR/iran_results.json`.
///
/// Unlike the Python original, which calls `sys.exit(1)` for a missing file and
/// lets read/JSON exceptions escape, this Rust replacement exposes each branch
/// as a typed [`Result`] error for callers and parity tests.
pub fn load_iran_results(path: &Path) -> Result<Value, ResultsWriterError> {
    if !path.exists() {
        return Err(ResultsWriterError::MissingIranResults {
            path: path.to_path_buf(),
        });
    }

    let text = fs::read_to_string(path).map_err(|source| ResultsWriterError::ReadIranResults {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| ResultsWriterError::ParseIranResults {
        path: path.to_path_buf(),
        source,
    })
}

/// Returns true if the bridge is a domain-fronted WebTunnel bridge:
/// transport=webtunnel, has a url= host that is a domain name (not an IP),
/// and the bridge line lacks a routable [ip]:port field.
///
/// These bridges cannot be TCP-probed and are currently assigned
/// tcp_unreachable by the Go iran_tester, but that status is meaningless
/// for domain-fronting — TCP is the wrong probe for them. The Go parser
/// leaves the `host` field empty for URL-only WebTunnel lines (the only
/// endpoint it sees is the domain inside `url=`), so the front domain is
/// derived from the bridge line's url= parameter first.
fn is_domain_fronted_webtunnel(bridge: &Value) -> bool {
    let transport = bridge
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("");
    if transport != "webtunnel" {
        return false;
    }

    let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");
    // Documentation-prefix IPv6 placeholders (RFC 3849, 2001:db8::/32) are
    // BridgeDB anti-enumeration substitutes for a real IPv6 endpoint; the
    // line carries a literal endpoint token and must not be treated as a
    // domain-fronted URL-only bridge here.
    if line.contains("2001:db8:") {
        return false;
    }

    // Prefer the explicit `host` field when the tester populated it with a
    // domain name (e.g. an FQDN:PORT endpoint).
    let host = bridge.get("host").and_then(Value::as_str).unwrap_or("");
    if !host.is_empty() {
        // If host parses as an IP address, it has a routable endpoint — not
        // domain-fronted. Domain-fronted bridges carry a domain name.
        return host.parse::<std::net::IpAddr>().is_err();
    }

    // URL-only WebTunnel: extract the front host from the url= parameter.
    // Accept only when it is a domain name (a bare IP url host implies a
    // directly dialable endpoint, which is not domain-fronting).
    for token in line.split_whitespace() {
        if let Some(rest) = token.strip_prefix("url=") {
            let after_scheme = rest
                .strip_prefix("https://")
                .or_else(|| rest.strip_prefix("http://"))
                .unwrap_or(rest);
            let authority = after_scheme
                .split(['/', '?', '#'])
                .next()
                .unwrap_or(after_scheme);
            let front_host =
                authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            let front_host = front_host
                .rsplit_once(':')
                .map_or(front_host, |(h, _p)| h);
            let front_host = front_host.trim_start_matches('[').trim_end_matches(']');
            if !front_host.is_empty() && front_host.parse::<std::net::IpAddr>().is_err() {
                return true;
            }
        }
    }
    false
}

/// Categorise bridges and write all `results_writer.py` bridge text outputs.
///
/// Behavior traced to `results_writer.py::write_result_files`:
/// * ignores bridges with blank or missing `line`;
/// * writes lexicographically sorted, deduplicated files;
/// * Tier 1 (`iran_likely_working`) wins over Tier 2 for each transport;
/// * Tier 2 includes `iran_unknown` bridges when TCP-reachable, and always for
///   `snowflake`/`webtunnel` because Python treats those transports specially;
/// * blocked and global files are produced independently of working tiers.
pub fn write_result_files(
    bridge_dir: &Path,
    bridges: &[Value],
) -> Result<BTreeMap<String, usize>, ResultsWriterError> {
    fs::create_dir_all(bridge_dir).map_err(|source| ResultsWriterError::CreateDir {
        path: bridge_dir.to_path_buf(),
        source,
    })?;

    let mut stats = BTreeMap::new();
    let mut t1_by_transport = empty_transport_map(WORKING_TRANSPORTS);
    let mut t2_by_transport = empty_transport_map(WORKING_TRANSPORTS);
    let mut blocked_lines: Vec<String> = Vec::new();
    let mut global_by_transport = empty_transport_map(GLOBAL_TRANSPORTS);

    for bridge in bridges {
        let line = bridge
            .get("line")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if line.is_empty() {
            continue;
        }

        let transport = bridge
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let status = bridge
            .get("iran_status")
            .and_then(Value::as_str)
            .unwrap_or("");
        let tcp_ok = bridge
            .get("tcp_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if WORKING_STATUSES.contains(&status) {
            if let Some(bucket) = t1_by_transport.get_mut(transport) {
                bucket.push(line.clone());
            }
        }

        // v2.6.2: Domain-fronted WebTunnel bridges (url=, no routable IP)
        // cannot be probed via raw TCP. The Go iran_tester correctly marks
        // them tcp_unreachable, but that is the wrong signal for WebTunnel.
        // Reclassify them as iran_unknown so that Tier 2's existing
        // webtunnel special-case (bypasses tcp_ok) promotes them.
        let effective_status = if status == "tcp_unreachable"
            && transport == "webtunnel"
            && is_domain_fronted_webtunnel(bridge)
        {
            "iran_unknown"
        } else {
            status
        };

        if UNKNOWN_REACHABLE.contains(&effective_status)
            && (tcp_ok || matches!(transport, "snowflake" | "webtunnel"))
        {
            if let Some(bucket) = t2_by_transport.get_mut(transport) {
                bucket.push(line.clone());
            }
        }

        if BLOCKED_STATUSES.contains(&status) {
            blocked_lines.push(line.clone());
        }

        if (tcp_ok || transport == "snowflake") && global_by_transport.contains_key(transport) {
            if let Some(bucket) = global_by_transport.get_mut(transport) {
                bucket.push(line);
            }
        }
    }

    let mut all_working = Vec::new();
    for transport in WORKING_TRANSPORTS {
        let t1_lines = t1_by_transport.remove(*transport).unwrap_or_default();
        let t2_lines = t2_by_transport.remove(*transport).unwrap_or_default();
        let combined = if !t1_lines.is_empty() {
            t1_lines
        } else {
            t2_lines
        };
        if combined.is_empty() {
            continue;
        }
        let filename = format!("iran_likely_working_{transport}.txt");
        let count = write_sorted_file(&bridge_dir.join(&filename), &combined)?;
        stats.insert(filename, count);
        all_working.extend(combined);
    }

    let all_path = bridge_dir.join("iran_likely_working_all.txt");
    stats.insert(
        "iran_likely_working_all.txt".to_string(),
        write_sorted_file(&all_path, &all_working)?,
    );
    assert_integrity(&all_path)?;

    stats.insert(
        "iran_blocked.txt".to_string(),
        write_sorted_file(&bridge_dir.join("iran_blocked.txt"), &blocked_lines)?,
    );

    for transport in GLOBAL_TRANSPORTS {
        let lines = global_by_transport.remove(*transport).unwrap_or_default();
        let filename = format!("tested_global_{transport}.txt");
        stats.insert(
            filename.clone(),
            write_sorted_file(&bridge_dir.join(filename), &lines)?,
        );
    }

    Ok(stats)
}

fn empty_transport_map(transports: &[&str]) -> BTreeMap<String, Vec<String>> {
    transports
        .iter()
        .map(|transport| ((*transport).to_string(), Vec::new()))
        .collect()
}

fn write_sorted_file(path: &Path, lines: &[String]) -> Result<usize, ResultsWriterError> {
    let clean: BTreeSet<String> = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let mut text = clean.iter().cloned().collect::<Vec<_>>().join("\n");
    if !clean.is_empty() {
        text.push('\n');
    }
    fs::write(path, text).map_err(|source| ResultsWriterError::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(clean.len())
}

fn assert_integrity(path: &Path) -> Result<(), ResultsWriterError> {
    let text = fs::read_to_string(path).map_err(|source| ResultsWriterError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let expected: Vec<&str> = lines
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if lines != expected {
        return Err(ResultsWriterError::Integrity {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}
