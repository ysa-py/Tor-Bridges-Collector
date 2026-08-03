//! Mass dynamic bridge ingestion engine.
//!
//! Replaces the old single-source ingestion bottleneck with a multi-source,
//! ordered-fallback harvest spanning every transport family (`obfs4`,
//! `webtunnel`, `vanilla`, `snowflake`, `meek_lite`, `conjure`):
//!
//!   1. **BridgeDB** — `https://bridges.torproject.org/bridges?transport=…`
//!      HTML pages for every distributable transport, IPv4 + IPv6 variants.
//!   2. **MOAT API** — Tor Browser's bridge distributor protocol (reuses
//!      [`crate::scraper::fetch_moat`] via the live harvest path).
//!   3. **Telegram channels** — public channel preview pages (`t.me/s/…`)
//!      are parsed for bridge lines (HTML-to-text extraction).
//!   4. **OnionHop / community mirrors** — raw GitHub bridge lists
//!      (Delta-Kronecker mirror, self mirror, plus env-extendable
//!      `MASS_INGEST_MIRRORS` / `MASS_INGEST_TELEGRAM_CHANNELS`).
//!
//! Fallback semantics: every source is optional. A source failure is recorded
//! in the [`HarvestReport`] outcomes and the harvest continues with the next
//! source — the pipeline never fails because one upstream is unreachable.
//! Static built-in bridges are always merged as the final fallback layer, so
//! even a fully offline run produces a non-empty candidate list.
//!
//! Output contract (identical shape to the scraper stages, additive only):
//!
//!   * `bridge/bridge_history.json` — merged and pruned via
//!     [`crate::scraper::merge_raw_into_history`] / `prune_history`;
//!   * `bridge/bridge_list_for_testing.json` — rewritten via
//!     [`crate::scraper::write_testing_json`] so the tester stages always
//!     receive the widest available candidate pool.
//!
//! The `network` Cargo feature enables live fetching (production workflow
//! runs `cargo run --features network --bin mass_ingest`); the default build
//! merges the static seed only and reports `offline: true`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::adaptive_selector::AdaptiveBridgeSelector;
use crate::anti_ai_dpi::detect_transport;
use crate::scraper::{
    load_history, merge_raw_into_history, prune_history, save_history, write_testing_json,
};
use crate::sources_torproject::is_valid_line;
use crate::static_bridges;

#[cfg(feature = "network")]
use std::time::Duration;

#[cfg(feature = "network")]
use crate::scraper::HttpFetch;

/// Every transport family the mass ingestion engine attempts to harvest.
pub const ALL_TRANSPORTS: &[&str] = &[
    "obfs4",
    "webtunnel",
    "vanilla",
    "snowflake",
    "meek_lite",
    "conjure",
];

/// Transports BridgeDB distributes via its public HTML endpoint.
pub const BRIDGEDB_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla", "snowflake"];

/// Per-transport raw list files exposed by community GitHub mirrors.
pub const MIRROR_TRANSPORT_FILES: &[&str] = &[
    "obfs4.txt",
    "webtunnel.txt",
    "vanilla.txt",
    "snowflake.txt",
    "conjure.txt",
    "meek_lite.txt",
    "meek-azure.txt",
];

/// Delta-Kronecker community seed mirror (OnionHop lineage).
pub const DEFAULT_MIRROR_BASE: &str =
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge";

/// Self mirror — this repository's own published `bridge/` directory.
pub const SELF_MIRROR_BASE: &str =
    "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/main/bridge";

/// Default Telegram channels harvested via their public preview pages.
pub const DEFAULT_TELEGRAM_CHANNELS: &[&str] = &["iranbridges", "tor_bridges"];

/// One concrete ingestion source.
#[derive(Debug, Clone)]
pub enum SourceKind {
    /// bridges.torproject.org HTML page for one transport (optional IPv6).
    BridgeDb { transport: &'static str, ipv6: bool },
    /// Raw bridge lines from a plain-text URL.
    RawMirror { url: String },
    /// Public Telegram channel preview (`https://t.me/s/<channel>`).
    TelegramPreview { channel: String },
}

/// A named source specification with its fetch kind.
#[derive(Debug, Clone)]
pub struct SourceSpec {
    /// Stable human-readable label used in the harvest report.
    pub label: String,
    /// Concrete fetch/parse behaviour.
    pub kind: SourceKind,
}

/// Outcome of harvesting one source.
#[derive(Debug, Clone)]
pub struct SourceOutcome {
    /// Source label (matches [`SourceSpec::label`]).
    pub label: String,
    /// Number of bridge lines successfully parsed from the source.
    pub lines: usize,
    /// Fetch/parse error, if the source was unreachable.
    pub error: Option<String>,
}

/// Aggregated harvest result.
#[derive(Debug, Clone, Default)]
pub struct HarvestReport {
    /// Per-source outcomes (used for diagnostics and fallback transparency).
    pub outcomes: Vec<SourceOutcome>,
    /// `(raw line, transport, ip_version)` tuples collected from all sources.
    pub lines: Vec<(String, String, String)>,
}

/// Machine-readable summary of one `run_mass_ingestion` invocation.
#[derive(Debug, Clone)]
pub struct IngestionSummary {
    /// Number of configured live sources attempted.
    pub sources_attempted: usize,
    /// Number of live sources that returned parseable lines.
    pub sources_ok: usize,
    /// Number of unique bridge lines harvested (static + live).
    pub lines_harvested: usize,
    /// Number of records added to history in this run.
    pub lines_merged: usize,
    /// Total history records after the run.
    pub history_records: usize,
    /// Number of candidates written to `bridge_list_for_testing.json`.
    pub testing_count: usize,
    /// Harvested line counts grouped by transport.
    pub per_transport: std::collections::BTreeMap<String, usize>,
    /// `true` when the build had no `network` feature (static seed only).
    pub offline: bool,
}

impl IngestionSummary {
    /// JSON representation used by the CLI and the workflow log.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "offline": self.offline,
            "sources_attempted": self.sources_attempted,
            "sources_ok": self.sources_ok,
            "lines_harvested": self.lines_harvested,
            "lines_new_to_history": self.lines_merged,
            "history_records": self.history_records,
            "testing_candidates": self.testing_count,
            "per_transport": self.per_transport,
        })
    }
}

/// Build the full ordered source list (BridgeDB → mirrors → Telegram → env).
#[must_use]
pub fn sources() -> Vec<SourceSpec> {
    let mut out: Vec<SourceSpec> = Vec::new();

    for transport in BRIDGEDB_TRANSPORTS {
        out.push(SourceSpec {
            label: format!("bridgedb:{transport}:v4"),
            kind: SourceKind::BridgeDb {
                transport,
                ipv6: false,
            },
        });
        out.push(SourceSpec {
            label: format!("bridgedb:{transport}:v6"),
            kind: SourceKind::BridgeDb {
                transport,
                ipv6: true,
            },
        });
    }

    for base in [DEFAULT_MIRROR_BASE, SELF_MIRROR_BASE] {
        for file in MIRROR_TRANSPORT_FILES {
            out.push(SourceSpec {
                label: format!("mirror:{file}"),
                kind: SourceKind::RawMirror {
                    url: format!("{base}/{file}"),
                },
            });
        }
    }

    if let Ok(extra) = std::env::var("MASS_INGEST_MIRRORS") {
        for url in extra.split(',').filter(|s| !s.trim().is_empty()) {
            let url = url.trim();
            out.push(SourceSpec {
                label: format!("mirror-env:{url}"),
                kind: SourceKind::RawMirror {
                    url: url.to_string(),
                },
            });
        }
    }

    for channel in DEFAULT_TELEGRAM_CHANNELS {
        out.push(SourceSpec {
            label: format!("telegram:{channel}"),
            kind: SourceKind::TelegramPreview {
                channel: (*channel).to_string(),
            },
        });
    }

    if let Ok(extra) = std::env::var("MASS_INGEST_TELEGRAM_CHANNELS") {
        for channel in extra.split(',').filter(|s| !s.trim().is_empty()) {
            let channel = channel.trim();
            out.push(SourceSpec {
                label: format!("telegram-env:{channel}"),
                kind: SourceKind::TelegramPreview {
                    channel: channel.to_string(),
                },
            });
        }
    }

    out
}

/// Resolve a source kind to its fetch URL.
#[must_use]
pub fn source_url(kind: &SourceKind) -> String {
    match kind {
        SourceKind::BridgeDb { transport, ipv6 } => {
            let base = format!("https://bridges.torproject.org/bridges?transport={transport}");
            if *ipv6 {
                format!("{base}&ipv6=yes")
            } else {
                base
            }
        }
        SourceKind::RawMirror { url } => url.clone(),
        SourceKind::TelegramPreview { channel } => format!("https://t.me/s/{channel}"),
    }
}

/// Minimal HTML-to-text: block tags become newlines, all other tags are
/// dropped. Good enough for Telegram preview pages and BridgeDB fallbacks.
fn html_to_text(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_tag = false;
    let mut tag = String::new();
    for ch in body.chars() {
        if ch == '<' {
            in_tag = true;
            tag.clear();
        } else if ch == '>' && in_tag {
            in_tag = false;
            let t = tag.trim().to_lowercase();
            if matches!(t.as_str(), "br" | "br/" | "p" | "/p" | "div" | "/div") {
                out.push('\n');
            }
        } else if in_tag {
            tag.push(ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Decode the HTML entities that commonly appear in Telegram preview pages.
fn unescape_html(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

/// Parse a Telegram channel preview page for bridge lines.
#[must_use]
pub fn parse_telegram_preview(body: &str) -> Vec<String> {
    let text = unescape_html(&html_to_text(body));
    text.split('\n')
        .map(str::trim)
        .filter(|line| is_valid_line(line))
        .map(str::to_string)
        .collect()
}

/// Parse a fetched body according to the source kind.
#[must_use]
pub fn parse_source_body(kind: &SourceKind, body: &str) -> Vec<String> {
    match kind {
        SourceKind::BridgeDb { .. } => crate::sources_torproject::parse_html(body),
        SourceKind::RawMirror { .. } => body
            .lines()
            .map(str::trim)
            .filter(|line| is_valid_line(line))
            .map(str::to_string)
            .collect(),
        SourceKind::TelegramPreview { .. } => parse_telegram_preview(body),
    }
}

/// Infer the transport family of a raw bridge line. Extends
/// [`detect_transport`] with the `conjure` family so history records stay
/// correctly classified for every published transport.
#[must_use]
pub fn infer_transport(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("conjure") {
        "conjure"
    } else {
        detect_transport(line)
    }
}

/// Infer the IP version of a raw bridge line from bracketed IPv6 syntax.
#[must_use]
pub fn infer_ip_version(line: &str) -> &'static str {
    if line.contains('[') {
        "ipv6"
    } else {
        "ipv4"
    }
}

/// Static seed lines across every transport (the final fallback layer).
fn harvest_static_seed() -> Vec<(String, String, String)> {
    static_bridges::fallback_all()
        .into_iter()
        .map(|line| {
            (
                line.to_string(),
                infer_transport(line).to_string(),
                infer_ip_version(line).to_string(),
            )
        })
        .collect()
}

/// Fetch one URL and return the body text, or a descriptive error.
#[cfg(feature = "network")]
fn fetch_body(client: &dyn HttpFetch, url: &str) -> Result<String, String> {
    let resp = client
        .get(url, Duration::from_secs(25))
        .map_err(|err| err.to_string())?;
    if resp.status != 200 {
        return Err(format!("HTTP status {}", resp.status));
    }
    Ok(resp.text)
}

/// Harvest every live source in order, containing per-source failures.
#[cfg(feature = "network")]
pub fn harvest_live(client: &dyn HttpFetch) -> HarvestReport {
    let mut report = HarvestReport::default();
    for spec in sources() {
        let url = source_url(&spec.kind);
        match fetch_body(client, &url) {
            Ok(body) => {
                let lines = parse_source_body(&spec.kind, &body);
                report.outcomes.push(SourceOutcome {
                    label: spec.label.clone(),
                    lines: lines.len(),
                    error: None,
                });
                for line in lines {
                    report.lines.push((
                        line.clone(),
                        infer_transport(&line).to_string(),
                        infer_ip_version(&line).to_string(),
                    ));
                }
            }
            Err(error) => report.outcomes.push(SourceOutcome {
                label: spec.label,
                lines: 0,
                error: Some(error),
            }),
        }
    }
    report
}

/// Run the mass ingestion pipeline against `bridge_dir`.
///
/// Always merges the static seed; with the `network` feature enabled it also
/// harvests every live source with ordered fallback. Never fails on upstream
/// errors — only on local I/O failures. Returns an [`IngestionSummary`].
pub fn run_mass_ingestion(bridge_dir: &Path) -> Result<IngestionSummary, String> {
    fs::create_dir_all(bridge_dir)
        .map_err(|err| format!("cannot create {}: {err}", bridge_dir.display()))?;

    let mut all_lines: Vec<(String, String, String)> = harvest_static_seed();
    let mut outcomes: Vec<SourceOutcome> = Vec::new();

    #[cfg(feature = "network")]
    {
        let client = crate::scraper::ReqwestHttpFetch::new(Duration::from_secs(30));
        let live = harvest_live(&client);
        outcomes.extend(live.outcomes);
        all_lines.extend(live.lines);
    }
    #[cfg(not(feature = "network"))]
    {
        outcomes.push(SourceOutcome {
            label: "offline-mode".to_string(),
            lines: all_lines.len(),
            error: None,
        });
    }

    // Deduplicate preserving first-seen order (static seed first, then live).
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut unique: Vec<(String, String, String)> = Vec::new();
    for (raw, transport, ipv) in all_lines {
        let key = raw.trim();
        if key.is_empty() {
            continue;
        }
        if seen.insert(key.to_string()) {
            unique.push((raw, transport, ipv));
        }
    }

    let history_path = bridge_dir.join("bridge_history.json");
    let mut history = load_history(&history_path).map_err(|err| err.to_string())?;
    let before = history.as_object().map(|m| m.len()).unwrap_or(0);
    merge_raw_into_history(&mut history, &unique).map_err(|err| err.to_string())?;
    let pruned = prune_history(&mut history).map_err(|err| err.to_string())?;
    save_history(&history, &history_path).map_err(|err| err.to_string())?;

    let testing_path = bridge_dir.join("bridge_list_for_testing.json");
    let selector = AdaptiveBridgeSelector::from_env();
    let testing_count = write_testing_json(&history, &testing_path, &selector)
        .map_err(|err| err.to_string())?;

    let after = history.as_object().map(|m| m.len()).unwrap_or(0);
    let new_records = (after as i64 - (before as i64 - pruned as i64)).max(0) as usize;

    let mut per_transport: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (_, transport, _) in &unique {
        *per_transport.entry(transport.clone()).or_insert(0) += 1;
    }

    let sources_ok = outcomes.iter().filter(|o| o.error.is_none()).count();
    let summary = IngestionSummary {
        sources_attempted: outcomes.len(),
        sources_ok,
        lines_harvested: unique.len(),
        lines_merged: new_records,
        history_records: after,
        testing_count,
        per_transport,
        offline: cfg!(not(feature = "network")),
    };

    // Persist the report so the artifact bundle carries the harvest evidence.
    let data_dir = Path::new("data");
    fs::create_dir_all(data_dir)
        .map_err(|err| format!("cannot create {}: {err}", data_dir.display()))?;
    let report_path = data_dir.join("mass_ingestion_report.json");
    let mut report_body = serde_json::to_string_pretty(&summary.to_json())
        .map_err(|err| err.to_string())?;
    report_body.push('\n');
    fs::write(&report_path, report_body)
        .map_err(|err| format!("cannot write {}: {err}", report_path.display()))?;

    println!(
        "mass_ingest: {}",
        serde_json::to_string_pretty(&summary.to_json()).map_err(|err| err.to_string())?
    );
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_seed_covers_every_transport() {
        let seed = harvest_static_seed();
        assert!(!seed.is_empty());
        let transports: BTreeSet<&str> = seed.iter().map(|(_, t, _)| t.as_str()).collect();
        for transport in ALL_TRANSPORTS {
            assert!(transports.contains(transport), "missing {transport}");
        }
    }

    #[test]
    fn infer_transport_detects_conjure_and_tls_families() {
        assert_eq!(
            infer_transport("conjure 1.2.3.4:443 abc url=https://x"),
            "conjure"
        );
        assert_eq!(
            infer_transport("meek_lite 1.2.3.4:80 ABC url=https://m"),
            "meek_lite"
        );
        assert_eq!(
            infer_transport("snowflake 1.2.3.4:1 ABC url=https://s"),
            "snowflake"
        );
        assert_eq!(
            infer_transport("obfs4 1.2.3.4:443 cert=abc"),
            "obfs4"
        );
        assert_eq!(infer_transport("5.6.7.8:9001 12345"), "vanilla");
    }

    #[test]
    fn infer_ip_version_handles_brackets() {
        assert_eq!(infer_ip_version("obfs4 1.2.3.4:443"), "ipv4");
        assert_eq!(infer_ip_version("obfs4 [2001:db8::1]:443"), "ipv6");
    }

    #[test]
    fn telegram_preview_parses_bridge_lines() {
        let html = "<html><body><div class=\"tgme_widget_message_text\">obfs4 193.11.166.194:27025 \
            1AE2C08904527FEA90C4307C2A428523CF4DFED2 cert=abc iat-mode=2<br>vanilla 5.6.7.8:9001 \
            12345</div></body></html>";
        let lines = parse_telegram_preview(html);
        assert!(lines.iter().any(|l| l.starts_with("obfs4")));
        assert!(lines.iter().any(|l| l.starts_with("vanilla")));
    }

    #[test]
    fn raw_mirror_parsing_skips_comments_and_blank_lines() {
        let body = "# comment\n\nobfs4 1.2.3.4:443 cert=abc\nNo bridges available\nwebtunnel 5.6.7.8:443 url=https://x\n";
        let lines = parse_source_body(
            &SourceKind::RawMirror {
                url: "https://example.invalid/obfs4.txt".to_string(),
            },
            body,
        );
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn run_mass_ingestion_offline_writes_history_and_testing_list() {
        let dir = std::env::temp_dir().join(format!("mass_ingest_test_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let summary = run_mass_ingestion(&bridge_dir).expect("run");
        assert!(summary.lines_harvested > 0);
        assert!(summary.history_records > 0);
        assert!(summary.testing_count > 0);
        let testing = std::fs::read_to_string(bridge_dir.join("bridge_list_for_testing.json"))
            .expect("json");
        let list: Vec<String> = serde_json::from_str(&testing).expect("array");
        assert!(!list.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
