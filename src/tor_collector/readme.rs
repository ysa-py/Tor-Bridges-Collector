//! README, ZIP, Telegram, and optional Prometheus text rendering.

use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use reqwest::multipart::{Form, Part};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::config::{CollectorConfig, ListSpec, Transport};

/// Counts for one generated bridge-list projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ListStats {
    /// Full archive count.
    pub archive: usize,
    /// First-seen-within-window count.
    pub recent: usize,
    /// Protocol-verified count.
    pub tested: usize,
}

/// All per-list statistics keyed by archive filename.
pub type StatsMap = BTreeMap<String, ListStats>;

/// Render the dynamic bridge collector README. The generated links maintain
/// the raw GitHub path convention used by the Python scripts.
pub fn render_readme(config: &CollectorConfig, stats: &StatsMap, now: DateTime<Utc>) -> String {
    let repo = config.raw_repo_url.trim_end_matches('/');
    let pooled_rows = Transport::POOLED
        .iter()
        .map(|transport| pooled_row(*transport, repo, stats))
        .collect::<Vec<_>>()
        .join("\n");
    let fronted_rows = Transport::FRONTED
        .iter()
        .map(|transport| fronted_row(*transport, repo, stats))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Tor Bridges Collector & Archive\n\
\n\
This repository automatically collects, validates, and archives public Tor bridge\n\
lines. The Rust collector merges official BridgeDB results, the community seed\n\
list, and Tor Browser fronted defaults on an hourly GitHub Actions schedule.\n\
\n\
_Last updated: {}_\n\
\n\
## Tested & Active\n\
\n\
`*_tested.txt` only contains lines that passed a transport-appropriate check in\n\
the current run: direct TCP for vanilla and IPv6 obfs4, an obfs4 SOCKS\n\
handshake for IPv4 obfs4 when a harness is available, a WebSocket `101` upgrade\n\
for WebTunnel, or TLS to the broker/front for domain-fronted transports.\n\
\n\
| Transport | IPv4 tested | IPv6 tested | Fresh 72h IPv4 | Fresh 72h IPv6 | Full archive IPv4 | Full archive IPv6 |\n\
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n\
{pooled_rows}\n\
\n\
## Fronted transports\n\
\n\
Snowflake, meek-azure (`meek_lite` bridge token), and Conjure do not have\n\
BridgeDB rotating pools. Their published default lines use documentation\n\
placeholder addresses; their tested lists reflect front/broker TLS reachability.\n\
\n\
| Transport | Tested & active | Fresh 72h | Default archive |\n\
| :--- | :--- | :--- | :--- |\n\
{fronted_rows}\n\
\n\
## IPv6 and WebTunnel notes\n\
\n\
IPv6 bridge availability depends on the runner and local network. WebTunnel\n\
bridges are retained only when the exact `url=` endpoint answers an HTTP\n\
WebSocket Upgrade with `101 Switching Protocols`; an ordinary CDN TLS response\n\
does not qualify.\n\
\n\
## Sources\n\
\n\
- Official Tor BridgeDB: <https://bridges.torproject.org>\n\
- Community seed: <https://github.com/Delta-Kronecker/Tor-Bridges-Collector>\n\
- Fixed Snowflake, meek-azure, and Conjure defaults from Tor Browser transport\n\
  configuration\n\
\n\
## Automation and safety\n\
\n\
The collector preserves existing non-empty archives when an upstream source is\n\
empty or unavailable, retains history for {} days, and marks bridges first seen\n\
in the last {} hours as fresh. `--dry-run` performs collection and probing but\n\
prints the would-change summary without writing `bridge/`, `README.md`, or ZIP\n\
outputs.\n\
\n\
## Disclaimer\n\
\n\
Bridge availability is network- and time-dependent. A successful protocol probe\n\
is not a guarantee of a complete Tor circuit or availability in a particular\n\
country. Use public bridge data responsibly and in accordance with applicable\n\
law.\n",
        now.format("%Y-%m-%d %H:%M UTC"),
        config.history_retention_days,
        config.recent_hours,
    )
}

/// Build a ZIP equivalent to vip.py's archive layout. Every `.txt` bridge file
/// is placed under `Tor Bridges/Full Archive`, `Recent 72h`, or `Tested` based
/// on its filename. History and existing ZIP files are intentionally excluded.
pub fn build_zip(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, bytes) in entries {
        if !name.ends_with(".txt") || name == "tor_bridges.zip" {
            continue;
        }
        let folder = if name.ends_with("_tested.txt") {
            "Tested"
        } else if name.contains("_72h") {
            "Recent 72h"
        } else {
            "Full Archive"
        };
        zip.start_file(format!("Tor Bridges/{folder}/{name}"), options)
            .with_context(|| format!("unable to add {name} to ZIP"))?;
        zip.write_all(bytes)
            .with_context(|| format!("unable to write {name} to ZIP"))?;
    }
    let cursor = zip.finish().context("unable to finalize bridge ZIP")?;
    Ok(cursor.into_inner())
}

/// Upload a generated archive to Telegram. A remote failure is returned for
/// logging but is intentionally not allowed to erase local publication output.
pub async fn upload_telegram(
    config: &CollectorConfig,
    zip_bytes: Vec<u8>,
    caption: String,
) -> Result<()> {
    let token = config
        .telegram_bot_token
        .as_deref()
        .ok_or_else(|| anyhow!("TELEGRAM_BOT_TOKEN is not configured"))?;
    let chat_id = config
        .telegram_chat_id
        .as_deref()
        .ok_or_else(|| anyhow!("TELEGRAM_CHAT_ID is not configured"))?;
    let url = format!("https://api.telegram.org/bot{token}/sendDocument");
    let document = Part::bytes(zip_bytes)
        .file_name("tor_bridges.zip")
        .mime_str("application/zip")
        .context("unable to construct Telegram ZIP part")?;
    let form = Form::new()
        .text("chat_id", chat_id.to_owned())
        .text("caption", caption)
        .text("parse_mode", "Markdown")
        .part("document", document);
    let response = reqwest::Client::new()
        .post(url)
        .multipart(form)
        .send()
        .await
        .context("Telegram upload request failed")?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Telegram upload returned HTTP {}",
            response.status()
        ))
    }
}

/// Format the legacy-compatible Telegram caption from current list statistics.
pub fn telegram_caption(stats: &StatsMap) -> String {
    let count = |name: &str, projection: fn(ListStats) -> usize| {
        stats.get(name).copied().map(projection).unwrap_or(0)
    };
    let full = |transport: Transport, ipv6: bool| {
        let spec = ListSpec { transport, ipv6 };
        count(&spec.archive_name(), |stat| stat.archive)
    };
    let fresh = |transport: Transport, ipv6: bool| {
        let spec = ListSpec { transport, ipv6 };
        count(&spec.archive_name(), |stat| stat.recent)
    };
    let tested = |transport: Transport| {
        let spec = ListSpec {
            transport,
            ipv6: false,
        };
        count(&spec.archive_name(), |stat| stat.tested)
    };
    let total = Transport::POOLED
        .iter()
        .map(|transport| full(*transport, false) + full(*transport, true))
        .sum::<usize>();

    format!(
        "*Tor Bridges Collector - Live Update*\n\
\n\
*Source:* All pooled bridges are fetched from BridgeDB and the community seed in real time.\n\
\n\
*Statistics:*\n\
\n\
*Full Archive (All Time):*\n\
• obfs4 IPv4: {} | IPv6: {}\n\
• WebTunnel IPv4: {} | IPv6: {}\n\
• Vanilla IPv4: {} | IPv6: {}\n\
\n\
*Tested & Active (Recommended - IPv4 only):*\n\
• obfs4: {}\n\
• WebTunnel: {}\n\
• Vanilla: {}\n\
\n\
*Recent (Last 72h):*\n\
• obfs4 IPv4: {} | IPv6: {}\n\
• WebTunnel IPv4: {} | IPv6: {}\n\
• Vanilla IPv4: {} | IPv6: {}\n\
\n\
*Total Unique Bridges:* {total}\n\
\n\
━━━━━━━━━━━━━━━━━━━━━━\n\
*ZIP Contents:*\n\
• Full Archive/ - Complete bridge history\n\
• Recent 72h/ - Bridges from last 3 days\n\
• Tested/ - Verified working bridges\n\
\n\
Note: IPv6 bridges are fewer and often less stable than IPv4. For best results, use IPv4 first.",
        full(Transport::Obfs4, false),
        full(Transport::Obfs4, true),
        full(Transport::WebTunnel, false),
        full(Transport::WebTunnel, true),
        full(Transport::Vanilla, false),
        full(Transport::Vanilla, true),
        tested(Transport::Obfs4),
        tested(Transport::WebTunnel),
        tested(Transport::Vanilla),
        fresh(Transport::Obfs4, false),
        fresh(Transport::Obfs4, true),
        fresh(Transport::WebTunnel, false),
        fresh(Transport::WebTunnel, true),
        fresh(Transport::Vanilla, false),
        fresh(Transport::Vanilla, true),
    )
}

/// Read text files in an existing bridge directory for ZIP inclusion. Values
/// staged by the current run should be inserted by the caller afterward.
pub fn existing_zip_entries(bridge_dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    if !bridge_dir.is_dir() {
        return Ok(entries);
    }
    for entry in std::fs::read_dir(bridge_dir)
        .with_context(|| format!("unable to enumerate {}", bridge_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".txt") && name != "tor_bridges.zip" {
            entries.insert(
                name.to_owned(),
                std::fs::read(&path)
                    .with_context(|| format!("unable to read {}", path.display()))?,
            );
        }
    }
    Ok(entries)
}

fn pooled_row(transport: Transport, repo: &str, stats: &StatsMap) -> String {
    let ipv4 = ListSpec {
        transport,
        ipv6: false,
    };
    let ipv6 = ListSpec {
        transport,
        ipv6: true,
    };
    let four = stats.get(&ipv4.archive_name()).copied().unwrap_or_default();
    let six = stats.get(&ipv6.archive_name()).copied().unwrap_or_default();
    format!(
        "| **{transport}** | {} | {} | {} | {} | {} | {} |",
        linked(repo, &ipv4.tested_name(), four.tested),
        linked(repo, &ipv6.tested_name(), six.tested),
        linked(repo, &ipv4.recent_name(), four.recent),
        linked(repo, &ipv6.recent_name(), six.recent),
        linked(repo, &ipv4.archive_name(), four.archive),
        linked(repo, &ipv6.archive_name(), six.archive),
    )
}

fn fronted_row(transport: Transport, repo: &str, stats: &StatsMap) -> String {
    let spec = ListSpec {
        transport,
        ipv6: false,
    };
    let stat = stats.get(&spec.archive_name()).copied().unwrap_or_default();
    format!(
        "| **{transport}** | {} | {} | {} |",
        linked(repo, &spec.tested_name(), stat.tested),
        linked(repo, &spec.recent_name(), stat.recent),
        linked(repo, &spec.archive_name(), stat.archive),
    )
}

fn linked(repo: &str, name: &str, count: usize) -> String {
    format!("[{name}]({repo}/{name}) (**{count}**)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CollectorConfig {
        CollectorConfig {
            bridge_dir: "bridge".into(),
            readme_path: "README.md".into(),
            history_path: "bridge/bridge_history.json".into(),
            zip_path: "bridge/tor_bridges.zip".into(),
            bridgedb_base_url: "https://example.invalid".to_owned(),
            delta_raw_base_url: "https://example.invalid".to_owned(),
            raw_repo_url: "https://raw.example/bridge".to_owned(),
            connect_timeout_secs: 8,
            obfs4_handshake_timeout_secs: 12,
            max_retries: 2,
            max_workers: 50,
            min_workers: 4,
            max_test_per_list: 600,
            recent_hours: 72,
            history_retention_days: 30,
            obfs4_verify_min_fraction: 0.2,
            front_failure_threshold: 3,
            front_cooldown_secs: 300,
            fetch_retries: 3,
            metrics_output: None,
            dry_run: false,
            verbose: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            telegram_upload: false,
            github_actions: false,
        }
    }

    #[test]
    fn readme_contains_transport_rows_and_raw_links() {
        let mut stats = StatsMap::new();
        stats.insert(
            "obfs4.txt".to_owned(),
            ListStats {
                archive: 12,
                recent: 3,
                tested: 4,
            },
        );
        let now = DateTime::parse_from_rfc3339("2026-08-03T12:00:00+00:00")
            .map(|time| time.with_timezone(&Utc))
            .expect("fixture timestamp");
        let output = render_readme(&config(), &stats, now);
        assert!(output.contains("**obfs4**"));
        assert!(output.contains("obfs4_tested.txt"));
        assert!(output.contains("https://raw.example/bridge/obfs4.txt"));
    }

    #[test]
    fn zip_uses_expected_three_folder_layout() {
        let entries = BTreeMap::from([
            ("obfs4.txt".to_owned(), b"one\n".to_vec()),
            ("obfs4_72h.txt".to_owned(), b"two\n".to_vec()),
            ("obfs4_tested.txt".to_owned(), b"three\n".to_vec()),
        ]);
        let bytes = build_zip(&entries).expect("fixture ZIP");
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("fixture ZIP readable");
        assert!(zip.by_name("Tor Bridges/Full Archive/obfs4.txt").is_ok());
        assert!(zip.by_name("Tor Bridges/Recent 72h/obfs4_72h.txt").is_ok());
        assert!(zip.by_name("Tor Bridges/Tested/obfs4_tested.txt").is_ok());
    }

    #[test]
    fn telegram_caption_includes_legacy_sections() {
        let caption = telegram_caption(&StatsMap::new());
        assert!(caption.contains("*Full Archive (All Time):*"));
        assert!(caption.contains("*ZIP Contents:*"));
    }
}
