//! Async upstream collection with bounded retries and jittered exponential backoff.

use std::collections::BTreeSet;
use std::env;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use reqwest::Client;
use scraper::{Html, Selector};
use tokio::task::JoinSet;
use tokio::time::sleep;

use super::config::{CollectorConfig, Transport, COMMUNITY_SOURCE_BASES, USER_AGENT};
use super::parsing::{clean_output_line, is_ipv6_line, is_valid_bridge_line};

/// HTTP source client shared across BridgeDB and community-seed fetches.
#[derive(Clone)]
pub struct SourceFetcher {
    client: Client,
    config: CollectorConfig,
}

impl SourceFetcher {
    /// Build a source client with a realistic browser user agent and bounded
    /// request timeout. TLS validation remains enabled for upstream sources.
    pub fn new(config: CollectorConfig) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .timeout(Duration::from_secs(
                config.connect_timeout_secs.saturating_mul(3),
            ))
            .build()
            .context("unable to construct upstream HTTP client")?;
        Ok(Self { client, config })
    }

    /// Fetch BridgeDB HTML and extract `#bridgelines` text for one transport/IP
    /// family. A source failure is returned for the caller to log and skip.
    pub async fn fetch_bridgedb(&self, transport: Transport, ipv6: bool) -> Result<Vec<String>> {
        let base = format!(
            "{}?transport={}",
            self.config.bridgedb_base_url.trim_end_matches('/'),
            transport.bridgedb_name()
        );
        // BridgeDB has accepted both `yes/no` and boolean query spellings in
        // different deployments. Try a redundant spelling when the primary
        // response is empty so WebTunnel IPv4 and Vanilla IPv6 do not depend
        // on one server-side parameter parser.
        let urls = if ipv6 {
            vec![format!("{base}&ipv6=yes"), format!("{base}&ipv6=true")]
        } else {
            vec![format!("{base}&ipv6=no"), base]
        };
        let mut last_error = None;
        for url in urls {
            match self.fetch_text(&url).await {
                Ok(body) => {
                    let lines = filter_variant(extract_bridgedb_lines(&body)?, ipv6);
                    if !lines.is_empty() {
                        return Ok(lines);
                    }
                    last_error = Some(anyhow!(
                        "BridgeDB returned no {transport} {ip} lines",
                        ip = if ipv6 { "IPv6" } else { "IPv4" }
                    ));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("BridgeDB returned no usable lines")))
    }

    /// Fetch the primary community seed list matching the existing output
    /// filename. Kept as a small compatibility method for callers that want
    /// one source only.
    pub async fn fetch_delta(&self, transport: Transport, ipv6: bool) -> Result<Vec<String>> {
        let urls = self.source_urls(transport, ipv6);
        let url = urls
            .first()
            .ok_or_else(|| anyhow!("no configured community source"))?;
        let body = self.fetch_text(url).await?;
        Ok(filter_variant(
            body.lines().map(clean_output_line).collect(),
            ipv6,
        ))
    }

    /// Fetch and merge every configured public mirror for one transport/IP
    /// family. The result is source-diverse and deduplicated; a single outage
    /// is not allowed to suppress lines returned by a healthy mirror.
    pub async fn fetch_community_sources(
        &self,
        transport: Transport,
        ipv6: bool,
    ) -> Result<Vec<String>> {
        let urls = self.source_urls(transport, ipv6);
        let mut tasks = JoinSet::new();
        for url in urls {
            let fetcher = self.clone();
            tasks.spawn(async move {
                let result = fetcher.fetch_text(&url).await;
                (url, result)
            });
        }

        let mut fetched = Vec::new();
        let mut failures = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_url, Ok(body))) => fetched.extend(body.lines().map(clean_output_line)),,
                Ok((url, Err(error))) => failures.push(format!("{url}: {error}")),
                Err(error) => failures.push(format!("source task failed: {error}")),
            }
        }
        let filtered = filter_variant(fetched, ipv6);
        if filtered.is_empty() && !failures.is_empty() {
            return Err(anyhow!(
                "all community mirrors failed: {}",
                failures.join("; ")
            ));
        }
        Ok(filtered)
    }

    /// Build a deterministic, redundant URL set. A custom base may be either
    /// a directory (`https://host/bridge`) or a template containing
    /// `{transport}` and `{ipv6}`. Transport aliases cover the filenames used
    /// by BridgeDB/community archives (`meek`, `meek_lite`, and `meek-azure`).
    fn source_urls(&self, transport: Transport, ipv6: bool) -> Vec<String> {
        let mut bases = vec![self.config.delta_raw_base_url.clone()];
        // A test/controlled deployment that overrides the primary endpoint
        // must not unexpectedly contact public mirrors. Production defaults
        // retain the redundant second mirror.
        if self.config.delta_raw_base_url == COMMUNITY_SOURCE_BASES[0] {
            bases.extend(
                COMMUNITY_SOURCE_BASES
                    .iter()
                    .skip(1)
                    .map(|base| (*base).to_string()),
            );
        }
        if let Ok(extra) = env::var("BRIDGE_SOURCE_BASES") {
            bases.extend(
                extra
                    .split(',')
                    .map(str::trim)
                    .filter(|base| !base.is_empty())
                    .map(str::to_owned),
            );
        }

        let names: &[&str] = match transport {
            Transport::MeekAzure => &["meek-azure", "meek_lite", "meek"],
            _ => &[transport.file_name()],
        };
        let suffix = if ipv6 { "_ipv6" } else { "" };
        let mut urls = BTreeSet::new();
        for base in bases {
            for name in names {
                let url = if base.contains("{transport}") {
                    base.replace("{transport}", name)
                        .replace("{ipv6}", if ipv6 { "_ipv6" } else { "" })
                } else {
                    format!("{}/{}{}.txt", base.trim_end_matches('/'), name, suffix)
                };
                urls.insert(url);
            }
        }
        urls.into_iter().collect()
    }

    /// Fetch text with exponential backoff and full jitter. Empty successful
    /// responses are errors rather than replacement data, ensuring an upstream
    /// outage can never wipe an existing archive.
    async fn fetch_text(&self, url: &str) -> Result<String> {
        let mut last_error = None;
        for attempt in 0..self.config.fetch_retries {
            match self.client.get(url).send().await {
                Ok(response) if response.status().is_success() => match response.text().await {
                    Ok(text) if !text.trim().is_empty() => return Ok(text),
                    Ok(_) => last_error = Some(anyhow!("upstream returned an empty body")),
                    Err(error) => {
                        last_error = Some(anyhow!("unable to read response body: {error}"))
                    }
                },
                Ok(response) => {
                    last_error = Some(anyhow!("upstream HTTP status {}", response.status()));
                }
                Err(error) => {
                    last_error = Some(anyhow!("upstream request failed: {error}"));
                }
            }

            if attempt + 1 < self.config.fetch_retries {
                let exponent = attempt.min(8) as u32;
                let ceiling_ms = 250_u64.saturating_mul(1_u64 << exponent).min(20_000);
                let delay_ms = rand::thread_rng().gen_range(0..=ceiling_ms);
                tracing::warn!(
                    attempt = attempt + 1,
                    retries = self.config.fetch_retries,
                    delay_ms,
                    "source fetch failed; retrying with jitter"
                );
                sleep(Duration::from_millis(delay_ms)).await;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("source fetch failed without an error")))
            .with_context(|| format!("fetching {url}"))
    }
}

/// Parse BridgeDB HTML using `scraper`, with a plain-text fallback for harmless
/// markup variations. The fallback still applies strict bridge-line filtering.
pub fn extract_bridgedb_lines(body: &str) -> Result<Vec<String>> {
    let selector = Selector::parse("#bridgelines")
        .map_err(|error| anyhow!("invalid built-in BridgeDB selector: {error}"))?;
    let document = Html::parse_document(body);
    let selected = document
        .select(&selector)
        .flat_map(|element| element.text())
        .collect::<Vec<_>>()
        .join("\n");

    let candidate_text = if selected.trim().is_empty() {
        body
    } else {
        &selected
    };
    let lines = candidate_text
        .lines()
        .map(clean_output_line)
        .filter(|line| is_valid_bridge_line(line))
        .collect();
    Ok(deduplicate(lines))
}

/// Deduplicate case/whitespace variants while retaining a deterministic,
/// human-readable representative.
pub fn deduplicate(lines: Vec<String>) -> Vec<String> {
    let mut unique = std::collections::BTreeMap::new();
    for line in lines {
        let clean = clean_output_line(&line);
        if !is_valid_bridge_line(&clean) {
            continue;
        }
        let key = clean.to_ascii_lowercase();
        unique.entry(key).or_insert(clean);
    }
    unique.into_values().collect()
}

fn filter_variant(lines: Vec<String>, ipv6: bool) -> Vec<String> {
    deduplicate(
        lines
            .into_iter()
            .map(|line| clean_output_line(&line))
            .filter(|line| is_valid_bridge_line(line) && is_ipv6_line(line) == ipv6)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridgedb_parser_uses_container_and_deduplicates() {
        let html = r#"
            <html><body><div id="bridgelines">
              obfs4 1.2.3.4:443 FINGER cert=abc
              obfs4 1.2.3.4:443 FINGER cert=abc
              # comment
            </div></body></html>
        "#;
        let lines = extract_bridgedb_lines(html).expect("fixture HTML must parse");
        assert_eq!(lines, vec!["obfs4 1.2.3.4:443 FINGER cert=abc"]);
    }

    #[test]
    fn variant_filter_separates_ipv4_and_ipv6() {
        let lines = vec![
            "obfs4 1.2.3.4:443 FINGER cert=abc".to_owned(),
            "obfs4 [2001:db8::1]:443 FINGER cert=abc".to_owned(),
        ];
        assert_eq!(filter_variant(lines.clone(), false).len(), 1);
        assert_eq!(filter_variant(lines, true).len(), 1);
    }
}
