//! Async upstream collection with bounded retries and jittered exponential backoff.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use reqwest::Client;
use scraper::{Html, Selector};
use tokio::time::sleep;

use super::config::{CollectorConfig, Transport, USER_AGENT};
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
        let mut url = format!(
            "{}?transport={}",
            self.config.bridgedb_base_url.trim_end_matches('/'),
            transport.bridgedb_name()
        );
        if ipv6 {
            url.push_str("&ipv6=yes");
        }
        let body = self.fetch_text(&url).await?;
        let lines = extract_bridgedb_lines(&body)?;
        Ok(filter_variant(lines, ipv6))
    }

    /// Fetch a community seed list matching the existing output filename.
    pub async fn fetch_delta(&self, transport: Transport, ipv6: bool) -> Result<Vec<String>> {
        let suffix = if ipv6 { "_ipv6" } else { "" };
        let url = format!(
            "{}/{}{}.txt",
            self.config.delta_raw_base_url.trim_end_matches('/'),
            transport.file_name(),
            suffix
        );
        let body = self.fetch_text(&url).await?;
        Ok(filter_variant(
            body.lines().map(clean_output_line).collect(),
            ipv6,
        ))
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
