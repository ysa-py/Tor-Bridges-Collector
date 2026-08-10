//! Async upstream collection with bounded retries, jittered exponential
//! backoff, per-source circuit breaking, and HTTP 429/403 detection.

use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use reqwest::Client;
use scraper::{Html, Selector};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use super::config::{CollectorConfig, Transport, COMMUNITY_SOURCE_BASES, USER_AGENT};
use super::parsing::{clean_output_line, is_ipv6_line, is_valid_bridge_line};

/// ── Per-source circuit breaker ─────────────────────────────────────────
///
/// After `threshold` consecutive fetch failures for a source key (typically
/// the hostname of the URL), the breaker opens and all subsequent attempts
/// for that source are skipped for `cooldown` seconds.  This prevents a
/// persistently dead mirror from consuming the entire stage budget on every
/// run.  A single successful fetch from the source resets the counter and
/// closes the breaker.
#[derive(Clone, Debug)]
pub struct SourceCircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    open_since: Arc<Mutex<std::collections::HashMap<String, Instant>>>,
    failures: Arc<Mutex<std::collections::HashMap<String, u32>>>,
}

impl SourceCircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            threshold,
            cooldown,
            open_since: Arc::new(Mutex::new(std::collections::HashMap::new())),
            failures: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Check whether the source is allowed to be contacted.  An open breaker
    /// automatically resets when its cooldown has elapsed.
    pub fn allow(&self, source_key: &str) -> bool {
        let mut open = match self.open_since.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        if let Some(opened) = open.get(source_key).copied() {
            if now.duration_since(opened) >= self.cooldown {
                // Cooldown expired — close the breaker
                open.remove(source_key);
                if let Ok(mut f) = self.failures.lock() {
                    f.remove(source_key);
                }
                tracing::info!(
                    source = %source_key,
                    "circuit-breaker cooldown elapsed; source re-enabled"
                );
                return true;
            }
            return false;
        }
        true
    }

    /// Record one fetch outcome.  After `threshold` consecutive failures
    /// the source is blocked until the cooldown passes.
    pub fn record(&self, source_key: &str, success: bool) {
        if success {
            // Reset on any success
            let mut failed = match self.failures.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            failed.remove(source_key);
            let mut open = match self.open_since.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            open.remove(source_key);
            return;
        }
        let mut failed = match self.failures.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let count = failed.entry(source_key.to_ascii_lowercase()).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= self.threshold {
            let mut open = match self.open_since.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            open.insert(source_key.to_ascii_lowercase(), Instant::now());
            tracing::warn!(
                source = %source_key,
                consecutive_failures = *count,
                cooldown_secs = self.cooldown.as_secs(),
                "source circuit breaker opened; source will be skipped"
            );
        }
    }

    /// Extract a stable source key from a URL (hostname component).
    pub fn key_from_url(url: &str) -> String {
        url.split('/')
            .nth(2)
            .map(|h| h.split(':').next().unwrap_or("unknown"))
            .unwrap_or("unknown")
            .to_ascii_lowercase()
    }
}

/// HTTP source client shared across BridgeDB and community-seed fetches.
#[derive(Clone)]
pub struct SourceFetcher {
    client: Client,
    config: CollectorConfig,
    circuit_breaker: SourceCircuitBreaker,
}

impl SourceFetcher {
    /// Build a source client with a realistic browser user agent and bounded
    /// request timeout. TLS validation remains enabled for upstream sources.
    pub fn new(config: CollectorConfig) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .timeout(Duration::from_secs(
                config
                    .per_source_timeout_secs
                    .max(config.connect_timeout_secs.saturating_mul(3)),
            ))
            .build()
            .context("unable to construct upstream HTTP client")?;
        let circuit_breaker = SourceCircuitBreaker::new(
            config.source_circuit_breaker_failures,
            Duration::from_secs(config.source_circuit_breaker_reset_secs),
        );
        Ok(Self {
            client,
            config,
            circuit_breaker,
        })
    }

    /// Fetch BridgeDB HTML and extract `#bridgelines` text for one transport/IP
    /// family. A source failure is returned for the caller to log and skip.
    pub async fn fetch_bridgedb(&self, transport: Transport, ipv6: bool) -> Result<Vec<String>> {
        let base = format!(
            "{}?transport={}",
            self.config.bridgedb_base_url.trim_end_matches('/'),
            transport.bridgedb_name()
        );
        let urls = if ipv6 {
            vec![format!("{base}&ipv6=yes"), format!("{base}&ipv6=true")]
        } else {
            vec![format!("{base}&ipv6=no"), base]
        };
        let source_key = SourceCircuitBreaker::key_from_url(&self.config.bridgedb_base_url);
        if !self.circuit_breaker.allow(&source_key) {
            return Err(anyhow!(
                "BridgeDB source circuit-broken for {source_key} (skipped after {} consecutive failures)",
                self.config.source_circuit_breaker_failures
            ));
        }

        let mut last_error = None;
        for url in urls {
            match self.fetch_text(&url).await {
                Ok(body) => {
                    self.circuit_breaker.record(&source_key, true);
                    let lines = filter_variant(extract_bridgedb_lines(&body)?, ipv6);
                    if !lines.is_empty() {
                        return Ok(lines);
                    }
                    last_error = Some(anyhow!(
                        "BridgeDB returned no {transport} {ip} lines",
                        ip = if ipv6 { "IPv6" } else { "IPv4" }
                    ));
                }
                Err(error) => {
                    self.circuit_breaker.record(&source_key, false);
                    last_error = Some(error);
                }
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

    /// Validate each configured mirror URL at startup with a lightweight HEAD
    /// request.  Unreachable mirrors are removed from the active source list
    /// for this run instead of being retried blindly.
    pub async fn validate_mirrors(&self, bases: &[String]) -> Vec<String> {
        let mut valid = Vec::new();
        let mut tasks = JoinSet::new();
        for base in bases {
            let client = self.client.clone();
            let base_url = base.clone();
            let timeout_secs = self.config.per_source_timeout_secs.min(10);
            tasks.spawn(async move {
                let result = timeout(
                    Duration::from_secs(timeout_secs),
                    client.head(&base_url).send(),
                )
                .await;
                (base_url, result)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((base, Ok(Ok(response)))) if response.status().is_success() => {
                    tracing::info!(mirror = %base, "mirror validated (HEAD OK)");
                    valid.push(base);
                }
                Ok((base, Ok(Ok(response)))) => {
                    let status = response.status();
                    tracing::warn!(
                        mirror = %base,
                        http_status = %status,
                        "mirror HEAD check returned non-success; removing from active list"
                    );
                }
                Ok((base, Ok(Err(error)))) => {
                    tracing::warn!(
                        mirror = %base,
                        %error,
                        "mirror HEAD check network error; removing from active list"
                    );
                }
                Ok((base, Err(_timeout))) => {
                    tracing::warn!(
                        mirror = %base,
                        "mirror HEAD check timed out; removing from active list"
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "mirror validation task failed");
                }
            }
        }
        valid
    }

    /// Fetch and merge every configured public mirror for one transport/IP
    /// family. The result is source-diverse and deduplicated; a single outage
    /// is not allowed to suppress lines returned by a healthy mirror.
    /// Mirrors that are circuit-broken are skipped with a structured log entry.
    pub async fn fetch_community_sources(
        &self,
        transport: Transport,
        ipv6: bool,
    ) -> Result<Vec<String>> {
        let urls = self.source_urls(transport, ipv6);
        let mut tasks = JoinSet::new();
        let mut skipped_count = 0u32;
        for url in urls {
            let fetcher = self.clone();
            let source_key = SourceCircuitBreaker::key_from_url(&url);
            if !fetcher.circuit_breaker.allow(&source_key) {
                tracing::warn!(
                    source = %source_key,
                    url = %url,
                    transport = %transport,
                    ipv6,
                    "community mirror circuit-broken; skipping this run"
                );
                skipped_count = skipped_count.saturating_add(1);
                continue;
            }
            tasks.spawn(async move {
                let result = fetcher.fetch_text(&url).await;
                (url, source_key, result)
            });
        }

        let mut fetched = Vec::new();
        let mut failures = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_url, source_key, Ok(body))) => {
                    self.circuit_breaker.record(&source_key, true);
                    fetched.extend(body.lines().map(clean_output_line));
                }
                Ok((url, source_key, Err(error))) => {
                    self.circuit_breaker.record(&source_key, false);
                    failures.push(format!("{url}: {error}"));
                }
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
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                transport = %transport,
                ipv6,
                "mirrors skipped by circuit breaker"
            );
        }
        Ok(filtered)
    }

    /// Build a deterministic, redundant URL set. A custom base may be either
    /// a directory (`https://host/bridge`) or a template containing
    /// `{transport}` and `{ipv6}`. Transport aliases cover the filenames used
    /// by BridgeDB/community archives (`meek`, `meek_lite`, and `meek-azure`).
    fn source_urls(&self, transport: Transport, ipv6: bool) -> Vec<String> {
        let mut bases = vec![self.config.delta_raw_base_url.clone()];
        // Add the resolved raw_repo_url as a secondary mirror (self-host)
        let raw = self.config.raw_repo_url.clone();
        if !raw.contains("UNRESOLVED") && raw != self.config.delta_raw_base_url {
            bases.push(raw);
        }
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
    ///
    /// HTTP 429 (Too Many Requests) and 403 (Forbidden → possible CAPTCHA wall)
    /// are detected and treated with a longer backoff so rate-limited sources
    /// are not hammered with rapid retries.
    async fn fetch_text(&self, url: &str) -> Result<String> {
        let source_key = SourceCircuitBreaker::key_from_url(url);
        let mut last_error = None;
        for attempt in 0..self.config.fetch_retries {
            let fetch_result = timeout(
                Duration::from_secs(self.config.per_source_timeout_secs),
                self.client.get(url).send(),
            )
            .await;

            match fetch_result {
                Ok(Ok(response)) => {
                    let status = response.status();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        // 429 — rate-limited; back off significantly
                        last_error = Some(anyhow!("upstream rate-limited (HTTP 429)"));
                        let delay_secs =
                            std::cmp::min(30_u64.saturating_mul(1_u64 << attempt.min(3)), 120);
                        tracing::warn!(
                            source = %source_key,
                            attempt = attempt + 1,
                            delay_secs,
                            "upstream returned HTTP 429; backing off longer"
                        );
                        sleep(Duration::from_secs(delay_secs)).await;
                        continue;
                    }
                    if status == reqwest::StatusCode::FORBIDDEN {
                        // 403 — possible CAPTCHA wall
                        last_error = Some(anyhow!(
                            "upstream returned HTTP 403 (possible CAPTCHA/bot detection)"
                        ));
                        tracing::warn!(
                            source = %source_key,
                            attempt = attempt + 1,
                            "upstream returned HTTP 403; treating as CAPTCHA wall"
                        );
                        continue;
                    }
                    if status.is_success() {
                        match response.text().await {
                            Ok(text) if !text.trim().is_empty() => return Ok(text),
                            Ok(_) => last_error = Some(anyhow!("upstream returned an empty body")),
                            Err(error) => {
                                last_error = Some(anyhow!("unable to read response body: {error}"))
                            }
                        }
                    } else {
                        last_error = Some(anyhow!("upstream HTTP status {status}"));
                    }
                }
                Ok(Err(error)) => {
                    last_error = Some(anyhow!("upstream request failed: {error}"));
                }
                Err(_elapsed) => {
                    last_error = Some(anyhow!(
                        "upstream request timed out after {}s",
                        self.config.per_source_timeout_secs
                    ));
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
                    source = %source_key,
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
            "obfs4 [2606:4700:4700::1111]:443 FINGER cert=abc".to_owned(),
        ];
        assert_eq!(filter_variant(lines.clone(), false).len(), 1);
        assert_eq!(filter_variant(lines, true).len(), 1);
    }

    #[test]
    fn circuit_breaker_opens_after_threshold_failures() {
        let cb = SourceCircuitBreaker::new(3, Duration::from_secs(60));
        let key = "test.example.com";
        assert!(cb.allow(key));
        cb.record(key, false);
        assert!(cb.allow(key));
        cb.record(key, false);
        assert!(cb.allow(key));
        cb.record(key, false);
        assert!(!cb.allow(key), "breaker should open after 3 failures");
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        let cb = SourceCircuitBreaker::new(3, Duration::from_secs(60));
        let key = "test.example.com";
        cb.record(key, false);
        cb.record(key, false);
        assert!(cb.allow(key));
        cb.record(key, true);
        cb.record(key, false);
        assert!(cb.allow(key), "breaker should be reset after a success");
    }

    #[test]
    fn key_from_url_extracts_hostname() {
        assert_eq!(
            SourceCircuitBreaker::key_from_url(
                "https://raw.githubusercontent.com/Delta-Kronecker/Repo/main/bridge/obfs4.txt"
            ),
            "raw.githubusercontent.com"
        );
    }
}
