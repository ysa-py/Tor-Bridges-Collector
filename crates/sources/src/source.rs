//! The `Source` trait, the shared [`SourceContext`], and the generic
//! [`HttpSource`] collector.
//!
//! Every collector implements [`Source`] and receives a [`SourceContext`]
//! carrying the shared resilience stack. [`HttpSource`] adapts any HTTPS
//! bridge-list endpoint: it fetches through the global limiter and the
//! per-host circuit breaker, replays ETag/Last-Modified validators, retries
//! transient failures with jittered backoff, parses the body, and attaches
//! provenance. Failures are returned as [`CollectionFailure`] entries — a run
//! completes even when individual URLs or lines fail (skip-and-record).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use url::Url;

use crate::backoff::Backoff;
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::error::SourceError;
use crate::http::{FetchOutcome, HttpClient};
use crate::parsers::{parse_bridge_json, parse_bridge_text, ParseReport};
use crate::provenance::{CollectedBridge, SourceId};
use crate::rate_limit::TokenBucket;
use crate::BoxFuture;
use tbc_core::{Clock, Metrics};

/// Shared resources handed to every source during a collection run.
#[derive(Clone)]
pub struct SourceContext {
    /// The caching HTTP client (cheap to clone; shares transport and cache).
    pub http: HttpClient,
    /// The global token-bucket limiter shared by all sources in the run.
    pub limiter: Arc<TokenBucket>,
    /// Per-host circuit breakers, created on first use.
    pub breakers: Arc<BreakerRegistry>,
    /// The injected clock for deterministic timestamps and tests.
    pub clock: Arc<dyn Clock>,
    /// The run's metrics registry.
    pub metrics: Arc<Metrics>,
}

impl SourceContext {
    /// Build a context from its parts.
    pub fn new(
        http: HttpClient,
        limiter: Arc<TokenBucket>,
        breakers: Arc<BreakerRegistry>,
        clock: Arc<dyn Clock>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            http,
            limiter,
            breakers,
            clock,
            metrics,
        }
    }
}

/// A per-host circuit-breaker registry with a shared configuration.
#[derive(Debug)]
pub struct BreakerRegistry {
    config: CircuitBreakerConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<HashMap<String, Arc<CircuitBreaker>>>,
}

impl BreakerRegistry {
    /// Create a registry that mints breakers with `config`.
    pub fn new(config: CircuitBreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Arc<CircuitBreaker>>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Get (or create) the breaker for a host.
    pub fn for_host(&self, host: &str) -> Arc<CircuitBreaker> {
        let mut map = self.lock();
        if let Some(breaker) = map.get(host) {
            return breaker.clone();
        }
        let breaker = Arc::new(CircuitBreaker::new(
            host.to_owned(),
            self.config.clone(),
            self.clock.clone(),
        ));
        map.insert(host.to_owned(), breaker.clone());
        breaker
    }
}

/// One recorded, non-fatal failure from a collection run.
#[derive(Debug)]
pub struct CollectionFailure {
    /// The URL the failure came from (blank for parse-level line rejections).
    pub url: String,
    /// The classified error.
    pub error: SourceError,
    /// How many HTTP attempts were made before giving up (0 for pre-flight
    /// refusals such as an open circuit breaker).
    pub attempts: u32,
}

/// The complete result of collecting from one or more URLs.
#[derive(Debug, Default)]
pub struct CollectionReport {
    /// Successfully parsed bridges, with provenance attached.
    pub bridges: Vec<CollectedBridge>,
    /// Every failure encountered, so nothing is silent.
    pub failures: Vec<CollectionFailure>,
}

/// How a source interprets a fetched body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    /// Newline-delimited bridge lines.
    Text,
    /// A JSON bridge list (see [`crate::parsers::parse_bridge_json`]).
    Json,
}

/// A pluggable bridge source.
pub trait Source: Send + Sync {
    /// The source's stable identifier.
    fn id(&self) -> &SourceId;

    /// Collect bridges, returning a report of successes and failures.
    fn collect<'a>(
        &'a self,
        ctx: &'a SourceContext,
    ) -> BoxFuture<'a, Result<CollectionReport, SourceError>>;
}

/// The outcome of a guarded fetch (see [`fetch_guarded`]).
pub(crate) enum GuardedFetch {
    /// A fresh body and the number of attempts used.
    Body(Vec<u8>, u32),
    /// `304 Not Modified`.
    NotModified,
    /// A terminal failure and the number of attempts used.
    Failed(SourceError, u32),
}

/// Fetch `url` through the limiter, circuit breaker, conditional cache, and
/// jittered retry loop. This is the single resilience path shared by every
/// HTTP-backed source.
pub(crate) async fn fetch_guarded(
    ctx: &SourceContext,
    url: &Url,
    max_attempts: u32,
    mut backoff: Backoff,
) -> GuardedFetch {
    let breaker = ctx.breakers.for_host(&host_key(url));
    if let Err(error) = breaker.allow() {
        ctx.metrics.increment("tbc_sources_circuit_open_total", 1);
        return GuardedFetch::Failed(error, 0);
    }
    if let Err(error) = ctx.limiter.acquire().await {
        ctx.metrics
            .increment("tbc_sources_rate_limit_config_total", 1);
        return GuardedFetch::Failed(error, 0);
    }

    let mut attempts = 0u32;
    loop {
        attempts = attempts.saturating_add(1);
        match ctx.http.get(url).await {
            Ok(FetchOutcome::NotModified) => {
                breaker.record_success();
                ctx.metrics
                    .increment("tbc_sources_http_not_modified_total", 1);
                return GuardedFetch::NotModified;
            }
            Ok(FetchOutcome::Success { body, .. }) => {
                breaker.record_success();
                ctx.metrics.increment("tbc_sources_http_ok_total", 1);
                return GuardedFetch::Body(body, attempts);
            }
            Err(error) if error.is_retryable() && attempts < max_attempts => {
                breaker.record_failure();
                ctx.metrics.increment("tbc_sources_http_retry_total", 1);
                let delay = backoff.next_delay();
                tracing::warn!(
                    url = %url,
                    attempt = attempts,
                    kind = error.kind_name(),
                    "retryable fetch failure; backing off"
                );
                tokio::time::sleep(delay).await;
            }
            Err(error) => {
                breaker.record_failure();
                ctx.metrics.increment("tbc_sources_http_error_total", 1);
                return GuardedFetch::Failed(error, attempts);
            }
        }
    }
}

/// Derive a stable host key for the circuit-breaker registry.
fn host_key(url: &Url) -> String {
    url.host_str()
        .map(str::to_owned)
        .unwrap_or_else(|| url.as_str().to_owned())
}

/// A generic HTTP bridge-list source: a set of URLs and a body format.
pub struct HttpSource {
    id: SourceId,
    urls: Vec<Url>,
    format: BodyFormat,
    max_attempts: u32,
    backoff: Backoff,
}

impl HttpSource {
    /// Build a source from a validated [`SourceId`], a non-empty URL set, and
    /// a body format. Defaults to 3 attempts with the default backoff.
    pub fn new(id: SourceId, urls: Vec<Url>, format: BodyFormat) -> Result<Self, SourceError> {
        if urls.is_empty() {
            return Err(SourceError::Config(
                "HttpSource requires at least one URL".into(),
            ));
        }
        Ok(Self {
            id,
            urls,
            format,
            max_attempts: 3,
            backoff: Backoff::default(),
        })
    }

    /// Override the retry policy.
    pub fn with_retry(mut self, max_attempts: u32, backoff: Backoff) -> Self {
        self.max_attempts = max_attempts.max(1);
        self.backoff = backoff;
        self
    }

    /// Parse a body according to this source's format.
    fn parse_body(&self, body: &str, now: DateTime<Utc>) -> Result<ParseReport, SourceError> {
        match self.format {
            BodyFormat::Text => Ok(parse_bridge_text(body, now)),
            BodyFormat::Json => parse_bridge_json(body, now),
        }
    }

    /// Collect from a single URL, folding every failure into the report.
    async fn collect_url(&self, ctx: &SourceContext, url: &Url) -> CollectionReport {
        match fetch_guarded(ctx, url, self.max_attempts, self.backoff.clone()).await {
            GuardedFetch::NotModified => CollectionReport::default(),
            GuardedFetch::Failed(error, attempts) => CollectionReport {
                failures: vec![CollectionFailure {
                    url: url.to_string(),
                    error,
                    attempts,
                }],
                ..CollectionReport::default()
            },
            GuardedFetch::Body(body, attempts) => {
                let body_str = match std::str::from_utf8(&body) {
                    Ok(text) => text,
                    Err(error) => {
                        return CollectionReport {
                            failures: vec![CollectionFailure {
                                url: url.to_string(),
                                error: SourceError::Parse(format!(
                                    "body is not valid UTF-8: {error}"
                                )),
                                attempts,
                            }],
                            ..CollectionReport::default()
                        };
                    }
                };
                let parsed = match self.parse_body(body_str, ctx.clock.now()) {
                    Ok(report) => report,
                    Err(error) => {
                        return CollectionReport {
                            failures: vec![CollectionFailure {
                                url: url.to_string(),
                                error,
                                attempts,
                            }],
                            ..CollectionReport::default()
                        };
                    }
                };

                let now = ctx.clock.now();
                let mut bridges = Vec::with_capacity(parsed.bridges.len());
                for mut bridge in parsed.bridges {
                    bridge.add_source(self.id.as_str());
                    bridges.push(CollectedBridge {
                        bridge,
                        source: self.id.clone(),
                        collected_at: now,
                    });
                }

                let mut failures = Vec::with_capacity(parsed.rejected.len());
                for rejected in parsed.rejected {
                    ctx.metrics.increment("tbc_sources_rejected_lines_total", 1);
                    tracing::warn!(
                        source = %self.id.as_str(),
                        url = %url,
                        ordinal = rejected.ordinal,
                        reason = %rejected.reason,
                        "rejected bridge line (skip-and-record)"
                    );
                    failures.push(CollectionFailure {
                        url: url.to_string(),
                        error: SourceError::Parse(rejected.reason),
                        attempts,
                    });
                }

                CollectionReport { bridges, failures }
            }
        }
    }
}

impl Source for HttpSource {
    fn id(&self) -> &SourceId {
        &self.id
    }

    fn collect<'a>(
        &'a self,
        ctx: &'a SourceContext,
    ) -> BoxFuture<'a, Result<CollectionReport, SourceError>> {
        Box::pin(async move {
            let mut report = CollectionReport::default();
            for url in &self.urls {
                let url_report = self.collect_url(ctx, url).await;
                report.bridges.extend(url_report.bridges);
                report.failures.extend(url_report.failures);
            }
            ctx.metrics.increment(
                "tbc_sources_collected_bridges_total",
                report.bridges.len() as u64,
            );
            ctx.metrics.increment(
                "tbc_sources_collection_failures_total",
                report.failures.len() as u64,
            );
            Ok(report)
        })
    }
}
