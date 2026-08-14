//! GitHub contents source.
//!
//! Enumerates bridge-list files (`.txt` / `.json`) under a public repository
//! directory through the GitHub `contents` API, then collects each file's
//! raw `download_url` through the same limiter / breaker / cache / retry
//! stack. Rate limiting is handled by the shared 429 → backoff path, so the
//! source never hammers the API.

use url::Url;

use crate::backoff::Backoff;
use crate::error::SourceError;
use crate::provenance::SourceId;
use crate::source::{
    fetch_guarded, BodyFormat, CollectionFailure, CollectionReport, GuardedFetch, HttpSource,
    Source, SourceContext,
};
use crate::BoxFuture;

/// One bridge-list file discovered in a repository directory.
struct ListedFile {
    name: String,
    download_url: String,
}

/// Parse a GitHub `contents` JSON array into bridge-list files.
fn parse_listing(body: &str) -> Result<Vec<ListedFile>, SourceError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| SourceError::Parse(error.to_string()))?;
    let items = value
        .as_array()
        .ok_or_else(|| SourceError::Parse("GitHub contents response is not a JSON array".into()))?;

    let mut files = Vec::new();
    for item in items {
        let object = match item.as_object() {
            Some(object) => object,
            None => continue,
        };
        let kind = object.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "file" {
            continue;
        }
        let name = match object.get("name").and_then(|v| v.as_str()) {
            Some(name) => name.to_owned(),
            None => continue,
        };
        let download_url = match object.get("download_url").and_then(|v| v.as_str()) {
            Some(url) => url.to_owned(),
            None => continue,
        };
        if name.ends_with(".txt") || name.ends_with(".json") {
            files.push(ListedFile { name, download_url });
        }
    }
    Ok(files)
}

/// A collector that enumerates bridge lists in a public GitHub repository.
pub struct GithubContentsSource {
    id: SourceId,
    owner: String,
    repo: String,
    path: String,
    api_base: Url,
    max_attempts: u32,
    backoff: Backoff,
}

impl GithubContentsSource {
    /// Build a source for `owner/repo` at directory `path` (use `""` for the
    /// repository root).
    pub fn new(
        id: impl Into<String>,
        owner: impl Into<String>,
        repo: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, SourceError> {
        let id = SourceId::new(id)?;
        let owner = owner.into();
        let repo = repo.into();
        if owner.is_empty() || repo.is_empty() {
            return Err(SourceError::Config(
                "GitHub owner and repo must both be non-empty".into(),
            ));
        }
        let api_base = Url::parse("https://api.github.com/")
            .map_err(|error| SourceError::InvalidUrl(error.to_string()))?;
        Ok(Self {
            id,
            owner,
            repo,
            path: path.into(),
            api_base,
            max_attempts: 3,
            backoff: Backoff::default(),
        })
    }

    /// Override the API base URL (for self-hosted GitHub or tests).
    pub fn with_api_base(mut self, base: &str) -> Result<Self, SourceError> {
        self.api_base = Url::parse(base).map_err(|_| SourceError::InvalidUrl(base.to_owned()))?;
        Ok(self)
    }

    /// Override the retry policy.
    pub fn with_retry(mut self, max_attempts: u32, backoff: Backoff) -> Self {
        self.max_attempts = max_attempts.max(1);
        self.backoff = backoff;
        self
    }

    fn listing_url(&self) -> Result<Url, SourceError> {
        let relative = format!(
            "repos/{}/{}/contents/{}",
            self.owner,
            self.repo,
            self.path.trim_start_matches('/')
        );
        self.api_base
            .join(&relative)
            .map_err(|error| SourceError::InvalidUrl(error.to_string()))
    }

    async fn collect_file_group(
        &self,
        ctx: &SourceContext,
        format: BodyFormat,
        urls: Vec<Url>,
    ) -> CollectionReport {
        let source = match HttpSource::new(self.id.clone(), urls, format) {
            Ok(source) => source.with_retry(self.max_attempts, self.backoff.clone()),
            Err(error) => {
                return CollectionReport {
                    failures: vec![CollectionFailure {
                        url: String::new(),
                        error,
                        attempts: 0,
                    }],
                    ..CollectionReport::default()
                };
            }
        };
        match source.collect(ctx).await {
            Ok(report) => report,
            Err(error) => CollectionReport {
                failures: vec![CollectionFailure {
                    url: String::new(),
                    error,
                    attempts: 0,
                }],
                ..CollectionReport::default()
            },
        }
    }
}

impl Source for GithubContentsSource {
    fn id(&self) -> &SourceId {
        &self.id
    }

    fn collect<'a>(
        &'a self,
        ctx: &'a SourceContext,
    ) -> BoxFuture<'a, Result<CollectionReport, SourceError>> {
        Box::pin(async move {
            let listing_url = self.listing_url()?;

            let body =
                match fetch_guarded(ctx, &listing_url, self.max_attempts, self.backoff.clone())
                    .await
                {
                    GuardedFetch::Body(body, _) => body,
                    GuardedFetch::NotModified => return Ok(CollectionReport::default()),
                    GuardedFetch::Failed(error, attempts) => {
                        return Ok(CollectionReport {
                            failures: vec![CollectionFailure {
                                url: listing_url.to_string(),
                                error,
                                attempts,
                            }],
                            ..CollectionReport::default()
                        });
                    }
                };

            let body_str = match std::str::from_utf8(&body) {
                Ok(text) => text,
                Err(error) => {
                    return Ok(CollectionReport {
                        failures: vec![CollectionFailure {
                            url: listing_url.to_string(),
                            error: SourceError::Parse(format!(
                                "listing is not valid UTF-8: {error}"
                            )),
                            attempts: 0,
                        }],
                        ..CollectionReport::default()
                    });
                }
            };

            let files = match parse_listing(body_str) {
                Ok(files) => files,
                Err(error) => {
                    return Ok(CollectionReport {
                        failures: vec![CollectionFailure {
                            url: listing_url.to_string(),
                            error,
                            attempts: 0,
                        }],
                        ..CollectionReport::default()
                    });
                }
            };

            let mut text_urls = Vec::new();
            let mut json_urls = Vec::new();
            for file in files {
                match Url::parse(&file.download_url) {
                    Ok(url) => {
                        if file.name.ends_with(".json") {
                            json_urls.push(url);
                        } else {
                            text_urls.push(url);
                        }
                    }
                    Err(error) => {
                        ctx.metrics
                            .increment("tbc_sources_invalid_download_url_total", 1);
                        tracing::warn!(
                            source = %self.id.as_str(),
                            url = %file.download_url,
                            "skipping file with unparsable download_url: {error}"
                        );
                    }
                }
            }

            let mut report = CollectionReport::default();
            if !text_urls.is_empty() {
                let text_report = self
                    .collect_file_group(ctx, BodyFormat::Text, text_urls)
                    .await;
                report.bridges.extend(text_report.bridges);
                report.failures.extend(text_report.failures);
            }
            if !json_urls.is_empty() {
                let json_report = self
                    .collect_file_group(ctx, BodyFormat::Json, json_urls)
                    .await;
                report.bridges.extend(json_report.bridges);
                report.failures.extend(json_report.failures);
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
