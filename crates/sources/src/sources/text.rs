//! Thin, configured [`HttpSource`]s for plain-text and JSON bridge lists.

use url::Url;

use crate::error::SourceError;
use crate::provenance::SourceId;
use crate::source::{BodyFormat, CollectionReport, HttpSource, Source, SourceContext};
use crate::BoxFuture;

/// Parse a list of URL strings, rejecting malformed entries with the URL text.
pub(crate) fn parse_urls(urls: Vec<String>) -> Result<Vec<Url>, SourceError> {
    urls.into_iter()
        .map(|raw| Url::parse(&raw).map_err(|_| SourceError::InvalidUrl(raw)))
        .collect()
}

/// A collector for HTTPS endpoints that serve newline-delimited bridge lines.
pub struct BridgeLineTextSource {
    inner: HttpSource,
}

impl BridgeLineTextSource {
    /// Build a text source over `urls`.
    pub fn new(id: impl Into<String>, urls: Vec<String>) -> Result<Self, SourceError> {
        let id = SourceId::new(id)?;
        let urls = parse_urls(urls)?;
        Ok(Self {
            inner: HttpSource::new(id, urls, BodyFormat::Text)?,
        })
    }

    /// Override the retry policy.
    pub fn with_retry(mut self, max_attempts: u32, backoff: crate::Backoff) -> Self {
        self.inner = self.inner.with_retry(max_attempts, backoff);
        self
    }
}

impl Source for BridgeLineTextSource {
    fn id(&self) -> &SourceId {
        self.inner.id()
    }

    fn collect<'a>(
        &'a self,
        ctx: &'a SourceContext,
    ) -> BoxFuture<'a, Result<CollectionReport, SourceError>> {
        self.inner.collect(ctx)
    }
}

/// A collector for HTTPS endpoints that serve a JSON bridge list.
pub struct BridgeLineJsonSource {
    inner: HttpSource,
}

impl BridgeLineJsonSource {
    /// Build a JSON source over `urls`.
    pub fn new(id: impl Into<String>, urls: Vec<String>) -> Result<Self, SourceError> {
        let id = SourceId::new(id)?;
        let urls = parse_urls(urls)?;
        Ok(Self {
            inner: HttpSource::new(id, urls, BodyFormat::Json)?,
        })
    }

    /// Override the retry policy.
    pub fn with_retry(mut self, max_attempts: u32, backoff: crate::Backoff) -> Self {
        self.inner = self.inner.with_retry(max_attempts, backoff);
        self
    }
}

impl Source for BridgeLineJsonSource {
    fn id(&self) -> &SourceId {
        self.inner.id()
    }

    fn collect<'a>(
        &'a self,
        ctx: &'a SourceContext,
    ) -> BoxFuture<'a, Result<CollectionReport, SourceError>> {
        self.inner.collect(ctx)
    }
}
