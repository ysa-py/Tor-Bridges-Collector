//! HTTP transport abstraction.
//!
//! [`HttpTransport`] is the seam between collector logic and the network.
//! [`ReqwestTransport`] is the production implementation (TLS via rustls,
//! configurable timeout and user agent); tests substitute an in-memory
//! transport so the cache/breaker/rate-limit logic is exercised without any
//! outbound traffic. [`HttpClient`] sits above the transport and adds
//! conditional-GET caching and status classification.

use std::sync::Arc;

use reqwest::header::{
    HeaderMap, HeaderValue, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use url::Url;

use crate::cache::ConditionalCache;
use crate::error::SourceError;
use crate::BoxFuture;

/// A single HTTP request to a collector endpoint.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The target URL.
    pub url: Url,
    /// Request headers (conditional-GET validators, user agent, etc.).
    pub headers: HeaderMap,
}

/// A single HTTP response from a collector endpoint.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// An asynchronous HTTP transport.
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    /// Execute `request` and return the response.
    fn send<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, SourceError>>;
}

/// Production HTTP transport backed by `reqwest`.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with the given per-request timeout and user agent.
    pub fn new(timeout: std::time::Duration, user_agent: &str) -> Result<Self, SourceError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
            .map_err(|error| {
                SourceError::Config(format!("failed to build HTTP client: {error}"))
            })?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, SourceError>> {
        Box::pin(async move {
            let built = self
                .client
                .get(request.url.clone())
                .headers(request.headers.clone())
                .build()
                .map_err(|error| SourceError::Transport {
                    url: request.url.to_string(),
                    message: error.to_string(),
                })?;

            let response =
                self.client
                    .execute(built)
                    .await
                    .map_err(|error| SourceError::Transport {
                        url: request.url.to_string(),
                        message: error.to_string(),
                    })?;

            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .map_err(|error| SourceError::Transport {
                    url: request.url.to_string(),
                    message: error.to_string(),
                })?
                .to_vec();

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// The outcome of a cached fetch.
#[derive(Debug, Clone)]
pub enum FetchOutcome {
    /// The server returned a fresh body.
    Success {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    /// The server returned `304 Not Modified`; cached validators are current.
    NotModified,
}

/// Caching HTTP client used by all collectors.
#[derive(Debug, Clone)]
pub struct HttpClient {
    transport: Arc<dyn HttpTransport>,
    cache: Arc<ConditionalCache>,
}

impl HttpClient {
    /// Wrap a transport with a shared conditional cache.
    pub fn new(transport: Arc<dyn HttpTransport>, cache: Arc<ConditionalCache>) -> Self {
        Self { transport, cache }
    }

    /// Fetch `url`, replaying cached validators and updating them on success.
    pub async fn get(&self, url: &Url) -> Result<FetchOutcome, SourceError> {
        let key = url.to_string();

        let mut headers = HeaderMap::new();
        if let Some(entry) = self.cache.get(&key) {
            if let Some(etag) = entry.etag {
                let value = HeaderValue::from_str(&etag)
                    .map_err(|error| SourceError::Header(error.to_string()))?;
                headers.insert(IF_NONE_MATCH, value);
            }
            if let Some(last_modified) = entry.last_modified {
                let value = HeaderValue::from_str(&last_modified)
                    .map_err(|error| SourceError::Header(error.to_string()))?;
                headers.insert(IF_MODIFIED_SINCE, value);
            }
        }

        let response = self
            .transport
            .send(&HttpRequest {
                url: url.clone(),
                headers,
            })
            .await?;

        match response.status {
            304 => Ok(FetchOutcome::NotModified),
            429 => Err(SourceError::RateLimited { url: key }),
            status if status >= 500 => Err(SourceError::Http { url: key, status }),
            status if (200..300).contains(&status) => {
                let etag = header_string(&response.headers, ETAG);
                let last_modified = header_string(&response.headers, LAST_MODIFIED);
                self.cache.store(&key, etag.clone(), last_modified.clone());
                Ok(FetchOutcome::Success {
                    body: response.body,
                    etag,
                    last_modified,
                })
            }
            status => Err(SourceError::Http { url: key, status }),
        }
    }
}

/// Read a header as a lossy UTF-8 string, if present and valid.
fn header_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
