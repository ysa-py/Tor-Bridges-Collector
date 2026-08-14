//! HTTP transport abstraction for the vantage adapters.
//!
//! [`HttpTransport`] is the seam between the adapters and the network.
//! [`ReqwestTransport`] is the production implementation (TLS via rustls,
//! configurable timeout and user agent); tests substitute an in-memory
//! transport so request building, response parsing, and quota accounting are
//! exercised without any outbound traffic.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::error::VantageError;
use crate::BoxFuture;

/// HTTP method for a vantage request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// A single HTTP request to a platform endpoint.
#[derive(Debug, Clone)]
pub struct VantageRequest {
    /// The HTTP method.
    pub method: Method,
    /// The target URL.
    pub url: String,
    /// Ordered headers (names are validated at the transport).
    pub headers: Vec<(String, String)>,
    /// The request body, if any.
    pub body: Option<Vec<u8>>,
}

/// A single HTTP response from a platform endpoint.
#[derive(Debug, Clone)]
pub struct VantageResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// An asynchronous HTTP transport.
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    /// Execute `request` and return the response.
    fn send<'a>(
        &'a self,
        request: &'a VantageRequest,
    ) -> BoxFuture<'a, Result<VantageResponse, VantageError>>;
}

/// Production HTTP transport backed by `reqwest`.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with the given per-request timeout and user agent.
    pub fn new(timeout: Duration, user_agent: &str) -> Result<Self, VantageError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
            .map_err(|error| {
                VantageError::Config(format!("failed to build HTTP client: {error}"))
            })?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send<'a>(
        &'a self,
        request: &'a VantageRequest,
    ) -> BoxFuture<'a, Result<VantageResponse, VantageError>> {
        Box::pin(async move {
            let headers = build_headers(&request.headers, &request.url)?;
            let built = match request.method {
                Method::Get => self.client.get(&request.url).headers(headers).build(),
                Method::Post => self
                    .client
                    .post(&request.url)
                    .headers(headers)
                    .body(request.body.clone().unwrap_or_default())
                    .build(),
            }
            .map_err(|error| VantageError::Transport {
                url: request.url.clone(),
                message: error.to_string(),
            })?;

            let response =
                self.client
                    .execute(built)
                    .await
                    .map_err(|error| VantageError::Transport {
                        url: request.url.clone(),
                        message: error.to_string(),
                    })?;

            let status = response.status().as_u16();
            let body = response
                .bytes()
                .await
                .map_err(|error| VantageError::Transport {
                    url: request.url.clone(),
                    message: error.to_string(),
                })?
                .to_vec();

            Ok(VantageResponse { status, body })
        })
    }
}

/// Build a `reqwest` header map from ordered name/value pairs, mapping any
/// invalid header to a [`VantageError`] instead of panicking.
fn build_headers(pairs: &[(String, String)], url: &str) -> Result<HeaderMap, VantageError> {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| VantageError::Transport {
                url: url.to_owned(),
                message: format!("invalid header name {name:?}: {error}"),
            })?;
        let value = HeaderValue::from_str(value).map_err(|error| VantageError::Transport {
            url: url.to_owned(),
            message: format!("invalid header value for {name}: {error}"),
        })?;
        headers.insert(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_headers_accepts_valid_pairs() {
        let headers = build_headers(
            &[
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Authorization".to_owned(), "Key abc".to_owned()),
            ],
            "https://example.test/",
        )
        .unwrap();
        assert_eq!(
            headers.get("content-type").unwrap().to_str().unwrap(),
            "application/json"
        );
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Key abc"
        );
    }

    #[test]
    fn build_headers_rejects_invalid_name() {
        let error = build_headers(
            &[("Bad Header".to_owned(), "value".to_owned())],
            "https://example.test/",
        )
        .unwrap_err();
        assert_eq!(error.kind_name(), "transport_error");
    }

    #[test]
    fn build_headers_rejects_invalid_value() {
        let error = build_headers(
            &[("X-Test".to_owned(), "bad\nvalue".to_owned())],
            "https://example.test/",
        )
        .unwrap_err();
        assert_eq!(error.kind_name(), "transport_error");
    }

    #[test]
    fn reqwest_transport_rejects_invalid_user_agent() {
        let error = ReqwestTransport::new(Duration::from_secs(5), "bad\nagent").unwrap_err();
        assert_eq!(error.kind_name(), "config_error");
    }

    #[test]
    fn reqwest_transport_builds_with_valid_config() {
        let _transport =
            ReqwestTransport::new(Duration::from_secs(5), "tbc-vantage/0.1.0").unwrap();
    }
}
