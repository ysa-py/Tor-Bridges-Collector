//! Shared helpers for the platform adapters: a status-classifying HTTP call
//! and JSON deserialization with platform context.

use serde::de::DeserializeOwned;

use crate::error::VantageError;
use crate::transport::{HttpTransport, VantageRequest, VantageResponse};

/// Execute one request and classify its HTTP status: `429` becomes
/// [`VantageError::RateLimited`], other non-2xx statuses become
/// [`VantageError::Http`], and 2xx responses pass through.
pub(crate) async fn call(
    http: &dyn HttpTransport,
    request: &VantageRequest,
) -> Result<VantageResponse, VantageError> {
    let url = request.url.clone();
    let response = http.send(request).await?;
    match response.status {
        429 => Err(VantageError::RateLimited { url }),
        status if (200..300).contains(&status) => Ok(response),
        status => Err(VantageError::Http { url, status }),
    }
}

/// Deserialize a response body as JSON, tagging failures with the platform.
pub(crate) fn parse_json<T: DeserializeOwned>(
    response: VantageResponse,
    platform: &'static str,
) -> Result<T, VantageError> {
    serde_json::from_slice(&response.body)
        .map_err(|error| VantageError::Parse(format!("{platform} response parse: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::transport::{Method, VantageRequest, VantageResponse};

    #[derive(Debug)]
    struct StubTransport(VantageResponse);

    impl HttpTransport for StubTransport {
        fn send<'a>(
            &'a self,
            _request: &'a VantageRequest,
        ) -> crate::BoxFuture<'a, Result<VantageResponse, VantageError>> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    fn get_request() -> VantageRequest {
        VantageRequest {
            method: Method::Get,
            url: "https://example.test/".to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[tokio::test]
    async fn call_passes_through_2xx_responses() {
        let transport = StubTransport(VantageResponse {
            status: 200,
            body: b"{}".to_vec(),
        });
        let response = call(&transport, &get_request()).await.unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn call_maps_429_to_rate_limited() {
        let transport = StubTransport(VantageResponse {
            status: 429,
            body: Vec::new(),
        });
        let error = call(&transport, &get_request()).await.unwrap_err();
        assert_eq!(error.kind_name(), "rate_limited");
    }

    #[tokio::test]
    async fn call_maps_other_non_2xx_to_http_error() {
        let transport = StubTransport(VantageResponse {
            status: 500,
            body: Vec::new(),
        });
        let error = call(&transport, &get_request()).await.unwrap_err();
        assert_eq!(error.kind_name(), "http_error");
    }

    #[test]
    fn parse_json_deserializes_valid_body() {
        let response = VantageResponse {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        };
        let parsed: serde_json::Value = parse_json(response, "test").unwrap();
        assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn parse_json_tags_invalid_body_as_parse_error() {
        let response = VantageResponse {
            status: 200,
            body: b"not json".to_vec(),
        };
        let error = parse_json::<serde_json::Value>(response, "test").unwrap_err();
        assert_eq!(error.kind_name(), "parse_error");
    }
}
