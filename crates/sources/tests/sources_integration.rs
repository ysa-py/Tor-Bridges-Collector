//! Integration tests for `tbc-sources`.
//!
//! These tests exercise the full collector path (limiter → circuit breaker →
//! conditional cache → retry → parse → provenance) against an in-memory
//! [`MockTransport`]. The mock is a test fixture: it does not make network
//! requests and is never presented as real network data.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, IF_NONE_MATCH};
use tbc_core::{Clock, Metrics, TestClock};
use tbc_sources::{
    Backoff, BreakerRegistry, BridgeLineJsonSource, BridgeLineTextSource, CircuitBreakerConfig,
    ConditionalCache, GithubContentsSource, HttpClient, HttpRequest, HttpResponse, HttpTransport,
    Source, SourceContext, TokenBucket,
};

/// One scripted response for a URL.
#[derive(Debug)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }

    fn ok_with_etag(body: &str, etag: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("etag".to_string(), etag.to_string())],
            body: body.as_bytes().to_vec(),
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }
}

/// An in-memory transport with a scripted queue of responses per URL.
#[derive(Debug)]
struct MockTransport {
    routes: Mutex<HashMap<String, VecDeque<MockResponse>>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl MockTransport {
    fn new(routes: HashMap<String, VecDeque<MockResponse>>) -> Self {
        Self {
            routes: Mutex::new(routes),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn recorded_requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for MockTransport {
    fn send<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> tbc_sources::BoxFuture<'a, Result<HttpResponse, tbc_sources::SourceError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request.clone());
            let key = request.url.to_string();
            let mut routes = self.routes.lock().unwrap();
            let queue =
                routes
                    .get_mut(&key)
                    .ok_or_else(|| tbc_sources::SourceError::Transport {
                        url: key.clone(),
                        message: "no mock route".into(),
                    })?;
            // Once the scripted responses are exhausted, answer 503 so a
            // circuit-breaker test can observe an unambiguously failing host.
            let response = queue
                .pop_front()
                .unwrap_or_else(|| MockResponse::status(503));

            let mut headers = HeaderMap::new();
            for (name, value) in response.headers {
                let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
                let value = HeaderValue::from_str(&value).unwrap();
                headers.insert(name, value);
            }
            Ok(HttpResponse {
                status: response.status,
                headers,
                body: response.body,
            })
        })
    }
}

fn test_clock() -> Arc<dyn Clock> {
    let start = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    Arc::new(TestClock::new(start))
}

fn make_ctx(transport: Arc<dyn HttpTransport>) -> SourceContext {
    let clock = test_clock();
    let cache = Arc::new(ConditionalCache::new());
    let http = HttpClient::new(transport, cache);
    let limiter = Arc::new(TokenBucket::new(1000.0, 1000.0, clock.clone()).unwrap());
    let breakers = Arc::new(BreakerRegistry::new(
        CircuitBreakerConfig::default(),
        clock.clone(),
    ));
    let metrics = Arc::new(Metrics::new());
    SourceContext::new(http, limiter, breakers, clock, metrics)
}

const VALID_OBFS4: &str =
    "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg== iat-mode=0";
const VALID_OBFS4_B: &str =
    "obfs4 192.0.2.2:8443 1123456789ABCDEF0123456789ABCDEF01234567 cert=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg== iat-mode=0";

#[tokio::test]
async fn text_source_collects_and_attaches_provenance() {
    let mut routes = HashMap::new();
    routes.insert(
        "https://example.invalid/list.txt".to_string(),
        VecDeque::from([MockResponse::ok(&format!("# comment\n{VALID_OBFS4}\n"))]),
    );
    let mock = Arc::new(MockTransport::new(routes));
    let transport: Arc<dyn HttpTransport> = mock.clone();
    let ctx = make_ctx(transport.clone());

    let source = BridgeLineTextSource::new(
        "github:test/list",
        vec!["https://example.invalid/list.txt".to_string()],
    )
    .unwrap()
    .with_retry(1, Backoff::default());

    let report = source.collect(&ctx).await.unwrap();
    assert_eq!(report.bridges.len(), 1);
    assert_eq!(report.failures.len(), 0);
    let collected = &report.bridges[0];
    assert_eq!(collected.source.as_str(), "github:test/list");
    assert!(collected.bridge.sources.contains("github:test/list"));
    assert_eq!(collected.collected_at, ctx.clock.now());
    assert_eq!(collected.bridge.transport.to_string(), "obfs4");
}

#[tokio::test]
async fn etag_replay_yields_not_modified_and_no_duplicates() {
    let mut routes = HashMap::new();
    routes.insert(
        "https://example.invalid/list.txt".to_string(),
        VecDeque::from([
            MockResponse::ok_with_etag(VALID_OBFS4, "\"v1\""),
            MockResponse::status(304),
        ]),
    );
    let mock = Arc::new(MockTransport::new(routes));
    let transport: Arc<dyn HttpTransport> = mock.clone();
    let ctx = make_ctx(transport.clone());

    let source =
        BridgeLineTextSource::new("t", vec!["https://example.invalid/list.txt".to_string()])
            .unwrap()
            .with_retry(1, Backoff::default());

    let first = source.collect(&ctx).await.unwrap();
    assert_eq!(first.bridges.len(), 1);

    let second = source.collect(&ctx).await.unwrap();
    assert_eq!(second.bridges.len(), 0);
    assert_eq!(second.failures.len(), 0);

    let requests = mock.recorded_requests();
    assert_eq!(requests.len(), 2);
    let replay = requests[1]
        .headers
        .get(IF_NONE_MATCH)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(replay, "\"v1\"");
}

#[tokio::test]
async fn json_source_parses_objects_and_records_rejections() {
    let body = format!(
        "{{\"bridges\": [{{\"line\": \"{VALID_OBFS4}\"}}, {{\"raw\": \"not-a-bridge\"}}]}}"
    );
    let mut routes = HashMap::new();
    routes.insert(
        "https://example.invalid/list.json".to_string(),
        VecDeque::from([MockResponse::ok(&body)]),
    );
    let transport: Arc<dyn HttpTransport> = Arc::new(MockTransport::new(routes));
    let ctx = make_ctx(transport);

    let source = BridgeLineJsonSource::new(
        "json:test",
        vec!["https://example.invalid/list.json".to_string()],
    )
    .unwrap()
    .with_retry(1, Backoff::default());

    let report = source.collect(&ctx).await.unwrap();
    assert_eq!(report.bridges.len(), 1);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].attempts, 1);
}

#[tokio::test]
async fn circuit_breaker_opens_after_consecutive_failures() {
    let mut routes = HashMap::new();
    routes.insert(
        "https://flaky.invalid/list.txt".to_string(),
        VecDeque::from([
            MockResponse::status(500),
            MockResponse::status(500),
            MockResponse::status(500),
            MockResponse::status(500),
            MockResponse::status(500),
        ]),
    );
    let mock = Arc::new(MockTransport::new(routes));
    let transport: Arc<dyn HttpTransport> = mock.clone();
    let ctx = make_ctx(transport.clone());

    let source =
        BridgeLineTextSource::new("flaky", vec!["https://flaky.invalid/list.txt".to_string()])
            .unwrap()
            .with_retry(1, Backoff::default());

    for _ in 0..5 {
        let report = source.collect(&ctx).await.unwrap();
        assert_eq!(report.bridges.len(), 0);
        assert_eq!(report.failures.len(), 1);
    }

    // The sixth collection is refused by the open breaker without an HTTP call.
    let sixth = source.collect(&ctx).await.unwrap();
    assert_eq!(sixth.bridges.len(), 0);
    assert_eq!(sixth.failures.len(), 1);
    assert_eq!(sixth.failures[0].attempts, 0);
    assert!(matches!(
        sixth.failures[0].error,
        tbc_sources::SourceError::CircuitOpen { .. }
    ));

    let requests = mock.recorded_requests();
    assert_eq!(requests.len(), 5);
}

#[tokio::test]
async fn github_contents_source_lists_and_collects_files() {
    let listing = "[{\"type\": \"file\", \"name\": \"a.txt\", \"download_url\": \"https://raw.example.invalid/a.txt\"},\
                   {\"type\": \"file\", \"name\": \"b.json\", \"download_url\": \"https://raw.example.invalid/b.json\"},\
                   {\"type\": \"dir\", \"name\": \"skipme\"}]";
    let mut routes = HashMap::new();
    routes.insert(
        "https://api.github.com/repos/o/r/contents/".to_string(),
        VecDeque::from([MockResponse::ok(listing)]),
    );
    routes.insert(
        "https://raw.example.invalid/a.txt".to_string(),
        VecDeque::from([MockResponse::ok(VALID_OBFS4)]),
    );
    routes.insert(
        "https://raw.example.invalid/b.json".to_string(),
        VecDeque::from([MockResponse::ok(&format!("[\"{VALID_OBFS4_B}\"]"))]),
    );
    let transport: Arc<dyn HttpTransport> = Arc::new(MockTransport::new(routes));
    let ctx = make_ctx(transport);

    let source = GithubContentsSource::new("github:o/r", "o", "r", "")
        .unwrap()
        .with_api_base("https://api.github.com/")
        .unwrap()
        .with_retry(1, Backoff::default());

    let report = source.collect(&ctx).await.unwrap();
    assert_eq!(report.bridges.len(), 2);
    assert!(report
        .bridges
        .iter()
        .all(|b| b.source.as_str() == "github:o/r"));
    assert!(report.bridges.iter().any(|b| b.bridge.port == 443));
    assert!(report.bridges.iter().any(|b| b.bridge.port == 8443));
}
