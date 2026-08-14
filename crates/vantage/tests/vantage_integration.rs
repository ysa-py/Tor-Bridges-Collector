//! Integration tests for the vantage adapters.
//!
//! A scripted in-memory [`HttpTransport`] records every request and returns
//! canned responses, so the adapters' request building, response parsing, and
//! quota accounting are exercised end-to-end without any outbound traffic.
//! These fixtures are never presented as real platform measurements.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tbc_core::{ProbeKind, VantageKind, Verdict};
use tbc_vantage::{
    to_observation, AgentVantage, Budget, GlobalpingVantage, HttpTransport, MeasurementRequest,
    Method, OoniVantage, RipeAtlasVantage, Vantage, VantageRequest, VantageResponse,
};

#[derive(Clone, Debug)]
struct MockTransport {
    requests: Arc<Mutex<Vec<VantageRequest>>>,
    responses: Arc<Mutex<VecDeque<VantageResponse>>>,
}

impl MockTransport {
    fn new(responses: Vec<VantageResponse>) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into())),
        }
    }

    fn requests(&self) -> Vec<VantageRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for MockTransport {
    fn send<'a>(
        &'a self,
        request: &'a VantageRequest,
    ) -> tbc_vantage::BoxFuture<'a, Result<VantageResponse, tbc_vantage::VantageError>> {
        self.requests.lock().unwrap().push(request.clone());
        let response = self.responses.lock().unwrap().pop_front().ok_or_else(|| {
            tbc_vantage::VantageError::Config("mock transport exhausted".to_owned())
        });
        Box::pin(async move { response })
    }
}

fn json(status: u16, body: serde_json::Value) -> VantageResponse {
    VantageResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn request() -> MeasurementRequest {
    MeasurementRequest {
        target: "1.2.3.4".to_owned(),
        port: 443,
        probe_kind: ProbeKind::TcpConnect,
        country: None,
        asn: None,
    }
}

#[tokio::test]
async fn globalping_submits_polls_and_normalizes_reachable() {
    let transport = MockTransport::new(vec![
        json(202, serde_json::json!({ "id": "gp-1" })),
        json(
            200,
            serde_json::json!({
                "status": "finished",
                "results": [{
                    "result": {
                        "status": "finished",
                        "resolvedAddress": "1.2.3.4",
                        "rawOutput": "64 bytes from 1.2.3.4",
                        "timings": [{ "rtt": 12.5 }]
                    }
                }]
            }),
        ),
    ]);
    let adapter = GlobalpingVantage::new(
        "https://api.globalping.io/".to_owned(),
        Arc::new(transport.clone()),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(result.verdict, Verdict::Reachable);
    assert_eq!(result.rtt_ms, Some(13));
    assert_eq!(result.measurement_ref, "gp-1");
    // submit + one poll = two external calls.
    assert_eq!(budget.remaining(), 8);

    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, Method::Post);
    assert!(requests[0].url.ends_with("/v1/measurements"));
    assert_eq!(requests[1].method, Method::Get);
    assert!(requests[1].url.ends_with("/v1/measurements/gp-1"));
}

#[tokio::test]
async fn globalping_stops_when_quota_is_exhausted() {
    let transport = MockTransport::new(vec![json(202, serde_json::json!({ "id": "gp-2" }))]);
    let adapter = GlobalpingVantage::new(
        "https://api.globalping.io".to_owned(),
        Arc::new(transport),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(1);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "quota_exhausted");
}

#[tokio::test]
async fn globalping_maps_rate_limit_to_error() {
    let transport = MockTransport::new(vec![VantageResponse {
        status: 429,
        body: Vec::new(),
    }]);
    let adapter = GlobalpingVantage::new(
        "https://api.globalping.io".to_owned(),
        Arc::new(transport),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "rate_limited");
}

#[tokio::test]
async fn ripe_atlas_requires_an_api_key() {
    let transport = MockTransport::new(vec![]);
    let adapter = RipeAtlasVantage::new(
        "https://atlas.ripe.net".to_owned(),
        Arc::new(transport),
        None,
        "IR".to_owned(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "missing_api_key");
    assert_eq!(budget.remaining(), 10);
}

#[tokio::test]
async fn ripe_atlas_submits_with_auth_and_normalizes() {
    let transport = MockTransport::new(vec![
        json(200, serde_json::json!({ "measurements": [12345] })),
        json(
            200,
            serde_json::json!([{ "avg": 20.0, "rcvd": 3, "status": "done" }]),
        ),
    ]);
    let adapter = RipeAtlasVantage::new(
        "https://atlas.ripe.net".to_owned(),
        Arc::new(transport.clone()),
        Some("secret-key".to_owned()),
        "IR".to_owned(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(result.verdict, Verdict::Reachable);
    assert_eq!(result.rtt_ms, Some(20));
    assert_eq!(result.measurement_ref, "12345");

    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0]
        .headers
        .iter()
        .any(|(name, value)| name == "Authorization" && value == "Key secret-key"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_deref().unwrap()).unwrap();
    assert_eq!(body["definitions"][0]["type"], "ping");
    assert_eq!(body["probes"][0]["value"], "IR");
}

#[tokio::test]
async fn ooni_queries_open_data_and_normalizes_confirmed() {
    let transport = MockTransport::new(vec![json(
        200,
        serde_json::json!({
            "results": [{
                "confirmed": true,
                "anomaly": false,
                "test_name": "web_connectivity",
                "measurement_start_time": "2026-08-14T00:00:00Z",
                "report_id": "r-1"
            }]
        }),
    )]);
    let adapter = OoniVantage::new(
        "https://api.ooni.io".to_owned(),
        Arc::new(transport.clone()),
        "IR".to_owned(),
        10,
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert!(matches!(result.verdict, Verdict::Blocked { .. }));
    assert_eq!(result.error_class.as_deref(), Some("confirmed_blocked"));
    assert_eq!(result.measurement_ref, "r-1");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::Get);
    assert!(requests[0].url.contains("probe_cc=IR"));
    assert!(requests[0].url.contains("input=1.2.3.4"));
}

#[tokio::test]
async fn agent_posts_probe_and_maps_verdict() {
    let transport = MockTransport::new(vec![json(
        200,
        serde_json::json!({
            "verdict": "blocked",
            "evidence": "SYN drop",
            "measurement_ref": "agent-1"
        }),
    )]);
    let adapter = AgentVantage::new(
        "http://127.0.0.1:8080".to_owned(),
        Arc::new(transport.clone()),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(
        result.verdict,
        Verdict::Blocked {
            evidence: "SYN drop".to_owned()
        }
    );
    assert_eq!(result.measurement_ref, "agent-1");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::Post);
    assert!(requests[0].url.ends_with("/probe"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_deref().unwrap()).unwrap();
    assert_eq!(body["target"], "1.2.3.4");
    assert_eq!(body["port"], 443);
}

#[tokio::test]
async fn agent_result_maps_to_an_observation() {
    let transport = MockTransport::new(vec![json(
        200,
        serde_json::json!({ "verdict": "reachable", "rtt_ms": 64, "measurement_ref": "agent-2" }),
    )]);
    let adapter =
        AgentVantage::new("http://127.0.0.1:8080".to_owned(), Arc::new(transport)).unwrap();
    let mut budget = Budget::new(10);
    let result = adapter.run(&request(), &mut budget).await.unwrap();

    let vantage = tbc_core::Vantage {
        kind: VantageKind::VolunteerAgent,
        country: Some("IR".to_owned()),
        asn: Some(197_207),
        as_name: None,
        is_mobile: true,
    };
    let observation = to_observation(
        &result,
        "obfs4|1.2.3.4|443||",
        vantage.clone(),
        ProbeKind::TcpConnect,
    );
    assert_eq!(observation.verdict, Verdict::Reachable);
    assert_eq!(observation.vantage, vantage);
    assert_eq!(observation.measurement_ref.as_deref(), Some("agent-2"));
    assert_eq!(observation.rtt_ms, Some(64));
}
