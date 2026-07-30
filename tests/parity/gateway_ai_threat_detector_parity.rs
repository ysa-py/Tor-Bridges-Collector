// Live-Python differential parity test for
// `torshield_ai_gateway/ai_threat_detector.py` vs its Rust port.
//
// Identical observation sequences are replayed through the real Python detector
// and the Rust port; the deterministic outputs (threat level, raw confidence,
// observation count, per-provider baseline latencies) are asserted equal. The
// time-dependent `last_assessment_age_s` and stored `timestamp` are excluded.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::ai_threat_detector::AIThreatDetector;

// One observation: [provider, latency_ms, success, http_status|null, error|null]
type Obs<'a> = (&'a str, f64, bool, Option<i64>, Option<&'a str>);

fn py_replay(window: usize, obs: &[Obs]) -> Value {
    let obs_json: Vec<Value> = obs
        .iter()
        .map(|(p, lat, ok, st, err)| json!([p, lat, ok, st, err]))
        .collect();
    let script = r#"
import json, sys
from torshield_ai_gateway.ai_threat_detector import AIThreatDetector
window = int(sys.argv[1])
obs = json.loads(sys.argv[2])
d = AIThreatDetector(window_size=window)
for provider, latency, success, status, err in obs:
    d.record(provider, latency, success, http_status=status, error_type=err)
print(json.dumps({
    "threat_level": d.threat_level.value,
    "confidence": d.confidence,
    "observation_count": len(d._observations),
    "baseline_latencies": d._baseline_latency,
}, sort_keys=True, separators=(",", ":")))
"#;
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .arg(window.to_string())
        .arg(serde_json::to_string(&obs_json).expect("serialize observations"))
        .output()
        .expect("python parity oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python oracle must emit JSON")
}

fn rust_replay(window: usize, obs: &[Obs]) -> Value {
    let mut d = AIThreatDetector::new(window);
    for (p, lat, ok, st, err) in obs {
        d.record(p, *lat, *ok, *st, *err);
    }
    json!({
        "threat_level": d.threat_level().value(),
        "confidence": d.confidence(),
        "observation_count": d.observation_count(),
        "baseline_latencies": d.baseline_latencies(),
    })
}

fn assert_parity(window: usize, obs: &[Obs], label: &str) {
    let py = py_replay(window, obs);
    let rust = rust_replay(window, obs);
    assert_eq!(
        py["threat_level"], rust["threat_level"],
        "threat_level [{label}]"
    );
    assert_eq!(py["confidence"], rust["confidence"], "confidence [{label}]");
    assert_eq!(
        py["observation_count"], rust["observation_count"],
        "observation_count [{label}]"
    );
    assert_eq!(
        py["baseline_latencies"], rust["baseline_latencies"],
        "baseline_latencies [{label}]"
    );
}

#[test]
fn parity_all_healthy() {
    let obs: Vec<Obs> = vec![
        ("cloudflare-1", 100.0, true, Some(200), None),
        ("cerebras", 120.0, true, Some(200), None),
        ("portkey", 110.0, true, Some(200), None),
    ];
    assert_parity(20, &obs, "all_healthy");
}

#[test]
fn parity_asymmetric_with_timeouts() {
    let obs: Vec<Obs> = vec![
        ("cloudflare-1", 100.0, true, Some(200), None),
        ("cloudflare-2", 95.0, true, Some(200), None),
        ("cerebras", 0.0, false, None, Some("ReadTimeout")),
        ("portkey", 0.0, false, None, Some("Connection timeout")),
    ];
    assert_parity(20, &obs, "asymmetric_timeouts");
}

#[test]
fn parity_latency_spikes_and_dns() {
    let obs: Vec<Obs> = vec![
        ("cloudflare-1", 100.0, true, Some(200), None),
        ("cloudflare-1", 100.0, true, Some(200), None),
        ("cloudflare-1", 5000.0, true, Some(200), None),
        ("cerebras", 90.0, false, None, Some("DNS lookup failed")),
        ("portkey", 90.0, false, None, Some("dns error")),
    ];
    assert_parity(20, &obs, "latency_dns");
}

#[test]
fn parity_window_eviction() {
    let mut obs: Vec<Obs> = Vec::new();
    for i in 0..12 {
        let provider = if i % 2 == 0 {
            "cloudflare-1"
        } else {
            "cerebras"
        };
        let success = i % 3 != 0;
        obs.push((provider, 100.0 + i as f64 * 10.0, success, Some(200), None));
    }
    assert_parity(5, &obs, "window_eviction");
}

#[test]
fn parity_critical_scenario() {
    let obs: Vec<Obs> = vec![
        ("cloudflare-1", 100.0, true, Some(200), None),
        ("cloudflare-2", 100.0, true, Some(200), None),
        ("cloudflare-3", 100.0, true, Some(200), None),
        ("cerebras", 0.0, false, None, Some("timeout")),
        ("portkey", 0.0, false, None, Some("timeout")),
        ("cerebras", 0.0, false, None, Some("dns failure")),
    ];
    assert_parity(20, &obs, "critical");
}
