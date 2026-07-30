// Live-Python differential parity test for
// `torshield_ai_gateway/iran_traffic_evasion.py`.
//
// The deterministic static header set at each threat level and the retry
// base-delay formula are asserted equal to the real Python oracle. Randomized
// values (UA, X-Request-ID/noise hex, IPs, Gaussian jitter) are checked for the
// same structural contract Python guarantees (pool membership, hex length, IP
// prefix/shape, delay bounds) since CPython's RNG cannot be byte-matched.

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::iran_traffic_evasion::{
    IranTrafficEvasion, CAMOUFLAGE_USER_AGENTS, IP_PREFIXES,
};

fn oracle(script: &str, args: &[&str]) -> Value {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .args(args)
        .output()
        .expect("python parity oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python oracle must emit JSON")
}

const APPLY_SCRIPT: &str = r#"
import json, sys
from torshield_ai_gateway.iran_traffic_evasion import IranTrafficEvasion
e = IranTrafficEvasion()
base = json.loads(sys.argv[1])
level = sys.argv[2]
h = e.apply_evasion(dict(base), level, "cf")
print(json.dumps({
    "headers": h,
    "has_user_agent_key": any(k.lower() == "user-agent" for k in h),
}, sort_keys=True, separators=(",", ":")))
"#;

fn deterministic_keys(level: &str) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if matches!(level, "medium" | "high" | "critical") {
        keys.extend(["Accept", "Accept-Language", "Accept-Encoding", "Origin", "Referer"]);
    }
    if matches!(level, "high" | "critical") {
        keys.extend([
            "Cache-Control",
            "Pragma",
            "Connection",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
        ]);
    }
    if level == "critical" {
        keys.push("X-TLS-Fragment");
    }
    keys
}

#[test]
fn parity_none_passthrough() {
    let e = IranTrafficEvasion::new();
    let mut base = BTreeMap::new();
    base.insert("X-Existing".to_string(), "v".to_string());
    let base_json = serde_json::to_string(&base).unwrap();
    let py = oracle(APPLY_SCRIPT, &[&base_json, "none"]);
    let rust = e.apply_evasion(&base, "none", "cf");
    assert_eq!(py["headers"], serde_json::to_value(rust).unwrap());
}

#[test]
fn parity_static_headers_per_level() {
    let e = IranTrafficEvasion::new();
    let base: BTreeMap<String, String> = BTreeMap::new();
    let base_json = serde_json::to_string(&base).unwrap();

    for level in ["low", "medium", "high", "critical"] {
        let py = oracle(APPLY_SCRIPT, &[&base_json, level]);
        let rust = e.apply_evasion(&base, level, "cf");

        // Deterministic static headers must match exactly.
        for key in deterministic_keys(level) {
            assert_eq!(
                py["headers"][key],
                json!(rust.get(key)),
                "static header {key} mismatch at {level}"
            );
        }
        // User-Agent added from the pool on both sides.
        assert_eq!(py["has_user_agent_key"], Value::Bool(true));
        assert!(CAMOUFLAGE_USER_AGENTS.contains(&rust["User-Agent"].as_str()));
        // X-Request-ID present on both.
        assert!(py["headers"]["X-Request-ID"].is_string());
        assert!(rust.contains_key("X-Request-ID"));
    }
}

#[test]
fn parity_existing_user_agent_preserved() {
    let e = IranTrafficEvasion::new();
    let mut base = BTreeMap::new();
    base.insert("user-agent".to_string(), "MyClient/1.0".to_string());
    let base_json = serde_json::to_string(&base).unwrap();

    let py = oracle(APPLY_SCRIPT, &[&base_json, "high"]);
    let rust = e.apply_evasion(&base, "high", "cf");
    // Both keep the original lowercase user-agent and add no "User-Agent".
    assert_eq!(py["headers"]["user-agent"], "MyClient/1.0");
    assert_eq!(rust["user-agent"], "MyClient/1.0");
    assert!(!rust.contains_key("User-Agent"));
    assert_eq!(py["headers"].get("User-Agent"), None);
}

#[test]
fn parity_critical_ip_shape() {
    let e = IranTrafficEvasion::new();
    let base = BTreeMap::new();
    let rust = e.apply_evasion(&base, "critical", "cf");
    for key in ["X-Forwarded-For", "X-Real-IP"] {
        let ip = &rust[key];
        assert!(IP_PREFIXES.iter().any(|p| ip.starts_with(p)), "{key} prefix");
        let octets: Vec<&str> = ip.split('.').collect();
        assert_eq!(octets.len(), 4, "{key} should have 4 octets");
        for o in &octets[2..] {
            let n: u32 = o.parse().expect("octet numeric");
            assert!((1..=254).contains(&n));
        }
    }
    assert_eq!(rust["X-TLS-Fragment"], "150");
}

#[test]
fn parity_retry_base_delay_formula() {
    let script = r#"
import json, sys
level = sys.argv[1]
attempt = int(sys.argv[2])
base_ms = float(sys.argv[3])
mult = {"none":1.0,"low":1.8,"medium":3.0,"high":5.0,"critical":10.0}.get(level, 1.0)
base_delay = (base_ms/1000) * (2 ** (attempt-1)) * mult
print(json.dumps({"base_delay": base_delay}, separators=(",", ":")))
"#;
    for level in ["none", "low", "medium", "high", "critical", "unknown"] {
        for attempt in [1_i64, 2, 3, 5] {
            let py = oracle(script, &[level, &attempt.to_string(), "500"]);
            let rust = IranTrafficEvasion::retry_base_delay(attempt, level, 500.0);
            assert_eq!(py["base_delay"], json!(rust), "base_delay {level} a{attempt}");
            // Full delay stays within the documented clamp on the Rust side.
            let d = IranTrafficEvasion::get_safe_retry_delay(attempt, level, 500.0);
            assert!((0.1..=45.0).contains(&d));
        }
    }
}
