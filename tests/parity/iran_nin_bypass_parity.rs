// Differential parity tests for `src/iran_nin_bypass.rs` vs
// `iran_nin_bypass.py`.
//
// Covers the deterministic scoring/detection surface: `_nin_score` (the
// transport/ASN/port survivability blend, incl. the CDN-ASN and preferred-
// port tables) and `_detect_nextgen` (protocol pattern detection). The
// network functions (`_tcp_probe`, `detect_nin_status`, `_check_ech`, `run`)
// perform real socket/TLS I/O and are covered by in-crate mock-probe unit
// tests, not differentially.
//
// `_nin_score` is pure f64 arithmetic over identical IEEE-754 constants in
// both languages; parity is asserted to a 1e-9 tolerance (well below any
// meaningful score granularity) rather than by string formatting.

use std::process::Command;

use serde_json::json;
use torshield_ir_ultra::iran_nin_bypass::{detect_nextgen, nin_score};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("import json\nimport iran_nin_bypass as m\n{body}\n");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn parity_nin_score() {
    let records = vec![
        json!({"transport": "snowflake", "asn": "AS13335", "port": 443, "composite_score": 0.8}),
        json!({"transport": "webtunnel", "asn": "AS200000", "port": 2053, "composite_score": 0.6}),
        json!({"transport": "obfs4", "asn": "AS54113", "port": 8443, "composite_score": 0.5}),
        json!({"transport": "vanilla", "asn": "UNKNOWN", "port": 9001, "composite_score": 0.2}),
        json!({"transport": "meek_lite", "asn": "AS16509", "port": 80, "composite_score": 0.9}),
        json!({"transport": "obfs4", "port": 2083}), // missing asn/composite -> defaults
        json!({"transport": "unknown-thing", "asn": "AS15169", "port": 443, "composite_score": 1.0}),
        json!({"transport": "snowflake", "asn": "AS13335", "port": 443, "composite_score": 1.0}), // clamp to 1.0
        json!({"port": "443", "transport": "webtunnel"}), // string port coercion
        json!({}),                                        // all defaults
    ];
    for r in &records {
        let compact = serde_json::to_string(r).unwrap();
        let py: f64 = run_python(&format!(
            "print(repr(m._nin_score(json.loads(r'''{compact}'''))))"
        ))
        .parse()
        .unwrap();
        let rs = nin_score(r);
        assert!(
            (py - rs).abs() < 1e-9,
            "nin_score divergence for {r}: py={py} rs={rs}"
        );
    }
}

#[test]
fn parity_detect_nextgen() {
    let lines = [
        "hysteria2://abc@1.2.3.4:443",
        "hysteria://abc@1.2.3.4:443",
        "vless://uuid@host:443?security=reality", // both vless and reality present -> order matters
        "reality server 1.2.3.4",
        "vmess://base64blob",
        "trojan://pass@host:443",
        "ss://method:pass@host:8388",
        "obfs4 1.2.3.4:443 cert=abc", // no next-gen -> None
        "HYSTERIA2://UPPER@host",     // case-insensitive
        "plain vanilla line",
    ];
    for line in lines {
        let py = run_python(&format!(
            "r = m._detect_nextgen(r'''{line}'''); print('None' if r is None else r)"
        ));
        let rs = detect_nextgen(line).unwrap_or("None");
        assert_eq!(py, rs, "detect_nextgen for {line:?}");
    }
}
