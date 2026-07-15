// Parity tests for `src/nin_advanced_bypass.rs` vs `nin_advanced_bypass.py`.
//
// Each test invokes a fresh Python interpreter on the same input and
// asserts byte-identical JSON output from the Rust port. The TCP probe is
// mocked on both sides (Python: socket.create_connection is patched;
// Rust: an `AlwaysUnreachable`/`AlwaysReachable` TcpProbe is injected).

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::nin_advanced_bypass::{
    detect_transport, domain_in_nin_cdn, extract_endpoint, port_nin_open, score_for_nin,
    NIN_OPEN_PORTS, NIN_REACHABLE_CDNS,
};

struct AlwaysUnreachable;
impl torshield_ir_ultra::nin_advanced_bypass::TcpProbe for AlwaysUnreachable {
    fn is_reachable(&self, _: &str, _: u16, _: f64) -> bool {
        false
    }
}

struct AlwaysReachable;
impl torshield_ir_ultra::nin_advanced_bypass::TcpProbe for AlwaysReachable {
    fn is_reachable(&self, _: &str, _: u16, _: f64) -> bool {
        true
    }
}

fn python_executable() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return std::path::PathBuf::from(path);
    }
    for candidate in [
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    std::path::PathBuf::from("python")
}

fn python_score_for_nin(bridge_line: &str, reachable: bool) -> Value {
    let py_reachable = if reachable { "True" } else { "False" };
    let script = format!(
        r#"
import json, socket
from nin_advanced_bypass import score_for_nin
# Patch socket.create_connection to return a fake success or raise.
def _fake_connect(addr, timeout=None):
    if {reachable}:
        class _Fake:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def close(self): pass
        return _Fake()
    raise ConnectionRefusedError("mock unreachable")
socket.create_connection = _fake_connect
out = score_for_nin({line:?})
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
"#,
        reachable = py_reachable,
        line = bridge_line,
    );
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn parity_detect_transport_all_branches() {
    // Note: Python's _detect_transport checks "url=https" before "meek", so
    // a meek_lite line containing url=https is classified as webtunnel.
    // This matches the Python original's branch order exactly.
    for (line, expected) in [
        ("snowflake 192.0.2.3:1 url=https://x", "snowflake"),
        ("webtunnel 192.0.2.4:443 url=https://y", "webtunnel"),
        ("obfs4 1.2.3.4:443 cert=abc iat-mode=2", "obfs4"),
        ("meek_lite 192.0.2.5:80 url=https://y front=z", "webtunnel"), // url=https wins
        ("meek_lite 192.0.2.5:80 front=z", "meek_lite"),               // no url=https
        ("vanilla 1.2.3.4:9001", "vanilla"),
    ] {
        assert_eq!(detect_transport(line), expected, "line: {line}");
    }
}

#[test]
fn parity_extract_endpoint_branches() {
    let cases = [
        (
            "webtunnel x url=https://example.com:8443/path",
            Some("example.com"),
            Some(8443),
        ),
        (
            "webtunnel x url=https://example.com/path",
            Some("example.com"),
            Some(443),
        ),
        ("obfs4 1.2.3.4:443 cert=abc", Some("1.2.3.4"), Some(443)),
        ("just a plain string", None, None),
    ];
    for (line, exp_host, exp_port) in cases {
        let (h, p) = extract_endpoint(line);
        assert_eq!(h.as_deref(), exp_host, "line: {line}");
        assert_eq!(p, exp_port, "line: {line}");
    }
}

#[test]
fn parity_domain_in_nin_cdn_branches() {
    assert!(domain_in_nin_cdn(Some("cdn.arvancloud.com")));
    assert!(domain_in_nin_cdn(Some("arvancloud.ir")));
    assert!(!domain_in_nin_cdn(Some("example.com")));
    assert!(!domain_in_nin_cdn(None));
    assert!(!domain_in_nin_cdn(Some("")));
}

#[test]
fn parity_port_nin_open_branches() {
    assert!(port_nin_open(Some(443)));
    assert!(port_nin_open(Some(8080)));
    assert!(!port_nin_open(Some(22)));
    assert!(!port_nin_open(None));
}

#[test]
fn parity_score_for_nin_webtunnel_cdn_open_port_reachable() {
    let line = "webtunnel 192.0.2.4:443 url=https://cdn.arvancloud.com/path";
    let py = python_score_for_nin(line, true);
    let rs = score_for_nin(line, &AlwaysReachable);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_for_nin_snowflake_skips_tcp_probe() {
    let line = "snowflake 192.0.2.3:1 url=https://x";
    // snowflake skips TCP probe on both sides; reachable flag is irrelevant
    let py = python_score_for_nin(line, true);
    let rs = score_for_nin(line, &AlwaysReachable);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_for_nin_obfs4_unreachable() {
    let line = "obfs4 1.2.3.4:443 cert=abc iat-mode=2";
    let py = python_score_for_nin(line, false);
    let rs = score_for_nin(line, &AlwaysUnreachable);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_for_nin_vanilla_baseline() {
    let line = "vanilla 1.2.3.4:9001";
    let py = python_score_for_nin(line, false);
    let rs = score_for_nin(line, &AlwaysUnreachable);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_for_nin_meek_lite_with_cdn() {
    let line = "meek_lite 192.0.2.5:80 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com";
    let py = python_score_for_nin(line, false);
    let rs = score_for_nin(line, &AlwaysUnreachable);
    assert_eq!(py, rs);
}

#[test]
fn nin_reachable_cdns_includes_known_iranian_cdns() {
    assert!(NIN_REACHABLE_CDNS.contains(&"arvancloud.com"));
    assert!(NIN_REACHABLE_CDNS.contains(&"derak.cloud"));
    assert!(NIN_REACHABLE_CDNS.contains(&"cloudflare.com"));
}

#[test]
fn nin_open_ports_includes_443_and_80() {
    assert!(NIN_OPEN_PORTS.contains(&443));
    assert!(NIN_OPEN_PORTS.contains(&80));
    assert!(NIN_OPEN_PORTS.contains(&8443));
    assert!(!NIN_OPEN_PORTS.contains(&22));
}

#[test]
fn score_for_nin_score_clamped_to_one() {
    // All bonuses apply → score 1.05 → clamped to 1.0
    let result = score_for_nin(
        "webtunnel 192.0.2.4:443 url=https://cdn.arvancloud.com/path",
        &AlwaysReachable,
    );
    assert_eq!(result["nin_score"], json!(1.0));
}
