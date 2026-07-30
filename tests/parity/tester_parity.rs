#![allow(warnings)]
// Differential parity tests for `src/tester.rs` vs `core/tester.py`.
//
// Covers the pure bridge-line parsing functions `detect_transport`,
// `extract_endpoint`, and `is_ip`. The async TCP/TLS probes in the Python
// original perform real network I/O and are out of scope (see the module
// header in `src/tester.rs`).
//
// Documented bounded divergence: Python's `int(port)` accepts values
// > 65535, while the Rust port parses into `u16` (yielding `None` on
// overflow). Real bridge lines never exceed the valid port range, so the
// fixtures below stay within 0..=65535 where parity is exact.

use std::process::Command;

use torshield_ir_ultra::tester::{detect_transport, extract_endpoint, is_ip};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(script: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

const LINES: &[&str] = &[
    "snowflake 192.0.2.3:1 url=https://snowflake.example/",
    "webtunnel 192.0.2.4:443 url=https://cdn.example.net/path",
    "obfs4 1.2.3.4:443 cert=abc iat-mode=0",
    "meek_lite 192.0.2.5:80 url=https://meek.azureedge.net/",
    "meek_lite 192.0.2.5:80 front=cdn.example",
    "vanilla 1.2.3.4:9001",
    "Bridge obfs4 [2001:db8::1]:443 cert=xyz",
    "Bridge 5.6.7.8:8080",
    "obfs4 relay.example.com:9002 cert=zzz",
    "some.host.io:2083",
    "webtunnel url=https://host.dev:8443/x",
    "totally malformed line with no endpoint",
    "OBFS4 9.9.9.9:12345 CERT=ABC",
    "   obfs4 3.3.3.3:443 leading whitespace   ",
];

#[test]
fn parity_detect_transport() {
    for line in LINES {
        let py = run_python(&format!(
            "from core.tester import detect_transport; \
             print(detect_transport(r'''{line}'''))"
        ));
        assert_eq!(py, detect_transport(line), "detect_transport for {line:?}");
    }
}

#[test]
fn parity_extract_endpoint() {
    for line in LINES {
        // Python prints "host|port|transport" with None rendered literally.
        let py = run_python(&format!(
            "from core.tester import extract_endpoint; \
             h,p,t = extract_endpoint(r'''{line}'''); \
             print(f'{{h}}|{{p}}|{{t}}')"
        ));
        let (h, p, t) = extract_endpoint(line);
        let rs = format!(
            "{}|{}|{}",
            h.unwrap_or_else(|| "None".to_string()),
            p.map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string()),
            t
        );
        assert_eq!(py, rs, "extract_endpoint for {line:?}");
    }
}

#[test]
fn parity_is_ip() {
    let hosts = [
        "1.2.3.4",
        "255.255.255.255",
        "2001:db8::1",
        "::1",
        "example.com",
        "not an ip",
        "",
        "999.999.999.999",
        "1.2.3",
        "0.0.0.0",
    ];
    for h in hosts {
        // Lower-case Python's bool so it matches Rust's Display ("true"/"false").
        let py = run_python(&format!(
            "from core.tester import is_ip; print(str(is_ip(r'''{h}''')).lower())"
        ));
        assert_eq!(py, is_ip(h).to_string(), "is_ip for {h:?}");
    }
}
