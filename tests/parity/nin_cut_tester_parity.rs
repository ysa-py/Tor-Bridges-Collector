// Differential parity tests for `src/nin_cut_tester.rs` vs
// `nin_cut_tester.py`.
//
// Covers the deterministic, network-free surface: `_parse_bridge_line`,
// `_is_iran_domestic` (the embedded Iran domestic CIDR table), and
// `_score_bridge`. The async TCP probes (`_probe_bridge`/`_run_all_probes`)
// perform real network I/O and are covered by in-crate mock-probe unit
// tests, not differentially.

use std::net::IpAddr;
use std::process::Command;

use torshield_ir_ultra::nin_cut_tester::{
    is_iran_domestic, parse_bridge_line, score_bridge, IranCidrTable,
};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("import json\nimport nin_cut_tester as m\n{body}\n");
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

const LINES: &[&str] = &[
    "obfs4 5.160.1.2:443 cert=abc iat-mode=0",      // Iran domestic (5.160/14), nin port, obfs4
    "webtunnel 46.209.5.5:8443 url=https://x/",      // Iran domestic (46.209/16), nin port, webtunnel
    "vanilla 8.8.8.8:9001",                          // foreign, non-nin port, vanilla
    "obfs4 [2001:db8::1]:443 cert=xyz",              // IPv6 -> not domestic
    "snowflake 1.2.3.4:80",                          // foreign, nin port, snowflake (not high-survival)
    "meek_lite 94.182.7.7:8080 front=z",             // domestic (94.182/16), nin port
    "# a comment line",                              // -> None
    "",                                              // -> None
    "garbage with no endpoint",                      // -> None
    "obfs3 82.99.200.1:2083 cert=q",                 // domestic (82.99.192/18? 82.99.200 in /18), non-nin port
    "OBFS4 5.22.200.9:443 CERT=ABC",                 // case-insensitive PT prefix, domestic
    "5.53.40.1:443",                                 // no PT -> vanilla, domestic
    "webtunnel 185.143.234.9:443",                   // ArvanCloud domestic
    "obfs4 192.0.2.9:70000",                         // port out of range -> None (regex \\d{2,5} won't match 70000 fully? test)
];

#[test]
fn parity_parse_bridge_line() {
    for line in LINES {
        let py = run_python(&format!(
            "p = m._parse_bridge_line(r'''{line}'''); \
             print('None' if p is None else f\"{{p['raw']}}|{{p['ip']}}|{{p['port']}}|{{p['transport']}}\")"
        ));
        let rs = match parse_bridge_line(line) {
            None => "None".to_string(),
            Some(p) => format!("{}|{}|{}|{}", p.raw, p.ip, p.port, p.transport),
        };
        assert_eq!(py, rs, "parse_bridge_line for {line:?}");
    }
}

#[test]
fn parity_is_iran_domestic() {
    let table = IranCidrTable::new();
    let ips = [
        "5.160.1.2", "46.209.5.5", "94.182.7.7", "82.99.200.1", "5.22.200.9",
        "185.143.234.9", "8.8.8.8", "1.1.1.1", "203.0.113.5", "2001:db8::1",
        "5.159.255.255", "5.160.0.0", "2.144.0.0", "2.143.255.255",
    ];
    for ip_str in ips {
        let py = run_python(&format!(
            "import ipaddress; \
             print(str(m._is_iran_domestic(ipaddress.ip_address(r'''{ip_str}'''))).lower())"
        ));
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_eq!(py, is_iran_domestic(ip, &table).to_string(), "is_iran_domestic({ip_str})");
    }
}

#[test]
fn parity_score_bridge() {
    let table = IranCidrTable::new();
    // Only parseable lines produce a score (score_bridge takes a parsed bridge).
    for line in LINES {
        if let Some(parsed) = parse_bridge_line(line) {
            let py = run_python(&format!(
                "p = m._parse_bridge_line(r'''{line}'''); print(f'{{m._score_bridge(p):.4f}}')"
            ));
            let rs = format!("{:.4}", score_bridge(&parsed, &table));
            assert_eq!(py, rs, "score_bridge for {line:?}");
        }
    }
}
