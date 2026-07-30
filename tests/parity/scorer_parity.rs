#![allow(warnings)]
// Differential parity tests for `src/scorer.rs` vs `core/scorer.py`.
//
// Covers the deterministic scoring dimensions and the full `score()`
// aggregate. To make the time-dependent freshness component and the
// disk-loaded transport weights deterministic, the Python oracle is driven
// with:
//   * `core.scorer.utc_now` monkeypatched to a fixed instant matching the
//     Rust `IranScorer::new(FIXED_NOW)` clock, and
//   * `TRANSPORT_SCORES` reset to `_DEFAULT_TRANSPORT_SCORES` (the Rust
//     `new()` constructor also uses defaults; `data/transport_weights.json`
//     exists on disk and would otherwise perturb the Python side only).
//
// This test also verifies the ja3 penalty port (previously a stub that
// returned 0, which broke score() parity — see MIGRATION_NOTES.md §Session 10).

use std::process::Command;

use chrono::{TimeZone, Utc};
use serde_json::json;
use torshield_ir_ultra::scorer::IranScorer;

const FIXED_NOW: &str = "2026-06-28T12:00:00+00:00";

fn fixed_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 28, 12, 0, 0).unwrap()
}

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    // Shared preamble: fixed clock + default transport scores.
    let script = format!(
        "import json\n\
         from datetime import datetime, timezone\n\
         import core.scorer as sc\n\
         sc.utc_now = lambda: datetime.fromisoformat('{FIXED_NOW}')\n\
         s = sc.IranScorer()\n\
         s.TRANSPORT_SCORES = dict(sc.IranScorer._DEFAULT_TRANSPORT_SCORES)\n\
         {body}\n"
    );
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

fn scorer() -> IranScorer {
    IranScorer::new(fixed_now())
}

#[test]
fn parity_port_score() {
    let s = scorer();
    for p in [
        443u16, 80, 8080, 8443, 2083, 2087, 2096, 22, 1023, 1024, 9001, 65535, 0,
    ] {
        let py = run_python(&format!("print(s._port_score({p}))"));
        assert_eq!(py, s.port_score(p).to_string(), "port_score({p})");
    }
}

#[test]
fn parity_ipv_score() {
    let s = scorer();
    for h in [
        "1.2.3.4",
        "2001:db8::1",
        "example.com",
        "",
        "255.255.255.255",
        "::1",
    ] {
        let py = run_python(&format!("print(s._ipv_score(r'''{h}'''))"));
        assert_eq!(py, s.ipv_score(h).to_string(), "ipv_score({h:?})");
    }
}

#[test]
fn parity_test_score() {
    let s = scorer();
    for (lit, val) in [("True", Some(true)), ("False", Some(false)), ("None", None)] {
        let py = run_python(&format!("print(s._test_score({lit}))"));
        assert_eq!(py, s.test_score(val).to_string(), "test_score({lit})");
    }
}

#[test]
fn parity_cdn_bonus() {
    let s = scorer();
    let lines = [
        "url=https://fastly.net/x",
        "url=https://arvancloud.ir/y",
        "url=https://arvancloud.com/y",
        "url=https://cdn.irimc.ir/z",
        "url=https://d123.cloudfront.net/a",
        "url=https://x.azureedge.net/b",
        "url=https://y.aspnetcdn.com/c",
        "url=https://r1---sn.googlevideo.com/d",
        "url=https://ssl.gstatic.com/e",
        "url=https://example.com/none",
        "obfs4 1.2.3.4:443",
    ];
    for l in lines {
        let py = run_python(&format!("print(s._cdn_bonus(r'''{l}'''))"));
        assert_eq!(py, s.cdn_bonus(l).to_string(), "cdn_bonus({l:?})");
    }
}

/// The ported JA3 penalty — the core of this session's fix. Exercises the
/// transport-default path, the high-risk-port proxy, known-fingerprint DB
/// hits, safe-hash clamping, and banker's-rounding (`.5`) edges.
#[test]
fn parity_ja3_penalty() {
    let s = scorer();
    let records = vec![
        json!({"transport": "obfs4", "port": 443}),
        json!({"transport": "snowflake", "port": 80}),
        json!({"transport": "vanilla", "port": 9001}), // port_risk kicks in
        json!({"transport": "vanilla", "port": 443}),
        json!({"transport": "webtunnel"}), // port defaults to 0
        json!({"transport": "meek_lite", "port": 8080}),
        json!({"transport": "unknown", "port": 1}),
        json!({"transport": "obfs4", "port": 9030}),
        json!({"transport": "meek_lite", "port": 8080, "ja3_hash": "deadbeef"}), // unknown hash 0.3 -> round(4.5)=4
        json!({"ja3_hash": "e7d705a3286e19ea42f587b344ee6865"}), // DB critical 1.0 -> 15
        json!({"ja3_hash": "6734f37431670b3ab4292b8f60f29984"}), // 0.95 -> round(14.25)=14
        json!({"ja3_hash": "5d7e19ef9b3a4c56f5cd4a38cd0d0aa3"}), // 0.55 -> round(8.25)=8
        json!({"ja3_hash": "de350869b8c85de67a350c8d186f11e6"}), // 0.75 -> round(11.25)=11
        json!({"ja3_hash": "3b5074b1b5d032e5620f69f9159c9b58"}), // 0.50 -> round(7.5)=8 (even)
        json!({"ja3_hash": "cd08e31494f9531f560d64c695473da9"}), // 0.30 -> round(4.5)=4 (even)
        json!({"ja3_hash": "b32309a26951912be7dba376398abc3b"}), // SAFE hash -> 0
        json!({"ja3_hash": "aaa7bf52f6c250ce0e70d7d4f32a6d52"}), // SAFE hash -> 0
        json!({"transport": "obfs4", "port": "9050"}),           // string port coercion
        json!({"raw": "vanilla 1.2.3.4:9001", "port": 9001}),    // transport inferred from raw
    ];
    for r in &records {
        let compact = serde_json::to_string(r).unwrap();
        let py = run_python(&format!(
            "print(s._ja3_penalty(json.loads(r'''{compact}''')))"
        ));
        assert_eq!(py, s.ja3_penalty(r).to_string(), "ja3_penalty for {r}");
    }
}

/// Full `score()` aggregate across transports, ports, freshness buckets,
/// test results, CDN bonuses, and ja3 penalties.
#[test]
fn parity_score_full_records() {
    let s = scorer();
    let records = vec![
        json!({"raw": "obfs4 1.2.3.4:443 cert=abc", "transport": "obfs4",
               "first_seen": "2026-06-28T11:00:00+00:00", "test_pass": true, "port": 443}),
        json!({"raw": "snowflake 192.0.2.3:1 url=https://snowflake.example/", "transport": "snowflake",
               "first_seen": "2026-06-26T12:00:00+00:00", "test_pass": false}),
        json!({"raw": "vanilla 5.6.7.8:9001", "transport": "vanilla",
               "first_seen": "2026-06-23T12:00:00+00:00", "port": 9001}),
        json!({"raw": "webtunnel 9.9.9.9:443 url=https://cdn.fastly.net/x", "transport": "webtunnel",
               "first_seen": "2026-06-08T12:00:00+00:00", "test_pass": true}),
        json!({"raw": "meek_lite 2.2.2.2:8080 url=https://x.azureedge.net/", "transport": "meek_lite",
               "first_seen": "2026-04-29T12:00:00+00:00", "ja3_hash": "deadbeef", "port": 8080}),
        json!({"raw": "obfs4 [2001:db8::1]:443 cert=xyz", "transport": "obfs4",
               "first_seen": "2026-06-28T11:59:00+00:00"}),
        json!({"raw": "some.host.io:2083", "first_seen": "not-a-date"}),
        json!({"raw": "vanilla 1.2.3.4:9001", "transport": "vanilla",
               "first_seen": "2026-06-28T11:00:00+00:00", "ja3_hash": "e7d705a3286e19ea42f587b344ee6865", "port": 9001}),
    ];
    for r in &records {
        let compact = serde_json::to_string(r).unwrap();
        let py = run_python(&format!("print(s.score(json.loads(r'''{compact}''')))"));
        assert_eq!(py, s.score(r).to_string(), "score for {r}");
    }
}
