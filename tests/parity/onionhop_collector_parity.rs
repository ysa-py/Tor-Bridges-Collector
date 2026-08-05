// Parity tests for `src/onionhop_collector.rs` vs `onionhop_collector.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `onionhop_collector` and calls the matching function on the same input.
// The Rust port is invoked on the identical input and the JSON outputs
// are compared for equality (parsed [`Value`] comparison so object key
// ordering is irrelevant).
//
// Coverage:
// * `is_valid` over empty, short, marker, IPv4, IPv6, and URL branches.
// * `strip_prefix` over `Bridge `-prefixed and bare lines.
// * `transport_token` over lowercased first tokens.
// * `detect_transport` over all six transport branches.
// * `detect_ip_version` over IPv6 bracket and IPv4 plain.
// * `is_fronted` over each `FRONTED_TOKENS` entry and a non-fronted line.
// * `extract_front_host` over `url=`, `fronts=`, `front=`, and missing.
// * `extract_endpoint` over all four pattern alternatives and the no-match
//   fallback.
// * `parse_iso_safe` over missing, invalid, sentinel, and valid input.
// * `entry_last_seen` over dict, string, and other types.
// * `load_history` over missing file, legacy string, and dict entries.
// * `cleanup_history` over retention boundary cases.
// * `record_bridge` over insert and update branches.
// * `fetch_bridgedb` / `fetch_delta` over mock HTTP responses (no real
//   network).
// * `test_many_with_probes` over the cap-and-filter logic with a mock
//   reachability probe.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use torshield_ir_ultra::onionhop_collector::{
    self, cleanup_history_with_now, detect_ip_version, detect_transport, entry_last_seen,
    extract_endpoint, extract_front_host, fetch_bridgedb, fetch_delta, is_fronted, is_valid,
    load_history, parse_iso_safe, record_bridge_with_now, save_history, strip_prefix,
    test_many_with_probes, transport_token, ReachabilityProbe,
};
use torshield_ir_ultra::scraper::{HttpFetch, HttpResponse, ScraperError};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
        "/home/z/.venv/bin/python3",
        "/home/z/.venv/bin/python",
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("python")
}

/// Dispatch a single JSON command to the Python `onionhop_collector` module
/// and return the parsed JSON output.
fn python_onionhop(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("onionhop parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os
os.environ.setdefault('BRIDGE_DIR', '/tmp/torshield_onionhop_parity_bridge')
import onionhop_collector as oh

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'is_valid':
    print(json.dumps(oh._is_valid(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'strip_prefix':
    print(json.dumps(oh._strip_prefix(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'transport_token':
    print(json.dumps(oh._transport_token(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'detect_transport':
    print(json.dumps(oh._detect_transport(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'detect_ip_version':
    print(json.dumps(oh._detect_ip_version(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'is_fronted':
    print(json.dumps(oh._is_fronted(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'extract_front_host':
    result = oh._extract_front_host(cmd['line'])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
elif op == 'extract_endpoint':
    host, port, transport = oh._extract_endpoint(cmd['line'])
    print(json.dumps({'host': host, 'port': port, 'transport': transport}, sort_keys=True, separators=(',', ':')))
elif op == 'parse_iso_safe':
    result = oh._parse_iso_safe(cmd.get('stamp'))
    if result is None:
        print(json.dumps(None, sort_keys=True, separators=(',', ':')))
    else:
        print(json.dumps(result.isoformat(), sort_keys=True, separators=(',', ':')))
elif op == 'entry_last_seen':
    entry = cmd['entry']
    result = oh._entry_last_seen(entry)
    if result is None:
        print(json.dumps(None, sort_keys=True, separators=(',', ':')))
    else:
        print(json.dumps(result.isoformat(), sort_keys=True, separators=(',', ':')))
elif op == 'load_history':
    from pathlib import Path
    oh.HISTORY_FILE = Path(cmd['path'])
    print(json.dumps(oh._load_history(), sort_keys=True, separators=(',', ':')))
elif op == 'save_history':
    from pathlib import Path
    oh.HISTORY_FILE = Path(cmd['path'])
    oh._save_history(cmd['history'])
    print(json.dumps(None, sort_keys=True, separators=(',', ':')))
elif op == 'cleanup_history':
    from datetime import datetime, timezone
    history = cmd['history']
    retention_days = cmd['retention_days']
    fixed_now = datetime.fromisoformat(cmd['now_iso'])
    orig_datetime = oh.datetime
    class _PatchedDatetime(orig_datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)
    oh.datetime = _PatchedDatetime
    result = oh._cleanup_history(history)
    oh.datetime = orig_datetime
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
elif op == 'record_bridge':
    from datetime import datetime, timezone
    history = cmd['history']
    bridge = cmd['bridge']
    transport = cmd['transport']
    ip_version = cmd['ip_version']
    fixed_now = datetime.fromisoformat(cmd['now_iso'])
    orig_datetime = oh.datetime
    class _PatchedDatetime(orig_datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)
    oh.datetime = _PatchedDatetime
    oh._record_bridge(history, bridge, transport, ip_version)
    oh.datetime = orig_datetime
    print(json.dumps(history, sort_keys=True, separators=(',', ':')))
else:
    raise SystemExit('unknown op: ' + op)
"#;
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .arg(&cmd_json)
        .output()
        .unwrap_or_else(|err| panic!("python onionhop helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python onionhop helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python onionhop helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock HTTP client
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct MockHttpFetch {
    gets: BTreeMap<String, HttpResponse>,
}

impl MockHttpFetch {
    fn with_get(mut self, url: &str, status: u16, text: &str) -> Self {
        self.gets.insert(
            url.to_string(),
            HttpResponse {
                status,
                headers: Vec::new(),
                text: text.to_string(),
            },
        );
        self
    }
}

impl HttpFetch for MockHttpFetch {
    fn get(&self, url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
        Ok(self.gets.get(url).cloned().unwrap_or(HttpResponse {
            status: 404,
            headers: Vec::new(),
            text: String::new(),
        }))
    }

    fn post_json(
        &self,
        _url: &str,
        _body: &Value,
        _headers: &[(String, String)],
        _timeout: Duration,
    ) -> Result<HttpResponse, ScraperError> {
        Ok(HttpResponse {
            status: 404,
            headers: Vec::new(),
            text: String::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock reachability probe
// ─────────────────────────────────────────────────────────────────────────────

struct MockProbe {
    reachable_set: std::collections::BTreeSet<String>,
}

impl ReachabilityProbe for MockProbe {
    fn test_tcp(&self, host: &str, port: u16) -> bool {
        self.reachable_set
            .contains(&format!("tcp:{}:{}", host, port))
    }
    fn test_tls(&self, host: &str, port: u16) -> bool {
        self.reachable_set
            .contains(&format!("tls:{}:{}", host, port))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Python parity (>=4 scenarios invoking Python)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_is_valid_branches() {
    for line in [
        "",
        "# short",
        "No bridges available here",
        "short",
        "obfs4 1.2.3.4:443 ABC",
        "obfs4 [2001:db8::1]:443 ABC",
        "url=https://example.com/",
    ] {
        let cmd = json!({"op": "is_valid", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(is_valid(line));
        assert_eq!(rs, py, "is_valid mismatch for {:?}", line);
    }
}

#[test]
fn parity_strip_prefix_branches() {
    for line in [
        "Bridge 1.2.3.4:443 ABC",
        "  1.2.3.4:443 ABC  ",
        "no prefix here",
        "",
    ] {
        let cmd = json!({"op": "strip_prefix", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(strip_prefix(line));
        assert_eq!(rs, py, "strip_prefix mismatch for {:?}", line);
    }
}

#[test]
fn parity_transport_token_branches() {
    for line in [
        "Bridge OBFS4 1.2.3.4:443 ABC",
        "snowflake url=https://x",
        "Meek_Lite 192.0.2.18:80 ABC",
        "",
        "   ",
    ] {
        let cmd = json!({"op": "transport_token", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(transport_token(line));
        assert_eq!(rs, py, "transport_token mismatch for {:?}", line);
    }
}

#[test]
fn parity_detect_transport_all_branches() {
    for line in [
        "snowflake 192.0.2.3:80 ABC",
        "webtunnel url=https://example.com/",
        "obfs4 1.2.3.4:443 ABC",
        "meek_lite 192.0.2.18:80 ABC",
        "conjure url=https://x",
        "1.2.3.4:443 ABC",
    ] {
        let cmd = json!({"op": "detect_transport", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(detect_transport(line));
        assert_eq!(rs, py, "detect_transport mismatch for {:?}", line);
    }
}

#[test]
fn parity_detect_ip_version_branches() {
    for line in [
        "obfs4 [2001:db8::1]:443 ABC",
        "obfs4 1.2.3.4:443 ABC",
        "[fe80::1]:443",
        "url=https://example.com/",
    ] {
        let cmd = json!({"op": "detect_ip_version", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(detect_ip_version(line));
        assert_eq!(rs, py, "detect_ip_version mismatch for {:?}", line);
    }
}

#[test]
fn parity_is_fronted_branches() {
    for line in [
        "snowflake url=https://x",
        "meek_lite 192.0.2.18:80 ABC",
        "meek-azure something",
        "meek something else",
        "conjure url=https://x",
        "obfs4 1.2.3.4:443 ABC",
        "vanilla 1.2.3.4:443 ABC",
    ] {
        let cmd = json!({"op": "is_fronted", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(is_fronted(line));
        assert_eq!(rs, py, "is_fronted mismatch for {:?}", line);
    }
}

#[test]
fn parity_extract_front_host_all_branches() {
    for line in [
        "snowflake 1.2.3.4:80 ABC url=https://example.com/x",
        "snowflake 1.2.3.4:80 ABC fronts=front.example.com,other",
        "meek_lite 1.2.3.4:80 ABC front=front.example.com",
        "vanilla 1.2.3.4:80 ABC",
        "snowflake 1.2.3.4:80 ABC url=https://[2001:db8::1]:8443/x",
    ] {
        let cmd = json!({"op": "extract_front_host", "line": line});
        let py = python_onionhop(&cmd);
        let rs = json!(extract_front_host(line));
        assert_eq!(rs, py, "extract_front_host mismatch for {:?}", line);
    }
}

#[test]
fn parity_extract_endpoint_all_patterns() {
    for line in [
        "webtunnel url=https://example.com/x",
        "obfs4 [2001:db8::1]:443 ABC",
        "obfs4 1.2.3.4:443 ABC",
        "webtunnel url=https://[2001:db8::1]:8443/x",
        "webtunnel url=https://example.com:8443/x",
        "vanilla no endpoint here",
    ] {
        let cmd = json!({"op": "extract_endpoint", "line": line});
        let py = python_onionhop(&cmd);
        let (host, port, transport) = extract_endpoint(line);
        let rs = json!({
            "host": host,
            "port": port,
            "transport": transport,
        });
        assert_eq!(rs, py, "extract_endpoint mismatch for {:?}", line);
    }
}

#[test]
fn parity_parse_iso_safe_branches() {
    for stamp in [
        None,
        Some("not-a-date"),
        Some("1970-01-01T00:00:00+00:00"),
        Some("2026-06-09T00:00:00+00:00"),
        Some("2026-06-09T00:00:00"),
    ] {
        let cmd = json!({"op": "parse_iso_safe", "stamp": stamp});
        let py = python_onionhop(&cmd);
        let rs_dt = parse_iso_safe(stamp);
        let rs = match rs_dt {
            Some(dt) => json!(dt.to_rfc3339()),
            None => Value::Null,
        };
        assert_eq!(rs, py, "parse_iso_safe mismatch for {:?}", stamp);
    }
}

#[test]
fn parity_entry_last_seen_branches() {
    for entry in [
        json!({"last_seen": "2026-06-09T00:00:00+00:00"}),
        json!("2026-06-09T00:00:00+00:00"),
        json!(42),
        json!(null),
        json!({"last_seen": "not-a-date"}),
        json!({}),
    ] {
        let cmd = json!({"op": "entry_last_seen", "entry": entry});
        let py = python_onionhop(&cmd);
        let rs_dt = entry_last_seen(&entry);
        let rs = match rs_dt {
            Some(dt) => json!(dt.to_rfc3339()),
            None => Value::Null,
        };
        assert_eq!(rs, py, "entry_last_seen mismatch for {}", entry);
    }
}

#[test]
fn parity_load_history_legacy_and_dict_entries() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "onionhop_parity_load_history_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    // Missing file → empty object on both sides.
    let cmd = json!({"op": "load_history", "path": tmp.to_string_lossy()});
    let py = python_onionhop(&cmd);
    let rs = load_history(&tmp).unwrap();
    assert_eq!(rs, py, "missing-file load_history mismatch");

    // Legacy string entry + dict entry.
    let content = r#"{
  "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567": "2026-01-01T00:00:00+00:00",
  "snowflake url=https://example.com/ abcdef0123456789": {
    "raw": "snowflake url=https://example.com/ abcdef0123456789",
    "transport": "snowflake",
    "ip_version": "ipv4",
    "first_seen": "2026-06-09T00:00:00+00:00",
    "last_seen": "2026-06-09T00:00:00+00:00",
    "tcp_reachable": null
  }
}"#;
    fs::write(&tmp, content).unwrap();

    let cmd = json!({"op": "load_history", "path": tmp.to_string_lossy()});
    let py = python_onionhop(&cmd);
    let rs = load_history(&tmp).unwrap();
    assert_eq!(rs, py, "legacy+dict load_history mismatch");
    let _ = fs::remove_file(&tmp);
}

#[test]
fn parity_cleanup_history_boundary_cases() {
    let now_iso = "2026-06-10T12:00:00+00:00";
    let history = json!({
        "old": {"last_seen": "2000-01-01T00:00:00+00:00"},
        "new": {"last_seen": "2026-06-09T00:00:00+00:00"},
        "bad": {"last_seen": "not-a-date"},
        "missing": {},
        "str_entry": "2026-06-09T00:00:00+00:00",
    });
    let cmd = json!({
        "op": "cleanup_history",
        "history": history,
        "retention_days": 30,
        "now_iso": now_iso,
    });
    let py = python_onionhop(&cmd);
    let now = chrono::DateTime::parse_from_rfc3339(now_iso)
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    let rs = cleanup_history_with_now(&history, 30, now).unwrap();
    assert_eq!(rs, py);
}

#[test]
fn parity_record_bridge_insert_and_update() {
    let now_iso = "2026-06-10T12:00:00+00:00";
    let history_init = json!({});
    let cmd = json!({
        "op": "record_bridge",
        "history": history_init,
        "bridge": "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF",
        "transport": "obfs4",
        "ip_version": "ipv4",
        "now_iso": now_iso,
    });
    let py = python_onionhop(&cmd);
    let mut rs = history_init;
    let now = chrono::DateTime::parse_from_rfc3339(now_iso)
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    record_bridge_with_now(
        &mut rs,
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF",
        "obfs4",
        "ipv4",
        now,
    )
    .unwrap();
    assert_eq!(rs, py, "insert branch mismatch");

    // Second call updates last_seen but preserves first_seen.
    let later_iso = "2026-06-11T12:00:00+00:00";
    let cmd = json!({
        "op": "record_bridge",
        "history": rs.clone(),
        "bridge": "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF",
        "transport": "obfs4",
        "ip_version": "ipv4",
        "now_iso": later_iso,
    });
    let py = python_onionhop(&cmd);
    let later = chrono::DateTime::parse_from_rfc3339(later_iso)
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    record_bridge_with_now(
        &mut rs,
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF",
        "obfs4",
        "ipv4",
        later,
    )
    .unwrap();
    assert_eq!(rs, py, "update branch mismatch");
}

#[test]
fn parity_save_history_round_trips_through_load_history() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "onionhop_parity_save_history_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    let history = json!({
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123": {
            "raw": "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": "2026-06-09T00:00:00+00:00",
            "last_seen": "2026-06-09T00:00:00+00:00",
            "tcp_reachable": null,
        },
        "snowflake url=https://example.com/ abcdef0123456789": {
            "raw": "snowflake url=https://example.com/ abcdef0123456789",
            "transport": "snowflake",
            "ip_version": "ipv4",
            "first_seen": "2026-06-09T00:00:00+00:00",
            "last_seen": "2026-06-09T00:00:00+00:00",
            "tcp_reachable": null,
        }
    });
    let cmd = json!({"op": "save_history", "path": tmp.to_string_lossy(), "history": history});
    let _py = python_onionhop(&cmd);
    let py_bytes = fs::read_to_string(&tmp).unwrap();
    let _ = fs::remove_file(&tmp);

    save_history(&history, &tmp).unwrap();
    let rs_bytes = fs::read_to_string(&tmp).unwrap();
    let _ = fs::remove_file(&tmp);

    // Both sides should produce the same JSON object when re-parsed.
    let py_parsed: Value = serde_json::from_str(&py_bytes).unwrap();
    let rs_parsed: Value = serde_json::from_str(&rs_bytes).unwrap();
    assert_eq!(py_parsed, rs_parsed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Rust-only branches (no Python invocation)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fetch_bridgedb_with_mock_client_returns_bridge_lines() {
    let html = r#"<div id="bridgelines">
obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567
</div>"#;
    let url = "https://bridges.torproject.org/bridges?transport=obfs4";
    let client = MockHttpFetch::default().with_get(url, 200, html);
    let result = fetch_bridgedb(&client, "obfs4", false).unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains("obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"));
}

#[test]
fn fetch_bridgedb_with_non_200_returns_empty_set() {
    let url = "https://bridges.torproject.org/bridges?transport=obfs4";
    let client = MockHttpFetch::default().with_get(url, 403, "");
    let result = fetch_bridgedb(&client, "obfs4", false).unwrap();
    assert!(result.is_empty());
}

#[test]
fn fetch_bridgedb_with_no_bridgelines_div_returns_empty_set() {
    let html = r#"<html><body><p>captcha required</p></body></html>"#;
    let url = "https://bridges.torproject.org/bridges?transport=obfs4";
    let client = MockHttpFetch::default().with_get(url, 200, html);
    let result = fetch_bridgedb(&client, "obfs4", false).unwrap();
    assert!(result.is_empty());
}

#[test]
fn fetch_delta_with_mock_client_returns_union() {
    let base = onionhop_collector::DELTA_RAW_BASE;
    let url1 = format!("{}/obfs4.txt", base);
    let url2 = format!("{}/obfs4_72h.txt", base);
    let client = MockHttpFetch::default()
        .with_get(
            &url1,
            200,
            "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567\n",
        )
        .with_get(
            &url2,
            200,
            "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567\n",
        );
    let result = fetch_delta(&client, "obfs4", false).unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn fetch_delta_with_404_returns_empty_set() {
    let base = onionhop_collector::DELTA_RAW_BASE;
    let url1 = format!("{}/obfs4.txt", base);
    let url2 = format!("{}/obfs4_72h.txt", base);
    // Both URLs return 404 (default mock).
    let client = MockHttpFetch::default()
        .with_get(&url1, 404, "")
        .with_get(&url2, 404, "");
    let result = fetch_delta(&client, "obfs4", false).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_many_with_probes_accepts_full_candidate_pool() {
    let probe = MockProbe {
        reachable_set: std::collections::BTreeSet::new(),
    };
    let mut bridges: Vec<String> = (0..(onionhop_collector::MAX_TEST_PER_LIST + 5))
        .map(|i| format!("obfs4 1.2.3.{}:443 ABC", i % 256))
        .collect();
    let result = test_many_with_probes(&bridges, &probe);
    assert_eq!(result.len(), 0); // nothing reachable; all candidates are considered.
    bridges.clear();
    let empty = test_many_with_probes(&bridges, &probe);
    assert!(empty.is_empty());
}

#[test]
fn test_many_with_probes_returns_only_reachable_bridges() {
    let mut reachable = std::collections::BTreeSet::new();
    reachable.insert("tcp:1.2.3.4:443".to_string());
    reachable.insert("tcp:5.6.7.8:443".to_string());
    let probe = MockProbe {
        reachable_set: reachable,
    };
    let bridges = vec![
        "obfs4 1.2.3.4:443 ABC".to_string(),
        "obfs4 5.6.7.8:443 ABC".to_string(),
        "obfs4 9.10.11.12:443 ABC".to_string(),
    ];
    let result = test_many_with_probes(&bridges, &probe);
    assert_eq!(result.len(), 2);
    assert!(result.contains(&"obfs4 1.2.3.4:443 ABC".to_string()));
    assert!(result.contains(&"obfs4 5.6.7.8:443 ABC".to_string()));
}

#[test]
fn parse_iso_safe_returns_none_for_invalid_input() {
    assert!(parse_iso_safe(None).is_none());
    assert!(parse_iso_safe(Some("not-a-date")).is_none());
    assert!(parse_iso_safe(Some("1970-01-01T00:00:00+00:00")).is_some());
    assert!(parse_iso_safe(Some("2026-06-09T00:00:00+00:00")).is_some());
}

#[test]
fn load_history_returns_empty_object_for_missing_file() {
    let tmp = std::env::temp_dir().join(format!(
        "onionhop_missing_history_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    let history = load_history(&tmp).unwrap();
    assert!(history.as_object().map(|m| m.is_empty()).unwrap_or(false));
}

#[test]
fn fronted_bridges_constant_table_has_three_transports() {
    let table = onionhop_collector::fronted_bridges();
    assert_eq!(table.len(), 3);
    assert_eq!(table[0].0, "snowflake");
    assert_eq!(table[0].1.len(), 2);
    assert_eq!(table[1].0, "meek-azure");
    assert_eq!(table[1].1.len(), 1);
    assert_eq!(table[2].0, "conjure");
    assert_eq!(table[2].1.len(), 1);
}
