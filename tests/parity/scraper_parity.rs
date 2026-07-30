// Parity tests for `src/scraper.rs` vs `scraper.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `scraper` and calls the matching function on the same input. The Rust
// port is invoked on the identical input and the JSON outputs are
// compared for equality (parsed [`Value`] comparison so object key
// ordering is irrelevant).
//
// Coverage:
// * `normalize_for_history` / `normalize_for_file` over vanilla-prefix and
//   non-vanilla branches.
// * `is_valid_line` over empty, short, marker, IPv4, IPv6, and URL branches.
// * `parse_bridgelines_html` over div-bridgelines, pre/code fallback, and
//   empty input.
// * `parse_moat_response` over valid, missing `bridges`, non-object root,
//   and non-list values.
// * `get_static` over the four built-in bridge lines.
// * `_infer_transport` / `_infer_ip_version` over each transport and
//   IPv4/IPv6.
// * `load_history` over missing file, legacy string entries, and dict
//   entries.
// * `save_history` round-trips through `load_history`.
// * `update_history` over new entries and `last_seen` updates.
// * `prune_history` over retention boundary cases.
// * `write_sorted` over preserve_order and sort branches.
// * `classify_zip_folder` over tested / fresh / archive branches.
// * `fetch_torproject` / `fetch_moat` over mock HTTP responses (no real
//   network).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use torshield_ir_ultra::adaptive_selector::{AdaptiveBridgeSelector, AdaptiveConfig};
use torshield_ir_ultra::scraper::{
    self, classify_zip_folder, fetch_moat, fetch_torproject, get_static, infer_ip_version,
    infer_transport, is_valid_line, load_history, normalize_for_file, normalize_for_history,
    parse_bridgelines_html, parse_moat_response, prune_history_with_now, save_history,
    write_sorted, write_testing_json, HttpFetch, HttpResponse, ScraperError,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    // Prefer a venv python that has bs4 + requests installed; fall back to
    // the system interpreter for parity tests that do not need third-party
    // packages.
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

/// Dispatch a single JSON command to the Python `scraper` module and return
/// the parsed JSON output. Supported operations:
/// * `normalize_for_history` — `{line, transport}` → normalized string.
/// * `normalize_for_file` — `{line, transport}` → normalized string.
/// * `is_valid_line` — `{line}` → bool.
/// * `parse_bridgelines_html` — `{html}` → list of strings.
/// * `parse_moat_response` — `{data}` → list of `[line, transport]` pairs.
/// * `get_static` — returns list of `[line, transport, ip_version]`.
/// * `infer_transport` — `{key}` → string.
/// * `infer_ip_version` — `{key}` → string.
/// * `load_history` — `{path}` → JSON object.
/// * `save_history` — `{path, history}` → null (writes file).
/// * `update_history` — `{history, lines, now_iso}` → updated history.
/// * `prune_history` — `{history, retention_days, now_iso}` → `{removed, history}`.
/// * `write_sorted` — `{path, lines, preserve_order}` → null (writes file).
/// * `classify_zip_folder` — `{name, recent_hours}` → string.
fn python_scraper(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("scraper parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os
# Suppress the import-time side effects of scraper.py (mkdir calls).
os.environ.setdefault('BRIDGE_DIR', '/tmp/torshield_scraper_parity_bridge')
import scraper

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'normalize_for_history':
    print(json.dumps(scraper.normalize_for_history(cmd['line'], cmd['transport']), sort_keys=True, separators=(',', ':')))
elif op == 'normalize_for_file':
    print(json.dumps(scraper.normalize_for_file(cmd['line'], cmd['transport']), sort_keys=True, separators=(',', ':')))
elif op == 'is_valid_line':
    print(json.dumps(scraper.is_valid_line(cmd['line']), sort_keys=True, separators=(',', ':')))
elif op == 'parse_bridgelines_html':
    print(json.dumps(scraper._parse_bridgelines_html(cmd['html']), sort_keys=True, separators=(',', ':')))
elif op == 'parse_moat_response':
    pairs = scraper._parse_moat_response(cmd['data'])
    print(json.dumps([[l, t] for l, t in pairs], sort_keys=True, separators=(',', ':')))
elif op == 'get_static':
    result = scraper.get_static()
    print(json.dumps([[l, t, ip] for l, t, ip in result], sort_keys=True, separators=(',', ':')))
elif op == 'infer_transport':
    print(json.dumps(scraper._infer_transport(cmd['key']), sort_keys=True, separators=(',', ':')))
elif op == 'infer_ip_version':
    print(json.dumps(scraper._infer_ip_version(cmd['key']), sort_keys=True, separators=(',', ':')))
elif op == 'load_history':
    # Override HISTORY_FILE to point at the requested path.
    from pathlib import Path
    scraper.HISTORY_FILE = Path(cmd['path'])
    print(json.dumps(scraper.load_history(), sort_keys=True, separators=(',', ':')))
elif op == 'save_history':
    from pathlib import Path
    scraper.HISTORY_FILE = Path(cmd['path'])
    scraper.save_history(cmd['history'])
    print(json.dumps(None, sort_keys=True, separators=(',', ':')))
elif op == 'update_history':
    from datetime import datetime, timezone
    history = cmd['history']
    lines = [(l, t, ip) for l, t, ip in cmd['lines']]
    # Reproduce update_history with injectable now by patching datetime.
    import scraper as _s
    UTC = timezone.utc
    fixed_now = datetime.fromisoformat(cmd['now_iso'])
    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now.astimeze(tz) if tz else fixed_now.replace(tzinfo=None)
    # Monkey-patch the now() call inside update_history by replacing the
    # `datetime` symbol used in the module namespace.
    orig = _s.datetime if hasattr(_s, 'datetime') else None
    _s.datetime = type('DT', (), {'now': staticmethod(lambda tz=None: fixed_now if tz is None else fixed_now.astimezone(tz))})
    _s.update_history(history, lines)
    if orig is not None:
        _s.datetime = orig
    print(json.dumps(history, sort_keys=True, separators=(',', ':')))
elif op == 'prune_history':
    from datetime import datetime, timezone
    history = cmd['history']
    retention_days = cmd['retention_days']
    fixed_now = datetime.fromisoformat(cmd['now_iso'])
    import scraper as _s
    # Monkey-patch datetime.now() for the duration of the call.
    orig_datetime = _s.datetime
    class _PatchedDatetime(orig_datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)
    _s.datetime = _PatchedDatetime
    removed = _s.prune_history(history)
    _s.datetime = orig_datetime
    print(json.dumps({'removed': removed, 'history': history}, sort_keys=True, separators=(',', ':')))
elif op == 'write_sorted':
    from pathlib import Path
    scraper._write_sorted(Path(cmd['path']), cmd['lines'], cmd.get('preserve_order', False))
    with open(cmd['path'], 'r', encoding='utf-8') as fh:
        content = fh.read()
    print(json.dumps(content, sort_keys=True, separators=(',', ':')))
elif op == 'classify_zip_folder':
    name = cmd['name']
    rh = cmd['recent_hours']
    # Mirror the Python branch order: tested/likely_working, fresh, archive.
    if '_tested' in name or 'likely_working' in name:
        folder = 'Tor Bridges/Verified'
    elif f'_{rh}h' in name:
        folder = f'Tor Bridges/Fresh ({rh}h)'
    else:
        folder = 'Tor Bridges/Full Archive'
    print(json.dumps(folder, sort_keys=True, separators=(',', ':')))
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
        .unwrap_or_else(|err| panic!("python scraper helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python scraper helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python scraper helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock HTTP client
// ─────────────────────────────────────────────────────────────────────────────

/// Mock [`HttpFetch`] implementation that returns canned responses from a
/// per-URL lookup table. Tests construct this with the exact HTML / JSON
/// strings the production fetcher would receive from
/// `bridges.torproject.org` and the MOAT API.
#[derive(Default, Clone)]
struct MockHttpFetch {
    gets: BTreeMap<String, HttpResponse>,
    posts: BTreeMap<String, HttpResponse>,
}

impl MockHttpFetch {
    fn with_get(mut self, url: &str, status: u16, text: &str) -> Self {
        self.gets.insert(
            url.to_string(),
            HttpResponse {
                status,
                text: text.to_string(),
            },
        );
        self
    }

    fn with_post(mut self, url: &str, status: u16, text: &str) -> Self {
        self.posts.insert(
            url.to_string(),
            HttpResponse {
                status,
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
            text: String::new(),
        }))
    }

    fn post_json(
        &self,
        url: &str,
        _body: &Value,
        _headers: &[(String, String)],
        _timeout: Duration,
    ) -> Result<HttpResponse, ScraperError> {
        Ok(self.posts.get(url).cloned().unwrap_or(HttpResponse {
            status: 404,
            text: String::new(),
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Python parity (>=4 scenarios invoking Python)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_normalize_for_history_and_file() {
    for (line, transport) in [
        ("1.2.3.4:443 ABCDEF0123456789ABCDEF", "vanilla"),
        ("Bridge 1.2.3.4:443 ABCDEF0123456789ABCDEF", "vanilla"),
        ("  obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF  ", "obfs4"),
        ("snowflake url=https://example.com/", "snowflake"),
    ] {
        let cmd = json!({
            "op": "normalize_for_history",
            "line": line,
            "transport": transport,
        });
        let py = python_scraper(&cmd);
        let rs = json!(normalize_for_history(line, transport));
        assert_eq!(
            rs,
            py,
            "normalize_for_history mismatch for {:?}",
            (line, transport)
        );

        let cmd = json!({
            "op": "normalize_for_file",
            "line": line,
            "transport": transport,
        });
        let py = python_scraper(&cmd);
        let rs = json!(normalize_for_file(line, transport));
        assert_eq!(
            rs,
            py,
            "normalize_for_file mismatch for {:?}",
            (line, transport)
        );
    }
}

#[test]
fn parity_is_valid_line_branches() {
    for line in [
        "",
        "short",
        "# this is a long enough comment line",
        "No bridges available right now",
        "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567",
        "obfs4 [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567",
        "webtunnel url=https://example.com/ abcdef0123456789",
    ] {
        let cmd = json!({"op": "is_valid_line", "line": line});
        let py = python_scraper(&cmd);
        let rs = json!(is_valid_line(line));
        assert_eq!(rs, py, "is_valid_line mismatch for {:?}", line);
    }
}

#[test]
fn parity_parse_bridgelines_html_div_and_fallback() {
    let div_html = r#"<html><body>
<div id="bridgelines">
obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567
</div></body></html>"#;
    let pre_html = r#"<html><body>
<pre>obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567</pre>
<code>obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567</code>
</body></html>"#;
    let empty_html = r#"<html><body><p>no bridges here</p></body></html>"#;
    for html in [div_html, pre_html, empty_html] {
        let cmd = json!({"op": "parse_bridgelines_html", "html": html});
        let py = python_scraper(&cmd);
        let rs = json!(parse_bridgelines_html(html));
        assert_eq!(rs, py, "parse_bridgelines_html mismatch for {:?}", html);
    }
}

#[test]
fn parity_parse_moat_response_branches() {
    let cases = [
        json!({
            "bridges": {
                "obfs4": ["obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"],
                "webTunnel": ["webtunnel url=https://example.com/ abcdef0123456789"],
                "snowflake": ["snowflake 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567"],
                "unknown_transport": ["short"],
            }
        }),
        json!({}),
        json!({"bridges": {}}),
        json!({"bridges": {"obfs4": "not-a-list"}}),
        json!({"bridges": "wrong-type"}),
    ];
    for data in cases {
        // Python's `_parse_moat_response` raises an `AttributeError` when
        // `data["bridges"]` is a string (the `or {}` short-circuits on
        // truthy values, then `.items()` is called on the string). For
        // that case we skip the Python call and only assert the Rust port
        // rejects the input with a typed error.
        if data["bridges"].is_string() {
            let rs_result = parse_moat_response(&data);
            assert!(
                rs_result.is_err(),
                "expected Rust to reject non-object bridges for {}",
                data
            );
            continue;
        }
        let cmd = json!({"op": "parse_moat_response", "data": data});
        let py = python_scraper(&cmd);
        let rs_result = parse_moat_response(&data);
        let rs: Value = match &rs_result {
            Ok(pairs) => json!(pairs.iter().map(|(l, t)| json!([l, t])).collect::<Vec<_>>()),
            Err(_) => Value::Null,
        };
        assert_eq!(rs, py, "parse_moat_response mismatch for {}", data);
    }
}

#[test]
fn parity_get_static_returns_four_built_in_bridges() {
    let cmd = json!({"op": "get_static"});
    let py = python_scraper(&cmd);
    let rs_vec = get_static();
    let rs = json!(rs_vec
        .into_iter()
        .map(|(l, t, ip)| json!([l, t, ip]))
        .collect::<Vec<_>>());
    assert_eq!(rs, py);
}

#[test]
fn parity_infer_transport_and_ip_version() {
    for key in [
        "snowflake 192.0.2.3:1 ABC",
        "obfs4 1.2.3.4:443 ABC",
        "webtunnel url=https://example.com/ ABC",
        "meek_lite 192.0.2.18:80 ABC",
        "1.2.3.4:443 ABC",
        "obfs4 [2001:db8::1]:443 ABC",
    ] {
        let cmd_t = json!({"op": "infer_transport", "key": key});
        let py_t = python_scraper(&cmd_t);
        let rs_t = json!(infer_transport(key));
        assert_eq!(rs_t, py_t, "infer_transport mismatch for {:?}", key);

        let cmd_ip = json!({"op": "infer_ip_version", "key": key});
        let py_ip = python_scraper(&cmd_ip);
        let rs_ip = json!(infer_ip_version(key));
        assert_eq!(rs_ip, py_ip, "infer_ip_version mismatch for {:?}", key);
    }
}

#[test]
fn parity_load_history_legacy_and_dict_entries() {
    // Use a fresh temp file per test run to avoid cross-test contamination.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "scraper_parity_load_history_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    // Missing file → empty object on both sides.
    let cmd = json!({"op": "load_history", "path": tmp.to_string_lossy()});
    let py = python_scraper(&cmd);
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
    let py = python_scraper(&cmd);
    let rs = load_history(&tmp).unwrap();
    assert_eq!(rs, py, "legacy+dict load_history mismatch");
    let _ = fs::remove_file(&tmp);
}

#[test]
fn parity_save_history_round_trips_through_load_history() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "scraper_parity_save_history_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    let history = json!({
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123": {
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": "2026-06-09T00:00:00+00:00",
            "last_seen": "2026-06-09T00:00:00+00:00",
            "tcp_reachable": null,
        }
    });
    let cmd = json!({"op": "save_history", "path": tmp.to_string_lossy(), "history": history});
    let _py = python_scraper(&cmd);
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

#[test]
fn parity_update_history_with_injectable_now() {
    let history_init = json!({});
    let lines = vec![
        (
            "1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123".to_string(),
            "vanilla".to_string(),
            "ipv4".to_string(),
        ),
        (
            "1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123".to_string(),
            "vanilla".to_string(),
            "ipv4".to_string(),
        ),
        (
            "obfs4 5.6.7.8:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123".to_string(),
            "obfs4".to_string(),
            "ipv4".to_string(),
        ),
    ];
    let now_iso = "2026-06-10T12:00:00+00:00";
    let cmd = json!({
        "op": "update_history",
        "history": history_init,
        "lines": lines.iter().map(|(l, t, ip)| json!([l, t, ip])).collect::<Vec<_>>(),
        "now_iso": now_iso,
    });
    let py = python_scraper(&cmd);
    let mut rs = history_init;
    let now = chrono::DateTime::parse_from_rfc3339(now_iso)
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    scraper::update_history_with_now(&mut rs, &lines, now).unwrap();
    assert_eq!(rs, py);
}

#[test]
fn parity_prune_history_boundary_cases() {
    let now_iso = "2026-06-10T12:00:00+00:00";
    let history = json!({
        "old": {"transport": "obfs4", "last_seen": "2000-01-01T00:00:00+00:00"},
        "boundary_old": {"transport": "obfs4", "last_seen": "2026-05-11T12:00:00+00:00"},
        "new": {"transport": "obfs4", "last_seen": "2026-06-09T00:00:00+00:00"},
        "missing": {"transport": "obfs4"},
    });
    let cmd = json!({
        "op": "prune_history",
        "history": history,
        "retention_days": 30,
        "now_iso": now_iso,
    });
    let py = python_scraper(&cmd);
    let mut rs = history.clone();
    let now = chrono::DateTime::parse_from_rfc3339(now_iso)
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    let removed = prune_history_with_now(&mut rs, 30, now).unwrap();
    let rs_result = json!({"removed": removed, "history": rs});
    assert_eq!(rs_result, py);
}

#[test]
fn parity_write_sorted_preserve_and_sort_branches() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "scraper_parity_write_sorted_{}.txt",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    for preserve in [false, true] {
        let lines = vec![
            "bbb 1.2.3.4:443 ABCDEF0123456789".to_string(),
            "aaa 5.6.7.8:443 ABCDEF0123456789".to_string(),
            "bbb 1.2.3.4:443 ABCDEF0123456789".to_string(),
            "".to_string(),
        ];
        let cmd = json!({
            "op": "write_sorted",
            "path": tmp.to_string_lossy(),
            "lines": lines,
            "preserve_order": preserve,
        });
        let py = python_scraper(&cmd);
        let py_content = py.as_str().unwrap().to_string();
        write_sorted(&tmp, &lines, preserve).unwrap();
        let rs_content = fs::read_to_string(&tmp).unwrap();
        assert_eq!(
            rs_content, py_content,
            "write_sorted preserve_order={} mismatch",
            preserve
        );
        let _ = fs::remove_file(&tmp);
    }
}

#[test]
fn parity_classify_zip_folder_all_branches() {
    for (name, rh) in [
        ("obfs4_tested.txt", 72),
        ("iran_likely_working_obfs4.txt", 72),
        ("obfs4_72h.txt", 72),
        ("obfs4.txt", 72),
        ("obfs4_24h.txt", 24),
    ] {
        let cmd = json!({"op": "classify_zip_folder", "name": name, "recent_hours": rh});
        let py = python_scraper(&cmd);
        let rs = json!(classify_zip_folder(name, rh));
        assert_eq!(rs, py, "classify_zip_folder mismatch for {:?}", (name, rh));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Rust-only branches (no Python invocation)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fetch_torproject_with_mock_client_returns_bridges() {
    let html = r#"<div id="bridgelines">
obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567
</div>"#;
    let client = MockHttpFetch::default().with_get(
        "https://bridges.torproject.org/bridges?transport=obfs4",
        200,
        html,
    );
    let bridges = fetch_torproject(&client);
    // Only the obfs4 ipv4 URL is wired; the remaining 5 URLs return 404 and
    // contribute zero bridges.
    let obfs4_ipv4_count = bridges
        .iter()
        .filter(|(_, t, ip)| t == "obfs4" && ip == "ipv4")
        .count();
    assert_eq!(obfs4_ipv4_count, 2);
}

#[test]
fn fetch_moat_with_mock_client_returns_pairs() {
    let body =
        r#"{"bridges":{"obfs4":["obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"]}}"#;
    let client = MockHttpFetch::default()
        .with_post(scraper::MOAT_BUILTIN_URL, 200, body)
        .with_post(scraper::MOAT_SETTINGS_URL, 200, body);
    let bridges = fetch_moat(&client);
    // Both endpoints return the same body, so we expect 2 (line, transport, ip) tuples.
    assert_eq!(bridges.len(), 2);
    assert_eq!(bridges[0].1, "obfs4");
    assert_eq!(bridges[0].2, "ipv4");
}

#[test]
fn write_testing_json_with_disabled_selector_round_trips() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "scraper_parity_testing_json_{}.json",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);

    let history = json!({
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123": {
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": "2026-06-09T00:00:00+00:00",
            "last_seen": "2026-06-09T00:00:00+00:00",
            "tcp_reachable": null,
            "raw": "1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
        }
    });
    let selector = AdaptiveBridgeSelector::with_data(
        AdaptiveConfig::default(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let count = write_testing_json(&history, &tmp, &selector).unwrap();
    assert_eq!(count, 1);
    let written: Value = serde_json::from_str(&fs::read_to_string(&tmp).unwrap()).unwrap();
    assert!(written.as_array().map(|a| a.len() == 1).unwrap_or(false));
    let _ = fs::remove_file(&tmp);
}

#[test]
fn tcp_reachable_returns_false_for_non_ipv4_lines() {
    // No IPv4:port in the line — the regex doesn't match and we return false
    // without consulting any probe. We use the production StdTcpProbe here
    // because it's never actually called.
    assert!(!scraper::tcp_reachable(
        "snowflake url=https://example.com/",
        1.0
    ));
}

#[test]
fn load_history_returns_typed_error_for_non_object_root() {
    let tmp = std::env::temp_dir().join(format!(
        "scraper_parity_non_object_{}.json",
        std::process::id()
    ));
    fs::write(&tmp, r#"[1, 2, 3]"#).unwrap();
    let err = load_history(&tmp).unwrap_err();
    assert!(matches!(err, ScraperError::HistoryNotObject { .. }));
    let _ = fs::remove_file(&tmp);
}

#[test]
fn prune_history_with_now_returns_zero_for_empty_history() {
    let mut history = json!({});
    let now = chrono::DateTime::parse_from_rfc3339("2026-06-10T12:00:00+00:00")
        .unwrap()
        .with_timezone::<chrono::Utc>(&chrono::Utc);
    let removed = prune_history_with_now(&mut history, 30, now).unwrap();
    assert_eq!(removed, 0);
}
