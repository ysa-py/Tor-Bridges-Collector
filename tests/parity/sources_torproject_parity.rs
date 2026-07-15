// Parity test: `sources/torproject.py` vs `sources_torproject.rs`.
//
// Runs both the Python original and the Rust port on the same fixed input
// set and asserts identical output for every branch logged in the Phase 0
// contract.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;
use torshield_ir_ultra::scraper::{HttpFetch, HttpResponse, ScraperError};
use torshield_ir_ultra::sources_torproject as rs;

fn python_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_python_is_valid_line(line: &str) -> bool {
    let script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
print(json.dumps(m._is_valid_line({line:?})))
"#,
        root = python_root().display().to_string(),
        line = line,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python _is_valid_line failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str::<bool>(&s).expect("python output must be a bool")
}

fn run_python_parse_html(html: &str) -> Vec<String> {
    let script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
print(json.dumps(m._parse_html({html:?})))
"#,
        root = python_root().display().to_string(),
        html = html,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python _parse_html failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str::<Vec<String>>(&s).expect("python output must be a list")
}

struct MockHttp {
    responses: std::collections::HashMap<String, HttpResponse>,
}
impl HttpFetch for MockHttp {
    fn get(&self, url: &str, _timeout: Duration) -> Result<HttpResponse, ScraperError> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| ScraperError::Http {
                url: url.to_string(),
                message: "mock 404".to_string(),
            })
    }
    fn post_json(
        &self,
        _url: &str,
        _body: &Value,
        _headers: &[(String, String)],
        _timeout: Duration,
    ) -> Result<HttpResponse, ScraperError> {
        Err(ScraperError::Http {
            url: String::new(),
            message: "POST not supported".to_string(),
        })
    }
}

#[test]
fn parity_targets_count_and_shape() {
    // Python `TARGETS` is a list of 6 quadruples. Rust `TARGETS` is a slice
    // of 6 tuples. Both must have the same length and the same URL strings.
    let py_script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
print(json.dumps([(t[0], t[2], t[3]) for t in m.TARGETS]))
"#,
        root = python_root().display().to_string(),
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .output()
        .expect("python3 must be installed");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let py_targets: Vec<(String, String, String)> =
        serde_json::from_str(&s).expect("python output must be a list of triples");

    assert_eq!(py_targets.len(), rs::TARGETS.len());
    for (i, (py, rs_t)) in py_targets.iter().zip(rs::TARGETS.iter()).enumerate() {
        assert_eq!(py.0, rs_t.0, "URL mismatch at index {i}");
        assert_eq!(py.1, rs_t.2, "transport mismatch at index {i}");
        assert_eq!(py.2, rs_t.3, "ip_version mismatch at index {i}");
    }
}

#[test]
fn parity_user_agents_count() {
    let py_script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
print(json.dumps(len(m._USER_AGENTS)))
"#,
        root = python_root().display().to_string(),
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .output()
        .expect("python3 must be installed");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let py_count: usize = serde_json::from_str(&s).unwrap();
    assert_eq!(py_count, rs::USER_AGENTS.len());
}

#[test]
fn parity_is_valid_line_short_lines() {
    for line in &["", "short", "123456789"] {
        let py = run_python_is_valid_line(line);
        let rs_v = rs::is_valid_line(line);
        assert_eq!(py, rs_v, "is_valid_line({line:?})");
    }
}

#[test]
fn parity_is_valid_line_no_bridges_message() {
    let line = "No bridges available right now";
    let py = run_python_is_valid_line(line);
    let rs_v = rs::is_valid_line(line);
    assert_eq!(py, rs_v);
    assert!(!py);
}

#[test]
fn parity_is_valid_line_comment_lines() {
    let line = "# this is a comment line";
    let py = run_python_is_valid_line(line);
    let rs_v = rs::is_valid_line(line);
    assert_eq!(py, rs_v);
    assert!(!py);
}

#[test]
fn parity_is_valid_line_ipv4() {
    let line = "obfs4 1.2.3.4:443 cert=abc";
    let py = run_python_is_valid_line(line);
    let rs_v = rs::is_valid_line(line);
    assert_eq!(py, rs_v);
    assert!(py);
}

#[test]
fn parity_is_valid_line_ipv6() {
    let line = "obfs4 [2001:db8::1]:443 cert=abc";
    let py = run_python_is_valid_line(line);
    let rs_v = rs::is_valid_line(line);
    assert_eq!(py, rs_v);
    assert!(py);
}

#[test]
fn parity_is_valid_line_https_url() {
    let line = "webtunnel url=https://example.com/path";
    let py = run_python_is_valid_line(line);
    let rs_v = rs::is_valid_line(line);
    assert_eq!(py, rs_v);
    assert!(py);
}

#[test]
fn parity_parse_html_bridgelines_div() {
    let html = r#"<html><body><div id="bridgelines">obfs4 1.2.3.4:443 cert=abc
obfs4 5.6.7.8:443 cert=def
# comment line
</div></body></html>"#;
    let py = run_python_parse_html(html);
    let rs_v = rs::parse_html(html);
    assert_eq!(py, rs_v);
    assert_eq!(py.len(), 2);
}

#[test]
fn parity_parse_html_pre_fallback() {
    let html = r#"<html><body><pre>obfs4 1.2.3.4:443 cert=abc
obfs4 5.6.7.8:443 cert=def
</pre></body></html>"#;
    let py = run_python_parse_html(html);
    let rs_v = rs::parse_html(html);
    assert_eq!(py, rs_v);
    assert_eq!(py.len(), 2);
}

#[test]
fn parity_parse_html_code_fallback() {
    let html = r#"<html><body><code>webtunnel url=https://example.com/x
</code></body></html>"#;
    let py = run_python_parse_html(html);
    let rs_v = rs::parse_html(html);
    assert_eq!(py, rs_v);
    assert_eq!(py.len(), 1);
}

#[test]
fn parity_parse_html_empty_when_no_bridgelines() {
    let html = r#"<html><body><p>no bridges here</p></body></html>"#;
    let py = run_python_parse_html(html);
    let rs_v = rs::parse_html(html);
    assert_eq!(py, rs_v);
    assert!(py.is_empty());
}

#[test]
fn parity_fetch_one_with_mock_extracts_bridges() {
    // Both sides: given an HTML response, both should return the same
    // parsed bridge lines. The Rust side uses a mock HttpFetch; the Python
    // side uses a monkey-patched `requests.get` returning the same body.
    let html = r#"<html><body><div id="bridgelines">obfs4 1.2.3.4:443 cert=abc
obfs4 5.6.7.8:443 cert=def
</div></body></html>"#;
    let url = "https://bridges.torproject.org/bridges?transport=obfs4";

    // Rust side
    let mut responses = std::collections::HashMap::new();
    responses.insert(
        url.to_string(),
        HttpResponse {
            status: 200,
            text: html.to_string(),
        },
    );
    let client = MockHttp { responses };
    let rs_lines = rs::fetch_one(&client, url, "obfs4", Some(0)).unwrap();

    // Python side
    let py_script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
class FakeResp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP %d" % self.status_code)
class FakeSession:
    def get(self, url, **kw):
        return FakeResp({html:?})
m.requests.Session = lambda: FakeSession()
# Also patch requests.get (used inside _fetch_one directly)
m.requests.get = lambda url, **kw: FakeResp({html:?})
lines = m._fetch_one({url:?}, "obfs4")
print(json.dumps(lines))
"#,
        root = python_root().display().to_string(),
        html = html,
        url = url,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python _fetch_one failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let py_lines: Vec<String> = serde_json::from_str(&s).unwrap();

    assert_eq!(py_lines, rs_lines, "fetch_one parity mismatch");
    assert_eq!(py_lines.len(), 2);
}

#[test]
fn parity_fetch_one_handles_500_status() {
    // Both sides should treat HTTP 500 as an error and return an empty
    // list (Python) / Err (Rust). The Python `fetch_one` catches Exception
    // and returns `[]`; the Rust port returns an `Err`.
    let url = "https://example.com/x";
    let html = "Internal Server Error";

    // Python side
    let py_script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import sources.torproject as m
class FakeResp:
    def __init__(self, text, status_code=500):
        self.text = text
        self.status_code = status_code
    def raise_for_status(self):
        raise Exception("HTTP 500")
m.requests.get = lambda url, **kw: FakeResp({html:?})
lines = m._fetch_one({url:?}, "obfs4")
print(json.dumps(lines))
"#,
        root = python_root().display().to_string(),
        html = html,
        url = url,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .output()
        .expect("python3 must be installed");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let py_lines: Vec<String> = serde_json::from_str(&s).unwrap();
    // Python returns [] on HTTP 500 (caught exception).
    assert!(py_lines.is_empty());

    // Rust side: should return Err
    let mut responses = std::collections::HashMap::new();
    responses.insert(
        url.to_string(),
        HttpResponse {
            status: 500,
            text: html.to_string(),
        },
    );
    let client = MockHttp { responses };
    let result = rs::fetch_one(&client, url, "obfs4", Some(0));
    assert!(result.is_err(), "Rust should error on HTTP 500");
}
