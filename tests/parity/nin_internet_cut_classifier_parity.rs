// Parity tests for `src/nin_internet_cut_classifier.rs` vs
// `nin_internet_cut_classifier.py`.
//
// Two test groups:
// 1. Pure-function parity — invokes the Python `_parse_bridge` and
//    `_classify` helpers directly via `std::process::Command` on fixed
//    inputs and asserts identical JSON output.
// 2. End-to-end pipeline parity — runs both the Python `main()` and the
//    Rust [`NINInternetCutClassifier::run`] on the same temp-directory
//    bridge sources with a mocked clock and compares the output files and
//    report JSON byte-for-byte.
//
// Pure-Rust branch tests cover every documented branch of `classify` plus
// the empty-input and threshold-boundary edge cases.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::nin_internet_cut_classifier::{
    classify, parse_bridge, Clock, IranCidrTable, NINError, NINInternetCutClassifier, ParsedBridge,
    IRAN_CDN_CIDR_RAW, NIN_SAFE_PORTS,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
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

/// Dispatch a single JSON command to the Python `nin_internet_cut_classifier`
/// module and return the parsed JSON output. The Python helper supports four
/// operations:
/// * `parse_bridge` — call `_parse_bridge(line)`.
/// * `classify` — call `_classify(parsed)`.
/// * `load_all_bridges` — patch `BRIDGE_SOURCES` to point at a temp file and
///   call `_load_all_bridges()`.
/// * `main` — patch `BRIDGE_SOURCES`, output paths, and `datetime` for a
///   deterministic clock, then call `main()` and return all outputs.
fn python_nin(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("nin parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os, tempfile, shutil
from pathlib import Path
from datetime import datetime, timezone
import nin_internet_cut_classifier as mod

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'parse_bridge':
    line = cmd['line']
    result = mod._parse_bridge(line)
    print(json.dumps(result, sort_keys=True))

elif op == 'classify':
    bridge = cmd['bridge']
    tier = mod._classify(bridge)
    print(json.dumps({'tier': tier, 'bridge': bridge}, sort_keys=True))

elif op == 'load_all_bridges':
    tmpdir = tempfile.mkdtemp()
    try:
        files = cmd['files']  # list of {path: rel, content: str}
        paths = []
        for entry in files:
            full = os.path.join(tmpdir, entry['path'])
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w') as f:
                f.write(entry['content'])
            paths.append(Path(full))
        mod.BRIDGE_SOURCES = paths
        lines = mod._load_all_bridges()
        print(json.dumps({'lines': lines}, sort_keys=True))
    finally:
        shutil.rmtree(tmpdir)

elif op == 'main':
    tmpdir = tempfile.mkdtemp()
    try:
        files = cmd['files']
        paths = []
        for entry in files:
            full = os.path.join(tmpdir, entry['path'])
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w') as f:
                f.write(entry['content'])
            paths.append(Path(full))
        mod.BRIDGE_SOURCES = paths
        mod.GREEN_OUT = Path(os.path.join(tmpdir, 'green.txt'))
        mod.YELLOW_OUT = Path(os.path.join(tmpdir, 'yellow.txt'))
        mod.COMBINED_OUT = Path(os.path.join(tmpdir, 'combined.txt'))
        mod.REPORT_OUT = Path(os.path.join(tmpdir, 'report.json'))

        # Mock datetime to a fixed timestamp.
        fixed = datetime.fromisoformat(cmd['now'])
        class _MockDT:
            @classmethod
            def now(cls, tz=None):
                return fixed
        mod.datetime = _MockDT

        rc = mod.main()
        green = open(mod.GREEN_OUT).read()
        yellow = open(mod.YELLOW_OUT).read()
        combined = open(mod.COMBINED_OUT).read()
        with open(mod.REPORT_OUT) as f:
            report = json.load(f)
        print(json.dumps({
            'rc': rc,
            'green': green,
            'yellow': yellow,
            'combined': combined,
            'report': report,
        }, sort_keys=True))
    finally:
        shutil.rmtree(tmpdir)

else:
    raise SystemExit('unknown op: ' + op)
"#
    .to_string();
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .arg(&cmd_json)
        .output()
        .unwrap_or_else(|err| panic!("python nin helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python nin helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python nin helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Temp directory helper
// ─────────────────────────────────────────────────────────────────────────────

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_nin_internet_cut_classifier_parity_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn fixed_clock(iso: &str) -> (Clock, DateTime<Utc>) {
    let dt = DateTime::parse_from_rfc3339(iso)
        .unwrap_or_else(|err| panic!("fixed clock iso must parse: {err}"))
        .with_timezone(&Utc);
    (Arc::new(move || dt), dt)
}

/// Write a single bridge source file in `dir` with the given `content`.
fn write_source(dir: &Path, rel: &str, content: &str) -> PathBuf {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create source parent");
    }
    fs::write(&path, content).expect("write source file");
    path
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_bridge Python parity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_parse_bridge_handles_various_lines() {
    let lines = [
        "obfs4 1.2.3.4:443 cert=abc url=https://www.aparat.com/path",
        "snowflake 192.0.2.1:443",
        "webtunnel 192.0.2.1:443 url=https://digikala.com",
        "vanilla 1.2.3.4:9001",
        "obfs4 1.2.3.4:9001",
        "meek_lite 1.2.3.4:443",
        "meek-lite 1.2.3.4:443",
        "obfs4 1.2.3.4:443 cert=abc url=https://sub.digikala.com",
        "obfs4 5.200.64.5:443 cert=abc",
        "obfs4 [2001:db8::1]:443 cert=abc",
        "obfs4 999.999.999.999:443 cert=abc",
        "obfs4 1.2.3.4:443",
        "webtunnel 1.2.3.4:443",
        "unknown_transport 1.2.3.4:443",
        "  obfs4 1.2.3.4:443  ",
        "# comment line",
        "",
        "obfs4notransport 1.2.3.4:443",
        "obfs4\t1.2.3.4:443",
        "obfs4  1.2.3.4:443",
        "obfs4 1.2.3.4.5:443",
        "obfs4 1.2.3.4:5",
        "obfs4 1.2.3.4:123456",
        "obfs4 1.2.3.4:65535",
        "obfs4 1.2.3.4:65536",
        "OBFS4 1.2.3.4:443",
        "obfs4 1.2.3.04:443",
        "obfs4 11.22.33.44:8080",
    ];

    for line in lines {
        let py = python_nin(&json!({"op": "parse_bridge", "line": line}));
        // Python's `None` serializes to JSON `null`; treat Rust's `None` as
        // equivalent to `Value::Null`.
        let rs_value = parse_bridge(line)
            .map(|p| p.to_json())
            .unwrap_or(Value::Null);
        assert_eq!(rs_value, py, "parse_bridge mismatch for line: {line:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// classify Python parity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_classify_branches_match_python() {
    let cidrs = IranCidrTable::new();
    // (line, expected_tier)
    let cases: &[(&str, &str)] = &[
        // GREEN transports
        ("snowflake 192.0.2.1:443", "GREEN"),
        ("meek_lite 192.0.2.1:443", "GREEN"),
        ("meek-lite 192.0.2.1:443", "GREEN"),
        // webtunnel variants
        (
            "webtunnel 1.2.3.4:443 url=https://www.aparat.com/x",
            "GREEN",
        ),
        ("webtunnel 1.2.3.4:443 url=https://aparat.com", "GREEN"),
        (
            "webtunnel 1.2.3.4:443 url=https://sub.digikala.com",
            "GREEN",
        ),
        ("webtunnel 1.2.3.4:443 url=https://fastly.net", "YELLOW"),
        ("webtunnel 1.2.3.4:443 url=https://sub.fastly.net", "YELLOW"),
        ("webtunnel 1.2.3.4:443 url=https://example.com", "YELLOW"),
        ("webtunnel 1.2.3.4:443", "RED"),
        // obfs4 variants
        ("obfs4 1.2.3.4:443 cert=abc", "YELLOW"),
        ("obfs4 5.200.64.5:443 cert=abc", "GREEN"), // Iran IP
        ("obfs4 104.16.0.5:443 cert=abc", "GREEN"), // Cloudflare IR
        ("obfs4 1.2.3.4:80 cert=abc", "YELLOW"),
        ("obfs4 1.2.3.4:8080 cert=abc", "YELLOW"),
        ("obfs4 1.2.3.4:8443 cert=abc", "YELLOW"),
        ("obfs4 1.2.3.4:9001 cert=abc", "RED"),
        ("obfs4 999.999.999.999:443 cert=abc", "YELLOW"), // invalid IP
        ("obfs4 [2001:db8::1]:443 cert=abc", "YELLOW"),   // IPv6
        // RED transports
        ("vanilla 1.2.3.4:9001", "RED"),
        ("obfs3 1.2.3.4:443", "RED"),
        // unknown transport → vanilla → RED
        ("unknown 1.2.3.4:443", "RED"),
    ];

    for (line, expected_tier) in cases {
        let parsed =
            parse_bridge(line).unwrap_or_else(|| panic!("parse_bridge returned None for {line:?}"));
        let py_result = python_nin(&json!({"op": "classify", "bridge": parsed.to_json()}));
        let py_tier = py_result["tier"].as_str().unwrap();
        let rs_tier = classify(&parsed, &cidrs);
        assert_eq!(
            rs_tier, *expected_tier,
            "Rust tier mismatch for line: {line:?}"
        );
        assert_eq!(
            py_tier, *expected_tier,
            "Python tier mismatch for line: {line:?}"
        );
        assert_eq!(
            rs_tier, py_tier,
            "Rust vs Python tier mismatch for line: {line:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_all_bridges Python parity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_load_all_bridges_dedup_and_skip() {
    let dir = case_dir("load_all_bridges");
    // Two source files with overlapping + duplicate + comment + empty lines.
    let file_a = write_source(
        &dir,
        "a.txt",
        "snowflake 192.0.2.1:443\nobfs4 1.2.3.4:443 cert=abc\n# comment\n\nsnowflake 192.0.2.1:443\n",
    );
    let file_b = write_source(
        &dir,
        "b.txt",
        "obfs4 1.2.3.4:443 cert=abc\nvanilla 5.6.7.8:9001\n",
    );
    let files_json = json!({
        "op": "load_all_bridges",
        "files": [
            {"path": "a.txt", "content": "snowflake 192.0.2.1:443\nobfs4 1.2.3.4:443 cert=abc\n# comment\n\nsnowflake 192.0.2.1:443\n"},
            {"path": "b.txt", "content": "obfs4 1.2.3.4:443 cert=abc\nvanilla 5.6.7.8:9001\n"},
        ]
    });
    let py = python_nin(&files_json);
    let py_lines: Vec<String> = py["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![file_a, file_b],
        dir.join("green.txt"),
        dir.join("yellow.txt"),
        dir.join("combined.txt"),
        dir.join("report.json"),
        Arc::new(|| Utc.timestamp_opt(0, 0).unwrap()),
    );
    let rs_lines = classifier
        .load_all_bridges()
        .expect("load_all_bridges succeeds");

    assert_eq!(rs_lines, py_lines);
    assert_eq!(
        rs_lines,
        vec![
            "snowflake 192.0.2.1:443",
            "obfs4 1.2.3.4:443 cert=abc",
            "vanilla 5.6.7.8:9001",
        ]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// main() end-to-end Python parity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_main_with_mixed_bridges() {
    let dir = case_dir("main_mixed");
    let now_iso = "2024-01-01T12:00:00.123456+00:00";
    let (clock, _) = fixed_clock(now_iso);

    let content = [
        "snowflake 192.0.2.1:443",
        "obfs4 1.2.3.4:443 cert=abc",
        "vanilla 5.6.7.8:9001",
        "webtunnel 1.2.3.4:443 url=https://www.aparat.com/path",
        "obfs4 5.200.64.5:443 cert=abc",
        "# comment line",
        "",
        "snowflake 192.0.2.1:443", // duplicate
    ]
    .join("\n")
        + "\n";

    let source_path = write_source(&dir, "bridges.txt", &content);
    let green_out = dir.join("green.txt");
    let yellow_out = dir.join("yellow.txt");
    let combined_out = dir.join("combined.txt");
    let report_out = dir.join("report.json");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![source_path],
        green_out.clone(),
        yellow_out.clone(),
        combined_out.clone(),
        report_out.clone(),
        clock,
    );
    let rc = classifier.run().expect("run succeeds");
    assert_eq!(rc, 0);

    let rs_green = fs::read_to_string(&green_out).unwrap();
    let rs_yellow = fs::read_to_string(&yellow_out).unwrap();
    let rs_combined = fs::read_to_string(&combined_out).unwrap();
    let rs_report: Value = serde_json::from_str(&fs::read_to_string(&report_out).unwrap()).unwrap();

    let py = python_nin(&json!({
        "op": "main",
        "now": now_iso,
        "files": [{"path": "bridges.txt", "content": content}],
    }));

    assert_eq!(py["rc"], json!(rc));
    assert_eq!(py["green"].as_str().unwrap(), rs_green);
    assert_eq!(py["yellow"].as_str().unwrap(), rs_yellow);
    assert_eq!(py["combined"].as_str().unwrap(), rs_combined);
    assert_eq!(py["report"], rs_report);
}

#[test]
fn parity_main_with_empty_input() {
    let dir = case_dir("main_empty");
    let now_iso = "2024-01-01T12:00:00.123456+00:00";
    let (clock, _) = fixed_clock(now_iso);

    let source_path = write_source(&dir, "bridges.txt", "");
    let green_out = dir.join("green.txt");
    let yellow_out = dir.join("yellow.txt");
    let combined_out = dir.join("combined.txt");
    let report_out = dir.join("report.json");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![source_path],
        green_out.clone(),
        yellow_out.clone(),
        combined_out.clone(),
        report_out.clone(),
        clock,
    );
    let rc = classifier.run().expect("run succeeds on empty input");
    assert_eq!(rc, 0);

    let rs_green = fs::read_to_string(&green_out).unwrap();
    let rs_yellow = fs::read_to_string(&yellow_out).unwrap();
    let rs_combined = fs::read_to_string(&combined_out).unwrap();
    let rs_report: Value = serde_json::from_str(&fs::read_to_string(&report_out).unwrap()).unwrap();

    let py = python_nin(&json!({
        "op": "main",
        "now": now_iso,
        "files": [{"path": "bridges.txt", "content": ""}],
    }));

    assert_eq!(py["rc"], json!(rc));
    assert_eq!(py["green"].as_str().unwrap(), rs_green);
    assert_eq!(py["yellow"].as_str().unwrap(), rs_yellow);
    assert_eq!(py["combined"].as_str().unwrap(), rs_combined);
    assert_eq!(py["report"], rs_report);

    // Empty-report shape sanity checks.
    assert_eq!(rs_report["total_bridges"], json!(0));
    assert_eq!(rs_report["green_count"], json!(0));
    assert_eq!(rs_report["yellow_count"], json!(0));
    assert_eq!(rs_report["red_count"], json!(0));
    assert_eq!(rs_report["note"], json!("No bridge source files found."));
    assert_eq!(rs_report["bridges"], json!([]));
    assert_eq!(rs_report["generated_at"], json!(now_iso));
}

#[test]
fn parity_main_with_no_source_files() {
    let dir = case_dir("main_no_sources");
    let now_iso = "2024-01-01T12:00:00.123456+00:00";
    let (clock, _) = fixed_clock(now_iso);

    // Point at a non-existent source file.
    let source_path = dir.join("nonexistent.txt");
    let green_out = dir.join("green.txt");
    let yellow_out = dir.join("yellow.txt");
    let combined_out = dir.join("combined.txt");
    let report_out = dir.join("report.json");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![source_path],
        green_out.clone(),
        yellow_out.clone(),
        combined_out.clone(),
        report_out.clone(),
        clock,
    );
    let rc = classifier.run().expect("run succeeds with missing source");
    assert_eq!(rc, 0);

    let rs_report: Value = serde_json::from_str(&fs::read_to_string(&report_out).unwrap()).unwrap();

    let py = python_nin(&json!({
        "op": "main",
        "now": now_iso,
        "files": [],
    }));

    assert_eq!(py["rc"], json!(rc));
    assert_eq!(py["report"], rs_report);
    assert_eq!(rs_report["note"], json!("No bridge source files found."));
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure-Rust branch tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_bridge_returns_none_for_empty_or_comment_lines() {
    assert!(parse_bridge("").is_none());
    assert!(parse_bridge("    ").is_none());
    assert!(parse_bridge("\t\n").is_none());
    assert!(parse_bridge("# comment").is_none());
    assert!(parse_bridge("   # leading comment").is_none());
}

#[test]
fn parse_bridge_extracts_ipv6_address() {
    let p = parse_bridge("obfs4 [2001:db8::1]:443 cert=abc").unwrap();
    assert_eq!(p.transport, "obfs4");
    assert_eq!(p.ip, "2001:db8::1");
    assert_eq!(p.port, 443);
}

#[test]
fn parse_bridge_falls_back_to_vanilla_when_no_whitespace_follows_transport() {
    let p = parse_bridge("obfs4notransport 1.2.3.4:443").unwrap();
    assert_eq!(p.transport, "vanilla");
    assert_eq!(p.raw, "obfs4notransport 1.2.3.4:443");
}

#[test]
fn classify_snowflake_meek_lite_and_meek_dash_lite_are_green() {
    let cidrs = IranCidrTable::new();
    for line in [
        "snowflake 1.2.3.4:443",
        "meek_lite 1.2.3.4:443",
        "meek-lite 1.2.3.4:443",
    ] {
        let p = parse_bridge(line).unwrap();
        assert_eq!(classify(&p, &cidrs), "GREEN", "line: {line}");
    }
}

#[test]
fn classify_obfs4_threshold_boundary_ports() {
    let cidrs = IranCidrTable::new();
    // All four NIN_SAFE_PORTS should yield YELLOW (with non-Iran IP).
    for &port in NIN_SAFE_PORTS {
        let line = format!("obfs4 1.2.3.4:{port} cert=abc");
        let p = parse_bridge(&line).unwrap();
        assert_eq!(p.port, port);
        assert_eq!(classify(&p, &cidrs), "YELLOW", "port: {port}");
    }
    // Ports outside NIN_SAFE_PORTS → RED.
    for port in [79u32, 444, 8079, 8081, 8442, 8444, 9001, 65535, 0] {
        // Skip port=0 because the regex requires 2-5 digit port.
        if port == 0 {
            continue;
        }
        let line = format!("obfs4 1.2.3.4:{port} cert=abc");
        let p = parse_bridge(&line).unwrap();
        assert_eq!(classify(&p, &cidrs), "RED", "port: {port}");
    }
}

#[test]
fn classify_obfs4_iran_ip_boundaries() {
    let cidrs = IranCidrTable::new();
    // 5.200.64.0/18 covers 5.200.64.0 - 5.200.127.255
    let inside = parse_bridge("obfs4 5.200.64.1:443 cert=abc").unwrap();
    assert_eq!(classify(&inside, &cidrs), "GREEN");
    let edge_low = parse_bridge("obfs4 5.200.64.0:443 cert=abc").unwrap();
    assert_eq!(classify(&edge_low, &cidrs), "GREEN");
    let edge_high = parse_bridge("obfs4 5.200.127.255:443 cert=abc").unwrap();
    assert_eq!(classify(&edge_high, &cidrs), "GREEN");
    let just_outside = parse_bridge("obfs4 5.200.128.0:443 cert=abc").unwrap();
    assert_eq!(classify(&just_outside, &cidrs), "YELLOW");
    // Cloudflare 104.16.0.0/13 covers 104.16.0.0 - 104.23.255.255.
    // 104.24.0.0/14 covers 104.24.0.0 - 104.27.255.255 (also in IRAN_CDN_CIDRS).
    let cf_inside = parse_bridge("obfs4 104.23.255.255:443 cert=abc").unwrap();
    assert_eq!(classify(&cf_inside, &cidrs), "GREEN");
    let cf_inside_second = parse_bridge("obfs4 104.24.0.0:443 cert=abc").unwrap();
    assert_eq!(classify(&cf_inside_second, &cidrs), "GREEN");
    // 104.28.0.0 is outside both Cloudflare ranges.
    let cf_outside = parse_bridge("obfs4 104.28.0.0:443 cert=abc").unwrap();
    assert_eq!(classify(&cf_outside, &cidrs), "YELLOW");
}

#[test]
fn classify_obfs4_invalid_ip_falls_through_to_yellow_on_safe_port() {
    let cidrs = IranCidrTable::new();
    let invalid_high = parse_bridge("obfs4 999.999.999.999:443 cert=abc").unwrap();
    assert_eq!(classify(&invalid_high, &cidrs), "YELLOW");
    let leading_zero = parse_bridge("obfs4 1.2.3.04:443 cert=abc").unwrap();
    assert_eq!(classify(&leading_zero, &cidrs), "YELLOW");
    let ipv6 = parse_bridge("obfs4 [2001:db8::1]:443 cert=abc").unwrap();
    assert_eq!(classify(&ipv6, &cidrs), "YELLOW");
    // An obfs4 line with no IP:port match has port=0, which is NOT in
    // NIN_SAFE_PORTS — so the classifier returns RED, not YELLOW.
    let no_ip = parse_bridge("obfs4 :443 cert=abc").unwrap();
    assert_eq!(no_ip.ip, "");
    assert_eq!(no_ip.port, 0);
    assert_eq!(classify(&no_ip, &cidrs), "RED");
}

#[test]
fn classify_webtunnel_sni_boundary_conditions() {
    let cidrs = IranCidrTable::new();
    // Exact GREEN SNI.
    let exact = parse_bridge("webtunnel 1.2.3.4:443 url=https://aparat.com").unwrap();
    assert_eq!(classify(&exact, &cidrs), "GREEN");
    // Subdomain of GREEN SNI.
    let sub = parse_bridge("webtunnel 1.2.3.4:443 url=https://sub.aparat.com").unwrap();
    assert_eq!(classify(&sub, &cidrs), "GREEN");
    // SNI that ends with green SNI but not as a subdomain — should NOT match GREEN.
    let not_sub = parse_bridge("webtunnel 1.2.3.4:443 url=https://notaparat.com").unwrap();
    assert_eq!(not_sub.sni, "notaparat.com");
    assert_eq!(classify(&not_sub, &cidrs), "YELLOW"); // unknown CDN → YELLOW
                                                      // YELLOW SNI exact.
    let yellow = parse_bridge("webtunnel 1.2.3.4:443 url=https://fastly.net").unwrap();
    assert_eq!(classify(&yellow, &cidrs), "YELLOW");
    // YELLOW SNI subdomain.
    let yellow_sub = parse_bridge("webtunnel 1.2.3.4:443 url=https://cdn.fastly.net").unwrap();
    assert_eq!(classify(&yellow_sub, &cidrs), "YELLOW");
    // No SNI → RED.
    let no_sni = parse_bridge("webtunnel 1.2.3.4:443").unwrap();
    assert_eq!(classify(&no_sni, &cidrs), "RED");
}

#[test]
fn classifier_run_writes_outputs_in_order() {
    let dir = case_dir("run_order");
    let now_iso = "2024-06-15T03:30:45.987654+00:00";
    let (clock, _) = fixed_clock(now_iso);

    let content = [
        "obfs4 5.200.64.5:443 cert=abc", // GREEN (Iran IP)
        "snowflake 192.0.2.1:443",       // GREEN (transport)
        "obfs4 1.2.3.4:443 cert=abc",    // YELLOW (safe port, non-Iran)
        "vanilla 5.6.7.8:9001",          // RED
        "webtunnel 1.2.3.4:443",         // RED (no SNI)
    ]
    .join("\n")
        + "\n";

    let source = write_source(&dir, "src.txt", &content);
    let green_out = dir.join("green.txt");
    let yellow_out = dir.join("yellow.txt");
    let combined_out = dir.join("combined.txt");
    let report_out = dir.join("report.json");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![source],
        green_out.clone(),
        yellow_out.clone(),
        combined_out.clone(),
        report_out.clone(),
        clock,
    );
    let rc = classifier.run().expect("run succeeds");
    assert_eq!(rc, 0);

    let green = fs::read_to_string(&green_out).unwrap();
    let yellow = fs::read_to_string(&yellow_out).unwrap();
    let combined = fs::read_to_string(&combined_out).unwrap();
    let report: Value = serde_json::from_str(&fs::read_to_string(&report_out).unwrap()).unwrap();

    // GREEN list preserves first-seen order.
    assert_eq!(
        green,
        "obfs4 5.200.64.5:443 cert=abc\nsnowflake 192.0.2.1:443\n"
    );
    assert_eq!(yellow, "obfs4 1.2.3.4:443 cert=abc\n");
    // Combined = GREEN + YELLOW in order.
    assert_eq!(
        combined,
        "obfs4 5.200.64.5:443 cert=abc\nsnowflake 192.0.2.1:443\nobfs4 1.2.3.4:443 cert=abc\n"
    );
    // Counts.
    assert_eq!(report["total_bridges"], json!(5));
    assert_eq!(report["green_count"], json!(2));
    assert_eq!(report["yellow_count"], json!(1));
    assert_eq!(report["red_count"], json!(2));
    assert_eq!(report["generated_at"], json!(now_iso));
    // Bridge details preserve input order.
    let bridges = report["bridges"].as_array().unwrap();
    assert_eq!(bridges.len(), 5);
    assert_eq!(bridges[0]["tier"], json!("GREEN"));
    assert_eq!(bridges[1]["tier"], json!("GREEN"));
    assert_eq!(bridges[2]["tier"], json!("YELLOW"));
    assert_eq!(bridges[3]["tier"], json!("RED"));
    assert_eq!(bridges[4]["tier"], json!("RED"));
}

#[test]
fn classifier_write_empty_uses_injected_clock() {
    let dir = case_dir("write_empty");
    let now_iso = "2024-12-31T23:59:59.000001+00:00";
    let (clock, _) = fixed_clock(now_iso);

    let green_out = dir.join("green.txt");
    let yellow_out = dir.join("yellow.txt");
    let combined_out = dir.join("combined.txt");
    let report_out = dir.join("report.json");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![dir.join("nonexistent.txt")],
        green_out.clone(),
        yellow_out.clone(),
        combined_out.clone(),
        report_out.clone(),
        clock,
    );
    classifier.write_empty().expect("write_empty succeeds");

    assert_eq!(fs::read_to_string(&green_out).unwrap(), "");
    assert_eq!(fs::read_to_string(&yellow_out).unwrap(), "");
    assert_eq!(fs::read_to_string(&combined_out).unwrap(), "");
    let report: Value = serde_json::from_str(&fs::read_to_string(&report_out).unwrap()).unwrap();
    assert_eq!(report["generated_at"], json!(now_iso));
    assert_eq!(report["total_bridges"], json!(0));
    assert_eq!(report["green_count"], json!(0));
    assert_eq!(report["yellow_count"], json!(0));
    assert_eq!(report["red_count"], json!(0));
    assert_eq!(report["note"], json!("No bridge source files found."));
    assert_eq!(report["bridges"], json!([]));
    // Empty report must NOT include the `scenario` or `classification_logic`
    // keys — only the `note` field.
    assert!(report.get("scenario").is_none());
    assert!(report.get("classification_logic").is_none());
}

#[test]
fn classifier_load_all_bridges_skips_missing_files() {
    let dir = case_dir("load_missing");
    let existing = write_source(&dir, "exists.txt", "snowflake 1.2.3.4:443\n");
    let missing = dir.join("missing.txt");

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![missing, existing],
        dir.join("g.txt"),
        dir.join("y.txt"),
        dir.join("c.txt"),
        dir.join("r.json"),
        Arc::new(|| Utc.timestamp_opt(0, 0).unwrap()),
    );
    let lines = classifier.load_all_bridges().expect("load succeeds");
    assert_eq!(lines, vec!["snowflake 1.2.3.4:443"]);
}

#[test]
fn constants_match_python_module_values() {
    // Sanity check that the Rust constants compile-time match the Python
    // module-level constants. The full parity is verified by the Python
    // subprocess tests above; here we just sanity-check the counts.
    assert_eq!(IRAN_CDN_CIDR_RAW.len(), 10);
    assert_eq!(NIN_SAFE_PORTS, &[80, 443, 8080, 8443]);
}

#[test]
fn parsed_bridge_to_json_with_tier_has_correct_field_set() {
    let p = ParsedBridge {
        raw: "obfs4 1.2.3.4:443".to_string(),
        transport: "obfs4".to_string(),
        ip: "1.2.3.4".to_string(),
        port: 443,
        sni: "".to_string(),
    };
    let json = p.to_json_with_tier("YELLOW");
    let obj = json.as_object().unwrap();
    // `serde_json::Map` (without the `preserve_order` feature) sorts keys
    // alphabetically. The Python original preserves insertion order, but
    // `serde_json::Value::Object` equality is order-independent — so JSON
    // parity is preserved. We assert the key SET matches Python's
    // `{**parsed, "tier": tier}` field set.
    let mut expected: Vec<&str> = vec!["raw", "transport", "ip", "port", "sni", "tier"];
    expected.sort_unstable();
    let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
    actual.sort_unstable();
    assert_eq!(actual, expected);
    assert_eq!(obj["tier"], json!("YELLOW"));
    assert_eq!(obj["raw"], json!("obfs4 1.2.3.4:443"));
    assert_eq!(obj["port"], json!(443));
}

#[test]
fn classifier_run_returns_io_error_for_unreadable_source() {
    let dir = case_dir("unreadable");
    // Create a directory where a file is expected — `fs::read_to_string`
    // will fail with an io error.
    let dir_path = dir.join("iam_a_directory.txt");
    fs::create_dir_all(&dir_path).unwrap();

    let classifier = NINInternetCutClassifier::with_paths_and_clock(
        vec![dir_path.clone()],
        dir.join("g.txt"),
        dir.join("y.txt"),
        dir.join("c.txt"),
        dir.join("r.json"),
        Arc::new(|| Utc.timestamp_opt(0, 0).unwrap()),
    );
    let err = classifier.load_all_bridges().unwrap_err();
    assert!(matches!(err, NINError::ReadBridge { .. }));
}
