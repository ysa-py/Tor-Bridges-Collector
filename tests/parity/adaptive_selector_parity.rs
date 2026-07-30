// Parity tests for `src/adaptive_selector.rs` vs `adaptive_selector.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `adaptive_selector` and calls the matching method on the same input. The
// Rust port is invoked on the identical input and the JSON outputs are
// compared for equality (parsed [`Value`] comparison so object key ordering
// is irrelevant).
//
// Coverage:
// * `score` over the empty-data, snowflake-tcp-boost, iran-likely-working,
//   iran-asn-blocked, CDN-good, domain-front-degraded, ooni-factor override,
//   ripe-tested/reachable, pt-status positive/negative, failure-penalty
//   (open/half_open circuit), transport preference, and invalid-ooni-factor
//   branches.
// * `select` over disabled, enabled-empty, enabled-filter, and enabled-sort
//   branches.
// * `AdaptiveConfig.from_env` over default and overridden environments.
// * `is_cdn_good` over the CDN-org and flag-based branches.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::adaptive_selector::{
    is_cdn_good, AdaptiveBridgeSelector, AdaptiveConfig, AdaptiveSelectorError,
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

/// Dispatch a single JSON command to the Python `adaptive_selector` module
/// and return the parsed JSON output. Supported operations:
/// * `score` — override the selector's index dicts, call `score(line, record)`,
///   return `{"score": float, "meta": dict}`.
/// * `select` — override the selector's index dicts, call `select(items)`,
///   return the list of `(line, record)` tuples as a JSON array.
/// * `from_env` — call `AdaptiveConfig.from_env()`, return the config dict.
fn python_adaptive_selector(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("adaptive_selector parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os
from adaptive_selector import AdaptiveBridgeSelector, AdaptiveConfig

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'from_env':
    config = AdaptiveConfig.from_env()
    print(json.dumps({
        'enabled': config.enabled,
        'min_score': config.min_score,
        'prefer_webtunnel': config.prefer_webtunnel,
        'prefer_obfs4': config.prefer_obfs4,
        'recent_failure_penalty': config.recent_failure_penalty,
    }, sort_keys=True, separators=(',', ':')))
elif op == 'score':
    config = AdaptiveConfig(**cmd.get('config', {}))
    selector = AdaptiveBridgeSelector(config)
    selector.iran_by_line = {r['line']: r for r in cmd.get('iran_bridges', []) if isinstance(r, dict)}
    selector.scheduler_by_line = {r.get('bridge_line', ''): r for r in cmd.get('scheduler_results', []) if isinstance(r, dict)}
    selector.latest_by_line = {r.get('line', ''): r for r in cmd.get('latest_bridges', []) if isinstance(r, dict)}
    score, meta = selector.score(cmd['line'], cmd['record'])
    print(json.dumps({'score': score, 'meta': meta}, sort_keys=True, separators=(',', ':')))
elif op == 'select':
    config = AdaptiveConfig(**cmd.get('config', {}))
    selector = AdaptiveBridgeSelector(config)
    selector.iran_by_line = {r['line']: r for r in cmd.get('iran_bridges', []) if isinstance(r, dict)}
    selector.scheduler_by_line = {r.get('bridge_line', ''): r for r in cmd.get('scheduler_results', []) if isinstance(r, dict)}
    selector.latest_by_line = {r.get('line', ''): r for r in cmd.get('latest_bridges', []) if isinstance(r, dict)}
    items = [(item[0], item[1]) for item in cmd['items']]
    result = selector.select(items)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
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
        .unwrap_or_else(|err| panic!("python adaptive_selector helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python adaptive_selector helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python adaptive_selector helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust helpers
// ─────────────────────────────────────────────────────────────────────────────

fn rust_selector(
    config: &AdaptiveConfig,
    iran: &[Value],
    scheduler: &[Value],
    latest: &[Value],
) -> AdaptiveBridgeSelector {
    let iran_map: BTreeMap<String, Value> = iran
        .iter()
        .map(|r| {
            let key = r
                .get("line")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (key, r.clone())
        })
        .collect();
    let sched_map: BTreeMap<String, Value> = scheduler
        .iter()
        .map(|r| {
            let key = r
                .get("bridge_line")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (key, r.clone())
        })
        .collect();
    let latest_map: BTreeMap<String, Value> = latest
        .iter()
        .map(|r| {
            let key = r
                .get("line")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (key, r.clone())
        })
        .collect();
    AdaptiveBridgeSelector::with_data(config.clone(), iran_map, sched_map, latest_map)
}

fn rust_score(
    config: &AdaptiveConfig,
    iran: &[Value],
    scheduler: &[Value],
    latest: &[Value],
    line: &str,
    record: &Value,
) -> Value {
    let selector = rust_selector(config, iran, scheduler, latest);
    let (score, meta) = selector.score(line, record).expect("rust score succeeds");
    json!({"score": score, "meta": meta})
}

fn rust_select(
    config: &AdaptiveConfig,
    iran: &[Value],
    scheduler: &[Value],
    latest: &[Value],
    items: &[(String, Value)],
) -> Value {
    let selector = rust_selector(config, iran, scheduler, latest);
    let result = selector.select(items).expect("rust select succeeds");
    json!(result
        .into_iter()
        .map(|(line, rec)| json!([line, rec]))
        .collect::<Vec<_>>())
}

fn config_to_json(cfg: &AdaptiveConfig) -> Value {
    json!({
        "enabled": cfg.enabled,
        "min_score": cfg.min_score,
        "prefer_webtunnel": cfg.prefer_webtunnel,
        "prefer_obfs4": cfg.prefer_obfs4,
        "recent_failure_penalty": cfg.recent_failure_penalty,
    })
}

fn assert_score_parity(
    label: &str,
    config: &AdaptiveConfig,
    iran: Vec<Value>,
    scheduler: Vec<Value>,
    latest: Vec<Value>,
    line: &str,
    record: Value,
) {
    let py_cmd = json!({
        "op": "score",
        "config": config_to_json(config),
        "iran_bridges": iran,
        "scheduler_results": scheduler,
        "latest_bridges": latest,
        "line": line,
        "record": record,
    });
    let py = python_adaptive_selector(&py_cmd);
    let rs = rust_score(config, &iran, &scheduler, &latest, line, &record);
    assert_eq!(py, rs, "score parity failed for {label}");
}

// ─────────────────────────────────────────────────────────────────────────────
// score parity (Python subprocess on every case)
// ─────────────────────────────────────────────────────────────────────────────

const LINE: &str = "obfs4 1.2.3.4:443 cert=abc";

#[test]
fn parity_score_empty_data_neutral_factors() {
    assert_score_parity(
        "empty_data",
        &AdaptiveConfig::default(),
        vec![],
        vec![],
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_snowflake_tcp_boost() {
    assert_score_parity(
        "snowflake_tcp",
        &AdaptiveConfig::default(),
        vec![],
        vec![],
        vec![],
        LINE,
        json!({"transport": "snowflake"}),
    );
}

#[test]
fn parity_score_iran_likely_working() {
    let iran = vec![
        json!({"line": LINE, "iran_status": "iran_likely_working", "transport": "obfs4", "tcp_reachable": true}),
    ];
    assert_score_parity(
        "iran_working",
        &AdaptiveConfig::default(),
        iran,
        vec![],
        vec![],
        LINE,
        json!({"transport": "obfs4"}),
    );
}

#[test]
fn parity_score_iran_asn_blocked() {
    let iran =
        vec![json!({"line": LINE, "iran_status": "iran_asn_blocked", "tcp_reachable": false})];
    assert_score_parity(
        "asn_blocked",
        &AdaptiveConfig::default(),
        iran,
        vec![],
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_cdn_good_asn_org() {
    let iran = vec![
        json!({"line": LINE, "iran_status": "", "asn_org": "Cloudflare Inc.", "tcp_reachable": true, "flags": []}),
    ];
    assert_score_parity(
        "cdn_good_org",
        &AdaptiveConfig::default(),
        iran,
        vec![],
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_domain_front_degraded_flag() {
    let iran = vec![
        json!({"line": LINE, "iran_status": "", "flags": ["domain_front_degraded"], "tcp_reachable": true}),
    ];
    assert_score_parity(
        "domain_front_degraded",
        &AdaptiveConfig::default(),
        iran,
        vec![],
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_ooni_factor_override() {
    let latest = vec![json!({"line": LINE, "ooni_factor": 0.9})];
    assert_score_parity(
        "ooni_override",
        &AdaptiveConfig::default(),
        vec![],
        vec![],
        latest,
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_ripe_tested_reachable() {
    let sched = vec![
        json!({"bridge_line": LINE, "ripe_tested": true, "ripe_reachable": true, "pt_status": "reachable"}),
    ];
    assert_score_parity(
        "ripe_reachable",
        &AdaptiveConfig::default(),
        vec![],
        sched,
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_pt_status_error_failure_penalty() {
    let sched = vec![json!({"bridge_line": LINE, "pt_status": "error"})];
    assert_score_parity(
        "pt_error",
        &AdaptiveConfig::default(),
        vec![],
        sched,
        vec![],
        LINE,
        json!({}),
    );
}

#[test]
fn parity_score_circuit_open_penalty() {
    assert_score_parity(
        "circuit_open",
        &AdaptiveConfig::default(),
        vec![],
        vec![],
        vec![],
        LINE,
        json!({"circuit_state": "open"}),
    );
}

#[test]
fn parity_score_circuit_half_open_penalty() {
    assert_score_parity(
        "circuit_half_open",
        &AdaptiveConfig::default(),
        vec![],
        vec![],
        vec![],
        LINE,
        json!({"circuit_state": "half_open"}),
    );
}

#[test]
fn parity_score_transport_preference_webtunnel() {
    let cfg = AdaptiveConfig {
        prefer_webtunnel: true,
        ..AdaptiveConfig::default()
    };
    assert_score_parity(
        "prefer_webtunnel",
        &cfg,
        vec![],
        vec![],
        vec![],
        LINE,
        json!({"transport": "webtunnel"}),
    );
}

#[test]
fn parity_score_combined_full_record() {
    let iran = vec![json!({
        "line": LINE,
        "iran_status": "iran_likely_working",
        "transport": "obfs4",
        "tcp_reachable": true,
        "asn_org": "Cloudflare",
        "flags": ["domain_front_cdn_ok"]
    })];
    let sched = vec![json!({
        "bridge_line": LINE,
        "ripe_tested": true,
        "ripe_reachable": true,
        "pt_status": "reachable"
    })];
    let latest = vec![json!({"line": LINE, "ooni_factor": 0.8, "circuit_state": "open"})];
    let cfg = AdaptiveConfig {
        enabled: true,
        min_score: 0.0,
        prefer_obfs4: true,
        recent_failure_penalty: 0.2,
        ..AdaptiveConfig::default()
    };
    assert_score_parity(
        "combined_full",
        &cfg,
        iran,
        sched,
        latest,
        LINE,
        json!({"transport": "obfs4", "circuit_state": "open"}),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// select parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_select_disabled_returns_unchanged() {
    let cfg = AdaptiveConfig::default();
    let items = vec![
        ("a".to_string(), json!({"x": 1})),
        ("b".to_string(), json!({"x": 2})),
    ];
    let py_cmd = json!({
        "op": "select",
        "config": config_to_json(&cfg),
        "iran_bridges": [],
        "scheduler_results": [],
        "latest_bridges": [],
        "items": items.iter().map(|(l, r)| json!([l, r])).collect::<Vec<_>>(),
    });
    let py = python_adaptive_selector(&py_cmd);
    let rs = rust_select(&cfg, &[], &[], &[], &items);
    assert_eq!(py, rs, "select disabled parity failed");
}

#[test]
fn parity_select_enabled_filters_and_sorts() {
    let cfg = AdaptiveConfig {
        enabled: true,
        min_score: 0.5,
        ..AdaptiveConfig::default()
    };
    let items = vec![
        ("low".to_string(), json!({"transport": "vanilla"})),
        (
            "high".to_string(),
            json!({"transport": "snowflake", "last_seen": "2024-01-02"}),
        ),
        ("mid".to_string(), json!({"last_seen": "2024-01-01"})),
    ];
    let py_cmd = json!({
        "op": "select",
        "config": config_to_json(&cfg),
        "iran_bridges": [],
        "scheduler_results": [],
        "latest_bridges": [],
        "items": items.iter().map(|(l, r)| json!([l, r])).collect::<Vec<_>>(),
    });
    let py = python_adaptive_selector(&py_cmd);
    let rs = rust_select(&cfg, &[], &[], &[], &items);
    assert_eq!(py, rs, "select enabled parity failed");
}

#[test]
fn parity_select_enabled_empty_items() {
    let cfg = AdaptiveConfig {
        enabled: true,
        min_score: 0.0,
        ..AdaptiveConfig::default()
    };
    let items: Vec<(String, Value)> = vec![];
    let py_cmd = json!({
        "op": "select",
        "config": config_to_json(&cfg),
        "iran_bridges": [],
        "scheduler_results": [],
        "latest_bridges": [],
        "items": [],
    });
    let py = python_adaptive_selector(&py_cmd);
    let rs = rust_select(&cfg, &[], &[], &[], &items);
    assert_eq!(py, rs, "select empty parity failed");
}

#[test]
fn parity_select_enabled_min_score_filters_all_out() {
    let cfg = AdaptiveConfig {
        enabled: true,
        min_score: 0.99,
        ..AdaptiveConfig::default()
    };
    let items = vec![
        ("a".to_string(), json!({})),
        ("b".to_string(), json!({"transport": "snowflake"})),
    ];
    let py_cmd = json!({
        "op": "select",
        "config": config_to_json(&cfg),
        "iran_bridges": [],
        "scheduler_results": [],
        "latest_bridges": [],
        "items": items.iter().map(|(l, r)| json!([l, r])).collect::<Vec<_>>(),
    });
    let py = python_adaptive_selector(&py_cmd);
    let rs = rust_select(&cfg, &[], &[], &[], &items);
    assert_eq!(py, rs, "select filter-all parity failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// from_env parity (Python subprocess with controlled env)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_from_env_defaults() {
    let py = {
        let output = Command::new(python_executable())
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env_clear()
            .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
            .arg("-c")
            .arg(
                r#"
import json
from adaptive_selector import AdaptiveConfig
config = AdaptiveConfig.from_env()
print(json.dumps({
    'enabled': config.enabled,
    'min_score': config.min_score,
    'prefer_webtunnel': config.prefer_webtunnel,
    'prefer_obfs4': config.prefer_obfs4,
    'recent_failure_penalty': config.recent_failure_penalty,
}, sort_keys=True, separators=(',', ':')))
"#,
            )
            .output()
            .unwrap_or_else(|err| panic!("python from_env must execute: {err}"));
        assert!(
            output.status.success(),
            "python from_env failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let rs = AdaptiveConfig::from_env();
    assert_eq!(py["enabled"], json!(rs.enabled));
    assert_eq!(py["min_score"], json!(rs.min_score));
    assert_eq!(py["prefer_webtunnel"], json!(rs.prefer_webtunnel));
    assert_eq!(py["prefer_obfs4"], json!(rs.prefer_obfs4));
    assert_eq!(
        py["recent_failure_penalty"],
        json!(rs.recent_failure_penalty)
    );
}

#[test]
fn parity_from_env_overridden() {
    let env_vars = [
        ("ADAPTIVE_IR_SCORING_ENABLED", "true"),
        ("ADAPTIVE_IR_MIN_SCORE", "0.5"),
        ("ADAPTIVE_IR_PREFER_WEBTUNNEL", "1"),
        ("ADAPTIVE_IR_PREFER_OBFS4", "yes"),
        ("ADAPTIVE_IR_RECENT_FAILURE_PENALTY", "0.25"),
    ];
    let py = {
        let mut cmd = Command::new(python_executable());
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
            .env_clear()
            .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"));
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }
        let output = cmd
            .arg("-c")
            .arg(
                r#"
import json
from adaptive_selector import AdaptiveConfig
config = AdaptiveConfig.from_env()
print(json.dumps({
    'enabled': config.enabled,
    'min_score': config.min_score,
    'prefer_webtunnel': config.prefer_webtunnel,
    'prefer_obfs4': config.prefer_obfs4,
    'recent_failure_penalty': config.recent_failure_penalty,
}, sort_keys=True, separators=(',', ':')))
"#,
            )
            .output()
            .unwrap_or_else(|err| panic!("python from_env override must execute: {err}"));
        assert!(
            output.status.success(),
            "python from_env override failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let mut map = BTreeMap::new();
    for (k, v) in &env_vars {
        map.insert((*k).to_string(), (*v).to_string());
    }
    let rs = AdaptiveConfig::from_env_map(&map);
    assert_eq!(py["enabled"], json!(rs.enabled));
    assert_eq!(py["min_score"], json!(rs.min_score));
    assert_eq!(py["prefer_webtunnel"], json!(rs.prefer_webtunnel));
    assert_eq!(py["prefer_obfs4"], json!(rs.prefer_obfs4));
    assert_eq!(
        py["recent_failure_penalty"],
        json!(rs.recent_failure_penalty)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// is_cdn_good parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_is_cdn_good_all_branches() {
    let cases: Vec<(Vec<Value>, &str, bool)> = vec![
        (vec![json!("domain_front_cdn_ok")], "anything", true),
        (vec![], "Cloudflare Inc.", true),
        (vec![], "Amazon AWS", true),
        (vec![], "Google LLC", true),
        (vec![], "Fastly", true),
        (vec![], "Akamai", true),
        (vec![], "Azure CDN", true),
        (vec![], "my cdn provider", true),
        (vec![], "Random ISP", false),
        (vec![json!("other_flag")], "Random ISP", false),
        (vec![], "", false),
    ];
    for (flags, asn_org, expected) in cases {
        // is_cdn_good is a static method; invoke via Python directly
        let py = {
            let flags_json = serde_json::to_string(&flags).unwrap();
            let output = Command::new(python_executable())
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .env_clear()
                .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
                .arg("-c")
                .arg(format!(
                    r#"
import json
from adaptive_selector import AdaptiveBridgeSelector
flags = {flags}
asn_org = {asn_org:?}
print(json.dumps(AdaptiveBridgeSelector._is_cdn_good(flags, asn_org)))
"#,
                    flags = flags_json,
                ))
                .output()
                .unwrap_or_else(|err| panic!("python is_cdn_good must execute: {err}"));
            assert!(
                output.status.success(),
                "python is_cdn_good failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice::<Value>(&output.stdout).unwrap()
        };
        let rs = is_cdn_good(&flags, asn_org);
        assert_eq!(
            py,
            json!(rs),
            "is_cdn_good parity failed for flags={flags:?} org={asn_org}"
        );
        assert_eq!(
            rs, expected,
            "is_cdn_good expected mismatch for org={asn_org}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-only typed-error path
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_score_invalid_ooni_factor_returns_typed_error() {
    let mut latest = BTreeMap::new();
    latest.insert(LINE.to_string(), json!({"ooni_factor": [1, 2, 3]}));
    let selector = AdaptiveBridgeSelector::with_data(
        AdaptiveConfig::default(),
        BTreeMap::new(),
        BTreeMap::new(),
        latest,
    );
    let err = selector
        .score(LINE, &json!({}))
        .expect_err("array ooni_factor must error");
    assert!(matches!(
        err,
        AdaptiveSelectorError::InvalidOoniFactor { .. }
    ));
}

#[test]
fn rust_score_string_ooni_factor_parses_like_python_float() {
    // Python float("0.7") = 0.7; Rust should match
    let mut latest = BTreeMap::new();
    latest.insert(LINE.to_string(), json!({"ooni_factor": "0.7"}));
    let selector = AdaptiveBridgeSelector::with_data(
        AdaptiveConfig::default(),
        BTreeMap::new(),
        BTreeMap::new(),
        latest,
    );
    let (score, meta) = selector
        .score(LINE, &json!({}))
        .expect("string ooni_factor should parse");
    // ooni=0.7, others default 0.5
    // 0.25*0.5 + 0.15*0.5 + 0.25*0.7 + 0.15*0.5 + 0.20*0.5
    // = 0.125 + 0.075 + 0.175 + 0.075 + 0.10 = 0.55
    assert!((score - 0.55).abs() < 1e-9);
    assert_eq!(meta["adaptive_signals"]["ooni"], json!(0.7));
}
