// Parity tests for `src/formatter.rs` vs `core/formatter.py`.
//
// Follows the JSON-payload-via-argv pattern established in
// `iran_bridge_prioritizer_parity.rs`/`nin_selector_parity.rs`. Given the
// scope of this module (10 output files across 2 directories, a ZIP
// archive, a large README template), most tests exercise the full
// `export_all` + `update_readme` pipeline together against a shared
// history fixture, then compare each output file's content with
// wall-clock-dependent lines/fields normalized out — matching the same
// approach used for `nin_selector.rs`'s `build_nin_pack` (see that
// module's doc comment for the general rationale: a value that's real
// wall-clock time on both sides has no single ground truth for a
// subprocess-boundary byte-exact comparison to target).
//
// `IranScorer`'s transport-weight auto-load (`data/transport_weights.json`)
// is redirected to a nonexistent path on both sides for every test, so
// both implementations use the same deterministic default transport
// scores rather than whatever the real repo's weights file happens to
// contain.
//
// The ZIP archive's file *ordering* is explicitly NOT compared byte-exact
// (see `formatter.rs`'s module doc comment: Python's own `os.listdir()`
// order is unspecified) — only the *set* of (folder, filename) pairs in
// each archive is compared.

use std::path::Path;
use std::process::Command;

use chrono::{TimeZone, Utc};
use serde_json::{json, Value};

use torshield_ir_ultra::config::{from_env_map, EnvMap};
use torshield_ir_ultra::formatter::BridgeFormatter;
use torshield_ir_ultra::history::HistoryManager;

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        return Box::leak(path.into_boxed_str());
    }
    "python3"
}

fn fixed_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap()
}

/// One bridge fixture: `(line, transport, score, test_pass, latency_ms)`.
/// `test_pass`/`latency_ms` are `None` to mean "never tested" (Python:
/// `update_test` never called for this bridge).
#[derive(Clone)]
struct Fixture {
    line: &'static str,
    transport: &'static str,
    score: i64,
    test_pass: Option<bool>,
    latency_ms: Option<i64>,
}

fn base_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            line: "obfs4 1.2.3.4:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            transport: "obfs4",
            score: 80,
            test_pass: Some(true),
            latency_ms: Some(120),
        },
        Fixture {
            line: "obfs4 5.6.7.8:9001 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            transport: "obfs4",
            score: 40,
            test_pass: Some(false),
            latency_ms: None,
        },
        Fixture {
            line: "obfs4 [2001:db8::1]:443 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            transport: "obfs4",
            score: 70,
            test_pass: Some(true),
            latency_ms: Some(200),
        },
        Fixture {
            line: "snowflake url=https://snow.example/ fingerprint=DEAD",
            transport: "snowflake",
            score: 100,
            test_pass: Some(true),
            latency_ms: Some(90),
        },
        Fixture {
            line: "webtunnel 9.9.9.9:443 url=https://cdn.fastly.net/wt EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
            transport: "webtunnel",
            score: 90,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "vanilla 10.10.10.10:9050 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            transport: "vanilla",
            score: 20,
            test_pass: Some(true),
            latency_ms: Some(500),
        },
    ]
}

fn fixtures_json(fixtures: &[Fixture]) -> Value {
    Value::Array(
        fixtures
            .iter()
            .map(|f| {
                json!({
                    "line": f.line,
                    "transport": f.transport,
                    "score": f.score,
                    "test_pass": f.test_pass,
                    "latency_ms": f.latency_ms,
                })
            })
            .collect(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

const RUN_PIPELINE_SCRIPT: &str = r##"
import json, os, sys, zipfile
from pathlib import Path

payload = json.loads(sys.argv[1])
tmp = Path(payload["tmp_dir"])
bridge_dir = tmp / "bridge"
export_dir = tmp / "export"
history_file = bridge_dir / "bridge_history.json"
readme_path = tmp / "README.md"

import config
config.BRIDGE_DIR = str(bridge_dir)
config.EXPORT_DIR = str(export_dir)
config.HISTORY_FILE = str(history_file)

import core.scorer as scorer_mod
scorer_mod._TRANSPORT_WEIGHTS_PATH = Path(str(tmp / "nonexistent_transport_weights.json"))

import core.formatter as fmt_mod
import core.history as history_mod

history = history_mod.HistoryManager()
for fx in payload["fixtures"]:
    history.add_bridge(fx["line"], fx["transport"])
    history.update_score(fx["line"], fx["score"])
    if fx["test_pass"] is not None:
        history.update_test(fx["line"], fx["test_pass"], fx["latency_ms"])

formatter = fmt_mod.BridgeFormatter()
stats = formatter.export_all(history)

cwd = os.getcwd()
try:
    os.chdir(str(tmp))
    formatter.update_readme(stats)
finally:
    os.chdir(cwd)

def read_or_empty(p):
    return p.read_text(encoding="utf-8") if p.exists() else None

def strip_generated_line(text):
    if text is None:
        return None
    return "\n".join(l for l in text.split("\n") if not l.startswith("# Generated:"))

def strip_ts_line(text):
    if text is None:
        return None
    return "\n".join(l for l in text.split("\n") if "**Last update:**" not in l)

bridge_txts = {}
for f in os.listdir(bridge_dir):
    if f.endswith(".txt"):
        bridge_txts[f] = (bridge_dir / f).read_text(encoding="utf-8")

api = json.loads((export_dir / "bridges_api.json").read_text(encoding="utf-8"))
api.pop("updated", None)
# first_seen/last_seen come from HistoryManager.add_bridge, which always
# calls utc_now_iso() directly (real wall-clock time) -- there is no
# injectable-time mechanism on the Python side, unlike Rust's
# HistoryManager::new(..., now) constructor. Same "no single ground
# truth to compare" situation as `updated` above; normalize instead of
# comparing exact values.
for entries in api.get("bridges", {}).values():
    for entry in entries:
        entry.pop("first_seen", None)
        entry.pop("last_seen", None)

scores_db = json.loads((bridge_dir / "bridge_scores.json").read_text(encoding="utf-8"))

zip_entries = set()
with zipfile.ZipFile(bridge_dir / "tor_bridges.zip") as zf:
    for name in zf.namelist():
        zip_entries.add(name)

out = {
    "stats_without_zip_path": {k: v for k, v in stats.items() if k != "__zip_path__"},
    "bridge_txts": bridge_txts,
    "iran_pack_body": strip_generated_line(read_or_empty(export_dir / "iran_pack.txt")),
    "iran_cut_pack_body": read_or_empty(export_dir / "iran_cut_pack.txt"),
    "bridges_api": api,
    "scores_db": scores_db,
    "zip_entries": sorted(zip_entries),
    "readme_body": strip_ts_line(read_or_empty(readme_path)),
}
print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
"##;

fn run_pipeline_python(tmp_dir: &Path, fixtures: &[Fixture]) -> Value {
    let payload = json!({
        "tmp_dir": tmp_dir.display().to_string(),
        "fixtures": fixtures_json(fixtures),
    });
    let payload_json = serde_json::to_string(&payload).expect("payload serializes");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(RUN_PIPELINE_SCRIPT)
        .arg(&payload_json)
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

// ─────────────────────────────────────────────────────────────────────────────
// Rust side
// ─────────────────────────────────────────────────────────────────────────────

fn run_pipeline_rust(tmp_dir: &Path, fixtures: &[Fixture]) -> Value {
    let bridge_dir = tmp_dir.join("bridge");
    let export_dir = tmp_dir.join("export");
    let history_file = bridge_dir.join("bridge_history.json");
    let readme_path = tmp_dir.join("README.md");

    let now = fixed_now();
    let mut history =
        HistoryManager::new(&history_file, &bridge_dir, &export_dir, now).unwrap();
    for fx in fixtures {
        history.add_bridge(fx.line, fx.transport);
        history.update_score(fx.line, fx.score);
        if let Some(passed) = fx.test_pass {
            history.update_test(fx.line, passed, fx.latency_ms);
        }
    }

    let mut cfg = from_env_map(&EnvMap::new()).unwrap();
    cfg.bridge_dir = bridge_dir.display().to_string();
    cfg.export_dir = export_dir.display().to_string();

    let formatter = BridgeFormatter::new(
        now,
        &tmp_dir.join("nonexistent_transport_weights.json"),
    );
    let stats = formatter.export_all(&history, &cfg, now).unwrap();
    formatter
        .update_readme_with_path(&stats, &readme_path, &cfg, now)
        .unwrap();

    let read_or_none = |p: &Path| -> Option<String> { std::fs::read_to_string(p).ok() };
    let strip_generated_line = |text: Option<String>| -> Option<String> {
        text.map(|t| {
            t.split('\n')
                .filter(|l| !l.starts_with("# Generated:"))
                .collect::<Vec<_>>()
                .join("\n")
        })
    };
    let strip_ts_line = |text: Option<String>| -> Option<String> {
        text.map(|t| {
            t.split('\n')
                .filter(|l| !l.contains("**Last update:**"))
                .collect::<Vec<_>>()
                .join("\n")
        })
    };

    let mut bridge_txts = serde_json::Map::new();
    for entry in std::fs::read_dir(&bridge_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".txt") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            bridge_txts.insert(name, json!(content));
        }
    }

    let mut api: Value =
        serde_json::from_str(&std::fs::read_to_string(export_dir.join("bridges_api.json")).unwrap())
            .unwrap();
    api.as_object_mut().unwrap().remove("updated");
    if let Some(bridges) = api.get_mut("bridges").and_then(|b| b.as_object_mut()) {
        for entries in bridges.values_mut() {
            if let Some(arr) = entries.as_array_mut() {
                for entry in arr {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.remove("first_seen");
                        obj.remove("last_seen");
                    }
                }
            }
        }
    }

    let scores_db: Value =
        serde_json::from_str(&std::fs::read_to_string(bridge_dir.join("bridge_scores.json")).unwrap())
            .unwrap();

    let zip_file = std::fs::File::open(bridge_dir.join("tor_bridges.zip")).unwrap();
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();
    let mut zip_entries: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    zip_entries.sort();

    let mut stats_no_zip = stats.as_object().unwrap().clone();
    stats_no_zip.remove("__zip_path__");

    json!({
        "stats_without_zip_path": stats_no_zip,
        "bridge_txts": Value::Object(bridge_txts),
        "iran_pack_body": strip_generated_line(read_or_none(&export_dir.join("iran_pack.txt"))),
        "iran_cut_pack_body": read_or_none(&export_dir.join("iran_cut_pack.txt")),
        "bridges_api": api,
        "scores_db": scores_db,
        "zip_entries": zip_entries,
        "readme_body": strip_ts_line(read_or_none(&readme_path)),
    })
}

fn unique_tmp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "formatter_parity_{}_{}_{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_full_pipeline_mixed_fixtures() {
    let fixtures = base_fixtures();
    let tmp = unique_tmp_dir("full");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(
        py["stats_without_zip_path"], rs["stats_without_zip_path"],
        "per-file bridge counts must match"
    );
    assert_eq!(py["bridge_txts"], rs["bridge_txts"], "bridge/*.txt contents must match");
    assert_eq!(py["iran_pack_body"], rs["iran_pack_body"]);
    assert_eq!(py["iran_cut_pack_body"], rs["iran_cut_pack_body"]);
    assert_eq!(py["bridges_api"], rs["bridges_api"]);
    assert_eq!(py["scores_db"], rs["scores_db"]);
    assert_eq!(py["zip_entries"], rs["zip_entries"], "zip archive contents (set) must match");
    assert_eq!(py["readme_body"], rs["readme_body"]);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_empty_history() {
    let fixtures: Vec<Fixture> = vec![];
    let tmp = unique_tmp_dir("empty");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py, rs);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_single_untested_bridge() {
    let fixtures = vec![Fixture {
        line: "obfs4 1.2.3.4:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        transport: "obfs4",
        score: 50,
        test_pass: None,
        latency_ms: None,
    }];
    let tmp = unique_tmp_dir("untested");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py, rs);
    // Untested bridge must not appear in any "_tested" file.
    assert_eq!(py["bridge_txts"]["obfs4_tested.txt"], json!(""));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_ipv6_classification() {
    // Different TRANSPORTS deliberately, not just different `.score`
    // values, and NOT two obfs4-on-port-443 records: `iran_cut_pack`
    // assigns obfs4-on-port-443 bridges a FIXED bucket score (60)
    // independent of the record's own `.score` field, so two
    // same-transport, same-port-class records still tie there even with
    // distinct `.score` values (confirmed by hitting this exact failure
    // twice while designing this test). `vanilla` never qualifies for
    // any `iran_cut_pack` bucket at all, and using a different transport
    // per record also guarantees `_export_json_api`'s per-transport
    // grouping has exactly one record per group, so no intra-group tie
    // is possible there either. See `formatter.rs`'s module doc comment
    // for the underlying BTreeMap-vs-insertion-order divergence this
    // sidesteps.
    let fixtures = vec![
        Fixture {
            line: "obfs4 [2001:db8::42]:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            transport: "obfs4",
            score: 65,
            test_pass: Some(true),
            latency_ms: Some(80),
        },
        Fixture {
            line: "vanilla 192.0.2.1:9050 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            transport: "vanilla",
            score: 20,
            test_pass: Some(true),
            latency_ms: Some(80),
        },
    ];
    let tmp = unique_tmp_dir("ipv6");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py, rs);
    assert!(py["bridge_txts"]["obfs4_ipv6.txt"]
        .as_str()
        .unwrap()
        .contains("2001:db8::42"));
    assert!(!py["bridge_txts"]["obfs4.txt"]
        .as_str()
        .unwrap()
        .contains("2001:db8::42"));
    assert!(py["bridge_txts"]["vanilla.txt"]
        .as_str()
        .unwrap()
        .contains("192.0.2.1"));
    assert!(!py["bridge_txts"]["vanilla_ipv6.txt"]
        .as_str()
        .unwrap()
        .contains("192.0.2.1"));

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Rust-only test (NOT a Python parity assertion — see `formatter.rs`'s
/// module doc comment). Demonstrates, rather than hides, the documented
/// `BTreeMap`-vs-Python-dict-insertion-order tie-break divergence: two
/// records with an EQUAL score, where the second-inserted record's
/// normalized key sorts alphabetically before the first's
/// (`"192.0.2.1"` < `"[2001:db8::42]"` in ASCII: `'1' < '['`).
#[test]
fn tie_break_order_documented_divergence() {
    let fixtures = vec![
        Fixture {
            line: "obfs4 [2001:db8::42]:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            transport: "obfs4",
            score: 60,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "obfs4 192.0.2.1:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            transport: "obfs4",
            score: 60,
            test_pass: None,
            latency_ms: None,
        },
    ];
    let tmp = unique_tmp_dir("tiedoc");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    // Python (insertion order): AAAA (inserted first) sorts first among
    // the tie. Rust (BTreeMap key order): BBBB's key ("obfs4 192...")
    // sorts alphabetically before AAAA's key ("obfs4 [2001..."), so BBBB
    // comes first instead. This is the DOCUMENTED divergence, not a bug
    // in this module -- everything else (bridge_txts, iran packs,
    // scores_db, zip contents, readme) still matches exactly.
    let py_lines: Vec<&str> = py["bridges_api"]["bridges"]["obfs4"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["line"].as_str().unwrap())
        .collect();
    let rs_lines: Vec<&str> = rs["bridges_api"]["bridges"]["obfs4"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["line"].as_str().unwrap())
        .collect();
    assert!(py_lines[0].contains("2001:db8::42"), "python: insertion order preserved");
    assert!(rs_lines[0].contains("192.0.2.1"), "rust: BTreeMap key order preserved");
    assert_ne!(py_lines, rs_lines, "this test exists to document that these DO diverge");

    // Confirm the divergence is scoped to ordering only: same two lines
    // present on both sides, same everything else.
    let mut py_sorted = py_lines.clone();
    let mut rs_sorted = rs_lines.clone();
    py_sorted.sort();
    rs_sorted.sort();
    assert_eq!(py_sorted, rs_sorted, "same set of lines on both sides");
    assert_eq!(py["bridge_txts"], rs["bridge_txts"]);
    assert_eq!(py["scores_db"], rs["scores_db"]);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_score_tie_break_in_json_api() {
    // NOTE: this specific pair of IPs ("1.1.1.1" / "2.2.2.2") happens to
    // sort the same way under both Python's insertion order and Rust's
    // BTreeMap key order, so this test passing does NOT by itself prove
    // general tie-break parity -- see `tie_break_order_documented_divergence`
    // below for a case where the two orderings genuinely differ, and
    // `formatter.rs`'s module doc comment for the full explanation. This
    // test still has value: it confirms both sides perform a truly
    // STABLE sort (not, say, an accidental additional re-ordering) for
    // the common case where iteration order already agrees.
    // Two obfs4 bridges with the SAME score -> tests the stable-sort
    // tie-break in `_export_json_api`'s per-transport grouping.
    let fixtures = vec![
        Fixture {
            line: "obfs4 1.1.1.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            transport: "obfs4",
            score: 55,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "obfs4 2.2.2.2:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            transport: "obfs4",
            score: 55,
            test_pass: None,
            latency_ms: None,
        },
    ];
    let tmp = unique_tmp_dir("tie");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py, rs);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_snowflake_and_webtunnel_cdn_iran_cut_pack() {
    // Exercises iran_cut_pack's snowflake/webtunnel-CDN/meek_lite/obfs4-443
    // branches together.
    let fixtures = vec![
        Fixture {
            line: "snowflake url=https://snow.example/ fingerprint=DEAD",
            transport: "snowflake",
            score: 100,
            test_pass: Some(true),
            latency_ms: Some(90),
        },
        Fixture {
            line: "webtunnel 9.9.9.9:443 url=https://cdn.fastly.net/wt EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
            transport: "webtunnel",
            score: 90,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "webtunnel 8.8.8.8:443 url=https://random.example/wt FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            transport: "webtunnel",
            score: 85,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "meek_lite azureedge.net GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
            transport: "meek_lite",
            score: 70,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "obfs4 1.2.3.4:443 HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
            transport: "obfs4",
            score: 60,
            test_pass: None,
            latency_ms: None,
        },
        Fixture {
            line: "obfs4 1.2.3.4:9001 IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
            transport: "obfs4",
            score: 60,
            test_pass: None,
            latency_ms: None,
        },
    ];
    let tmp = unique_tmp_dir("cutpack");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py, rs);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn parity_zip_categories_present() {
    let fixtures = base_fixtures();
    let tmp = unique_tmp_dir("zipcats");

    let py = run_pipeline_python(&tmp.join("py"), &fixtures);
    let rs = run_pipeline_rust(&tmp.join("rs"), &fixtures);

    assert_eq!(py["zip_entries"], rs["zip_entries"]);
    let entries = py["zip_entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e.as_str().unwrap().contains("Tested (Verified)")));
    assert!(entries.iter().any(|e| e.as_str().unwrap().contains("Full Archive")));
    assert!(entries.iter().any(|e| e.as_str().unwrap().contains("Iran Optimized")));

    let _ = std::fs::remove_dir_all(&tmp);
}
