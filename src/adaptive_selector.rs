//! Parity port of `adaptive_selector.py`.
//!
//! Adaptive bridge scoring and selection for Iran-oriented outputs.
//!
//! The selector is opt-in via `ADAPTIVE_IR_SCORING_ENABLED`.  It never fetches
//! or removes source bridges; callers pass the final candidate records and,
//! when enabled, receive those records ranked and filtered by a composite
//! adaptive score.
//!
//! Behavior traced to `adaptive_selector.py`:
//! * [`AdaptiveConfig::from_env`] / [`AdaptiveConfig::from_env_map`] — mirror
//!   `AdaptiveConfig.from_env()` using `_env_bool` / `_env_float` semantics.
//! * [`AdaptiveBridgeSelector::new`] — loads the three index dictionaries
//!   (`iran_by_line`, `scheduler_by_line`, `latest_by_line`) from injectable
//!   file paths via [`crate::generated_json_loader::load_generated_json`].
//! * [`AdaptiveBridgeSelector::score`] — composite adaptive score in `[0, 1]`
//!   combining tcp/asn/ooni/ripe/pt factors with failure penalties and
//!   transport preferences. Returns `(score, meta)` where `meta` mirrors the
//!   Python `{"adaptive_score": …, "adaptive_signals": {…}}` dict.
//! * [`AdaptiveBridgeSelector::select`] — when enabled, scores and filters
//!   items by `min_score`, then sorts by `(score, last_seen, line)` descending.
//!   When disabled, returns items unchanged.
//!
//! File I/O is injectable via `&Path`. All public methods return `Result<T,
//! AdaptiveSelectorError>`; the Python original raises uncaught exceptions on
//! non-numeric `ooni_factor` values, which Rust surfaces as
//! [`AdaptiveSelectorError::InvalidOoniFactor`].

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::generated_json_loader::load_generated_json;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `adaptive_selector.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum AdaptiveSelectorError {
    /// `latest["ooni_factor"]` is present but cannot be coerced to `float`
    /// the way Python's `float(ooni_factor)` does. The Python original lets
    /// the `TypeError`/`ValueError` propagate uncaught; the Rust port surfaces
    /// it as a typed error so callers can decide whether to log or skip.
    #[error("invalid ooni_factor value: {value}")]
    InvalidOoniFactor { value: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Env helpers (mirror `_env_bool`, `_env_float`)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_env_bool(name, default)`: reads `std::env::var(name)`,
/// lower-cases the trimmed value, and returns `true` for
/// `{"1", "true", "yes", "on"}`. Returns `default` when the variable is
/// unset.
pub fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(raw) => {
            let lower = raw.trim().to_lowercase();
            matches!(lower.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

/// Mirror of `_env_float(name, default)`: reads `std::env::var(name)` and
/// parses as `f64`. Returns `default` on parse failure or when unset.
pub fn env_float(name: &str, default: f64) -> f64 {
    match env::var(name) {
        Ok(raw) => raw.parse::<f64>().unwrap_or(default),
        Err(_) => default,
    }
}

/// Injectable variant of [`env_bool`] for unit tests.
pub fn env_bool_from_map(map: &BTreeMap<String, String>, name: &str, default: bool) -> bool {
    match map.get(name) {
        Some(raw) => {
            let lower = raw.trim().to_lowercase();
            matches!(lower.as_str(), "1" | "true" | "yes" | "on")
        }
        None => default,
    }
}

/// Injectable variant of [`env_float`] for unit tests.
pub fn env_float_from_map(map: &BTreeMap<String, String>, name: &str, default: f64) -> f64 {
    match map.get(name) {
        Some(raw) => raw.parse::<f64>().unwrap_or(default),
        None => default,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveConfig (mirror of the frozen dataclass)
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`AdaptiveBridgeSelector`]. Mirrors the
/// `@dataclass(frozen=True) AdaptiveConfig` in `adaptive_selector.py`.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub min_score: f64,
    pub prefer_webtunnel: bool,
    pub prefer_obfs4: bool,
    pub recent_failure_penalty: f64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_score: 0.0,
            prefer_webtunnel: false,
            prefer_obfs4: false,
            recent_failure_penalty: 0.15,
        }
    }
}

impl AdaptiveConfig {
    /// Mirror of `AdaptiveConfig.from_env()`. Reads the
    /// `ADAPTIVE_IR_*` environment variables via [`env_bool`] / [`env_float`].
    pub fn from_env() -> Self {
        Self {
            enabled: env_bool("ADAPTIVE_IR_SCORING_ENABLED", false),
            min_score: env_float("ADAPTIVE_IR_MIN_SCORE", 0.0),
            prefer_webtunnel: env_bool("ADAPTIVE_IR_PREFER_WEBTUNNEL", false),
            prefer_obfs4: env_bool("ADAPTIVE_IR_PREFER_OBFS4", false),
            recent_failure_penalty: env_float("ADAPTIVE_IR_RECENT_FAILURE_PENALTY", 0.15),
        }
    }

    /// Injectable variant of [`Self::from_env`] for unit tests.
    pub fn from_env_map(map: &BTreeMap<String, String>) -> Self {
        Self {
            enabled: env_bool_from_map(map, "ADAPTIVE_IR_SCORING_ENABLED", false),
            min_score: env_float_from_map(map, "ADAPTIVE_IR_MIN_SCORE", 0.0),
            prefer_webtunnel: env_bool_from_map(map, "ADAPTIVE_IR_PREFER_WEBTUNNEL", false),
            prefer_obfs4: env_bool_from_map(map, "ADAPTIVE_IR_PREFER_OBFS4", false),
            recent_failure_penalty: env_float_from_map(
                map,
                "ADAPTIVE_IR_RECENT_FAILURE_PENALTY",
                0.15,
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Value coercion helpers (mirror Python duck typing)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python's `str(value)` for the JSON value types that
/// `pt_status` and `circuit_state` can see.
fn python_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) => "[...]".to_string(),
        Value::Object(_) => "{...}".to_string(),
    }
}

/// Mirror of Python's truthiness for JSON values.
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Return the first truthy value among `values`, or `None`.
fn first_truthy_value<'a>(values: &[Option<&'a Value>]) -> Option<&'a Value> {
    values.iter().flatten().find(|v| is_truthy(v)).copied()
}

/// Return the first non-empty string among `values`, or `None`.
fn first_truthy_string(values: &[Option<&Value>]) -> Option<String> {
    for v in values.iter().flatten() {
        if let Some(s) = v.as_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Mirror of Python's `round(x, 4)` for `f64`. Uses round-half-to-even
/// (banker's rounding) via Rust's `{:.4}` format, which matches Python's
/// `round` for the common cases.
fn python_round_4(x: f64) -> f64 {
    format!("{:.4}", x).parse::<f64>().unwrap_or(x)
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveBridgeSelector
// ─────────────────────────────────────────────────────────────────────────────

/// Score, rank, and optionally filter bridge records using local signals.
///
/// Mirrors `AdaptiveBridgeSelector` in `adaptive_selector.py`.
pub struct AdaptiveBridgeSelector {
    /// The adaptive scoring configuration.
    pub config: AdaptiveConfig,
    /// Index of `bridge/iran_results.json` by `line` field.
    pub iran_by_line: BTreeMap<String, Value>,
    /// Index of `data/scheduler_results.json` by `bridge_line` field.
    pub scheduler_by_line: BTreeMap<String, Value>,
    /// Index of `data/latest-results.json` by `line` field.
    pub latest_by_line: BTreeMap<String, Value>,
}

impl AdaptiveBridgeSelector {
    /// Construct a selector that loads the three index dictionaries from the
    /// given file paths. Mirrors `AdaptiveBridgeSelector.__init__` with
    /// injectable paths.
    pub fn new(
        config: AdaptiveConfig,
        iran_path: &Path,
        scheduler_path: &Path,
        latest_path: &Path,
    ) -> Self {
        Self {
            config,
            iran_by_line: load_by_line(iran_path, "bridges", "line"),
            scheduler_by_line: load_by_line(scheduler_path, "results", "bridge_line"),
            latest_by_line: load_by_line(latest_path, "bridges", "line"),
        }
    }

    /// Construct a selector using the default relative paths from the Python
    /// original (`bridge/iran_results.json`, `data/scheduler_results.json`,
    /// `data/latest-results.json`).
    pub fn with_defaults(config: AdaptiveConfig) -> Self {
        Self::new(
            config,
            Path::new("bridge/iran_results.json"),
            Path::new("data/scheduler_results.json"),
            Path::new("data/latest-results.json"),
        )
    }

    /// Construct a selector with `AdaptiveConfig::from_env()` and the default
    /// relative paths.
    pub fn from_env() -> Self {
        Self::with_defaults(AdaptiveConfig::from_env())
    }

    /// Construct a selector with pre-loaded index dictionaries. Useful for
    /// tests that want to bypass file I/O.
    pub fn with_data(
        config: AdaptiveConfig,
        iran_by_line: BTreeMap<String, Value>,
        scheduler_by_line: BTreeMap<String, Value>,
        latest_by_line: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            config,
            iran_by_line,
            scheduler_by_line,
            latest_by_line,
        }
    }

    /// Mirror of `AdaptiveBridgeSelector._is_cdn_good(flags, asn_org)`.
    pub fn is_cdn_good(flags: &[Value], asn_org: &str) -> bool {
        is_cdn_good(flags, asn_org)
    }

    /// Mirror of `AdaptiveBridgeSelector.score(line, record)`.
    ///
    /// Returns `(score, meta)` where `score` is the clamped composite score
    /// in `[0, 1]` and `meta` is the
    /// `{"adaptive_score": round(score, 4), "adaptive_signals": {…}}` dict.
    pub fn score(&self, line: &str, record: &Value) -> Result<(f64, Value), AdaptiveSelectorError> {
        let empty = Value::Object(Map::new());
        let iran = self.iran_by_line.get(line).unwrap_or(&empty);
        let sched = self.scheduler_by_line.get(line).unwrap_or(&empty);
        let latest = self.latest_by_line.get(line).unwrap_or(&empty);

        // transport = (record.get("transport") or iran.get("transport")
        //              or sched.get("transport") or "").lower()
        let transport = first_truthy_string(&[
            record.get("transport"),
            iran.get("transport"),
            sched.get("transport"),
        ])
        .unwrap_or_default()
        .to_lowercase();

        // tcp = iran.get("tcp_reachable", record.get("tcp_reachable"))
        let tcp = if iran.get("tcp_reachable").is_some() {
            iran.get("tcp_reachable")
        } else {
            record.get("tcp_reachable")
        };
        let tcp_factor = if tcp == Some(&Value::Bool(true)) || transport == "snowflake" {
            1.0
        } else if tcp == Some(&Value::Bool(false)) {
            0.0
        } else {
            0.5
        };

        // flags = list(iran.get("flags", []))
        let flags: Vec<Value> = iran
            .get("flags")
            .and_then(Value::as_array)
            .map(|a| a.to_vec())
            .unwrap_or_default();

        // iran_status = iran.get("iran_status", "")
        let iran_status = iran
            .get("iran_status")
            .and_then(Value::as_str)
            .unwrap_or("");

        let asn_factor = if iran_status == "iran_likely_working" {
            1.0
        } else if iran_status == "iran_asn_blocked" {
            0.0
        } else if is_cdn_good(
            &flags,
            iran.get("asn_org").and_then(Value::as_str).unwrap_or(""),
        ) {
            1.0
        } else if flags
            .iter()
            .any(|f| f.as_str() == Some("domain_front_degraded"))
        {
            0.25
        } else {
            0.5
        };

        // ooni_factor = latest.get("ooni_factor")
        let ooni_factor: f64 = match latest.get("ooni_factor") {
            None | Some(Value::Null) => {
                if iran_status == "iran_likely_working" {
                    1.0
                } else if iran_status == "iran_likely_blocked"
                    || iran_status == "iran_frequently_blocked"
                {
                    0.0
                } else {
                    0.5
                }
            }
            Some(v) => match python_float(v) {
                Some(f) => f,
                None => {
                    return Err(AdaptiveSelectorError::InvalidOoniFactor {
                        value: v.to_string(),
                    });
                }
            },
        };

        // ripe_factor
        let ripe_factor = if sched.get("ripe_tested").is_some_and(is_truthy) {
            if sched.get("ripe_reachable").is_some_and(is_truthy) {
                1.0
            } else {
                0.0
            }
        } else {
            0.5
        };

        // pt_factor
        let pt_status = match sched.get("pt_status") {
            None => String::new(),
            Some(v) => python_str(v),
        }
        .to_lowercase();
        let pt_factor = match pt_status.as_str() {
            "reachable" | "quic_reachable" => 1.0,
            "timeout" | "refused" | "error" => 0.0,
            _ => 0.5,
        };

        // failure_penalty
        let failed = matches!(
            iran_status,
            "tcp_unreachable" | "iran_likely_blocked" | "iran_frequently_blocked"
        ) || pt_factor == 0.0;
        let default_closed = Value::String("closed".to_string());
        let circuit_state_raw = first_truthy_value(&[
            record.get("circuit_state"),
            iran.get("circuit_state"),
            latest.get("circuit_state"),
        ])
        .unwrap_or(&default_closed);
        let circuit_state = python_str(circuit_state_raw).to_lowercase();

        let mut failure_penalty = 0.0;
        if failed {
            failure_penalty += self.config.recent_failure_penalty;
        }
        if circuit_state == "open" {
            failure_penalty += self.config.recent_failure_penalty;
        } else if circuit_state == "half_open" {
            failure_penalty += self.config.recent_failure_penalty / 2.0;
        }

        // preference
        let mut preference = 0.0;
        if self.config.prefer_webtunnel && transport == "webtunnel" {
            preference += 0.05;
        }
        if self.config.prefer_obfs4 && transport == "obfs4" {
            preference += 0.05;
        }

        // score
        let raw_score = (0.25 * tcp_factor)
            + (0.15 * asn_factor)
            + (0.25 * ooni_factor)
            + (0.15 * ripe_factor)
            + (0.20 * pt_factor);
        let adjusted = raw_score + preference - failure_penalty;
        let score = adjusted.clamp(0.0, 1.0);

        let meta = json!({
            "adaptive_score": python_round_4(score),
            "adaptive_signals": {
                "tcp": tcp_factor,
                "asn_cdn": asn_factor,
                "ooni": ooni_factor,
                "ripe": ripe_factor,
                "pt": pt_factor,
                "failure_penalty": python_round_4(failure_penalty),
            }
        });

        Ok((score, meta))
    }

    /// Mirror of `AdaptiveBridgeSelector.select(items)`.
    ///
    /// When `config.enabled` is `false`, returns `items` unchanged.
    /// Otherwise, scores each item, filters by `config.min_score`, enriches
    /// the record with the score metadata, and sorts by
    /// `(score, last_seen, line)` descending.
    pub fn select(
        &self,
        items: &[(String, Value)],
    ) -> Result<Vec<(String, Value)>, AdaptiveSelectorError> {
        if !self.config.enabled {
            return Ok(items.to_vec());
        }
        let mut scored: Vec<(f64, String, Value)> = Vec::new();
        for (line, record) in items {
            let (score, meta) = self.score(line, record)?;
            if score >= self.config.min_score {
                let mut enriched = record.clone();
                if let Some(obj) = enriched.as_object_mut() {
                    if let Some(meta_obj) = meta.as_object() {
                        for (k, v) in meta_obj {
                            obj.insert(k.clone(), v.clone());
                        }
                    }
                }
                scored.push((score, line.clone(), enriched));
            }
        }
        // Python: scored.sort(key=lambda x: (x[0], x[2].get("last_seen", ""), x[1]), reverse=True)
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(Ordering::Equal)
                .then_with(|| {
                    let a_last = a.2.get("last_seen").and_then(Value::as_str).unwrap_or("");
                    let b_last = b.2.get("last_seen").and_then(Value::as_str).unwrap_or("");
                    b_last.cmp(a_last)
                })
                .then_with(|| b.1.cmp(&a.1))
        });
        Ok(scored
            .into_iter()
            .map(|(_, line, rec)| (line, rec))
            .collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module-level helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `AdaptiveBridgeSelector._is_cdn_good(flags, asn_org)` (static method).
pub fn is_cdn_good(flags: &[Value], asn_org: &str) -> bool {
    let org = asn_org.to_lowercase();
    const CDN_ORGS: &[&str] = &[
        "cloudflare",
        "fastly",
        "akamai",
        "azure",
        "amazon",
        "google",
        "cdn",
    ];
    flags
        .iter()
        .any(|f| f.as_str() == Some("domain_front_cdn_ok"))
        || CDN_ORGS.iter().any(|s| org.contains(s))
}

/// Mirror of Python's `float(value)` for the JSON value types that
/// `ooni_factor` can see. Returns `None` for values that would raise
/// `TypeError`/`ValueError`.
fn python_float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

/// Load a generated JSON artifact and index its list field by a key field.
/// Mirrors `_load_iran_results`, `_load_scheduler_results`,
/// `_load_latest_results`.
fn load_by_line(path: &Path, list_field: &str, key_field: &str) -> BTreeMap<String, Value> {
    let fallback = json!({ list_field: [] });
    let data = load_generated_json(path, fallback);
    let mut map = BTreeMap::new();
    if let Some(list) = data.get(list_field).and_then(Value::as_array) {
        for r in list {
            if r.is_object() {
                let key = match r.get(key_field) {
                    Some(Value::String(s)) => s.clone(),
                    _ => String::new(),
                };
                map.insert(key, r.clone());
            }
        }
    }
    map
}

#[cfg(test)]
// env::set_var/remove_var became unsafe fn in Rust 1.82 (process-wide
// mutation can race with other threads reading the environment via libc).
// These tests correctly wrap the calls in unsafe blocks with SAFETY comments
// for that (the toolchain CI actually builds with). On older toolchains —
// e.g. the 1.75.0 fallback used in sandboxes where rustup is network-blocked
// — the wrapper is a no-op lint false-positive rather than a real problem,
// so it's allowed here rather than stripped, to stay correct on both.
#[allow(unused_unsafe)]
mod tests {
    use super::*;

    #[test]
    fn env_bool_default_when_unset() {
        // SAFETY: env_bool reads a process-global variable; this test runs
        // single-threaded within the module's test binary and uses a unique
        // name to avoid collision with other tests.
        unsafe {
            env::remove_var("TORSHIELD_PARITY_TEST_UNSET_BOOL");
        }
        assert!(!env_bool("TORSHIELD_PARITY_TEST_UNSET_BOOL", false));
        assert!(env_bool("TORSHIELD_PARITY_TEST_UNSET_BOOL", true));
    }

    #[test]
    fn env_bool_truthy_values() {
        for val in ["1", "true", "TRUE", "Yes", " on ", "On"] {
            let name = "TORSHIELD_PARITY_TEST_BOOL_SET";
            unsafe {
                env::set_var(name, val);
            }
            assert!(env_bool(name, false), "expected truthy for {val:?}");
        }
    }

    #[test]
    fn env_bool_falsy_values() {
        for val in ["0", "false", "no", "off", "", "maybe"] {
            let name = "TORSHIELD_PARITY_TEST_BOOL_FALSY";
            unsafe {
                env::set_var(name, val);
            }
            assert!(!env_bool(name, true), "expected falsy for {val:?}");
        }
    }

    #[test]
    fn env_float_default_on_invalid() {
        let name = "TORSHIELD_PARITY_TEST_FLOAT_BAD";
        unsafe {
            env::set_var(name, "not-a-number");
        }
        assert_eq!(env_float(name, 0.42), 0.42);
    }

    #[test]
    fn adaptive_config_default_matches_python() {
        let cfg = AdaptiveConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.min_score, 0.0);
        assert!(!cfg.prefer_webtunnel);
        assert!(!cfg.prefer_obfs4);
        assert_eq!(cfg.recent_failure_penalty, 0.15);
    }

    #[test]
    fn adaptive_config_from_env_map_parses_overrides() {
        let mut map = BTreeMap::new();
        map.insert(
            "ADAPTIVE_IR_SCORING_ENABLED".to_string(),
            "true".to_string(),
        );
        map.insert("ADAPTIVE_IR_MIN_SCORE".to_string(), "0.5".to_string());
        map.insert("ADAPTIVE_IR_PREFER_WEBTUNNEL".to_string(), "1".to_string());
        map.insert("ADAPTIVE_IR_PREFER_OBFS4".to_string(), "yes".to_string());
        map.insert(
            "ADAPTIVE_IR_RECENT_FAILURE_PENALTY".to_string(),
            "0.25".to_string(),
        );
        let cfg = AdaptiveConfig::from_env_map(&map);
        assert!(cfg.enabled);
        assert_eq!(cfg.min_score, 0.5);
        assert!(cfg.prefer_webtunnel);
        assert!(cfg.prefer_obfs4);
        assert_eq!(cfg.recent_failure_penalty, 0.25);
    }

    #[test]
    fn is_cdn_good_matches_python_logic() {
        assert!(is_cdn_good(&[json!("domain_front_cdn_ok")], "anything"));
        assert!(is_cdn_good(&[], "Cloudflare Inc."));
        assert!(is_cdn_good(&[], "Amazon AWS"));
        assert!(!is_cdn_good(&[], "Random ISP"));
        assert!(!is_cdn_good(&[json!("other_flag")], "Random ISP"));
    }

    #[test]
    fn score_empty_data_returns_neutral_factors() {
        let selector = AdaptiveBridgeSelector::with_data(
            AdaptiveConfig::default(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let (score, meta) = selector
            .score("line1", &json!({}))
            .expect("empty score succeeds");
        // tcp=0.5 (unknown), asn=0.5 (default), ooni=0.5 (default),
        // ripe=0.5 (untested), pt=0.5 (empty status) → 0.5
        assert!((score - 0.5).abs() < 1e-9);
        assert_eq!(meta["adaptive_signals"]["tcp"], json!(0.5));
        assert_eq!(meta["adaptive_signals"]["asn_cdn"], json!(0.5));
        assert_eq!(meta["adaptive_signals"]["ooni"], json!(0.5));
        assert_eq!(meta["adaptive_signals"]["ripe"], json!(0.5));
        assert_eq!(meta["adaptive_signals"]["pt"], json!(0.5));
        assert_eq!(meta["adaptive_signals"]["failure_penalty"], json!(0.0));
    }

    #[test]
    fn score_snowflake_boosts_tcp_factor() {
        let selector = AdaptiveBridgeSelector::with_data(
            AdaptiveConfig::default(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let (score, _) = selector
            .score("line1", &json!({"transport": "snowflake"}))
            .expect("snowflake score succeeds");
        // tcp=1.0 (snowflake), asn=0.5, ooni=0.5, ripe=0.5, pt=0.5
        // = 0.25*1 + 0.15*0.5 + 0.25*0.5 + 0.15*0.5 + 0.20*0.5
        // = 0.25 + 0.075 + 0.125 + 0.075 + 0.10 = 0.625
        assert!((score - 0.625).abs() < 1e-9);
    }

    #[test]
    fn score_failure_penalty_clamps_to_zero() {
        let cfg = AdaptiveConfig {
            recent_failure_penalty: 1.0,
            ..AdaptiveConfig::default()
        };
        let selector = AdaptiveBridgeSelector::with_data(
            cfg,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let (score, meta) = selector
            .score("line1", &json!({"circuit_state": "open"}))
            .expect("clamped score succeeds");
        // raw_score=0.5, failure_penalty=1.0 (open circuit) → 0.5-1.0=-0.5 → clamped to 0
        assert!((score - 0.0).abs() < 1e-9);
        assert_eq!(meta["adaptive_signals"]["failure_penalty"], json!(1.0));
    }

    #[test]
    fn select_disabled_returns_items_unchanged() {
        let selector = AdaptiveBridgeSelector::with_data(
            AdaptiveConfig::default(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let items = vec![
            ("a".to_string(), json!({"x": 1})),
            ("b".to_string(), json!({"x": 2})),
        ];
        let result = selector.select(&items).expect("disabled select succeeds");
        assert_eq!(result, items);
    }

    #[test]
    fn select_enabled_filters_and_sorts() {
        let cfg = AdaptiveConfig {
            enabled: true,
            min_score: 0.5,
            ..AdaptiveConfig::default()
        };
        let selector = AdaptiveBridgeSelector::with_data(
            cfg,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let items = vec![
            ("low".to_string(), json!({"transport": "vanilla"})),
            (
                "high".to_string(),
                json!({"transport": "snowflake", "last_seen": "2024-01-01"}),
            ),
            ("mid".to_string(), json!({})),
        ];
        let result = selector.select(&items).expect("enabled select succeeds");
        // snowflake has tcp=1.0 → highest score; empty has 0.5; vanilla has 0.5
        // min_score=0.5 → all pass (snowflake=0.625, empty=0.5, vanilla=0.5)
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "high"); // snowflake first
    }

    #[test]
    fn score_invalid_ooni_factor_returns_typed_error() {
        let mut latest = BTreeMap::new();
        latest.insert("line1".to_string(), json!({"ooni_factor": [1, 2, 3]}));
        let selector = AdaptiveBridgeSelector::with_data(
            AdaptiveConfig::default(),
            BTreeMap::new(),
            BTreeMap::new(),
            latest,
        );
        let err = selector
            .score("line1", &json!({}))
            .expect_err("array ooni_factor must error");
        assert!(matches!(
            err,
            AdaptiveSelectorError::InvalidOoniFactor { .. }
        ));
    }
}
