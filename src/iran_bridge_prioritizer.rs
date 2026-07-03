//! Parity port of `core/iran_bridge_prioritizer.py`.
//!
//! Non-destructive Iran-aware bridge prioritization: scores and reorders
//! existing bridge records without ever dropping records, mutating input
//! records in place, or removing existing fields.
//!
//! ## Config-call simplifications (provably dead code, not feature loss)
//!
//! The Python original wraps several `getattr(config, FLAG, default)`
//! reads in helpers (`_enabled(...)`, `_number(...)`) that handle inputs
//! which are not yet a native `bool`/`float`. Every config attribute this
//! module reads is declared in `config.py` with an unconditional type
//! coercion at module-load time (e.g.
//! `IRAN_BRIDGE_PRIORITIZATION_ENABLED: bool = os.getenv(...).lower() ==
//! "true"`, `IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT: float =
//! float(os.getenv(...))`) — so by the time this module's functions run,
//! `config.py` has already either produced a real `bool`/`float` or
//! crashed at import time. `_enabled`'s string-parsing branch and
//! `_number`'s exception fallback are therefore provably unreachable for
//! every call site in this file specifically (confirmed by inspection of
//! `config.py`, not assumed). This port reads the already-typed
//! `bool`/`f64` fields straight from [`crate::config::Config`], which
//! `config.rs` independently parses with the same coercions and defaults.
//! This is a simplification of *this file's* control flow only — it does
//! not change `_enabled`/`_number`'s general-purpose contract, which
//! callers elsewhere are free to rely on if `config.rs` ever gains a
//! field that bypasses load-time coercion.
//!
//! ## Known, documented non-determinism in the Python original
//!
//! `_extract_transport`'s fallback path iterates a Python `set` literal
//! (`_SUPPORTED_TRANSPORTS`). `PYTHONHASHSEED` is not pinned anywhere in
//! this repository (checked: no occurrence in any `.py`/`.toml`/`.cfg`/
//! `.ini`/`.yml`/`.sh` file), and Python's set iteration order for string
//! elements depends on the per-process hash seed — empirically confirmed
//! non-deterministic across process runs (5 separate `python3`
//! invocations of the literal set produced 5 different orderings). This
//! only matters when a raw bridge line's lowercased text contains 2+
//! supported-transport names as separate whole words — a case where
//! Python's *own* behavior has no single ground truth to match. This
//! port iterates [`SUPPORTED_TRANSPORTS`] in the fixed order the Python
//! source lists them in (`snowflake, webtunnel, obfs4, meek_lite,
//! vanilla`) as a documented, deterministic substitute. Parity tests only
//! assert byte-identical output against live Python for inputs where at
//! most one transport name matches — the only case Python itself
//! resolves deterministically.

use std::sync::OnceLock;

use chrono::{DateTime, FixedOffset, Timelike, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::config::Config;
use crate::dt_utils::{coerce_utc_dt, DEFAULT_FALLBACK};

/// Mirrors `_SUPPORTED_TRANSPORTS` from the Python original. See the
/// module-level doc comment for why this is a `Vec`/array in a fixed
/// order rather than an unordered set.
const SUPPORTED_TRANSPORTS: [&str; 5] = ["snowflake", "webtunnel", "obfs4", "meek_lite", "vanilla"];

/// Mirrors `_TRANSPORT_SCORES.get(transport, _TRANSPORT_SCORES["unknown"])`.
fn transport_score(transport: &str) -> f64 {
    match transport {
        "snowflake" => 1.0,
        "webtunnel" => 0.92,
        "meek_lite" => 0.84,
        "obfs4" => 0.76,
        "vanilla" => 0.18,
        _ => 0.30, // "unknown"
    }
}

/// Mirrors `_ENDPOINT_RE = re.compile(r"(?P<host>\[[^\]]+\]|[^\s:]+):(?P<port>\d{2,5})")`.
///
/// The port group is narrowed to ASCII `[0-9]` rather than Python's
/// (Unicode-by-default) `\d`. Python's `\d` in a `str` pattern matches any
/// Unicode decimal digit, and `int()` on the captured text accepts those
/// same Unicode digits — so Python and a naive Rust `\d` (which also
/// defaults to Unicode-aware matching) would actually disagree downstream
/// anyway, since Rust's `str::parse::<i64>` is ASCII-only. Restricting to
/// `[0-9]` here keeps the regex match and the integer parse consistent
/// with each other. This only affects bridge lines using non-ASCII
/// digits for a port number, which does not occur in real Tor bridge
/// configuration data (ASCII-only by the bridge-line format itself).
fn endpoint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?P<host>\[[^\]]+\]|[^\s:]+):(?P<port>[0-9]{2,5})")
            .expect("endpoint_re compiles")
    })
}

/// One compiled `\bTRANSPORT\b` pattern per entry in [`SUPPORTED_TRANSPORTS`],
/// in that fixed order. Mirrors `re.search(rf"\b{re.escape(transport)}\b", raw)`
/// for each set member in the Python `for transport in _SUPPORTED_TRANSPORTS`
/// loop.
fn transport_word_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        SUPPORTED_TRANSPORTS
            .iter()
            .map(|&name| {
                let pattern = format!(r"\b{}\b", regex::escape(name));
                (
                    name,
                    Regex::new(&pattern).expect("transport word pattern compiles"),
                )
            })
            .collect()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Python-semantics helpers (truthiness, `or`-chains, `int()` coercion)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors Python truthiness (`bool(value)`) for JSON-representable types.
fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Mirrors Python's `a or b or c` chain: returns the first truthy value,
/// or — if none are truthy — the *last* value in the chain as-is (Python
/// never collapses a falsy final term to `None`; it returns that falsy
/// value verbatim). `values` must be non-empty.
fn or_chain<'a>(values: &[Option<&'a Value>]) -> Option<&'a Value> {
    debug_assert!(!values.is_empty(), "or_chain requires at least one value");
    for &v in values {
        if is_truthy(v) {
            return v;
        }
    }
    *values.last().unwrap_or(&None)
}

fn is_bool_true(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

fn is_bool_false(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(false)))
}

/// Mirrors Python's `int(str)` parsing: optional surrounding whitespace,
/// optional leading `+`/`-`, digit groups optionally separated by single
/// underscores (PEP 515 — no leading/trailing/doubled underscore, no
/// decimal point). Empirically verified against CPython 3.12 across
/// `'443'`, `' 443 '`, `'+443'`, `'-1'`, `'4_43'`, `'4__43'` (rejected),
/// `'_443'`/`'443_'` (rejected), `'443.5'` (rejected), `'00443'` (→ 443).
/// Returns `None` exactly where Python's `int(s)` would raise `ValueError`.
fn python_int_str(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    let (sign, digits_part) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => match trimmed.strip_prefix('+') {
            Some(rest) => (1i64, rest),
            None => (1i64, trimmed),
        },
    };
    if digits_part.is_empty() {
        return None;
    }
    let bytes = digits_part.as_bytes();
    if bytes[0] == b'_' || bytes[bytes.len() - 1] == b'_' {
        return None;
    }
    let mut clean = String::with_capacity(digits_part.len());
    let mut prev_was_underscore = false;
    for c in digits_part.chars() {
        if c == '_' {
            if prev_was_underscore {
                return None;
            }
            prev_was_underscore = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        prev_was_underscore = false;
        clean.push(c);
    }
    clean.parse::<i64>().ok().map(|v| v * sign)
}

/// Mirrors Python's `int(value)` for the JSON-representable types that can
/// appear in a parsed bridge record. Returns `None` exactly where Python's
/// `int(value)` would raise `TypeError` or `ValueError`. Out-of-`i64`-range
/// floats/strings saturate/fail-to-parse rather than matching Python's
/// arbitrary-precision int exactly — but every caller in this module only
/// ever checks `0 < port <= 65535` afterward, so an extreme out-of-range
/// input converges on the same observable fallthrough behavior either way
/// (see `extract_port`).
fn python_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(b) => Some(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else {
                n.as_f64().map(|f| f as i64)
            }
        }
        Value::String(s) => python_int_str(s),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Round to 4 decimal places matching Python's `round(x, 4)`.
///
/// Both Python's `round()` and Rust's `format!("{:.4}", x)` perform
/// correctly-rounded decimal conversion based on the float's *exact*
/// binary value (round-half-to-even at that exact value, not at the
/// "intended" decimal value) — empirically verified identical across 17
/// cases including the classic float-representation gotchas
/// (`round(2.675, 4)` → `2.675` not `2.6750`'s naive-decimal neighbor,
/// `0.99995` → `1.0000`, `0.00005` → `0.0001`).
fn python_round4(x: f64) -> f64 {
    format!("{:.4}", x)
        .parse::<f64>()
        .expect("a 4-decimal formatted float always reparses")
}

// ─────────────────────────────────────────────────────────────────────────────
// Field extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_raw_line`: first of `raw`/`line`/`bridge_line` that is a
/// non-empty string, else `""`.
fn raw_line(record: &Map<String, Value>) -> &str {
    for key in ["raw", "line", "bridge_line"] {
        if let Some(Value::String(s)) = record.get(key) {
            if !s.is_empty() {
                return s.as_str();
            }
        }
    }
    ""
}

/// Mirrors `_extract_port`.
fn extract_port(record: &Map<String, Value>) -> i64 {
    if let Some(value) = record.get("port") {
        let is_none_or_empty_string =
            matches!(value, Value::Null) || matches!(value, Value::String(s) if s.is_empty());
        if !is_none_or_empty_string {
            if let Some(port) = python_int(value) {
                if port > 0 && port <= 65535 {
                    return port;
                }
            }
            // Python: a TypeError/ValueError here is caught, recorded via
            // record_silent_failure (telemetry-only — see
            // monitoring/structured_logger.py), and falls through to the
            // regex path below. We have no equivalent telemetry sink to
            // call into from Rust yet, so this falls through silently;
            // the *return value* (what this function produces) is
            // unaffected either way.
        }
    }
    let Some(captures) = endpoint_re().captures(raw_line(record)) else {
        return 0;
    };
    captures
        .name("port")
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0)
}

/// Mirrors `_extract_transport`.
fn extract_transport(record: &Map<String, Value>) -> String {
    if let Some(Value::String(s)) = record.get("transport") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed.to_lowercase();
        }
    }
    let raw = raw_line(record).to_lowercase();
    for (name, pattern) in transport_word_patterns() {
        if pattern.is_match(&raw) {
            return (*name).to_string();
        }
    }
    "unknown".to_string()
}

/// Mirrors `_recency_score`.
fn recency_score(record: &Map<String, Value>, now: DateTime<Utc>) -> f64 {
    let value = or_chain(&[
        record.get("last_seen"),
        record.get("tested_at"),
        record.get("first_seen"),
    ]);
    if !is_truthy(value) {
        return 0.0;
    }
    // Python: coerce_utc_dt(value) — non-str/non-datetime values fall back
    // to coerce_utc_dt's own default fallback ("2000-01-01T00:00:00+00:00",
    // i.e. DEFAULT_FALLBACK here too).
    let value_str = value.and_then(Value::as_str);
    let dt = coerce_utc_dt(value_str, DEFAULT_FALLBACK);
    let age = now - dt; // chrono::Duration; may be negative if `value` is in the future.
    if age <= chrono::Duration::hours(24) {
        1.0
    } else if age <= chrono::Duration::hours(72) {
        0.75
    } else if age <= chrono::Duration::days(7) {
        0.50
    } else if age <= chrono::Duration::days(30) {
        0.25
    } else {
        0.05
    }
}

/// Mirrors `_reachability_score`.
fn reachability_score(record: &Map<String, Value>) -> f64 {
    for key in ["reachable", "test_pass", "success", "is_reachable"] {
        let v = record.get(key);
        if is_bool_true(v) {
            return 1.0;
        }
        if is_bool_false(v) {
            return 0.0;
        }
    }

    let metadata = or_chain(&[
        record.get("reachability"),
        record.get("reachability_metadata"),
    ]);
    if let Some(Value::Object(meta)) = metadata {
        for key in ["success", "reachable", "ok"] {
            let v = meta.get(key);
            if is_bool_true(v) {
                return 1.0;
            }
            if is_bool_false(v) {
                return 0.0;
            }
        }
        if let Some(score_val) = meta.get("score") {
            // Python: isinstance(score, (int, float)) — bool is a subtype
            // of int in Python, so a literal True/False "score" also
            // qualifies (float(True) == 1.0, float(False) == 0.0).
            let as_number: Option<f64> = match score_val {
                Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
                Value::Number(n) => n.as_f64(),
                _ => None,
            };
            if let Some(score) = as_number {
                return score.max(0.0).min(1.0);
            }
        }
    }

    if is_bool_true(record.get("ripe_atlas_reachable")) || is_bool_true(record.get("atlas_success"))
    {
        return 1.0;
    }
    0.0
}

/// Mirrors `_within_window`.
fn within_window(hour: i64, start: i64, end: i64) -> bool {
    if start == end {
        return true;
    }
    if start < end {
        start <= hour && hour <= end
    } else {
        hour >= start || hour <= end
    }
}

/// Mirrors `_context_multiplier`. See the module-level doc comment for why
/// `UTLS_EVASION_MODE`/`NIN_MODE` read `cfg`'s native `bool` fields
/// directly instead of replicating `_enabled`'s string-parsing branch.
fn context_multiplier(cfg: &Config, now: DateTime<Utc>) -> f64 {
    let mut multiplier = 1.0_f64;
    if cfg.utls_evasion_mode {
        multiplier += 0.05;
    }
    if cfg.nin_mode {
        multiplier += 0.05;
    }

    // Iran Standard Time: UTC+03:30.
    let irst = FixedOffset::east_opt(3 * 3600 + 30 * 60).expect("IRST is a valid fixed offset");
    let iran_hour = now.with_timezone(&irst).hour() as i64;

    if within_window(
        iran_hour,
        cfg.irst_high_censorship_start,
        cfg.irst_high_censorship_end,
    ) {
        multiplier += 0.05;
    }
    if within_window(
        iran_hour,
        cfg.irst_ultra_stealth_start,
        cfg.irst_ultra_stealth_end,
    ) {
        multiplier += 0.05;
    }
    if !cfg.ripe_atlas_api_key.is_empty() {
        multiplier += 0.05;
    }
    multiplier
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `score_bridge`: returns an annotated copy of one bridge record
/// with prioritization data. Never mutates `record`; never drops or
/// renames any of its existing fields.
pub fn score_bridge(
    record: &Map<String, Value>,
    cfg: &Config,
    now: DateTime<Utc>,
) -> Map<String, Value> {
    let port = extract_port(record);
    let transport = extract_transport(record);

    // Raw (unclamped) config weights — these are what get stored in the
    // output "weights" object, matching Python's `weights` dict exactly.
    let w_port_raw = cfg.iran_bridge_prioritization_weight_port;
    let w_transport_raw = cfg.iran_bridge_prioritization_weight_transport;
    let w_recency_raw = cfg.iran_bridge_prioritization_weight_recency;
    let w_reachability_raw = cfg.iran_bridge_prioritization_weight_reachability;

    let s_port = if cfg.iran_preferred_ports.contains(&port) {
        1.0
    } else {
        0.0
    };
    let s_transport = transport_score(&transport);
    let s_recency = recency_score(record, now);
    let s_reachability = reachability_score(record);

    // Clamped (>= 0.0) weights — used only for the weighted-average
    // computation, matching Python's `max(0.0, weight)` calls.
    let total_weight = {
        let sum = w_port_raw.max(0.0)
            + w_transport_raw.max(0.0)
            + w_recency_raw.max(0.0)
            + w_reachability_raw.max(0.0);
        if sum == 0.0 {
            1.0
        } else {
            sum
        }
    };
    let raw_score = (s_port * w_port_raw.max(0.0)
        + s_transport * w_transport_raw.max(0.0)
        + s_recency * w_recency_raw.max(0.0)
        + s_reachability * w_reachability_raw.max(0.0))
        / total_weight;
    let score = raw_score * context_multiplier(cfg, now);
    let clamped_score = python_round4(score.max(0.0).min(1.0));

    let mut annotated = record.clone();
    annotated.insert(
        "iran_prioritization".to_string(),
        json!({
            "score": clamped_score,
            "signals": {
                "port": s_port,
                "transport": s_transport,
                "recency": s_recency,
                "reachability": s_reachability,
            },
            "weights": {
                "port": w_port_raw,
                "transport": w_transport_raw,
                "recency": w_recency_raw,
                "reachability": w_reachability_raw,
            },
            "port": port,
            "transport": transport,
        }),
    );
    annotated
}

/// Mirrors `prioritize_bridges`: returns all bridge records in Iran-aware
/// priority order when `cfg.iran_bridge_prioritization_enabled` is true.
///
/// When disabled, returns a clone of `records` in original order, without
/// annotation — matching Python's `return list(bridges)` (a fresh list,
/// but with each record otherwise untouched).
pub fn prioritize_bridges(
    records: &[Map<String, Value>],
    cfg: &Config,
    annotate: bool,
    now: DateTime<Utc>,
) -> Vec<Map<String, Value>> {
    if !cfg.iran_bridge_prioritization_enabled {
        return records.to_vec();
    }

    let mut scored: Vec<(usize, Map<String, Value>)> = records
        .iter()
        .enumerate()
        .map(|(idx, record)| (idx, score_bridge(record, cfg, now)))
        .collect();

    // Python: scored.sort(key=lambda item: (item[1][...]["score"], -item[0]),
    // reverse=True) — descending by score; ties broken by ASCENDING
    // original index (earlier records win ties). Verified by hand-tracing
    // the (score, -idx) / reverse=True key against a worked 3-element
    // example with two tied scores.
    scored.sort_by(|a, b| {
        let score_a =
            a.1.get("iran_prioritization")
                .and_then(|v| v.get("score"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
        let score_b =
            b.1.get("iran_prioritization")
                .and_then(|v| v.get("score"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });

    let ranked: Vec<Map<String, Value>> = scored.into_iter().map(|(_, record)| record).collect();

    if annotate {
        ranked
    } else {
        ranked
            .into_iter()
            .map(|mut record| {
                record.remove("iran_prioritization");
                record
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::BTreeMap;

    fn base_config() -> Config {
        crate::config::from_env_map(&BTreeMap::new()).expect("default env map parses")
    }

    fn enabled_config() -> Config {
        let mut cfg = base_config();
        cfg.iran_bridge_prioritization_enabled = true;
        cfg
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 30, 12, 0, 0).unwrap()
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn extract_port_prefers_direct_int_field() {
        let record = obj(vec![("port", json!(443))]);
        assert_eq!(extract_port(&record), 443);
    }

    #[test]
    fn extract_port_accepts_numeric_string() {
        let record = obj(vec![("port", json!("8080"))]);
        assert_eq!(extract_port(&record), 8080);
    }

    #[test]
    fn extract_port_falls_back_to_regex_when_out_of_range() {
        let record = obj(vec![
            ("port", json!(70000)), // out of (0, 65535]
            ("raw", json!("obfs4 1.2.3.4:443 ABCDEF")),
        ]);
        assert_eq!(extract_port(&record), 443);
    }

    #[test]
    fn extract_port_falls_back_to_regex_on_unparseable_string() {
        let record = obj(vec![
            ("port", json!("not-a-number")),
            ("raw", json!("obfs4 1.2.3.4:9001 ABCDEF")),
        ]);
        assert_eq!(extract_port(&record), 9001);
    }

    #[test]
    fn extract_port_handles_ipv6_bracket_host_in_regex_fallback() {
        let record = obj(vec![("raw", json!("obfs4 [::1]:443 ABCDEF"))]);
        assert_eq!(extract_port(&record), 443);
    }

    #[test]
    fn extract_port_returns_zero_when_nothing_matches() {
        let record = obj(vec![("raw", json!("no endpoint here"))]);
        assert_eq!(extract_port(&record), 0);
    }

    #[test]
    fn extract_port_skips_none_and_empty_string_port_field() {
        let record = obj(vec![
            ("port", Value::Null),
            ("raw", json!("obfs4 1.2.3.4:443 ABCDEF")),
        ]);
        assert_eq!(extract_port(&record), 443);

        let record2 = obj(vec![
            ("port", json!("")),
            ("raw", json!("obfs4 1.2.3.4:553 ABCDEF")),
        ]);
        assert_eq!(extract_port(&record2), 553);
    }

    #[test]
    fn extract_transport_prefers_explicit_field() {
        let record = obj(vec![("transport", json!("  OBFS4  "))]);
        assert_eq!(extract_transport(&record), "obfs4");
    }

    #[test]
    fn extract_transport_detects_single_match_in_raw_line() {
        let record = obj(vec![("raw", json!("snowflake url=https://x abc"))]);
        assert_eq!(extract_transport(&record), "snowflake");
    }

    #[test]
    fn extract_transport_unknown_when_no_match() {
        let record = obj(vec![("raw", json!("totally unrecognized line"))]);
        assert_eq!(extract_transport(&record), "unknown");
    }

    #[test]
    fn recency_score_buckets_match_python_thresholds() {
        let now = fixed_now();
        let mk = |hours_ago: i64| {
            obj(vec![(
                "last_seen",
                json!((now - chrono::Duration::hours(hours_ago)).to_rfc3339()),
            )])
        };
        assert_eq!(recency_score(&mk(1), now), 1.0);
        assert_eq!(recency_score(&mk(48), now), 0.75);
        assert_eq!(recency_score(&mk(96), now), 0.50);
        assert_eq!(recency_score(&mk(24 * 20), now), 0.25);
        assert_eq!(recency_score(&mk(24 * 60), now), 0.05);
    }

    #[test]
    fn recency_score_zero_when_no_timestamp_field_present() {
        let record = obj(vec![]);
        assert_eq!(recency_score(&record, fixed_now()), 0.0);
    }

    #[test]
    fn recency_score_falls_back_through_chain() {
        let now = fixed_now();
        let record = obj(vec![
            ("last_seen", json!("")), // falsy, skipped
            (
                "tested_at",
                json!((now - chrono::Duration::hours(1)).to_rfc3339()),
            ),
        ]);
        assert_eq!(recency_score(&record, now), 1.0);
    }

    #[test]
    fn reachability_score_identity_checks_true_false() {
        assert_eq!(
            reachability_score(&obj(vec![("reachable", json!(true))])),
            1.0
        );
        assert_eq!(
            reachability_score(&obj(vec![("test_pass", json!(false))])),
            0.0
        );
        // Non-bool truthy value (e.g. integer 1) must NOT match `is True`.
        assert_eq!(reachability_score(&obj(vec![("reachable", json!(1))])), 0.0);
    }

    #[test]
    fn reachability_score_reads_nested_metadata_score() {
        let record = obj(vec![("reachability_metadata", json!({"score": 0.42}))]);
        assert_eq!(reachability_score(&record), 0.42);
    }

    #[test]
    fn reachability_score_clamps_out_of_range_metadata_score() {
        let record = obj(vec![("reachability", json!({"score": 5.0}))]);
        assert_eq!(reachability_score(&record), 1.0);
    }

    #[test]
    fn reachability_score_falls_back_to_atlas_flags() {
        let record = obj(vec![("ripe_atlas_reachable", json!(true))]);
        assert_eq!(reachability_score(&record), 1.0);
    }

    #[test]
    fn reachability_score_default_zero() {
        assert_eq!(reachability_score(&obj(vec![])), 0.0);
    }

    #[test]
    fn within_window_handles_wraparound() {
        assert!(within_window(23, 22, 2));
        assert!(within_window(1, 22, 2));
        assert!(!within_window(10, 22, 2));
        assert!(within_window(5, 5, 5)); // start == end => always true
    }

    #[test]
    fn score_bridge_preserves_existing_fields() {
        let cfg = base_config();
        let record = obj(vec![
            ("raw", json!("obfs4 1.2.3.4:443 ABCDEF")),
            ("custom_field", json!("must survive")),
        ]);
        let scored = score_bridge(&record, &cfg, fixed_now());
        assert_eq!(scored.get("custom_field"), Some(&json!("must survive")));
        assert_eq!(scored.get("raw"), record.get("raw"));
        assert!(scored.contains_key("iran_prioritization"));
    }

    #[test]
    fn score_bridge_score_is_clamped_to_unit_interval() {
        let cfg = base_config();
        let record = obj(vec![
            ("port", json!(443)),
            ("reachable", json!(true)),
            ("last_seen", json!(fixed_now().to_rfc3339())),
        ]);
        let scored = score_bridge(&record, &cfg, fixed_now());
        let score = scored["iran_prioritization"]["score"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn prioritize_bridges_passthrough_when_disabled() {
        let cfg = base_config(); // prioritization disabled by default
        let records = vec![obj(vec![("id", json!(1))]), obj(vec![("id", json!(2))])];
        let result = prioritize_bridges(&records, &cfg, true, fixed_now());
        assert_eq!(result, records);
        for r in &result {
            assert!(!r.contains_key("iran_prioritization"));
        }
    }

    #[test]
    fn prioritize_bridges_sorts_descending_with_ascending_index_tiebreak() {
        let cfg = enabled_config();
        let now = fixed_now();
        // Three records with identical (empty) signals -> identical scores;
        // original order must be preserved (idx0, idx1, idx2).
        let records = vec![
            obj(vec![("id", json!(0))]),
            obj(vec![("id", json!(1))]),
            obj(vec![("id", json!(2))]),
        ];
        let result = prioritize_bridges(&records, &cfg, true, now);
        let ids: Vec<i64> = result.iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn prioritize_bridges_higher_score_sorts_first() {
        let cfg = enabled_config();
        let now = fixed_now();
        let weak = obj(vec![("id", json!("weak"))]);
        let strong = obj(vec![
            ("id", json!("strong")),
            ("port", json!(443)),
            ("reachable", json!(true)),
            ("last_seen", json!(now.to_rfc3339())),
            ("transport", json!("snowflake")),
        ]);
        let records = vec![weak.clone(), strong.clone()];
        let result = prioritize_bridges(&records, &cfg, true, now);
        assert_eq!(result[0]["id"], json!("strong"));
        assert_eq!(result[1]["id"], json!("weak"));
    }

    #[test]
    fn prioritize_bridges_unannotated_strips_iran_prioritization_key() {
        let cfg = enabled_config();
        let records = vec![obj(vec![("id", json!(1))])];
        let result = prioritize_bridges(&records, &cfg, false, fixed_now());
        assert!(!result[0].contains_key("iran_prioritization"));
        assert_eq!(result[0]["id"], json!(1));
    }

    #[test]
    fn python_round4_matches_known_cpython_cases() {
        // Verified against CPython 3.12's round(x, 4) for these exact values.
        assert_eq!(python_round4(0.12345), 0.1235);
        assert_eq!(python_round4(2.675), 2.675);
        assert_eq!(python_round4(0.99995), 1.0);
        assert_eq!(python_round4(0.00005), 0.0001);
        assert_eq!(python_round4(0.0), 0.0);
    }

    #[test]
    fn python_int_str_handles_underscores_and_signs() {
        assert_eq!(python_int_str("443"), Some(443));
        assert_eq!(python_int_str(" 443 "), Some(443));
        assert_eq!(python_int_str("+443"), Some(443));
        assert_eq!(python_int_str("-1"), Some(-1));
        assert_eq!(python_int_str("4_43"), Some(443));
        assert_eq!(python_int_str("4_4_3"), Some(443));
        assert_eq!(python_int_str("4__43"), None);
        assert_eq!(python_int_str("_443"), None);
        assert_eq!(python_int_str("443_"), None);
        assert_eq!(python_int_str("443.5"), None);
        assert_eq!(python_int_str(""), None);
        assert_eq!(python_int_str("00443"), Some(443));
    }

    #[test]
    fn extract_transport_multi_match_uses_documented_fixed_order() {
        // Rust-only test: NOT a Python parity assertion. See the
        // module-level doc comment on transport-iteration non-determinism.
        // Both "obfs4" and "vanilla" appear as whole words; this port
        // deterministically picks "snowflake"/"webtunnel"/"obfs4" first
        // per SUPPORTED_TRANSPORTS' fixed order (obfs4 precedes vanilla).
        let record = obj(vec![("raw", json!("obfs4 or vanilla bridge"))]);
        assert_eq!(extract_transport(&record), "obfs4");
    }
}
