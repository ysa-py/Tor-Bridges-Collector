//! Parity port of `core/nin_survival_pack.py`.
//!
//! NIN Survival Mode: generates and maintains a bridge pack optimized for
//! National Internet Network (NIN / شبکه ملی) isolation, when Iran cuts
//! international connectivity and only CDN-fronted transports (Snowflake,
//! WebTunnel, meek-lite, obfs4 on port 443) can still tunnel through.
//!
//! ADDITIVE in the Python original: does not replace `core/nin_selector.py`
//! or `core/iran_detector.py`.
//!
//! ## Live NIN detection (`crate::iran_detector::NinDetector`)
//!
//! `core/nin_survival_pack.py`'s `__init__` (Python, lines 106-113)
//! constructs `self._detector = NINDetector(events_path=events_path)`
//! whenever the import succeeds — note it passes only `events_path`, not
//! `export_path`, so the constructed detector's own `export_path` always
//! takes `NINDetector`'s own default (`export/iran_cut_pack.txt`),
//! independent of whatever this class's own `export_path` argument was.
//! `detect_nin_state()` then calls `self._detector.is_nin_active()`
//! inside a `try/except Exception` that falls back to `False`.
//!
//! `core/iran_detector.py` is now ported (`src/iran_detector.rs`,
//! Session 9), so this port wires the equivalent: [`NinSurvivalPack`]
//! holds `Option<NinDetector>`, always `Some` from the standard
//! [`NinSurvivalPack::new`]/[`NinSurvivalPack::default`] constructors —
//! matching the same hardcoded-default-export-path detail above — since
//! Rust has no equivalent of Python's import-time fallibility (modules
//! resolve at compile time, not runtime, so there's nothing here that can
//! fail the way a Python `import` can). The `None` case is still a real,
//! reachable Python code path though (`_detector` stays `None` if
//! construction itself raises), so it's preserved as a reachable Rust
//! state too, via [`NinSurvivalPack::without_detector`] — used by tests
//! that specifically exercise that fallback, not by normal construction.
//!
//! **Parity point traced across the actual call graph, not just one
//! function in isolation:** `is_nin_active()`'s own doc comment documents
//! an unguarded directory-creation failure that panics, preserved on
//! purpose because Python's `is_nin_active()` doesn't catch it *itself*.
//! But Python's `NINSurvivalPack.detect_nin_state()` — the caller being
//! ported here — *does* catch it, via its own `except Exception`, same as
//! it would catch any other failure from that call. Faithful parity has
//! to hold at the boundary a caller actually observes, not just inside
//! each function individually: from any code that calls
//! `detect_nin_state()`, Python never raises, always returns a `bool`.
//! [`NinSurvivalPack::detect_nin_state`] therefore wraps the call in
//! `std::panic::catch_unwind`, converting a panic to `false` + a
//! `tracing::warn!`, matching Python's `except Exception as exc:
//! log.warning(...); return False` at this exact call site. This is not a
//! blanket "catch all panics" policy — it's this one call site, because
//! tracing the actual Python call graph up from `is_nin_active()` shows
//! this is where Python's own exception handling actually lives.
//!
//! `generate_pack` and `export_pack` do not depend on the detector at all
//! and are fully parity-verified against the live Python class with no
//! compromise — unchanged by any of the above.
//!
//! ## `enriched.setdefault("transport", tport)` — only-if-absent, not overwrite
//!
//! Python's `dict.setdefault` (line 142) only inserts `tport` (the
//! normalized transport string) under the `"transport"` key if that key is
//! **absent** from the input bridge. If the input already has a
//! `"transport"` key — even an un-normalized one like `"OBFS4"` or
//! `"obfs4-slow"` — the output keeps that original value verbatim. Only
//! the internal priority lookup and the `is_nin_capable` filter use the
//! normalized form; the emitted `"transport"` field does not, unless it
//! was missing to begin with. [`generate_pack`] mirrors this with
//! `entry.entry("transport".to_string()).or_insert(...)`, not a blind
//! overwrite.
//!
//! ## Two different `port` defaulting rules in the same Python file
//!
//! `_normalize_transport` (line 75) reads the port as
//! `bridge.get("port") or 0` — falsy-coalescing: an explicit `null`, `0`,
//! `""`, or a missing key are all treated as `0`.
//!
//! `generate_pack`'s port-443 bonus check (line 146) reads it as
//! `b.get("port", 0)` — *only-if-missing* defaulting: an explicit
//! `"port": null` is **not** replaced by the default (`.get(key, default)`
//! only applies `default` when the key is absent), so `int(None)` is
//! reached and raises `TypeError` in Python, silently caught by that
//! block's own inner `except: pass` (no bonus applied, entry still kept).
//! [`normalize_transport`] and the bonus-check logic in [`generate_pack`]
//! implement these two rules separately and do not share one helper.
//!
//! ## Sort-key coercion is *not* guarded in the Python original
//!
//! `generate_pack`'s final `candidates.sort(key=...)` (lines 165-171) reads
//! `float(b.get("iran_score", b.get("score", 0.0)) or 0.0)` and
//! `float(b.get("last_seen_ts", 0.0) or 0.0)` with **no** surrounding
//! `try/except` — unlike the per-bridge loop body one level up. Python
//! computes every sort key before comparing (decorate-sort-undecorate), so
//! a single candidate with a non-numeric `iran_score`/`score`/
//! `last_seen_ts` raises an uncaught `TypeError` that aborts the *entire*
//! call — not just that one candidate, unlike the per-bridge `except
//! Exception` a few lines above it, which only skips the one malformed
//! input bridge. [`generate_pack`] therefore returns
//! `Result<Vec<_>, NinSurvivalPackError>`: `Ok` with a fully-sorted
//! candidate list, or `Err` if any candidate's sort key isn't coercible —
//! matching Python's whole-call failure rather than silently dropping the
//! offending entry or defaulting its key.
//!
//! ## `str()`-on-arbitrary-JSON-value fields
//!
//! A handful of fields (`transport`/`transport_type`/`type`,
//! `bridge_line`/`line`, `address`/`ip`, `port` in
//! [`format_bridge_line`]) are read with Python's implicit `str()`
//! coercion applied to whatever value is present. [`python_str`] mirrors
//! this faithfully for the JSON shapes every writer in this codebase
//! actually produces for these fields (string, number, bool, null —
//! confirmed by grepping every bridge-dict literal assignment site) —
//! matching the precedent `nin_selector.rs` set for the analogously-typed
//! `transport` field. Array/Object values are not bit-for-bit
//! repr()-faithful (Python dict/list `str()` uses Python's own repr
//! syntax, e.g. single-quoted keys); no writer in this codebase produces
//! those shapes for these fields.
//!
//! ## Rust's type system makes one Python defensive guard unreachable
//!
//! `generate_pack(self, all_bridges)` iterates `all_bridges or []` (line
//! 137) — a defensive guard against a caller passing `None` despite the
//! type hint. [`generate_pack`] takes `&[Map<String, Value>]`, so "absent"
//! is not representable; the guard has no Rust equivalent to port because
//! there is nothing left for it to guard against.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::iran_detector::NinDetector;

/// Mirrors `NIN_TRANSPORT_PRIORITIES`. Order matches the Python dict's
/// insertion order; membership + value lookup are the only ways it's used
/// (`get_status` round-trips it into a JSON object where key order is not
/// asserted by the parity tests — see `tests/parity/nin_survival_pack_parity.rs`).
pub const NIN_TRANSPORT_PRIORITIES: &[(&str, i64)] = &[
    ("snowflake", 1),
    ("webtunnel", 2),
    ("meek_lite", 3),
    ("meek-lite", 3),
    ("obfs4_443", 4),
    ("obfs4", 5),
];

fn transport_priority(transport: &str) -> Option<i64> {
    NIN_TRANSPORT_PRIORITIES
        .iter()
        .find(|(k, _)| *k == transport)
        .map(|(_, v)| *v)
}

/// Mirrors `_is_nin_capable`.
pub fn is_nin_capable(transport: &str) -> bool {
    transport_priority(transport).is_some()
}

/// Errors surfaced by this module.
#[derive(Debug, thiserror::Error)]
pub enum NinSurvivalPackError {
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Mirrors the uncaught Python `TypeError` from `float(...)` on a
    /// non-numeric `iran_score`/`score`/`last_seen_ts` sort key — see the
    /// module doc comment's "Sort-key coercion" section.
    #[error(
        "candidate field `{field}` is present but not coercible to a number \
             (Python `float(...)` would raise here): {value}"
    )]
    NonNumericSortKey { field: &'static str, value: String },
    /// Mirrors the uncaught Python `AttributeError` from calling
    /// `.startswith()` on a non-string, truthy `bridge_line`/`line` value
    /// inside `_normalize_transport`, caught by `generate_pack`'s
    /// per-bridge `except Exception` (the bridge is skipped, not fatal to
    /// the whole call — contrast with `NonNumericSortKey` above).
    #[error("bridge `bridge_line`/`line` is a non-string truthy value: {0}")]
    NonStringBridgeLine(String),
}

fn io_err(path: &Path, source: std::io::Error) -> NinSurvivalPackError {
    NinSurvivalPackError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Mirrors Python truthiness (`or`-chain short-circuiting) for the JSON
/// value shapes these fields realistically hold.
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Mirrors `map.get(k1) or map.get(k2) or ... or default` — returns the
/// first *present and truthy* value among `keys`, else `default`.
fn get_truthy_or<'a>(map: &'a Map<String, Value>, keys: &[&str], default: &'a Value) -> &'a Value {
    for k in keys {
        if let Some(v) = map.get(*k) {
            if is_truthy(v) {
                return v;
            }
        }
    }
    default
}

/// Best-effort mirror of Python's `str()` for string/number/bool/null.
/// See the module doc comment ("`str()`-on-arbitrary-JSON-value fields")
/// for why Array/Object are not repr()-faithful.
fn python_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Null => "None".to_string(),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                n.to_string()
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                let s = f.to_string();
                // Rust's float Display omits a trailing ".0" for whole
                // numbers; Python's str(float) never does.
                if s.contains('.') || s.contains('e') || s.contains('E') {
                    s
                } else {
                    format!("{s}.0")
                }
            }
        }
        other => other.to_string(),
    }
}

/// Mirrors Python's `int(...)` builtin for the JSON shapes a `port` field
/// realistically holds, returning `None` where Python would raise
/// (mirrors the inner `except Exception: pass` in `generate_pack`'s
/// port-443 bonus check).
fn python_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if let Some(u) = n.as_u64() {
                i64::try_from(u).ok()
            } else {
                n.as_f64().map(|f| f.trunc() as i64) // int() truncates toward zero
            }
        }
        Value::Bool(b) => Some(if *b { 1 } else { 0 }),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Mirrors `_normalize_transport`.
pub fn normalize_transport(bridge: &Map<String, Value>) -> Result<String, NinSurvivalPackError> {
    let empty = Value::String(String::new());
    let raw = get_truthy_or(bridge, &["transport", "transport_type", "type"], &empty);
    let raw_str = if is_truthy(raw) {
        python_str(raw)
    } else {
        // raw fell through to the empty-string default above; try the
        // bridge_line/line parse path (Python lines 68-72).
        let line_val = get_truthy_or(bridge, &["bridge_line", "line"], &empty);
        if is_truthy(line_val) {
            match line_val {
                Value::String(s) => {
                    if let Some(rest) = s.strip_prefix("bridge ") {
                        rest.split_whitespace()
                            .next()
                            .map(|s| s.to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    }
                }
                other => {
                    // Python: line.startswith("bridge ") on a non-string
                    // truthy value raises AttributeError here.
                    return Err(NinSurvivalPackError::NonStringBridgeLine(python_str(other)));
                }
            }
        } else {
            String::new()
        }
    };

    let s = raw_str.trim().to_lowercase().replace('-', "_");

    let port = bridge.get("port").filter(|v| is_truthy(v));
    let port_is_443 = port.map(python_str).as_deref() == Some("443");
    if s == "obfs4" && port_is_443 {
        Ok("obfs4_443".to_string())
    } else {
        Ok(s)
    }
}

/// Generates and maintains a bridge pack optimized for NIN isolation.
///
/// Mirrors `NINSurvivalPack`. See the module doc comment for how the NIN
/// detector is wired up and how `Option<NinDetector>` maps to Python's
/// `self._detector: Any | None`.
pub struct NinSurvivalPack {
    export_path: String,
    events_path: String,
    detector: Option<NinDetector>,
    last_pack: Vec<Map<String, Value>>,
    last_generated_ts: f64,
}

impl Default for NinSurvivalPack {
    /// Mirrors the Python constructor's default arguments.
    fn default() -> Self {
        Self::new("export/iran_cut_pack.txt", "data/nin_events.json")
    }
}

impl NinSurvivalPack {
    /// Mirrors `NINSurvivalPack.__init__` in the normal case (Python's
    /// import succeeds, so `self._detector` is constructed). Note the
    /// constructed `NinDetector` always gets the *literal* default export
    /// path, not this constructor's own `export_path` argument — see the
    /// module doc comment; that mirrors what the one line of Python here
    /// (`NINDetector(events_path=events_path)`) actually passes, which is
    /// not `export_path`.
    pub fn new(export_path: impl Into<String>, events_path: impl Into<String>) -> Self {
        let events_path = events_path.into();
        let detector = Some(NinDetector::new(
            events_path.clone(),
            "export/iran_cut_pack.txt",
        ));
        Self::with_detector(export_path, events_path, detector)
    }

    /// Mirrors the real, reachable-but-narrow Python code path where
    /// `self._detector` stays `None` (import or construction failed). Not
    /// used by [`Self::new`]/[`Self::default`] — Rust has no equivalent
    /// import-time fallibility to trigger this automatically — but kept
    /// as an explicit constructor since it's genuine Python behavior, and
    /// used by tests that specifically exercise the no-detector fallback.
    pub fn without_detector(
        export_path: impl Into<String>,
        events_path: impl Into<String>,
    ) -> Self {
        Self::with_detector(export_path, events_path, None)
    }

    /// Inject a specific detector (or `None`) directly. Python's nearest
    /// equivalent for tests would be monkeypatching `self._detector`
    /// after construction; Rust's privacy model doesn't allow reaching
    /// into a private field from outside the module, so this is the
    /// idiomatic substitute — not a general observer/DI abstraction, just
    /// a plain constructor parameter, matching how simple the underlying
    /// `Option` field already is.
    pub fn with_detector(
        export_path: impl Into<String>,
        events_path: impl Into<String>,
        detector: Option<NinDetector>,
    ) -> Self {
        Self {
            export_path: export_path.into(),
            events_path: events_path.into(),
            detector,
            last_pack: Vec::new(),
            last_generated_ts: 0.0,
        }
    }

    pub fn export_path(&self) -> &str {
        &self.export_path
    }

    pub fn events_path(&self) -> &str {
        &self.events_path
    }

    pub fn last_pack(&self) -> &[Map<String, Value>] {
        &self.last_pack
    }

    pub fn detector_available(&self) -> bool {
        self.detector.is_some()
    }

    /// Mirrors `detect_nin_state`. See the module doc comment's parity
    /// note: Python's own `except Exception` at this exact call site is
    /// why a panic from `is_nin_active` gets caught here specifically,
    /// not swallowed generically.
    pub fn detect_nin_state(&self) -> bool {
        let Some(detector) = self.detector.as_ref() else {
            tracing::debug!("[NinSurvivalPack] no detector — assuming NIN inactive");
            return false;
        };
        match std::panic::catch_unwind(|| detector.is_nin_active(false)) {
            Ok(active) => active,
            Err(_) => {
                tracing::warn!("[NinSurvivalPack] NIN detection failed (panicked)");
                false
            }
        }
    }

    /// Mirrors `generate_pack`. See the module doc comment for the
    /// `setdefault`, two-port-defaulting-rules, and sort-key-coercion
    /// sections — each is load-bearing for this implementation.
    pub fn generate_pack(
        &mut self,
        all_bridges: &[Map<String, Value>],
    ) -> Result<Vec<Map<String, Value>>, NinSurvivalPackError> {
        let mut candidates: Vec<Map<String, Value>> = Vec::new();

        for b in all_bridges {
            let tport = match normalize_transport(b) {
                Ok(t) => t,
                Err(_) => continue, // per-bridge `except Exception`: skip, not fatal
            };
            if !is_nin_capable(&tport) {
                continue;
            }

            let mut enriched = b.clone();
            enriched
                .entry("transport".to_string())
                .or_insert_with(|| Value::String(tport.clone()));
            let base_priority = transport_priority(&tport).expect("checked by is_nin_capable");
            enriched.insert("nin_priority".to_string(), json!(base_priority));

            // Bonus for port 443 — inner try/except: on failure, no bonus,
            // entry still kept (see module doc comment).
            if let Some(port_val) = b.get("port") {
                if let Some(p) = python_int(port_val) {
                    if p == 443 {
                        let bumped = std::cmp::max(1, base_priority - 1);
                        enriched.insert("nin_priority".to_string(), json!(bumped));
                        enriched.insert("port_443_bonus".to_string(), json!(true));
                    }
                }
                // python_int(...) == None mirrors int(...) raising: no
                // bonus, fall through silently.
            } else {
                // b.get("port", 0) with a missing key defaults to 0, which
                // is never 443, so no bonus either way.
            }

            // Bonus for IPv4.
            let empty = Value::String(String::new());
            let addr_val = get_truthy_or(b, &["address", "ip"], &empty);
            let addr = python_str(addr_val);
            if addr.contains('.') && !addr.contains(':') {
                enriched.insert("ipv4_bonus".to_string(), json!(true));
            }

            candidates.push(enriched);
        }

        // Sort: nin_priority asc, then iran_score/score desc, then
        // last_seen_ts desc. Stable sort to match Python's `list.sort`.
        // Sort keys are computed for every candidate up front so a single
        // malformed value fails the whole call, matching Python's
        // decorate-sort-undecorate semantics (see module doc comment).
        let mut keyed: Vec<(i64, f64, f64, Map<String, Value>)> =
            Vec::with_capacity(candidates.len());
        for c in candidates {
            let priority = c.get("nin_priority").and_then(Value::as_i64).unwrap_or(99);

            let empty_num = json!(0.0);
            let score_val = {
                let iran_score = c.get("iran_score");
                match iran_score {
                    Some(v) if is_truthy(v) => v.clone(),
                    _ => {
                        let score = c.get("score");
                        match score {
                            Some(v) if is_truthy(v) => v.clone(),
                            _ => empty_num.clone(),
                        }
                    }
                }
            };
            let score = python_float(&score_val).ok_or_else(|| {
                NinSurvivalPackError::NonNumericSortKey {
                    field: "iran_score/score",
                    value: score_val.to_string(),
                }
            })?;

            let lst_val = match c.get("last_seen_ts") {
                Some(v) if is_truthy(v) => v.clone(),
                _ => empty_num.clone(),
            };
            let last_seen =
                python_float(&lst_val).ok_or_else(|| NinSurvivalPackError::NonNumericSortKey {
                    field: "last_seen_ts",
                    value: lst_val.to_string(),
                })?;

            keyed.push((priority, score, last_seen, c));
        }
        keyed.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
                .then(b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
        });

        let sorted: Vec<Map<String, Value>> = keyed.into_iter().map(|(_, _, _, c)| c).collect();
        self.last_pack = sorted.clone();
        self.last_generated_ts = unix_time_now();
        Ok(sorted)
    }

    /// Mirrors `export_pack`.
    pub fn export_pack(&self, path: Option<&str>) -> Result<(), NinSurvivalPackError> {
        let target: &str = match path {
            Some(p) if !p.is_empty() => p,
            _ => &self.export_path,
        };
        let target_path = Path::new(target);
        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| io_err(target_path, e))?;
            }
        }

        let mut body = String::new();
        body.push_str("# TorShield-IR Ultra VIP — NIN Survival Pack\n");
        body.push_str(&format!("# Generated: {}\n", python_isoformat_utc_now()));
        body.push_str("# Transports: snowflake > webtunnel > meek-lite > obfs4:443\n");
        body.push_str(&format!("# Total: {} bridges\n", self.last_pack.len()));
        body.push_str("# Source: core/nin_survival_pack.py\n\n");

        for b in &self.last_pack {
            let empty = Value::String(String::new());
            let line_val = get_truthy_or(b, &["bridge_line", "line"], &empty);
            let line = if is_truthy(line_val) {
                python_str(line_val)
            } else {
                format_bridge_line(b)
            };
            body.push_str(&line);
            body.push('\n');
        }

        std::fs::write(target_path, body).map_err(|e| io_err(target_path, e))
    }

    /// Mirrors `get_status`. `nin_detector_available` mirrors `self._detector
    /// is not None`; `nin_active` mirrors `self.detect_nin_state() if
    /// self._detector else False` — computed via `detect_nin_state()`
    /// itself so the panic-recovery behavior documented there applies
    /// here too, not a second, separately-maintained code path.
    pub fn get_status(&self) -> Value {
        let priorities: Map<String, Value> = NIN_TRANSPORT_PRIORITIES
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        let nin_detector_available = self.detector.is_some();
        let nin_active = if nin_detector_available {
            self.detect_nin_state()
        } else {
            false
        };
        json!({
            "engine": "NINSurvivalPack",
            "nin_detector_available": nin_detector_available,
            "nin_active": nin_active,
            "last_pack_size": self.last_pack.len(),
            "last_generated_ts": self.last_generated_ts,
            "transport_priorities": Value::Object(priorities),
            "export_path": self.export_path,
        })
    }
}

/// Mirrors `_format_bridge_line`.
fn format_bridge_line(b: &Map<String, Value>) -> String {
    let default_obfs4 = Value::String("obfs4".to_string());
    let tport = b
        .get("transport")
        .filter(|v| matches!(v, Value::String(_)))
        .unwrap_or(&default_obfs4);
    let tport_s = python_str(tport);

    let default_addr = Value::String("0.0.0.0".to_string());
    let empty = Value::String(String::new());
    let addr_val = get_truthy_or(b, &["address", "ip"], &empty);
    let addr = if is_truthy(addr_val) {
        python_str(addr_val)
    } else {
        python_str(&default_addr)
    };

    let default_port = json!(443);
    let port_val = b.get("port").unwrap_or(&default_port);
    let port_s = python_str(port_val);

    let default_fp = "0".repeat(40);
    let fp_val = get_truthy_or(b, &["fingerprint", "id"], &empty);
    let fp = if is_truthy(fp_val) {
        python_str(fp_val)
    } else {
        default_fp
    };

    format!("bridge {tport_s} {addr}:{port_s} {fp}")
}

/// Mirrors Python's `float(...)` builtin for the JSON shapes these sort
/// keys realistically hold, `None` where Python would raise `TypeError`/
/// `ValueError` (see the module doc comment's "Sort-key coercion"
/// section).
fn python_float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// `time.time()` — seconds since the Unix epoch as an `f64`.
fn unix_time_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Mirrors `datetime.now(UTC).isoformat()` used directly in
/// `export_pack` (Python line 187) — deliberately **not** reused from
/// `dt_utils::utc_now_iso()`. Two independent reasons:
///
/// 1. `core/nin_survival_pack.py` calls the raw stdlib `.isoformat()`
///    directly, not `core.dt_utils.utc_now_iso()` — there is no
///    indirection through that wrapper in the Python source to mirror.
/// 2. Empirically (this sandbox, Python 3.12), `datetime.now(UTC)
///    .isoformat()` includes microsecond precision
///    (`"...T06:44:47.771971+00:00"`), but `dt_utils.rs::utc_now_iso()`
///    is implemented with `SecondsFormat::Secs`, which drops the
///    fractional part entirely — that existing helper does not actually
///    match its own Python counterpart at full precision. Flagged in
///    `MIGRATION_NOTES.md` as a discovered issue in already-shipped code,
///    out of scope to fix here (touches a previously parity-verified
///    file with other call sites this session hasn't reviewed).
///
/// This function uses genuine microsecond precision
/// (`SecondsFormat::Micros`), matching Python for every case except the
/// ~1-in-1,000,000 chance `Utc::now()` lands on exactly zero
/// microseconds, where Python omits the fractional part entirely and
/// this prints `.000000` instead. Purely cosmetic (a `#`-prefixed
/// comment header in a human-readable export file — confirmed no reader
/// in this codebase parses it back), not a functional divergence.
fn python_isoformat_utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn transport_priorities_lookup() {
        assert_eq!(transport_priority("snowflake"), Some(1));
        assert_eq!(transport_priority("meek-lite"), Some(3));
        assert_eq!(transport_priority("meek_lite"), Some(3));
        assert_eq!(transport_priority("nope"), None);
    }

    #[test]
    fn is_nin_capable_matches_priority_table() {
        assert!(is_nin_capable("obfs4"));
        assert!(is_nin_capable("obfs4_443"));
        assert!(!is_nin_capable("vanilla"));
    }

    #[test]
    fn normalize_transport_prefers_explicit_field() {
        let b = bridge(&[("transport", json!("OBFS4")), ("port", json!(443))]);
        assert_eq!(normalize_transport(&b).unwrap(), "obfs4_443");
    }

    #[test]
    fn normalize_transport_obfs4_non_443_stays_obfs4() {
        let b = bridge(&[("transport", json!("obfs4")), ("port", json!(9001))]);
        assert_eq!(normalize_transport(&b).unwrap(), "obfs4");
    }

    #[test]
    fn normalize_transport_falls_back_to_bridge_line() {
        let b = bridge(&[("bridge_line", json!("bridge snowflake 1.2.3.4:443 abc"))]);
        assert_eq!(normalize_transport(&b).unwrap(), "snowflake");
    }

    #[test]
    fn normalize_transport_non_string_bridge_line_errors() {
        let b = bridge(&[("bridge_line", json!({"nested": true}))]);
        assert!(normalize_transport(&b).is_err());
    }

    #[test]
    fn generate_pack_filters_non_nin_transports() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![
            bridge(&[("transport", json!("vanilla"))]),
            bridge(&[("transport", json!("snowflake"))]),
        ];
        let out = pack.generate_pack(&bridges).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["transport"], json!("snowflake"));
    }

    #[test]
    fn generate_pack_setdefault_preserves_original_transport_value() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![bridge(&[("transport", json!("Snowflake"))])];
        let out = pack.generate_pack(&bridges).unwrap();
        // Original casing preserved — normalized form only used
        // internally for priority lookup, per setdefault semantics.
        assert_eq!(out[0]["transport"], json!("Snowflake"));
    }

    #[test]
    fn generate_pack_port_443_bonus_applies_and_floors_at_one() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![bridge(&[
            ("transport", json!("webtunnel")),
            ("port", json!(443)),
        ])];
        let out = pack.generate_pack(&bridges).unwrap();
        assert_eq!(out[0]["nin_priority"], json!(1)); // 2 - 1 = 1
        assert_eq!(out[0]["port_443_bonus"], json!(true));

        let mut pack2 = NinSurvivalPack::default();
        let bridges2 = vec![bridge(&[
            ("transport", json!("snowflake")),
            ("port", json!(443)),
        ])];
        let out2 = pack2.generate_pack(&bridges2).unwrap();
        assert_eq!(out2[0]["nin_priority"], json!(1)); // max(1, 1-1) = 1, floored
    }

    #[test]
    fn generate_pack_null_port_skips_bonus_without_dropping_entry() {
        // b.get("port", 0) with an explicit null present does NOT use the
        // default 0 — int(None) raises, caught, no bonus, entry kept.
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![bridge(&[
            ("transport", json!("webtunnel")),
            ("port", Value::Null),
        ])];
        let out = pack.generate_pack(&bridges).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["nin_priority"], json!(2)); // no bonus
        assert!(out[0].get("port_443_bonus").is_none());
    }

    #[test]
    fn generate_pack_ipv4_bonus() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![
            bridge(&[
                ("transport", json!("snowflake")),
                ("address", json!("1.2.3.4")),
            ]),
            bridge(&[("transport", json!("snowflake")), ("address", json!("::1"))]),
        ];
        let out = pack.generate_pack(&bridges).unwrap();
        assert_eq!(out[0]["ipv4_bonus"], json!(true));
        assert!(out[1].get("ipv4_bonus").is_none());
    }

    #[test]
    fn generate_pack_sort_order() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![
            bridge(&[("transport", json!("obfs4")), ("iran_score", json!(0.9))]),
            bridge(&[
                ("transport", json!("snowflake")),
                ("iran_score", json!(0.1)),
            ]),
            bridge(&[
                ("transport", json!("webtunnel")),
                ("iran_score", json!(0.5)),
            ]),
        ];
        let out = pack.generate_pack(&bridges).unwrap();
        let transports: Vec<_> = out
            .iter()
            .map(|b| b["transport"].as_str().unwrap())
            .collect();
        assert_eq!(transports, vec!["snowflake", "webtunnel", "obfs4"]);
    }

    #[test]
    fn generate_pack_non_numeric_score_errors_whole_call() {
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![bridge(&[
            ("transport", json!("snowflake")),
            ("iran_score", json!("not-a-number")),
        ])];
        assert!(pack.generate_pack(&bridges).is_err());
    }

    #[test]
    fn export_pack_writes_header_and_lines() {
        let tmp =
            std::env::temp_dir().join(format!("nin_survival_pack_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let out_path = tmp.join("iran_cut_pack.txt");

        let mut pack = NinSurvivalPack::new(out_path.to_str().unwrap(), "unused.json");
        let bridges = vec![bridge(&[
            ("transport", json!("snowflake")),
            ("bridge_line", json!("bridge snowflake 1.2.3.4:443 abcd")),
        ])];
        pack.generate_pack(&bridges).unwrap();
        pack.export_pack(None).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("# TorShield-IR Ultra VIP — NIN Survival Pack"));
        assert!(content.contains("# Total: 1 bridges"));
        assert!(content.contains("bridge snowflake 1.2.3.4:443 abcd"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn export_pack_formats_missing_bridge_line() {
        let tmp =
            std::env::temp_dir().join(format!("nin_survival_pack_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let out_path = tmp.join("out.txt");

        let mut pack = NinSurvivalPack::new(out_path.to_str().unwrap(), "unused.json");
        let bridges = vec![bridge(&[
            ("transport", json!("snowflake")),
            ("address", json!("9.9.9.9")),
            ("port", json!(443)),
            ("fingerprint", json!("DEADBEEF")),
        ])];
        pack.generate_pack(&bridges).unwrap();
        pack.export_pack(None).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("bridge snowflake 9.9.9.9:443 DEADBEEF"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn get_status_reports_detector_unavailable() {
        let pack =
            NinSurvivalPack::without_detector("export/iran_cut_pack.txt", "data/nin_events.json");
        let status = pack.get_status();
        assert_eq!(status["engine"], json!("NINSurvivalPack"));
        assert_eq!(status["nin_detector_available"], json!(false));
        assert_eq!(status["nin_active"], json!(false));
        assert_eq!(status["last_pack_size"], json!(0));
    }

    #[test]
    fn detect_nin_state_without_detector_is_false() {
        let pack =
            NinSurvivalPack::without_detector("export/iran_cut_pack.txt", "data/nin_events.json");
        assert!(!pack.detect_nin_state());
    }

    #[test]
    fn default_constructor_has_detector_available() {
        let pack = NinSurvivalPack::default();
        assert!(pack.detector_available());
        assert_eq!(pack.get_status()["nin_detector_available"], json!(true));
    }

    /// Real end-to-end probing through the injected detector (no seam to
    /// avoid it — same as `iran_detector.rs`'s own `is_nin_active`, this
    /// genuinely costs the real ~3s probe budget). Only asserts that a
    /// `bool` comes back without panicking; deliberately doesn't assert
    /// which one, so it stays valid regardless of this sandbox's current
    /// network characteristics.
    #[test]
    fn detect_nin_state_with_real_detector_does_not_panic() {
        let dir = std::env::temp_dir().join(format!(
            "torshield-survival-pack-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let pack = NinSurvivalPack::new(
            dir.join("iran_cut_pack.txt").to_string_lossy().to_string(),
            dir.join("nin_events.json").to_string_lossy().to_string(),
        );
        let _ = pack.detect_nin_state(); // must not panic
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Confirms the `catch_unwind` wiring documented in the module doc
    /// comment actually works: forces the same `ENOTDIR` directory-
    /// creation panic `iran_detector.rs`'s own tests force directly, but
    /// here through `NinSurvivalPack::detect_nin_state`, and asserts a
    /// graceful `false` comes back rather than the panic propagating.
    ///
    /// Depends on this sandbox's currently-confirmed network
    /// characteristics (see `iran_detector.rs`'s module doc comment):
    /// both real NIN probe targets connect instantly and international
    /// ones time out, so `is_nin_active()` reliably reaches
    /// `on_nin_detected` → `record_event` → the panic. There's no
    /// injectable-targets seam at this level to force that outcome
    /// independent of real network state — Python doesn't have one
    /// either at the equivalent call site, so adding one here would be
    /// scope beyond what this wiring task needed.
    #[test]
    fn detect_nin_state_recovers_from_detector_panic() {
        let dir = std::env::temp_dir().join(format!(
            "torshield-survival-pack-test-panic-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let blocking_file = dir.join("not_a_directory");
        std::fs::write(&blocking_file, b"blocks create_dir_all below it").unwrap();
        let events_path = blocking_file.join("nested").join("nin_events.json");

        let detector = NinDetector::new(events_path, dir.join("iran_cut_pack.txt"));
        let pack = NinSurvivalPack::with_detector(
            "export/iran_cut_pack.txt",
            "data/nin_events.json",
            Some(detector),
        );

        assert!(
            !pack.detect_nin_state(),
            "a panicking detector must be caught and treated as NIN-inactive, not propagate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_pack_explicit_obfs4_with_port_443_keeps_label_bumps_priority() {
        // transport key present ("obfs4") so setdefault does NOT overwrite
        // it with the normalized "obfs4_443" form, but the priority
        // lookup and bonus both use the normalized form internally:
        // base=4 (obfs4_443), bonus -1 -> 3. Verified against live Python
        // (see conversation record) — Python returns transport="obfs4",
        // nin_priority=3.
        let mut pack = NinSurvivalPack::default();
        let bridges = vec![bridge(&[
            ("transport", json!("obfs4")),
            ("port", json!(443)),
        ])];
        let out = pack.generate_pack(&bridges).unwrap();
        assert_eq!(out[0]["transport"], json!("obfs4"));
        assert_eq!(out[0]["nin_priority"], json!(3));
        assert_eq!(out[0]["port_443_bonus"], json!(true));
    }

    #[test]
    fn python_str_formats_whole_number_floats_with_trailing_zero() {
        assert_eq!(python_str(&json!(443.0)), "443.0");
        assert_eq!(python_str(&json!(443)), "443");
        assert_eq!(python_str(&json!(true)), "True");
    }
}
