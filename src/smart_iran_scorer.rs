//! Parity port of `core/smart_iran_scorer.py`.
//!
//! Unified AI + heuristic bridge scorer: blends [`crate::scorer::IranScorer`],
//! NIN survivability, DPI resistance, port safety, and a censorship-level
//! modifier into a single 0-100 score per bridge.
//!
//! ## `core.scorer.IranScorer` integration is real, not deferred — but inherits one known gap
//!
//! Unlike `nin_survival_pack.rs`'s NIN-detector situation, `core/scorer.py`
//! is already ported (`src/scorer.rs`, prior session). Python's
//! `IranScorer()` constructor auto-loads `data/transport_weights.json` if
//! present (`_load_transport_scores`, called from `__init__`) — confirmed
//! by reading `core/scorer.py` directly rather than assuming
//! `IranScorer::with_defaults()` alone is equivalent (it isn't: that
//! constructor's own doc comment says "default transport scores" only, no
//! auto-load). [`SmartIranScorer::new`] calls
//! `with_defaults()` **and then** `load_transport_scores(Path::new("data/transport_weights.json"))`
//! to match Python's actual constructor behavior. The integration itself
//! is real — but `scorer.rs`'s own already-disclosed `ja3_penalty()`
//! simplification turns out to matter more than its one-line description
//! suggested; see "Inherited from `scorer.rs`" near the end of this
//! comment for the measured, per-transport size of that gap.
//!
//! ## AI refinement layer is deferred (same pattern as the NIN detector)
//!
//! `torshield_ai_gateway.iran_intelligence.IranIntelligenceLayer` is not
//! ported (the whole `torshield_ai_gateway` package — 30 files — is
//! unstarted). Python's own `_load_subsystems` already defines the
//! fallback for this: if the import fails, `self.use_ai` is reset to
//! `False` and a warning logged. This port takes that exact branch
//! unconditionally — `use_ai` is accepted as a constructor parameter (for
//! API-shape fidelity) but has no effect; `_maybe_ai_refine` is always a
//! no-op. Revisit once an `iran_intelligence.rs` exists.
//!
//! ## `tier`/`recommendation` are not recomputed after AI refinement
//!
//! `score_record` calls `_assign_tier` (sets `tier`/`recommendation` from
//! the pre-AI `final_score`) **before** `_maybe_ai_refine` (which can
//! change `final_score` but does not touch `tier`/`recommendation`).
//! Confirmed by reading the call order in `core/smart_iran_scorer.py`'s
//! `score_record` — not a Rust-introduced quirk. A bridge whose AI-refined
//! score crosses a tier boundary keeps its pre-refinement tier label. This
//! is moot in practice today (AI refinement is always a no-op per above),
//! but the field ordering is preserved for when it isn't.
//!
//! ## `bridge_id` uses missing-key-only defaulting, and can be JSON `null`
//!
//! `record.get("fingerprint", record.get("id", raw[:40]))` — both `.get`
//! calls use the two-argument form, so only an **absent** key falls
//! through; an explicit `"fingerprint": null` is kept as `None`, not
//! replaced. Modeled as `serde_json::Value` (not `String`) to preserve
//! this exactly, including the `null` case. Confirmed this field has no
//! downstream behavioral effect anywhere else in the Python module (not
//! read by `_assign_tier`, `_maybe_ai_refine`, `score_all`, `top_bridges`,
//! `write_report`, or `export_bridge_lines`) — purely descriptive.
//!
//! ## `obfs4` substring override in `_extract_endpoint`
//!
//! After the word-boundary transport regex match, Python unconditionally
//! overrides `transport = "obfs4"` if the literal substring `"obfs4"`
//! appears **anywhere** in the lowercased raw line — even if the regex
//! already matched a different transport. Ported as a literal second
//! check, not merged into the regex, to preserve the override semantics
//! exactly (a line matching `"snowflake"` via the regex but also
//! containing `"obfs4"` elsewhere ends up labeled `"obfs4"`).
//!
//! ## `round()` is banker's rounding, not Rust's default
//!
//! Every rounded field (`base_score`, `final_score` to 1 decimal;
//! `nin_score`/`dpi_score`/`port_score`/`level_mod` to 3) uses Python's
//! `round()`, which rounds half-to-even — not Rust's default
//! round-half-away-from-zero. [`python_round_1`]/[`python_round_3`] mirror
//! the pattern already established in `adaptive_transport.rs`'s
//! `python_round_4`/`python_round_int` (format-then-reparse, which uses
//! the same half-to-even rule Python does).
//!
//! ## `data/` directory creation
//!
//! Python creates `data/` as a **module-import-time** side effect
//! (`DATA_DIR.mkdir(parents=True, exist_ok=True)` at module scope) — so it
//! always exists by the time `write_report`'s *default* path is used, but
//! a custom path passed to `write_report`/`export_bridge_lines` is **not**
//! separately protected by that line (only `export_bridge_lines` has its
//! own explicit `path.parent.mkdir(...)` call in the Python source;
//! `write_report` does not). [`SmartIranScorer::new`] creates `data/`
//! (mirroring the module-import side effect, since constructing this type
//! is the closest Rust equivalent to "the module is in use"); `write_report`
//! does **not** additionally create directories for a custom path, matching
//! Python's actual behavior for that case (a custom, not-yet-existing
//! directory fails in both languages); `export_bridge_lines` does create
//! its target's parent directory, matching Python's explicit call.
//!
//! ## CLI (`if __name__ == "__main__":`) is not ported
//!
//! Consistent with every other module ported so far (e.g. `nin_selector.py`
//! has one; `nin_selector.rs` does not) — entry-point scripts are out of
//! scope for these library ports.
//!
//! ## Inherited from `scorer.rs`: the JA3 penalty gap is now CLOSED (Session 10)
//!
//! Earlier sessions disclosed that `scorer::IranScorer::ja3_penalty()` was
//! a stub returning `0`, deferring the JA3 database integration. Wiring
//! this module up to `scorer.rs` and comparing against live Python showed
//! the real cost of that stub: for the common case of a record with no
//! explicit `ja3_hash`, Python's `_ja3_penalty` applies a transport-keyed
//! heuristic penalty (measured against a live Python process as:
//! `snowflake`→1, `webtunnel`→2, `obfs4`→3, `meek_lite`→4, `unknown`→8,
//! `vanilla`→14 on the `score()` 0-100 scale). The stub applied none of it,
//! so `SmartIranScorer::base_score`/`final_score` read higher than Python's
//! for every hash-less record.
//!
//! **Session 10 fix:** `scorer::IranScorer::ja3_penalty` is now wired to the
//! already-ported [`crate::ja3_intelligence::JA3Intel`]
//! (`transport_default_risk` / `port_risk` / `score`), applying Python's
//! self-contained fallback formula
//! `int(round(max(transport_default_risk(transport), port_risk(port)) * 15))`
//! (and the `ja3_hash`-present database lookup), with Python's
//! round-half-to-even semantics replicated exactly. `base_score` therefore
//! now matches the *real, unpatched* Python scorer byte-for-byte.
//!
//! Parity tests in `tests/parity/smart_iran_scorer_parity.rs` reflect this:
//! the `JA3_PATCH_PREAMBLE` that previously monkeypatched Python's
//! `_ja3_penalty` to `0` is now a no-op (comparisons run real-vs-real), and
//! `measures_real_world_ja3_gap_unpatched` now asserts the gap is ≈ 0
//! rather than pinning a ~14-point divergence. See `scorer.rs` and
//! `tests/parity/scorer_parity.rs` for the direct ja3 parity coverage.

use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::scorer::IranScorer;

// ─────────────────────────────────────────────────────────────────────────────
// Lookup tables (mirror the Python module-level dicts exactly)
// ─────────────────────────────────────────────────────────────────────────────

pub const SAFE_PORTS: &[(i64, f64)] = &[
    (443, 1.00),
    (80, 0.80),
    (2053, 0.90),
    (2083, 0.85),
    (2087, 0.85),
    (2096, 0.80),
    (8443, 0.75),
    (8080, 0.60),
];

pub const TRANSPORT_DPI: &[(&str, f64)] = &[
    ("snowflake", 0.95),
    ("webtunnel", 0.88),
    ("meek_lite", 0.80),
    ("obfs4", 0.72),
    ("vanilla", 0.05),
    ("unknown", 0.30),
];

pub const TRANSPORT_NIN: &[(&str, f64)] = &[
    ("snowflake", 1.00),
    ("webtunnel", 0.90),
    ("meek_lite", 0.85),
    ("obfs4", 0.35),
    ("vanilla", 0.05),
    ("unknown", 0.20),
];

pub const CDN_ASN_BONUS: &[(&str, f64)] = &[
    ("AS200000", 0.95),
    ("AS13335", 0.90),
    ("AS20940", 0.80),
    ("AS16509", 0.75),
    ("AS8075", 0.70),
    ("AS15169", 0.65),
    ("AS54113", 0.70),
];

struct LevelWeights {
    base: f64,
    nin: f64,
    dpi: f64,
    port: f64,
    level: f64,
}

fn level_weights(level: i64) -> LevelWeights {
    match level {
        1 => LevelWeights {
            base: 0.50,
            nin: 0.10,
            dpi: 0.20,
            port: 0.10,
            level: 0.10,
        },
        2 => LevelWeights {
            base: 0.40,
            nin: 0.15,
            dpi: 0.25,
            port: 0.10,
            level: 0.10,
        },
        3 => LevelWeights {
            base: 0.35,
            nin: 0.20,
            dpi: 0.25,
            port: 0.10,
            level: 0.10,
        },
        4 => LevelWeights {
            base: 0.25,
            nin: 0.25,
            dpi: 0.30,
            port: 0.10,
            level: 0.10,
        },
        5 => LevelWeights {
            base: 0.15,
            nin: 0.45,
            dpi: 0.25,
            port: 0.05,
            level: 0.10,
        },
        // censorship_level is clamped to 1..=5 in SmartIranScorer::new,
        // so this arm is unreachable under normal conditions. A default
        // level-1 fallback is returned instead of a panic so a future
        // caller that bypasses the constructor guard does not crash.
        _ => LevelWeights {
            base: 0.50,
            nin: 0.05,
            dpi: 0.25,
            port: 0.15,
            level: 0.05,
        },
    }
}

fn level_transport_boost(level: i64, transport: &str) -> f64 {
    let table: &[(&str, f64)] = match level {
        4 => &[
            ("snowflake", 1.15),
            ("webtunnel", 1.10),
            ("obfs4", 0.85),
            ("vanilla", 0.30),
        ],
        5 => &[
            ("snowflake", 1.30),
            ("webtunnel", 1.25),
            ("obfs4", 0.50),
            ("vanilla", 0.10),
            ("meek_lite", 1.10),
        ],
        _ => &[],
    };
    table
        .iter()
        .find(|(k, _)| *k == transport)
        .map(|(_, v)| *v)
        .unwrap_or(1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint extraction
// ─────────────────────────────────────────────────────────────────────────────

fn ip_port_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").unwrap())
}

fn trans_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(snowflake|webtunnel|obfs4|meek_lite|vanilla)\b").unwrap())
}

/// Mirrors `_extract_endpoint`. Returns `(host, port, transport)`.
pub fn extract_endpoint(raw: &str) -> (String, i64, String) {
    let lower = raw.to_lowercase();
    let mut transport = trans_re()
        .captures(&lower)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Unconditional override: literal "obfs4" anywhere in the lowercased
    // line wins, even over a different regex match — see module doc
    // comment.
    if lower.contains("obfs4") {
        transport = "obfs4".to_string();
    }

    if let Some(caps) = ip_port_re().captures(raw) {
        let host = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let port: i64 = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<i64>().ok())
            .unwrap_or(0);
        (host, port, transport)
    } else {
        (String::new(), 0, transport)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rounding (banker's rounding, matching Python's `round()`)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python's `round(x, 1)`. Same format-then-reparse idiom as
/// `adaptive_transport.rs`'s `python_round_4`/`python_round_int`.
fn python_round_1(x: f64) -> f64 {
    format!("{x:.1}").parse::<f64>().unwrap_or(x)
}

/// Mirror of Python's `round(x, 3)`.
fn python_round_3(x: f64) -> f64 {
    format!("{x:.3}").parse::<f64>().unwrap_or(x)
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeScore
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Excellent,
    Good,
    Capable,
    Poor,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Excellent => "excellent",
            Tier::Good => "good",
            Tier::Capable => "capable",
            Tier::Poor => "poor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    Use,
    Avoid,
    Test,
}

impl Recommendation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Recommendation::Use => "use",
            Recommendation::Avoid => "avoid",
            Recommendation::Test => "test",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BridgeScore {
    /// See module doc comment — missing-key-only defaulting, can be
    /// JSON `null`, purely descriptive (no behavioral effect in this
    /// module).
    pub bridge_id: Value,
    pub transport: String,
    pub port: i64,
    pub base_score: f64,
    pub nin_score: f64,
    pub dpi_score: f64,
    pub port_score: f64,
    pub level_mod: f64,
    pub final_score: f64,
    pub ai_refined: bool,
    pub ai_score: f64,
    pub tier: Tier,
    pub recommendation: Recommendation,
    pub raw: String,
}

impl BridgeScore {
    /// JSON representation used by parity tests and available to callers
    /// who want the exact field set `score_record`/`score_all` expose in
    /// Python.
    pub fn to_json(&self) -> Value {
        json!({
            "bridge_id": self.bridge_id,
            "transport": self.transport,
            "port": self.port,
            "base_score": self.base_score,
            "nin_score": self.nin_score,
            "dpi_score": self.dpi_score,
            "port_score": self.port_score,
            "level_mod": self.level_mod,
            "final_score": self.final_score,
            "ai_refined": self.ai_refined,
            "ai_score": self.ai_score,
            "tier": self.tier.as_str(),
            "recommendation": self.recommendation.as_str(),
            "raw": self.raw,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SmartIranScorerError {
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> SmartIranScorerError {
    SmartIranScorerError::Io {
        path: path.display().to_string(),
        source,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmartIranScorer
// ─────────────────────────────────────────────────────────────────────────────

pub struct SmartIranScorer {
    level: i64,
    /// Accepted for API-shape fidelity; always behaves as `false`
    /// internally — see module doc comment ("AI refinement layer is
    /// deferred").
    use_ai_requested: bool,
    ai_thresh_low: f64,
    ai_thresh_high: f64,
    iran_scorer: IranScorer,
}

impl Default for SmartIranScorer {
    fn default() -> Self {
        Self::new(3, false, 35.0, 70.0)
    }
}

impl SmartIranScorer {
    pub fn new(
        censorship_level: i64,
        use_ai: bool,
        ai_threshold_low: f64,
        ai_threshold_high: f64,
    ) -> Self {
        // Mirrors the module-import-time `DATA_DIR.mkdir(...)` side
        // effect — see module doc comment ("data/ directory creation").
        let _ = std::fs::create_dir_all("data");

        let level = censorship_level.clamp(1, 5);

        let mut iran_scorer = IranScorer::with_defaults();
        iran_scorer.load_transport_scores(Path::new("data/transport_weights.json"));

        Self {
            level,
            use_ai_requested: use_ai,
            ai_thresh_low: ai_threshold_low,
            ai_thresh_high: ai_threshold_high,
            iran_scorer,
        }
    }

    pub fn level(&self) -> i64 {
        self.level
    }

    /// Always `false` — see module doc comment ("AI refinement layer is
    /// deferred").
    pub fn use_ai_active(&self) -> bool {
        false
    }

    pub fn use_ai_requested(&self) -> bool {
        self.use_ai_requested
    }

    /// Accepted at construction for API-shape fidelity; consulted by
    /// Python's `_maybe_ai_refine` to decide whether a bridge is
    /// "uncertain" enough to send to the AI layer. Exposed here even
    /// though `_maybe_ai_refine` is currently always a no-op (see module
    /// doc comment), so the thresholds aren't silently discarded.
    pub fn ai_thresholds(&self) -> (f64, f64) {
        (self.ai_thresh_low, self.ai_thresh_high)
    }

    // ── Signal computation ──────────────────────────────────────────────

    pub fn base_score(&self, record: &Map<String, Value>) -> f64 {
        self.iran_scorer.score(&Value::Object(record.clone())) as f64 / 100.0
    }

    pub fn nin_signal(&self, record: &Map<String, Value>) -> f64 {
        let raw = raw_field(record);
        let (_, port, transport) = extract_endpoint(&raw);
        let asn = record
            .get("asn")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let t_nin = TRANSPORT_NIN
            .iter()
            .find(|(k, _)| *k == transport)
            .map(|(_, v)| *v)
            .unwrap_or(0.20);
        let asn_bonus = CDN_ASN_BONUS
            .iter()
            .find(|(k, _)| *k == asn)
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        let port_ok = if matches!(port, 443 | 80 | 2053 | 2083 | 2087) {
            1.0
        } else {
            0.4
        };

        (t_nin * 0.6 + asn_bonus * 0.25 + port_ok * 0.15).min(1.0)
    }

    pub fn dpi_signal(&self, record: &Map<String, Value>) -> f64 {
        let raw = raw_field(record);
        let (_, _, transport) = extract_endpoint(&raw);
        TRANSPORT_DPI
            .iter()
            .find(|(k, _)| *k == transport)
            .map(|(_, v)| *v)
            .unwrap_or(0.30)
    }

    pub fn port_signal(&self, port: i64) -> f64 {
        SAFE_PORTS
            .iter()
            .find(|(k, _)| *k == port)
            .map(|(_, v)| *v)
            .unwrap_or(0.20)
    }

    pub fn level_modifier(&self, transport: &str) -> f64 {
        level_transport_boost(self.level, transport)
    }

    // ── Composite score ──────────────────────────────────────────────────

    fn compute(&self, record: &Map<String, Value>) -> BridgeScore {
        let raw = raw_field(record);
        let (_, port, transport) = extract_endpoint(&raw);
        let bridge_id = bridge_id_field(record, &raw);

        let w = level_weights(self.level);
        let base_s = self.base_score(record);
        let nin_s = self.nin_signal(record);
        let dpi_s = self.dpi_signal(record);
        let port_s = self.port_signal(port);
        let level_mod = self.level_modifier(&transport);

        let raw_score = w.base * base_s
            + w.nin * nin_s
            + w.dpi * dpi_s
            + w.port * port_s
            + w.level * (level_mod - 1.0 + 0.5);

        let raw_score = raw_score * (0.85 + 0.15 * level_mod);
        let final_score = (raw_score * 100.0).clamp(0.0, 100.0);

        BridgeScore {
            bridge_id,
            transport,
            port,
            base_score: python_round_1(base_s * 100.0),
            nin_score: python_round_3(nin_s),
            dpi_score: python_round_3(dpi_s),
            port_score: python_round_3(port_s),
            level_mod: python_round_3(level_mod),
            final_score: python_round_1(final_score),
            ai_refined: false,
            ai_score: -1.0,
            tier: Tier::Poor,
            recommendation: Recommendation::Avoid,
            raw,
        }
    }

    fn assign_tier(bs: &mut BridgeScore) {
        let s = bs.final_score;
        if s >= 75.0 {
            bs.tier = Tier::Excellent;
            bs.recommendation = Recommendation::Use;
        } else if s >= 55.0 {
            bs.tier = Tier::Good;
            bs.recommendation = Recommendation::Use;
        } else if s >= 35.0 {
            bs.tier = Tier::Capable;
            bs.recommendation = Recommendation::Test;
        } else {
            bs.tier = Tier::Poor;
            bs.recommendation = Recommendation::Avoid;
        }
    }

    /// Always a no-op — see module doc comment ("AI refinement layer is
    /// deferred"). Kept as a method (rather than inlined away) so the
    /// call order relative to `assign_tier` stays visible at the call
    /// site, matching Python's `score_record` structure.
    fn maybe_ai_refine(&self, _bs: &mut BridgeScore) {}

    // ── Public API ───────────────────────────────────────────────────────

    pub fn score_record(&self, record: &Map<String, Value>) -> BridgeScore {
        let mut bs = self.compute(record);
        Self::assign_tier(&mut bs);
        self.maybe_ai_refine(&mut bs);
        bs
    }

    pub fn score_all(&self, records: &[Map<String, Value>]) -> Vec<BridgeScore> {
        let mut results: Vec<BridgeScore> = records.iter().map(|r| self.score_record(r)).collect();
        // Python: `results.sort(key=lambda x: x.final_score, reverse=True)`.
        // Stable descending sort — ties keep their original relative
        // order (a `reverse=True` stable sort is NOT equivalent to
        // sorting ascending and reversing the whole list).
        results.sort_by(|a, b| {
            b.final_score
                .partial_cmp(&a.final_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    pub fn top_bridges(
        &self,
        results: &[BridgeScore],
        n: usize,
        min_score: f64,
        transports: Option<&[String]>,
    ) -> Vec<BridgeScore> {
        let filtered: Vec<BridgeScore> = results
            .iter()
            .filter(|r| r.final_score >= min_score)
            .filter(|r| {
                transports
                    .map(|ts| ts.iter().any(|t| t == &r.transport))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        filtered.into_iter().take(n).collect()
    }

    /// Mirrors `write_report`. `path` defaults to
    /// `data/smart_iran_score_report.json` when `None`. Does **not**
    /// create the parent directory for a custom path — see module doc
    /// comment ("data/ directory creation").
    pub fn write_report(
        &self,
        results: &[BridgeScore],
        path: Option<&Path>,
    ) -> Result<(), SmartIranScorerError> {
        let default_path = PathBuf::from("data/smart_iran_score_report.json");
        let target = path.unwrap_or(&default_path);

        let tier_count = |t: Tier| results.iter().filter(|r| r.tier == t).count();
        // Dynamic yield: compute ceiling from config instead of hardcoded .take(50)
        let top_ceiling = crate::config::Config::from_env()
            .map(|cfg| crate::config::compute_dynamic_ceiling(results.len(), &cfg))
            .unwrap_or(50);
        let top_50: Vec<Value> = results
            .iter()
            .take(top_ceiling)
            .enumerate()
            .map(|(i, r)| {
                json!({
                    "rank": i + 1,
                    "score": r.final_score,
                    "tier": r.tier.as_str(),
                    "transport": r.transport,
                    "port": r.port,
                    "nin_score": r.nin_score,
                    "dpi_score": r.dpi_score,
                    "ai_refined": r.ai_refined,
                    "recommend": r.recommendation.as_str(),
                    "bridge": python_str_slice_chars(&r.raw, 80),
                })
            })
            .collect();

        let report = json!({
            "censorship_level": self.level,
            "ai_used": self.use_ai_active(),
            "total_bridges": results.len(),
            "tier_counts": {
                "excellent": tier_count(Tier::Excellent),
                "good": tier_count(Tier::Good),
                "capable": tier_count(Tier::Capable),
                "poor": tier_count(Tier::Poor),
            },
            "top_50": top_50,
        });

        let body = serde_json::to_string_pretty(&report).unwrap_or_default();
        std::fs::write(target, body).map_err(|e| io_err(target, e))
    }

    /// Mirrors `export_bridge_lines`.
    pub fn export_bridge_lines(
        &self,
        results: &[BridgeScore],
        path: &Path,
        n: usize,
        min_score: f64,
    ) -> Result<usize, SmartIranScorerError> {
        let top = self.top_bridges(results, n, min_score, None);
        let lines: Vec<&str> = top
            .iter()
            .map(|r| r.raw.as_str())
            .filter(|r| !r.trim().is_empty())
            .collect();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
            }
        }
        let body = format!("{}\n", lines.join("\n"));
        std::fs::write(path, body).map_err(|e| io_err(path, e))?;
        Ok(lines.len())
    }
}

/// Mirrors `record.get("raw", record.get("line", ""))`.
fn raw_field(record: &Map<String, Value>) -> String {
    record
        .get("raw")
        .and_then(Value::as_str)
        .or_else(|| record.get("line").and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

/// Mirrors `record.get("fingerprint", record.get("id", raw[:40]))` —
/// missing-key-only defaulting; can resolve to JSON `null` if
/// `"fingerprint"` (or, failing that, `"id"`) is present-but-null. See
/// module doc comment.
fn bridge_id_field(record: &Map<String, Value>, raw: &str) -> Value {
    if let Some(v) = record.get("fingerprint") {
        return v.clone();
    }
    if let Some(v) = record.get("id") {
        return v.clone();
    }
    Value::String(python_str_slice_chars(raw, 40))
}

/// Mirrors Python's `s[:n]` — slices by Unicode *codepoint* count, not
/// UTF-8 bytes (naive Rust byte-index slicing can panic or cut a
/// multi-byte character; bridge lines are ASCII in every writer this
/// codebase has, but this is correct regardless).
fn python_str_slice_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// One-shot pipeline: score all bridges, write the report, export the
/// best lines. Mirrors `run_smart_scoring`.
pub fn run_smart_scoring(
    records: &[Map<String, Value>],
    censorship_level: i64,
    use_ai: bool,
    output_prefix: &str,
) -> Result<(Vec<BridgeScore>, PathBuf), SmartIranScorerError> {
    let scorer = SmartIranScorer::new(censorship_level, use_ai, 35.0, 70.0);
    let results = scorer.score_all(records);

    let report_path = PathBuf::from(format!("data/{output_prefix}_iran_score_report.json"));
    scorer.write_report(&results, Some(&report_path))?;

    let export_path = PathBuf::from(format!("export/{output_prefix}_iran_best.txt"));
    scorer.export_bridge_lines(&results, &export_path, 50, 30.0)?;

    Ok((results, report_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn extract_endpoint_basic() {
        let (host, port, transport) = extract_endpoint("bridge snowflake 1.2.3.4:443 abcd");
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 443);
        assert_eq!(transport, "snowflake");
    }

    #[test]
    fn extract_endpoint_obfs4_override_wins_over_other_match() {
        // Contains both "webtunnel" and "obfs4" — obfs4 must win per the
        // unconditional override.
        let (_, _, transport) = extract_endpoint("webtunnel-ish but really obfs4 1.1.1.1:9001");
        assert_eq!(transport, "obfs4");
    }

    #[test]
    fn extract_endpoint_underscore_blocks_word_boundary() {
        let (_, _, transport) = extract_endpoint("bridge_obfs4_test 1.1.1.1:1");
        // No word boundary before/after "obfs4" here (underscores are
        // word characters) but the literal-substring override still
        // fires, so this still resolves to obfs4 rather than "unknown".
        assert_eq!(transport, "obfs4");
    }

    #[test]
    fn extract_endpoint_no_ip_returns_zero_port_empty_host() {
        let (host, port, transport) = extract_endpoint("obfs4 no address here");
        assert_eq!(host, "");
        assert_eq!(port, 0);
        assert_eq!(transport, "obfs4");
    }

    #[test]
    fn python_round_matches_bankers_rounding() {
        assert_eq!(python_round_1(72.05), 72.0);
        // 0.0625 and 0.1875 are both exactly representable in binary, so
        // these are genuine half-way ties at the 3rd decimal (unlike
        // 0.1255, whose actual binary value is a hair above the true
        // midpoint and rounds up in both languages for that reason, not
        // because of the half-to-even rule). Verified against live
        // Python: round(0.0625,3)==0.062 (ties to even, down),
        // round(0.1875,3)==0.188 (ties to even, up) — confirms this is
        // genuine round-half-to-even, not "always round down".
        assert_eq!(python_round_3(0.0625), 0.062);
        assert_eq!(python_round_3(0.1875), 0.188);
    }

    #[test]
    fn score_record_snowflake_high_level_scores_well() {
        let scorer = SmartIranScorer::new(4, false, 35.0, 70.0);
        let r = record(&[("raw", json!("bridge snowflake 1.2.3.4:443 abcd"))]);
        let bs = scorer.score_record(&r);
        assert_eq!(bs.transport, "snowflake");
        assert_eq!(bs.port, 443);
        assert!(
            bs.final_score > 50.0,
            "expected a solid score, got {}",
            bs.final_score
        );
    }

    #[test]
    fn score_record_vanilla_scores_poorly() {
        let scorer = SmartIranScorer::default();
        let r = record(&[("raw", json!("bridge vanilla 1.2.3.4:9001 abcd"))]);
        let bs = scorer.score_record(&r);
        assert_eq!(bs.tier, Tier::Poor);
        assert_eq!(bs.recommendation, Recommendation::Avoid);
    }

    #[test]
    fn bridge_id_prefers_fingerprint_then_id_then_raw_prefix() {
        let scorer = SmartIranScorer::default();
        let r1 = record(&[
            ("raw", json!("x")),
            ("fingerprint", json!("FP1")),
            ("id", json!("ID1")),
        ]);
        assert_eq!(scorer.score_record(&r1).bridge_id, json!("FP1"));

        let r2 = record(&[("raw", json!("x")), ("id", json!("ID1"))]);
        assert_eq!(scorer.score_record(&r2).bridge_id, json!("ID1"));

        let r3 = record(&[("raw", json!("hello"))]);
        assert_eq!(scorer.score_record(&r3).bridge_id, json!("hello"));
    }

    #[test]
    fn bridge_id_explicit_null_is_kept_not_defaulted() {
        let scorer = SmartIranScorer::default();
        let r = record(&[
            ("raw", json!("x")),
            ("fingerprint", Value::Null),
            ("id", json!("ID1")),
        ]);
        // fingerprint key present (even though null) -> used as-is, "id"
        // is NOT consulted, matching missing-key-only defaulting.
        assert_eq!(scorer.score_record(&r).bridge_id, Value::Null);
    }

    #[test]
    fn score_all_sorts_descending_stable_on_ties() {
        let scorer = SmartIranScorer::default();
        let records = vec![
            record(&[
                ("raw", json!("bridge obfs4 1.1.1.1:1 a")),
                ("id", json!("first")),
            ]),
            record(&[
                ("raw", json!("bridge obfs4 1.1.1.1:1 b")),
                ("id", json!("second")),
            ]),
        ];
        let results = scorer.score_all(&records);
        // Identical scoring inputs -> tied scores -> original order
        // preserved (stable sort, not reversed-tie-order).
        assert_eq!(results[0].bridge_id, json!("first"));
        assert_eq!(results[1].bridge_id, json!("second"));
    }

    #[test]
    fn top_bridges_filters_by_min_score_and_transport() {
        let scorer = SmartIranScorer::default();
        let records = vec![
            record(&[("raw", json!("bridge snowflake 1.1.1.1:443 a"))]),
            record(&[("raw", json!("bridge vanilla 1.1.1.1:1 b"))]),
        ];
        let results = scorer.score_all(&records);
        let top = scorer.top_bridges(&results, 10, 50.0, None);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].transport, "snowflake");

        let top_filtered = scorer.top_bridges(&results, 10, 0.0, Some(&["vanilla".to_string()]));
        assert_eq!(top_filtered.len(), 1);
        assert_eq!(top_filtered[0].transport, "vanilla");
    }

    #[test]
    fn write_report_and_export_bridge_lines_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("smart_iran_scorer_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let scorer = SmartIranScorer::default();
        let records = vec![record(&[(
            "raw",
            json!("bridge snowflake 1.1.1.1:443 abcd"),
        )])];
        let results = scorer.score_all(&records);

        let report_path = dir.join("report.json");
        scorer.write_report(&results, Some(&report_path)).unwrap();
        let report: Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        assert_eq!(report["total_bridges"], json!(1));

        let export_path = dir.join("export").join("best.txt");
        let n = scorer
            .export_bridge_lines(&results, &export_path, 50, 0.0)
            .unwrap();
        assert_eq!(n, 1);
        let content = std::fs::read_to_string(&export_path).unwrap();
        assert_eq!(content, "bridge snowflake 1.1.1.1:443 abcd\n");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
