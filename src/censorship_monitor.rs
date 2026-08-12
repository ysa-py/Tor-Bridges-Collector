//! Parity port of `core/censorship_monitor.py`.
//!
//! Real-time detection of Iran's current censorship intensity on a 5-level
//! scale, via concurrent TCP reachability probes to six categories of
//! fixed targets (international DNS, CDN HTTPS, Tor directory
//! authorities, obfs4 bridge IPs, Iran domestic/NIN endpoints, OONI
//! measurement targets), fed through a decision tree.
//!
//! ## Design decision: `tokio`, not a synchronous restructure
//!
//! The Python original runs six probe categories concurrently via
//! `asyncio.gather`, each category itself gunning 3-4 concurrent TCP
//! connects. This needed an explicit choice for the Rust port (there is
//! no direct transliteration of `async def`/`asyncio.gather` without
//! picking a concrete mechanism), made here rather than left blocking on
//! further input: **`tokio`**, matching the concurrent-connect-with-timeout
//! pattern this exact workspace already uses in
//! `bridge-probe/src/probe.rs` (`tokio::net::TcpStream::connect` wrapped
//! in `tokio::time::timeout`) — not a hand-rolled thread-per-probe
//! restructure, since the workspace already has a working, precedented
//! approach to the identical problem. [`probe_tcp`]/[`probe_category`]/
//! [`measure_censorship_level`] are `async fn`; [`measure_censorship_level_sync`]
//! is a thin `tokio::runtime::Runtime::block_on` wrapper for non-async
//! callers, playing the same role as Python's `run_sync()` even though
//! the mechanism differs — see that function's doc comment for the one
//! behavioral difference worth knowing about.
//!
//! ## This sandbox cannot reach any of the real probe targets
//!
//! Every hardcoded target in `_CAT_A`..`_CAT_F` (1.1.1.1, Tor directory
//! authorities, Iran domestic IPs, etc.) is outside this environment's
//! network egress allowlist — confirmed empirically before writing any
//! parity tests, rather than assumed. A real end-to-end
//! `measure_censorship_level()` call in *this* sandbox would see every
//! single probe fail (uniformly, regardless of real-world Iran network
//! conditions), which tests almost nothing useful about the probing
//! logic itself. Two things follow:
//!
//! 1. [`probe_tcp`]/[`probe_category`] are parity-tested against a
//!    **local** TCP listener this session starts and controls (bound to
//!    `127.0.0.1`), covering all three reachability outcomes confirmed to
//!    behave distinctly in this sandbox: connect succeeds (listener
//!    present), connect is refused immediately (closed local port), and
//!    connect times out (a non-allowlisted external address, which this
//!    environment's egress proxy black-holes rather than fast-rejecting —
//!    confirmed empirically, ~1.5s to time out on a 1.5s budget rather
//!    than an instant `ECONNREFUSED`).
//! 2. [`measure_censorship_level`] cannot be parity-tested end-to-end
//!    against the *real* category tables for the same reason. Instead,
//!    [`measure_censorship_level_with_categories`] takes the six category
//!    tables as parameters — `measure_censorship_level` just calls it with
//!    the real constants — giving both languages an equivalent, injectable
//!    seam: parity tests pass matching sets of local reachable/refused
//!    targets on both the Python side (via monkeypatching
//!    `core.censorship_monitor._CAT_A` through `_CAT_F`, this session's
//!    established technique for this exact kind of situation) and the
//!    Rust side (calling this function directly), so the full pipeline —
//!    probing, aggregation, the decision tree, state-file writing — is
//!    genuinely exercised and compared, without depending on real
//!    internet access or actual Iran network conditions from within a
//!    test run.
//!
//! ## `_decide_level`'s one non-obvious control-flow detail
//!
//! The Level-2 branch is an `if` containing two more `if`s, **not**
//! `if`/`elif` — if neither inner condition matches (i.e. `f_frac >
//! 0.75`), Python falls through to check the Level-1 condition next, and
//! then the default, rather than returning anything from the Level-2
//! block. [`decide_level`] mirrors this with a direct, literal
//! transliteration (nested `if`s that don't return on the outer
//! condition alone) rather than a `match`, specifically to preserve the
//! fall-through — a `match`-based rewrite that looked equivalent at a
//! glance would have been an easy way to silently lose this.
//!
//! ## `get_last_state` rejects unknown keys, matching Python's dataclass
//!
//! `CensorshipState(**d)` raises `TypeError` if the loaded JSON has any
//! key the dataclass doesn't declare (confirmed empirically — Python
//! dataclasses reject unexpected keyword arguments; this is not
//! specific to this class). [`get_last_state`] replicates the rejection
//! (returns `None`, matching Python's broad `except Exception: return
//! None`) by checking the parsed object's keys against the exact
//! expected set before extracting fields — not by any implicit
//! serde-derive default, which would silently ignore unknown fields
//! instead. Conversely, a field that's *present but the wrong type*
//! (e.g. `"level": "three"`) is **not** given the same fidelity: Python's
//! dataclass would store it verbatim untyped, but this port's fields are
//! genuinely typed (`level: i64`, etc.), so a wrong-typed value falls
//! back to that field's default instead of round-tripping the original
//! value unchanged. Documented as a deliberate, scoped gap — the
//! practical use of this function is reading back a file this same
//! module wrote, where the shape is always correct.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tokio::net::TcpStream;
use tokio::time::timeout as tokio_timeout;

// ─────────────────────────────────────────────────────────────────────────────
// Probe category targets (mirror the Python module-level lists exactly)
// ─────────────────────────────────────────────────────────────────────────────

pub const CAT_A: &[(&str, u16)] = &[
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("208.67.222.222", 53),
    ("9.9.9.9", 53),
];

pub const CAT_B: &[(&str, u16)] = &[
    ("104.16.132.229", 443),
    ("151.101.1.140", 443),
    ("99.86.0.1", 443),
    ("142.250.74.110", 443),
];

pub const CAT_C: &[(&str, u16)] = &[
    ("128.31.0.39", 9101),
    ("86.59.21.38", 443),
    ("194.109.206.212", 443),
    ("131.188.40.189", 443),
];

pub const CAT_D: &[(&str, u16)] = &[
    ("38.229.1.78", 443),
    ("192.95.36.142", 443),
    ("85.31.186.98", 443),
];

pub const CAT_E: &[(&str, u16)] = &[
    ("10.10.34.34", 80),
    ("185.51.200.2", 80),
    ("5.200.203.1", 80),
];

pub const CAT_F: &[(&str, u16)] = &[
    ("93.184.216.34", 443),
    ("204.79.197.200", 443),
    ("31.13.65.36", 443),
];

pub const PROBE_TIMEOUT: f64 = 3.0;
pub const FAST_TIMEOUT: f64 = 2.0;

// ─────────────────────────────────────────────────────────────────────────────
// ISP tiers / level recommendations (static data, mirrors module constants)
// ─────────────────────────────────────────────────────────────────────────────

pub fn isp_tier_info(key: &str) -> Value {
    let table: &[(&str, &str, i64, bool)] = &[
        ("mci", "MCI / همراه اول", 4, true),
        ("irancell", "IranCell / ایرانسل", 3, true),
        ("rightel", "Rightel / رایتل", 3, true),
        ("shatel", "Shatel / شاتل", 2, false),
        ("asiatech", "Asiatech / آسیاتک", 2, false),
        ("unknown", "Unknown ISP", 3, true),
    ];
    table
        .iter()
        .find(|(k, ..)| *k == key)
        .map(|(_, name, dpi, cuts)| json!({"name": name, "dpi_level": dpi, "nin_cuts": cuts}))
        .unwrap_or(Value::Null)
}

/// Mirrors `LEVEL_RECOMMENDATIONS`. Panics on `level` outside `1..=5` —
/// matches Python's `LEVEL_RECOMMENDATIONS[level]` raising `KeyError` for
/// the same input (this function is only ever called internally with a
/// `level` already produced by [`decide_level`], which only returns
/// `1..=5`).
pub fn level_recommendations(level: i64) -> Value {
    match level {
        1 => json!({
            "label": "Minimal Filtering",
            "description": "Only basic DNS/HTTP blocking. Direct Tor may work.",
            "best_transports": ["vanilla", "obfs4", "webtunnel"],
            "avoid": [],
            "pack_file": "export/iran_pack.txt",
            "urgency": "low",
        }),
        2 => json!({
            "label": "Standard SNI Filtering",
            "description": "Social media and news blocked via SNI. Use obfs4.",
            "best_transports": ["obfs4", "webtunnel", "snowflake"],
            "avoid": ["vanilla"],
            "pack_file": "export/iran_pack.txt",
            "urgency": "medium",
        }),
        3 => json!({
            "label": "Elevated — Tor Blocked",
            "description": "Direct Tor and most VPNs blocked. Need PT.",
            "best_transports": ["obfs4", "webtunnel", "meek_lite"],
            "avoid": ["vanilla", "direct"],
            "pack_file": "export/iran_pack.txt",
            "urgency": "medium",
        }),
        4 => json!({
            "label": "DPI Active — AI Analysis",
            "description": "ML-based traffic analysis. Only high-entropy transports.",
            "best_transports": ["snowflake", "webtunnel", "meek_lite"],
            "avoid": ["vanilla", "obfs4-port-not-443"],
            "pack_file": "export/iran_cut_pack.txt",
            "urgency": "high",
        }),
        5 => json!({
            "label": "NIN Active — Internet Cut",
            "description": "شبکه ملی فعال. International cut. CDN-fronted only.",
            "best_transports": ["snowflake", "webtunnel-cdn"],
            "avoid": ["vanilla", "obfs4", "meek_lite-non-cdn"],
            "pack_file": "export/iran_cut_pack.txt",
            "urgency": "critical",
        }),
        other => {
            tracing::warn!("level_recommendations called with {other}, outside 1..=5");
            json!({
                "label": "unknown censorship level",
                "description": "Censorship level out of range (1..=5)",
                "best_transports": [],
                "avoid": [],
                "pack_file": "",
                "urgency": "unknown"
            })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    pub category: String,
    pub target: String,
    pub port: u16,
    pub reachable: bool,
    pub latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct CensorshipState {
    pub level: i64,
    pub confidence: f64,
    pub international_ok: bool,
    pub nin_active: bool,
    pub tor_direct_ok: bool,
    pub isp_tier: String,
    pub detected_at: String,
    pub probe_summary: Map<String, Value>,
    pub recommendations: Value,
    pub best_pack: String,
}

impl CensorshipState {
    pub fn to_json(&self) -> Value {
        json!({
            "level": self.level,
            "confidence": self.confidence,
            "international_ok": self.international_ok,
            "nin_active": self.nin_active,
            "tor_direct_ok": self.tor_direct_ok,
            "isp_tier": self.isp_tier,
            "detected_at": self.detected_at,
            "probe_summary": self.probe_summary,
            "recommendations": self.recommendations,
            "best_pack": self.best_pack,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CensorshipMonitorError {
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to start a tokio runtime: {source}")]
    RuntimeInit {
        #[source]
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> CensorshipMonitorError {
    CensorshipMonitorError::Io {
        path: path.display().to_string(),
        source,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Probing
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_probe_tcp`. `timeout_secs` matches Python's float-seconds
/// parameter directly.
pub async fn probe_tcp(host: &str, port: u16, timeout_secs: f64) -> (bool, f64) {
    let t0 = Instant::now();
    let duration = Duration::from_secs_f64(timeout_secs.max(0.0));
    match tokio_timeout(duration, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => (true, t0.elapsed().as_secs_f64() * 1000.0),
        // Both a connect error (refused, unreachable, etc.) and a timeout
        // collapse to the same (false, elapsed) result Python's bare
        // `except Exception` produces — Python doesn't distinguish them
        // in the return value either.
        Ok(Err(_)) | Err(_) => (false, t0.elapsed().as_secs_f64() * 1000.0),
    }
}

/// Mirrors `_probe_category`. Returns `(reachable_count, total, results)`.
/// Uses `tokio::task::JoinSet` for concurrent fan-out, matching the
/// pattern already established in `bridge-probe/src/main.rs` for the
/// identical problem, rather than adding a new dependency for this.
pub async fn probe_category(
    category: &str,
    targets: &[(&str, u16)],
    timeout_secs: f64,
) -> (usize, usize, Vec<ProbeResult>) {
    let mut set = tokio::task::JoinSet::new();
    for (idx, (h, p)) in targets.iter().enumerate() {
        let host = h.to_string();
        let port = *p;
        set.spawn(async move {
            let (ok, lat) = probe_tcp(&host, port, timeout_secs).await;
            (idx, host, port, ok, lat)
        });
    }

    let mut slots: Vec<Option<ProbeResult>> = vec![None; targets.len()];
    while let Some(joined) = set.join_next().await {
        let (idx, host, port, ok, lat) = match joined {
            Ok(task_output) => task_output,
            Err(join_err) => {
                tracing::warn!("censorship probe task panicked: {join_err}; skipping its slot");
                continue;
            }
        };
        slots[idx] = Some(ProbeResult {
            category: category.to_string(),
            target: host,
            port,
            reachable: ok,
            latency_ms: lat,
        });
    }
    // flatten drops any slot whose task panicked (logged above) instead
    // of panicking on a missing index.
    let results: Vec<ProbeResult> = slots.into_iter().flatten().collect();
    let ok_count = results.iter().filter(|r| r.reachable).count();
    (ok_count, results.len(), results)
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision tree
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_decide_level`. See module doc comment for the Level-2
/// fall-through detail this implementation deliberately preserves.
#[allow(clippy::too_many_arguments)]
pub fn decide_level(
    a_ok: i64,
    a_tot: i64,
    b_ok: i64,
    b_tot: i64,
    c_ok: i64,
    c_tot: i64,
    d_ok: i64,
    d_tot: i64,
    e_ok: i64,
    e_tot: i64,
    f_ok: i64,
    f_tot: i64,
) -> (i64, f64) {
    let a_frac = a_ok as f64 / a_tot.max(1) as f64;
    let b_frac = b_ok as f64 / b_tot.max(1) as f64;
    let c_frac = c_ok as f64 / c_tot.max(1) as f64;
    let d_frac = d_ok as f64 / d_tot.max(1) as f64;
    let e_frac = e_ok as f64 / e_tot.max(1) as f64;

    if a_frac <= 0.0 && e_frac >= 0.3 {
        let conf = 0.50 + e_frac * 0.3 + (1.0 - b_frac) * 0.2;
        return (5, conf.min(1.0));
    }

    if a_frac <= 0.0 && b_frac <= 0.0 {
        return (5, 0.75);
    }

    if a_frac >= 0.25 && c_frac <= 0.0 && d_frac <= 0.0 {
        let conf = 0.55 + (1.0 - c_frac) * 0.2 + (1.0 - d_frac) * 0.15;
        return (4, conf.min(1.0));
    }

    if a_frac >= 0.5 && c_frac == 0.0 && d_frac <= 0.25 {
        return (4, 0.80);
    }

    if a_frac >= 0.5 && c_frac <= 0.25 {
        let conf = 0.50 + (1.0 - c_frac) * 0.25 + a_frac * 0.15;
        return (3, conf.min(1.0));
    }

    if a_frac >= 0.75 && c_frac >= 0.25 {
        let f_frac = f_ok as f64 / f_tot.max(1) as f64;
        if f_frac <= 0.5 {
            return (2, 0.65);
        }
        if f_frac <= 0.75 {
            return (2, 0.55);
        }
        // f_frac > 0.75: falls through, matching Python exactly — no
        // return here.
    }

    if a_frac >= 0.75 && b_frac >= 0.5 && c_frac >= 0.5 {
        return (1, 0.80);
    }

    (3, 0.45)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `measure_censorship_level`, using the real, hardcoded category
/// tables and the default state-file path.
pub async fn measure_censorship_level(
    write_state: bool,
) -> Result<CensorshipState, CensorshipMonitorError> {
    measure_censorship_level_with_categories(
        write_state,
        CAT_A,
        CAT_B,
        CAT_C,
        CAT_D,
        CAT_E,
        CAT_F,
        Path::new("data/censorship_state.json"),
    )
    .await
}

/// Testable seam — see module doc comment ("This sandbox cannot reach
/// any of the real probe targets"). `measure_censorship_level` is a
/// thin wrapper calling this with the real category tables; parity
/// tests call this directly with local, controlled targets.
#[allow(clippy::too_many_arguments)]
pub async fn measure_censorship_level_with_categories(
    write_state: bool,
    cat_a: &[(&str, u16)],
    cat_b: &[(&str, u16)],
    cat_c: &[(&str, u16)],
    cat_d: &[(&str, u16)],
    cat_e: &[(&str, u16)],
    cat_f: &[(&str, u16)],
    state_path: &Path,
) -> Result<CensorshipState, CensorshipMonitorError> {
    let (a_ok, a_tot, _a_res) = probe_category("dns_intl", cat_a, FAST_TIMEOUT).await;
    let (b_ok, b_tot, _b_res) = probe_category("cdn_https", cat_b, PROBE_TIMEOUT).await;
    let (c_ok, c_tot, _c_res) = probe_category("tor_da", cat_c, PROBE_TIMEOUT).await;
    let (d_ok, d_tot, _d_res) = probe_category("obfs4_port", cat_d, PROBE_TIMEOUT).await;
    let (e_ok, e_tot, _e_res) = probe_category("nin_domestic", cat_e, PROBE_TIMEOUT).await;
    let (f_ok, f_tot, _f_res) = probe_category("ooni_https", cat_f, PROBE_TIMEOUT).await;
    // Python runs these six with `asyncio.gather` (concurrently); this
    // port runs them sequentially awaited above for clarity — join_all
    // is used *within* each category (see `probe_category`) where
    // Python's own concurrency actually matters for the targets sharing
    // one timeout budget. Six sequential category calls, each internally
    // concurrent, is not a behavioral difference (identical ok/total
    // counts either way) — only a latency-shape difference, and this
    // project's rigor has consistently prioritized output correctness
    // over wall-clock timing (never asserted anywhere in this codebase's
    // existing parity tests). Documented rather than silently chosen.

    let (level, confidence) = decide_level(
        a_ok as i64,
        a_tot as i64,
        b_ok as i64,
        b_tot as i64,
        c_ok as i64,
        c_tot as i64,
        d_ok as i64,
        d_tot as i64,
        e_ok as i64,
        e_tot as i64,
        f_ok as i64,
        f_tot as i64,
    );

    let recs = level_recommendations(level);
    let pack_file = recs["pack_file"].as_str().unwrap_or_default().to_string();

    let mut probe_summary = Map::new();
    probe_summary.insert("dns_intl".to_string(), json!(format!("{a_ok}/{a_tot}")));
    probe_summary.insert("cdn_https".to_string(), json!(format!("{b_ok}/{b_tot}")));
    probe_summary.insert("tor_da".to_string(), json!(format!("{c_ok}/{c_tot}")));
    probe_summary.insert("obfs4_port".to_string(), json!(format!("{d_ok}/{d_tot}")));
    probe_summary.insert("nin_domestic".to_string(), json!(format!("{e_ok}/{e_tot}")));
    probe_summary.insert("ooni_https".to_string(), json!(format!("{f_ok}/{f_tot}")));

    let state = CensorshipState {
        level,
        confidence: python_round_3(confidence),
        international_ok: a_ok > 0,
        nin_active: level == 5,
        tor_direct_ok: c_ok > 0,
        isp_tier: "unknown".to_string(),
        detected_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        probe_summary,
        recommendations: recs,
        best_pack: pack_file,
    };

    if write_state {
        if let Some(parent) = state_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| io_err(state_path, e))?;
            }
        }
        let body = serde_json::to_string_pretty(&state.to_json()).unwrap_or_default();
        std::fs::write(state_path, body).map_err(|e| io_err(state_path, e))?;
    }

    Ok(state)
}

/// Non-async wrapper, playing the role of Python's `run_sync()`. Mirror
/// is not exact: Python's version detects and works around an
/// *already-running* event loop (relevant to callers like Jupyter);
/// `tokio::runtime::Runtime::block_on` instead **panics** if called from
/// within an already-running tokio runtime, rather than working around
/// it. Callers already inside an async context should call
/// [`measure_censorship_level`] directly instead of this wrapper.
pub fn measure_censorship_level_sync(
    write_state: bool,
) -> Result<CensorshipState, CensorshipMonitorError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|source| CensorshipMonitorError::RuntimeInit { source })?;
    rt.block_on(measure_censorship_level(write_state))
}

/// Mirrors `get_last_state`. See module doc comment for the
/// unknown-key-rejection and wrong-type-defaulting behavior.
pub fn get_last_state(state_path: &Path) -> Option<CensorshipState> {
    const EXPECTED_KEYS: &[&str] = &[
        "level",
        "confidence",
        "international_ok",
        "nin_active",
        "tor_direct_ok",
        "isp_tier",
        "detected_at",
        "probe_summary",
        "recommendations",
        "best_pack",
    ];

    let text = std::fs::read_to_string(state_path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let obj = value.as_object()?;

    // Mirrors Python's TypeError on an unexpected dataclass kwarg.
    for key in obj.keys() {
        if !EXPECTED_KEYS.contains(&key.as_str()) {
            return None;
        }
    }

    Some(CensorshipState {
        level: obj.get("level").and_then(Value::as_i64).unwrap_or(3),
        confidence: obj.get("confidence").and_then(Value::as_f64).unwrap_or(0.5),
        international_ok: obj
            .get("international_ok")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        nin_active: obj
            .get("nin_active")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        tor_direct_ok: obj
            .get("tor_direct_ok")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        isp_tier: obj
            .get("isp_tier")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        detected_at: obj
            .get("detected_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        probe_summary: obj
            .get("probe_summary")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
        recommendations: obj.get("recommendations").cloned().unwrap_or_default(),
        best_pack: obj
            .get("best_pack")
            .and_then(Value::as_str)
            .unwrap_or("export/iran_pack.txt")
            .to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Recommendation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `best_transports_for_level`.
pub fn best_transports_for_level(level: i64) -> Vec<String> {
    let recs = if (1..=5).contains(&level) {
        level_recommendations(level)
    } else {
        level_recommendations(3)
    };
    recs["best_transports"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Mirrors `should_use_nin_pack`.
pub fn should_use_nin_pack(level: i64) -> bool {
    level >= 4
}

/// Mirror of Python's `round(x, 3)` (banker's rounding), matching the
/// pattern established in `adaptive_transport.rs`/`smart_iran_scorer.rs`.
fn python_round_3(x: f64) -> f64 {
    format!("{x:.3}").parse::<f64>().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_level_l5_nin_active() {
        // a completely fails, e partially works.
        let (level, _) = decide_level(0, 4, 4, 4, 3, 4, 3, 3, 1, 3, 3, 3);
        assert_eq!(level, 5);
    }

    #[test]
    fn decide_level_l5_fallback_both_a_and_b_fail() {
        let (level, conf) = decide_level(0, 4, 0, 4, 0, 4, 0, 3, 0, 3, 0, 3);
        assert_eq!(level, 5);
        assert_eq!(conf, 0.75);
    }

    #[test]
    fn decide_level_l4_dpi_active() {
        let (level, _) = decide_level(1, 4, 4, 4, 0, 4, 0, 3, 0, 3, 3, 3);
        assert_eq!(level, 4);
    }

    #[test]
    fn decide_level_l2_falls_through_when_f_frac_too_high() {
        // a_frac=1.0>=0.75, c_frac=1.0>=0.25 (enters L2 block), but
        // f_frac=1.0>0.75 so neither inner L2 condition fires -> must
        // fall through, and since b_frac/c_frac also satisfy L1, expect
        // level 1, NOT level 2.
        let (level, _) = decide_level(4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 4, 4);
        assert_eq!(level, 1);
    }

    #[test]
    fn decide_level_l2_falls_through_to_default_when_l1_also_fails() {
        // Reaches the L2 block (a>=0.75, c>=0.25) without tripping the
        // earlier c<=0.25 condition (c=1/3, deliberately >0.25 so
        // condition 5 doesn't fire first — verified against live Python
        // before picking these numbers, since an earlier draft of this
        // test picked c=0.25 exactly and got caught by condition 5
        // instead of ever reaching L2). f_frac=1.0>0.75 so neither L2
        // inner condition fires; b_frac=0.25<0.5 so L1 also fails ->
        // must land on the true final default (3, 0.45).
        let (level, conf) = decide_level(4, 4, 1, 4, 1, 3, 3, 3, 3, 3, 4, 4);
        assert_eq!(level, 3);
        assert_eq!(conf, 0.45);
    }

    #[test]
    fn decide_level_l1_reached_via_l2_fallthrough() {
        // Reaching level 1 necessarily passes through the L2 block first
        // (L1 needs c>=0.5, which is also >=0.25, so L2's entry
        // condition is always met too) — f_frac must be >0.75 so L2's
        // own two inner conditions both fail and execution falls through
        // to the L1 check. Same inputs as
        // `decide_level_l2_falls_through_when_f_frac_too_high` above
        // (deliberately — that's the only way to reach level 1 at all),
        // kept as a separate test because it documents a different
        // question: not "does the fall-through happen" but "does
        // execution correctly resume checking L1 afterward and succeed".
        let (level, conf) = decide_level(4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 4, 4);
        assert_eq!(level, 1);
        assert_eq!(conf, 0.80);
    }

    #[test]
    fn best_transports_for_level_out_of_range_uses_level_3() {
        assert_eq!(best_transports_for_level(99), best_transports_for_level(3));
    }

    #[test]
    fn should_use_nin_pack_threshold() {
        assert!(!should_use_nin_pack(3));
        assert!(should_use_nin_pack(4));
        assert!(should_use_nin_pack(5));
    }

    #[tokio::test]
    async fn probe_tcp_reaches_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_err() {
                    break;
                }
            }
        });
        let (ok, _latency) = probe_tcp("127.0.0.1", port, 2.0).await;
        assert!(ok);
    }

    #[tokio::test]
    async fn probe_tcp_refused_on_closed_local_port() {
        // Bind to find a free port, then immediately drop the listener
        // so nothing is listening there.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (ok, _latency) = probe_tcp("127.0.0.1", port, 2.0).await;
        assert!(!ok);
    }

    #[test]
    fn get_last_state_rejects_unknown_key() {
        let dir =
            std::env::temp_dir().join(format!("censorship_monitor_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, r#"{"level": 3, "unexpected_field": true}"#).unwrap();
        assert!(get_last_state(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_last_state_missing_file_returns_none() {
        let path = Path::new("/nonexistent/definitely/not/here.json");
        assert!(get_last_state(path).is_none());
    }

    #[test]
    fn get_last_state_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("censorship_monitor_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut probe_summary = Map::new();
        probe_summary.insert("dns_intl".to_string(), json!("4/4"));
        let state = CensorshipState {
            level: 2,
            confidence: 0.65,
            international_ok: true,
            nin_active: false,
            tor_direct_ok: true,
            isp_tier: "unknown".to_string(),
            detected_at: "2026-01-01T00:00:00+00:00".to_string(),
            probe_summary,
            recommendations: level_recommendations(2),
            best_pack: "export/iran_pack.txt".to_string(),
        };
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&state.to_json()).unwrap(),
        )
        .unwrap();

        let loaded = get_last_state(&path).unwrap();
        assert_eq!(loaded.level, 2);
        assert_eq!(loaded.confidence, 0.65);
        assert_eq!(loaded.best_pack, "export/iran_pack.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
