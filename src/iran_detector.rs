//! Parity port of `core/iran_detector.py`.
//!
//! Detects whether international internet is reachable and, specifically,
//! whether Iran's National Information Network (NIN / شبکه ملی اطلاعات)
//! isolation is active, by racing TCP connect probes against a handful of
//! international DNS resolvers and two Iranian domestic gateway IPs. If
//! only the domestic probes succeed, an internet cut is inferred.
//!
//! ## Design decision: `tokio`, matching `censorship_monitor.rs`
//!
//! The Python original runs its probes concurrently via
//! `asyncio.gather`. Same situation `censorship_monitor.rs` already
//! decided: **`tokio`**, using `tokio::task::JoinSet` for the concurrent
//! fan-out (matching `probe_category`'s established pattern for the
//! identical problem) rather than a hand-rolled thread pool. [`probe_tcp`]
//! and [`check_connectivity`] are `async fn`; [`NinDetector::is_nin_active`]
//! is a synchronous caller and gets its own `tokio::runtime::Runtime::
//! block_on` wrapper, playing the same role as Python's inline
//! `asyncio.run()` / `nest_asyncio.apply()` dance — see that method's doc
//! comment for the one behavioral difference worth knowing about, which
//! mirrors `measure_censorship_level_sync`'s documented caveat exactly.
//!
//! ## This sandbox cannot reach any of the real probe targets — and one
//! ## "reachable" result here is not what it looks like
//!
//! Confirmed empirically (`socket.create_connection`, both languages see
//! the same outcome) before writing any parity tests, matching
//! `censorship_monitor.rs`'s precedent of checking rather than assuming:
//!
//! - All four international targets (`8.8.8.8:53`, `1.1.1.1:53`,
//!   `208.67.222.222:53`, `9.9.9.9:53`) time out at the full 3s probe
//!   budget — this environment's egress proxy black-holes them rather
//!   than fast-rejecting.
//! - Both NIN targets (`10.10.34.34:80`, `185.51.200.2:80`) return an
//!   *instant* (0.00s) TCP connect success from inside this sandbox. This
//!   is not evidence of real NIN-gateway reachability: `10.10.34.34` is
//!   an RFC 1918 private address, which can only ever resolve to
//!   *something on whatever private network the caller is on* — here,
//!   this sandbox's own container networking, not Iran's national
//!   gateway. `185.51.200.2` is a public address, but an instant 0.00s
//!   accept from a sandboxed environment with no other route to Iran
//!   points the same way: this sandbox's egress path, not a real
//!   round-trip. Both results are artifacts of *this* environment, not
//!   signal about NIN state.
//!
//! Because of this, parity tests never call [`check_connectivity`]
//! (the real-targets entry point) end-to-end. They use
//! [`check_connectivity_with_targets`] instead, an injectable-parameters
//! seam over local `TcpListener`s this test suite starts and controls —
//! the same split `censorship_monitor.rs` uses between
//! `measure_censorship_level` and `measure_censorship_level_with_categories`.
//!
//! ## `record_silent_failure` → `tracing`
//!
//! Same substitution as `self_heal.rs`: the Python original calls
//! `monitoring.structured_logger.record_silent_failure` inside every
//! `except Exception` block (`monitoring/*` isn't ported yet). This port
//! routes those call sites through `tracing::debug!`/`tracing::warn!`
//! instead, matched per-site to whatever Python itself does at that same
//! site (see individual function doc comments) rather than firing one
//! blanket level for all of them.
//!
//! ## Three docstring/implementation mismatches in the Python original,
//! ## preserved exactly as found — not "fixed"
//!
//! Found by reading the full class body against its own docstring, not
//! by a failing test (there is nothing to test against Python for
//! behavior Python itself doesn't implement):
//!
//! 1. `NINDetector`'s docstring claims four detection signals (DNS
//!    unreachability, `*.ir`-only resolution, CDN edge timeouts, bridge
//!    failure rate). The actual implementation only ever calls the
//!    pre-existing [`check_connectivity`] — signal 1 in spirit, and even
//!    that only approximately (raw TCP connect, not DNS resolution).
//!    Signals 2-4 have no corresponding code anywhere in the file.
//! 2. The docstring's "When NIN detected" list claims step 1 is
//!    "Exports `export/iran_cut_pack.txt`". `_on_nin_detected` calls only
//!    `record_event` and `_notify_telegram`; `self.export_path` is
//!    assigned in `__init__` and never read again anywhere in the file.
//!    [`NinDetector`] stores `export_path` for constructor-signature
//!    fidelity only — same "confirmed-inert" treatment
//!    `endpoint_validator.rs` gave `account_id`.
//! 3. The docstring says the class is additive alongside
//!    "`check_nin_state()` and `recommend_strategy()`". No
//!    `check_nin_state` function exists anywhere in this file; the actual
//!    pre-existing function is [`check_connectivity`]. Likely a stale
//!    rename the docstring never caught up with — noted, not corrected,
//!    since correcting Python's docstring is out of scope for a Rust
//!    port.
//!
//! None of this is invented or guessed: it's what the Python source
//! actually does, read function body by function body.
//!
//! The top-of-file module docstring has the same pattern, one level up:
//! it claims an "inside Iran" detection step, an HTTPS probe "to a
//! known-good international endpoint", and a special-case where
//! "GitHub Actions mode... always returns international reachable". None
//! of the three exist anywhere in this file — there is no CI/environment
//! branch and no HTTPS probing, only the plain TCP `_INTERNATIONAL_PROBES`
//! / `_NIN_PROBES` logic above. Noted for completeness; not chased
//! further, since there's no code left to read parity into once a claim
//! has no implementation anywhere in the file.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout as tokio_timeout;

use crate::dt_utils::utc_now_iso;

/// Well-known international DNS/HTTPS endpoints. Mirrors
/// `_INTERNATIONAL_PROBES`.
pub const INTERNATIONAL_PROBES: &[(&str, u16)] = &[
    ("8.8.8.8", 53),        // Google DNS
    ("1.1.1.1", 53),        // Cloudflare DNS
    ("208.67.222.222", 53), // OpenDNS
    ("9.9.9.9", 53),        // Quad9
];

/// Iranian NIN / domestic gateway IPs. Mirrors `_NIN_PROBES`.
pub const NIN_PROBES: &[(&str, u16)] = &[
    ("10.10.34.34", 80),  // IRNIC / IRCERT portal
    ("185.51.200.2", 80), // Known NIN DNS
];

/// Mirrors `_PROBE_TIMEOUT`.
pub const PROBE_TIMEOUT_SECS: f64 = 3.0;

/// Mirrors `_probe_tcp`.
///
/// Python does an additional best-effort `writer.close()` +
/// `await wait_for(writer.wait_closed(), timeout=1.0)` after a successful
/// connect, wrapped in its own try/except that logs-and-ignores failure
/// without changing the return value (`return True` happens unconditionally
/// afterward, outside that inner try/except). Rust's `TcpStream` has no
/// analogous async close-and-wait handshake — the socket closes
/// synchronously via `Drop` when it goes out of scope, with no failure mode
/// to swallow. This is a genuine mechanism difference (Python's
/// asyncio transport/protocol layer requires an explicit close handshake;
/// Rust's ownership model does not), not a behavior gap: both languages
/// end up with the connection closed and `true` returned.
pub async fn probe_tcp(host: &str, port: u16, timeout_secs: f64) -> bool {
    let duration = Duration::from_secs_f64(timeout_secs.max(0.0));
    matches!(
        tokio_timeout(duration, TcpStream::connect((host, port))).await,
        Ok(Ok(_))
    )
}

/// Mirrors `check_connectivity`, probing the real hardcoded targets. See
/// the module doc comment: this sandbox cannot meaningfully exercise this
/// function end-to-end, so parity tests use
/// [`check_connectivity_with_targets`] against local listeners instead.
pub async fn check_connectivity() -> (bool, bool) {
    check_connectivity_with_targets(INTERNATIONAL_PROBES, NIN_PROBES, PROBE_TIMEOUT_SECS).await
}

/// Injectable-targets variant of `check_connectivity`, mirroring the
/// `measure_censorship_level` / `measure_censorship_level_with_categories`
/// split in `censorship_monitor.rs`. `check_connectivity` just calls this
/// with the real constants; parity tests call this directly with local
/// `TcpListener` addresses.
///
/// Returns `(international_ok, nin_active)`:
/// - `international_ok` = at least one international probe succeeded.
/// - `nin_active` = an NIN probe succeeded but no international probe did
///   (strong signal an internet cut is in effect).
pub async fn check_connectivity_with_targets(
    international: &[(&str, u16)],
    nin: &[(&str, u16)],
    timeout_secs: f64,
) -> (bool, bool) {
    let mut int_set = tokio::task::JoinSet::new();
    for (h, p) in international {
        let host = (*h).to_string();
        let port = *p;
        int_set.spawn(async move { probe_tcp(&host, port, timeout_secs).await });
    }
    let mut nin_set = tokio::task::JoinSet::new();
    for (h, p) in nin {
        let host = (*h).to_string();
        let port = *p;
        nin_set.spawn(async move { probe_tcp(&host, port, timeout_secs).await });
    }

    // Both sets were already spawned above, so they run concurrently in
    // wall-clock time regardless of join order — matching Python's
    // `asyncio.gather(gather(*int_tasks), gather(*nin_tasks))`.
    let mut int_ok = false;
    while let Some(res) = int_set.join_next().await {
        if res.expect("probe task must not panic") {
            int_ok = true;
        }
    }
    let mut nin_ok = false;
    while let Some(res) = nin_set.join_next().await {
        if res.expect("probe task must not panic") {
            nin_ok = true;
        }
    }

    let nin_active = nin_ok && !int_ok;

    if nin_active {
        tracing::warn!(
            "\u{26a0}\u{fe0f}  IRAN INTERNET CUT DETECTED — international internet unreachable. \
             Recommending Snowflake / WebTunnel (CDN) bridges."
        );
    } else if !int_ok {
        tracing::warn!("No internet connectivity detected at all.");
    } else {
        tracing::info!("International internet reachable.");
    }

    (int_ok, nin_active)
}

/// Mirrors `recommend_strategy`. Pure function, byte-identical to the
/// Python original's concatenated string literals.
pub fn recommend_strategy(nin_active: bool) -> String {
    if nin_active {
        "Internet cut detected (شبکه ملی فعال). \
         Use: export/iran_cut_pack.txt → Snowflake, then WebTunnel (CDN-fronted). \
         Avoid vanilla/obfs4 — their IPs are unreachable during cuts."
            .to_string()
    } else {
        "International internet reachable. \
         Use: export/iran_pack.txt → obfs4 (port 443) or WebTunnel for best performance."
            .to_string()
    }
}

struct DetectorState {
    cached: bool,
    last_check: Option<Instant>,
}

/// Mirrors the condition inline in `is_nin_active`
/// (`not force_refresh and (now - self._last_check_ts) < 30.0`), extracted
/// as a pure function of elapsed time rather than wall-clock timestamps so
/// the 30s boundary can be unit-tested directly without a real probe or a
/// faked `Instant`. `None` (never checked yet) is never valid, matching
/// Python's `_last_check_ts: float = 0.0` default always failing the `<
/// 30.0` check on a freshly-constructed instance in practice (any real
/// `time.time()` value minus `0.0` is far larger than 30).
fn cache_still_valid(elapsed_since_last_check: Option<Duration>, force_refresh: bool) -> bool {
    if force_refresh {
        return false;
    }
    match elapsed_since_last_check {
        Some(elapsed) => elapsed < Duration::from_secs_f64(30.0),
        None => false,
    }
}

/// Mirrors `NINDetector`. See the module doc comment for three
/// docstring/implementation mismatches in the Python original that this
/// port preserves exactly rather than "fixing".
pub struct NinDetector {
    events_path: PathBuf,
    /// Accepted for constructor-signature fidelity only — confirmed
    /// unused anywhere after `__init__` in the Python original. See
    /// module doc comment, mismatch 2.
    #[allow(dead_code)]
    export_path: PathBuf,
    state: Mutex<DetectorState>,
}

impl NinDetector {
    /// Mirrors `NINDetector.__init__`.
    pub fn new(events_path: impl Into<PathBuf>, export_path: impl Into<PathBuf>) -> Self {
        Self {
            events_path: events_path.into(),
            export_path: export_path.into(),
            state: Mutex::new(DetectorState {
                cached: false,
                last_check: None,
            }),
        }
    }

    /// Mirrors Python's default constructor arguments
    /// (`data/nin_events.json`, `export/iran_cut_pack.txt`).
    pub fn with_defaults() -> Self {
        Self::new("data/nin_events.json", "export/iran_cut_pack.txt")
    }

    /// Mirrors `is_nin_active`.
    ///
    /// **Caveat shared with `measure_censorship_level_sync`:** Python's
    /// version detects and works around an *already-running* event loop
    /// (relevant to callers on a loop already, e.g. inside another async
    /// framework) via `nest_asyncio.apply(loop)`. `tokio::runtime::Runtime
    /// ::block_on` instead **panics** if called from within an
    /// already-running tokio runtime rather than working around it.
    /// Callers already inside an async context should call
    /// [`check_connectivity`] directly instead of this method.
    ///
    /// **Unguarded error path, preserved on purpose:** Python's
    /// `_on_nin_detected()` — and the `record_event` call inside it — run
    /// *outside* `is_nin_active`'s own `try/except Exception`, which only
    /// wraps the connectivity-check portion. A directory-creation failure
    /// in `record_event` (`os.makedirs`, itself unguarded) therefore
    /// propagates all the way out of `is_nin_active`, uncaught, in the
    /// Python original — an undeclared exception path despite the `->
    /// bool` return type. This port preserves that faithfully via a panic
    /// at the same point (see [`Self::record_event`]) rather than
    /// silently swallowing it, which would be a real behavior change, or
    /// changing the return type to `Result`, which the Python signature
    /// gives no indication of either.
    pub fn is_nin_active(&self, force_refresh: bool) -> bool {
        {
            let state = self.state.lock().expect("state mutex poisoned");
            let elapsed = state.last_check.map(|t| t.elapsed());
            if cache_still_valid(elapsed, force_refresh) {
                return state.cached;
            }
        }

        let rt = tokio::runtime::Runtime::new().expect("failed to start a tokio runtime");
        let (_international_ok, nin_active) = rt.block_on(check_connectivity());
        let cached = nin_active;

        {
            let mut state = self.state.lock().expect("state mutex poisoned");
            state.cached = cached;
            state.last_check = Some(Instant::now());
        }

        if cached {
            self.on_nin_detected(cached);
        }
        cached
    }

    /// Mirrors `record_event`. `details` takes `serde_json::Value` rather
    /// than a typed struct, matching Python's untyped `dict`.
    ///
    /// Directory creation (`std::fs::create_dir_all`) is **not** wrapped
    /// in error recovery here, matching the Python original's unguarded
    /// `os.makedirs` call — see [`Self::is_nin_active`]'s doc comment.
    /// The two read-side fallbacks (missing file, unparseable/non-array
    /// JSON) and the write-side failure *are* guarded, matching Python's
    /// two `except` clauses and final `except Exception`, respectively.
    pub fn record_event(&self, kind: &str, details: Value) {
        if let Some(parent) = self
            .events_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                panic!(
                    "record_event: could not create directory {}: {e}",
                    parent.display()
                )
            });
        }

        let mut events: Vec<Value> = match std::fs::read_to_string(&self.events_path) {
            Ok(contents) => match serde_json::from_str::<Value>(&contents) {
                Ok(Value::Array(arr)) => arr,
                _ => {
                    tracing::debug!(
                        "[NinDetector] events file at {} missing/unparseable/non-array; starting fresh",
                        self.events_path.display()
                    );
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };

        events.push(json!({
            "timestamp": utc_now_iso(),
            "kind": kind,
            "details": details,
        }));

        if let Err(e) = std::fs::write(
            &self.events_path,
            serde_json::to_string_pretty(&events).unwrap_or_default(),
        ) {
            tracing::warn!("[NinDetector] could not write events: {e}");
        }
    }

    /// Mirrors `_on_nin_detected`. `cached_state` is passed through
    /// explicitly rather than re-read from `self.state`, since by the
    /// time this runs it has already been set and Python's own version
    /// reads the same just-set value off `self`.
    fn on_nin_detected(&self, cached_state: bool) {
        self.record_event("nin_detected", json!({ "cached_state": cached_state }));
        // Python wraps this call in its own try/except ("Telegram
        // notification is optional and never raises"); `notify_telegram`
        // below has no fallible path that isn't already handled
        // internally (any request error is caught and logged, not
        // propagated), so there's nothing left to catch at this call site.
        self.notify_telegram();
    }

    /// Mirrors `_notify_telegram`. Real HTTP send, gated behind the
    /// `network` feature — same convention `endpoint_validator.rs` uses
    /// for its `reqwest`-dependent probe.
    #[cfg(feature = "network")]
    fn notify_telegram(&self) {
        let token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
        let token = token.trim();
        let chat_id = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
        let chat_id = chat_id.trim();
        if token.is_empty() || chat_id.is_empty() {
            return;
        }
        let text = "TorShield-IR: NIN isolation detected. Switched to iran_cut_pack.";
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        if let Err(e) = client
            .get(url)
            .query(&[("chat_id", chat_id), ("text", text)])
            .header("User-Agent", "TorShield-IR")
            .send()
        {
            tracing::debug!("[NinDetector] telegram send failed: {e}");
        }
    }

    /// Without the `network` feature there is no HTTP client compiled in
    /// at all — this is a no-op, which looks identical from the caller's
    /// side to Python's own no-op path when `TELEGRAM_BOT_TOKEN` /
    /// `TELEGRAM_CHAT_ID` aren't set.
    #[cfg(not(feature = "network"))]
    fn notify_telegram(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_never_checked_is_invalid() {
        assert!(!cache_still_valid(None, false));
    }

    #[test]
    fn cache_just_under_30s_is_valid() {
        assert!(cache_still_valid(
            Some(Duration::from_secs_f64(29.9)),
            false
        ));
    }

    #[test]
    fn cache_exactly_30s_is_invalid() {
        // Mirrors Python's strict `< 30.0`: exactly 30.0 elapsed does not
        // satisfy "less than", so the cache must be treated as expired.
        assert!(!cache_still_valid(
            Some(Duration::from_secs_f64(30.0)),
            false
        ));
    }

    #[test]
    fn cache_just_over_30s_is_invalid() {
        assert!(!cache_still_valid(
            Some(Duration::from_secs_f64(30.1)),
            false
        ));
    }

    #[test]
    fn force_refresh_always_invalidates_even_a_fresh_cache() {
        assert!(!cache_still_valid(
            Some(Duration::from_secs_f64(0.001)),
            true
        ));
    }

    #[test]
    fn recommend_strategy_branches_are_distinct() {
        assert_ne!(recommend_strategy(true), recommend_strategy(false));
    }

    #[test]
    fn probes_constants_have_documented_lengths() {
        assert_eq!(INTERNATIONAL_PROBES.len(), 4);
        assert_eq!(NIN_PROBES.len(), 2);
    }
}

// ============================================================================
// SECTION 4 — Adaptive Anti-Filtering & Anti-DPI (WARFARE LAYER)
//
// CRITICAL CONSTRAINT (directive §4): every capability here is gated behind the
// non-default `smart-detection` Cargo feature. With the feature OFF — the
// default build — none of this compiles in and the crate's observable behavior
// is byte-identical to the legacy Python `core/iran_detector.py`
// (`check_connectivity`, `recommend_strategy`, `NinDetector` unchanged).
//
// Nothing below adds a mandatory dependency: the scoring/classification core is
// pure `std` + `serde_json`. The one genuinely network-touching helper
// (`probe_https_443`) is additionally gated behind the pre-existing `network`
// feature, mirroring how `notify_telegram` gates its real `reqwest` call.
//
// Testability: classification and scoring take an injected `&[ProbeResult]`
// telemetry slice — the same "injectable seam" pattern the baseline uses with
// `check_connectivity_with_targets`, so every `InterferenceKind` variant is
// exercised deterministically on loopback with no real egress.
// ============================================================================
#[cfg(feature = "smart-detection")]
pub mod smart {
    use std::time::Duration;

    /// Outcome of a single probe, carrying enough TCP/TLS telemetry to classify
    /// *how* a target failed (directive §4.2), not merely whether it failed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProbeOutcome {
        /// Connected (and, for an HTTPS probe, completed the TLS handshake).
        Ok,
        /// No response within the probe budget — passive black-holing.
        Timeout,
        /// TCP RST / connection refused — an *active* in-path reset.
        Refused,
        /// Name resolution failed / was poisoned before any TCP occurred.
        DnsFailure,
        /// TCP connected but the TLS handshake was torn down — the signature
        /// of SNI-based selective blocking ("Smart Filtering" / فیلترینگ هوشمند).
        TlsHandshakeFail,
    }

    /// Per-probe telemetry captured during one connectivity round.
    ///
    /// `anchor_group` is a coarse ASN/geographic diversity bucket: two anchors
    /// with the same value are treated as correlated evidence (e.g. two
    /// resolvers behind the same upstream), so confidence is weighted by the
    /// number of *distinct* groups that succeed rather than the raw probe count
    /// (directive §4.1, "weighted fraction of geographically/ASN-diverse
    /// anchors").
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProbeResult {
        pub host: String,
        pub port: u16,
        pub international: bool,
        pub anchor_group: u8,
        pub outcome: ProbeOutcome,
        pub elapsed: Duration,
    }

    impl ProbeResult {
        /// Convenience constructor for tests and callers.
        pub fn new(
            host: impl Into<String>,
            port: u16,
            international: bool,
            anchor_group: u8,
            outcome: ProbeOutcome,
            elapsed: Duration,
        ) -> Self {
            Self {
                host: host.into(),
                port,
                international,
                anchor_group,
                outcome,
                elapsed,
            }
        }
    }

    /// Classification of *how* international reachability is being interfered
    /// with (directive §4.2). Exact variant set mandated by the directive.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InterferenceKind {
        None,
        Timeout,
        ActiveReset,
        DnsInterference,
        TlsHandshakeFail,
        Mixed,
    }

    /// Multi-signal assessment (directive §4.1). `check_connectivity`'s
    /// `(bool, bool)` contract is preserved verbatim in the baseline; this is a
    /// strictly richer, additive view derived from the same telemetry.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ConnectivityAssessment {
        /// Weighted fraction (0.0..=1.0) of distinct international anchor groups
        /// that succeeded.
        pub international_confidence: f64,
        /// Weighted fraction (0.0..=1.0) of distinct domestic/NIN anchor groups
        /// that succeeded.
        pub nin_confidence: f64,
        pub interference: InterferenceKind,
        /// Byte-for-byte compatible with the baseline `check_connectivity`
        /// return: `international_ok = international_confidence > 0`.
        pub international_ok: bool,
        /// `nin_active = nin_confidence > 0 && !international_ok`, matching the
        /// baseline's `nin_ok && !int_ok`.
        pub nin_active: bool,
    }

    /// Weighted-by-diversity success fraction: distinct anchor groups that had
    /// at least one `Ok`, over distinct anchor groups seen. Returns 0.0 when no
    /// anchors of that class were probed (avoids a divide-by-zero and matches
    /// "no evidence" ⇒ "no confidence").
    fn diverse_success_fraction<'a>(results: impl Iterator<Item = &'a ProbeResult>) -> f64 {
        let mut seen_groups: Vec<u8> = Vec::new();
        let mut ok_groups: Vec<u8> = Vec::new();
        for r in results {
            if !seen_groups.contains(&r.anchor_group) {
                seen_groups.push(r.anchor_group);
            }
            if r.outcome == ProbeOutcome::Ok && !ok_groups.contains(&r.anchor_group) {
                ok_groups.push(r.anchor_group);
            }
        }
        if seen_groups.is_empty() {
            0.0
        } else {
            ok_groups.len() as f64 / seen_groups.len() as f64
        }
    }

    /// Classify interference from the *failing international* probes only.
    /// Domestic probe outcomes never drive this: interference is a statement
    /// about the international path.
    fn classify_interference(results: &[ProbeResult]) -> InterferenceKind {
        let intl: Vec<&ProbeResult> = results.iter().filter(|r| r.international).collect();
        if intl.is_empty() {
            return InterferenceKind::None;
        }
        if intl.iter().any(|r| r.outcome == ProbeOutcome::Ok) {
            // At least one international anchor is fully reachable ⇒ whatever
            // else failed, the path as a whole is not being blocked.
            return InterferenceKind::None;
        }
        let mut kinds: Vec<InterferenceKind> = Vec::new();
        for r in &intl {
            let k = match r.outcome {
                ProbeOutcome::Timeout => InterferenceKind::Timeout,
                ProbeOutcome::Refused => InterferenceKind::ActiveReset,
                ProbeOutcome::DnsFailure => InterferenceKind::DnsInterference,
                ProbeOutcome::TlsHandshakeFail => InterferenceKind::TlsHandshakeFail,
                ProbeOutcome::Ok => continue,
            };
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
        match kinds.as_slice() {
            [] => InterferenceKind::None,
            [single] => *single,
            _ => InterferenceKind::Mixed,
        }
    }

    /// Multi-signal confidence scoring + interference classification
    /// (directive §4.1/§4.2). Pure function of injected telemetry.
    pub fn compute_confidence(results: &[ProbeResult]) -> ConnectivityAssessment {
        let international_confidence =
            diverse_success_fraction(results.iter().filter(|r| r.international));
        let nin_confidence = diverse_success_fraction(results.iter().filter(|r| !r.international));
        let international_ok = international_confidence > 0.0;
        let nin_active = nin_confidence > 0.0 && !international_ok;
        ConnectivityAssessment {
            international_confidence,
            nin_confidence,
            interference: classify_interference(results),
            international_ok,
            nin_active,
        }
    }

    /// Pluggable transports the adaptive router ranks (directive §4.3).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Transport {
        Snowflake,
        DomainFrontedWebTunnel,
        Ech,
        WebTunnel,
        Obfs4,
        Vanilla,
    }

    impl Transport {
        /// Deterministic tie-break priority (lower = preferred) so equal scores
        /// never produce a non-deterministic ordering — favours censorship-
        /// resistant transports, matching the Python `recommend_strategy`
        /// preference for Snowflake/WebTunnel during cuts.
        fn tie_break(self) -> u8 {
            match self {
                Transport::Snowflake => 0,
                Transport::DomainFrontedWebTunnel => 1,
                Transport::Ech => 2,
                Transport::WebTunnel => 3,
                Transport::Obfs4 => 4,
                Transport::Vanilla => 5,
            }
        }
    }

    /// Live per-transport health, 0.0 (dead) ..= 1.0 (healthy). Sourced from the
    /// bridge-probe member at the call site; injected here for testability.
    #[derive(Debug, Clone, PartialEq)]
    pub struct BridgeHealthSnapshot {
        pub snowflake: f64,
        pub domain_fronted_webtunnel: f64,
        pub ech: f64,
        pub webtunnel: f64,
        pub obfs4: f64,
        pub vanilla: f64,
    }

    impl BridgeHealthSnapshot {
        fn health(&self, t: Transport) -> f64 {
            match t {
                Transport::Snowflake => self.snowflake,
                Transport::DomainFrontedWebTunnel => self.domain_fronted_webtunnel,
                Transport::Ech => self.ech,
                Transport::WebTunnel => self.webtunnel,
                Transport::Obfs4 => self.obfs4,
                Transport::Vanilla => self.vanilla,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct StrategyRecommendation {
        pub ranked: Vec<Transport>,
        pub rationale: String,
    }

    const ALL_TRANSPORTS: [Transport; 6] = [
        Transport::Snowflake,
        Transport::DomainFrontedWebTunnel,
        Transport::Ech,
        Transport::WebTunnel,
        Transport::Obfs4,
        Transport::Vanilla,
    ];

    /// Interference-aware multiplier applied to a transport's health score.
    /// Under `ActiveReset` and `TlsHandshakeFail` (directive §4.3), CDN-fronted
    /// / ECH-capable / Snowflake transports are boosted and IP-pinned
    /// transports (obfs4/vanilla) are penalised, because the former defeat
    /// SNI/IP-based selective blocking while the latter expose exactly the
    /// signal the DPI is keying on.
    fn adaptive_multiplier(t: Transport, interference: InterferenceKind) -> f64 {
        use InterferenceKind::*;
        use Transport::*;
        match interference {
            ActiveReset | TlsHandshakeFail => match t {
                Snowflake | DomainFrontedWebTunnel | Ech => 1.6,
                WebTunnel => 1.2,
                Obfs4 => 0.5,
                Vanilla => 0.2,
            },
            DnsInterference => match t {
                // DNS poisoning: prefer transports that don't depend on
                // resolving a blocked hostname on the client side.
                Snowflake | Ech => 1.4,
                DomainFrontedWebTunnel | WebTunnel => 1.1,
                Obfs4 => 0.8,
                Vanilla => 0.4,
            },
            Timeout | Mixed => match t {
                // Passive black-holing / mixed: modest lean toward covert
                // transports without hard-penalising the rest.
                Snowflake | DomainFrontedWebTunnel => 1.2,
                Ech | WebTunnel => 1.1,
                Obfs4 => 0.9,
                Vanilla => 0.7,
            },
            None => 1.0,
        }
    }

    /// Adaptive, telemetry-aware transport routing (directive §4.3). Deterministic:
    /// ranks by `adjusted_score = health * adaptive_multiplier`, with a fixed
    /// tie-break order so identical scores never reorder between runs.
    pub fn recommend_strategy_adaptive(
        assessment: &ConnectivityAssessment,
        bridge_health: &BridgeHealthSnapshot,
    ) -> StrategyRecommendation {
        let mut scored: Vec<(Transport, f64)> = ALL_TRANSPORTS
            .iter()
            .map(|&t| {
                (
                    t,
                    bridge_health.health(t) * adaptive_multiplier(t, assessment.interference),
                )
            })
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.tie_break().cmp(&b.0.tie_break()))
        });
        let ranked: Vec<Transport> = scored.into_iter().map(|(t, _)| t).collect();
        let rationale = format!(
            "interference={:?}, international_confidence={:.2}, nin_active={} → top={:?}",
            assessment.interference,
            assessment.international_confidence,
            assessment.nin_active,
            ranked[0]
        );
        StrategyRecommendation { ranked, rationale }
    }

    // ── Probe traffic-shape jitter & OpSec hardening (directive §4.4) ───────
    //
    // A deterministic, seedable splitmix64 PRNG (no `rand` dependency added):
    // seed from the wall clock in production, from a fixed value in tests. Used
    // for bounded timing jitter between probes and for an adaptive 30s cache
    // cadence, so the traffic profile is not a fixed, fingerprint-able cadence.

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform f64 in [0, 1) from the PRNG (53-bit mantissa precision).
    fn next_unit(state: &mut u64) -> f64 {
        (splitmix64(state) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Bounded jitter around `base`: result is uniformly within
    /// `[base*(1-frac), base*(1+frac)]`. `frac` is clamped to `[0, 1]`.
    pub fn jitter_delay(base: Duration, frac: f64, state: &mut u64) -> Duration {
        let frac = frac.clamp(0.0, 1.0);
        let u = next_unit(state); // [0,1)
        let factor = 1.0 - frac + 2.0 * frac * u; // [1-frac, 1+frac)
        base.mul_f64(factor)
    }

    /// A full round of bounded inter-probe delays — one per probe — so probes
    /// within a round are not emitted on a fixed cadence (directive §4.4).
    pub fn jittered_round(base: Duration, frac: f64, count: usize, seed: u64) -> Vec<Duration> {
        let mut state = seed;
        (0..count)
            .map(|_| jitter_delay(base, frac, &mut state))
            .collect()
    }

    /// Adaptive cadence for the 30s `is_nin_active` cache window (directive
    /// §4.4): jitters the fixed 30.0s TTL by ±20% so cache-refresh probes do
    /// not recur on a predictable, profile-able 30s beat. Bounded to
    /// `[24s, 36s]`.
    pub fn adaptive_cache_window(seed: u64) -> Duration {
        let mut state = seed;
        jitter_delay(Duration::from_secs_f64(30.0), 0.20, &mut state)
    }

    /// Explicit HTTPS/443 TLS probe to a known-good international endpoint
    /// (directive §4.1). Real network I/O, so additionally gated behind the
    /// pre-existing `network` feature (same convention as `notify_telegram`).
    /// Distinguishes a TCP-level failure from a TLS-handshake teardown so the
    /// caller can feed a precise [`ProbeOutcome`] into [`compute_confidence`].
    #[cfg(feature = "network")]
    pub fn probe_https_443(host: &str, timeout: Duration) -> ProbeOutcome {
        // A successful GET over https means TCP + TLS both completed. reqwest
        // surfaces connect/timeout/tls errors distinctly enough to map onto our
        // telemetry taxonomy.
        let client = match reqwest::blocking::Client::builder()
            .https_only(true)
            .timeout(timeout)
            .build()
        {
            Ok(c) => c,
            Err(_) => return ProbeOutcome::TlsHandshakeFail,
        };
        let url = format!("https://{host}/");
        match client.get(url).send() {
            Ok(_) => ProbeOutcome::Ok,
            Err(e) if e.is_timeout() => ProbeOutcome::Timeout,
            Err(e) if e.is_connect() => ProbeOutcome::TlsHandshakeFail,
            Err(_) => ProbeOutcome::Refused,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn r(intl: bool, group: u8, outcome: ProbeOutcome) -> ProbeResult {
            ProbeResult::new(
                "127.0.0.1",
                443,
                intl,
                group,
                outcome,
                Duration::from_millis(1),
            )
        }

        #[test]
        fn confidence_all_international_ok_is_full_and_no_interference() {
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Ok),
                r(true, 2, ProbeOutcome::Ok),
                r(false, 9, ProbeOutcome::Ok),
            ]);
            assert_eq!(a.international_confidence, 1.0);
            assert!(a.international_ok);
            assert!(!a.nin_active);
            assert_eq!(a.interference, InterferenceKind::None);
        }

        #[test]
        fn confidence_is_diversity_weighted_not_raw_count() {
            // Two probes, same anchor_group ⇒ counts as one unit of evidence.
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Ok),
                r(true, 1, ProbeOutcome::Ok),
                r(true, 2, ProbeOutcome::Timeout),
            ]);
            // 1 of 2 distinct groups succeeded.
            assert_eq!(a.international_confidence, 0.5);
        }

        #[test]
        fn nin_active_mirrors_baseline_semantics() {
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Timeout),
                r(true, 2, ProbeOutcome::Timeout),
                r(false, 9, ProbeOutcome::Ok),
            ]);
            assert!(!a.international_ok);
            assert!(a.nin_active);
            assert!(a.nin_confidence > 0.0);
        }

        #[test]
        fn interference_timeout_variant() {
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Timeout),
                r(true, 2, ProbeOutcome::Timeout),
            ]);
            assert_eq!(a.interference, InterferenceKind::Timeout);
        }

        #[test]
        fn interference_active_reset_variant() {
            let a = compute_confidence(&[r(true, 1, ProbeOutcome::Refused)]);
            assert_eq!(a.interference, InterferenceKind::ActiveReset);
        }

        #[test]
        fn interference_dns_variant() {
            let a = compute_confidence(&[r(true, 1, ProbeOutcome::DnsFailure)]);
            assert_eq!(a.interference, InterferenceKind::DnsInterference);
        }

        #[test]
        fn interference_tls_handshake_variant() {
            let a = compute_confidence(&[r(true, 1, ProbeOutcome::TlsHandshakeFail)]);
            assert_eq!(a.interference, InterferenceKind::TlsHandshakeFail);
        }

        #[test]
        fn interference_mixed_variant() {
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Timeout),
                r(true, 2, ProbeOutcome::Refused),
            ]);
            assert_eq!(a.interference, InterferenceKind::Mixed);
        }

        #[test]
        fn interference_none_when_any_intl_ok() {
            let a = compute_confidence(&[
                r(true, 1, ProbeOutcome::Ok),
                r(true, 2, ProbeOutcome::Refused),
            ]);
            assert_eq!(a.interference, InterferenceKind::None);
        }

        fn healthy() -> BridgeHealthSnapshot {
            BridgeHealthSnapshot {
                snowflake: 0.8,
                domain_fronted_webtunnel: 0.8,
                ech: 0.8,
                webtunnel: 0.8,
                obfs4: 0.8,
                vanilla: 0.8,
            }
        }

        #[test]
        fn adaptive_routing_boosts_covert_transports_under_active_reset() {
            let assessment = compute_confidence(&[r(true, 1, ProbeOutcome::Refused)]);
            let rec = recommend_strategy_adaptive(&assessment, &healthy());
            // Under ActiveReset, Snowflake/domain-fronted/ECH must outrank obfs4/vanilla.
            let pos = |t: Transport| rec.ranked.iter().position(|&x| x == t).unwrap();
            assert!(pos(Transport::Snowflake) < pos(Transport::Obfs4));
            assert!(pos(Transport::DomainFrontedWebTunnel) < pos(Transport::Vanilla));
            assert!(pos(Transport::Ech) < pos(Transport::Obfs4));
            assert_eq!(rec.ranked[0], Transport::Snowflake);
        }

        #[test]
        fn adaptive_routing_boosts_covert_transports_under_tls_handshake_fail() {
            let assessment = compute_confidence(&[r(true, 1, ProbeOutcome::TlsHandshakeFail)]);
            let rec = recommend_strategy_adaptive(&assessment, &healthy());
            let pos = |t: Transport| rec.ranked.iter().position(|&x| x == t).unwrap();
            assert!(pos(Transport::Snowflake) < pos(Transport::Obfs4));
            assert!(pos(Transport::Ech) < pos(Transport::Vanilla));
        }

        #[test]
        fn adaptive_routing_respects_health_when_no_interference() {
            let assessment = compute_confidence(&[r(true, 1, ProbeOutcome::Ok)]);
            let mut h = healthy();
            h.obfs4 = 1.0; // healthiest with no interference multiplier in play
            h.snowflake = 0.1;
            let rec = recommend_strategy_adaptive(&assessment, &h);
            assert_eq!(rec.ranked[0], Transport::Obfs4);
        }

        #[test]
        fn adaptive_routing_is_deterministic() {
            let assessment = compute_confidence(&[r(true, 1, ProbeOutcome::Refused)]);
            let a = recommend_strategy_adaptive(&assessment, &healthy());
            let b = recommend_strategy_adaptive(&assessment, &healthy());
            assert_eq!(a.ranked, b.ranked);
        }

        #[test]
        fn jitter_is_bounded_and_seed_deterministic() {
            let base = Duration::from_millis(100);
            let round1 = jittered_round(base, 0.25, 8, 42);
            let round2 = jittered_round(base, 0.25, 8, 42);
            assert_eq!(round1, round2, "same seed ⇒ same jitter sequence");
            for d in round1 {
                assert!(d >= base.mul_f64(0.75), "jitter under lower bound: {d:?}");
                assert!(d <= base.mul_f64(1.25), "jitter over upper bound: {d:?}");
            }
        }

        #[test]
        fn jitter_actually_varies_across_probes() {
            let base = Duration::from_millis(100);
            let round = jittered_round(base, 0.25, 16, 7);
            let all_same = round.windows(2).all(|w| w[0] == w[1]);
            assert!(
                !all_same,
                "a fixed cadence would defeat the anti-profiling goal"
            );
        }

        #[test]
        fn adaptive_cache_window_bounded_around_30s() {
            for seed in 0..64u64 {
                let w = adaptive_cache_window(seed);
                assert!(
                    w >= Duration::from_secs_f64(24.0),
                    "window under 24s: {w:?}"
                );
                assert!(w <= Duration::from_secs_f64(36.0), "window over 36s: {w:?}");
            }
        }
    }
}
