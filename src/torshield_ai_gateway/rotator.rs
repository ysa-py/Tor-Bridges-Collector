// Parity port of `torshield_ai_gateway/rotator.py` — AccountRotator v8.0
// multi-slot rotation with circuit-breaker, latency EMA, health scoring, and
// deterministic weighted primary selection.
//
// Selection is deterministic: `run_seed` hashes `GITHUB_RUN_ID:GITHUB_RUN_ATTEMPT`
// with SHA-256 (reproduced exactly via the local `hashing` helper), and
// `get_primary` picks by cumulative health-score weight against
// `(seed % 10000) / 10000`. Wall-clock reads (`time.time()`) affect only the
// circuit-breaker / backoff timing and the `GITHUB_RUN_ID` default; those are
// documented and, in the parity suite, controlled via env / fresh slots.
// `logger.*` side effects are dropped (no observable output change).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::hashing;

pub const BACKOFF_WINDOW: f64 = 90.0;
pub const LATENCY_EMA_ALPHA: f64 = 0.25;
pub const MAX_CONSECUTIVE_ERR: i64 = 3;
pub const CIRCUIT_RESET_SEC: f64 = 180.0;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A single provider account slot with runtime health + circuit state.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountSlot {
    pub index: i64,
    pub account_id: String,
    pub api_key: String,
    pub gateway_url: String,
    pub extra: BTreeMap<String, Value>,

    pub failures: i64,
    pub consecutive_errors: i64,
    pub last_failure_ts: f64,
    pub total_requests: i64,
    pub total_successes: i64,
    pub avg_latency_ms: f64,

    pub circuit_open: bool,
    pub circuit_open_ts: f64,
}

impl AccountSlot {
    /// Construct a slot with the Python dataclass defaults.
    pub fn new(index: i64, account_id: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            index,
            account_id: account_id.into(),
            api_key: api_key.into(),
            gateway_url: String::new(),
            extra: BTreeMap::new(),
            failures: 0,
            consecutive_errors: 0,
            last_failure_ts: 0.0,
            total_requests: 0,
            total_successes: 0,
            avg_latency_ms: 200.0,
            circuit_open: false,
            circuit_open_ts: 0.0,
        }
    }

    /// `total_successes / total_requests`, or 1.0 when no requests yet.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        self.total_successes as f64 / self.total_requests as f64
    }

    /// Composite 0.0-1.0 score: `success_rate * (1 - min(latency/10000, 0.5))`.
    pub fn health_score(&self) -> f64 {
        let latency_penalty = (self.avg_latency_ms / 10_000.0).min(0.5);
        self.success_rate() * (1.0 - latency_penalty)
    }

    /// Exponential moving average update of `avg_latency_ms`.
    pub fn record_latency(&mut self, latency_ms: f64) {
        self.avg_latency_ms =
            LATENCY_EMA_ALPHA * latency_ms + (1.0 - LATENCY_EMA_ALPHA) * self.avg_latency_ms;
    }

    /// Whether the circuit is open, auto-resetting after `CIRCUIT_RESET_SEC`.
    pub fn is_circuit_open(&mut self) -> bool {
        if !self.circuit_open {
            return false;
        }
        if (now_secs() - self.circuit_open_ts) > CIRCUIT_RESET_SEC {
            self.circuit_open = false;
            self.consecutive_errors = 0;
            return false;
        }
        true
    }

    /// Open the circuit, stamping the current time.
    pub fn open_circuit(&mut self) {
        self.circuit_open = true;
        self.circuit_open_ts = now_secs();
    }
}

/// Error mirroring the `ValueError` raised for an empty slot set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoConfiguredSlots(pub String);

impl std::fmt::Display for NoConfiguredSlots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoConfiguredSlots {}

/// Rotates across multiple free-tier account slots for one provider.
#[derive(Debug, Clone)]
pub struct AccountRotator {
    pub provider_name: String,
    pub slots: Vec<AccountSlot>,
}

impl AccountRotator {
    /// Mirrors `AccountRotator(provider_name, slots)`: keeps only slots with a
    /// non-empty api_key and errors if none remain.
    pub fn new(
        provider_name: impl Into<String>,
        slots: Vec<AccountSlot>,
    ) -> Result<Self, NoConfiguredSlots> {
        let provider_name = provider_name.into();
        let slots: Vec<AccountSlot> = slots
            .into_iter()
            .filter(|s| !s.api_key.is_empty())
            .collect();
        if slots.is_empty() {
            return Err(NoConfiguredSlots(format!(
                "[AccountRotator:{provider_name}] No configured slots — check env vars for this provider"
            )));
        }
        Ok(Self {
            provider_name,
            slots,
        })
    }

    /// Deterministic run seed reduced modulo `modulus`. Mirrors
    /// `int(sha256("{run_id}:{attempt}").hexdigest(), 16) % modulus`.
    pub fn run_seed_mod(modulus: u64) -> u64 {
        let run_id =
            std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| (now_secs() as i64).to_string());
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".to_string());
        hashing::sha256_int_mod(format!("{run_id}:{attempt}").as_bytes(), modulus)
    }

    /// Indices (into `self.slots`) of currently available slots.
    fn available_indices(&mut self) -> Vec<usize> {
        let now = now_secs();
        let mut out = Vec::new();
        for i in 0..self.slots.len() {
            let ok = !self.slots[i].is_circuit_open()
                && (self.slots[i].failures == 0
                    || (now - self.slots[i].last_failure_ts) > BACKOFF_WINDOW);
            if ok {
                out.push(i);
            }
        }
        out
    }

    fn reset_failures(&mut self) {
        for s in &mut self.slots {
            s.failures = 0;
            s.last_failure_ts = 0.0;
        }
    }

    /// Select the primary slot by deterministic health-weighted choice.
    /// Returns the index into `self.slots` of the chosen slot.
    pub fn get_primary(&mut self) -> usize {
        let mut available = self.available_indices();
        if available.is_empty() {
            self.reset_failures();
            available = (0..self.slots.len()).collect();
        }

        let scores: Vec<f64> = available
            .iter()
            .map(|&i| self.slots[i].health_score())
            .collect();
        let total_score: f64 = scores.iter().sum();
        let weights: Vec<f64> = if total_score == 0.0 {
            let n = available.len() as f64;
            vec![1.0 / n; available.len()]
        } else {
            scores.iter().map(|s| s / total_score).collect()
        };

        let seed_mod = Self::run_seed_mod(10_000);
        let threshold = seed_mod as f64 / 10_000.0;
        let mut cumulative = 0.0;
        for (&slot_idx, &weight) in available.iter().zip(weights.iter()) {
            cumulative += weight;
            if threshold <= cumulative {
                return slot_idx;
            }
        }
        *available.last().expect("available is non-empty here")
    }

    /// Fallback chain (excluding `exclude_index`), sorted by health desc.
    /// Returns indices into `self.slots`.
    pub fn get_fallback_chain(&mut self, exclude_index: i64) -> Vec<usize> {
        let available = self.available_indices();
        let mut chain: Vec<usize> = available
            .into_iter()
            .filter(|&i| self.slots[i].index != exclude_index)
            .collect();
        // Stable sort by health_score descending (matches Python sorted reverse).
        chain.sort_by(|&a, &b| {
            self.slots[b]
                .health_score()
                .partial_cmp(&self.slots[a].health_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        chain
    }

    /// Record a success on the slot at `idx`.
    pub fn mark_success(&mut self, idx: usize, latency_ms: f64) {
        let s = &mut self.slots[idx];
        s.failures = 0;
        s.consecutive_errors = 0;
        s.last_failure_ts = 0.0;
        s.total_requests += 1;
        s.total_successes += 1;
        s.record_latency(latency_ms);
    }

    /// Record a failure on the slot at `idx`, opening the circuit if needed.
    pub fn mark_failure(&mut self, idx: usize) {
        let s = &mut self.slots[idx];
        s.failures += 1;
        s.consecutive_errors += 1;
        s.last_failure_ts = now_secs();
        s.total_requests += 1;
        if s.consecutive_errors >= MAX_CONSECUTIVE_ERR {
            s.open_circuit();
        }
    }

    /// Per-slot status report (rounded like Python `round`).
    pub fn status_report(&self) -> Vec<Value> {
        self.slots
            .iter()
            .map(|s| {
                serde_json::json!({
                    "index": s.index,
                    "success_rate": round_n(s.success_rate(), 3),
                    "avg_latency_ms": round_n(s.avg_latency_ms, 1),
                    "health_score": round_n(s.health_score(), 3),
                    "circuit_open": s.circuit_open,
                    "consecutive_errors": s.consecutive_errors,
                    "total_requests": s.total_requests,
                })
            })
            .collect()
    }
}

/// Python `round(x, ndigits)`-compatible half-to-even rounding for the
/// non-negative values used in `status_report` (MSRV-1.75 safe).
fn round_n(x: f64, ndigits: u32) -> f64 {
    let factor = 10_f64.powi(ndigits as i32);
    let scaled = x * factor;
    let floor = scaled.floor();
    let diff = scaled - floor;
    let round_up = diff > 0.5 || (diff == 0.5 && (floor as i64) % 2 != 0);
    let rounded = if round_up { floor + 1.0 } else { floor };
    rounded / factor
}

/// Build an AccountRotator from environment variables (mirrors
/// `build_rotator_from_env`). Missing vars are silently skipped.
pub fn build_rotator_from_env(
    provider_name: &str,
    n_accounts: i64,
) -> Result<AccountRotator, NoConfiguredSlots> {
    let prefix = provider_name.to_uppercase().replace(['.', '-'], "_");
    let mut slots = Vec::new();
    for i in 1..=n_accounts {
        let api_key = std::env::var(format!("{prefix}_API_KEY_{i}")).unwrap_or_default();
        let account_id = std::env::var(format!("{prefix}_ACCOUNT_ID_{i}")).unwrap_or_default();
        if !api_key.is_empty() {
            slots.push(AccountSlot::new(i, account_id, api_key));
        }
    }
    AccountRotator::new(provider_name, slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_and_success_rate() {
        let mut s = AccountSlot::new(1, "acc", "key");
        assert_eq!(s.success_rate(), 1.0);
        s.total_requests = 4;
        s.total_successes = 3;
        assert_eq!(s.success_rate(), 0.75);
        s.avg_latency_ms = 200.0;
        assert!((s.health_score() - 0.75 * (1.0 - 0.02)).abs() < 1e-12);
    }

    #[test]
    fn latency_ema() {
        let mut s = AccountSlot::new(1, "", "key");
        s.avg_latency_ms = 200.0;
        s.record_latency(1000.0);
        assert!((s.avg_latency_ms - (0.25 * 1000.0 + 0.75 * 200.0)).abs() < 1e-12);
    }

    #[test]
    fn empty_slots_errors() {
        let err = AccountRotator::new("cf", vec![AccountSlot::new(1, "", "")]);
        assert!(err.is_err());
    }

    #[test]
    fn mark_failure_opens_circuit() {
        let mut r = AccountRotator::new("cf", vec![AccountSlot::new(1, "", "key")]).unwrap();
        for _ in 0..MAX_CONSECUTIVE_ERR {
            r.mark_failure(0);
        }
        assert!(r.slots[0].circuit_open);
    }
}
