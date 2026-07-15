// Parity port of `torshield_ai_gateway/iran_traffic_evasion.py` — adaptive Iran
// DPI evasion headers across 5 threat levels, plus human-like retry timing.
//
// The static header sets added at each level (Accept*, Origin, Referer,
// Cache-Control, Pragma, Connection, Sec-Fetch-*, X-TLS-Fragment) and the
// deterministic retry base-delay are reproduced exactly. The randomized parts —
// User-Agent choice, `X-Request-ID`/noise hex (sha256/md5 of `time()`+`random()`),
// realistic IPs, and Gaussian retry jitter — cannot be byte-matched against
// CPython's RNG, so the preserved contract (asserted in the parity suite) is
// pool membership, hex length, IP prefix/shape, and delay bounds. Documented in
// `MIGRATION_NOTES.md`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Standard headers that could reveal API-client identity.
pub const NEUTRALIZE_HEADERS: [&str; 3] = ["x-amz-date", "x-api-version", "user-agent"];

/// Browser-like User-Agent strings for traffic camouflage.
pub const CAMOUFLAGE_USER_AGENTS: [&str; 4] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
];

/// Candidate keys for noise headers (Level 3+).
pub const NOISE_HEADER_KEYS: [&str; 5] = [
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Trace-ID",
    "X-Session-ID",
    "X-Client-Version",
];

/// Realistic IP prefixes for X-Forwarded-For / X-Real-IP camouflage.
pub const IP_PREFIXES: [&str; 7] = [
    "185.220", "51.15", "45.33", "198.98", "104.244", "23.129", "141.98",
];

fn rand_u64() -> u64 {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let c = CTR.fetch_add(1, Ordering::Relaxed);
    let mut x = nanos ^ c.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

fn rand_index(len: usize) -> usize {
    (rand_u64() as usize) % len.max(1)
}

fn random_hex(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        out.push_str(&format!("{:016x}", rand_u64()));
    }
    out.truncate(n);
    out
}

fn random_range_incl(lo: u64, hi: u64) -> u64 {
    lo + rand_u64() % (hi - lo + 1)
}

/// Modifies HTTP request patterns to evade Iran's DPI systems.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IranTrafficEvasion;

impl IranTrafficEvasion {
    pub fn new() -> Self {
        Self
    }

    /// Apply level-appropriate DPI-evasion headers. Mirrors `apply_evasion`.
    pub fn apply_evasion(
        &self,
        headers: &BTreeMap<String, String>,
        threat_level: &str,
        _provider: &str,
    ) -> BTreeMap<String, String> {
        if threat_level == "none" {
            return headers.clone();
        }

        let mut modified = headers.clone();

        // Level 1 — browser UA (only if none present, case-insensitive).
        let ua = CAMOUFLAGE_USER_AGENTS[rand_index(CAMOUFLAGE_USER_AGENTS.len())];
        if !modified.keys().any(|k| k.to_lowercase() == "user-agent") {
            modified.insert("User-Agent".to_string(), ua.to_string());
        }
        modified.insert("X-Request-ID".to_string(), random_hex(24));

        if matches!(threat_level, "medium" | "high" | "critical") {
            modified.insert(
                "Accept".to_string(),
                "application/json, text/plain, */*".to_string(),
            );
            modified.insert(
                "Accept-Language".to_string(),
                "en-US,en;q=0.9,fa;q=0.8,ar;q=0.7".to_string(),
            );
            modified.insert(
                "Accept-Encoding".to_string(),
                "gzip, deflate, br".to_string(),
            );
            modified.insert("Origin".to_string(), "https://chat.openai.com".to_string());
            modified.insert(
                "Referer".to_string(),
                "https://chat.openai.com/".to_string(),
            );
        }

        if matches!(threat_level, "high" | "critical") {
            modified.insert("Cache-Control".to_string(), "no-cache".to_string());
            modified.insert("Pragma".to_string(), "no-cache".to_string());
            modified.insert("Connection".to_string(), "keep-alive".to_string());
            modified.insert("Sec-Fetch-Dest".to_string(), "empty".to_string());
            modified.insert("Sec-Fetch-Mode".to_string(), "cors".to_string());
            modified.insert("Sec-Fetch-Site".to_string(), "cross-site".to_string());
            for (k, v) in Self::generate_noise_headers(5) {
                modified.insert(k, v);
            }
        }

        if threat_level == "critical" {
            modified.insert("X-Forwarded-For".to_string(), Self::generate_realistic_ip());
            modified.insert("X-Real-IP".to_string(), Self::generate_realistic_ip());
            modified.insert("X-TLS-Fragment".to_string(), "150".to_string());
        }

        modified
    }

    /// Generate `count` harmless, unpredictable headers (keys may collide).
    pub fn generate_noise_headers(count: usize) -> BTreeMap<String, String> {
        let mut noise = BTreeMap::new();
        for _ in 0..count {
            let key = NOISE_HEADER_KEYS[rand_index(NOISE_HEADER_KEYS.len())];
            noise.insert(key.to_string(), random_hex(16));
        }
        noise
    }

    /// Generate a realistic-looking IP from a camouflage prefix.
    pub fn generate_realistic_ip() -> String {
        let prefix = IP_PREFIXES[rand_index(IP_PREFIXES.len())];
        format!(
            "{prefix}.{}.{}",
            random_range_incl(1, 254),
            random_range_incl(1, 254)
        )
    }

    /// Deterministic base retry delay (seconds) before Gaussian jitter.
    /// `(base_ms / 1000) * 2^(attempt-1) * threat_multiplier`.
    pub fn retry_base_delay(attempt: i64, threat_level: &str, base_ms: f64) -> f64 {
        let multiplier = match threat_level {
            "none" => 1.0,
            "low" => 1.8,
            "medium" => 3.0,
            "high" => 5.0,
            "critical" => 10.0,
            _ => 1.0,
        };
        (base_ms / 1000.0) * 2_f64.powi((attempt - 1) as i32) * multiplier
    }

    /// Human-like retry delay with threat-adaptive Gaussian jitter, clamped to
    /// [0.1, 45.0]. Mirrors `get_safe_retry_delay`.
    pub fn get_safe_retry_delay(attempt: i64, threat_level: &str, base_ms: f64) -> f64 {
        let base_delay = Self::retry_base_delay(attempt, threat_level, base_ms);
        // Gaussian jitter (sigma = 25%) via Box-Muller; RNG differs from CPython.
        let u1 = (rand_u64() as f64 / u64::MAX as f64).max(1e-12);
        let u2 = rand_u64() as f64 / u64::MAX as f64;
        let gauss = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let mut jitter = gauss * (base_delay * 0.25);
        if (rand_u64() as f64 / u64::MAX as f64) < 0.05 {
            jitter += 1.0 + (rand_u64() as f64 / u64::MAX as f64) * 2.0;
        }
        (base_delay + jitter).clamp(0.1, 45.0)
    }
}

/// Return an `IranTrafficEvasion`. Mirrors the Python singleton accessor.
pub fn get_iran_evasion() -> IranTrafficEvasion {
    IranTrafficEvasion::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_level_passthrough() {
        let e = IranTrafficEvasion::new();
        let mut base = BTreeMap::new();
        base.insert("X-A".to_string(), "1".to_string());
        assert_eq!(e.apply_evasion(&base, "none", "cf"), base);
    }

    #[test]
    fn medium_adds_static_headers() {
        let e = IranTrafficEvasion::new();
        let h = e.apply_evasion(&BTreeMap::new(), "medium", "cf");
        assert_eq!(h["Accept"], "application/json, text/plain, */*");
        assert_eq!(h["Origin"], "https://chat.openai.com");
        assert_eq!(h["X-Request-ID"].len(), 24);
        assert!(CAMOUFLAGE_USER_AGENTS.contains(&h["User-Agent"].as_str()));
    }

    #[test]
    fn critical_adds_ip_and_fragment() {
        let e = IranTrafficEvasion::new();
        let h = e.apply_evasion(&BTreeMap::new(), "critical", "cf");
        assert_eq!(h["X-TLS-Fragment"], "150");
        assert_eq!(h["Sec-Fetch-Mode"], "cors");
        let xff = &h["X-Forwarded-For"];
        assert!(IP_PREFIXES.iter().any(|p| xff.starts_with(p)));
    }

    #[test]
    fn existing_user_agent_not_overwritten() {
        let e = IranTrafficEvasion::new();
        let mut base = BTreeMap::new();
        base.insert("user-agent".to_string(), "custom".to_string());
        let h = e.apply_evasion(&base, "low", "cf");
        assert_eq!(h["user-agent"], "custom");
        assert!(!h.contains_key("User-Agent"));
    }

    #[test]
    fn retry_base_delay_is_deterministic() {
        assert_eq!(IranTrafficEvasion::retry_base_delay(1, "none", 500.0), 0.5);
        assert_eq!(
            IranTrafficEvasion::retry_base_delay(2, "medium", 500.0),
            3.0
        );
        let d = IranTrafficEvasion::get_safe_retry_delay(3, "critical", 500.0);
        assert!((0.1..=45.0).contains(&d));
    }
}
