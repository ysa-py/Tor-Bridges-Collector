// Parity port of `torshield_ai_gateway/iran_gateway_dpi_shaper.py` — AI
// Gateway-specific DPI evasion for Iran's SIAM/NGFW.
//
// Deterministic decisions (ISP->slot-group selection, static header set,
// whether to front, non-rotating domain) are reproduced exactly. The Python
// `random.choice` picks (slot within a group, User-Agent, rotated domain at
// high/critical) are non-deterministic by design; the exact value cannot match
// CPython's RNG across languages, so the preserved contract is that the returned
// value is always a member of the same candidate pool Python would choose from.
// This is documented in `MIGRATION_NOTES.md`.
//
// The Python module-level singleton + `threading.Lock` accessor
// (`get_gateway_dpi_shaper`) has no observable state, so the Rust accessor simply
// returns a fresh zero-sized `GatewayDPIShaper`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// CF fronting domains — Iran cannot selectively block these (index 0 primary).
pub const CF_FRONTING_DOMAINS: [&str; 2] = ["gateway.ai.cloudflare.com", "api.cloudflare.com"];

/// ISP -> CF-account slot groups, in Python insertion order (first match wins).
pub const ISP_SLOT_MAPPING: [(&str, &[i64]); 5] = [
    ("irancell", &[1, 2, 3]),
    ("mci", &[4, 5, 6]),
    ("rightel", &[7, 8]),
    ("shatel", &[9, 10]),
    ("other", &[11]),
];

/// Browser-like User-Agent pool used at medium+ threat levels.
pub const BROWSER_USER_AGENTS: [&str; 6] = [
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) Chrome/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/17.4",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Firefox/126.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/125.0",
];

/// Non-deterministic index into a non-empty pool — the analogue of CPython's
/// `random.choice`. Seeded from the wall clock plus a monotonically increasing
/// counter so successive calls vary within a process.
fn rand_index(len: usize) -> usize {
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
    (x as usize) % len.max(1)
}

/// AI Gateway-specific DPI evasion for Iran's SIAM/NGFW (zero-sized).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatewayDPIShaper;

impl GatewayDPIShaper {
    /// Create a shaper. Mirrors `GatewayDPIShaper()`.
    pub fn new() -> Self {
        Self
    }

    /// Return the slot group Python would select for `detected_isp` (first
    /// substring match in `ISP_SLOT_MAPPING` order, falling back to `"other"`).
    /// This exposes the deterministic half of `get_optimal_slot_for_isp` so
    /// parity tests can assert group selection without depending on RNG.
    pub fn slot_group_for_isp(&self, detected_isp: Option<&str>) -> &'static [i64] {
        // Python: `(detected_isp or "other").lower()` — both None and "" are
        // falsy and map to "other".
        let raw = match detected_isp {
            Some(s) if !s.is_empty() => s,
            _ => "other",
        };
        let isp_key = raw.to_lowercase();
        for (pattern, slots) in ISP_SLOT_MAPPING.iter() {
            if isp_key.contains(pattern) {
                return slots;
            }
        }
        // Final fallback mirrors `random.choice(ISP_SLOT_MAPPING["other"])`.
        ISP_SLOT_MAPPING[4].1
    }

    /// Route to the CF account slot best suited for the detected ISP.
    /// Mirrors `get_optimal_slot_for_isp` including the `random.choice` pick.
    pub fn get_optimal_slot_for_isp(&self, detected_isp: Option<&str>) -> i64 {
        let group = self.slot_group_for_isp(detected_isp);
        group[rand_index(group.len())]
    }

    /// Augment request headers to blend with normal HTTPS traffic. At medium+
    /// threat levels, adds browser-like headers (with a rotated User-Agent).
    /// Mirrors `get_dpi_evading_headers`.
    pub fn get_dpi_evading_headers(
        &self,
        base_headers: &BTreeMap<String, String>,
        threat_level: &str,
    ) -> BTreeMap<String, String> {
        let mut headers = base_headers.clone();
        if matches!(threat_level, "medium" | "high" | "critical") {
            headers.insert(
                "Accept".to_string(),
                "application/json, text/event-stream, */*".to_string(),
            );
            headers.insert(
                "Accept-Language".to_string(),
                "fa-IR,fa;q=0.9,en-US;q=0.8".to_string(),
            );
            headers.insert(
                "Accept-Encoding".to_string(),
                "gzip, deflate, br".to_string(),
            );
            headers.insert("Cache-Control".to_string(), "no-cache".to_string());
            headers.insert(
                "User-Agent".to_string(),
                BROWSER_USER_AGENTS[rand_index(BROWSER_USER_AGENTS.len())].to_string(),
            );
        }
        headers
    }

    /// Whether CF Gateway fronting should be used (low and above).
    /// Mirrors `should_use_gateway_fronting`.
    pub fn should_use_gateway_fronting(&self, threat_level: &str) -> bool {
        matches!(threat_level, "low" | "medium" | "high" | "critical")
    }

    /// Best CF fronting domain for the threat level; rotates at high/critical.
    /// Mirrors `get_fronting_domain`.
    pub fn get_fronting_domain(&self, threat_level: &str) -> &'static str {
        if matches!(threat_level, "high" | "critical") {
            CF_FRONTING_DOMAINS[rand_index(CF_FRONTING_DOMAINS.len())]
        } else {
            CF_FRONTING_DOMAINS[0]
        }
    }
}

/// Return a `GatewayDPIShaper`. Mirrors the Python singleton accessor
/// `get_gateway_dpi_shaper()` (no observable shared state).
pub fn get_gateway_dpi_shaper() -> GatewayDPIShaper {
    GatewayDPIShaper::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fronting_decision_matches_threat_levels() {
        let s = GatewayDPIShaper::new();
        for lvl in ["none", "off", ""] {
            assert!(!s.should_use_gateway_fronting(lvl));
        }
        for lvl in ["low", "medium", "high", "critical"] {
            assert!(s.should_use_gateway_fronting(lvl));
        }
    }

    #[test]
    fn fronting_domain_default_is_primary() {
        let s = GatewayDPIShaper::new();
        for lvl in ["none", "low", "medium"] {
            assert_eq!(s.get_fronting_domain(lvl), CF_FRONTING_DOMAINS[0]);
        }
        for lvl in ["high", "critical"] {
            assert!(CF_FRONTING_DOMAINS.contains(&s.get_fronting_domain(lvl)));
        }
    }

    #[test]
    fn slot_group_selection_is_deterministic() {
        let s = GatewayDPIShaper::new();
        assert_eq!(s.slot_group_for_isp(Some("Irancell-IR")), &[1, 2, 3]);
        assert_eq!(s.slot_group_for_isp(Some("mci")), &[4, 5, 6]);
        assert_eq!(s.slot_group_for_isp(Some("rightel-tehran")), &[7, 8]);
        assert_eq!(s.slot_group_for_isp(Some("shatel")), &[9, 10]);
        assert_eq!(s.slot_group_for_isp(Some("unknown")), &[11]);
        assert_eq!(s.slot_group_for_isp(None), &[11]);
        assert_eq!(s.slot_group_for_isp(Some("")), &[11]);
        // Returned optimal slot is always within the selected group.
        assert!([1, 2, 3].contains(&s.get_optimal_slot_for_isp(Some("irancell"))));
    }

    #[test]
    fn headers_unchanged_below_medium() {
        let s = GatewayDPIShaper::new();
        let mut base = BTreeMap::new();
        base.insert("X-Test".to_string(), "1".to_string());
        assert_eq!(s.get_dpi_evading_headers(&base, "low"), base);
        assert_eq!(s.get_dpi_evading_headers(&base, "none"), base);
    }

    #[test]
    fn headers_augmented_at_medium_and_above() {
        let s = GatewayDPIShaper::new();
        let base = BTreeMap::new();
        let h = s.get_dpi_evading_headers(&base, "high");
        assert_eq!(h["Accept"], "application/json, text/event-stream, */*");
        assert_eq!(h["Accept-Language"], "fa-IR,fa;q=0.9,en-US;q=0.8");
        assert_eq!(h["Accept-Encoding"], "gzip, deflate, br");
        assert_eq!(h["Cache-Control"], "no-cache");
        assert!(BROWSER_USER_AGENTS.contains(&h["User-Agent"].as_str()));
    }
}
