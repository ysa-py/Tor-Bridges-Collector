//! Parity port of `core/scorer.py`.
//!
//! Iran-aware bridge scoring engine. Scores each bridge 0-100 based on
//! its likelihood of working inside Iran, especially under DPI and during
//! internet cuts (NIN active).
//!
//! Scoring dimensions:
//!   - Transport:    0-30 pts (snowflake best, vanilla worst; adaptive weights from disk)
//!   - Port:         0-20 pts (443 best, high random ports worst)
//!   - IP version:   0-10 pts (IPv4 preferred in Iran)
//!   - Freshness:    0-20 pts (newer bridges less likely to be blocked)
//!   - Test result:  0-20 pts (proven reachable earns full marks)
//!   - CDN bonus:   +10 pts (CDN-fronted bridges survive internet cuts)
//!   - JA3 penalty:  0-15 pts (deducted for high-risk TLS fingerprint)

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;

use crate::dt_utils::{coerce_utc_dt, DEFAULT_FALLBACK};
use crate::tester::{detect_transport, extract_endpoint};

/// Default transport scores. Mirrors `_DEFAULT_TRANSPORT_SCORES`.
pub fn default_transport_scores() -> BTreeMap<&'static str, i64> {
    let mut m = BTreeMap::new();
    m.insert("snowflake", 30);
    m.insert("webtunnel", 28);
    m.insert("obfs4", 25);
    m.insert("meek_lite", 20);
    m.insert("vanilla", 5);
    m.insert("unknown", 8);
    m
}

/// Iran port scores. Mirrors `_IRAN_PORT_SCORES`.
pub fn iran_port_scores() -> BTreeMap<u16, i64> {
    let mut m = BTreeMap::new();
    m.insert(443, 20);
    m.insert(80, 15);
    m.insert(8080, 12);
    m.insert(8443, 12);
    m.insert(2083, 10);
    m.insert(2087, 10);
    m.insert(2096, 10);
    m
}

const PORT_SCORE_DEFAULT_LOW: i64 = 8;
const PORT_SCORE_DEFAULT_HIGH: i64 = 4;
#[allow(dead_code)]
const JA3_MAX_PENALTY: i64 = 15;

/// CDN survival patterns. Mirrors `_CDN_SURVIVAL_PATTERNS`.
/// Case-insensitive regex match against the bridge line.
pub fn cdn_survival_patterns() -> Vec<Regex> {
    [
        r"(?i)fastly\.net",
        r"(?i)arvancloud\.(com|ir)",
        r"(?i)cdn\.irimc\.ir",
        r"(?i)cloudfront\.net",
        r"(?i)azureedge\.net",
        r"(?i)aspnetcdn\.com",
        r"(?i)googlevideo\.com",
        r"(?i)gstatic\.com",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
}

/// Mirror of `IranScorer`. Stateful — holds the (possibly adaptive)
/// transport scores table. The JA3 penalty is simplified to 0 in this
/// port because the full JA3Intel database integration requires the
/// `ja3_intelligence` module's runtime state. See MIGRATION_NOTES.md.
pub struct IranScorer {
    transport_scores: BTreeMap<String, i64>,
    cdn_patterns: Vec<Regex>,
    now: DateTime<Utc>,
}

impl IranScorer {
    /// Construct with default transport scores and an injectable clock.
    pub fn new(now: DateTime<Utc>) -> Self {
        let mut transport_scores = BTreeMap::new();
        for (k, v) in default_transport_scores() {
            transport_scores.insert(k.to_string(), v);
        }
        Self {
            transport_scores,
            cdn_patterns: cdn_survival_patterns(),
            now,
        }
    }

    /// Production constructor — uses `chrono::Utc::now()`.
    pub fn with_defaults() -> Self {
        Self::new(Utc::now())
    }

    /// Mirror of `_load_transport_scores`. Loads adaptive scores from
    /// `data/transport_weights.json` if present, merging with defaults.
    /// On any error, falls back to defaults.
    pub fn load_transport_scores(&mut self, path: &Path) {
        if !path.exists() {
            return;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("Could not load adaptive transport scores: {e}");
                return;
            }
        };
        let data: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Could not parse adaptive transport scores: {e}");
                return;
            }
        };
        if let Some(scores) = data.get("scores").and_then(Value::as_object) {
            for (t, s) in scores {
                if let Some(score) = s.as_f64() {
                    if self.transport_scores.contains_key(t) {
                        self.transport_scores
                            .insert(t.clone(), (score.round()) as i64);
                    }
                }
            }
        }
    }

    /// Mirror of `_port_score(port)`.
    pub fn port_score(&self, port: u16) -> i64 {
        if let Some(&s) = iran_port_scores().get(&port) {
            return s;
        }
        if port < 1024 {
            PORT_SCORE_DEFAULT_LOW
        } else {
            PORT_SCORE_DEFAULT_HIGH
        }
    }

    /// Mirror of `_ipv_score(host)`. Returns 10 for IPv4 or domain,
    /// 5 for IPv6 or empty.
    pub fn ipv_score(&self, host: &str) -> i64 {
        if host.is_empty() {
            return 5;
        }
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            return if addr.is_ipv4() { 10 } else { 5 };
        }
        10 // Domain — assume IPv4 CDN
    }

    /// Mirror of `_freshness_score(first_seen)`.
    pub fn freshness_score(&self, first_seen: &str) -> i64 {
        let ts = coerce_utc_dt(Some(first_seen), DEFAULT_FALLBACK);
        let age = self.now.signed_duration_since(ts);
        if age <= chrono::Duration::hours(24) {
            20
        } else if age <= chrono::Duration::hours(72) {
            15
        } else if age <= chrono::Duration::days(7) {
            10
        } else if age <= chrono::Duration::days(30) {
            5
        } else {
            2
        }
    }

    /// Mirror of `_test_score(test_pass)`.
    pub fn test_score(&self, test_pass: Option<bool>) -> i64 {
        match test_pass {
            Some(true) => 20,
            Some(false) => 0,
            None => 10,
        }
    }

    /// Mirror of `_cdn_bonus(line)`.
    pub fn cdn_bonus(&self, line: &str) -> i64 {
        for pat in &self.cdn_patterns {
            if pat.is_match(line) {
                return 10;
            }
        }
        0
    }

    /// Mirror of `_ja3_penalty(record)`. Simplified — returns 0 because
    /// the full JA3Intel database integration requires runtime state from
    /// the `ja3_intelligence` module. See MIGRATION_NOTES.md.
    pub fn ja3_penalty(&self, _record: &Value) -> i64 {
        0
    }

    /// Mirror of `score(record)`. Computes a 0-100 Iran effectiveness
    /// score for a bridge record.
    pub fn score(&self, record: &Value) -> i64 {
        let raw = record.get("raw").and_then(Value::as_str).unwrap_or("");
        let transport_str = record
            .get("transport")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .unwrap_or_else(|| detect_transport(raw).to_string());
        let (host, port, _) = extract_endpoint(raw);

        let t_score = self
            .transport_scores
            .get(&transport_str.to_ascii_lowercase())
            .copied()
            .unwrap_or(8);
        let p_score = self.port_score(port.unwrap_or(0));
        let ip_score = self.ipv_score(&host.unwrap_or_default());
        let f_score = self.freshness_score(
            record
                .get("first_seen")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        let test_score = self.test_score(record.get("test_pass").and_then(Value::as_bool));
        let cdn_bonus = self.cdn_bonus(raw);
        let ja3_pen = self.ja3_penalty(record);

        let total = t_score + p_score + ip_score + f_score + test_score + cdn_bonus - ja3_pen;
        total.clamp(0, 100)
    }

    /// Mirror of `top_for_iran(history, n=50, min_score=0)`. Returns the
    /// top-`n` records sorted descending by `score`; ties preserve the
    /// order they appear in `history` (Python's `sorted(..., reverse=True)`
    /// is stable, and `Vec::sort_by_key` is documented stable too, so no
    /// extra index tie-break is needed).
    pub fn top_for_iran(&self, history: &[Value], n: usize, min_score: i64) -> Vec<Value> {
        let mut candidates: Vec<(Value, i64)> = history
            .iter()
            .filter_map(|v| {
                let score = v.get("score").and_then(Value::as_i64).unwrap_or(0);
                if score >= min_score {
                    Some((v.clone(), score))
                } else {
                    None
                }
            })
            .collect();
        candidates.sort_by_key(|item| std::cmp::Reverse(item.1));
        candidates.into_iter().take(n).map(|(v, _)| v).collect()
    }

    /// Mirror of `iran_cut_pack(history)`. Returns bridges most likely
    /// to work during Iranian internet cut (NIN active).
    pub fn iran_cut_pack(&self, history: &[Value]) -> Vec<Value> {
        let mut results: Vec<(Value, i64)> = Vec::new();
        for v in history {
            let t = v.get("transport").and_then(Value::as_str).unwrap_or("");
            let raw = v.get("raw").and_then(Value::as_str).unwrap_or("");
            if t == "snowflake" {
                results.push((v.clone(), 100));
            } else if t == "webtunnel" && self.cdn_bonus(raw) > 0 {
                results.push((v.clone(), 90));
            } else if t == "webtunnel" {
                results.push((v.clone(), 75));
            } else if t == "meek_lite" {
                results.push((v.clone(), 70));
            } else if t == "obfs4" {
                let (_, port, _) = extract_endpoint(raw);
                if port == Some(443) || port == Some(80) {
                    results.push((v.clone(), 60));
                }
            }
        }
        results.sort_by_key(|item| std::cmp::Reverse(item.1));
        results.into_iter().map(|(v, _)| v).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.from_utc_datetime(
            &chrono::NaiveDate::from_ymd_opt(2026, 6, 28)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
        )
    }

    #[test]
    fn port_score_known_ports() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.port_score(443), 20);
        assert_eq!(s.port_score(80), 15);
        assert_eq!(s.port_score(8080), 12);
    }

    #[test]
    fn port_score_unknown_low_port() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.port_score(22), PORT_SCORE_DEFAULT_LOW); // < 1024
    }

    #[test]
    fn port_score_unknown_high_port() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.port_score(9001), PORT_SCORE_DEFAULT_HIGH); // >= 1024
    }

    #[test]
    fn ipv_score_branches() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.ipv_score("1.2.3.4"), 10); // IPv4
        assert_eq!(s.ipv_score("2001:db8::1"), 5); // IPv6
        assert_eq!(s.ipv_score("example.com"), 10); // domain
        assert_eq!(s.ipv_score(""), 5); // empty
    }

    #[test]
    fn freshness_score_branches() {
        let s = IranScorer::new(fixed_now());
        // 1 hour old → 20
        let ts1 = (fixed_now() - chrono::Duration::hours(1)).to_rfc3339();
        assert_eq!(s.freshness_score(&ts1), 20);
        // 48 hours old → 15
        let ts48 = (fixed_now() - chrono::Duration::hours(48)).to_rfc3339();
        assert_eq!(s.freshness_score(&ts48), 15);
        // 5 days old → 10
        let ts5d = (fixed_now() - chrono::Duration::days(5)).to_rfc3339();
        assert_eq!(s.freshness_score(&ts5d), 10);
        // 20 days old → 5
        let ts20d = (fixed_now() - chrono::Duration::days(20)).to_rfc3339();
        assert_eq!(s.freshness_score(&ts20d), 5);
        // 60 days old → 2
        let ts60d = (fixed_now() - chrono::Duration::days(60)).to_rfc3339();
        assert_eq!(s.freshness_score(&ts60d), 2);
    }

    #[test]
    fn test_score_branches() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.test_score(Some(true)), 20);
        assert_eq!(s.test_score(Some(false)), 0);
        assert_eq!(s.test_score(None), 10);
    }

    #[test]
    fn cdn_bonus_matches_known_cdns() {
        let s = IranScorer::new(fixed_now());
        assert_eq!(s.cdn_bonus("url=https://fastly.net/x"), 10);
        assert_eq!(s.cdn_bonus("url=https://arvancloud.com/x"), 10);
        assert_eq!(s.cdn_bonus("url=https://example.com/x"), 0);
    }

    #[test]
    fn score_combines_all_dimensions() {
        let s = IranScorer::new(fixed_now());
        let recent = (fixed_now() - chrono::Duration::hours(1)).to_rfc3339();
        let record = serde_json::json!({
            "raw": "snowflake 192.0.2.3:1 url=https://fastly.net/x",
            "transport": "snowflake",
            "first_seen": recent,
            "test_pass": true,
        });
        let score = s.score(&record);
        // extract_endpoint returns (fastly.net, 443) for snowflake lines with url=https
        // snowflake=30 + port(443)=20 + ipv(fastly.net=domain)=10 + freshness=20 + test=20 + cdn=10 - ja3=0 = 110
        // clamped to 100
        assert_eq!(score, 100);
    }

    #[test]
    fn score_clamped_to_100() {
        let s = IranScorer::new(fixed_now());
        let recent = (fixed_now() - chrono::Duration::hours(1)).to_rfc3339();
        // All max: snowflake=30 + port(443)=20 + ipv=10 + freshness=20 + test=20 + cdn=10 = 110 → clamped to 100
        let record = serde_json::json!({
            "raw": "snowflake 192.0.2.3:443 url=https://fastly.net/x",
            "transport": "snowflake",
            "first_seen": recent,
            "test_pass": true,
        });
        let score = s.score(&record);
        assert_eq!(score, 100);
    }

    #[test]
    fn iran_cut_pack_prioritizes_snowflake() {
        let s = IranScorer::new(fixed_now());
        let history = vec![
            serde_json::json!({"transport": "vanilla", "raw": "vanilla 1.2.3.4:9001"}),
            serde_json::json!({"transport": "snowflake", "raw": "snowflake 5.6.7.8:1 url=https://x"}),
            serde_json::json!({"transport": "webtunnel", "raw": "webtunnel 9.10.11.12:443 url=https://fastly.net/y"}),
        ];
        let pack = s.iran_cut_pack(&history);
        assert_eq!(pack.len(), 2); // snowflake + webtunnel-with-CDN
        assert_eq!(pack[0]["transport"], "snowflake");
        assert_eq!(pack[1]["transport"], "webtunnel");
    }

    #[test]
    fn load_transport_scores_overrides_defaults() {
        let dir = std::env::temp_dir().join(format!("scorer_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("weights.json");
        std::fs::write(&path, r#"{"scores": {"snowflake": 50, "obfs4": 35}}"#).unwrap();

        let mut s = IranScorer::new(fixed_now());
        s.load_transport_scores(&path);
        assert_eq!(s.transport_scores.get("snowflake"), Some(&50));
        assert_eq!(s.transport_scores.get("obfs4"), Some(&35));
        // Defaults preserved for unlisted transports
        assert_eq!(s.transport_scores.get("vanilla"), Some(&5));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
