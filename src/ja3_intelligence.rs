//! Parity port of `ja3_intelligence.py` — FEATURE 2: JA3/JA3S Fingerprint
//! Evasion Intelligence.
//!
//! Maintains a database of TLS ClientHello fingerprints (JA3 hashes) known
//! to be flagged by Iran's SIAM deep-packet inspection infrastructure.
//! Provides scoring functions used by `core/scorer.py` to penalise bridges
//! whose TLS fingerprint is identifiable as Tor.
//!
//! # Behavior traced to `ja3_intelligence.py`
//!
//! * [`JA3Entry`] — mirrors the Python `@dataclass` of the same name. The
//!   [`JA3Entry::to_json`] method reproduces the field order produced by
//!   `dataclasses.asdict` so parity tests can compare JSON payloads directly.
//! * [`DATABASE`] — the built-in catalogue of high-risk JA3 fingerprints.
//!   Returned by [`database()`] to avoid lifetime gymnastics; the [`JA3Intel`]
//!   struct clones it into an internal HashMap at construction time.
//! * [`SAFE_HASHES`] / [`HIGH_RISK_PORTS`] / [`TRANSPORT_DEFAULT_RISK`] —
//!   module-level constant tables exposed for parity inspection.
//! * [`JA3Intel`] — the intelligence database interface with `lookup`,
//!   `score`, `is_critical`, `transport_default_risk`, `port_risk`,
//!   `all_critical_hashes`, and `summary` methods that match the Python
//!   class method-for-method and branch-for-branch.
//! * [`rotate_ja3_fingerprints_with_options`] — the Stage 8n rotation engine.
//!   Accepts injectable baseline / plan / report paths, an injectable
//!   `now` timestamp, and an injectable `default_padding_bytes` value that
//!   replaces the Python `random.randint(8, 32)` call. The default
//!   [`rotate_ja3_fingerprints`] helper uses the Python default paths,
//!   `Utc::now()`, and a fixed `padding_bytes = 16` (the midpoint of the
//!   Python random range); the deviation is documented in
//!   `MIGRATION_NOTES.md`.
//!
//! # Side effects not ported
//!
//! * The Python `monitoring.structured_logger.record_silent_failure` call on
//!   baseline read failure is replaced with `tracing::warn!`.
//! * The Python `_ja3_cli_main` argparse entry point and `__main__` guard
//!   are not ported as a single binary entry point. Callers compose
//!   [`rotate_ja3_fingerprints_with_options`] directly.
//! * The Python `random.randint(8, 32)` for the default rotation strategy
//!   is replaced by an injectable `default_padding_bytes` parameter. This is
//!   a documented deviation in `MIGRATION_NOTES.md`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `ja3_intelligence.py` parity port.
#[derive(Debug, Error)]
pub enum JA3Error {
    /// File I/O failure on a baseline / plan / report path.
    #[error("ja3 I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization / deserialization failure.
    #[error("ja3 JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// JA3Entry (mirrors the Python @dataclass)
// ─────────────────────────────────────────────────────────────────────────────

/// A single JA3 fingerprint intelligence entry. Mirrors the Python
/// `@dataclass class JA3Entry` field-for-field.
#[derive(Debug, Clone, PartialEq)]
pub struct JA3Entry {
    /// Lowercased MD5-style JA3 fingerprint hex string.
    pub hash_hex: String,
    /// Human-readable description of the fingerprint.
    pub description: String,
    /// Provenance of the entry (research corpus / OONI report).
    pub source: String,
    /// DPI risk tier: `"critical"` | `"high"` | `"medium"` | `"low"`.
    pub dpi_risk: String,
    /// Whether OONI Iran measurements have confirmed this hash is blocked.
    pub iran_ooni_confirmed: bool,
    /// Penalty weight in `[0.0, 1.0]`.
    pub score: f64,
}

impl JA3Entry {
    /// Serialize to a [`serde_json::Value`] using the same field order as
    /// Python's `dataclasses.asdict`.
    pub fn to_json(&self) -> Value {
        json!({
            "hash_hex": self.hash_hex,
            "description": self.description,
            "source": self.source,
            "dpi_risk": self.dpi_risk,
            "iran_ooni_confirmed": self.iran_ooni_confirmed,
            "score": self.score,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database of known high-risk JA3 fingerprints (mirrors `_DATABASE`)
// ─────────────────────────────────────────────────────────────────────────────

/// Catalogue of known high-risk JA3 fingerprints for Iran's DPI infrastructure.
///
/// Returns a fresh `Vec` on each call so callers can move out of it; the
/// [`JA3Intel`] struct calls this once at construction time and indexes the
/// result by `hash_hex`.
pub fn database() -> Vec<JA3Entry> {
    vec![
        JA3Entry {
            hash_hex: "e7d705a3286e19ea42f587b344ee6865".to_string(),
            description: "Tor Browser default TLS 1.3 ClientHello (NSS-based, Firefox ESR)"
                .to_string(),
            source: "public-research/salesforce-ja3".to_string(),
            dpi_risk: "critical".to_string(),
            iran_ooni_confirmed: true,
            score: 1.0,
        },
        JA3Entry {
            hash_hex: "6734f37431670b3ab4292b8f60f29984".to_string(),
            description: "Tor Browser alternative fingerprint (older NSS TLS stack)".to_string(),
            source: "ooni-tls-blocking-ir".to_string(),
            dpi_risk: "critical".to_string(),
            iran_ooni_confirmed: true,
            score: 0.95,
        },
        JA3Entry {
            hash_hex: "b32309a26951912be7dba376398abc3b".to_string(),
            description:
                "obfs4proxy TLS layer — identified in OONI tls_blocking measurements from IR"
                    .to_string(),
            source: "ooni-tls-blocking-ir".to_string(),
            dpi_risk: "high".to_string(),
            iran_ooni_confirmed: true,
            score: 0.85,
        },
        JA3Entry {
            hash_hex: "5d7e19ef9b3a4c56f5cd4a38cd0d0aa3".to_string(),
            description: "Meek-lite Azure CDN TLS handshake — flagged in some Iranian ISPs"
                .to_string(),
            source: "ooni-tls-blocking-ir".to_string(),
            dpi_risk: "medium".to_string(),
            iran_ooni_confirmed: false,
            score: 0.55,
        },
        JA3Entry {
            hash_hex: "de350869b8c85de67a350c8d186f11e6".to_string(),
            description: "Non-standard cipher ordering consistent with Tor relay connections"
                .to_string(),
            source: "censored-planet-research".to_string(),
            dpi_risk: "high".to_string(),
            iran_ooni_confirmed: false,
            score: 0.75,
        },
        JA3Entry {
            hash_hex: "3b5074b1b5d032e5620f69f9159c9b58".to_string(),
            description: "Golang TLS default fingerprint — commonly used by Tor relays".to_string(),
            source: "public-research".to_string(),
            dpi_risk: "medium".to_string(),
            iran_ooni_confirmed: false,
            score: 0.50,
        },
        JA3Entry {
            hash_hex: "cd08e31494f9531f560d64c695473da9".to_string(),
            description: "Python ssl module default (used in some PT implementations)".to_string(),
            source: "public-research".to_string(),
            dpi_risk: "low".to_string(),
            iran_ooni_confirmed: false,
            score: 0.30,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Safe / CDN-mimicking fingerprints (mirrors `_SAFE_HASHES`)
// ─────────────────────────────────────────────────────────────────────────────

/// Safe / CDN-mimicking fingerprints with negative risk weights.
///
/// The Python `_SAFE_HASHES` dict maps a hash to a *negative* risk score;
/// [`JA3Intel::score`] clamps the result to `0.0` via `max(0.0, score)`.
/// Note that the hash `b32309a26951912be7dba376398abc3b` appears in BOTH
/// [`database()`] (with score `0.85`) and here (with weight `-0.15`); the
/// safe-hash lookup takes precedence in [`JA3Intel::score`], matching the
/// Python branch order.
pub fn safe_hashes() -> HashMap<&'static str, f64> {
    let mut m = HashMap::new();
    // Chrome 120 on Windows
    m.insert("aaa7bf52f6c250ce0e70d7d4f32a6d52", -0.20);
    // Firefox 125 on Linux
    m.insert("b32309a26951912be7dba376398abc3b", -0.15);
    // Safari on macOS 14
    m.insert("35e2d4b5c7d7a09ab32c1f0a76e06e2f", -0.15);
    m
}

// ─────────────────────────────────────────────────────────────────────────────
// Iran DPI-detected Tor port combinations (mirrors `_HIGH_RISK_PORTS`)
// ─────────────────────────────────────────────────────────────────────────────

/// Tor ports that Iran's DPI flags as high-risk. Used by
/// [`JA3Intel::port_risk`].
pub const HIGH_RISK_PORTS: &[i64] = &[9001, 9030, 9050];

// ─────────────────────────────────────────────────────────────────────────────
// Transport-level default JA3 risk scores (mirrors `_TRANSPORT_DEFAULT_RISK`)
// ─────────────────────────────────────────────────────────────────────────────

/// Default JA3 risk scores per transport type. Used by
/// [`JA3Intel::transport_default_risk`] when the actual JA3 hash is
/// unavailable.
pub fn transport_default_risk_table() -> HashMap<&'static str, f64> {
    let mut m = HashMap::new();
    m.insert("snowflake", 0.05); // uses DTLS/WebRTC — not a standard TLS fingerprint
    m.insert("webtunnel", 0.15); // mimics CDN HTTPS — low risk if properly configured
    m.insert("obfs4", 0.20); // random-looking traffic, no TLS fingerprint exposed
    m.insert("meek_lite", 0.30); // TLS to CDN — risk depends on CDN configuration
    m.insert("vanilla", 0.90); // standard Tor TLS — highly identifiable
    m.insert("unknown", 0.50);
    m
}

// ─────────────────────────────────────────────────────────────────────────────
// JA3Intel — the intelligence database interface
// ─────────────────────────────────────────────────────────────────────────────

/// Interface to the JA3 fingerprint intelligence database. Mirrors the
/// Python `class JA3Intel`.
pub struct JA3Intel {
    index: HashMap<String, JA3Entry>,
}

impl JA3Intel {
    /// Construct a new intelligence database indexed by lowercased `hash_hex`.
    pub fn new() -> Self {
        let mut index = HashMap::new();
        for entry in database() {
            index.insert(entry.hash_hex.clone(), entry);
        }
        Self { index }
    }

    /// Return the database entry for this JA3 hash, or `None` if not known.
    ///
    /// Mirrors `JA3Intel.lookup`. The input is lowercased before lookup.
    pub fn lookup(&self, ja3_hash: &str) -> Option<&JA3Entry> {
        self.index.get(&ja3_hash.to_lowercase())
    }

    /// Return a DPI risk score in `[0.0, 1.0]`.
    ///
    /// Mirrors `JA3Intel.score`:
    /// * `1.0` = confirmed blocked by Iran's SIAM DPI.
    /// * `0.0` = safe / CDN-mimicking fingerprint (negative weight clamped
    ///   to zero).
    /// * `0.3` = unknown hash → medium risk.
    ///
    /// The safe-hash lookup takes precedence over the database lookup,
    /// matching the Python branch order.
    pub fn score(&self, ja3_hash: &str) -> f64 {
        let h = ja3_hash.to_lowercase();
        if let Some(&risk) = safe_hashes().get(h.as_str()) {
            // safe hashes give negative risk → clamped to 0
            return risk.max(0.0);
        }
        match self.index.get(&h) {
            Some(entry) => entry.score,
            None => 0.3, // unknown → medium risk
        }
    }

    /// True if this JA3 hash is confirmed critical by Iran OONI data.
    ///
    /// Mirrors `JA3Intel.is_critical`: requires `dpi_risk == "critical"` AND
    /// `iran_ooni_confirmed == true`.
    pub fn is_critical(&self, ja3_hash: &str) -> bool {
        match self.index.get(&ja3_hash.to_lowercase()) {
            Some(entry) => entry.dpi_risk == "critical" && entry.iran_ooni_confirmed,
            None => false,
        }
    }

    /// Conservative risk score for a transport type when the actual JA3 hash
    /// is unavailable.
    ///
    /// Mirrors `JA3Intel.transport_default_risk`. Unknown transports return
    /// `0.50`.
    pub fn transport_default_risk(&self, transport: &str) -> f64 {
        let lower = transport.to_lowercase();
        *transport_default_risk_table()
            .get(lower.as_str())
            .unwrap_or(&0.50)
    }

    /// Additional risk from using a port associated with default Tor traffic.
    ///
    /// Mirrors `JA3Intel.port_risk`: returns `0.80` for ports in
    /// [`HIGH_RISK_PORTS`], `0.0` otherwise.
    pub fn port_risk(&self, port: i64) -> f64 {
        if HIGH_RISK_PORTS.contains(&port) {
            0.80
        } else {
            0.0
        }
    }

    /// Return all JA3 hashes confirmed as critical for Iran's DPI.
    ///
    /// Mirrors `JA3Intel.all_critical_hashes`. Iterates [`database()`] in
    /// definition order, matching the Python list comprehension over
    /// `_DATABASE`.
    pub fn all_critical_hashes(&self) -> Vec<String> {
        database()
            .into_iter()
            .filter(|e| e.dpi_risk == "critical" && e.iran_ooni_confirmed)
            .map(|e| e.hash_hex)
            .collect()
    }

    /// Return a summary of the database contents.
    ///
    /// Mirrors `JA3Intel.summary`. The returned [`Value`] is a JSON object
    /// with integer fields `total`, `critical`, `high`, `iran_confirmed`.
    pub fn summary(&self) -> Value {
        let db = database();
        let total = db.len() as i64;
        let critical = db.iter().filter(|e| e.dpi_risk == "critical").count() as i64;
        let high = db.iter().filter(|e| e.dpi_risk == "high").count() as i64;
        let iran_confirmed = db.iter().filter(|e| e.iran_ooni_confirmed).count() as i64;
        json!({
            "total": total,
            "critical": critical,
            "high": high,
            "iran_confirmed": iran_confirmed,
        })
    }
}

impl Default for JA3Intel {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JA3 fingerprint rotation engine (Objective 7 / Stage 8n)
// ─────────────────────────────────────────────────────────────────────────────

/// SIAM-blocked JA3 hashes from published censorship research.
///
/// Sources: OONI Iran reports, Censored Planet, University of Michigan.
/// Mirrors the Python `SIAM_BLOCKED_JA3` dict; iteration order matches the
/// Python dict insertion order (which [`rotate_ja3_fingerprints_with_options`]
/// preserves when building `blocked_details`).
pub const SIAM_BLOCKED_JA3: &[(&str, &str)] = &[
    // Standard Tor Browser fingerprints
    (
        "e7d705a3286e19ea42f587b344ee6865",
        "Tor Browser 12.x default",
    ),
    (
        "a0e9f5d64349fb13191bc781f81f42e1",
        "Tor Browser 11.x / obfs4 default",
    ),
    (
        "6734f37431670b3ab4292b8f60f29984",
        "obfs4proxy 0.0.14 TLS ClientHello",
    ),
    (
        "0a68a71f1c77c3e5c5f7a093a79c8f46",
        "Snowflake default WebRTC DTLS",
    ),
    (
        "da4a0008103d7aa41e359bfe4687d5f3",
        "Tor relay guard TLS 1.2",
    ),
    // Common Shadowsocks / V2Ray clients also blocked in Iran
    (
        "b32309a26951912be7dba376398d2d3f",
        "V2Ray 4.x TLS fingerprint",
    ),
    ("8bcea3c31e9862cf1c4b0e4fcd2cbecd", "Shadowsocks-libev TLS"),
    // meek fingerprints that SIAM correlates with Tor usage
    (
        "d9e0d4b1f8c5a3e2b7f6a1c0e8d2b5f9",
        "meek_lite CDN fingerprint",
    ),
    // Generic Go TLS default (used by many PT implementations)
    (
        "9e10692f1b7a698d15d9a5e0e43fd3a5",
        "Go net/tls default ClientHello",
    ),
];

/// Universal recommendations written to every rotation plan. Mirrors the
/// Python `universal_recommendations` list literal.
pub const UNIVERSAL_RECOMMENDATIONS: &[&str] = &[
    "Enable TLS padding extension (RFC 7685) on all pluggable transport clients.",
    "Use iat-mode=2 for obfs4 to randomise inter-arrival timing.",
    "Rotate JA3 baseline every 72 hours regardless of blocking status.",
    "Prefer WebTunnel over obfs4 -- WebTunnel JA3 is identical to browser HTTPS.",
    "Enable ECH if bridge supports it -- hides SNI from SIAM DPI completely.",
];

/// Build the rotation strategy dict for a given blocked-profile name.
///
/// Mirrors the Python `ROTATION_STRATEGIES` dict. The `default_padding_bytes`
/// parameter is used only for the `"default"` profile (replacing the Python
/// `random.randint(8, 32)` call). The two named profiles (`"Tor Browser
/// 12.x default"` and `"Go net/tls default ClientHello"`) use fixed
/// `padding_bytes` values from the Python source.
pub fn rotation_strategy(profile: &str, default_padding_bytes: i64) -> Value {
    match profile {
        "Tor Browser 12.x default" => json!({
            "action": "cipher_suite_reorder",
            "padding_bytes": 17,
            "recommended_cipher_order": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ],
            "extensions_order": ["SNI", "EC_POINT_FORMATS", "ALPN", "PADDING"],
            "siam_defeat_note":
                "Reordering cipher suites + adding 17-byte padding block \
                 changes the JA3 hash completely. Mimics Chrome 120 profile.",
        }),
        "Go net/tls default ClientHello" => json!({
            "action": "chrome_mimicry",
            "padding_bytes": 0,
            "recommended_cipher_order": [
                "TLS_GREASE",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
            ],
            "extensions_order": [
                "GREASE",
                "SNI",
                "EXTENDED_MASTER_SECRET",
                "RENEGOTIATION_INFO",
                "SUPPORTED_GROUPS",
                "EC_POINT_FORMATS",
                "SESSION_TICKET",
                "ALPN",
                "STATUS_REQUEST",
                "SIGNED_CERT_TIMESTAMPS",
                "KEY_SHARE",
                "PSK_KEY_EXCHANGE",
                "SUPPORTED_VERSIONS",
                "COMPRESS_CERTIFICATE",
                "GREASE",
                "PADDING",
            ],
            "siam_defeat_note":
                "Mimicking Chrome 120 TLS fingerprint. GREASE values and \
                 extension order are validated against Censored Planet dataset.",
        }),
        // The "default" strategy covers all profiles not explicitly named
        // above (including the V2Ray / Shadowsocks / meek / Snowflake /
        // Tor relay guard / Tor Browser 11.x profiles from SIAM_BLOCKED_JA3).
        _ => json!({
            "action": "random_padding",
            "padding_bytes": default_padding_bytes,
            "recommended_cipher_order": [],
            "extensions_order": [],
            "siam_defeat_note":
                "Add random TLS padding extension (RFC 7685) to alter JA3 hash.",
        }),
    }
}

/// Look up the SIAM-blocked profile name for a lowercased JA3 hash.
///
/// Returns `None` if the hash is not in [`SIAM_BLOCKED_JA3`]. Mirrors the
/// Python `SIAM_BLOCKED_JA3` dict lookup.
fn siam_blocked_profile(hash: &str) -> Option<&'static str> {
    SIAM_BLOCKED_JA3
        .iter()
        .find(|(h, _)| *h == hash)
        .map(|(_, p)| *p)
}

/// Read the baseline file and extract the list of lowercased JA3 hashes.
///
/// Mirrors the Python baseline-parsing branch:
/// * If the baseline is a JSON object, use `bridges` (or `hashes`, or
///   `[baseline]` as fallback).
/// * If the baseline is a JSON array, use it directly.
/// * Otherwise, use an empty list.
///
/// For each entry that is a JSON object, the first non-empty string value
/// found at keys `ja3`, `ja3_hash`, `hash`, `fingerprint` (in that order)
/// is lowercased and appended.
///
/// # Deviation from Python
///
/// The Python `entry.get(key, "")` returns whatever value is at that key,
/// including non-string truthy values like `123`. The subsequent `h.lower()`
/// call then crashes with `AttributeError` for non-string values. The Rust
/// port skips non-string values (treating them as missing), which is a
/// robustness improvement documented in `MIGRATION_NOTES.md`.
fn extract_bridge_hashes(baseline: &Value) -> Vec<String> {
    let entries: Vec<Value> = match baseline {
        Value::Object(_) => {
            if let Some(bridges) = baseline.get("bridges") {
                bridges.as_array().cloned().unwrap_or_default()
            } else if let Some(hashes) = baseline.get("hashes") {
                hashes.as_array().cloned().unwrap_or_default()
            } else {
                vec![baseline.clone()]
            }
        }
        Value::Array(arr) => arr.clone(),
        _ => vec![],
    };

    let mut bridge_hashes: Vec<String> = Vec::new();
    for entry in &entries {
        if !entry.is_object() {
            continue;
        }
        for key in &["ja3", "ja3_hash", "hash", "fingerprint"] {
            if let Some(h) = entry.get(key).and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    bridge_hashes.push(h.to_lowercase());
                    break;
                }
            }
        }
    }
    bridge_hashes
}

/// Build the rotation plan JSON object.
///
/// Mirrors the Python `plan` dict construction. The `generated_at` field
/// uses the injected `now` parameter formatted as RFC 3339 (matching
/// Python's `datetime.now(UTC).isoformat()`).
fn build_plan(now: DateTime<Utc>, bridge_hashes: &[String], blocked_found: &[Value]) -> Value {
    json!({
        "generated_at": now.to_rfc3339(),
        "baseline_hashes_checked": bridge_hashes.len() as i64,
        "blocked_hashes_found": blocked_found.len() as i64,
        "rotation_needed": !blocked_found.is_empty(),
        "siam_blocked_database_size": SIAM_BLOCKED_JA3.len() as i64,
        "blocked_details": blocked_found,
        "universal_recommendations": UNIVERSAL_RECOMMENDATIONS,
    })
}

/// Build the human-readable rotation report markdown.
///
/// Mirrors the Python `md_lines` construction and `"\n".join(md_lines)`
/// serialization. The `now_str` parameter is formatted as
/// `"%Y-%m-%d %H:%M:%S UTC"` to match Python's `strftime`.
fn build_report(now: DateTime<Utc>, bridge_hashes: &[String], blocked_found: &[Value]) -> String {
    let now_str = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let rotation_needed = if blocked_found.is_empty() {
        "NO"
    } else {
        "YES"
    };

    let mut md_lines: Vec<String> = Vec::new();
    md_lines.push("# JA3/TLS Fingerprint Rotation Report".to_string());
    md_lines.push(format!("**Generated:** {}  ", now_str));
    md_lines.push(String::new());
    md_lines.push("## Summary".to_string());
    md_lines.push(String::new());
    md_lines.push(format!(
        "- JA3 hashes checked against SIAM blocklist: **{}**",
        bridge_hashes.len()
    ));
    md_lines.push(format!(
        "- Blocked hashes detected: **{}**",
        blocked_found.len()
    ));
    md_lines.push(format!("- Rotation needed: **{}**", rotation_needed));
    md_lines.push(format!(
        "- SIAM blocked-hash database size: **{}**",
        SIAM_BLOCKED_JA3.len()
    ));
    md_lines.push(String::new());
    md_lines.push("## Blocked Hash Details".to_string());
    md_lines.push(String::new());

    if !blocked_found.is_empty() {
        for entry in blocked_found {
            let s = &entry["rotation_strategy"];
            md_lines.push(format!(
                "### `{}`",
                entry["ja3_hash"].as_str().unwrap_or("")
            ));
            md_lines.push(format!(
                "- **Profile:** {}",
                entry["blocked_profile"].as_str().unwrap_or("")
            ));
            md_lines.push(format!(
                "- **Action:** `{}`",
                s["action"].as_str().unwrap_or("")
            ));
            md_lines.push(format!("- **Padding bytes:** {}", s["padding_bytes"]));
            md_lines.push(format!(
                "- **SIAM defeat note:** {}",
                s["siam_defeat_note"].as_str().unwrap_or("")
            ));
            md_lines.push(String::new());
        }
    } else {
        md_lines.push(
            "> No blocked JA3 hashes detected in current baseline. \
             Continue monitoring every 72 hours."
                .to_string(),
        );
        md_lines.push(String::new());
    }

    md_lines.push("## Universal Recommendations".to_string());
    md_lines.push(String::new());
    md_lines.push("1. Enable TLS padding (RFC 7685) on all PT clients.".to_string());
    md_lines.push("2. Use `iat-mode=2` for obfs4 timing randomisation.".to_string());
    md_lines.push("3. Rotate JA3 baseline every 72 hours.".to_string());
    md_lines.push("4. Prefer WebTunnel — its JA3 is identical to browser HTTPS.".to_string());
    md_lines.push("5. Enable ECH where available — completely hides SNI from SIAM.".to_string());
    md_lines.push(String::new());
    md_lines.push("---".to_string());
    md_lines
        .push("*Generated by TorShield-IR Stage 8n (ja3_intelligence.py --rotate)*".to_string());

    md_lines.join("\n")
}

/// Run the JA3 fingerprint rotation engine with fully injectable parameters.
///
/// Mirrors the Python `rotate_ja3_fingerprints()` function:
/// 1. Read the baseline JSON from `baseline_file` (missing file → empty
///    baseline; invalid JSON → empty baseline with a `tracing::warn!`).
/// 2. Extract bridge JA3 hashes from the baseline.
/// 3. Compare each hash against [`SIAM_BLOCKED_JA3`]; for each match, look
///    up the rotation strategy via [`rotation_strategy`].
/// 4. Write the machine-readable plan JSON to `plan_file`.
/// 5. Write the human-readable report markdown to `report_file`.
/// 6. Return `Ok(0)` on success.
///
/// The `now` parameter is used for the `generated_at` field in the plan and
/// the `**Generated:**` line in the report. The `default_padding_bytes`
/// parameter replaces the Python `random.randint(8, 32)` call for the
/// `"default"` rotation strategy.
///
/// # Errors
///
/// Returns [`JA3Error::Io`] if the baseline file exists but cannot be read,
/// or if the plan / report files cannot be written. Returns [`JA3Error::Json`]
/// if the plan JSON cannot be serialized.
pub fn rotate_ja3_fingerprints_with_options(
    baseline_file: &Path,
    plan_file: &Path,
    report_file: &Path,
    now: DateTime<Utc>,
    default_padding_bytes: i64,
) -> Result<i32, JA3Error> {
    tracing::info!("=== JA3 Fingerprint Rotation Engine ===");

    // --- Load baseline ---
    let baseline: Value = if !baseline_file.exists() {
        tracing::warn!(
            "JA3 baseline not found: {} -- creating empty plan.",
            baseline_file.display()
        );
        Value::Object(serde_json::Map::new())
    } else {
        match fs::read_to_string(baseline_file) {
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(v) => v,
                Err(exc) => {
                    tracing::warn!("Cannot read JA3 baseline: {} -- using empty.", exc);
                    Value::Object(serde_json::Map::new())
                }
            },
            Err(exc) => {
                tracing::warn!("Cannot read JA3 baseline: {} -- using empty.", exc);
                Value::Object(serde_json::Map::new())
            }
        }
    };

    // --- Compare baseline hashes against blocked list ---
    let bridge_hashes = extract_bridge_hashes(&baseline);

    let mut blocked_found: Vec<Value> = Vec::new();
    for h in &bridge_hashes {
        if let Some(profile) = siam_blocked_profile(h) {
            let strategy = rotation_strategy(profile, default_padding_bytes);
            blocked_found.push(json!({
                "ja3_hash": h,
                "blocked_profile": profile,
                "rotation_strategy": strategy,
            }));
            tracing::warn!("BLOCKED JA3 hash detected: {} ({})", h, profile);
        }
    }

    // --- Build rotation plan ---
    if let Some(parent) = plan_file.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    let plan = build_plan(now, &bridge_hashes, &blocked_found);
    let plan_json = serde_json::to_string_pretty(&plan)?;
    fs::write(plan_file, plan_json).map_err(|source| JA3Error::Io {
        path: plan_file.to_string_lossy().to_string(),
        source,
    })?;
    tracing::info!("JA3 rotation plan written -> {}", plan_file.display());

    // --- Build human-readable report ---
    let report = build_report(now, &bridge_hashes, &blocked_found);
    fs::write(report_file, report).map_err(|source| JA3Error::Io {
        path: report_file.to_string_lossy().to_string(),
        source,
    })?;
    tracing::info!("JA3 rotation report written -> {}", report_file.display());
    tracing::info!("=== JA3 Rotation Engine done ===");
    Ok(0)
}

/// Run the JA3 fingerprint rotation engine with the Python default paths
/// and `Utc::now()`.
///
/// Equivalent to calling `rotate_ja3_fingerprints()` in Python. The
/// `default_padding_bytes` is set to `16` (the midpoint of the Python
/// `random.randint(8, 32)` range); pass [`rotate_ja3_fingerprints_with_options`]
/// directly to override.
pub fn rotate_ja3_fingerprints() -> Result<i32, JA3Error> {
    rotate_ja3_fingerprints_with_options(
        Path::new("data/ja3_baseline.json"),
        Path::new("data/ja3_rotation_plan.json"),
        Path::new("data/ja3_rotation_report.md"),
        Utc::now(),
        16,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_has_seven_entries() {
        assert_eq!(database().len(), 7);
    }

    #[test]
    fn intel_summary_matches_python_counts() {
        let intel = JA3Intel::new();
        let s = intel.summary();
        assert_eq!(s["total"], json!(7));
        assert_eq!(s["critical"], json!(2));
        assert_eq!(s["high"], json!(2));
        assert_eq!(s["iran_confirmed"], json!(3));
    }

    #[test]
    fn safe_hash_takes_precedence_over_database() {
        // b32309a26951912be7dba376398abc3b is in BOTH the database (score
        // 0.85) and the safe-hashes table (-0.15). The safe-hash lookup
        // fires first and returns 0.0 after clamping.
        let intel = JA3Intel::new();
        assert!((intel.score("b32309a26951912be7dba376398abc3b") - 0.0).abs() < f64::EPSILON);
        // But lookup() still returns the database entry.
        let entry = intel.lookup("b32309a26951912be7dba376398abc3b").unwrap();
        assert!((entry.score - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn unknown_hash_returns_medium_risk() {
        let intel = JA3Intel::new();
        assert!((intel.score("deadbeef") - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let intel = JA3Intel::new();
        assert!(intel.lookup("E7D705A3286E19EA42F587B344EE6865").is_some());
    }

    #[test]
    fn is_critical_requires_critical_tier_and_iran_confirmation() {
        let intel = JA3Intel::new();
        // e7d705a3... is critical + iran_ooni_confirmed → True
        assert!(intel.is_critical("e7d705a3286e19ea42f587b344ee6865"));
        // b32309a2... is high + iran_ooni_confirmed → False (not critical)
        assert!(!intel.is_critical("b32309a26951912be7dba376398abc3b"));
        // de350869... is high + NOT iran_ooni_confirmed → False
        assert!(!intel.is_critical("de350869b8c85de67a350c8d186f11e6"));
        // unknown hash → False
        assert!(!intel.is_critical("deadbeef"));
    }

    #[test]
    fn port_risk_high_risk_ports() {
        let intel = JA3Intel::new();
        for p in [9001, 9030, 9050] {
            assert!((intel.port_risk(p) - 0.80).abs() < f64::EPSILON);
        }
        for p in [443, 80, 8080, 0, 1234] {
            assert!((intel.port_risk(p) - 0.0).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn transport_default_risk_known_and_unknown() {
        let intel = JA3Intel::new();
        assert!((intel.transport_default_risk("snowflake") - 0.05).abs() < f64::EPSILON);
        assert!((intel.transport_default_risk("WebTunnel") - 0.15).abs() < f64::EPSILON);
        assert!((intel.transport_default_risk("OBFs4") - 0.20).abs() < f64::EPSILON);
        assert!((intel.transport_default_risk("unknown") - 0.50).abs() < f64::EPSILON);
        assert!((intel.transport_default_risk("not-a-transport") - 0.50).abs() < f64::EPSILON);
    }

    #[test]
    fn all_critical_hashes_returns_two_entries() {
        let intel = JA3Intel::new();
        let hashes = intel.all_critical_hashes();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"e7d705a3286e19ea42f587b344ee6865".to_string()));
        assert!(hashes.contains(&"6734f37431670b3ab4292b8f60f29984".to_string()));
    }

    #[test]
    fn rotation_strategy_tor_browser_12_default() {
        let s = rotation_strategy("Tor Browser 12.x default", 20);
        assert_eq!(s["action"], "cipher_suite_reorder");
        assert_eq!(s["padding_bytes"], 17);
    }

    #[test]
    fn rotation_strategy_go_tls_default() {
        let s = rotation_strategy("Go net/tls default ClientHello", 20);
        assert_eq!(s["action"], "chrome_mimicry");
        assert_eq!(s["padding_bytes"], 0);
    }

    #[test]
    fn rotation_strategy_default_uses_injected_padding() {
        let s = rotation_strategy("Tor Browser 11.x / obfs4 default", 20);
        assert_eq!(s["action"], "random_padding");
        assert_eq!(s["padding_bytes"], 20);
    }
}
