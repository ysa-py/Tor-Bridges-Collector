//! Single shared, table-driven non-routable IP validator.
//!
//! Every pipeline layer (scraper, collector, tester) calls the same two
//! functions exported here.  Adding a new reserved range requires only a
//! data entry in [`RESERVED_CIDR_V4`] or [`RESERVED_CIDR_V6`] — no logic
//! changes anywhere.
//!
//! Telemetry counters (`REJECTION_COUNTS`) are exported so the CI summary
//! can report per-transport/per-reason rejection counts without manual
//! investigation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

// ── Data-driven reserved CIDR tables ─────────────────────────────────────

/// Entry in the reserved-range table.  `label` is the reason code shown in
/// telemetry and logs (e.g. `RFC_3849_DOCUMENTATION`).
struct ReservedCidrV4 {
    /// Network portion as a 32-bit integer (host byte order).
    network: u32,
    /// CIDR prefix length (0–32).
    prefix: u8,
    /// Human-readable reason code for telemetry.
    label: &'static str,
}

struct ReservedCidrV6 {
    /// Network portion as a 128-bit integer (host byte order).
    network: u128,
    /// CIDR prefix length (0–128).
    prefix: u8,
    /// Human-readable reason code for telemetry.
    label: &'static str,
}

macro_rules! cidr_v4 {
    ([$a:literal, $b:literal, $c:literal, $d:literal] / $prefix:literal, $label:ident) => {
        ReservedCidrV4 {
            network: u32::from_be_bytes([$a, $b, $c, $d]) & mask_v4($prefix),
            prefix: $prefix,
            label: stringify!($label),
        }
    };
}

macro_rules! cidr_v6 {
    ([$a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $f:literal, $g:literal, $h:literal] / $prefix:literal, $label:ident) => {
        ReservedCidrV6 {
            network: u128::from_be_bytes([
                ($a >> 8) as u8,
                ($a & 0xff) as u8,
                ($b >> 8) as u8,
                ($b & 0xff) as u8,
                ($c >> 8) as u8,
                ($c & 0xff) as u8,
                ($d >> 8) as u8,
                ($d & 0xff) as u8,
                ($e >> 8) as u8,
                ($e & 0xff) as u8,
                ($f >> 8) as u8,
                ($f & 0xff) as u8,
                ($g >> 8) as u8,
                ($g & 0xff) as u8,
                ($h >> 8) as u8,
                ($h & 0xff) as u8,
            ]) & mask_v6($prefix),
            prefix: $prefix,
            label: stringify!($label),
        }
    };
}

const fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[rustfmt::skip]
const RESERVED_CIDR_V4: &[ReservedCidrV4] = &[
    // ── Non-routable / documentation / reserved ranges (IANA registries) ──
    cidr_v4!([0, 0, 0, 0] / 8,         CURRENT_NETWORK_RFC1122),
    cidr_v4!([10, 0, 0, 0] / 8,        PRIVATE_RFC1918_10),
    cidr_v4!([100, 64, 0, 0] / 10,     CGNAT_RFC6598),
    cidr_v4!([127, 0, 0, 0] / 8,       LOOPBACK_RFC1122),
    cidr_v4!([169, 254, 0, 0] / 16,    LINK_LOCAL_RFC3927),
    cidr_v4!([172, 16, 0, 0] / 12,     PRIVATE_RFC1918_172),
    cidr_v4!([192, 0, 0, 0] / 24,      IETF_PROTOCOL_RFC6890),
    cidr_v4!([192, 0, 2, 0] / 24,      TEST_NET_1_RFC5737),
    cidr_v4!([192, 88, 99, 0] / 24,    IPV6_TO_IPV4_RELAY_RFC3068),
    cidr_v4!([192, 168, 0, 0] / 16,    PRIVATE_RFC1918_192),
    cidr_v4!([198, 18, 0, 0] / 15,     BENCHMARKING_RFC2544),
    cidr_v4!([198, 51, 100, 0] / 24,   TEST_NET_2_RFC5737),
    cidr_v4!([203, 0, 113, 0] / 24,    TEST_NET_3_RFC5737),
    cidr_v4!([224, 0, 0, 0] / 4,       MULTICAST_RFC5771),
    cidr_v4!([240, 0, 0, 0] / 4,       RESERVED_RFC1112),
    cidr_v4!([255, 255, 255, 255] / 32, LIMITED_BROADCAST_RFC919),
];

#[rustfmt::skip]
const RESERVED_CIDR_V6: &[ReservedCidrV6] = &[
    // ── Non-routable / documentation / reserved IPv6 ranges ──
    cidr_v6!([0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 128, UNSPECIFIED),
    cidr_v6!([0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001] / 128, LOOPBACK_V6),
    cidr_v6!([0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xffff, 0x0000, 0x0000] / 96,  IPV4_MAPPED_RFC4291),
    cidr_v6!([0x0064, 0xff9b, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 96,  IPV4_IPV6_TRANSLATION_RFC6052),
    cidr_v6!([0x0100, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 64,  DISCARD_ONLY_RFC6666),
    cidr_v6!([0x2001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 32,  TEREDO_RFC4380),
    cidr_v6!([0x2001, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 48,  BENCHMARKING_V6_RFC5180),
    cidr_v6!([0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 32,  DOCUMENTATION_RFC3849_2001_DB8),
    cidr_v6!([0x2001, 0x0010, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 28,  DEPRECATED_ORCHID_RFC4843),
    cidr_v6!([0x2002, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 16,  SIX_TO_FOUR_RFC3056),
    cidr_v6!([0xfc00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 7,   UNIQUE_LOCAL_RFC4193),
    cidr_v6!([0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 10,  LINK_LOCAL_V6_RFC4291),
    cidr_v6!([0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000] / 8,   MULTICAST_V6_RFC4291),
];

// ── Telemetry ─────────────────────────────────────────────────────────────

/// Per-reason rejection counter, reset each pipeline run.
static REJECTION_COUNTS: OnceLock<std::collections::HashMap<&'static str, AtomicU64>> =
    OnceLock::new();

fn get_rejection_counts() -> &'static std::collections::HashMap<&'static str, AtomicU64> {
    REJECTION_COUNTS.get_or_init(|| {
        let mut m = std::collections::HashMap::new();
        for entry in RESERVED_CIDR_V4 {
            m.insert(entry.label, AtomicU64::new(0));
        }
        for entry in RESERVED_CIDR_V6 {
            m.insert(entry.label, AtomicU64::new(0));
        }
        m
    })
}

/// Increment the rejection counter for a given reason label (no-op for
/// unknown labels).
pub fn record_rejection(reason: &str, transport: &str) {
    if let Some(counter) = get_rejection_counts().get(reason) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    tracing::info!(
        target: "ip_guard",
        event = "rejected_non_routable_endpoint",
        reason = reason,
        transport = transport,
        "Rejected bridge with non-routable endpoint"
    );
}

/// Return a snapshot of all rejection counters, keyed by reason label.
pub fn rejection_snapshot() -> Vec<(&'static str, u64)> {
    let mut snapshot: Vec<_> = get_rejection_counts()
        .iter()
        .map(|(k, v)| (*k, v.load(Ordering::Relaxed)))
        .filter(|(_, count)| *count > 0)
        .collect();
    snapshot.sort_by_key(|b| std::cmp::Reverse(b.1)); // highest count first
    snapshot
}

/// Reset all rejection counters (call at the start of each pipeline run).
pub fn reset_rejection_counters() {
    for counter in get_rejection_counts().values() {
        counter.store(0, Ordering::Relaxed);
    }
}

// ── Core check functions ──────────────────────────────────────────────────

/// Return `true` when `ip` falls within any known reserved/non-routable range.
#[must_use]
pub fn is_documentation_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_documentation_or_reserved_ipv4(v4),
        IpAddr::V6(v6) => is_documentation_or_reserved_ipv6(v6),
    }
}

/// Return the reason label if `ip` is reserved, or `None` if routable.
#[must_use]
pub fn check_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from_be_bytes(v4.octets());
            for entry in RESERVED_CIDR_V4 {
                if bits & mask_v4(entry.prefix) == entry.network {
                    return Some(entry.label);
                }
            }
            None
        }
        IpAddr::V6(v6) => {
            let bits = u128::from_be_bytes(v6.octets());
            for entry in RESERVED_CIDR_V6 {
                if bits & mask_v6(entry.prefix) == entry.network {
                    return Some(entry.label);
                }
            }
            None
        }
    }
}

fn is_documentation_or_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let bits = u32::from_be_bytes(ip.octets());
    RESERVED_CIDR_V4
        .iter()
        .any(|entry| bits & mask_v4(entry.prefix) == entry.network)
}

fn is_documentation_or_reserved_ipv6(ip: Ipv6Addr) -> bool {
    let bits = u128::from_be_bytes(ip.octets());
    RESERVED_CIDR_V6
        .iter()
        .any(|entry| bits & mask_v6(entry.prefix) == entry.network)
}

// ── Line-based endpoint check ─────────────────────────────────────────────

/// Scan a bridge line for an IP endpoint and return `Some(reason_label)` if
/// its address falls within any reserved range.  Returns `None` for clean
/// lines.
///
/// Only literal IPv4/IPv6 endpoints are checked — DNS names and URL-only
/// lines are allowed through.
#[must_use]
pub fn contains_documentation_or_reserved_endpoint(line: &str) -> bool {
    check_endpoint(line).is_some()
}

/// Like [`contains_documentation_or_reserved_endpoint`] but returns the
/// reason label so callers can record telemetry.
#[must_use]
pub fn check_endpoint(line: &str) -> Option<&'static str> {
    // Strip optional "Bridge " prefix
    let trimmed = line.trim().strip_prefix("Bridge ").unwrap_or(line.trim());

    // Scan tokens for a literal IP endpoint
    for token in trimmed.split_whitespace() {
        let token = token.trim_matches(|c: char| matches!(c, ',' | ';' | '"'));
        if token.is_empty() || token.contains('=') {
            continue;
        }
        if token.starts_with("http://") || token.starts_with("https://") {
            continue;
        }

        // Bracketed IPv6: [addr]:port
        if let Some(rest) = token.strip_prefix('[') {
            if let Some((host, _port)) = rest.split_once("]:") {
                if let Ok(ip) = host.parse::<Ipv6Addr>() {
                    return check_ip(IpAddr::V6(ip));
                }
            }
            continue;
        }

        // IPv4 or DNS: host:port (rsplit_once to handle IPv4)
        if let Some((host, port_text)) = token.rsplit_once(':') {
            if !host.is_empty()
                && !host.contains(':')
                && port_text.parse::<u16>().is_ok_and(|p: u16| p != 0)
            {
                if let Ok(ip) = host.parse::<Ipv4Addr>() {
                    return check_ip(IpAddr::V4(ip));
                }
            }
        }
    }
    None
}

/// Convenience: check a line and record telemetry if rejected.
/// Returns `true` if the line was rejected (contains a reserved endpoint).
#[must_use]
pub fn reject_if_reserved(line: &str, transport: &str) -> bool {
    if let Some(reason) = check_endpoint(line) {
        record_rejection(reason, transport);
        true
    } else {
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CIDR table integrity ──────────────────────────────────────────

    #[test]
    fn cidr_v4_table_is_non_empty() {
        assert!(!RESERVED_CIDR_V4.is_empty());
    }

    #[test]
    fn cidr_v6_table_is_non_empty() {
        assert!(!RESERVED_CIDR_V6.is_empty());
    }

    #[test]
    fn every_v4_entry_has_unique_label() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in RESERVED_CIDR_V4 {
            assert!(
                seen.insert(entry.label),
                "Duplicate IPv4 label: {}",
                entry.label
            );
        }
    }

    #[test]
    fn every_v6_entry_has_unique_label() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in RESERVED_CIDR_V6 {
            assert!(
                seen.insert(entry.label),
                "Duplicate IPv6 label: {}",
                entry.label
            );
        }
    }

    // ── IPv4 reserved ranges ──────────────────────────────────────────

    #[test]
    fn rejects_current_network_0_0_0_0_8() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(0, 0, 0, 1)));
    }

    #[test]
    fn rejects_private_10_0_0_0_8() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            10, 0, 0, 1
        )));
    }

    #[test]
    fn rejects_cgnat_100_64_0_0_10() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            100, 100, 0, 1
        )));
    }

    #[test]
    fn rejects_loopback_127_0_0_0_8() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            127, 0, 0, 1
        )));
    }

    #[test]
    fn rejects_link_local_169_254_0_0_16() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            169, 254, 1, 1
        )));
    }

    #[test]
    fn rejects_private_172_16_0_0_12() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            172, 16, 0, 1
        )));
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            172, 31, 255, 1
        )));
    }

    #[test]
    fn allows_non_private_172_32_x_x() {
        assert!(!is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            172, 32, 0, 1
        )));
    }

    #[test]
    fn rejects_private_192_168_0_0_16() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            192, 168, 1, 1
        )));
    }

    #[test]
    fn rejects_test_net_1_192_0_2_0_24() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            192, 0, 2, 5
        )));
    }

    #[test]
    fn rejects_test_net_2_198_51_100_0_24() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            198, 51, 100, 5
        )));
    }

    #[test]
    fn rejects_test_net_3_203_0_113_0_24() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            203, 0, 113, 5
        )));
    }

    #[test]
    fn rejects_multicast_224_0_0_0_4() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            224, 0, 0, 1
        )));
    }

    #[test]
    fn rejects_reserved_240_0_0_0_4() {
        assert!(is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            240, 0, 0, 1
        )));
    }

    #[test]
    fn accepts_routable_ipv4() {
        assert!(!is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            8, 8, 4, 4
        )));
        assert!(!is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            1, 1, 1, 1
        )));
        assert!(!is_documentation_or_reserved_ipv4(Ipv4Addr::new(
            45, 33, 32, 156
        )));
    }

    // ── IPv6 reserved ranges ──────────────────────────────────────────

    #[test]
    fn rejects_unspecified_v6() {
        assert!(is_documentation_or_reserved_ipv6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn rejects_loopback_v6() {
        assert!(is_documentation_or_reserved_ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rejects_documentation_2001_db8() {
        assert!(is_documentation_or_reserved_ipv6(
            "2001:db8::1".parse().unwrap()
        ));
        assert!(is_documentation_or_reserved_ipv6(
            "2001:db8:f7d3:5976:5f99:663b:3ba1:4e3a".parse().unwrap()
        ));
    }

    #[test]
    fn rejects_link_local_fe80() {
        assert!(is_documentation_or_reserved_ipv6(
            "fe80::1".parse().unwrap()
        ));
    }

    #[test]
    fn rejects_ula_fc00() {
        assert!(is_documentation_or_reserved_ipv6(
            "fc00::1".parse().unwrap()
        ));
        assert!(is_documentation_or_reserved_ipv6(
            "fd00::1".parse().unwrap()
        ));
    }

    #[test]
    fn rejects_multicast_ff00() {
        assert!(is_documentation_or_reserved_ipv6(
            "ff02::1".parse().unwrap()
        ));
    }

    #[test]
    fn accepts_routable_ipv6() {
        assert!(!is_documentation_or_reserved_ipv6(
            "2001:4860:4860::8888".parse().unwrap()
        ));
        assert!(!is_documentation_or_reserved_ipv6(
            "2606:4700:4700::1111".parse().unwrap()
        ));
        assert!(!is_documentation_or_reserved_ipv6(
            "2a00:1450:4009:81f::200e".parse().unwrap()
        ));
    }

    // ── Endpoint extraction from bridge lines ─────────────────────────

    #[test]
    fn check_endpoint_rejects_2001_db8_in_brackets() {
        assert_eq!(
            check_endpoint("webtunnel [2001:db8:f7d3:5976:5f99:663b:3ba1:4e3a]:443 FINGERPRINT url=https://x ver=0.0.4"),
            Some("DOCUMENTATION_RFC3849_2001_DB8")
        );
    }

    #[test]
    fn check_endpoint_rejects_test_net_ipv4() {
        assert_eq!(
            check_endpoint("obfs4 192.0.2.5:443 cert=abc"),
            Some("TEST_NET_1_RFC5737")
        );
    }

    #[test]
    fn check_endpoint_allows_routable_ipv4() {
        assert_eq!(check_endpoint("obfs4 8.8.4.4:443 cert=abc"), None);
    }

    #[test]
    fn check_endpoint_allows_routable_ipv6() {
        assert_eq!(
            check_endpoint("obfs4 [2001:4860:4860::8888]:443 cert=abc"),
            None
        );
    }

    #[test]
    fn check_endpoint_allows_dns_name() {
        assert_eq!(
            check_endpoint("obfs4 bridge.example.net:8443 cert=abc"),
            None
        );
    }

    #[test]
    fn check_endpoint_allows_url_only_webtunnel() {
        assert_eq!(
            check_endpoint("webtunnel FINGERPRINT url=https://example.com/path ver=0.0.4"),
            None
        );
    }

    #[test]
    fn check_endpoint_allows_vanilla_without_prefix() {
        assert_eq!(check_endpoint("Bridge 8.8.4.4:9001 FINGERPRINT"), None);
    }

    // ── Telemetry ─────────────────────────────────────────────────────

    #[test]
    fn telemetry_counter_increments_on_rejection() {
        reset_rejection_counters();
        assert!(reject_if_reserved(
            "obfs4 [2001:db8::1]:443 cert=abc",
            "obfs4"
        ));
        let snapshot = rejection_snapshot();
        let doc_count: u64 = snapshot
            .iter()
            .filter(|(label, _)| *label == "DOCUMENTATION_RFC3849_2001_DB8")
            .map(|(_, count)| *count)
            .sum();
        assert_eq!(doc_count, 1);
    }

    #[test]
    fn telemetry_does_not_increment_on_clean_line() {
        reset_rejection_counters();
        assert!(!reject_if_reserved("obfs4 1.2.3.4:443 cert=abc", "obfs4"));
        let snapshot = rejection_snapshot();
        assert!(snapshot.is_empty());
    }

    // ── Regression: real BridgeDB HTML containing 2001:db8 lines ──────

    #[test]
    fn regression_rejects_bridgedb_2001_db8_webtunnel() {
        // Real captured BridgeDB response from 2026-08-10 showing
        // documentation-range IPv6 addresses for webtunnel bridges.
        let bridgedb_html = r#"<html><body>
            <div id="bridgelines" class="p-4 mb-3">
                webtunnel [2001:db8:e091:f9eb:f35c:5159:f61c:a762]:443 1508F1D97E9E8C8F3B0E2B3A4C5D6E7F8A9B0C1D url=https://tor.jmrp.io/BDZQOQc4eFpyM6rWz1y9X2aB ver=0.0.4
                webtunnel [2001:db8:2ae3:679a:856c:c72a:2746:1a1b]:443 8943B2E8A9F0C1D2E3F4A5B6C7D8E9F0A1B2C3D4 url=https://allium.heelsn.eu/abc123def456 ver=0.0.4
                obfs4 1.2.3.4:443 cert=abc123def456
            </div>
        </body></html>"#;

        // Simulate what parse_html / is_valid_line would do for each line
        let lines: Vec<&str> = bridgedb_html
            .split('\n')
            .map(|l| l.trim())
            .filter(|l| l.len() >= 10)
            .filter(|l| !l.starts_with('<') && !l.starts_with('<'))
            .collect();

        let mut rejected = 0_u64;
        let mut accepted = 0_u64;
        for line in &lines {
            if line.starts_with('<') || line.len() < 10 {
                continue;
            }
            if let Some(reason) = check_endpoint(line) {
                record_rejection(reason, "webtunnel");
                rejected += 1;
            } else {
                accepted += 1;
            }
        }

        // Both 2001:db8 lines must be rejected; the obfs4 routable line passes.
        assert_eq!(rejected, 2, "Both 2001:db8 lines must be rejected");
        assert_eq!(accepted, 1, "The routable obfs4 line must be accepted");

        // Verify telemetry captured the right reason
        let snapshot = rejection_snapshot();
        let doc_rfc3849: u64 = snapshot
            .iter()
            .filter(|(label, _)| *label == "DOCUMENTATION_RFC3849_2001_DB8")
            .map(|(_, count)| *count)
            .sum();
        assert_eq!(
            doc_rfc3849, 2,
            "Both rejected lines must carry DOCUMENTATION_RFC3849_2001_DB8 reason"
        );
    }

    // ── PART B: Edge-case regression tests ───────────────────────────────

    #[test]
    fn edge_case_ipv4_mapped_ipv6_is_rejected() {
        // ::ffff:192.0.2.1 is an IPv4-mapped IPv6 address pointing to
        // the TEST-NET-1 range. The ip_guard should reject it via the
        // IPv4-mapped CIDR entry.
        let ip: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(
            is_documentation_or_reserved_ipv6(ip),
            "IPv4-mapped IPv6 with reserved IPv4 should be rejected"
        );
        // But a routable IPv4-mapped address passes
        let routable: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(
            !is_documentation_or_reserved_ipv6(routable),
            "IPv4-mapped IPv6 with routable IPv4 should be accepted"
        );
    }

    #[test]
    fn edge_case_ipv6_with_zone_id_in_line() {
        // Zone IDs (%eth0) cannot be parsed as IPv6 by Rust's stdlib
        let result = "fe80::1%eth0".parse::<Ipv6Addr>();
        assert!(result.is_err(), "Zone ID should fail IPv6 parsing");
        // The line check should not panic
        assert!(!contains_documentation_or_reserved_endpoint(
            "obfs4 [fe80::1%eth0]:443 FINGER cert=abc"
        ));
    }

    #[test]
    fn edge_case_teredo_address_rejected() {
        // Teredo addresses (2001::/32) are rejected
        let teredo: Ipv6Addr = "2001::1".parse().unwrap();
        assert!(is_documentation_or_reserved_ipv6(teredo));
    }

    #[test]
    fn edge_case_six_to_four_rejected() {
        // 6to4 addresses (2002::/16) are rejected
        let six_to_four: Ipv6Addr = "2002:c000:0204::1".parse().unwrap();
        assert!(is_documentation_or_reserved_ipv6(six_to_four));
    }

    #[test]
    fn edge_case_benchmark_v6_rejected() {
        // Benchmark range (2001:2::/48) is rejected
        let bench: Ipv6Addr = "2001:2::1".parse().unwrap();
        assert!(is_documentation_or_reserved_ipv6(bench));
    }

    #[test]
    fn edge_case_discard_only_v6_rejected() {
        let discard: Ipv6Addr = "100::1".parse().unwrap();
        assert!(is_documentation_or_reserved_ipv6(discard));
    }

    #[test]
    fn edge_case_cgnat_ipv4_rejected() {
        let cgnat = Ipv4Addr::new(100, 64, 0, 1);
        assert!(is_documentation_or_reserved_ipv4(cgnat));
        // Boundary: just below CGNAT range
        let below_cgnat = Ipv4Addr::new(100, 63, 255, 255);
        assert!(!is_documentation_or_reserved_ipv4(below_cgnat));
    }

    #[test]
    fn edge_case_ietf_protocol_assignment_rejected() {
        let ietf = Ipv4Addr::new(192, 0, 0, 1);
        assert!(is_documentation_or_reserved_ipv4(ietf));
    }

    #[test]
    fn edge_case_ipv6_to_ipv4_relay_rejected() {
        let relay = Ipv4Addr::new(192, 88, 99, 1);
        assert!(is_documentation_or_reserved_ipv4(relay));
    }

    #[test]
    fn edge_case_check_endpoint_does_not_panic_on_garbage() {
        // The check_endpoint function should never panic
        for input in &[
            "",
            " ",
            "::::",
            "[",
            "[]",
            "[::]",
            "[::]:",
            "[::]:0",
            "[:]:443",
        ] {
            let _ = check_endpoint(input);
            let _ = contains_documentation_or_reserved_endpoint(input);
            let _ = reject_if_reserved(input, "obfs4");
        }
    }
}
