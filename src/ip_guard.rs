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
        m.insert(URL_HOST_RESERVED_NAME, AtomicU64::new(0));
        m.insert(URL_HOST_MALFORMED, AtomicU64::new(0));
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

/// Reason labels for URL-host validation on URL-addressed transports.
pub const URL_HOST_RESERVED_NAME: &str = "URL_HOST_RESERVED_NAME";
pub const URL_HOST_MALFORMED: &str = "URL_HOST_MALFORMED";

/// Host suffixes reserved for local, testing, or non-public name resolution.
/// Deliberately include the standards-defined special-use names and common
/// private-network suffixes; this is a denylist, not a TLD allowlist.
const NON_PUBLIC_HOST_SUFFIXES: &[&str] = &[
    ".localhost",
    ".local",
    ".localdomain",
    ".test",
    ".invalid",
    ".example",
    ".home.arpa",
    ".onion",
    ".alt",
    ".lan",
    ".internal",
    ".intranet",
    ".corp",
    ".private",
    ".home",
];

/// Validate a URL-addressed dial target. Returns a reason when malformed or
/// non-public; public domain names and globally routable IP literals pass.
fn check_url_host(raw_url: &str) -> Option<&'static str> {
    let raw_url = raw_url.trim_matches(|c| matches!(c, '"' | '\'' | ',' | ';'));
    let parsed = match url::Url::parse(raw_url) {
        Ok(parsed) => parsed,
        Err(_) => return Some(URL_HOST_MALFORMED),
    };

    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port() == Some(0)
    {
        return Some(URL_HOST_MALFORMED);
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => check_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => check_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(host)) => {
            if is_non_public_hostname(host) {
                Some(URL_HOST_RESERVED_NAME)
            } else if !is_valid_dns_hostname(host) {
                Some(URL_HOST_MALFORMED)
            } else {
                None
            }
        }
        None => Some(URL_HOST_MALFORMED),
    }
}

/// Validate one or more comma-separated front host names. Front fields in Tor
/// bridge lines commonly contain DNS names rather than complete URLs.
fn check_front_hosts(raw_fronts: &str) -> Option<&'static str> {
    let raw_fronts = raw_fronts.trim_matches(|c| matches!(c, '"' | '\''));
    if raw_fronts.is_empty() {
        return Some(URL_HOST_MALFORMED);
    }
    for front in raw_fronts.split(',') {
        let front = front.trim();
        if front.is_empty() {
            return Some(URL_HOST_MALFORMED);
        }
        let candidate = if front.starts_with("https://") || front.starts_with("http://") {
            front.to_string()
        } else {
            format!("https://{front}/")
        };
        if let Some(reason) = check_url_host(&candidate) {
            return Some(reason);
        }
    }
    None
}

fn is_valid_dns_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn is_non_public_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.is_empty()
        || !host.contains('.')
        || NON_PUBLIC_HOST_SUFFIXES
            .iter()
            .any(|suffix| host == suffix.trim_start_matches('.') || host.ends_with(suffix))
}

/// Scan a bridge line for literal reserved IP endpoints.
///
/// This is deliberately a raw-endpoint classifier rather than an ingestion
/// decision. Analytics use it to identify placeholder addresses even when a
/// URL-fronted transport has a valid public dial target.
#[must_use]
pub fn contains_documentation_or_reserved_endpoint(line: &str) -> bool {
    check_endpoint(line).is_some()
}

/// Like contains_documentation_or_reserved_endpoint but returns the reason
/// label so callers can record telemetry.
#[must_use]
pub fn check_endpoint(line: &str) -> Option<&'static str> {
    let tokens = bridge_tokens(line);
    check_endpoint_tokens(&tokens, None)
}

/// Validate a bridge line for ingestion.
///
/// Validate a bridge line for ingestion.
///
/// Some URL-fronted transports encode the dial target in url= while their
/// endpoint token is a documentation-only placeholder. Only literal IETF
/// documentation ranges (RFC 3849 and RFC 5737 TEST-NETs) may be ignored,
/// and only when a supported fronted transport has a separately validated
/// public HTTP(S) URL. Private, loopback, link-local, and other reserved
/// endpoint literals remain rejected. The raw check_endpoint API remains
/// unchanged for telemetry and analysis.
#[must_use]
pub fn check_ingestion_endpoint(line: &str) -> Option<&'static str> {
    let tokens = bridge_tokens(line);
    if tokens.is_empty() {
        return None;
    }

    let is_fronted_transport = canonical_fronted_transport(tokens[0]).is_some();
    let mut has_validated_url = false;

    for raw_token in &tokens {
        let Some((key, value)) = raw_token.split_once('=') else {
            continue;
        };
        if key.eq_ignore_ascii_case("url") {
            if let Some(reason) = check_url_host(value) {
                return Some(reason);
            }
            has_validated_url = true;
        } else if is_fronted_transport
            && (key.eq_ignore_ascii_case("front") || key.eq_ignore_ascii_case("fronts"))
        {
            if let Some(reason) = check_front_hosts(value) {
                return Some(reason);
            }
        }
    }

    let ignored_placeholder_index =
        if is_fronted_transport && has_validated_url {
            first_documentation_placeholder_index(&tokens)
        } else {
            None
        };
    check_endpoint_tokens(&tokens, ignored_placeholder_index)
}

/// Locate one literal address in an IETF documentation-only range. These
/// addresses can never be actual public bridge endpoints, so URL-fronted
/// transports may keep them as metadata when their independent URL is valid.
fn first_documentation_placeholder_index(tokens: &[&str]) -> Option<usize> {
    for (index, raw_token) in tokens.iter().enumerate().skip(1) {
        let token = raw_token.trim_matches(|c: char| matches!(c, ',' | ';' | '"' | '\''));
        if token.contains('=') {
            continue;
        }

        if let Some(rest) = token.strip_prefix('[') {
            let Some((host, _port)) = rest.split_once("]:") else {
                continue;
            };
            let Ok(ip) = host.parse::<Ipv6Addr>() else {
                continue;
            };
            if check_ip(IpAddr::V6(ip)) == Some("DOCUMENTATION_RFC3849_2001_DB8") {
                return Some(index);
            }
            continue;
        }

        let Some((host, _port)) = token.rsplit_once(':') else {
            continue;
        };
        let Ok(ip) = host.parse::<Ipv4Addr>() else {
            continue;
        };
        if matches!(
            check_ip(IpAddr::V4(ip)),
            Some("TEST_NET_1_RFC5737" | "TEST_NET_2_RFC5737" | "TEST_NET_3_RFC5737")
        ) {
            return Some(index);
        }
    }
    None
}

/// Remove Tor's optional vanilla Bridge prefix before classifying fields.
fn bridge_tokens(line: &str) -> Vec<&str> {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens
        .first()
        .is_some_and(|token| token.eq_ignore_ascii_case("Bridge"))
    {
        tokens.remove(0);
    }
    tokens
}

/// Scan tokens for literal IPv4/IPv6 endpoints. If supplied, ignored_index
/// identifies exactly one URL-front placeholder slot; every other address
/// token is still checked.
fn check_endpoint_tokens(tokens: &[&str], ignored_index: Option<usize>) -> Option<&'static str> {
    for (index, raw_token) in tokens.iter().enumerate() {
        if ignored_index == Some(index) {
            continue;
        }

        let token = raw_token.trim_matches(|c: char| matches!(c, ',' | ';' | '"' | '\''));
        if token.is_empty() || token.contains('=') {
            continue;
        }
        if token.starts_with("http://") || token.starts_with("https://") {
            continue;
        }

        // Inspect bracketed IPv6 independent of port validity. Address safety
        // and bridge-line port syntax are separate validation gates.
        if let Some(rest) = token.strip_prefix('[') {
            if let Some((host, _port_text)) = rest.split_once("]:") {
                if let Ok(ip) = host.parse::<Ipv6Addr>() {
                    if let Some(reason) = check_ip(IpAddr::V6(ip)) {
                        return Some(reason);
                    }
                }
            }
            continue;
        }

        // Also inspect IPv4 literals when the port is malformed. A bad port
        // must never make a reserved address evade the guard.
        if let Some((host, _port_text)) = token.rsplit_once(':') {
            if !host.is_empty() && !host.contains(':') {
                if let Ok(ip) = host.parse::<Ipv4Addr>() {
                    if let Some(reason) = check_ip(IpAddr::V4(ip)) {
                        return Some(reason);
                    }
                }
            }
        }
    }
    None
}

fn canonical_fronted_transport(token: &str) -> Option<&'static str> {
    match token.to_ascii_lowercase().as_str() {
        "webtunnel" | "web-tunnel" | "snowflake" | "meek" | "meek_lite" | "meek-lite"
        | "meek-azure" | "meek_azure" | "conjure" => Some("fronted"),
        _ => None,
    }
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
    fn cidr_v4_table_starts_with_this_network() {
        assert_eq!(RESERVED_CIDR_V4[0].label, "CURRENT_NETWORK_RFC1122");
    }

    #[test]
    fn cidr_v6_table_starts_with_unspecified() {
        assert_eq!(RESERVED_CIDR_V6[0].label, "UNSPECIFIED");
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
    fn raw_check_keeps_webtunnel_placeholder_classification_with_valid_url() {
        let line = "webtunnel [2001:db8:f7d3:5976:5f99:663b:3ba1:4e3a]:443 FINGERPRINT url=https://example.com/path ver=0.0.4";
        assert_eq!(check_endpoint(line), Some("DOCUMENTATION_RFC3849_2001_DB8"));
        assert_eq!(check_ingestion_endpoint(line), None);
    }

    #[test]
    fn ingestion_rejects_reserved_url_host() {
        assert_eq!(
            check_ingestion_endpoint(
                "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://bridge.local/path"
            ),
            Some(URL_HOST_RESERVED_NAME)
        );
    }

    #[test]
    fn ingestion_rejects_malformed_url_and_bad_dns_name() {
        assert_eq!(
            check_ingestion_endpoint("webtunnel [2001:db8::1]:443 FINGERPRINT url=not-a-url"),
            Some(URL_HOST_MALFORMED)
        );
        assert_eq!(
            check_ingestion_endpoint(
                "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://bad..example.com/path"
            ),
            Some(URL_HOST_MALFORMED)
        );
    }

    #[test]
    fn ingestion_rejects_private_ip_in_url_host() {
        assert_eq!(
            check_ingestion_endpoint(
                "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://192.168.1.5/path"
            ),
            Some("PRIVATE_RFC1918_192")
        );
    }

    #[test]
    fn ingestion_rejects_url_port_zero() {
        assert_eq!(
            check_ingestion_endpoint(
                "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://front.example.com:0/path"
            ),
            Some(URL_HOST_MALFORMED)
        );
    }

    #[test]
    fn ingestion_rejects_placeholder_without_url_or_front() {
        assert_eq!(
            check_ingestion_endpoint("webtunnel [2001:db8::1]:443 FINGERPRINT ver=0.0.4"),
            Some("DOCUMENTATION_RFC3849_2001_DB8")
        );
    }

    #[test]
    fn ingestion_rejects_reserved_front_host() {
        assert_eq!(
            check_ingestion_endpoint("snowflake 192.0.2.1:1 FINGERPRINT fronts=bridge.local"),
            Some(URL_HOST_RESERVED_NAME)
        );
    }

    #[test]
    fn ingestion_allows_public_front_hosts_with_routable_endpoint() {
        assert_eq!(
            check_ingestion_endpoint(
                "snowflake 8.8.8.8:443 FINGERPRINT fronts=cdn.sstatic.net,ajax.aspnetcdn.com"
            ),
            None
        );
    }

    #[test]
    fn ingestion_allows_documentation_placeholders_only_for_fronted_transports() {
        assert_eq!(
            check_ingestion_endpoint(
                "snowflake 192.0.2.1:1 FINGERPRINT url=https://example.com/broker fronts=cdn.sstatic.net"
            ),
            None
        );
        assert_eq!(
            check_ingestion_endpoint(
                "meek_lite 198.51.100.11:80 url=https://example.com/ front=example.com"
            ),
            None
        );
        assert_eq!(
            check_ingestion_endpoint(
                "obfs4 198.51.100.11:80 FINGERPRINT url=https://example.com/"
            ),
            Some("TEST_NET_2_RFC5737")
        );
        assert_eq!(
            check_ingestion_endpoint(
                "snowflake 192.168.1.1:443 FINGERPRINT url=https://example.com/ fronts=cdn.sstatic.net"
            ),
            Some("PRIVATE_RFC1918_192")
        );
    }

    #[test]
    fn ingestion_recognizes_fronted_transport_aliases() {
        let webtunnel =
            "web-tunnel [2001:db8::1]:443 FINGERPRINT url=https://front.example.com/path";
        assert_eq!(check_ingestion_endpoint(webtunnel), None);
        assert_eq!(
            check_endpoint(webtunnel),
            Some("DOCUMENTATION_RFC3849_2001_DB8"),
            "raw classifier must retain the WebTunnel placeholder classification"
        );

        let meek = "meek_azure 8.8.8.8:443 FINGERPRINT url=https://front.example.com/path";
        assert_eq!(check_ingestion_endpoint(meek), None);
        assert_eq!(check_endpoint(meek), None);
    }

    #[test]
    fn raw_check_rejects_reserved_ipv6_even_with_invalid_port() {
        for port in ["0", "65536", "not-a-port"] {
            let line = format!("obfs4 [2001:db8::1]:{port} FINGERPRINT cert=abc");
            assert_eq!(
                check_endpoint(&line),
                Some("DOCUMENTATION_RFC3849_2001_DB8"),
                "port={port}"
            );
        }
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

    // ── Regression: BridgeDB URL-fronted WebTunnel placeholders ──────

    #[test]
    fn regression_preserves_raw_placeholder_classification_but_accepts_valid_fronted_lines() {
        let bridgedb_html = r#"<html><body>
            <div id="bridgelines" class="p-4 mb-3">
                webtunnel [2001:db8:e091:f9eb:f35c:5159:f61c:a762]:443 1508F1D97E9E8C8F3B0E2B3A4C5D6E7F8A9B0C1D url=https://tor.jmrp.io/BDZQOQc4eFpyM6rWz1y9X2aB ver=0.0.4
                webtunnel [2001:db8:2ae3:679a:856c:c72a:2746:1a1b]:443 8943B2E8A9F0C1D2E3F4A5B6C7D8E9F0A1B2C3D4 url=https://allium.heelsn.eu/abc123def456 ver=0.0.4
                obfs4 1.2.3.4:443 cert=abc123def456
            </div>
        </body></html>"#;

        let lines: Vec<&str> = bridgedb_html
            .split('\n')
            .map(str::trim)
            .filter(|line| line.len() >= 10 && !line.starts_with('<'))
            .collect();

        let mut rejected_for_ingestion = 0_u64;
        let mut accepted_for_ingestion = 0_u64;
        let mut raw_doc_placeholders = 0_u64;
        for line in &lines {
            if check_endpoint(line) == Some("DOCUMENTATION_RFC3849_2001_DB8") {
                raw_doc_placeholders += 1;
            }
            if check_ingestion_endpoint(line).is_some() {
                rejected_for_ingestion += 1;
            } else {
                accepted_for_ingestion += 1;
            }
        }

        assert_eq!(
            raw_doc_placeholders, 2,
            "raw endpoint classification must retain the two RFC 3849 placeholder labels"
        );
        assert_eq!(
            rejected_for_ingestion, 0,
            "public URL hosts should validate despite RFC 3849 placeholder addresses"
        );
        assert_eq!(
            accepted_for_ingestion, 3,
            "both WebTunnel entries and the routable obfs4 line should pass"
        );
    }

    // ── PART B: Edge-case regression tests ───────────────────────────────

    #[test]
    fn edge_case_ipv4_mapped_ipv6_is_rejected() {
        // The entire ::ffff:0:0/96 (IPv4-mapped IPv6) range is reserved
        // per RFC 4291. Even if the mapped IPv4 address is routable
        // (e.g., 8.8.8.8), the IPv6 representation is not a real
        // routable IPv6 endpoint — it's an encoding convention.
        // ip_guard correctly rejects every address in this range.
        let test_net: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(
            is_documentation_or_reserved_ipv6(test_net),
            "IPv4-mapped IPv6 with reserved IPv4 should be rejected"
        );
        let routable_mapped: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(
            is_documentation_or_reserved_ipv6(routable_mapped),
            "IPv4-mapped IPv6 is always reserved regardless of mapped IPv4 — per ::ffff:0:0/96 CIDR entry"
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
            "", " ", "::::", "[", "[]", "[::]", "[::]:", "[::]:0", "[:]:443",
        ] {
            let _ = check_endpoint(input);
            let _ = contains_documentation_or_reserved_endpoint(input);
            let _ = reject_if_reserved(input, "obfs4");
        }
    }
}
