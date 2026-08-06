//! Parity port of `sources/static_bridges.py`.
//!
//! Official built-in Tor bridges (expanded). These bridges are hardcoded
//! inside Tor Browser and change very rarely. Including them ensures the
//! collector always has working bridges even when external APIs are
//! unreachable (critical during Iranian internet cuts).
//!
//! Documentation-range endpoint placeholders have been removed from every
//! production/static data path; fronted transports keep only their legitimate
//! broker/front metadata and are not counted as direct IP bridges.
//!
//! Beyond the sanitized static constants, this module also provides static
//! fallback lines for published transports whose bundled entries are complete
//! client bridge lines (vanilla, snowflake, obfs4, conjure, and meek variants)
//! via [`fallback_lines`] and [`fallback_all`]. URL-only WebTunnel metadata is
//! retained for reference but is never emitted as a client bridge fallback.
//!
//! Sources:
//! - Tor Browser source: tor-browser/src/app/tor-browser.git (torrc.defaults)
//! - Snowflake broker: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake>
//! - meek: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/meek>
//! - WebTunnel: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel>
//! - Conjure: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure>

// ─────────────────────────────────────────────────────────────────────────────
// Snowflake — WebRTC + CDN fronting. Extremely hard to block. Best for Iran.
// Direct TEST-NET endpoints were purged; routing is via broker/front metadata.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in Snowflake bridge lines. Length: 4.
pub const SNOWFLAKE_BRIDGES: &[&str] = &[
    // Primary — Fastly CDN front (googlevideo.com)
    "snowflake 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=ftls.googlevideo.com \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478 \
utls-imitate=hellorandomizedalpn",
    // Secondary — direct torproject.net with Fastly front
    "snowflake 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://snowflake-broker.torproject.net/ \
fronts=snowflake-broker.torproject.net.global.prod.fastly.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478 \
utls-imitate=hellorandomizedalpn",
    // AMP CDN — via ampproject.org (Google AMP CDN, harder to block in Iran)
    "snowflake 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=www.gstatic.com \
ice=stun:stun.l.google.com:19302,stun:stun.ekiga.net:3478,stun:stun.ideasip.com:3478,stun:stun.rixtelecom.se:3478,stun:stun.schlund.de:3478,stun:stun.stunprotocol.org:3478 \
utls-imitate=hellorandomizedalphv2",
    // Backup — hellorandomizednoalpn imitation
    "snowflake 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://snowflake-broker.torproject.net/ \
fronts=snowflake-broker.torproject.net.global.prod.fastly.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478 \
utls-imitate=hellorandomizednoalpn",
];

// ─────────────────────────────────────────────────────────────────────────────
// meek-lite — CDN domain fronting. Traffic appears as Azure/AWS, not Tor.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in meek-lite bridge lines. Length: 3.
pub const MEEK_BRIDGES: &[&str] = &[
    // meek-azure — Microsoft Azure CDN (very high availability)
    "meek_lite BE776A53492E1E044A26F17306E1BC46A55A1625 \
url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
    // meek-amazon — AWS CloudFront
    "meek_lite 0AC9589027B0B1F3B1D1D94C63CD9E8D05CD6D77 \
url=https://a0.awsstatic.com/ front=a0.awsstatic.com",
    // meek-azure alternate (CDN endpoint B)
    "meek_lite BE776A53492E1E044A26F17306E1BC46A55A1625 \
url=https://meek.azureedge.net/ front=cloudflightcdn.azureedge.net",
];

// ─────────────────────────────────────────────────────────────────────────────
// obfs4 — Public well-known bridges from official Tor documentation.
// NOTE: These are FROM the official Tor Project bridge pool public
// documentation. They may rotate; the MOAT API always provides fresher obfs4
// bridges.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in obfs4 bridge lines. Length: 5.
pub const OBFS4_BRIDGES: &[&str] = &[
    // From Tor Project's official bridge distributor (publicly documented)
    "obfs4 193.11.166.194:27025 \
1AE2C08904527FEA90C4307C2A428523CF4DFED2 \
cert=IYmSp4TQw7V87kQOPhwOGCHGEuNwMaS0IW0OEuYZVXslGcWCMI1Kes/GzJYKGR/5QQIZXQ \
iat-mode=2",
    "obfs4 193.11.166.194:27067 \
1AE2C08904527FEA90C4307C2A428523CF4DFED2 \
cert=cCbNa6Y1UrN9lGtKR3N0MhF5H62gU1VBIoJcNRHuInkBgMmJh5j0bECEMmjHgfSJUdRJqw \
iat-mode=2",
    "obfs4 37.218.245.14:38224 \
D9A82D2F9C2F65A18407B1D2B764F130847F8B5D \
cert=L4N/KQa4TQ24v0Q0VPKWG1Qq2ZXGQAB2OAhKj0f6YnEo1A99oPIFpLv1dMKiQAbHtFhXog \
iat-mode=2",
    "obfs4 89.163.212.153:15000 \
A30B2B9F02AEE22D1F26D0D73C4B61DB6C5F84AA \
cert=Dq5X8Ap5MJIO3sPbEG8vZONOvHUFIEJGN5oOpnAWKpMqXNDWjmhJCkNRmMDgj0H7a/MiFQ \
iat-mode=2",
    "obfs4 146.57.248.225:22 \
10A6CD36A537FCE513A322E120CD05179CE93655 \
cert=K1gDtDAIcUfeLqbstggjIos/FsSYZ2h24CNQpDjEs62Tm4bFDIoE9+X/mhzOt5Jsvg \
iat-mode=2",
];

// ─────────────────────────────────────────────────────────────────────────────
// webtunnel — TLS-in-TLS over HTTP/2 CDN fronting. Excellent for Iran.
// Lines below mirror the public WebTunnel bridge pool format
// `webtunnel <ip>:<port> <fingerprint> url=<registration URL> ver=<version>`.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in WebTunnel bridge lines (public pool, IPv6-first). Length: 4.
pub const WEBTUNNEL_BRIDGES: &[&str] = &[
    "webtunnel \
DF343521735ABE129910A998817B3A93AA2390FE \
url=https://coellen.xyz ver=0.0.3",
    "webtunnel \
68674E54A17AEB1C9ADE878BBBB46C6975DD3105 \
url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4",
    "webtunnel \
96E16DE2F8DA38060D93A554DC56C90A681F6FE4 \
url=https://jochenkessler.de/D82XI88Vz3nttmFEc9OBXGRD ver=0.0.3",
    "webtunnel \
88C9B6F63D50B63FC5E1DE2F5423FCDA2C0AC5EB \
url=https://vault.005184.xyz/e3QD38jnqsG3jzcfa8NA6ar9 ver=0.0.3",
];

// ─────────────────────────────────────────────────────────────────────────────
// vanilla — plain Tor bridges (`ip:port fingerprint`). Stored WITHOUT the
// `Bridge ` prefix: every `.txt` writer strips that prefix on output, so the
// fallback table uses the same convention as `normalize_for_file`.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in vanilla bridge lines. Length: 4.
pub const VANILLA_BRIDGES: &[&str] = &[
    "102.212.98.168:9393 B2CF966100CA013C4456643C98092B6FEBA3A304",
    "103.149.168.242:9443 91637DE9ED5B069722DA7A5796926EE13238694D",
    "107.173.164.249:50604 74DE4100C63CA34626E21C593C1A265793D69E76",
    "107.189.3.186:22512 5ABFC5405EAFD091BCAF4D9E4318D1FC52D531B9",
];

// ─────────────────────────────────────────────────────────────────────────────
// conjure — domain-fronted registration transport (Refraction Networking).
// Same line as `onionhop_collector::fronted_conjure`.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in conjure bridge lines. Length: 1.
pub const CONJURE_BRIDGES: &[&str] = &["conjure 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://registration.refraction.network/api \
fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min"];

// ─────────────────────────────────────────────────────────────────────────────
// meek-azure — Azure CDN domain fronting. Same line as
// `onionhop_collector::fronted_meek_azure`.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in meek-azure bridge lines. Length: 1.
pub const MEEK_AZURE_BRIDGES: &[&str] = &["meek_lite 97700DFE9F483596DDA6264C4D7DF7641E1E39CE \
url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"];

// ─────────────────────────────────────────────────────────────────────────────
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

/// Return the list of `(bridge_line, transport, ip_version)` tuples for all
/// built-in bridges in stable transport order:
/// snowflake×4, meek_lite×3, obfs4×5 (12 tuples total).
///
/// This function intentionally excludes documentation/reserved endpoints; the
/// transport families added for the publication FAILSAFE live in
/// [`fallback_lines`] / [`fallback_all`].
pub fn get_all() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut results: Vec<(&'static str, &'static str, &'static str)> = Vec::new();
    for line in SNOWFLAKE_BRIDGES {
        results.push((line, "snowflake", "ipv4"));
    }
    for line in MEEK_BRIDGES {
        results.push((line, "meek_lite", "ipv4"));
    }
    for line in OBFS4_BRIDGES {
        results.push((line, "obfs4", "ipv4"));
    }
    results
}

/// Static fallback lines for a single transport family.
///
/// Used by the exporter (`bridge_publication`) and the FAILSAFE when live
/// collection/probing produces no candidates. Returns only complete client
/// bridge lines; URL-only WebTunnel metadata intentionally yields an empty
/// vector until a source supplies a literal endpoint. Unknown transports also
/// return an empty vector.
pub fn fallback_lines(transport: &str) -> Vec<&'static str> {
    match transport {
        "snowflake" => SNOWFLAKE_BRIDGES.to_vec(),
        "meek_lite" => MEEK_BRIDGES.to_vec(),
        "obfs4" => OBFS4_BRIDGES.to_vec(),
        // The bundled WebTunnel metadata is URL-only and therefore cannot be
        // emitted as a client bridge line: no endpoint may be fabricated.
        // Return no fallback until a source supplies a literal IP:PORT or
        // [IPv6]:PORT record.
        "webtunnel" => Vec::new(),
        "vanilla" => VANILLA_BRIDGES.to_vec(),
        "conjure" => CONJURE_BRIDGES.to_vec(),
        "meek-azure" => MEEK_AZURE_BRIDGES.to_vec(),
        _ => Vec::new(),
    }
}

/// Static fallback lines across supported transports, in a fixed order, used
/// for aggregate files such as `iran_likely_working_all.txt`. URL-only
/// WebTunnel metadata is excluded.
pub fn fallback_all() -> Vec<&'static str> {
    let mut lines = Vec::new();
    for transport in [
        "obfs4",
        "webtunnel",
        "vanilla",
        "snowflake",
        "meek_lite",
        "conjure",
        "meek-azure",
    ] {
        lines.extend(fallback_lines(transport));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_bridge_count_preserved() {
        assert_eq!(SNOWFLAKE_BRIDGES.len(), 4);
    }

    #[test]
    fn meek_bridge_count_preserved() {
        assert_eq!(MEEK_BRIDGES.len(), 3);
    }

    #[test]
    fn obfs4_bridge_count_preserved() {
        assert_eq!(OBFS4_BRIDGES.len(), 5);
    }

    #[test]
    fn get_all_returns_twelve_tuples_in_documented_order() {
        let all = get_all();
        assert_eq!(all.len(), 12);
        for entry in &all[0..4] {
            assert_eq!(entry.1, "snowflake");
            assert_eq!(entry.2, "ipv4");
        }
        for entry in &all[4..7] {
            assert_eq!(entry.1, "meek_lite");
            assert_eq!(entry.2, "ipv4");
        }
        for entry in &all[7..12] {
            assert_eq!(entry.1, "obfs4");
            assert_eq!(entry.2, "ipv4");
        }
    }

    #[test]
    fn webtunnel_and_vanilla_constants_are_non_empty() {
        assert_eq!(WEBTUNNEL_BRIDGES.len(), 4);
        assert_eq!(VANILLA_BRIDGES.len(), 4);
        assert_eq!(CONJURE_BRIDGES.len(), 1);
        assert_eq!(MEEK_AZURE_BRIDGES.len(), 1);
    }

    #[test]
    fn fallback_lines_cover_every_published_transport() {
        for transport in [
            "obfs4",
            "vanilla",
            "snowflake",
            "meek_lite",
            "conjure",
            "meek-azure",
        ] {
            assert!(
                !fallback_lines(transport).is_empty(),
                "{transport} has no fallback"
            );
        }
        assert!(fallback_lines("unknown").is_empty());
    }

    #[test]
    fn fallback_all_is_non_empty_and_has_no_duplicates() {
        let all = fallback_all();
        assert!(!all.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for line in &all {
            assert!(seen.insert(*line), "duplicate line in fallback_all");
        }
    }
}
