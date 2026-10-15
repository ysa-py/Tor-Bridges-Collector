//! Parity port of `sources/static_bridges.py`.
//!
//! Official built-in Tor bridges. These are the lines Tor Browser itself
//! ships; they are refreshed from the MOAT `circumvention/builtin` API (the
//! same endpoint the collector's Stage 3 polls). Including them ensures the
//! collector always has bridges even when external APIs are unreachable
//! (critical during Iranian internet cuts).
//!
//! Broker/front transports (snowflake, meek*, conjure) carry IETF
//! documentation-range endpoint placeholders BY PROTOCOL DESIGN — BridgeDB
//! ships `meek_lite 192.0.2.20:80 url=…` and `snowflake 192.0.2.3:80 …` in
//! Tor Browser's own defaults, and the client dials the `url=`/`front=`
//! rendezvous, never the placeholder. Such lines are publishable whenever
//! their rendezvous validates (`ip_guard::publication_blocks_endpoint`); no
//! endpoint may ever be fabricated for a line that lacks one.
//!
//! Beyond the static constants, this module also provides static
//! fallback lines for published transports whose bundled entries are complete
//! client bridge lines (vanilla, snowflake, obfs4, conjure, and meek variants)
//! via [`fallback_lines`] and [`fallback_all`]. URL-only WebTunnel metadata is
//! retained for reference but is never emitted as a client bridge fallback.
//!
//! Sources (refreshed 2026-10-15 against the live MOAT builtin response):
//! - Tor Browser source: tor-browser/src/app/tor-browser.git (torrc.defaults)
//! - MOAT builtin: <https://bridges.torproject.org/moat/circumvention/builtin>
//! - Snowflake broker: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake>
//! - meek: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/meek>
//! - WebTunnel: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel>
//! - Conjure: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure>

// ─────────────────────────────────────────────────────────────────────────────
// Snowflake — WebRTC + CDN fronting. Extremely hard to block. Best for Iran.
// The first two lines are the CURRENT Tor defaults (CDN77 rendezvous,
// datapacket fronts, refreshed from MOAT builtin 2026-10-15); the
// documentation-range endpoint placeholders are the protocol form Tor Browser
// itself ships. The Fastly-broker variants remain valid secondary
// rendezvous points.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in Snowflake bridge lines. Length: 4.
pub const SNOWFLAKE_BRIDGES: &[&str] = &[
    // Current Tor default #1 — CDN77 rendezvous, datapacket fronts
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://1098762253.rsc.cdn77.org/ \
fronts=app.datapacket.com,www.datapacket.com \
ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 \
utls-imitate=hellorandomizedalpn",
    // Current Tor default #2 — same rendezvous, second fingerprint
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://1098762253.rsc.cdn77.org/ \
fronts=app.datapacket.com,www.datapacket.com \
ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 \
utls-imitate=hellorandomizedalpn",
    // Secondary — direct broker over Fastly (rendezvous still live)
    "snowflake 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=ftls.googlevideo.com \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478 \
utls-imitate=hellorandomizedalpn",
    // Backup — direct broker, no-ALPN imitation
    "snowflake 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://snowflake-broker.torproject.net/ \
fronts=snowflake-broker.torproject.net.global.prod.fastly.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478 \
utls-imitate=hellorandomizednoalpn",
];

// ─────────────────────────────────────────────────────────────────────────────
// meek-lite — CDN domain fronting. Traffic appears as ordinary CDN traffic.
// meek.azureedge.net / az668014.vo.msecnd.net are RETIRED (DNS removed,
// verified 2026-10-15); the current Tor default is the CDN77 rendezvous
// below (MOAT builtin, country=ir).
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in meek-lite bridge lines. Length: 1.
pub const MEEK_BRIDGES: &[&str] = &[
    // Current Tor default — CDN77 rendezvous (azure retired 2024/2025)
    "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org \
front=www.phpmyadmin.net utls=HelloRandomizedALPN",
];

// ─────────────────────────────────────────────────────────────────────────────
// obfs4 — the current Tor built-in obfs4 set, refreshed from the MOAT
// builtin API (country=ir, 2026-10-15). The MOAT response lists the
// 209.148.46.65 line twice; it is deduplicated here. The MOAT API always
// provides fresher obfs4 bridges.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in obfs4 bridge lines. Length: 6.
pub const OBFS4_BRIDGES: &[&str] = &[
    "obfs4 51.222.13.177:80 \
5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 \
cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew \
iat-mode=0",
    "obfs4 209.148.46.65:443 \
74FAD13168806246602538555B5521A0383A1875 \
cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw \
iat-mode=0",
    "obfs4 212.83.43.74:443 \
39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 \
cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw \
iat-mode=1",
    "obfs4 212.83.43.95:443 \
BFE712113A72899AD685764B211FACD30FF52C31 \
cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg \
iat-mode=1",
    "obfs4 45.145.95.6:27015 \
C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C \
cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw \
iat-mode=0",
    "obfs4 146.57.248.225:22 \
10A6CD36A537FCE513A322361547444B393989F0 \
cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw \
iat-mode=0",
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
// meek-azure — the meek family's current CDN77 rendezvous (the azure
// endpoints are retired; see the meek-lite section). Same line as
// `onionhop_collector::fronted_meek_azure`.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in meek-azure bridge lines. Length: 1.
pub const MEEK_AZURE_BRIDGES: &[&str] = &["meek_lite 192.0.2.20:80 \
url=https://1603026938.rsc.cdn77.org \
front=www.phpmyadmin.net utls=HelloRandomizedALPN"];

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
/// WebTunnel metadata is excluded. The meek-azure family mirrors the single
/// current meek_lite rendezvous line by design, so duplicate lines are
/// dropped here to keep aggregate files duplicate-free.
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
        for line in fallback_lines(transport) {
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
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
    fn meek_bridge_count_matches_current_tor_defaults() {
        // The azure endpoints are retired (DNS removed 2024/2025); the
        // current Tor default set is the single CDN77 rendezvous line.
        assert_eq!(MEEK_BRIDGES.len(), 1);
        assert!(MEEK_BRIDGES[0].contains("1603026938.rsc.cdn77.org"));
        assert!(!fallback_lines("meek_lite")
            .iter()
            .any(|line| line.contains("azureedge")));
    }

    #[test]
    fn obfs4_bridge_count_matches_current_tor_defaults() {
        assert_eq!(OBFS4_BRIDGES.len(), 6);
    }

    #[test]
    fn get_all_returns_tuples_in_documented_order() {
        let all = get_all();
        assert_eq!(all.len(), 4 + MEEK_BRIDGES.len() + OBFS4_BRIDGES.len());
        for entry in &all[0..4] {
            assert_eq!(entry.1, "snowflake");
            assert_eq!(entry.2, "ipv4");
        }
        for entry in &all[4..4 + MEEK_BRIDGES.len()] {
            assert_eq!(entry.1, "meek_lite");
            assert_eq!(entry.2, "ipv4");
        }
        for entry in &all[4 + MEEK_BRIDGES.len()..] {
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
