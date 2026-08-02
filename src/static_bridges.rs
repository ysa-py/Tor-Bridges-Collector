//! Parity port of `sources/static_bridges.py`.
//!
//! Official built-in Tor bridges (expanded). These bridges are hardcoded
//! inside Tor Browser and change very rarely. Including them ensures the
//! collector always has working bridges even when external APIs are
//! unreachable (critical during Iranian internet cuts).
//!
//! The four constants below are byte-identical to the Python source — each
//! Python fragment uses parenthesized implicit string concatenation, and
//! the Rust port reproduces the resulting string via `\`-continued string
//! literals (which strip the newline and any leading whitespace on the
//! following line while preserving the trailing space before `\`).
//!
//! Sources:
//! - Tor Browser source: tor-browser/src/app/tor-browser.git (torrc.defaults)
//! - Snowflake broker: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake>
//! - meek: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/meek>

// ─────────────────────────────────────────────────────────────────────────────
// Snowflake — WebRTC + CDN fronting. Extremely hard to block. Best for Iran.
// The 192.0.2.x IPs are documentation placeholders; routing is via broker URL.
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in Snowflake bridge lines. Length: 4.
pub const SNOWFLAKE_BRIDGES: &[&str] = &[
    // Primary — Fastly CDN front (googlevideo.com)
    "snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=ftls.googlevideo.com \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478 \
utls-imitate=hellorandomizedalpn",
    // Secondary — direct torproject.net with Fastly front
    "snowflake 192.0.2.4:1 8838024498816A039FCBBAB14E6F40A0843051FA \
fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA \
url=https://snowflake-broker.torproject.net/ \
fronts=snowflake-broker.torproject.net.global.prod.fastly.net \
ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478 \
utls-imitate=hellorandomizedalpn",
    // AMP CDN — via ampproject.org (Google AMP CDN, harder to block in Iran)
    "snowflake 192.0.2.5:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
fronts=www.gstatic.com \
ice=stun:stun.l.google.com:19302,stun:stun.ekiga.net:3478,stun:stun.ideasip.com:3478,stun:stun.rixtelecom.se:3478,stun:stun.schlund.de:3478,stun:stun.stunprotocol.org:3478 \
utls-imitate=hellorandomizedalphv2",
    // Backup — hellorandomizednoalpn imitation
    "snowflake 192.0.2.6:1 8838024498816A039FCBBAB14E6F40A0843051FA \
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
    "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 \
url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
    // meek-amazon — AWS CloudFront
    "meek_lite 192.0.2.16:80 0AC9589027B0B1F3B1D1D94C63CD9E8D05CD6D77 \
url=https://a0.awsstatic.com/ front=a0.awsstatic.com",
    // meek-azure alternate (CDN endpoint B)
    "meek_lite 192.0.2.19:80 BE776A53492E1E044A26F17306E1BC46A55A1625 \
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
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

/// Return the list of `(bridge_line, transport, ip_version)` tuples for all
/// built-in bridges, in the same order as the Python `get_all()`:
/// snowflake×4, meek_lite×3, obfs4×5 (12 tuples total).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_bridge_count_matches_python() {
        assert_eq!(SNOWFLAKE_BRIDGES.len(), 4);
    }

    #[test]
    fn meek_bridge_count_matches_python() {
        assert_eq!(MEEK_BRIDGES.len(), 3);
    }

    #[test]
    fn obfs4_bridge_count_matches_python() {
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
}
