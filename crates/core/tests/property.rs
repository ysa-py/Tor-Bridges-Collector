//! Property-based tests for bridge-line parsing.
//!
//! The parser must never panic on arbitrary input (a fuzz-style invariant) and
//! must produce a stable canonical key across whitespace/padding differences.

use chrono::Utc;
use proptest::prelude::*;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;

use tbc_core::types::BridgeLine;

fn base64_cert() -> String {
    STANDARD_NO_PAD.encode([0x5au8; 52])
}

fn fingerprint() -> &'static str {
    "0123456789ABCDEF0123456789ABCDEF01234567"
}

fn valid_obfs4_line() -> impl Strategy<Value = String> {
    (1u8..=254u8, 1u16..=65535u16).prop_map(move |(octet, port)| {
        format!(
            "obfs4 {octet}.2.3.4:{port} {} cert={} iat-mode=0",
            fingerprint(),
            base64_cert()
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// `parse` must never panic, regardless of input (including control
    /// characters, unicode, and pathological lengths).
    #[test]
    fn parse_never_panics_on_arbitrary_input(s in any::<String>()) {
        let now = Utc::now();
        let _ = BridgeLine::parse(&s, now);
    }

    /// Whitespace and padding differences never change the canonical dedupe key.
    #[test]
    fn canonical_key_is_whitespace_insensitive(line in valid_obfs4_line()) {
        let now = Utc::now();
        let plain = BridgeLine::parse(&line, now).expect("valid line parses");
        let padded = format!("   Bridge   {line}   ");
        let padded_parsed = BridgeLine::parse(&padded, now).expect("padded line parses");
        prop_assert_eq!(plain.canonical_key(), padded_parsed.canonical_key());
    }
}
