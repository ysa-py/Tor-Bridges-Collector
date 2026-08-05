//! Static bridge production-safety tests.
//!
//! The original parity tests asserted byte identity with the retired Python
//! static bridge module. Production safety now takes precedence: RFC 5737,
//! RFC 3849, and other documentation/reserved endpoints must not enter any
//! runtime/failsafe path.

use torshield_ir_ultra::scraper::contains_documentation_or_reserved_endpoint;
use torshield_ir_ultra::static_bridges::{
    fallback_all, fallback_lines, get_all, CONJURE_BRIDGES, MEEK_AZURE_BRIDGES, MEEK_BRIDGES,
    OBFS4_BRIDGES, SNOWFLAKE_BRIDGES, VANILLA_BRIDGES, WEBTUNNEL_BRIDGES,
};

fn assert_no_placeholder_endpoint(lines: &[&str]) {
    for line in lines {
        assert!(
            !contains_documentation_or_reserved_endpoint(line),
            "static/failsafe line contains documentation or reserved endpoint: {line}"
        );
    }
}

#[test]
fn static_constants_preserve_transport_coverage() {
    assert_eq!(SNOWFLAKE_BRIDGES.len(), 4);
    assert_eq!(MEEK_BRIDGES.len(), 3);
    assert_eq!(OBFS4_BRIDGES.len(), 5);
    assert_eq!(WEBTUNNEL_BRIDGES.len(), 4);
    assert_eq!(VANILLA_BRIDGES.len(), 4);
    assert_eq!(CONJURE_BRIDGES.len(), 1);
    assert_eq!(MEEK_AZURE_BRIDGES.len(), 1);
}

#[test]
fn get_all_preserves_documented_transport_order_without_placeholders() {
    let all = get_all();
    assert_eq!(all.len(), 12);
    for (idx, entry) in all.iter().enumerate() {
        let expected = if idx < 4 {
            "snowflake"
        } else if idx < 7 {
            "meek_lite"
        } else {
            "obfs4"
        };
        assert_eq!(entry.1, expected);
        assert_eq!(entry.2, "ipv4");
        assert!(!contains_documentation_or_reserved_endpoint(entry.0));
    }
}

#[test]
fn fallback_lines_cover_every_published_transport_without_placeholders() {
    for transport in [
        "obfs4",
        "webtunnel",
        "vanilla",
        "snowflake",
        "meek_lite",
        "conjure",
        "meek-azure",
    ] {
        let lines = fallback_lines(transport);
        assert!(!lines.is_empty(), "{transport} has no fallback");
        assert_no_placeholder_endpoint(&lines);
    }
    assert!(fallback_lines("unknown").is_empty());
}

#[test]
fn fallback_all_is_non_empty_deduplicated_and_placeholder_free() {
    let all = fallback_all();
    assert!(!all.is_empty());
    assert_no_placeholder_endpoint(&all);
    let mut seen = std::collections::BTreeSet::new();
    for line in &all {
        assert!(seen.insert(*line), "duplicate line in fallback_all");
    }
}
