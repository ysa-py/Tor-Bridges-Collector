//! Regression tests for the `idna_adapter` pin (`Cargo.toml`, workspace
//! dependency `reqwest`, which pulls in `idna` → `idna_adapter`).
//! This sandbox's rustc is fixed at 1.75.0 with no available upgrade path
//! (only rustc 1.75.0 is offered via `apt` in this Ubuntu 24.04
//! environment; `rustup`'s distribution domain isn't in this sandbox's
//! network egress allowlist — confirmed, not assumed, before deciding to
//! pin instead). `idna_adapter` is pinned to `1.2.0`, which resolves
//! against the older `icu4x` 1.5.x generation rather than the current
//! 2.x line (2.x's MSRV is 1.81-1.86 depending on the specific crate;
//! see the chain of pins in `Cargo.toml` and `MIGRATION_NOTES.md`'s
//! entry on this). `1.2.0` is still the ICU4X backend stream (full
//! UTS46/Unicode correctness) — not the `1.1.x` (unicode-rs, lower
//! fidelity) or `1.0.x` (stub, no real IDNA processing at all) streams.
//!
//! Moving to an older generation of the *same* backend should preserve
//! correct behavior, but "should" isn't evidence — these three cases are
//! checked directly against this exact pinned configuration:
//!
//! 1. A valid non-ASCII (IDN) domain normalizes to its correct Punycode
//!    form.
//! 2. The Punycode-encoded form of that same domain round-trips
//!    consistently.
//! 3. A deliberately confusable/homograph domain (Cyrillic "а" U+0430
//!    substituted for Latin "a" in "apple.com") does **not** normalize to
//!    the same string as the real domain — i.e. a client comparing
//!    resolved hostnames against a known-good value cannot be fooled by
//!    the substitution. Worth being precise about what this does and
//!    doesn't claim: `idna`/`url` do UTS46 `ToASCII` processing, not full
//!    Unicode Technical Standard #39 confusables-skeleton detection
//!    (that's a separate, higher-level anti-phishing feature browsers
//!    implement on top of basic URL parsing, not something a URL-parsing
//!    library does or is expected to do). What *is* being verified here —
//!    and *is* the property that actually matters for any code in this
//!    codebase comparing a parsed host against an allowlist — is that the
//!    Cyrillic substitution produces a completely different Punycode
//!    string, not that the library flags it as suspicious.
//!
//! All three checked here with `reqwest::Url::parse` (`reqwest`
//! re-exports the `url` crate's `Url` type — this exercises the exact
//! same `idna_adapter`-backed code path `endpoint_validator.rs` and
//! `scraper.rs` use for any host they parse), against the real, pinned
//! `Cargo.lock` state, not a fresh/unpinned resolution.
#![cfg(feature = "network")]

#[test]
fn non_ascii_idn_domain_normalizes_to_correct_punycode() {
    let url = reqwest::Url::parse("https://münchen.de/path").expect("must parse");
    assert_eq!(url.host_str(), Some("xn--mnchen-3ya.de"));
}

#[test]
fn punycode_domain_round_trips_consistently() {
    let url = reqwest::Url::parse("https://xn--mnchen-3ya.de/path").expect("must parse");
    assert_eq!(url.host_str(), Some("xn--mnchen-3ya.de"));

    // Both forms of the same real-world domain must resolve to the
    // identical host string, or comparing a Punycode input against a
    // Unicode-typed one elsewhere in this codebase would silently break.
    let unicode_form = reqwest::Url::parse("https://münchen.de/path").expect("must parse");
    assert_eq!(url.host_str(), unicode_form.host_str());
}

#[test]
fn cyrillic_homograph_does_not_collide_with_the_real_ascii_domain() {
    // U+0430 CYRILLIC SMALL LETTER A in place of U+0061 LATIN SMALL
    // LETTER A — visually near-identical, a classic homograph substitution.
    let spoofed = reqwest::Url::parse("https://\u{0430}pple.com/path").expect("must parse");
    let real = reqwest::Url::parse("https://apple.com/path").expect("must parse");

    assert_ne!(
        spoofed.host_str(),
        real.host_str(),
        "a Cyrillic-substituted domain must not resolve to the same host \
         string as the real ASCII domain — if this ever fails, any \
         hostname-allowlist check anywhere in this codebase would be \
         bypassable by homograph substitution"
    );
    // Pinned to the exact current value so a silent behavior change in a
    // future dependency bump is caught rather than passing this test by
    // coincidence forever.
    assert_eq!(spoofed.host_str(), Some("xn--pple-43d.com"));
    assert_eq!(real.host_str(), Some("apple.com"));
}
