#![allow(warnings)]
// Deterministic loopback integration tests for the Session 9 `smart-detection`
// warfare layer (directive §4). These run ONLY under `--features
// smart-detection`; the whole file compiles to nothing otherwise, so the
// default test matrix is unaffected.
//
// Directive §4.2 asks for "deterministic loopback integration testing for
// each variant" of `InterferenceKind`. Rather than depend on real egress
// (which this sandbox black-holes — see `src/iran_detector.rs`'s module doc),
// each variant is driven through the injectable `ProbeResult` telemetry seam,
// the same pattern the baseline parity suite uses with local `TcpListener`s.
// One end-to-end case additionally exercises a real loopback `TcpListener` to
// prove the seam matches an actual observed TCP outcome.
//
// Feature-gating lives in the top-level entrypoint `tests/
// iran_detector_smart_detection.rs` (a crate-root `#![cfg(...)]`), because an
// inner attribute is illegal inside an `include!`d file.

use std::net::TcpListener;
use std::time::Duration;

use torshield_ir_ultra::iran_detector::smart::{
    compute_confidence, recommend_strategy_adaptive, BridgeHealthSnapshot, InterferenceKind,
    ProbeOutcome, ProbeResult, Transport,
};

fn r(intl: bool, group: u8, outcome: ProbeOutcome) -> ProbeResult {
    ProbeResult::new(
        "anchor",
        443,
        intl,
        group,
        outcome,
        Duration::from_millis(1),
    )
}

fn uniform_health() -> BridgeHealthSnapshot {
    BridgeHealthSnapshot {
        snowflake: 0.5,
        domain_fronted_webtunnel: 0.5,
        ech: 0.5,
        webtunnel: 0.5,
        obfs4: 0.5,
        vanilla: 0.5,
    }
}

#[test]
fn variant_none_when_international_reachable() {
    let a = compute_confidence(&[r(true, 1, ProbeOutcome::Ok)]);
    assert_eq!(a.interference, InterferenceKind::None);
    assert!(a.international_ok);
}

#[test]
fn variant_timeout() {
    let a = compute_confidence(&[
        r(true, 1, ProbeOutcome::Timeout),
        r(true, 2, ProbeOutcome::Timeout),
    ]);
    assert_eq!(a.interference, InterferenceKind::Timeout);
}

#[test]
fn variant_active_reset() {
    let a = compute_confidence(&[r(true, 1, ProbeOutcome::Refused)]);
    assert_eq!(a.interference, InterferenceKind::ActiveReset);
}

#[test]
fn variant_dns_interference() {
    let a = compute_confidence(&[r(true, 1, ProbeOutcome::DnsFailure)]);
    assert_eq!(a.interference, InterferenceKind::DnsInterference);
}

#[test]
fn variant_tls_handshake_fail_isolates_sni_blocking() {
    let a = compute_confidence(&[r(true, 1, ProbeOutcome::TlsHandshakeFail)]);
    assert_eq!(a.interference, InterferenceKind::TlsHandshakeFail);
    // SNI-based selective blocking must route toward CDN-fronted / ECH transports.
    let rec = recommend_strategy_adaptive(&a, &uniform_health());
    let pos = |t: Transport| rec.ranked.iter().position(|&x| x == t).unwrap();
    assert!(pos(Transport::Ech) < pos(Transport::Obfs4));
    assert!(pos(Transport::DomainFrontedWebTunnel) < pos(Transport::Vanilla));
}

#[test]
fn variant_mixed() {
    let a = compute_confidence(&[
        r(true, 1, ProbeOutcome::Timeout),
        r(true, 2, ProbeOutcome::Refused),
        r(true, 3, ProbeOutcome::DnsFailure),
    ]);
    assert_eq!(a.interference, InterferenceKind::Mixed);
}

/// End-to-end sanity: a real loopback listener yields an `Ok` TCP outcome that,
/// fed through the telemetry seam, classifies as `None` interference — proving
/// the seam is consistent with an actual observed connection, not a fiction.
#[test]
fn loopback_reachable_listener_classifies_as_no_interference() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        // Accept exactly one connection then return.
        let _ = listener.accept();
    });
    // Observe a real TCP connect outcome against the live listener.
    let outcome = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => ProbeOutcome::Ok,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => ProbeOutcome::Timeout,
        Err(_) => ProbeOutcome::Refused,
    };
    let _ = handle.join();
    assert_eq!(outcome, ProbeOutcome::Ok);
    let a = compute_confidence(&[ProbeResult::new(
        "127.0.0.1",
        addr.port(),
        true,
        1,
        outcome,
        Duration::from_millis(1),
    )]);
    assert_eq!(a.interference, InterferenceKind::None);
    assert!(a.international_ok);
}
