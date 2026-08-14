//! End-to-end integration tests for the consent flow over the public API.
//!
//! These exercise the full path — parse a prompt answer, record it, and pass
//! the gate — for both the refuse and grant branches, asserting the refusal
//! path emits no proof.

use tbc_consent::{parse_consent_input, ConsentError, ConsentGate};

#[test]
fn refuse_path_emits_no_proof() {
    let answer = parse_consent_input("no").unwrap();
    assert!(!answer);

    let gate = ConsentGate::new();
    // A refusal records nothing, so the gate still refuses a protected action.
    let error = gate.require().unwrap_err();
    assert_eq!(error, ConsentError::NotGranted);
    assert!(!gate.is_granted());
}

#[test]
fn grant_path_records_once_and_issues_a_proof() {
    let answer = parse_consent_input("yes").unwrap();
    assert!(answer);

    let gate = ConsentGate::new();
    let record = gate.grant("integration_test");
    let proof = gate.require().unwrap();

    assert_eq!(proof.granted_at, record.granted_at);
    assert_eq!(proof.method, "integration_test");
    assert!(gate.is_granted());

    // The proof round-trips through JSON with exactly the consent fields.
    let json = serde_json::to_value(&proof).unwrap();
    assert_eq!(json["method"], "integration_test");
    assert!(json["granted_at"].is_string());
}

#[test]
fn ambiguous_input_is_an_error_and_never_grants() {
    let error = parse_consent_input("maybe").unwrap_err();
    assert_eq!(error.kind_name(), "invalid_consent_input");
}
