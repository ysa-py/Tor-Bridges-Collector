//! The consent gate: record consent and issue proofs of it.
//!
//! [`ConsentGate`] is cheap to clone (it shares one `Arc`-backed state), so the
//! same gate can be held by a server and by every protected worker. The only
//! way to obtain a [`ConsentProof`] is [`ConsentGate::require`] on a granted
//! gate — the struct has no public constructor.

use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::ConsentError;

/// A durable record of the volunteer's explicit consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentRecord {
    /// When consent was recorded.
    pub granted_at: DateTime<Utc>,
    /// How consent was recorded (`terminal_prompt`, `test`, ...).
    pub method: String,
}

/// Proof that consent has been recorded, issued by a granted [`ConsentGate`].
///
/// This type has no public constructor: it can only be produced by
/// [`ConsentGate::require`], so holding one *is* evidence of recorded consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentProof {
    /// When the underlying consent was recorded.
    pub granted_at: DateTime<Utc>,
    /// How the underlying consent was recorded.
    pub method: String,
}

impl ConsentProof {
    /// The record this proof vouches for.
    pub fn record(&self) -> ConsentRecord {
        ConsentRecord {
            granted_at: self.granted_at,
            method: self.method.clone(),
        }
    }
}

#[derive(Debug)]
enum State {
    AwaitingConsent,
    Granted(ConsentRecord),
}

/// A thread-safe gate that starts un-granted and must be granted before any
/// protected operation may proceed.
#[derive(Debug, Clone)]
pub struct ConsentGate {
    state: Arc<Mutex<State>>,
}

impl ConsentGate {
    /// A gate that starts un-granted.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::AwaitingConsent)),
        }
    }

    /// Record consent via `method`. The first grant is authoritative: if
    /// consent was already recorded, the existing record is returned unchanged.
    pub fn grant(&self, method: impl Into<String>) -> ConsentRecord {
        let mut state = self.lock();
        if let State::Granted(record) = &*state {
            return record.clone();
        }
        let record = ConsentRecord {
            granted_at: Utc::now(),
            method: method.into(),
        };
        *state = State::Granted(record.clone());
        record
    }

    /// Whether consent has been recorded.
    pub fn is_granted(&self) -> bool {
        matches!(&*self.lock(), State::Granted(_))
    }

    /// The recorded consent, if any.
    pub fn record(&self) -> Option<ConsentRecord> {
        match &*self.lock() {
            State::Granted(record) => Some(record.clone()),
            State::AwaitingConsent => None,
        }
    }

    /// The enforcement point: issue a [`ConsentProof`] only if consent has
    /// been recorded, otherwise fail with [`ConsentError::NotGranted`].
    pub fn require(&self) -> Result<ConsentProof, ConsentError> {
        match self.record() {
            Some(record) => Ok(ConsentProof {
                granted_at: record.granted_at,
                method: record.method,
            }),
            None => Err(ConsentError::NotGranted),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for ConsentGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gate_starts_un_granted_and_requires_fails() {
        let gate = ConsentGate::new();
        assert!(!gate.is_granted());
        assert!(gate.record().is_none());
        assert_eq!(gate.require().unwrap_err(), ConsentError::NotGranted);
    }

    #[test]
    fn grant_records_consent_and_issues_a_matching_proof() {
        let gate = ConsentGate::new();
        let record = gate.grant("terminal_prompt");
        assert!(gate.is_granted());
        assert_eq!(record.method, "terminal_prompt");

        let proof = gate.require().unwrap();
        assert_eq!(proof.granted_at, record.granted_at);
        assert_eq!(proof.method, record.method);
        assert_eq!(proof.record(), record);
    }

    #[test]
    fn first_grant_is_authoritative() {
        let gate = ConsentGate::new();
        let first = gate.grant("first");
        let second = gate.grant("second");
        assert_eq!(first, second);
        assert_eq!(second.method, "first");
    }

    #[test]
    fn clones_share_one_state() {
        let gate = ConsentGate::new();
        let clone = gate.clone();
        clone.grant("clone");
        assert!(gate.is_granted());
        assert_eq!(gate.require().unwrap().method, "clone");
    }

    #[test]
    fn proof_serializes_to_the_consent_record_fields() {
        let gate = ConsentGate::new();
        gate.grant("test");
        let proof = gate.require().unwrap();
        let value = serde_json::to_value(&proof).unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["granted_at", "method"]);
        assert_eq!(object["method"], "test");
    }
}
