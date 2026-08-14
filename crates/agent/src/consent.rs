//! Explicit, unskippable volunteer consent.
//!
//! The agent must not send any probe traffic until the volunteer has recorded
//! consent. [`ConsentGate`] is the in-process record of that consent, and the
//! probe engine refuses to run without a [`ConsentToken`] issued from a
//! granted gate. The interactive prompt itself lives in the binary; the
//! parser and the gate live here so both are unit-testable.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::error::AgentError;

/// A durable record of the volunteer's explicit consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRecord {
    /// When consent was recorded.
    pub recorded_at: DateTime<Utc>,
    /// How consent was recorded (`terminal_prompt`, `test`, ...).
    pub method: String,
}

/// Proof that consent has been recorded, issued by a granted [`ConsentGate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentToken {
    /// When the underlying consent was recorded.
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug)]
enum State {
    AwaitingConsent,
    Granted(ConsentRecord),
}

/// The consent gate shared between the server and the probe engine.
#[derive(Debug, Clone)]
pub struct ConsentGate {
    state: Arc<Mutex<State>>,
}

impl ConsentGate {
    /// A gate that starts un-granted: the agent refuses to probe until
    /// [`grant`](Self::grant) is called with the volunteer's explicit consent.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::AwaitingConsent)),
        }
    }

    /// Record consent via `method`. The first grant is authoritative: if
    /// consent was already recorded, the existing record is returned unchanged.
    pub fn grant(&self, method: &str) -> ConsentRecord {
        let mut state = self.lock();
        if let State::Granted(record) = &*state {
            return record.clone();
        }
        let record = ConsentRecord {
            recorded_at: Utc::now(),
            method: method.to_owned(),
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

    /// Issue a [`ConsentToken`] if consent has been recorded, otherwise fail
    /// with [`AgentError::ConsentRequired`].
    pub fn try_token(&self) -> Result<ConsentToken, AgentError> {
        match self.record() {
            Some(record) => Ok(ConsentToken {
                recorded_at: record.recorded_at,
            }),
            None => Err(AgentError::ConsentRequired),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
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

/// Parse one line of consent-screen input. Only an explicit `yes`/`no` is
/// accepted; anything else is an error so the prompt can loop until the
/// volunteer gives an unambiguous answer (the screen is unskippable).
pub fn parse_consent_input(input: &str) -> Result<bool, AgentError> {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        other => Err(AgentError::ConsentInput(format!(
            "unrecognized consent response {other:?} (answer yes or no)"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gate_starts_un_granted() {
        let gate = ConsentGate::new();
        assert!(!gate.is_granted());
        assert!(gate.record().is_none());
        assert_eq!(
            gate.try_token().unwrap_err().kind_name(),
            "consent_required"
        );
    }

    #[test]
    fn grant_records_consent_and_issues_tokens() {
        let gate = ConsentGate::new();
        let record = gate.grant("test");
        assert!(gate.is_granted());
        assert_eq!(record.method, "test");
        let token = gate.try_token().unwrap();
        assert_eq!(token.recorded_at, record.recorded_at);
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
    fn parser_accepts_yes_and_no_variants() {
        for (input, expected) in [
            ("yes", Some(true)),
            ("Y", Some(true)),
            ("  Yes ", Some(true)),
            ("no", Some(false)),
            ("n", Some(false)),
        ] {
            assert_eq!(parse_consent_input(input).ok(), expected, "input {input:?}");
        }
    }

    #[test]
    fn parser_rejects_ambiguous_input() {
        for input in ["", "maybe", "1", "yes please", "   "] {
            assert!(parse_consent_input(input).is_err(), "input {input:?}");
        }
    }
}
