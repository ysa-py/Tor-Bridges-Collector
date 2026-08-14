//! Consent-screen input parsing.
//!
//! Only an explicit `yes`/`no` is accepted; anything else is an error so a
//! prompt can loop until the volunteer gives an unambiguous answer (the screen
//! is unskippable).

use crate::error::ConsentError;

/// Parse one line of consent-screen input.
///
/// Accepted answers (case-insensitive, surrounding whitespace trimmed):
/// `y`/`yes` → `Ok(true)`, `n`/`no` → `Ok(false)`. Every other input returns
/// [`ConsentError::InvalidInput`] so the caller can re-prompt.
pub fn parse_consent_input(input: &str) -> Result<bool, ConsentError> {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        other => Err(ConsentError::InvalidInput(other.to_owned())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_yes_and_no_variants() {
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
    fn rejects_ambiguous_input() {
        for input in ["", "maybe", "1", "yes please", "   ", "yess", "nope"] {
            assert!(parse_consent_input(input).is_err(), "input {input:?}");
        }
    }

    #[test]
    fn error_reports_the_offending_input() {
        let error = parse_consent_input("maybe").unwrap_err();
        assert_eq!(error.kind_name(), "invalid_consent_input");
        assert!(error.to_string().contains("maybe"));
    }
}
