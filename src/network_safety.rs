//! Redacted diagnostics for HTTP client errors.
//!
//! Request URLs can contain credentials, tokens, or signed query parameters.
//! `reqwest::Error` may retain and display the full URL, so never format the
//! original error into logs or propagated error chains. This module deliberately
//! reduces it to a fixed low-cardinality label.

/// Return a fixed, non-sensitive label for an HTTP request failure.
///
/// Do not replace this with `error.to_string()` or `Debug`: reqwest may include
/// sensitive values embedded in the request URL.
pub fn safe_reqwest_error_summary(error: &reqwest::Error) -> &'static str {
    safe_summary_from_flags(
        error.is_timeout(),
        error.is_connect(),
        error.is_body(),
        error.is_decode(),
    )
}

fn safe_summary_from_flags(timeout: bool, connect: bool, body: bool, decode: bool) -> &'static str {
    if timeout {
        "request timed out"
    } else if connect {
        "connection failed"
    } else if body {
        "request or response body transfer failed"
    } else if decode {
        "response decoding failed"
    } else {
        "request failed"
    }
}

#[cfg(test)]
mod tests {
    use super::safe_summary_from_flags;

    #[test]
    fn summaries_are_fixed_and_cover_common_transport_failures() {
        let cases = [
            ((true, false, false, false), "request timed out"),
            ((false, true, false, false), "connection failed"),
            (
                (false, false, true, false),
                "request or response body transfer failed",
            ),
            ((false, false, false, true), "response decoding failed"),
            ((false, false, false, false), "request failed"),
        ];

        for ((timeout, connect, body, decode), expected) in cases {
            let actual = safe_summary_from_flags(timeout, connect, body, decode);
            assert_eq!(actual, expected);
            assert!(!actual.contains("bot"));
            assert!(!actual.contains("secret"));
        }
    }

    #[test]
    fn timeout_takes_precedence_without_exposing_other_error_details() {
        assert_eq!(
            safe_summary_from_flags(true, true, true, true),
            "request timed out"
        );
    }
}
