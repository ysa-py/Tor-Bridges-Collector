//! Redacted diagnostics for HTTP client errors.
//!
//! Request URLs can contain credentials, tokens, or signed query parameters.
//! `reqwest::Error` may retain and display the full URL, so never format the
//! original error into logs or propagated error chains. URL diagnostics should
//! retain at most the origin; request-error summaries are fixed low-cardinality
//! labels.

/// Return only the origin of a URL, excluding userinfo, path, query, and fragment.
/// Invalid URLs collapse to a fixed label rather than being echoed into logs.
#[must_use]
pub fn safe_url_origin(value: &str) -> String {
    url::Url::parse(value)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| "invalid URL".to_string())
}

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
    use super::{safe_summary_from_flags, safe_url_origin};

    #[test]
    fn url_origin_hides_credentials_paths_queries_and_fragments() {
        let label = safe_url_origin(
            "https://alice:sample-secret@example.invalid:8443/private/path?token=sample-token#frag",
        );
        assert_eq!(label, "https://example.invalid:8443");
        assert!(!label.contains("alice"));
        assert!(!label.contains("sample-secret"));
        assert!(!label.contains("sample-token"));
        assert!(!label.contains("private"));

        assert_eq!(
            safe_url_origin("https://[2001:db8::1]:8443/private?token=sample-token"),
            "https://[2001:db8::1]:8443"
        );
        assert_eq!(
            safe_url_origin("not a valid URL with sample-secret"),
            "invalid URL"
        );
    }

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
