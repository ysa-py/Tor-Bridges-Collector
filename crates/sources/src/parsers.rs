//! Bridge-list parsers: newline-delimited text and JSON.
//!
//! Parsing is strict but never silent. Malformed individual lines are
//! collected into [`ParseReport::rejected`] (skip-and-record) rather than
//! failing the whole list, while a body that is not JSON at all when JSON is
//! expected produces a [`SourceError::Parse`].

use chrono::{DateTime, Utc};

use crate::error::SourceError;
use tbc_core::BridgeLine;

/// One line (or JSON candidate) that failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedLine {
    /// 1-based ordinal: the line number for text input, or the candidate
    /// index for JSON input.
    pub ordinal: usize,
    /// The offending raw line.
    pub line: String,
    /// Why it was rejected.
    pub reason: String,
}

/// The outcome of parsing a bridge-list body.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParseReport {
    /// Successfully parsed and validated bridges.
    pub bridges: Vec<BridgeLine>,
    /// Lines that were skipped and recorded, with reasons.
    pub rejected: Vec<RejectedLine>,
}

impl ParseReport {
    /// Merge another report into this one, preserving rejection ordinals by
    /// offsetting them so callers can still locate the source line.
    pub fn extend_offset(&mut self, other: ParseReport, base: usize) {
        self.bridges.extend(other.bridges);
        self.rejected
            .extend(other.rejected.into_iter().map(|mut rejected| {
                rejected.ordinal += base;
                rejected
            }));
    }
}

/// Parse a newline-delimited bridge list.
///
/// Empty lines and `#` comments are ignored (they are formatting, not data).
/// Every other line is parsed with [`BridgeLine::parse`]; failures are
/// recorded, never dropped.
pub fn parse_bridge_text(body: &str, now: DateTime<Utc>) -> ParseReport {
    let mut report = ParseReport::default();
    for (index, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match BridgeLine::parse(line, now) {
            Ok(bridge) => report.bridges.push(bridge),
            Err(error) => report.rejected.push(RejectedLine {
                ordinal: index + 1,
                line: line.to_owned(),
                reason: error.to_string(),
            }),
        }
    }
    report
}

/// Parse a JSON bridge list.
///
/// Accepted shapes (any of the following, or a JSON object wrapping one):
/// * an array of bridge-line strings,
/// * an array of objects each carrying a `bridge`, `line`, or `raw` string
///   field,
/// * an object with a `bridges` array (and/or `bridge`/`line`/`raw` string).
///
/// A syntactically invalid JSON body is a hard [`SourceError::Parse`]; a
/// structurally valid body with bad bridge lines records rejections instead.
pub fn parse_bridge_json(body: &str, now: DateTime<Utc>) -> Result<ParseReport, SourceError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| SourceError::Parse(error.to_string()))?;

    let mut candidates: Vec<String> = Vec::new();
    collect_candidates(&value, &mut candidates);

    let mut report = ParseReport::default();
    for (index, candidate) in candidates.into_iter().enumerate() {
        match BridgeLine::parse(&candidate, now) {
            Ok(bridge) => report.bridges.push(bridge),
            Err(error) => report.rejected.push(RejectedLine {
                ordinal: index + 1,
                line: candidate,
                reason: error.to_string(),
            }),
        }
    }
    Ok(report)
}

/// Recursively extract candidate bridge-line strings from a JSON value.
fn collect_candidates(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_candidates(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            // A direct bridge-line string field wins over nested collections.
            for key in ["bridge", "line", "raw"] {
                if let Some(serde_json::Value::String(line)) = map.get(key) {
                    if !line.trim().is_empty() {
                        out.push(line.clone());
                        return;
                    }
                }
            }
            for key in ["bridges", "data", "results", "bridge_lines"] {
                if let Some(nested) = map.get(key) {
                    collect_candidates(nested, out);
                    return;
                }
            }
        }
        serde_json::Value::String(line) => {
            if !line.trim().is_empty() {
                out.push(line.clone());
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    const VALID_OBFS4: &str =
        "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWg== iat-mode=0";

    #[test]
    fn text_parser_skips_comments_and_records_rejections() {
        let body = format!("# a comment\n{VALID_OBFS4}\n\nthis is not a bridge at all\n");
        let report = parse_bridge_text(&body, now());
        assert_eq!(report.bridges.len(), 1);
        assert_eq!(report.bridges[0].transport.to_string(), "obfs4");
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].ordinal, 4);
    }

    #[test]
    fn json_array_of_strings() {
        let body = format!("[\"{VALID_OBFS4}\", \"not a bridge\"]");
        let report = parse_bridge_json(&body, now()).unwrap();
        assert_eq!(report.bridges.len(), 1);
        assert_eq!(report.rejected.len(), 1);
    }

    #[test]
    fn json_array_of_objects_and_nested_collections() {
        let body =
            format!("{{\"bridges\": [{{\"line\": \"{VALID_OBFS4}\"}}, {{\"raw\": \"nope\"}}]}}");
        let report = parse_bridge_json(&body, now()).unwrap();
        assert_eq!(report.bridges.len(), 1);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].line, "nope");
    }

    #[test]
    fn invalid_json_body_is_a_hard_error() {
        assert!(matches!(
            parse_bridge_json("{not json", now()),
            Err(SourceError::Parse(_))
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Text parsing is total; JSON parsing must return Err, not panic.
        let _ = parse_bridge_text("garbage \u{0} bytes \u{1}", now());
        let _ = parse_bridge_json("garbage \u{0} bytes \u{1}", now());
    }

    proptest! {
        #[test]
        fn text_parser_never_panics_on_arbitrary_input(s in any::<String>()) {
            let _ = parse_bridge_text(&s, now());
        }

        #[test]
        fn json_parser_never_panics_on_arbitrary_input(s in any::<String>()) {
            let _ = parse_bridge_json(&s, now());
        }
    }
}
