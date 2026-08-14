//! The report type this crate aggregates.
//!
//! The batcher is deliberately agnostic to the measurement content: it needs
//! an identifier and a timestamp. The upstream producer (for example
//! `tbc-agent::AnonymizedReport`) maps its own fields into this type
//! (token → `id`, measured timestamp → `recorded_at`); that producer-side
//! `From` adapter is a tracked follow-up.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One measurement report awaiting k-anonymous release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Opaque identifier supplied by the producer (e.g. an unlinkable token).
    pub id: String,
    /// When the measurement was taken.
    pub recorded_at: DateTime<Utc>,
}

impl Report {
    /// Construct a report from producer-supplied parts.
    pub fn new(id: impl Into<String>, recorded_at: DateTime<Utc>) -> Self {
        Self {
            id: id.into(),
            recorded_at,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn report_serde_round_trips() {
        let report = Report::new(
            "r1",
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        );
        let json = serde_json::to_string(&report).unwrap();
        let decoded: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(report, decoded);
        assert_eq!(decoded.id, "r1");
    }
}
