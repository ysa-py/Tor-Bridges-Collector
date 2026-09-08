//! Community mirror expansion source (additive, separately toggleable).
//!
//! This module adds one NEW bridge-source family without touching any
//! existing source code path: additional public community mirror
//! repositories on GitHub that publish curated `bridge/<transport>.txt`
//! projections through the GitHub contents API (`api.github.com`), the same
//! distribution channel the existing `scripts/refresh_bridge_seed.sh` uses
//! for its single built-in mirror.
//!
//! # Safety contract (identical gates to the core pipeline)
//!
//! Every line fetched from a mirror must pass BOTH of the existing
//! validation gates before it is ever considered a candidate:
//!
//! 1. [`crate::scraper::is_valid_line`] — the format gate every scraper
//!    source already applies (minimum length, comment/marker rejection,
//!    endpoint-regex match);
//! 2. [`crate::ip_guard::contains_documentation_or_reserved_endpoint`] —
//!    the shared non-routable endpoint guard (RFC 3849 documentation
//!    ranges, RFC 5737 TEST-NETs, loopback, RFC 1918, link-local, …).
//!
//! # Toggle semantics (advisory first)
//!
//! * `COMMUNITY_MIRRORS` — space-separated `owner/repo` list. The literal
//!   value `none` (or `0`) disables the module entirely. Default:
//!   [`DEFAULT_COMMUNITY_MIRRORS`].
//! * `COMMUNITY_MIRRORS_MERGE` — when `false` (default) the module is a
//!   pure advisory pass: it fetches, validates, and REPORTS per-mirror
//!   yield (`fetched / valid / rejected_placeholder / new / duplicate`) to
//!   `data/community_mirrors_report.json` and GitHub Actions notices, but
//!   never writes `bridge_history.json`. Setting it to `true` additionally
//!   merges validated lines through the canonical
//!   [`crate::scraper::merge_raw_into_history`] path (the exact merge the
//!   seed script performs).
//!
//! Publication is never changed by this module: merged lines still have to
//! survive the downstream probe/quality gates before anything is published.
//!
//! # Evaluated and deliberately NOT enabled
//!
//! * `scriptzteam/Tor-Bridges-Collector` — publishes `bridges-obfs4` etc.,
//!   but a live sample (2026-09-08) contains synthetic/non-routable
//!   endpoints such as `obfs4 1.0.0.1:9100 …` and `obfs4 1.1.1.1:9100 …`
//!   (Cloudflare DNS) with rotating fingerprints. The ip_guard would drop
//!   them, but the source itself is treated as untrusted and is not wired
//!   into any default list.
//! * `spicicpein/tor-bridges-feed` — reachable, but `bridges.json` was
//!   empty (`"bridges": []`) when evaluated on 2026-09-08; zero expected
//!   yield, so it is not in the default list either.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

use crate::scraper::{contains_documentation_or_reserved_endpoint, is_valid_line, HttpFetch};

/// Default mirror list: one additional, actively-maintained public mirror
/// with the same `bridge/<file>.txt` layout this repository publishes
/// (verified 2026-09-08 via the GitHub contents API; see the module docs
/// for the evaluation notes on rejected candidates).
pub const DEFAULT_COMMUNITY_MIRRORS: &[&str] = &["center2055/OnionHop-Bridges-Collector"];

/// Transport projections fetched from each mirror. Mirrors that do not
/// publish a file are skipped non-fatally (HTTP 404 is an expected,
/// non-error outcome for optional families).
pub const MIRROR_TRANSPORT_FILES: &[(&str, &str)] = &[
    ("obfs4.txt", "obfs4"),
    ("obfs4_ipv6.txt", "obfs4"),
    ("vanilla.txt", "vanilla"),
    ("vanilla_ipv6.txt", "vanilla"),
    ("webtunnel.txt", "webtunnel"),
    ("webtunnel_ipv6.txt", "webtunnel"),
    ("snowflake.txt", "snowflake"),
    ("snowflake_ipv6.txt", "snowflake"),
    ("meek.txt", "meek_lite"),
    ("meek-azure.txt", "meek_lite"),
    ("conjure.txt", "conjure"),
];

/// Diagnostics report written by every run (new file; nothing existing is
/// overwritten).
pub const REPORT_FILE: &str = "data/community_mirrors_report.json";

/// One mirror file fetch outcome, reported verbatim in the JSON report.
#[derive(Debug, Clone, Default)]
pub struct MirrorFileOutcome {
    /// File name inside the mirror's `bridge/` directory.
    pub file: String,
    /// Transport family the file belongs to.
    pub transport: String,
    /// HTTP status of the raw fetch (0 = request error, 404 = absent file).
    pub status: u16,
    /// Non-empty lines received (before validation).
    pub fetched_lines: usize,
    /// Lines passing the full validation gate (format + ip_guard).
    pub valid_lines: usize,
    /// Lines rejected by the non-routable endpoint guard.
    pub rejected_placeholder: usize,
    /// Lines rejected by the format gate only.
    pub rejected_format: usize,
    /// Validated `(bridge_line, ip_version)` pairs from this file.
    pub lines: Vec<(String, String)>,
}

impl MirrorFileOutcome {
    /// Serializable form used in the report.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "file": self.file,
            "transport": self.transport,
            "http_status": self.status,
            "fetched_lines": self.fetched_lines,
            "valid_lines": self.valid_lines,
            "rejected_placeholder_range": self.rejected_placeholder,
            "rejected_format": self.rejected_format,
        })
    }
}

/// Aggregate outcome for one mirror repository.
#[derive(Debug, Clone, Default)]
pub struct MirrorOutcome {
    /// `owner/repo` of the mirror.
    pub repo: String,
    /// Per-file outcomes in deterministic order.
    pub files: Vec<MirrorFileOutcome>,
    /// Validated `(bridge_line, transport, ip_version)` tuples ready for the
    /// canonical history merge.
    pub lines: Vec<(String, String, String)>,
}

impl MirrorOutcome {
    /// Serializable form used in the report.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let fetched: usize = self.files.iter().map(|f| f.fetched_lines).sum();
        let valid: usize = self.files.iter().map(|f| f.valid_lines).sum();
        let placeholder: usize = self.files.iter().map(|f| f.rejected_placeholder).sum();
        let rejected_format: usize = self.files.iter().map(|f| f.rejected_format).sum();
        json!({
            "repo": self.repo,
            "files_fetched_ok": self.files.iter().filter(|f| f.status == 200).count(),
            "files_absent_404": self.files.iter().filter(|f| f.status == 404).count(),
            "fetched_lines": fetched,
            "valid_lines": valid,
            "rejected_placeholder_range": placeholder,
            "rejected_format": rejected_format,
            "files": self.files.iter().map(MirrorFileOutcome::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Parse a raw `COMMUNITY_MIRRORS` value into a mirror list. Empty input
/// yields the default list; the literal `none`/`0` disables the module.
#[must_use]
pub fn mirrors_from_value(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_COMMUNITY_MIRRORS
            .iter()
            .map(|mirror| (*mirror).to_string())
            .collect();
    }
    if trimmed.eq_ignore_ascii_case("none") || trimmed == "0" {
        return Vec::new();
    }
    trimmed
        .split_whitespace()
        .map(str::to_string)
        .filter(|repo| repo.contains('/') && !repo.starts_with('-'))
        .collect()
}

/// Resolve the mirror list from the environment (empty/unset = defaults).
#[must_use]
pub fn mirrors_from_env() -> Vec<String> {
    mirrors_from_value(&std::env::var("COMMUNITY_MIRRORS").unwrap_or_default())
}

/// Parse a raw toggle value into the merge decision (default `false` =
/// advisory only).
#[must_use]
pub fn merge_enabled_from_value(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Whether the merge mode is enabled (default `false` = advisory only).
#[must_use]
pub fn merge_enabled_from_env() -> bool {
    merge_enabled_from_value(std::env::var("COMMUNITY_MIRRORS_MERGE").ok().as_deref())
}

/// Build the raw-content URL for one mirror file.
#[must_use]
pub fn mirror_file_url(repo: &str, file: &str) -> String {
    format!("https://api.github.com/repos/{repo}/contents/bridge/{file}")
}

/// Infer the transport family from the leading token of a bridge line.
#[must_use]
pub fn infer_transport_token(line: &str) -> &'static str {
    match line.split_whitespace().next().unwrap_or("") {
        "obfs4" => "obfs4",
        "webtunnel" => "webtunnel",
        "snowflake" => "snowflake",
        "conjure" => "conjure",
        "meek" | "meek_lite" | "meek-azure" => "meek_lite",
        _ => "vanilla",
    }
}

/// Fetch one mirror file and validate every line through the full existing
/// gate chain. Non-2xx responses are recorded, not fatal: 404 means the
/// mirror does not publish that family.
pub fn fetch_mirror_file(
    client: &dyn HttpFetch,
    repo: &str,
    file: &str,
    transport: &str,
) -> MirrorFileOutcome {
    let url = mirror_file_url(repo, file);
    let mut outcome = MirrorFileOutcome {
        file: file.to_string(),
        transport: transport.to_string(),
        ..MirrorFileOutcome::default()
    };
    let response = client.get_with_headers(
        &url,
        &[(
            "Accept".to_string(),
            "application/vnd.github.raw".to_string(),
        )],
        Duration::from_secs(30),
    );
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(repo = %repo, file = %file, %error, "community mirror fetch failed");
            return outcome;
        }
    };
    outcome.status = response.status;
    if !(200..300).contains(&response.status) {
        // 404 is an expected outcome for optional families; anything else is
        // logged but never fatal for the stage.
        if response.status != 404 {
            tracing::warn!(
                repo = %repo,
                file = %file,
                status = response.status,
                "community mirror returned a non-success status"
            );
        }
        return outcome;
    }
    let file_is_ipv6 = file.ends_with("_ipv6.txt");
    for raw in response.text.lines() {
        let clean = raw.trim();
        if clean.is_empty() {
            continue;
        }
        outcome.fetched_lines += 1;
        if contains_documentation_or_reserved_endpoint(clean) {
            outcome.rejected_placeholder += 1;
            continue;
        }
        if !is_valid_line(clean) {
            outcome.rejected_format += 1;
            continue;
        }
        outcome.valid_lines += 1;
        let ip_version = if clean.contains('[') || file_is_ipv6 {
            "ipv6"
        } else {
            "ipv4"
        };
        outcome
            .lines
            .push((clean.to_string(), ip_version.to_string()));
    }
    outcome
}

/// Fetch every configured transport file from one mirror and collect the
/// validated lines.
pub fn fetch_mirror(client: &dyn HttpFetch, repo: &str) -> MirrorOutcome {
    let mut outcome = MirrorOutcome {
        repo: repo.to_string(),
        ..MirrorOutcome::default()
    };
    for (file, transport) in MIRROR_TRANSPORT_FILES {
        let file_outcome = fetch_mirror_file(client, repo, file, transport);
        for (line, ip_version) in &file_outcome.lines {
            outcome
                .lines
                .push((line.clone(), (*transport).to_string(), ip_version.clone()));
        }
        outcome.files.push(file_outcome);
    }
    outcome
}

/// Count how many validated mirror lines are absent from the history, per
/// transport family (mirrors `supply_extension::count_added_lines`
/// semantics without modifying it).
#[must_use]
pub fn count_new_lines(
    history: &Value,
    lines: &[(String, String, String)],
) -> BTreeMap<String, usize> {
    use crate::scraper::normalize_for_history;
    let mut added: BTreeMap<String, usize> = BTreeMap::new();
    let Some(object) = history.as_object() else {
        return added;
    };
    let mut seen = std::collections::BTreeSet::new();
    for (line, transport, _ip_version) in lines {
        let key = normalize_for_history(line, transport);
        if !seen.insert(key.clone()) {
            continue;
        }
        if !object.contains_key(&key) {
            *added.entry(transport.clone()).or_insert(0) += 1;
        }
    }
    added
}

/// Build the full report payload for a set of mirror outcomes.
#[must_use]
pub fn build_report(
    outcomes: &[MirrorOutcome],
    merge_enabled: bool,
    added: &BTreeMap<String, usize>,
) -> Value {
    json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "module": "community_mirrors",
        "advisory_only": !merge_enabled,
        "merge_enabled": merge_enabled,
        "gates_applied": [
            "scraper::is_valid_line (format gate)",
            "ip_guard::contains_documentation_or_reserved_endpoint (non-routable endpoint guard)",
        ],
        "mirrors": outcomes.iter().map(MirrorOutcome::to_json).collect::<Vec<_>>(),
        "added_by_family_when_merged": added,
        "note": "Advisory mode reports mirror yield without touching bridge_history.json; set COMMUNITY_MIRRORS_MERGE=true to merge validated lines through the canonical history path.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scraper::HttpResponse;

    #[test]
    fn mirrors_from_value_defaults_and_disables() {
        assert_eq!(
            mirrors_from_value(""),
            vec!["center2055/OnionHop-Bridges-Collector"]
        );
        assert!(mirrors_from_value("none").is_empty());
        assert!(mirrors_from_value("0").is_empty());
        assert_eq!(mirrors_from_value("a/b c/d"), vec!["a/b", "c/d"]);
        // Malformed entries without an owner/repo slash are dropped.
        assert!(mirrors_from_value("not-a-repo").is_empty());
    }

    #[test]
    fn merge_enabled_defaults_to_advisory_only() {
        assert!(!merge_enabled_from_value(None));
        assert!(!merge_enabled_from_value(Some("false")));
        assert!(merge_enabled_from_value(Some("true")));
        assert!(merge_enabled_from_value(Some("1")));
        assert!(merge_enabled_from_value(Some("ON")));
    }

    #[test]
    fn transport_inference_covers_all_families() {
        assert_eq!(infer_transport_token("obfs4 1.2.3.4:443 x"), "obfs4");
        assert_eq!(
            infer_transport_token("webtunnel 1.2.3.4:443 x"),
            "webtunnel"
        );
        assert_eq!(infer_transport_token("snowflake x"), "snowflake");
        assert_eq!(infer_transport_token("conjure x"), "conjure");
        assert_eq!(infer_transport_token("meek_lite 1.2.3.4:80 x"), "meek_lite");
        assert_eq!(infer_transport_token("1.2.3.4:443 FINGER"), "vanilla");
    }

    #[test]
    fn count_new_lines_uses_normalized_history_keys() {
        let history = serde_json::json!({
            "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc": {
                "raw": "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc",
                "transport": "obfs4"
            }
        });
        let lines = vec![
            (
                "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc".to_string(),
                "obfs4".to_string(),
                "ipv4".to_string(),
            ),
            (
                "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc".to_string(),
                "obfs4".to_string(),
                "ipv4".to_string(),
            ),
        ];
        let added = count_new_lines(&history, &lines);
        assert_eq!(added.get("obfs4"), Some(&1));
    }

    struct MockFetch {
        status: u16,
        body: String,
    }

    impl HttpFetch for MockFetch {
        fn get(
            &self,
            _url: &str,
            _timeout: Duration,
        ) -> Result<HttpResponse, crate::scraper::ScraperError> {
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                text: self.body.clone(),
            })
        }

        fn post_json(
            &self,
            _url: &str,
            _body: &Value,
            _headers: &[(String, String)],
            _timeout: Duration,
        ) -> Result<HttpResponse, crate::scraper::ScraperError> {
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                text: self.body.clone(),
            })
        }
    }

    #[test]
    fn fetch_mirror_file_counts_validation_outcomes() {
        let body = "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0\n\
                    webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://front.example.com/x ver=0.0.4\n\
                    # comment line that is long enough to matter here\n\
                    short\n";
        let client = MockFetch {
            status: 200,
            body: body.to_string(),
        };
        let outcome = fetch_mirror_file(&client, "a/b", "obfs4.txt", "obfs4");
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.fetched_lines, 4);
        assert_eq!(outcome.valid_lines, 1);
        assert_eq!(outcome.rejected_placeholder, 1);
        assert_eq!(outcome.rejected_format, 2);
        assert_eq!(outcome.lines.len(), 1);
        assert_eq!(outcome.lines[0].1, "ipv4");
    }

    #[test]
    fn fetch_mirror_file_marks_ipv6_from_line_or_filename() {
        let client = MockFetch {
            status: 200,
            body:
                "obfs4 [2001:470:1234::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc\n"
                    .to_string(),
        };
        let outcome = fetch_mirror_file(&client, "a/b", "obfs4_ipv6.txt", "obfs4");
        assert_eq!(outcome.valid_lines, 1);
        assert_eq!(outcome.lines[0].1, "ipv6");
    }

    #[test]
    fn fetch_mirror_file_treats_404_as_absent() {
        let client = MockFetch {
            status: 404,
            body: String::new(),
        };
        let outcome = fetch_mirror_file(&client, "a/b", "conjure.txt", "conjure");
        assert_eq!(outcome.status, 404);
        assert_eq!(outcome.fetched_lines, 0);
        assert_eq!(outcome.valid_lines, 0);
    }

    #[test]
    fn report_is_serializable_and_advisory_by_default() {
        let outcome = MirrorOutcome {
            repo: "a/b".to_string(),
            files: vec![MirrorFileOutcome {
                file: "obfs4.txt".to_string(),
                transport: "obfs4".to_string(),
                status: 200,
                fetched_lines: 3,
                valid_lines: 2,
                rejected_placeholder: 1,
                rejected_format: 0,
                lines: Vec::new(),
            }],
            lines: Vec::new(),
        };
        let report = build_report(&[outcome], false, &BTreeMap::new());
        assert_eq!(report["advisory_only"], true);
        assert_eq!(report["merge_enabled"], false);
        assert_eq!(report["mirrors"][0]["valid_lines"], 2);
        assert!(report["note"].as_str().is_some_and(|n| !n.is_empty()));
    }
}
