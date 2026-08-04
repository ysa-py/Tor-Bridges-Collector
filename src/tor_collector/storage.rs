//! Durable bridge history with first-seen windows and additive health metadata.
//!
//! `bridge_history.json` has existed in several shapes over the lifetime of
//! this repository. This store accepts legacy timestamp strings and object
//! records, preserves unknown object fields, and only writes a parsed JSON
//! object. A corrupt/unreadable history is never overwritten by a fresh empty
//! object during the same collector run.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};

use super::config::Transport;
use super::parsing::{clean_output_line, history_key, strip_bridge_prefix};

/// In-memory representation of the JSON history object.
#[derive(Clone, Debug, Default)]
pub struct HistoryStore {
    entries: BTreeMap<String, Value>,
}

impl HistoryStore {
    /// Load a valid JSON object from `path`. A missing file starts an empty
    /// history; malformed/non-object data returns an error so callers can
    /// continue collection without replacing valuable historical data.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("unable to read history {}", path.display()))?;
        let value: Value = serde_json::from_str(&text)
            .with_context(|| format!("invalid JSON history {}", path.display()))?;
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("history {} must be a JSON object", path.display()))?;
        Ok(Self {
            entries: object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
    }

    /// Serialize the history in deterministic, pretty JSON form.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut object = Map::new();
        for (key, value) in &self.entries {
            object.insert(key.clone(), value.clone());
        }
        let value = Value::Object(object);
        let mut bytes = serde_json::to_vec_pretty(&value)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Number of retained bridge entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when no entries are present.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record an observation from a successful source fetch. Existing
    /// `first_seen` values are never replaced; `last_seen` is refreshed.
    pub fn observe_discovered(
        &mut self,
        line: &str,
        transport: Transport,
        ipv6: bool,
        now: DateTime<Utc>,
    ) {
        let raw = clean_output_line(line);
        if raw.is_empty() {
            return;
        }
        let preferred_key = history_key(&raw, transport);
        let key = self.find_key_for_line(&raw).unwrap_or(preferred_key);
        let now_text = now.to_rfc3339();
        let old = self.entries.remove(&key);
        let mut object = object_from_legacy(old, &raw, transport, ipv6, &now_text);

        object.insert("raw".to_owned(), Value::String(raw));
        object.insert(
            "transport".to_owned(),
            Value::String(transport.file_name().to_owned()),
        );
        object.insert(
            "ip_version".to_owned(),
            Value::String(if ipv6 { "ipv6" } else { "ipv4" }.to_owned()),
        );
        if !object.contains_key("first_seen") {
            object.insert("first_seen".to_owned(), Value::String(now_text.clone()));
        }
        object.insert("last_seen".to_owned(), Value::String(now_text));
        object
            .entry("tcp_reachable".to_owned())
            .or_insert(Value::Null);
        object
            .entry("probe_successes".to_owned())
            .or_insert_with(|| Value::from(0_u64));
        object
            .entry("probe_failures".to_owned())
            .or_insert_with(|| Value::from(0_u64));
        object
            .entry("health_score".to_owned())
            .or_insert_with(|| Value::from(0.5_f64));

        self.entries.insert(key, Value::Object(object));
    }

    /// Record an individual probe outcome and update the rolling health score.
    /// The exponentially weighted score gives recent tests more influence while
    /// keeping per-bridge success/failure counts as inspectable metadata.
    pub fn record_probe(
        &mut self,
        line: &str,
        transport: Transport,
        ipv6: bool,
        reachable: bool,
        latency_ms: Option<f64>,
        now: DateTime<Utc>,
    ) {
        self.observe_discovered(line, transport, ipv6, now);
        let raw = clean_output_line(line);
        let Some(key) = self.find_key_for_line(&raw) else {
            return;
        };
        let Some(value) = self.entries.get_mut(&key) else {
            return;
        };
        let Some(object) = value.as_object_mut() else {
            return;
        };

        let successes = object
            .get("probe_successes")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(u64::from(reachable));
        let failures = object
            .get("probe_failures")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(u64::from(!reachable));
        let old_score = object
            .get("health_score")
            .and_then(Value::as_f64)
            .filter(|score| score.is_finite())
            .unwrap_or(0.5);
        let target = if reachable { 1.0 } else { 0.0 };
        let score = (old_score.mul_add(0.80, target * 0.20)).clamp(0.0, 1.0);

        object.insert("tcp_reachable".to_owned(), Value::Bool(reachable));
        object.insert("probe_successes".to_owned(), Value::from(successes));
        object.insert("probe_failures".to_owned(), Value::from(failures));
        object.insert("health_score".to_owned(), Value::from(score));
        object.insert("last_probe".to_owned(), Value::String(now.to_rfc3339()));
        object.insert(
            "latency_ms".to_owned(),
            latency_ms.map_or(Value::Null, Value::from),
        );
    }

    /// Get a health score used to prioritize bridges before tests. Unknown and
    /// malformed entries intentionally retain a neutral score rather than
    /// being starved indefinitely.
    pub fn health_score(&self, line: &str) -> f64 {
        let raw = clean_output_line(line);
        self.find_key_for_line(&raw)
            .and_then(|key| self.entries.get(&key))
            .and_then(Value::as_object)
            .and_then(|object| object.get("health_score"))
            .and_then(Value::as_f64)
            .filter(|score| score.is_finite())
            .map(|score| score.clamp(0.0, 1.0))
            .unwrap_or(0.5)
    }

    /// Return whether a bridge was first observed inside `recent_hours`.
    pub fn is_recent(&self, line: &str, recent_hours: i64, now: DateTime<Utc>) -> bool {
        let raw = clean_output_line(line);
        let cutoff = now - Duration::hours(recent_hours);
        self.find_key_for_line(&raw)
            .and_then(|key| self.entries.get(&key))
            .and_then(first_seen)
            .map(|timestamp| timestamp > cutoff)
            .unwrap_or(false)
    }

    /// Remove records whose valid `last_seen` (or legacy timestamp) lies
    /// outside the retention window. Invalid records are retained rather than
    /// silently discarded: an operator can repair them without losing data.
    pub fn cleanup(&mut self, retention_days: i64, now: DateTime<Utc>) -> usize {
        let cutoff = now - Duration::days(retention_days);
        let before = self.entries.len();
        self.entries.retain(|_, value| match last_seen(value) {
            Some(timestamp) => timestamp > cutoff,
            None => true,
        });
        before.saturating_sub(self.entries.len())
    }

    /// Return an iterator suitable for report diagnostics and tests.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.entries.iter()
    }

    fn find_key_for_line(&self, raw: &str) -> Option<String> {
        let raw = clean_output_line(raw);
        let vanilla = format!("Bridge {raw}");
        self.entries
            .keys()
            .find(|key| {
                let normalized = clean_output_line(key);
                normalized.eq_ignore_ascii_case(&raw)
                    || strip_bridge_prefix(key).eq_ignore_ascii_case(&raw)
                    || key.eq_ignore_ascii_case(&vanilla)
            })
            .cloned()
    }
}

fn object_from_legacy(
    old: Option<Value>,
    raw: &str,
    transport: Transport,
    ipv6: bool,
    now_text: &str,
) -> Map<String, Value> {
    match old {
        Some(Value::Object(object)) => object,
        Some(Value::String(timestamp)) => {
            let mut object = Map::new();
            object.insert("first_seen".to_owned(), Value::String(timestamp.clone()));
            object.insert("last_seen".to_owned(), Value::String(timestamp));
            object
        }
        Some(other) => {
            let mut object = Map::new();
            object.insert("legacy_value".to_owned(), other);
            object
        }
        None => {
            let mut object = Map::new();
            object.insert("first_seen".to_owned(), Value::String(now_text.to_owned()));
            object.insert("last_seen".to_owned(), Value::String(now_text.to_owned()));
            object.insert("raw".to_owned(), Value::String(raw.to_owned()));
            object.insert(
                "transport".to_owned(),
                Value::String(transport.file_name().to_owned()),
            );
            object.insert(
                "ip_version".to_owned(),
                Value::String(if ipv6 { "ipv6" } else { "ipv4" }.to_owned()),
            );
            object
        }
    }
}

fn timestamp_from_value(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let value = value?.as_str()?;
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn first_seen(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::String(timestamp) => DateTime::parse_from_rfc3339(timestamp)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&Utc)),
        Value::Object(object) => timestamp_from_value(object.get("first_seen")),
        _ => None,
    }
}

fn last_seen(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::String(timestamp) => DateTime::parse_from_rfc3339(timestamp)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&Utc)),
        Value::Object(object) => timestamp_from_value(object.get("last_seen"))
            .or_else(|| timestamp_from_value(object.get("first_seen"))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .map(|parsed| parsed.with_timezone(&Utc))
            .unwrap_or_else(|error| panic!("test timestamp must parse: {error}"))
    }

    #[test]
    fn history_window_keeps_recent_and_removes_old_records() {
        let now = time("2026-08-03T12:00:00+00:00");
        let mut history = HistoryStore::default();
        history.observe_discovered(
            "1.2.3.4:443 FINGERPRINT",
            Transport::Vanilla,
            false,
            now - Duration::days(31),
        );
        history.observe_discovered(
            "obfs4 5.6.7.8:443 FINGERPRINT cert=abc",
            Transport::Obfs4,
            false,
            now - Duration::hours(71),
        );
        assert!(history.is_recent("obfs4 5.6.7.8:443 FINGERPRINT cert=abc", 72, now));
        assert_eq!(history.cleanup(30, now), 1);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn legacy_string_history_is_promoted_without_losing_first_seen() {
        let mut history = HistoryStore {
            entries: BTreeMap::from([(
                "Bridge 1.2.3.4:443 FINGER".to_owned(),
                Value::String("2026-08-01T00:00:00+00:00".to_owned()),
            )]),
        };
        let now = time("2026-08-03T12:00:00+00:00");
        history.observe_discovered("1.2.3.4:443 FINGER", Transport::Vanilla, false, now);
        let (_, value) = history.entries().next().expect("one fixture entry");
        assert_eq!(value["first_seen"], json!("2026-08-01T00:00:00+00:00"));
        assert_eq!(value["last_seen"], json!("2026-08-03T12:00:00+00:00"));
    }

    #[test]
    fn probe_score_is_additive_metadata_and_prioritizes_success() {
        let now = time("2026-08-03T12:00:00+00:00");
        let mut history = HistoryStore::default();
        let line = "obfs4 203.0.113.1:443 FINGER cert=abc";
        history.observe_discovered(line, Transport::Obfs4, false, now);
        history.record_probe(line, Transport::Obfs4, false, true, Some(12.5), now);
        assert!(history.health_score(line) > 0.5);
        let bytes = history.to_bytes().expect("JSON serialization fixture");
        let text = String::from_utf8(bytes).expect("history output must be UTF-8");
        assert!(text.contains("probe_successes"));
        assert!(text.contains("health_score"));
    }
}
