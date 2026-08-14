//! ETag / Last-Modified cache for conditional GETs.
//!
//! Collectors store the HTTP validators a server returns and replay them as
//! `If-None-Match` / `If-Modified-Since` on the next fetch, so unchanged
//! sources answer `304 Not Modified` instead of re-transferring their body.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// A cached HTTP validator pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheEntry {
    /// The `ETag` value, if the server provided one.
    pub etag: Option<String>,
    /// The `Last-Modified` value, if the server provided one.
    pub last_modified: Option<String>,
}

/// Thread-safe validator cache keyed by URL.
#[derive(Debug, Default)]
pub struct ConditionalCache {
    inner: Mutex<HashMap<String, CacheEntry>>,
}

impl ConditionalCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Look up cached validators for a URL, if any.
    pub fn get(&self, url: &str) -> Option<CacheEntry> {
        self.lock().get(url).cloned()
    }

    /// Store validators for a URL. A `None` value clears that validator slot;
    /// storing two `None`s removes the entry entirely.
    pub fn store(&self, url: &str, etag: Option<String>, last_modified: Option<String>) {
        let mut inner = self.lock();
        if etag.is_none() && last_modified.is_none() {
            inner.remove(url);
            return;
        }
        inner.insert(
            url.to_owned(),
            CacheEntry {
                etag,
                last_modified,
            },
        );
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn store_and_get_round_trip() {
        let cache = ConditionalCache::new();
        assert!(cache.is_empty());
        cache.store(
            "https://example.invalid/list",
            Some("\"abc123\"".into()),
            Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
        );
        assert_eq!(cache.len(), 1);
        let entry = cache.get("https://example.invalid/list").unwrap();
        assert_eq!(entry.etag.as_deref(), Some("\"abc123\""));
        assert_eq!(
            entry.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    }

    #[test]
    fn storing_no_validators_removes_entry() {
        let cache = ConditionalCache::new();
        cache.store("u", Some("e".into()), None);
        assert_eq!(cache.len(), 1);
        cache.store("u", None, None);
        assert!(cache.is_empty());
        assert!(cache.get("u").is_none());
    }

    #[test]
    fn missing_key_returns_none() {
        let cache = ConditionalCache::new();
        assert!(cache.get("nope").is_none());
    }
}
