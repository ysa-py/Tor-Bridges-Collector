//! Minimal thread-safe metrics registry with Prometheus text exposition.
//!
//! The prober and pipeline layers accumulate counters, gauges, and latency
//! histograms here and render a Prometheus text file at the end of a run
//! (Phase 9 observability). Locking uses `unwrap_or_else(|poisoned|
//! poisoned.into_inner())` so a panicked writer can never turn a metrics read
//! into a second panic.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

/// Default histogram bucket upper bounds (seconds), tuned for probe RTTs.
pub const DEFAULT_LATENCY_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Default)]
struct Inner {
    counters: BTreeMap<String, u64>,
    gauges: BTreeMap<String, f64>,
    histograms: BTreeMap<String, Histogram>,
}

#[derive(Debug, Default)]
struct Histogram {
    bounds: Vec<f64>,
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new(bounds: Vec<f64>) -> Self {
        let mut sorted = bounds;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let counts = vec![0u64; sorted.len()];
        Self {
            bounds: sorted,
            counts,
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count = self.count.saturating_add(1);
        // Increment only the single bucket this value falls into; the renderer
        // turns per-bucket counts into cumulative (`le=`) buckets.
        if let Some(index) = self.bounds.iter().position(|bound| value <= *bound) {
            self.counts[index] = self.counts[index].saturating_add(1);
        }
    }
}

/// A registry of counters, gauges, and histograms.
///
/// Safe to share across threads (`&Metrics` implements `Send + Sync`).
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Increment a named counter by `by`.
    pub fn increment(&self, name: &str, by: u64) {
        let mut inner = self.lock();
        let entry = inner.counters.entry(name.to_owned()).or_insert(0);
        *entry = entry.saturating_add(by);
    }

    /// Set a named gauge to an absolute value.
    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut inner = self.lock();
        inner.gauges.insert(name.to_owned(), value);
    }

    /// Record one observation in a named latency histogram.
    pub fn observe(&self, name: &str, value: f64) {
        let mut inner = self.lock();
        let histogram = inner
            .histograms
            .entry(name.to_owned())
            .or_insert_with(|| Histogram::new(DEFAULT_LATENCY_BUCKETS.to_vec()));
        histogram.observe(value);
    }

    /// Read the current value of a named counter (0 if absent).
    pub fn counter_value(&self, name: &str) -> u64 {
        self.lock().counters.get(name).copied().unwrap_or(0)
    }

    /// Render the registry in Prometheus text exposition format.
    ///
    /// Histogram buckets are cumulative (`le=` semantics) as Prometheus
    /// requires. Metric names are emitted verbatim, so callers must supply
    /// valid Prometheus names (`[a-zA-Z_:][a-zA-Z0-9_:]*`).
    pub fn render_prometheus(&self) -> String {
        let inner = self.lock();
        let mut out = String::new();

        for (name, value) in &inner.counters {
            out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
        }
        for (name, value) in &inner.gauges {
            out.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
        }
        for (name, histogram) in &inner.histograms {
            out.push_str(&format!("# TYPE {name} histogram\n"));
            let mut cumulative = 0u64;
            for (bound, count) in histogram.bounds.iter().zip(histogram.counts.iter()) {
                cumulative = cumulative.saturating_add(*count);
                out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {cumulative}\n"));
            }
            out.push_str(&format!(
                "{name}_bucket{{le=\"+Inf\"}} {}\n",
                histogram.count
            ));
            out.push_str(&format!(
                "{name}_sum {}\n{name}_count {}\n",
                histogram.sum, histogram.count
            ));
        }

        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_render() {
        let metrics = Metrics::new();
        metrics.increment("tbc_probes_total", 2);
        metrics.increment("tbc_probes_total", 3);
        metrics.set_gauge("tbc_pool_size", 42.0);
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("tbc_probes_total 5\n"));
        assert!(rendered.contains("tbc_pool_size 42\n"));
        assert_eq!(metrics.counter_value("tbc_probes_total"), 5);
    }

    #[test]
    fn histograms_are_cumulative() {
        let metrics = Metrics::new();
        metrics.observe("tbc_rtt_seconds", 0.01);
        metrics.observe("tbc_rtt_seconds", 5.0);
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("tbc_rtt_seconds_bucket{le=\"0.01\"} 1\n"));
        // Both observations fall at or below the 5.0 bucket.
        assert!(rendered.contains("tbc_rtt_seconds_bucket{le=\"5\"} 2\n"));
        assert!(rendered.contains("tbc_rtt_seconds_bucket{le=\"+Inf\"} 2\n"));
        assert!(rendered.contains("tbc_rtt_seconds_count 2\n"));
    }

    #[test]
    fn metrics_are_shared_across_threads() {
        let metrics = std::sync::Arc::new(Metrics::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let metrics = std::sync::Arc::clone(&metrics);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        metrics.increment("tbc_thread_counter", 1);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(metrics.counter_value("tbc_thread_counter"), 400);
    }
}
