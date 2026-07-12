//! PyO3 runtime bridge for `core/iran_detector`.
//!
//! Gate 4 ("legacy eradication") requires the runtime `core.iran_detector`
//! import to route through Rust rather than through the Python logic. This
//! extension exposes the already-verified parity port
//! (`torshield_ir_ultra::iran_detector`) to Python. The Python side becomes a
//! thin shim (`core/iran_detector.py`) with **no detection logic of its own** —
//! it only re-exports these symbols and provides trivial async adapters so the
//! existing `await check_connectivity()` / `asyncio.run(...)` call sites keep
//! working unchanged.
//!
//! The original Python implementation is retained ONLY as a test-time parity
//! baseline (`core/_iran_detector_legacy.py`); nothing at runtime imports it.

// Justified allow (directive §10: "zero clippy warnings without a documented
// #[allow]"). pyo3 0.22's `#[pyfunction]`/`#[pymethods]` proc-macros expand the
// `PyResult<T>` return into code containing an identity `Into<PyErr>`
// conversion, which clippy attributes to our (macro-input) return-type spans.
// It is not conversion code we wrote and cannot be removed from source; it is
// harmless (an identity map). Scoped to this bridge crate only.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use torshield_ir_ultra::iran_detector as core;

/// Build a small current-thread tokio runtime for the sync bridge calls. The
/// underlying probes use `tokio::task::JoinSet`, which requires an active
/// runtime; `enable_all` turns on the time + net drivers they need. Returns
/// `io::Result` so the `?` at call sites performs a real `io::Error -> PyErr`
/// conversion (pyo3 provides `From<io::Error>`), rather than an identity one.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Mirrors `recommend_strategy(nin_active) -> str`. Pure, no I/O.
#[pyfunction]
fn recommend_strategy(nin_active: bool) -> String {
    core::recommend_strategy(nin_active)
}

/// Mirrors the module-level async `check_connectivity()` — real hardcoded
/// targets — returning `(international_ok, nin_active)`. Sync at the FFI
/// boundary; the Python shim wraps it in an `async def` so `await` still works.
/// The GIL is released for the duration of the network probing.
#[pyfunction]
fn check_connectivity(py: Python<'_>) -> PyResult<(bool, bool)> {
    let rt = runtime()?;
    Ok(py.allow_threads(|| rt.block_on(core::check_connectivity())))
}

/// Injectable-targets variant, exposed for deterministic loopback differential
/// testing between this Rust bridge and the Python baseline.
#[pyfunction]
fn check_connectivity_with_targets(
    py: Python<'_>,
    international: Vec<(String, u16)>,
    nin: Vec<(String, u16)>,
    timeout_secs: f64,
) -> PyResult<(bool, bool)> {
    let rt = runtime()?;
    let intl: Vec<(&str, u16)> = international
        .iter()
        .map(|(h, p)| (h.as_str(), *p))
        .collect();
    let ninr: Vec<(&str, u16)> = nin.iter().map(|(h, p)| (h.as_str(), *p)).collect();
    Ok(py.allow_threads(|| {
        rt.block_on(core::check_connectivity_with_targets(
            &intl,
            &ninr,
            timeout_secs,
        ))
    }))
}

/// Mirrors `_probe_tcp`.
#[pyfunction]
fn probe_tcp(py: Python<'_>, host: String, port: u16, timeout_secs: f64) -> PyResult<bool> {
    let rt = runtime()?;
    Ok(py.allow_threads(|| rt.block_on(core::probe_tcp(&host, port, timeout_secs))))
}

/// Rust-backed detector. The Python shim's `NINDetector` wraps this and adds
/// the `export_path` attribute (which the Rust core keeps but never reads, per
/// the documented Python parity note).
#[pyclass]
struct RustNinDetector {
    inner: core::NinDetector,
}

#[pymethods]
impl RustNinDetector {
    #[new]
    fn new(events_path: String, export_path: String) -> Self {
        Self {
            inner: core::NinDetector::new(events_path, export_path),
        }
    }

    /// Mirrors `is_nin_active(force_refresh=False)`. Releases the GIL during
    /// probing.
    #[pyo3(signature = (force_refresh = false))]
    fn is_nin_active(&self, py: Python<'_>, force_refresh: bool) -> bool {
        py.allow_threads(|| self.inner.is_nin_active(force_refresh))
    }

    /// Mirrors `record_event(kind, details)`. `details` arrives pre-serialized
    /// as a JSON string from the Python shim (keeps this extension dependency-
    /// light — no pythonize). A malformed string maps to JSON null, matching
    /// how an empty/absent dict would serialize.
    fn record_event(&self, kind: String, details_json: String) -> PyResult<()> {
        let details: serde_json::Value =
            serde_json::from_str(&details_json).unwrap_or(serde_json::Value::Null);
        // `record_event` can panic only on the documented unguarded-makedirs
        // path (parity with Python's unguarded os.makedirs). Convert that panic
        // into a Python exception so it never tears down the interpreter.
        let inner = &self.inner;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inner.record_event(&kind, details)
        }))
        .map_err(|_| {
            pyo3::exceptions::PyOSError::new_err(
                "record_event: could not create events directory (parity with Python os.makedirs)",
            )
        })
    }
}

#[pymodule]
fn _iran_detector_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(recommend_strategy, m)?)?;
    m.add_function(wrap_pyfunction!(check_connectivity, m)?)?;
    m.add_function(wrap_pyfunction!(check_connectivity_with_targets, m)?)?;
    m.add_function(wrap_pyfunction!(probe_tcp, m)?)?;
    m.add_class::<RustNinDetector>()?;
    // Re-export the probe constants so the shim can mirror the legacy module's
    // module-level `_INTERNATIONAL_PROBES` / `_NIN_PROBES` / `_PROBE_TIMEOUT`.
    let intl: Vec<(String, u16)> = core::INTERNATIONAL_PROBES
        .iter()
        .map(|(h, p)| (h.to_string(), *p))
        .collect();
    let nin: Vec<(String, u16)> = core::NIN_PROBES
        .iter()
        .map(|(h, p)| (h.to_string(), *p))
        .collect();
    m.add("INTERNATIONAL_PROBES", intl)?;
    m.add("NIN_PROBES", nin)?;
    m.add("PROBE_TIMEOUT", core::PROBE_TIMEOUT_SECS)?;
    Ok(())
}
