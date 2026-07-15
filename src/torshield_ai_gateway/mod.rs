//! Rust port of the `torshield_ai_gateway` Python package.
//!
//! Ported module-by-module in dependency order (leaves first). Each submodule
//! is a functionally-equivalent, parity-verified port of the corresponding
//! `torshield_ai_gateway/*.py` file. See `tests/parity/*.rs` for the live-Python
//! differential parity tests.

pub mod ai_threat_detector;
pub mod cf_compat_model_formatter;
pub mod circuit_breaker;
pub mod exceptions;
pub mod hashing;
pub mod iran_gateway_dpi_shaper;
pub mod iran_traffic_evasion;
pub mod rotator;
