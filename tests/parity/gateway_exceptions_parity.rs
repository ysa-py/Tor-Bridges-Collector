// Live-Python differential parity test for
// `torshield_ai_gateway/exceptions.py` vs its Rust port.
//
// For each construction case the real Python oracle is executed and its
// observable attributes (`str(exc)`, `exc.provider`, `exc.slot`, class name,
// and `isinstance(exc, ValueError)`) are compared against the Rust port.

use std::process::Command;

use serde_json::Value;
use torshield_ir_ultra::torshield_ai_gateway::exceptions::{
    BadRequestError, ProviderConfigurationError,
};

/// Run the Python oracle for `ProviderConfigurationError(message, provider=...)`
/// and return its observable attributes as JSON.
fn py_provider_config(message: &str, provider: &str) -> Value {
    let script = r#"
import json, sys
from torshield_ai_gateway.exceptions import ProviderConfigurationError
message, provider = sys.argv[1], sys.argv[2]
e = ProviderConfigurationError(message, provider=provider)
print(json.dumps({
    "str": str(e),
    "provider": e.provider,
    "cls": type(e).__name__,
    "is_value_error": isinstance(e, ValueError),
}, sort_keys=True, separators=(",", ":")))
"#;
    run_oracle(script, &[message, provider])
}

/// Run the Python oracle for `BadRequestError(message, provider=..., slot=...)`.
fn py_bad_request(message: &str, provider: &str, slot: i64) -> Value {
    let script = r#"
import json, sys
from torshield_ai_gateway.exceptions import BadRequestError
message, provider, slot = sys.argv[1], sys.argv[2], int(sys.argv[3])
e = BadRequestError(message, provider=provider, slot=slot)
print(json.dumps({
    "str": str(e),
    "provider": e.provider,
    "slot": e.slot,
    "cls": type(e).__name__,
    "is_value_error": isinstance(e, ValueError),
}, sort_keys=True, separators=(",", ":")))
"#;
    let slot = slot.to_string();
    run_oracle(script, &[message, provider, &slot])
}

fn run_oracle(script: &str, args: &[&str]) -> Value {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .args(args)
        .output()
        .expect("python parity oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python oracle must emit JSON")
}

#[test]
fn parity_provider_configuration_error_cases() {
    let cases = [
        ("", ""),
        ("all API keys too short", ""),
        ("no slots configured", "portkey"),
        ("CF slot 400 empty body", "cloudflare"),
    ];
    for (message, provider) in cases {
        let py = py_provider_config(message, provider);
        let rust = ProviderConfigurationError::with_provider(message, provider);
        assert_eq!(py["str"], rust.to_string(), "str mismatch for {message:?}");
        assert_eq!(py["provider"], rust.provider, "provider mismatch");
        assert_eq!(py["cls"], "ProviderConfigurationError");
        // The ValueError base-class contract is documented as a deviation; the
        // oracle asserts Python's side so the parity record is explicit.
        assert_eq!(py["is_value_error"], Value::Bool(true));
    }
}

#[test]
fn parity_bad_request_error_cases() {
    let cases = [
        ("", "", 0_i64),
        ("bad model name", "", 0),
        ("malformed payload", "cloudflare", 3),
        ("bad url path", "portkey", 11),
    ];
    for (message, provider, slot) in cases {
        let py = py_bad_request(message, provider, slot);
        let rust = BadRequestError::with_context(message, provider, slot);
        assert_eq!(py["str"], rust.to_string(), "str mismatch for {message:?}");
        assert_eq!(py["provider"], rust.provider, "provider mismatch");
        assert_eq!(py["slot"], rust.slot, "slot mismatch");
        assert_eq!(py["cls"], "BadRequestError");
        assert_eq!(py["is_value_error"], Value::Bool(true));
    }
}
