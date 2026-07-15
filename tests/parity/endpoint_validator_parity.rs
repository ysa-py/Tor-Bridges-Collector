// Parity tests for `src/endpoint_validator.rs` vs `core/endpoint_validator.py`.
//
// `_probe_endpoint`'s reachability check is tested against local HTTP
// servers this suite starts and controls (raw TCP + hand-written
// HTTP/1.1 responses — no new server dependency needed), not real
// Cloudflare infrastructure. Worth noting explicitly: an earlier attempt
// to sanity-check this module's behavior against `gateway.ai.cloudflare.com`
// and `example.com` directly appeared to show them as "reachable" —
// but those hosts are outside this sandbox's network egress allowlist,
// and what was actually being observed was this environment's own
// egress proxy responding with an HTTP 403 (`x-deny-reason:
// host_not_allowed`), which the module's "any HTTP response counts as
// reachable" logic doesn't distinguish from a real response. Both
// Python and Rust see the identical proxy response in that scenario, so
// it wasn't a *wrong* parity data point, but it wasn't testing what it
// looked like it was testing — hence local, controlled servers here
// instead, for a genuine, unambiguous comparison.
//
// The pure-logic tests below (detect/validate/build/extract) don't need
// the `network` feature at all and run either way. Every test that
// actually calls `probe_endpoint` or the local HTTP-server helpers lives
// in the `network_tests` submodule, gated with `#[cfg(feature =
// "network")]` — `probe_endpoint` only exists in that configuration, so
// without the gate this file would hard-fail to compile with the
// feature off.

use std::process::Command;

use serde_json::{json, Value};

use torshield_ir_ultra::endpoint_validator::EndpointValidator;

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        return Box::leak(path.into_boxed_str());
    }
    "python3"
}

struct PythonResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_python_script(script: &str, payload: &Value) -> PythonResult {
    let payload_json = serde_json::to_string(payload).expect("payload must serialize");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&payload_json)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    PythonResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn run_python_json(script: &str, payload: &Value) -> Value {
    let result = run_python_script(script, payload);
    assert!(result.success, "python helper failed: {}", result.stderr);
    serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|err| panic!("python helper must emit JSON: {err}; stdout={}", result.stdout))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure logic — detect/validate/build/extract, no network feature needed
// ─────────────────────────────────────────────────────────────────────────────

const VALIDATE_NO_PROBE_SCRIPT: &str = r##"
import json, sys
import core.endpoint_validator as ev
# Disable the network probe specifically (not the whole validator) so
# this comparison isolates detect/validate/build/extract from any live
# HTTP call — mirrors this port's own non-network code path.
ev.EndpointValidator._probe_endpoint = staticmethod(lambda url, token: (True, 0.0))
from core.endpoint_validator import EndpointValidator

payload = json.loads(sys.argv[1])
v = EndpointValidator()
r = v.validate_slot_url(payload["slot"], payload["url"], account_id="", api_token=payload.get("token", ""))
print(json.dumps({
    "slot_index": r.slot_index,
    "url": r.url,
    "endpoint_type": r.endpoint_type.value,
    "is_valid": r.is_valid,
    "detected_suffix": r.detected_suffix,
    "recommended_url": r.recommended_url,
    "error_message": r.error_message,
}))
"##;

macro_rules! parity_validate_no_probe {
    ($name:ident, $slot:expr, $url:expr) => {
        #[test]
        fn $name() {
            let payload = json!({ "slot": $slot, "url": $url });
            let py = run_python_json(VALIDATE_NO_PROBE_SCRIPT, &payload);

            let mut v = EndpointValidator::new();
            let r = v.validate_slot_url($slot, $url, "", "");

            assert_eq!(py["slot_index"], json!(r.slot_index));
            assert_eq!(py["url"], json!(r.url));
            assert_eq!(py["endpoint_type"], json!(r.endpoint_type.as_str()));
            assert_eq!(py["is_valid"], json!(r.is_valid));
            assert_eq!(py["detected_suffix"], json!(r.detected_suffix));
            assert_eq!(py["recommended_url"], json!(r.recommended_url));
            assert_eq!(py["error_message"], json!(r.error_message));
        }
    };
}

parity_validate_no_probe!(
    validate_workers_ai_bug_detected_and_fixed,
    1,
    "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug/workers-ai/v1/chat/completions"
);
parity_validate_no_probe!(
    validate_compat_already_correct,
    2,
    "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug/compat/chat/completions"
);
parity_validate_no_probe!(
    validate_bare_gateway_url_defaults_to_compat,
    3,
    "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug"
);
parity_validate_no_probe!(
    validate_direct_cloudflare_api_url,
    4,
    "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/run/@cf/meta/llama"
);
parity_validate_no_probe!(validate_rejects_http_not_https, 5, "http://gateway.ai.cloudflare.com/v1/x/y");
parity_validate_no_probe!(
    validate_malformed_gateway_pattern,
    6,
    "https://gateway.ai.cloudflare.com/v1/not-a-valid-account-id/slug/compat/chat/completions"
);
parity_validate_no_probe!(validate_totally_unrelated_url, 7, "https://example.com/some/path");
parity_validate_no_probe!(
    validate_trailing_slash_stripped,
    8,
    "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/myslug/compat/chat/completions/"
);

// ─────────────────────────────────────────────────────────────────────────────
// validation-disabled short-circuit — also no network feature needed
// ─────────────────────────────────────────────────────────────────────────────

const VALIDATE_DISABLED_SCRIPT: &str = r##"
import json, sys, os
os.environ["ENABLE_ENDPOINT_VALIDATION"] = "false"
from core.endpoint_validator import EndpointValidator

payload = json.loads(sys.argv[1])
v = EndpointValidator()
r = v.validate_slot_url(payload["slot"], payload["url"], account_id="")
print(json.dumps({
    "is_valid": r.is_valid, "is_reachable": r.is_reachable,
    "detected_suffix": r.detected_suffix, "recommended_url": r.recommended_url,
}))
"##;

#[test]
fn parity_validation_disabled_short_circuits_identically() {
    let payload = json!({ "slot": 1, "url": "https://anything.example/x" });
    let py = run_python_json(VALIDATE_DISABLED_SCRIPT, &payload);

    std::env::set_var("ENABLE_ENDPOINT_VALIDATION", "false");
    let mut v = EndpointValidator::new();
    let r = v.validate_slot_url(1, "https://anything.example/x", "", "");
    std::env::remove_var("ENABLE_ENDPOINT_VALIDATION");

    assert_eq!(py["is_valid"], json!(r.is_valid));
    assert_eq!(py["is_reachable"], json!(r.is_reachable));
    assert_eq!(py["detected_suffix"], json!(r.detected_suffix));
    assert_eq!(py["recommended_url"], json!(r.recommended_url));
}

// ─────────────────────────────────────────────────────────────────────────────
// Real HTTP probing — network feature required; against local servers,
// not real Cloudflare infra
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "network")]
mod network_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use serde_json::json;

    use torshield_ir_ultra::endpoint_validator::{probe_endpoint, EndpointValidator};

    use super::run_python_json;

    /// Starts a local HTTP/1.1 server that responds to every request
    /// with `status_line` (e.g. "200 OK", "400 Bad Request") and no
    /// body, returning its port.
    fn start_http_server(status_line: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf); // drain the request, ignore content
                let response =
                    format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    const PROBE_ENDPOINT_SCRIPT: &str = r##"
import json, sys
from core.endpoint_validator import EndpointValidator

payload = json.loads(sys.argv[1])
v = EndpointValidator()
ok, latency_ms = v._probe_endpoint(payload["url"], payload.get("token", ""))
print(json.dumps({"ok": ok}))
"##;

    #[test]
    fn parity_probe_endpoint_reachable_via_200() {
        let port = start_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions");
        let payload = json!({ "url": url });
        let py = run_python_json(PROBE_ENDPOINT_SCRIPT, &payload);

        let (ok, _lat) = probe_endpoint(&url, "", Duration::from_secs(3));
        assert_eq!(py["ok"], json!(ok));
        assert!(ok);
    }

    #[test]
    fn parity_probe_endpoint_reachable_even_on_http_error_status() {
        // Mirrors the module's core design point: an HTTP error response
        // still counts as "reachable" (the endpoint exists and
        // responded), distinct from a connection-level failure.
        let port = start_http_server("400 Bad Request");
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions");
        let payload = json!({ "url": url });
        let py = run_python_json(PROBE_ENDPOINT_SCRIPT, &payload);

        let (ok, _lat) = probe_endpoint(&url, "", Duration::from_secs(3));
        assert_eq!(py["ok"], json!(ok));
        assert!(ok, "an HTTP error response should still count as reachable");
    }

    #[test]
    fn parity_probe_endpoint_unreachable_connection_refused() {
        let port = closed_port();
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions");
        let payload = json!({ "url": url });
        let py = run_python_json(PROBE_ENDPOINT_SCRIPT, &payload);

        let (ok, _lat) = probe_endpoint(&url, "", Duration::from_secs(3));
        assert_eq!(py["ok"], json!(ok));
        assert!(!ok);
    }

    #[test]
    fn probe_endpoint_reaches_server_when_chat_completions_suffix_present() {
        // Confirms this port's own suffix-stripping doesn't prevent a
        // real request from landing correctly against a live server
        // (not a Python parity comparison — see module note on why this
        // specific internal detail isn't independently observable from
        // outside).
        let port = start_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions/");
        let (ok, _lat) = probe_endpoint(&url, "", Duration::from_secs(3));
        assert!(ok);
    }

    #[test]
    fn end_to_end_validate_slot_url_reaches_local_server_and_reports_reachable() {
        // Not a parity test against Python (Python's env-var-based
        // slot/token reading in validate_all_slots isn't easily
        // redirected to a local server without monkeypatching more than
        // is proportionate here) — exercises this port's own full,
        // real, network-enabled path end to end: build the recommended
        // URL, then actually probe it live.
        let port = start_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions");
        let mut v = EndpointValidator::new();
        let r = v.validate_slot_url(1, &url, "", "");
        assert!(r.is_reachable);
    }

    #[test]
    fn get_validation_summary_matches_python_shape_for_a_known_case() {
        // Both sides probe the *same* local server with the *same* URL —
        // an earlier version of this test used the real
        // "gateway.ai.cloudflare.com" hostname for Python (to trigger
        // workers-ai detection) but a local port for Rust, which are
        // different inputs and can't be validly compared against each
        // other (caught because workers_ai_bug_detected genuinely
        // differed — 1 vs 0 — not because of a Rust bug, but because
        // the two sides were never testing the same thing). Endpoint-type
        // detection itself is already covered thoroughly elsewhere
        // (`validate_workers_ai_bug_detected_and_fixed` and siblings);
        // this test's actual job is just confirming `get_validation_summary`'s
        // JSON shape and aggregation match, which doesn't need that
        // specific scenario.
        let port = start_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/compat/chat/completions");

        let script = format!(
            r##"
import json
from core.endpoint_validator import EndpointValidator
v = EndpointValidator()
v.validate_slot_url(1, {url:?}, account_id="")
s = v.get_validation_summary()
print(json.dumps(s))
"##
        );
        let py = run_python_json(&script, &json!({}));

        let mut v = EndpointValidator::new();
        v.validate_slot_url(1, &url, "", "");
        let rs_summary = v.get_validation_summary();

        assert_eq!(py["total_slots_validated"], rs_summary["total_slots_validated"]);
        assert_eq!(py["workers_ai_bug_detected"], rs_summary["workers_ai_bug_detected"]);
        assert_eq!(py["fix_applied"], rs_summary["fix_applied"]);
        assert_eq!(py["results"]["1"]["suffix"], rs_summary["results"]["1"]["suffix"]);
        assert_eq!(py["results"]["1"]["reachable"], rs_summary["results"]["1"]["reachable"]);
        assert_eq!(py["results"]["1"]["type"], rs_summary["results"]["1"]["type"]);
    }
}
