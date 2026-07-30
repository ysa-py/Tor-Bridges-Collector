#![allow(warnings)]
// Live-Python differential parity test for
// `torshield_ai_gateway/iran_gateway_dpi_shaper.py` vs its Rust port.
//
// Deterministic behaviour (fronting decision, non-rotating domain, ISP->slot
// group, static header set) is asserted for exact equality against the real
// Python oracle. Random picks (`random.choice`) are asserted for pool
// membership on both sides (CPython's RNG cannot be byte-matched from Rust).

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::iran_gateway_dpi_shaper::GatewayDPIShaper;

fn oracle(script: &str, args: &[&str]) -> Value {
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
fn parity_fronting_decision_and_domain() {
    let script = r#"
import json, sys
from torshield_ai_gateway.iran_gateway_dpi_shaper import GatewayDPIShaper, CF_FRONTING_DOMAINS
s = GatewayDPIShaper()
lvl = sys.argv[1]
print(json.dumps({
    "use_fronting": s.should_use_gateway_fronting(lvl),
    "domain": s.get_fronting_domain(lvl),
    "domain_in_pool": s.get_fronting_domain(lvl) in CF_FRONTING_DOMAINS,
}, sort_keys=True, separators=(",", ":")))
"#;
    let s = GatewayDPIShaper::new();
    for lvl in ["none", "off", "low", "medium", "high", "critical"] {
        let py = oracle(script, &[lvl]);
        assert_eq!(
            py["use_fronting"],
            Value::Bool(s.should_use_gateway_fronting(lvl)),
            "fronting decision mismatch at {lvl}"
        );
        // Non-rotating levels: exact domain equality. Rotating levels
        // (high/critical): membership only, since Python uses random.choice.
        if !matches!(lvl, "high" | "critical") {
            assert_eq!(
                py["domain"],
                s.get_fronting_domain(lvl),
                "domain mismatch at {lvl}"
            );
        }
        assert_eq!(py["domain_in_pool"], Value::Bool(true));
        assert!(["gateway.ai.cloudflare.com", "api.cloudflare.com"]
            .contains(&s.get_fronting_domain(lvl)));
    }
}

#[test]
fn parity_slot_group_selection() {
    // Expose Python's deterministic group selection via a helper that returns
    // the whole matched group (mirrors the Rust `slot_group_for_isp`).
    let script = r#"
import json, sys
from torshield_ai_gateway.iran_gateway_dpi_shaper import ISP_SLOT_MAPPING
detected = sys.argv[1]
none = sys.argv[2] == "1"
isp_key = (None if none else detected) or "other"
isp_key = isp_key.lower()
group = None
for pat, slots in ISP_SLOT_MAPPING.items():
    if pat in isp_key:
        group = slots
        break
if group is None:
    group = ISP_SLOT_MAPPING["other"]
print(json.dumps({"group": group}, separators=(",", ":")))
"#;
    let s = GatewayDPIShaper::new();
    let cases: [(Option<&str>, &str, &str); 7] = [
        (Some("Irancell-IR"), "Irancell-IR", "0"),
        (Some("mci"), "mci", "0"),
        (Some("rightel-tehran"), "rightel-tehran", "0"),
        (Some("shatel"), "shatel", "0"),
        (Some("unknownisp"), "unknownisp", "0"),
        (Some(""), "", "0"),
        (None, "", "1"),
    ];
    for (opt, detected, none_flag) in cases {
        let py = oracle(script, &[detected, none_flag]);
        let rust_group: Vec<i64> = s.slot_group_for_isp(opt).to_vec();
        assert_eq!(py["group"], json!(rust_group), "group mismatch for {opt:?}");
        // The chosen optimal slot is always inside the selected group.
        assert!(rust_group.contains(&s.get_optimal_slot_for_isp(opt)));
    }
}

#[test]
fn parity_dpi_evading_headers() {
    // Compare the header map with the (random) User-Agent removed for exact
    // equality; assert the UA is a valid pool member on both sides.
    let script = r#"
import json, sys
from torshield_ai_gateway.iran_gateway_dpi_shaper import (
    GatewayDPIShaper, BROWSER_USER_AGENTS,
)
s = GatewayDPIShaper()
base = json.loads(sys.argv[1])
lvl = sys.argv[2]
h = s.get_dpi_evading_headers(base, lvl)
ua = h.pop("User-Agent", None)
print(json.dumps({
    "headers": h,
    "ua_in_pool": (ua in BROWSER_USER_AGENTS) if ua is not None else None,
}, sort_keys=True, separators=(",", ":")))
"#;
    let s = GatewayDPIShaper::new();
    let mut base = BTreeMap::new();
    base.insert("X-Test".to_string(), "1".to_string());
    let base_json = serde_json::to_string(&base).expect("serialize base headers");

    for lvl in ["none", "low", "medium", "high", "critical"] {
        let py = oracle(script, &[&base_json, lvl]);
        let mut rust_headers = s.get_dpi_evading_headers(&base, lvl);
        let rust_ua = rust_headers.remove("User-Agent");
        let rust_headers_json: Value = serde_json::to_value(&rust_headers).expect("headers json");
        assert_eq!(
            py["headers"], rust_headers_json,
            "headers mismatch at {lvl}"
        );
        match rust_ua {
            None => assert_eq!(py["ua_in_pool"], Value::Null, "UA presence mismatch"),
            Some(ua) => {
                assert_eq!(py["ua_in_pool"], Value::Bool(true));
                assert!([
                    "Mozilla/5.0 (Linux; Android 14; SM-G998B) Chrome/125.0",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/17.4",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Firefox/126.0",
                    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/125.0",
                ]
                .contains(&ua.as_str()));
            }
        }
    }
}
