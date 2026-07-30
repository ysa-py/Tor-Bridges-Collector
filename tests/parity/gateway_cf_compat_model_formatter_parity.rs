#![allow(warnings)]
// Live-Python differential parity test for
// `torshield_ai_gateway/cf_compat_model_formatter.py` vs its Rust port.
//
// Every function is deterministic, so this asserts exact byte equality between
// the real Python oracle and the Rust port across a broad set of inputs,
// including the constant tables and the `PORTKEY_HEALTH_MODEL` env-var path.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::cf_compat_model_formatter as cf;

fn oracle_env(script: &str, args: &[&str], env: &[(&str, &str)]) -> Value {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("python");
    cmd.current_dir(repo_root).arg("-c").arg(script).args(args);
    // Ensure a clean, explicit env for the var this module reads.
    cmd.env_remove("PORTKEY_HEALTH_MODEL");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("python parity oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python oracle must emit JSON")
}

fn oracle(script: &str, args: &[&str]) -> Value {
    oracle_env(script, args, &[])
}

#[test]
fn parity_constant_tables() {
    let script = r#"
import json
from torshield_ai_gateway.cf_compat_model_formatter import (
    STATIC_FALLBACK_MODELS, PORTKEY_SAFE_MODELS,
)
print(json.dumps({
    "static": STATIC_FALLBACK_MODELS,
    "portkey": PORTKEY_SAFE_MODELS,
}, separators=(",", ":")))
"#;
    let py = oracle(script, &[]);
    assert_eq!(py["static"], json!(cf::STATIC_FALLBACK_MODELS.to_vec()));
    assert_eq!(py["portkey"], json!(cf::PORTKEY_SAFE_MODELS.to_vec()));
}

#[test]
fn parity_model_formatting_functions() {
    let script = r#"
import json, sys
from torshield_ai_gateway import cf_compat_model_formatter as cf
m = sys.argv[1]
print(json.dumps({
    "compat": cf.format_model_for_compat_endpoint(m),
    "rest": cf.format_model_for_rest_api(m),
    "native": cf.format_model_for_native_path(m),
    "is_cf": cf.is_cf_model(m),
}, separators=(",", ":")))
"#;
    let inputs = [
        "",
        "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "openai/gpt-4o-mini",
        "anthropic/claude-3-haiku",
        "llama3.1-70b",
        "workers-ai/openai/gpt-4o-mini",
        "bare-model-name",
        "@cf/qwen/qwq-32b",
    ];
    for m in inputs {
        let py = oracle(script, &[m]);
        assert_eq!(
            py["compat"],
            cf::format_model_for_compat_endpoint(m),
            "compat {m:?}"
        );
        assert_eq!(py["rest"], cf::format_model_for_rest_api(m), "rest {m:?}");
        assert_eq!(
            py["native"],
            cf::format_model_for_native_path(m),
            "native {m:?}"
        );
        assert_eq!(py["is_cf"], Value::Bool(cf::is_cf_model(m)), "is_cf {m:?}");
    }
}

#[test]
fn parity_extract_gateway_name_and_urls() {
    let script = r#"
import json, sys
from torshield_ai_gateway import cf_compat_model_formatter as cf
url, acct, gw, model = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(json.dumps({
    "name": cf.extract_gateway_name(url),
    "f1": cf.build_format1_url(acct),
    "f3": cf.build_format3_url(acct, gw),
    "f2": cf.build_format2_url(acct, gw, model),
}, separators=(",", ":")))
"#;
    let cases = [
        (
            "https://gateway.ai.cloudflare.com/v1/acct123/mygw/compat/chat/completions",
            "acct123",
            "mygw",
            "workers-ai/@cf/meta/llama",
        ),
        (
            "https://gateway.ai.cloudflare.com/v1/acct9/gw9",
            "acct9",
            "gw9",
            "@cf/qwen/qwq-32b",
        ),
        ("barename", "a", "b", "openai/gpt-4o-mini"),
        ("https://example.com/other/path/", "acc", "gwn", "m1"),
        (
            "https://gateway.ai.cloudflare.com/v1/acctX/gwX/workers-ai/v1",
            "acctX",
            "gwX",
            "workers-ai/@cf/meta/llama-3.1-8b-instruct",
        ),
        ("", "acct0", "gw0", ""),
    ];
    for (url, acct, gw, model) in cases {
        let py = oracle(script, &[url, acct, gw, model]);
        assert_eq!(py["name"], cf::extract_gateway_name(url), "name {url:?}");
        assert_eq!(py["f1"], cf::build_format1_url(acct), "f1 {acct:?}");
        assert_eq!(py["f3"], cf::build_format3_url(acct, gw), "f3");
        assert_eq!(py["f2"], cf::build_format2_url(acct, gw, model), "f2");
    }
}

// Only this test touches PORTKEY_HEALTH_MODEL, so process-global env mutation
// here cannot race other tests (none of the others reach the env branch).
#[test]
fn parity_get_portkey_safe_model_env_paths() {
    let script = r#"
import json, sys
from torshield_ai_gateway import cf_compat_model_formatter as cf
print(json.dumps({"result": cf.get_portkey_safe_model(sys.argv[1])}, separators=(",", ":")))
"#;

    // 1) preferred already safe -> returned unchanged (env irrelevant).
    let py = oracle(script, &["gpt-4o-mini"]);
    std::env::remove_var("PORTKEY_HEALTH_MODEL");
    assert_eq!(py["result"], cf::get_portkey_safe_model("gpt-4o-mini"));

    // 2) preferred is @cf/, no env -> fallback[0].
    let py = oracle(script, &["@cf/meta/llama"]);
    std::env::remove_var("PORTKEY_HEALTH_MODEL");
    assert_eq!(py["result"], cf::get_portkey_safe_model("@cf/meta/llama"));
    assert_eq!(py["result"], "llama3.1-70b");

    // 3) preferred is @cf/, env set to a safe model -> env model.
    let py = oracle_env(
        script,
        &["@cf/meta/llama"],
        &[("PORTKEY_HEALTH_MODEL", "  meta/llama-3.1-70b-instruct  ")],
    );
    std::env::set_var("PORTKEY_HEALTH_MODEL", "  meta/llama-3.1-70b-instruct  ");
    assert_eq!(py["result"], cf::get_portkey_safe_model("@cf/meta/llama"));
    assert_eq!(py["result"], "meta/llama-3.1-70b-instruct");

    // 4) preferred is @cf/, env set to a cf model -> fallback[0].
    let py = oracle_env(
        script,
        &["@cf/meta/llama"],
        &[("PORTKEY_HEALTH_MODEL", "@cf/qwen/qwq-32b")],
    );
    std::env::set_var("PORTKEY_HEALTH_MODEL", "@cf/qwen/qwq-32b");
    assert_eq!(py["result"], cf::get_portkey_safe_model("@cf/meta/llama"));
    assert_eq!(py["result"], "llama3.1-70b");

    std::env::remove_var("PORTKEY_HEALTH_MODEL");
}
