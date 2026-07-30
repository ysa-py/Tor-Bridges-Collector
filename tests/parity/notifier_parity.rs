#![allow(warnings)]
// Differential parity tests for `src/notifier.rs` vs `core/notifier.py`.
//
// Covers the deterministic, network-free surface: `_enabled`, `_api`
// (URL construction), and the full `build_caption` Markdown template.
// The Python `build_caption` timestamp comes from `utc_now()`, which is
// monkeypatched to a fixed instant matching the Rust notifier's injected
// `now_iso`. The actual `send_message`/`send_document` HTTP calls perform
// real network I/O and are covered by the in-crate mock-API unit tests.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::notifier::{DisabledTelegramApi, TelegramNotifier};

const NOW_ISO: &str = "2026-06-28T12:34:00+00:00";
const TS_HUMAN: &str = "2026-06-28 12:34 UTC";

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!(
        "import json\n\
         from datetime import datetime, timezone\n\
         import core.notifier as nf\n\
         nf.utc_now = lambda: datetime(2026, 6, 28, 12, 34, 0, tzinfo=timezone.utc)\n\
         n = nf.TelegramNotifier()\n\
         {body}\n"
    );
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Do NOT trim: build_caption output is multi-line and internal layout
    // must be preserved. Only strip a single trailing newline from print().
    let s = String::from_utf8_lossy(&output.stdout);
    s.strip_suffix('\n').unwrap_or(&s).to_string()
}

fn notifier<'a>(token: &str, chat: &str, api: &'a DisabledTelegramApi) -> TelegramNotifier<'a> {
    TelegramNotifier::new(token, chat, 72, api, NOW_ISO.to_string())
}

#[test]
fn parity_enabled() {
    let api = DisabledTelegramApi;
    for (tok, chat) in [
        ("token123", "chat456"),
        ("", "chat456"),
        ("token123", ""),
        ("", ""),
    ] {
        let py = run_python(&format!(
            "n._token = r'''{tok}'''; n._chat = r'''{chat}'''; \
             print(str(n._enabled()).lower())"
        ));
        let n = notifier(tok, chat, &api);
        assert_eq!(py, n.enabled().to_string(), "enabled({tok:?},{chat:?})");
    }
}

#[test]
fn parity_api_url() {
    let api = DisabledTelegramApi;
    let n = notifier("BOTTOKEN:ABC-123", "chat", &api);
    for method in ["sendMessage", "sendDocument", "getMe"] {
        let py = run_python(&format!(
            "n._token = 'BOTTOKEN:ABC-123'; print(n._api(r'''{method}'''))"
        ));
        assert_eq!(py, n.api_url(method), "api_url({method})");
    }
}

fn assert_caption_parity(stats: &Value) {
    let api = DisabledTelegramApi;
    let n = notifier("token", "chat", &api);
    let compact = serde_json::to_string(stats).unwrap();
    let py = run_python(&format!(
        "print(n.build_caption(json.loads(r'''{compact}''')))"
    ));
    let rs = n.build_caption(stats);
    // Sanity: the injected timestamp must appear on both sides.
    assert!(rs.contains(TS_HUMAN), "rust caption missing timestamp");
    assert_eq!(py, rs, "build_caption for {stats}");
}

#[test]
fn parity_build_caption_full_stats() {
    assert_caption_parity(&json!({
        "by_transport": {
            "obfs4": 120, "webtunnel": 45, "snowflake": 300,
            "meek_lite": 12, "vanilla": 8
        },
        "passing": 210,
        "tested": 485
    }));
}

#[test]
fn parity_build_caption_empty_stats() {
    assert_caption_parity(&json!({}));
}

#[test]
fn parity_build_caption_partial_stats() {
    assert_caption_parity(&json!({
        "by_transport": {"snowflake": 5},
        "tested": 5
    }));
}
