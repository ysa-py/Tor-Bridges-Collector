#![allow(warnings)]
// Differential parity tests for `src/self_heal.rs` vs `self_heal.py`.
//
// Covers the pure, deterministic, security-relevant helpers:
//   * `_redact_secret_text` — credential scrubbing regexes
//   * `_build_limited_diff` — unified-diff generation + size/line caps
//   * `_is_allowed_patch_target` — patch-target allowlist / denylist
//
// The AI/HTTP functions (`_http_post`, `_call_portkey/_cerebras/_groq`,
// `_ask_ai`, `apply_patch`, `commit_patches`) perform network / git / FS
// side effects and are covered by in-crate mock/trait unit tests, not
// differentially.
//
// `_is_allowed_patch_target` depends on `_repo_root()`. This repo is not a
// git checkout, so Python's `_repo_root()` falls back to `cwd`
// (== CARGO_MANIFEST_DIR); the Rust port takes `repo_root` explicitly, so
// both sides are aligned on the same root and the comparison is exact.

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use torshield_ir_ultra::self_heal::{
    build_limited_diff, is_allowed_patch_target, redact_secret_text,
};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!("import json\nfrom pathlib import Path\nimport self_heal as s\n{body}\n");
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
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn parity_redact_secret_text() {
    let cases = [
        "clone https://user:pass@github.com/x/y.git",
        "Authorization: Bearer sk-abcdef123456",
        "authorization:   bearer   TOKENVALUE",
        "x-access-token:ghp_secretvalue@github.com",
        "no secrets here, just text",
        "multi https://a:b@h.com and Authorization: Bearer XYZ and x-access-token:qqq foo",
        "https://:@host.com edge",
        "",
    ];
    for v in cases {
        let py = run_python(&format!(
            "print(json.dumps(s._redact_secret_text(r'''{v}''')))"
        ));
        let py_val: Value = serde_json::from_str(&py).unwrap();
        assert_eq!(
            py_val,
            Value::String(redact_secret_text(v)),
            "redact for {v:?}"
        );
    }
}

#[test]
fn parity_build_limited_diff() {
    // (path_posix, original, fixed)
    let cases: &[(&str, &str, &str)] = &[
        (
            "core/x.py",
            "line1\nline2\nline3\n",
            "line1\nline2 changed\nline3\n",
        ),
        ("main.py", "a\nb\nc\n", "a\nb\nc\n"), // identical -> None
        ("sources/moat.py", "", "new content\nsecond\n"), // creation
        ("core/y.py", "old only\n", ""),       // deletion
        ("z.py", "keep\nremove me\nkeep2\n", "keep\nkeep2\n"), // removal
        (
            "core/multi.py",
            "l1\nl2\nl3\nl4\nl5\n",
            "l1\nL2\nl3\nL4\nl5\n",
        ), // multiple hunks-ish
    ];
    for (p, orig, fixed) in cases {
        let py = run_python(&format!(
            "print(json.dumps(s._build_limited_diff(Path(r'''{p}'''), r'''{orig}''', r'''{fixed}''')))"
        ));
        let py_val: Value = serde_json::from_str(&py).unwrap();
        let rs_val = match build_limited_diff(p, orig, fixed) {
            Some(d) => Value::String(d),
            None => Value::Null,
        };
        assert_eq!(py_val, rs_val, "build_limited_diff for {p}");
    }
}

#[test]
fn parity_is_allowed_patch_target() {
    let paths = [
        "main.py",
        "core/scorer.py",
        "sources/moat.py",
        "core/deep/nested.py",
        "notpython.txt",
        "core/config.yaml",
        ".github/workflows/ci.py",
        "configs/thing.py",
        "infra/deploy.py",
        "secrets/leak.py",
        "core/secret_helper.py",
        "core/token.py",
        "core/my_key.py",
        "core/env.py",
        "core/normal_module.py",
        "docs/readme.py",
        "../escape.py",
        "tools/util.py",
    ];
    for p in paths {
        let py = run_python(&format!(
            "print(str(s._is_allowed_patch_target(r'''{p}''')).lower())"
        ));
        let rs = is_allowed_patch_target(Path::new(p), repo_root()).to_string();
        assert_eq!(py, rs, "is_allowed_patch_target({p})");
    }
}
