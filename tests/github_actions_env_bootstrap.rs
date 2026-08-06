#![cfg(unix)]

//! Regression coverage for the GitHub Actions environment adapter.
//!
//! Empty proxy defaults must not be copied into `GITHUB_ENV`: Node-based
//! actions treat an empty proxy variable as a malformed proxy URL, which can
//! prevent the Zig installer and later network stages from starting. The
//! shared CircleCI bootstrap still receives the complete template; only the
//! GitHub Actions export is intentionally filtered.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_root() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "torshield-github-env-bootstrap-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create bootstrap fixture directory");
    root
}

#[test]
fn empty_proxy_defaults_are_not_exported_to_github_env() {
    let root = fixture_root();
    let env_file = root.join("runtime.env");
    let template = root.join("template.sh");
    let github_env = root.join("github.env");
    std::fs::write(
        &template,
        "HTTP_PROXY=\"\"\nHTTPS_PROXY=\"\"\nSAFE_VALUE=\"present\"\n",
    )
    .expect("write bootstrap template");

    let output = Command::new("bash")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/github_actions_env_bootstrap.sh"
        ))
        .arg(&env_file)
        .arg(&template)
        // The adapter intentionally follows the repository's relative
        // `scripts/circleci_env_bootstrap.sh` path, so execute it from the
        // checkout while keeping every generated fixture outside the tree.
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("GITHUB_ENV", &github_env)
        // Do not let a runner-level proxy turn the template defaults into
        // Context overrides; this test is specifically about empty defaults.
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .output()
        .expect("spawn GitHub Actions bootstrap");
    assert!(
        output.status.success(),
        "bootstrap failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let exported = std::fs::read_to_string(&github_env).expect("read GITHUB_ENV fixture");
    assert!(
        !exported
            .lines()
            .any(|line| line.starts_with("HTTP_PROXY<<") || line.starts_with("HTTPS_PROXY<<")),
        "empty proxy variables must not be materialised in GITHUB_ENV:\n{exported}"
    );
    assert!(exported.contains("SAFE_VALUE<<"));
    assert!(exported.contains("present"));

    let _ = std::fs::remove_dir_all(root);
}
