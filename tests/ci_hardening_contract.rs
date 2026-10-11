//! Workflow hardening contract: PR vs main isolation, least privilege,
//! pinned toolchain, locked cargo, and honest publication verify-only.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(err) => panic!("read {rel}: {err}"),
    }
}

#[test]
fn torshield_does_not_share_main_concurrency_with_prs() {
    let yml = read(".github/workflows/torshield-ir.yml");
    assert!(
        !yml.contains("pull_request.base.ref"),
        "PRs must not join the main hourly concurrency group"
    );
    assert!(yml.contains("github.event_name"));
    assert!(yml.contains("cancel-in-progress: false"));
}

#[test]
fn torshield_least_privilege_and_no_node_warning_mute() {
    let yml = read(".github/workflows/torshield-ir.yml");
    assert!(
        !yml.contains("NODE_NO_WARNINGS"),
        "do not mute Node warnings"
    );
    assert!(yml.contains("contents: read"));
    assert!(yml.contains("actions: write"));
    assert!(yml.contains("cargo clippy --locked"));
    assert!(yml.contains("toolchain: '1.90.0'"));
    assert!(yml.contains("if-no-files-found: error"));
}

#[test]
fn rust_toolchain_file_pins_stable_release() {
    let toml = read("rust-toolchain.toml");
    assert!(toml.contains("channel = \"1.90.0\""));
    assert!(toml.contains("rustfmt"));
    assert!(toml.contains("clippy"));
}

#[test]
fn cleanup_never_deletes_off_main() {
    let yml = read(".github/workflows/ai-ultra-pro-cleanup.yml");
    assert!(yml.contains("dry_run: true"));
    assert!(yml.contains("Refusing to delete workflow runs off main"));
}

#[test]
fn pr_publication_declares_missing_bridge_contract() {
    let yml = read(".github/workflows/torshield-ir.yml");
    assert!(yml.contains("--verify-only"));
    assert!(yml.contains("none committed"));
    assert!(yml.contains("--check-contract"));
    assert!(yml.contains("validation_noop does not invent"));
}

#[test]
fn c14_requires_locked_main_only_pipeline() {
    let script = read("scripts/verify_repo_invariants.sh");
    assert!(script.contains(
        "cargo run --locked --release --bin pipeline -- --all"
    ));
    let yml = read(".github/workflows/main-ci.yml");
    assert!(yml.contains(
        "run: cargo run --locked --release --bin pipeline -- --all"
    ));
    assert!(yml.contains(
        "if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"
    ));
}


#[test]
fn self_heal_normalizes_missing_audit_counts_before_numeric_use() {
    let script = read("scripts/self_heal.sh");
    assert!(
        script.contains("if [[ \"${VCOUNT_RAW:-}\" =~ ^[0-9]+$ ]]"),
        "audit count must be validated as a non-negative integer"
    );
    assert!(
        script.contains("--argjson vulnerabilities \"${VCOUNT}\""),
        "diagnostics JSON must receive a validated number, not tonumber of a string"
    );
    assert!(
        !script.contains("($vcount|tonumber)"),
        "empty audit counts must not trigger jq tonumber errors"
    );
}


#[test]
fn self_heal_fails_closed_when_audit_count_is_unavailable() {
    let script = read("scripts/self_heal.sh");
    assert!(
        script.contains("AUDIT_COUNT_VALID=false"),
        "audit parsing must start in an unverified state"
    );
    assert!(
        script.contains("EXIT_CODE=1"),
        "missing or invalid audit evidence must fail validation"
    );
    assert!(
        script.contains("error(\"missing or invalid vulnerability count\")"),
        "unexpected cargo-audit JSON schemas must be reported, not silently treated as zero"
    );
    assert!(
        script.contains("AUDIT_JSON_STATUS"),
        "cargo-audit execution failures must be retained for diagnostics"
    );
}


#[test]
fn probe_relay_canary_uses_only_a_wrangler_reported_workers_dev_fallback() {
    let yml = read(".github/workflows/torshield-ir.yml");
    assert!(
        yml.contains("WORKERS_DEV_URL=\\"$(grep -Eo"),
        "fallback URL must be extracted from the successful Wrangler deployment log"
    );
    assert!(
        yml.contains("export PROBE_RELAY_URL"),
        "the canary must receive the validated fallback endpoint"
    );
    assert!(
        yml.contains("Wrangler-reported workers.dev endpoint"),
        "the workflow must make fallback selection observable"
    );
    assert!(
        !yml.contains("tor-bridge-probe-relay.workers.dev"),
        "never guess the account-specific workers.dev hostname"
    );
}
