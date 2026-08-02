//! Rust port of the `Remove Vercel secrets (cleanup — additive step)` inline
//! Python script that used to run inside `.github/workflows/torshield-ir.yml`
//! (`/tmp/_vercel_cleanup.py`).
//!
//! Contract preserved:
//!
//!   * Reads `GH_PAT_AUTOFIX`, `GH_REPO_OWNER`, `GH_REPO_NAME`; when any is
//!     missing it prints `Cleanup: missing PAT -- skipping` and exits 0.
//!   * Lists `GET /repos/{owner}/{repo}/actions/secrets` on the GitHub API
//!     (Bearer auth, api-version 2022-11-28, 15 s timeout) and DELETEs every
//!     secret whose name contains `VERCEL`.
//!   * Every failure mode is non-fatal (exit 0) — this is an additive
//!     cleanup step by design, exactly like the Python original.
//!
//! The HTTP portion requires the crate's `network` feature (`reqwest`
//! blocking client). A build without `network` stays a faithful no-op:
//! it explains that and exits 0.

use std::env;

/// True when a repository secret name is Vercel-related (case-insensitive
/// containment, same as `"VERCEL" in s.upper()` in Python).
pub fn is_vercel_secret(name: &str) -> bool {
    name.to_uppercase().contains("VERCEL")
}

/// Execute the cleanup; returns the process exit code (always 0 — additive).
#[cfg(feature = "network")]
pub fn run() -> i32 {
    let token = env::var("GH_PAT_AUTOFIX").unwrap_or_default();
    let owner = env::var("GH_REPO_OWNER").unwrap_or_default();
    let repo = env::var("GH_REPO_NAME").unwrap_or_default();
    if token.is_empty() || owner.is_empty() || repo.is_empty() {
        println!("Cleanup: missing PAT -- skipping");
        return 0;
    }
    let base = format!("https://api.github.com/repos/{owner}/{repo}/actions/secrets");

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("torshield-ir-vercel-cleanup")
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            println!("Cleanup: could not list secrets: {err}");
            return 0;
        }
    };

    let response = client
        .get(&base)
        .bearer_auth(&token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send();
    let body = match response.and_then(|r| r.error_for_status()) {
        Ok(ok) => match ok.json::<serde_json::Value>() {
            Ok(value) => value,
            Err(err) => {
                println!("Cleanup: could not list secrets: {err}");
                return 0;
            }
        },
        Err(err) => {
            println!("Cleanup: could not list secrets: {err}");
            return 0;
        }
    };

    let names: Vec<String> = body
        .get("secrets")
        .and_then(serde_json::Value::as_array)
        .map(|secrets| {
            secrets
                .iter()
                .filter_map(|s| s.get("name").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let vercel: Vec<&String> = names.iter().filter(|n| is_vercel_secret(n)).collect();
    for name in &vercel {
        let outcome = client
            .delete(format!("{base}/{name}"))
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send();
        match outcome {
            Ok(resp) if resp.status().is_success() => {
                println!("Deleted Vercel secret: {name}");
            }
            Ok(resp) => println!("Could not delete {name}: HTTP {}", resp.status()),
            Err(err) => println!("Could not delete {name}: {err}"),
        }
    }
    if vercel.is_empty() {
        println!("No Vercel secrets found -- nothing to clean up.");
    }
    0
}

/// No-network build: additive step degrades to a documented no-op (exit 0).
#[cfg(not(feature = "network"))]
pub fn run() -> i32 {
    let _ = env::var("GH_PAT_AUTOFIX");
    println!("Cleanup: built without the `network` feature -- skipping");
    0
}

/// CLI entry point.
pub fn entry(_args: &[String]) -> i32 {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vercel_name_matching() {
        assert!(is_vercel_secret("VERCEL_TOKEN"));
        assert!(is_vercel_secret("my-vercel-oidc"));
        assert!(is_vercel_secret("Vercel"));
        assert!(!is_vercel_secret("GH_PAT_AUTOFIX"));
        assert!(!is_vercel_secret("TELEGRAM_BOT_TOKEN"));
    }

    #[test]
    fn cleanup_is_additive_and_never_fails_the_build() {
        // Without env vars (and/or without the network feature) this must
        // exit 0, exactly like the Python original.
        assert_eq!(run(), 0);
    }
}
