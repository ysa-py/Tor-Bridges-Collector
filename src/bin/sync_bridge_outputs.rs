//! Publish and optionally deliver the complete TorShield-IR bridge package.
//!
//! This binary is the only publication entry point used by
//! `.github/workflows/torshield-ir.yml`.  It builds one verified archive from
//! the canonical `bridge/` directory; Telegram, GitHub artifacts, and the git
//! commit therefore use identical bytes rather than independently generated
//! ZIP files.

use std::env;
use std::io;
use std::path::PathBuf;
#[cfg(feature = "network")]
use std::thread;
#[cfg(feature = "network")]
use std::time::Duration;

use torshield_ir_ultra::bridge_publication::{publish, verify_publication, PublishOptions};
use torshield_ir_ultra::publication_changelog::{append_entry, ChangelogEntry};

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn usage() -> &'static str {
    "Usage: sync_bridge_outputs [OPTIONS]\n\
     \n\
     Rebuilds and verifies every public bridge file, README.md, and\n\
     bridge/tor_bridges.zip. Telegram delivery is disabled unless explicitly\n\
     requested.\n\
     \n\
     Options:\n\
       --bridge-dir PATH          Bridge directory (default: bridge)\n\
       --readme PATH              README to render (default: README.md)\n\
       --repo-url URL             Raw GitHub URL prefix (default: REPO_URL or main)\n\
       --recent-hours N           Freshness window, default: 72\n\
       --telegram-upload BOOL     Upload the verified ZIP after publication\n\
       --telegram-token TOKEN     Overrides TELEGRAM_BOT_TOKEN\n\
       --telegram-chat-id ID      Overrides TELEGRAM_CHAT_ID\n\
       --retries N                Telegram retries, default: 3\n\
       --verify-only              Validate current files; do not rewrite them\n\
       --help                     Print this help"
}

#[derive(Debug)]
struct Options {
    publication: PublishOptions,
    telegram_upload: bool,
    telegram_token: String,
    telegram_chat_id: String,
    retries: u32,
    verify_only: bool,
}

fn parse_bool(value: &str, flag: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(invalid(format!(
            "{flag} must be true or false, got {value:?}"
        ))),
    }
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| invalid(format!("{flag} requires a value")))
}

fn parse_args() -> Result<Options, Box<dyn std::error::Error>> {
    let mut publication = PublishOptions::default();
    publication.repo_url = env::var("REPO_URL").unwrap_or(publication.repo_url);
    let mut telegram_upload = parse_bool(
        &env::var("TELEGRAM_UPLOAD").unwrap_or_else(|_| "false".to_string()),
        "TELEGRAM_UPLOAD",
    )?;
    let mut telegram_token = env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let mut telegram_chat_id = env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
    let mut retries = 3_u32;
    let mut verify_only = false;

    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--bridge-dir" => {
                publication.bridge_dir = PathBuf::from(next_value(&mut args, "--bridge-dir")?)
            }
            "--readme" => {
                publication.readme_path = PathBuf::from(next_value(&mut args, "--readme")?)
            }
            "--repo-url" => publication.repo_url = next_value(&mut args, "--repo-url")?,
            "--recent-hours" => {
                publication.recent_hours = next_value(&mut args, "--recent-hours")?
                    .parse::<i64>()
                    .map_err(|_| invalid("--recent-hours must be a positive integer"))?;
            }
            "--telegram-upload" => {
                telegram_upload = parse_bool(
                    &next_value(&mut args, "--telegram-upload")?,
                    "--telegram-upload",
                )?;
            }
            "--telegram-token" => telegram_token = next_value(&mut args, "--telegram-token")?,
            "--telegram-chat-id" => telegram_chat_id = next_value(&mut args, "--telegram-chat-id")?,
            "--retries" => {
                retries = next_value(&mut args, "--retries")?
                    .parse::<u32>()
                    .map_err(|_| invalid("--retries must be a non-negative integer"))?;
            }
            "--verify-only" => verify_only = true,
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            unknown => return Err(invalid(format!("unknown argument: {unknown}\n{}", usage()))),
        }
    }

    if publication.recent_hours <= 0 {
        return Err(invalid("--recent-hours must be positive"));
    }
    Ok(Options {
        publication,
        telegram_upload,
        telegram_token,
        telegram_chat_id,
        retries,
        verify_only,
    })
}

#[cfg(feature = "network")]
fn telegram_upload(
    token: &str,
    chat_id: &str,
    archive_path: &std::path::Path,
    caption: &str,
    retries: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if token.trim().is_empty() || chat_id.trim().is_empty() {
        return Err(invalid(
            "Telegram upload was requested but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is empty",
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(75))
        .build()?;
    let url = format!("https://api.telegram.org/bot{token}/sendDocument");
    let attempts = retries.max(1);
    let archive = std::fs::read(archive_path)?;
    let filename = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tor_bridges.zip");

    for attempt in 1..=attempts {
        // A boundary generated from a timestamp and attempt number cannot
        // collide with our binary ZIP payload in practice; the token itself is
        // never printed or embedded in diagnostics.
        let boundary = format!(
            "----TorShieldIR{}{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
            attempt
        );
        let mut body = Vec::with_capacity(archive.len() + 2048);
        for (key, value) in [("chat_id", chat_id), ("caption", caption)] {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\nContent-Type: application/zip\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&archive);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        match client
            .post(&url)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
        {
            Ok(response) if response.status().is_success() => {
                let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
                if payload.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                    println!("telegram delivery succeeded on attempt {attempt}/{attempts}");
                    return Ok(());
                }
                eprintln!("telegram delivery returned an unsuccessful API response on attempt {attempt}/{attempts}");
            }
            Ok(response) => {
                eprintln!(
                    "telegram delivery returned HTTP {} on attempt {attempt}/{attempts}",
                    response.status()
                );
            }
            Err(error) => {
                eprintln!("telegram delivery attempt {attempt}/{attempts} failed: {error}");
            }
        }
        if attempt < attempts {
            thread::sleep(Duration::from_secs(u64::from((attempt * 3).min(15))));
        }
    }
    Err(invalid("Telegram delivery failed after all retry attempts"))
}

#[cfg(not(feature = "network"))]
fn telegram_upload(
    _: &str,
    _: &str,
    _: &std::path::Path,
    _: &str,
    _: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(invalid(
        "Telegram upload requires the Rust `network` feature; rerun with --features network",
    ))
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("sync_bridge_outputs: {error}");
        std::process::exit(2);
    });

    if options.verify_only {
        if let Err(error) = verify_publication(&options.publication) {
            eprintln!("sync_bridge_outputs: verification failed: {error}");
            std::process::exit(1);
        }
        println!(
            "sync_bridge_outputs: verified {}",
            options.publication.bridge_dir.display()
        );
        return;
    }

    let report = publish(&options.publication).unwrap_or_else(|error| {
        eprintln!("sync_bridge_outputs: publication failed: {error}");
        std::process::exit(1);
    });
    println!(
        "sync_bridge_outputs: published {} history records and {} probe records; archive={} sha256={} entries={}",
        report.history_records,
        report.probe_records,
        report.archive_path.display(),
        report.archive_sha256,
        report.archive_entries,
    );

    // Directive v37 §1: commit a machine-readable, timestamped changelog with
    // the verified publication. Evidence tier/result counts come from the
    // stamped iran_results.json when present; a missing or unparsable
    // evidence block is reported loudly but does not fail the publication.
    let changelog_path = PathBuf::from("data").join("publication_changelog.json");
    let (tiers, results) = load_stamp_evidence(&options.publication.bridge_dir);
    if let Err(error) = append_entry(
        &changelog_path,
        ChangelogEntry {
            run_timestamp: report.generated_at.to_rfc3339(),
            producer: "sync_bridge_outputs".to_string(),
            archive_sha256: report.archive_sha256.clone(),
            history_records: report.history_records,
            probe_records: report.probe_records,
            file_counts: report.file_counts.clone(),
            tiers,
            results,
            status: "ok".to_string(),
        },
    ) {
        eprintln!(
            "sync_bridge_outputs: changelog append to {} failed: {error}",
            changelog_path.display()
        );
        std::process::exit(1);
    }
    println!(
        "sync_bridge_outputs: changelog entry appended to {}",
        changelog_path.display()
    );

    if options.telegram_upload {
        let working = report
            .file_counts
            .get("iran_likely_working_all.txt")
            .copied()
            .unwrap_or(0);
        let caption = format!(
            "TorShield-IR verified bridge package\n\
             advisory working entries: {working}\n\
             archive SHA-256: {}\n\
             Evidence is runner-side and advisory; see telegram_manifest.json.",
            report.archive_sha256
        );
        if let Err(error) = telegram_upload(
            &options.telegram_token,
            &options.telegram_chat_id,
            &report.archive_path,
            &caption,
            options.retries,
        ) {
            eprintln!("sync_bridge_outputs: {error}");
            std::process::exit(1);
        }
    }
}

/// Read the evidence tier/result counts stamped into `iran_results.json` by
/// the results stage (see `src/evidence_stamp.rs`). Missing or malformed
/// evidence is reported to stderr and returns empty maps; the publication
/// itself is unaffected.
fn load_stamp_evidence(
    bridge_dir: &std::path::Path,
) -> (
    std::collections::BTreeMap<String, usize>,
    std::collections::BTreeMap<String, usize>,
) {
    let path = bridge_dir.join("iran_results.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "sync_bridge_outputs: no stamp evidence available ({}): {error}",
                path.display()
            );
            return (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            );
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(doc) => doc,
        Err(error) => {
            eprintln!(
                "sync_bridge_outputs: stamp evidence unparsable ({}): {error}",
                path.display()
            );
            return (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            );
        }
    };
    let evidence = doc.get("evidence");
    let tiers = evidence
        .and_then(|e| e.get("tiers"))
        .and_then(serde_json::Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as usize)))
                .collect()
        })
        .unwrap_or_default();
    let results = evidence
        .and_then(|e| e.get("results"))
        .and_then(serde_json::Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as usize)))
                .collect()
        })
        .unwrap_or_default();
    (tiers, results)
}
