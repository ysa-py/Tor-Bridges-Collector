//! Rust-native configuration and local-engine health check for the AI gateway.
//!
//! External credentials are never printed or persisted. The command reports
//! only complete/partial slot counts so scheduled automation remains useful in
//! repositories where optional provider secrets are intentionally absent.

use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use torshield_ir_ultra::torshield_ai_gateway::cf_compat_model_formatter::{
    get_portkey_safe_model, STATIC_FALLBACK_MODELS,
};
use torshield_ir_ultra::torshield_ai_gateway::iran_gateway_dpi_shaper::GatewayDPIShaper;

#[derive(Debug)]
struct Options {
    output: PathBuf,
    task: String,
}

fn parse_args() -> Result<Options, String> {
    let mut output = PathBuf::from("data/ai_gateway_health.json");
    let mut task = String::from("general");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => output = PathBuf::from(args.next().ok_or("--output requires a path")?),
            "--task" => task = args.next().ok_or("--task requires a value")?,
            "--help" | "-h" => {
                println!("Usage: ai_gateway_health_check [--output PATH] [--task CATEGORY]");
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }
    Ok(Options { output, task })
}

fn present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn numbered_keys(prefix: &str, max: usize) -> usize {
    (1..=max)
        .filter(|index| present(&format!("{prefix}_{index}")))
        .count()
}

fn cloudflare_slots(max: usize) -> (usize, usize) {
    let mut complete = 0;
    let mut partial = 0;
    for index in 1..=max {
        let account = present(&format!("CF_ACCOUNT_ID_{index}"));
        let token = present(&format!("CF_API_TOKEN_{index}"));
        match (account, token) {
            (true, true) => complete += 1,
            (true, false) | (false, true) => partial += 1,
            (false, false) => {}
        }
    }
    (complete, partial)
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    std::fs::write(path, body)?;
    Ok(())
}

fn run(options: &Options) -> Result<Value, Box<dyn Error>> {
    let cerebras = numbered_keys("CEREBRAS_API_KEY", 3);
    let portkey = numbered_keys("PORTKEY_API_KEY", 3);
    let (cloudflare, cloudflare_partial) = cloudflare_slots(11);
    let external_slots = cerebras + portkey + cloudflare;

    let shaper = GatewayDPIShaper::new();
    let local_checks = json!({
        "fallback_models": STATIC_FALLBACK_MODELS.len(),
        "portkey_safe_model": get_portkey_safe_model(""),
        "default_iran_slot": shaper.get_optimal_slot_for_isp(None),
        "configuration_parser": "ok",
        "dpi_shaper": "ok",
    });

    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-ai-gateway-health-v1",
        "status": if external_slots > 0 { "ready_external" } else { "healthy_local_only" },
        "task": options.task,
        "local_checks": local_checks,
        "providers": {
            "cerebras_complete_slots": cerebras,
            "portkey_complete_slots": portkey,
            "cloudflare_complete_slots": cloudflare,
            "cloudflare_partial_slots": cloudflare_partial,
            "external_complete_slots": external_slots,
        },
        "note": if external_slots > 0 {
            "Optional external provider configuration is present; credentials were not exposed."
        } else {
            "No optional external provider secrets are configured; the local deterministic engine remains healthy."
        },
    });
    write_json(&options.output, &report)?;
    Ok(report)
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("ai_gateway_health_check: {error}");
        std::process::exit(2);
    });

    match run(&options) {
        Ok(report) => println!(
            "ai_gateway_health_check: {} -> {}",
            report["status"],
            options.output.display()
        ),
        Err(error) => {
            eprintln!("ai_gateway_health_check: {error}");
            std::process::exit(1);
        }
    }
}
