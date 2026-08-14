//! `vantage_probe` — run one in-country measurement adapter against its live
//! endpoint. This is the **manual, out-of-CI verification entry point**
//! referenced by the Item 4 gate table, not a test and not a fixture.
//!
//! It makes a REAL network call to the configured platform (Globalping /
//! RIPE Atlas / OONI / volunteer agent) and prints the normalized result as
//! JSON. Nothing here is mocked or hardcoded: if the platform cannot be
//! reached, the adapter returns its typed error.
//!
//! ## Examples
//!
//! ```text
//! # Globalping control-plane API (reachable from any host with egress; the
//! # measurement itself runs on Globalping's global probe network, NOT an
//! # Iranian vantage — see the Item 4 gate table for the honest boundary):
//! cargo run -p tbc-vantage --example vantage_probe -- \
//!   --adapter globalping --target 1.2.3.4 --probe-kind tcp_connect
//!
//! # OONI open data for probe_cc=IR (historical measurements taken by
//! # volunteers inside Iran; the closest in-country signal available in CI):
//! cargo run -p tbc-vantage --example vantage_probe -- \
//!   --adapter ooni --target example.com --country IR
//!
//! # RIPE Atlas one-off ping from an in-country probe (requires credits):
//! RIPE_ATLAS_API_KEY=<key> cargo run -p tbc-vantage --example vantage_probe -- \
//!   --adapter ripe_atlas --target 1.2.3.4 --country IR
//!
//! # Volunteer agent (must point at a running tbc-agent from inside the
//! # target country):
//! cargo run -p tbc-vantage --example vantage_probe -- \
//!   --adapter agent --target 1.2.3.4 --port 443 \
//!   --base-url http://127.0.0.1:8080
//! ```

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use tbc_core::ProbeKind;
use tbc_vantage::{
    AgentVantage, Budget, GlobalpingVantage, MeasurementRequest, OoniVantage, ReqwestTransport,
    RipeAtlasVantage, Vantage, VantageConfig,
};

#[derive(Debug)]
struct Args {
    adapter: String,
    target: String,
    port: u16,
    probe_kind: ProbeKind,
    country: Option<String>,
    base_url: Option<String>,
    api_key: Option<String>,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut adapter: Option<String> = None;
    let mut target: Option<String> = None;
    let mut port: u16 = 443;
    let mut probe_kind: Option<ProbeKind> = None;
    let mut country: Option<String> = None;
    let mut base_url: Option<String> = None;
    let mut api_key: Option<String> = None;

    let mut index = 0usize;
    while index < argv.len() {
        let flag = argv[index].as_str();
        let value = |index: &mut usize, argv: &[String]| -> Result<String, String> {
            *index += 1;
            argv.get(*index)
                .cloned()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag {
            "--adapter" => adapter = Some(value(&mut index, argv)?),
            "--target" => target = Some(value(&mut index, argv)?),
            "--port" => {
                let raw = value(&mut index, argv)?;
                port = raw
                    .parse()
                    .map_err(|_| format!("--port must be an integer, got {raw:?}"))?;
            }
            "--probe-kind" => {
                let raw = value(&mut index, argv)?;
                probe_kind = Some(
                    serde_json::from_str::<ProbeKind>(&format!("\"{raw}\""))
                        .map_err(|_| format!("unknown --probe-kind {raw:?}"))?,
                );
            }
            "--country" => country = Some(value(&mut index, argv)?),
            "--base-url" => base_url = Some(value(&mut index, argv)?),
            "--api-key" => api_key = Some(value(&mut index, argv)?),
            other => return Err(format!("unknown argument {other:?}")),
        }
        index += 1;
    }

    Ok(Args {
        adapter: adapter.ok_or_else(|| "missing required --adapter".to_owned())?,
        target: target.ok_or_else(|| "missing required --target".to_owned())?,
        port,
        probe_kind: probe_kind.unwrap_or(ProbeKind::TcpConnect),
        country,
        base_url,
        api_key,
    })
}

fn usage() -> String {
    "vantage_probe — run one in-country measurement adapter against its live endpoint\n\
     \n\
     USAGE:\n\
     \x20 vantage_probe --adapter <globalping|ripe_atlas|ooni|agent> --target <host-or-ip> \\\n\
     \x20   [--port <1..=65535>] [--probe-kind <tcp_connect|obfs4_handshake|webtunnel_upgrade|tls_sni|tcp_traceroute|tor_bootstrap>] \\\n\
     \x20   [--country <ISO-3166-1 alpha-2>] [--base-url <override>] [--api-key <key>]\n\
     \n\
     RIPE Atlas additionally reads RIPE_ATLAS_API_KEY from the environment.\n"
        .to_owned()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        eprintln!("{}", usage());
        return Ok(());
    }
    let args = parse_args(&argv).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{error}\n{}", usage()),
        )
    })?;

    let mut config = VantageConfig {
        timeout: Duration::from_secs(30),
        ..VantageConfig::default()
    };
    if let Some(base_url) = args.base_url.clone() {
        match args.adapter.as_str() {
            "globalping" => config.globalping_base_url = base_url,
            "ripe_atlas" | "ripe" => config.ripe_atlas_base_url = base_url,
            "ooni" => config.ooni_base_url = base_url,
            "agent" => config.agent_base_url = base_url,
            _ => {}
        }
    }

    let transport = Arc::new(ReqwestTransport::new(
        config.timeout,
        "tbc-vantage-probe/0.1.0",
    )?);
    let mut budget = Budget::new(config.quota_limit);
    let request = MeasurementRequest {
        target: args.target.clone(),
        port: args.port,
        probe_kind: args.probe_kind,
        country: args.country.clone(),
        asn: None,
    };

    let result = match args.adapter.as_str() {
        "globalping" => {
            let adapter = GlobalpingVantage::new(
                config.globalping_base_url.clone(),
                transport,
                config.max_polls,
                config.poll_interval,
            )?;
            adapter.run(&request, &mut budget).await?
        }
        "ripe_atlas" | "ripe" => {
            let api_key = args.api_key.clone().or_else(|| {
                std::env::var("RIPE_ATLAS_API_KEY")
                    .ok()
                    .filter(|v| !v.is_empty())
            });
            let adapter = RipeAtlasVantage::new(
                config.ripe_atlas_base_url.clone(),
                transport,
                api_key,
                config.default_country.clone(),
                config.max_polls,
                config.poll_interval,
            )?;
            adapter.run(&request, &mut budget).await?
        }
        "ooni" => {
            let adapter = OoniVantage::new(
                config.ooni_base_url.clone(),
                transport,
                config.default_country.clone(),
                10,
            )?;
            adapter.run(&request, &mut budget).await?
        }
        "agent" => {
            let adapter = AgentVantage::new(config.agent_base_url.clone(), transport)?;
            adapter.run(&request, &mut budget).await?
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown adapter {other:?} (expected globalping, ripe_atlas, ooni, agent)"),
            )
            .into())
        }
    };

    let output = serde_json::json!({
        "adapter": args.adapter,
        "target": args.target,
        "probe_kind": args.probe_kind,
        "verdict": serde_json::to_value(&result.verdict)?,
        "rtt_ms": result.rtt_ms,
        "error_class": result.error_class,
        "raw_evidence": result.raw_evidence,
        "measurement_ref": result.measurement_ref,
        "measured_at": result.measured_at.to_rfc3339(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
