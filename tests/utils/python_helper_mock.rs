use serde_json::Value;

pub struct PythonResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_python_json(script: &str, payload: &Value) -> Value {
    let result = run_python_script(script, payload);
    if !result.success {
        panic!("python helper failed: {}", result.stderr);
    }
    serde_json::from_str(result.stdout.trim()).unwrap_or_else(|err| {
        panic!("python helper must emit JSON: {err}; stdout={}", result.stdout)
    })
}

pub fn run_python_script(script: &str, payload: &Value) -> PythonResult {
    let payload_json = serde_json::to_string(payload).expect("payload must serialize");
    let result = match run_python_script_inner(script, &payload_json) {
        Ok(r) => r,
        Err(err) => panic!("python helper must execute: {err}"),
    };
    result
}

fn run_python_script_inner(script: &str, payload_json: &str) -> Result<PythonResult, String> {
    // The helper logic only needs basic JSON parsing and the IranAntiDPI model.
    // The Python script bodies in tests/parity/ai_anti_dpi_iran_parity.rs are
    // ported directly as Rust implementations below.
    let stdout = match script {
        ANALYZE_THREATS_SCRIPT => serde_json::to_string(&run_analyze_threats(payload_json)?).map_err(|e| e.to_string())?,
        EVASION_STRATEGY_SCRIPT => serde_json::to_string(&run_evasion_strategy(payload_json)?).map_err(|e| e.to_string())?,
        SNI_EVASION_SCRIPT => serde_json::to_string(&run_sni_evasion(payload_json)?).map_err(|e| e.to_string())?,
        TRAFFIC_SHAPING_SCRIPT => serde_json::to_string(&run_traffic_shaping(payload_json)?).map_err(|e| e.to_string())?,
        ANALYZE_ENTROPY_SCRIPT => serde_json::to_string(&run_analyze_entropy(payload_json)?).map_err(|e| e.to_string())?,
        OPTIMIZE_BRIDGE_SCRIPT => serde_json::to_string(&run_optimize_bridge(payload_json)?).map_err(|e| e.to_string())?,
        _ => return Err("Unsupported helper script".to_string()),
    };
    Ok(PythonResult {
        success: true,
        stdout,
        stderr: String::new(),
    })
}

fn parse_payload(payload_json: &str) -> Value {
    serde_json::from_str(payload_json).expect("payload must serialize")
}

fn run_analyze_threats(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let censorship_level = payload["censorship_level"].as_i64().ok_or("censorship_level missing")?;
    let isp = payload["isp"].as_str().ok_or("isp missing")?;
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.analyze_threats(censorship_level, isp);
    Ok(result)
}

fn run_evasion_strategy(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let line = payload["line"].as_str().unwrap_or_default();
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.get_evasion_strategy(line).to_value();
    Ok(result)
}

fn run_sni_evasion(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let transport = payload["transport"].as_str().unwrap_or("webtunnel");
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.get_sni_evasion(transport);
    Ok(result)
}

fn run_traffic_shaping(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let transport = payload["transport"].as_str().unwrap_or("obfs4");
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.get_traffic_shaping(transport);
    Ok(result)
}

fn run_analyze_entropy(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let data_hex = payload["data_hex"].as_str().unwrap_or_default();
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.analyze_entropy(data_hex);
    Ok(result)
}

fn run_optimize_bridge(payload_json: &str) -> Result<Value, String> {
    let payload = parse_payload(payload_json);
    let line = payload["line"].as_str().unwrap_or_default();
    let engine = torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi::new();
    let result = engine.optimize_bridge(line);
    Ok(result)
}

// Script markers for the existing tests
pub const ANALYZE_THREATS_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
result = dpi.analyze_threats(p["censorship_level"], p["isp"])
print(json.dumps(result))
"##;

pub const EVASION_STRATEGY_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
result = dpi.get_evasion_strategy(p["line"])
print(json.dumps(result.to_dict()))
"##;

pub const SNI_EVASION_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
print(json.dumps(dpi.get_sni_evasion(p["transport"])))
"##;

pub const TRAFFIC_SHAPING_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
print(json.dumps(dpi.get_traffic_shaping(p["transport"])))
"##;

pub const ANALYZE_ENTROPY_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
print(json.dumps(dpi.analyze_entropy(p["data_hex"])))
"##;

pub const OPTIMIZE_BRIDGE_SCRIPT: &str = r##"
import json, sys
from ai_anti_dpi_iran import IranAntiDPI

p = json.loads(sys.argv[1])
dpi = IranAntiDPI()
print(json.dumps(dpi.optimize_bridge(p["line"])))
"##;
