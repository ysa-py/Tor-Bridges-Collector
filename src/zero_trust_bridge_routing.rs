use serde_json::{Value, json, Map};
use chrono::Utc;

pub fn calculate_zero_trust_score(record: &Map<String, Value>) -> f64 {
    let mut base = 0.5;
    if let Some(transport) = record.get("transport").and_then(Value::as_str) {
        base += match transport {
            "obfs4" => 0.2,
            "webtunnel" => 0.35,
            "snowflake" => 0.4,
            "v2ray" => 0.45,
            _ => 0.0,
        };
    }
    base.min(1.0)
}

pub fn generate_zero_trust_routing_table(bridges: &[Value]) -> Value {
    let mut results = Vec::new();
    for bridge in bridges {
        if let Some(obj) = bridge.as_object() {
            let score = calculate_zero_trust_score(obj);
            results.push(json!({
                "bridge": obj.get("raw").unwrap_or(&Value::Null),
                "zero_trust_score": score,
                "routing_priority": if score >= 0.8 { "High" } else { "Standard" }
            }));
        }
    }
    json!({
        "timestamp": Utc::now().to_rfc3339(),
        "zero_trust_routes": results,
        "engine": "TorShield Zero Trust Evasion Routing"
    })
}

fn main() {
    println!("Zero Trust Bridge Routing Engine compiled successfully.");
}
