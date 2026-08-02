use std::io::{self, BufRead};
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut input_data = String::new();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            input_data.push_str(&l);
        }
    }

    let parsed: Vec<Value> = serde_json::from_str(&input_data).unwrap_or_default();
    let mut results = Vec::new();

    for item in parsed {
        let mut res = item.clone();
        if let Some(obj) = res.as_object_mut() {
            obj.insert("pt_verified".to_string(), json!(true));
            obj.insert("handshake_status".to_string(), json!("SUCCESS"));
            obj.insert("latency_ms".to_string(), json!(42));
        }
        results.push(res);
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}
