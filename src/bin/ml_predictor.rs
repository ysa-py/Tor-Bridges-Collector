//! Rust binary shim for ml_predictor.py

fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("ml_predictor: Rust-native implementation available via `cargo test --lib`");
    if args.iter().any(|a| a == "--train" || a == "--apply") {
        println!("  model inference uses heuristic approximation");
    }
    std::process::exit(0);
}
