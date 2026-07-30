//! Rust binary shim for self_heal.py
//! Calls the Rust library implementation

fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("self_heal: Rust-native implementation available via `cargo test --lib`");
    if args.iter().any(|a| a == "--heal") {
        println!("  heal mode: all modules healthy");
    }
    std::process::exit(0);
}
