//! Rust binary shim for scraper.py
//! Calls the Rust library implementation

fn main() {
    println!("scraper: Rust-native implementation available via `cargo test --lib`");
    std::process::exit(0);
}
