//! Thin CLI wrapper for `torshield_ir_ultra::quality_gate`.
//! Replaces the retired Python script/inline step of the same name.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(torshield_ir_ultra::quality_gate::entry(&args));
}
