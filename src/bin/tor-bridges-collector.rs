//! Explicitly named `tor-bridges-collector` executable.

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    if let Err(error) = torshield_ir_ultra::tor_collector::run_from_env().await {
        eprintln!("collector error: {error:#}");
        std::process::exit(1);
    }
}

/// The ARMv7-musl target is checked only as a Rust CI sentinel. Its runner has
/// no native TLS C toolchain, so the collector's Rustls/ring implementation is
/// intentionally not packaged for that target.
#[cfg(all(target_arch = "arm", target_env = "musl"))]
fn main() {
    eprintln!("tor-bridges-collector is not packaged for ARMv7-musl CI checks");
}
