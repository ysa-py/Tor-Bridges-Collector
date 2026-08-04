//! Default executable entry point for the unified Tor bridge collector.

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(error) = torshield_ir_ultra::tor_collector::run_from_env().await {
        eprintln!("collector error: {error:#}");
        std::process::exit(1);
    }
}

/// Keep the ARMv7-musl CI type-check independent of Rustls/ring's native C
/// cross toolchain. This target is a compile-only CI sentinel, not a supported
/// runtime package for the network collector.
#[cfg(all(target_arch = "arm", target_env = "musl"))]
fn main() {
    eprintln!("tor-bridges-collector is not packaged for ARMv7-musl CI checks");
}

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
