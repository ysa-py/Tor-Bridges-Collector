//! Default executable entry point for the unified Tor bridge collector.

#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(error) = torshield_ir_ultra::tor_collector::run_from_env().await {
        eprintln!("collector error: {error:#}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
