//! Thin CLI wrapper for `torshield_ir_ultra::ai_workflow_tools`.
//! Replaces the inline Python heredocs of the AI-gateway/self-healing workflows.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(torshield_ir_ultra::ai_workflow_tools::entry(&args));
}
