#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::fmt::format::FmtSpan;
use trippy_privilege::Privilege;
use trippy_sim::{simulate, Simulation};

/// Trace a route to a host and record statistics
#[allow(clippy::doc_markdown)]
#[derive(Parser, Debug)]
#[command(name = "trip", author, version, about, long_about = None, arg_required_else_help(true))]
pub struct Args {
    /// A simulation file to run.
    pub simulation: String,
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::NONE)
        .with_env_filter("debug")
        .init();
    if !Privilege::discover()?.has_privileges() {
        return Err(anyhow::anyhow!("Privileges required to run this command"));
    }
    let simulation_file =
        std::fs::read_to_string(&args.simulation).context(args.simulation.to_string())?;
    let sim: Simulation = toml::from_str(&simulation_file)?;
    simulate(sim).await
}
