#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

mod network;
mod simulation;
mod tracer;
mod tun_device;

use crate::tun_device::tun;
pub use simulation::Simulation;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Run a simulation.
pub async fn simulate(simulation: Simulation) -> anyhow::Result<()> {
    let sim = Arc::new(simulation);
    let tun = tun();
    let token = CancellationToken::new();
    let handle = tokio::spawn(network::run(tun.clone(), sim.clone(), token.clone()));
    tokio::task::spawn_blocking(move || tracer::Tracer::new(sim.clone(), token).trace()).await??;
    handle.await?
}
