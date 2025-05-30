#![cfg(all(
    feature = "sim-tests",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
#![allow(clippy::needless_pass_by_value, clippy::redundant_clone)]

use std::sync::{Arc, Mutex, OnceLock};
use test_case::test_case;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use trippy_sim::Simulation;

/// The maximum number of attempts for each test.
const MAX_ATTEMPTS: usize = 5;

static RUNTIME: OnceLock<Arc<Mutex<Runtime>>> = OnceLock::new();

pub fn runtime() -> &'static Arc<Mutex<Runtime>> {
    RUNTIME.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_span_events(FmtSpan::NONE)
            .with_env_filter(
                "sim=debug,trippy_sim::tracer=debug,trippy_sim::network=debug,trippy_core=info",
            )
            .init();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        Arc::new(Mutex::new(runtime))
    })
}

macro_rules! sim {
    ($path:expr) => {{
        let data = include_str!(concat!("resources/simulation/", $path));
        toml::from_str(data)?
    }};
}

#[test_case(sim!("ipv4_icmp.toml"))]
#[test_case(sim!("ipv4_icmp_gaps.toml"))]
#[test_case(sim!("ipv4_icmp_ooo.toml"))]
#[test_case(sim!("ipv4_icmp_min.toml"))]
#[test_case(sim!("ipv4_icmp_pattern.toml"))]
#[test_case(sim!("ipv4_icmp_quick.toml"))]
#[test_case(sim!("ipv4_icmp_wrap.toml"))]
#[test_case(sim!("ipv4_icmp_tos.toml"))]
#[test_case(sim!("ipv4_udp_classic_fixed_src.toml"))]
#[test_case(sim!("ipv4_udp_classic_fixed_dest.toml"))]
#[test_case(sim!("ipv4_udp_paris_fixed_both.toml"))]
#[test_case(sim!("ipv4_udp_dublin_fixed_both.toml"))]
#[test_case(sim!("ipv4_udp_classic_privileged_tos.toml"))]
#[test_case(sim!("ipv4_tcp_fixed_dest.toml"))]
fn test_simulation(simulation: Simulation) -> anyhow::Result<()> {
    run_simulation_with_retry(simulation)
}

// unprivileged mode is only supported on macOS
#[cfg(target_os = "macos")]
#[test_case(sim!("ipv4_udp_classic_unprivileged.toml"))]
#[test_case(sim!("ipv4_udp_classic_unprivileged_tos.toml"))]
fn test_simulation_macos(simulation: Simulation) -> anyhow::Result<()> {
    run_simulation_with_retry(simulation)
}

fn run_simulation_with_retry(simulation: Simulation) -> anyhow::Result<()> {
    let runtime = runtime().lock().unwrap();
    let name = simulation.name.clone();
    if !trippy_privilege::Privilege::discover()?.has_privileges() {
        // Skip if the current test as the user cannot create a tun device.
        warn!("skipping test {}: insufficient privileges", name);
        return Ok(());
    }
    for attempt in 1..=MAX_ATTEMPTS {
        info!("start simulating {} [attempt #{}]", name, attempt);
        if let Err(err) = runtime.block_on(trippy_sim::simulate(simulation.clone())) {
            error!("failed simulating {} {} [attempt #{}]", name, err, attempt);
        } else {
            info!("end simulating {} [attempt #{}]", name, attempt);
            return Ok(());
        }
    }
    anyhow::bail!("failed simulating {} after {} attempts", name, MAX_ATTEMPTS)
}
