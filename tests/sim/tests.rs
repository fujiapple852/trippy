use crate::simulation::Simulation;
use crate::tun_device::tun;
use crate::{network, tracer};
use std::sync::{Arc, Mutex, OnceLock};
use test_case::test_case;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;

static RUNTIME: OnceLock<Arc<Mutex<Runtime>>> = OnceLock::new();

pub fn runtime() -> &'static Arc<Mutex<Runtime>> {
    RUNTIME.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_span_events(FmtSpan::NONE)
            .with_env_filter("trippy=debug,sim=debug")
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
        let yaml = include_str!(concat!("../resources/simulation/", $path));
        serde_yaml::from_str(yaml)?
    }};
}

#[test_case(sim!("ipv4_icmp.yaml"))]
#[test_case(sim!("ipv4_icmp_gaps.yaml"))]
#[test_case(sim!("ipv4_icmp_ooo.yaml"))]
#[test_case(sim!("ipv4_udp_classic_fixed_src.yaml"))]
#[test_case(sim!("ipv4_udp_classic_fixed_dest.yaml"))]
#[test_case(sim!("ipv4_udp_paris_fixed_both.yaml"))]
#[test_case(sim!("ipv4_tcp_fixed_dest.yaml"))]
fn test_simulation(simulation: Simulation) -> anyhow::Result<()> {
    run_simulation(simulation)
}

fn run_simulation(simulation: Simulation) -> anyhow::Result<()> {
    let runtime = runtime().lock().unwrap();
    info!("simulating {}", simulation.name);
    runtime.block_on(async {
        let tun = tun();
        let sim = Arc::new(simulation);
        let token = CancellationToken::new();
        let handle = tokio::spawn(network::run(tun.clone(), sim.clone(), token.clone()));
        tokio::task::spawn_blocking(move || tracer::Tracer::new(sim, token).trace()).await??;
        handle.await??;
        Ok(())
    })
}
