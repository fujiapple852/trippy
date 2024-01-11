use crate::simulation::{Response, Simulation, SingleHost};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;
use trippy::tracing::{
    Builder, CompletionReason, MaxRounds, MultipathStrategy, PortDirection, ProbeStatus, Protocol,
    TimeToLive, TraceId, TracerRound,
};

pub struct Tracer {
    sim: Arc<Simulation>,
    token: CancellationToken,
}

impl Tracer {
    pub fn new(sim: Arc<Simulation>, token: CancellationToken) -> Self {
        Self { sim, token }
    }

    pub fn trace(&self) -> anyhow::Result<()> {
        Builder::new(self.sim.target, |round| self.validate_round(round))
            .trace_identifier(TraceId(self.sim.icmp_identifier))
            .protocol(Protocol::from(self.sim.protocol))
            .port_direction(PortDirection::from(self.sim.port_direction))
            .multipath_strategy(MultipathStrategy::from(self.sim.multipath_strategy))
            .max_rounds(MaxRounds(NonZeroUsize::MIN))
            .start()?;
        self.token.cancel();
        Ok(())
    }

    fn validate_round(&self, round: &TracerRound<'_>) {
        assert_eq!(CompletionReason::TargetFound, round.reason);
        assert_eq!(TimeToLive(self.sim.latest_ttl()), round.largest_ttl);
        for hop in round
            .probes
            .iter()
            .filter(|p| matches!(p.status, ProbeStatus::Awaited | ProbeStatus::Complete))
            .take(round.largest_ttl.0 as usize)
        {
            match hop.status {
                ProbeStatus::Complete => {
                    info!(
                        "{} {} {}",
                        hop.round.0,
                        hop.ttl.0,
                        hop.host.as_ref().map(ToString::to_string).unwrap(),
                    );
                }
                ProbeStatus::Awaited => {
                    info!("{} {} * * *", hop.round.0, hop.ttl.0);
                }
                _ => {}
            }
            let hop_index = usize::from(hop.ttl.0 - 1);
            let (expected_status, expected_host) = match self.sim.hops[hop_index].resp {
                Response::NoResponse => (ProbeStatus::Awaited, None),
                Response::SingleHost(SingleHost { addr, .. }) => {
                    (ProbeStatus::Complete, Some(addr))
                }
            };
            let expected_ttl = TimeToLive(self.sim.hops[hop_index].ttl);
            assert_eq!(expected_status, hop.status);
            assert_eq!(expected_host, hop.host);
            assert_eq!(expected_ttl, hop.ttl);
        }
    }
}
