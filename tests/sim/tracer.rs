use crate::simulation::{Response, Simulation, SingleHost};
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::info;
use trippy::tracing::{
    defaults, Builder, CompletionReason, MaxRounds, MultipathStrategy, PacketSize, PayloadPattern,
    PortDirection, ProbeStatus, Protocol, TimeToLive, TraceId, TracerRound,
};

// The length of time to wait after the completion of the tracing before
// cancelling the network simulator.  This is needed to ensure that all
// in-flight packets for the current test are send ot received prior to
// ending the round so that they are not incorrectly used in a subsequent
// test.
const CLEANUP_DELAY: Duration = Duration::from_millis(1000);

macro_rules! assert_eq_result {
    ($res:ident, $exp1:expr, $exp2:expr) => {{
        fn ensure_match<T: PartialEq>(fst: T, snd: T) -> anyhow::Result<()> {
            anyhow::ensure!(fst == snd);
            Ok(())
        }
        if let err @ Err(_) = ensure_match($exp1, $exp2) {
            *$res.borrow_mut() = err;
            return;
        }
    }};
}

pub struct Tracer {
    sim: Arc<Simulation>,
    token: CancellationToken,
}

impl Tracer {
    pub fn new(sim: Arc<Simulation>, token: CancellationToken) -> Self {
        Self { sim, token }
    }

    pub fn trace(&self) -> anyhow::Result<()> {
        let result = RefCell::new(Ok(()));
        let tracer_res = Builder::new(self.sim.target, |round| self.validate_round(round, &result))
            .trace_identifier(TraceId(self.sim.icmp_identifier))
            .protocol(Protocol::from(self.sim.protocol))
            .port_direction(PortDirection::from(self.sim.port_direction))
            .multipath_strategy(MultipathStrategy::from(self.sim.multipath_strategy))
            .packet_size(PacketSize(
                self.sim
                    .packet_size
                    .unwrap_or(defaults::DEFAULT_STRATEGY_PACKET_SIZE),
            ))
            .payload_pattern(PayloadPattern(
                self.sim
                    .payload_pattern
                    .unwrap_or(defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN),
            ))
            .min_round_duration(self.sim.min_round_duration.map_or(
                defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION,
                Duration::from_millis,
            ))
            .max_round_duration(self.sim.max_round_duration.map_or(
                defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION,
                Duration::from_millis,
            ))
            .grace_duration(self.sim.grace_duration.map_or(
                defaults::DEFAULT_STRATEGY_GRACE_DURATION,
                Duration::from_millis,
            ))
            .max_rounds(MaxRounds(NonZeroUsize::MIN))
            .start()
            .map_err(anyhow::Error::from);
        thread::sleep(CLEANUP_DELAY);
        self.token.cancel();
        // ensure both the tracer and the validator were successful.
        tracer_res.and(result.replace(Ok(())))
    }

    fn validate_round(&self, round: &TracerRound<'_>, result: &RefCell<anyhow::Result<()>>) {
        assert_eq_result!(result, round.reason, CompletionReason::TargetFound);
        assert_eq_result!(result, TimeToLive(self.sim.latest_ttl()), round.largest_ttl);
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
            assert_eq_result!(result, expected_status, hop.status);
            assert_eq_result!(result, expected_host, hop.host);
            assert_eq_result!(result, expected_ttl, hop.ttl);
        }
    }
}
