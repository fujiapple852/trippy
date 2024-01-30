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
    PortDirection, ProbeState, Protocol, TimeToLive, TraceId, TracerRound,
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

macro_rules! error_result {
    ($res:ident, $err:expr) => {{
        *$res.borrow_mut() = Err($err);
        return;
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
            .filter(|p| matches!(p, ProbeState::Awaited(_) | ProbeState::Complete(_)))
            .take(round.largest_ttl.0 as usize)
        {
            match hop {
                ProbeState::Complete(complete) => {
                    info!(
                        "{} {} {}",
                        complete.round.0,
                        complete.ttl.0,
                        complete.host.to_string(),
                    );

                    let hop_index = usize::from(complete.ttl.0 - 1);
                    let sim_hop = &self.sim.hops[hop_index];
                    if let Response::NoResponse = sim_hop.resp {
                        error_result!(result, anyhow::anyhow!("expected Response::SingleHost"));
                    }
                    let expected_host = match sim_hop.resp {
                        Response::NoResponse => None,
                        Response::SingleHost(SingleHost { addr, .. }) => Some(addr),
                    };
                    assert_eq_result!(result, expected_host, Some(complete.host));
                    let expected_ttl = TimeToLive(self.sim.hops[hop_index].ttl);
                    assert_eq_result!(result, expected_ttl, complete.ttl);
                }
                ProbeState::Awaited(awaited) => {
                    info!("{} {} * * *", awaited.round.0, awaited.ttl.0);

                    let hop_index = usize::from(awaited.ttl.0 - 1);
                    let sim_hop = &self.sim.hops[hop_index];
                    if let Response::SingleHost(_) = sim_hop.resp {
                        error_result!(result, anyhow::anyhow!("expected Response::NoResponse"));
                    }
                    let expected_host = match sim_hop.resp {
                        Response::NoResponse => None,
                        Response::SingleHost(SingleHost { addr, .. }) => Some(addr),
                    };
                    assert_eq_result!(result, expected_host, None);
                    let expected_ttl = TimeToLive(self.sim.hops[hop_index].ttl);
                    assert_eq_result!(result, expected_ttl, awaited.ttl);
                }
                _ => {}
            }
        }
    }
}
