use crate::simulation::{Response, Simulation, SingleHost};
use std::cell::RefCell;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::info;
use trippy_core::{
    defaults, Builder, CompletionReason, MultipathStrategy, PortDirection, PrivilegeMode,
    ProbeStatus, Protocol, Round, TimeToLive,
};

// The length of time to wait after the completion of the tracing before
// canceling the network simulator.  This is needed to ensure that all
// in-flight packets for the current test are send to received prior to
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
    pub const fn new(sim: Arc<Simulation>, token: CancellationToken) -> Self {
        Self { sim, token }
    }

    pub fn trace(&self) -> anyhow::Result<()> {
        let result = RefCell::new(Ok(()));
        let tracer = Builder::new(self.sim.target)
            .privilege_mode(PrivilegeMode::from(self.sim.privilege_mode))
            .trace_identifier(self.sim.icmp_identifier)
            .initial_sequence(
                self.sim
                    .initial_sequence
                    .unwrap_or(defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE),
            )
            .protocol(Protocol::from(self.sim.protocol))
            .port_direction(PortDirection::from(self.sim.port_direction))
            .multipath_strategy(MultipathStrategy::from(self.sim.multipath_strategy))
            .packet_size(
                self.sim
                    .packet_size
                    .unwrap_or(defaults::DEFAULT_STRATEGY_PACKET_SIZE),
            )
            .payload_pattern(
                self.sim
                    .payload_pattern
                    .unwrap_or(defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN),
            )
            .tos(self.sim.tos.unwrap_or(defaults::DEFAULT_STRATEGY_TOS))
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
            .max_rounds(self.sim.rounds.or(Some(1)))
            .build()?;
        let tracer_res = tracer
            .run_with(|round| self.validate_round(round, &result))
            .map_err(anyhow::Error::from);
        thread::sleep(CLEANUP_DELAY);
        self.token.cancel();
        // ensure both the tracer and the validation were successful.
        tracer_res.and(result.replace(Ok(())))
    }

    fn validate_round(&self, round: &Round<'_>, result: &RefCell<anyhow::Result<()>>) {
        assert_eq_result!(result, round.reason, CompletionReason::TargetFound);
        assert_eq_result!(result, TimeToLive(self.sim.latest_ttl()), round.largest_ttl);
        for hop in round
            .probes
            .iter()
            .filter(|p| matches!(p, ProbeStatus::Awaited(_) | ProbeStatus::Complete(_)))
            .take(round.largest_ttl.0 as usize)
        {
            match hop {
                ProbeStatus::Complete(complete) => {
                    info!(
                        "{} {} {}",
                        complete.round.0,
                        complete.ttl.0,
                        complete.host.to_string(),
                    );

                    let hop_index = usize::from(complete.ttl.0 - 1);
                    let sim_hop = &self.sim.hops[hop_index];
                    if matches!(sim_hop.resp, Response::NoResponse) {
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
                ProbeStatus::Awaited(awaited) => {
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
