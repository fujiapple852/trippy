use crate::config::StateConfig;
use crate::constants::MAX_TTL;
use crate::flows::{Flow, FlowId, FlowRegistry};
use crate::{Extensions, IcmpPacketType, ProbeState, Round, TimeToLive, TracerRound};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::iter::once;
use std::net::IpAddr;
use std::time::Duration;

/// The state of a trace.
#[derive(Debug, Clone, Default)]
pub struct TraceState {
    state_config: StateConfig,
    /// The flow id for the current round.
    round_flow_id: FlowId,
    /// Tracing data per registered flow id.
    state: HashMap<FlowId, FlowState>,
    /// Flow registry.
    registry: FlowRegistry,
    /// Tracing error message.
    error: Option<String>,
}

impl TraceState {
    /// Create a new `Trace`.
    #[must_use]
    pub fn new(state_config: StateConfig) -> Self {
        Self {
            state: once((
                Self::default_flow_id(),
                FlowState::new(state_config.max_samples),
            ))
            .collect::<HashMap<FlowId, FlowState>>(),
            round_flow_id: Self::default_flow_id(),
            state_config,
            registry: FlowRegistry::new(),
            error: None,
        }
    }

    /// Return the id of the default flow.
    #[must_use]
    pub fn default_flow_id() -> FlowId {
        FlowId(0)
    }

    /// Information about each hop for a given flow.
    #[must_use]
    pub fn hops(&self, flow_id: FlowId) -> &[Hop] {
        self.state[&flow_id].hops()
    }

    /// Is a given `Hop` the target hop for a given flow?
    ///
    /// A `Hop` is considered to be the target if it has the highest `ttl` value observed.
    ///
    /// Note that if the target host does not respond to probes then the highest `ttl` observed
    /// will be one greater than the `ttl` of the last host which did respond.
    #[must_use]
    pub fn is_target(&self, hop: &Hop, flow_id: FlowId) -> bool {
        self.state[&flow_id].is_target(hop)
    }

    /// Is a given `Hop` in the current round for a given flow?
    #[must_use]
    pub fn is_in_round(&self, hop: &Hop, flow_id: FlowId) -> bool {
        self.state[&flow_id].is_in_round(hop)
    }

    /// Return the target `Hop` for a given flow.
    #[must_use]
    pub fn target_hop(&self, flow_id: FlowId) -> &Hop {
        self.state[&flow_id].target_hop()
    }

    /// The current round of tracing for a given flow.
    #[must_use]
    pub fn round(&self, flow_id: FlowId) -> Option<usize> {
        self.state[&flow_id].round()
    }

    /// The total rounds of tracing for a given flow.
    #[must_use]
    pub fn round_count(&self, flow_id: FlowId) -> usize {
        self.state[&flow_id].round_count()
    }

    /// The `FlowId` for the current round.
    #[must_use]
    pub fn round_flow_id(&self) -> FlowId {
        self.round_flow_id
    }

    /// The registry of flows in the trace.
    #[must_use]
    pub fn flows(&self) -> &[(Flow, FlowId)] {
        self.registry.flows()
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn set_error(&mut self, error: Option<String>) {
        self.error = error;
    }

    /// The maximum number of samples to record per hop.
    #[must_use]
    pub fn max_samples(&self) -> usize {
        self.state_config.max_samples
    }

    /// The maximum number of flows to record.
    #[must_use]
    pub fn max_flows(&self) -> usize {
        self.state_config.max_flows
    }

    /// Update the tracing state from a `TracerRound`.
    pub fn update_from_round(&mut self, round: &TracerRound<'_>) {
        let flow = Flow::from_hops(
            round
                .probes
                .iter()
                .filter_map(|probe| match probe {
                    ProbeState::Awaited(_) => Some(None),
                    ProbeState::Complete(completed) => Some(Some(completed.host)),
                    _ => None,
                })
                .take(usize::from(round.largest_ttl.0)),
        );
        self.update_trace_flow(Self::default_flow_id(), round);
        if self.registry.flows().len() < self.state_config.max_flows {
            let flow_id = self.registry.register(flow);
            self.round_flow_id = flow_id;
            self.update_trace_flow(flow_id, round);
        }
    }

    fn update_trace_flow(&mut self, flow_id: FlowId, round: &TracerRound<'_>) {
        let flow_trace = self
            .state
            .entry(flow_id)
            .or_insert_with(|| FlowState::new(self.state_config.max_samples));
        flow_trace.update_from_round(round);
    }
}

/// Information about a single `Hop` within a `Trace`.
#[derive(Debug, Clone)]
pub struct Hop {
    /// The ttl of this hop.
    ttl: u8,
    /// The addrs of this hop and associated counts.
    addrs: IndexMap<IpAddr, usize>,
    /// The total probes sent for this hop.
    total_sent: usize,
    /// The total probes received for this hop.
    total_recv: usize,
    /// The total round trip time for this hop across all rounds.
    total_time: Duration,
    /// The round trip time for this hop in the current round.
    last: Option<Duration>,
    /// The best round trip time for this hop across all rounds.
    best: Option<Duration>,
    /// The worst round trip time for this hop across all rounds.
    worst: Option<Duration>,
    /// The current jitter i.e. round-trip difference with the last round-trip.
    jitter: Option<Duration>,
    /// The average jitter time for all probes at this hop.
    javg: f64,
    /// The worst round-trip jitter time for all probes at this hop.
    jmax: Option<Duration>,
    /// The smoothed jitter value for all probes at this hop.
    jinta: f64,
    /// The source port for last probe for this hop.
    last_src_port: u16,
    /// The destination port for last probe for this hop.
    last_dest_port: u16,
    /// The sequence number for the last probe for this hop.
    last_sequence: u16,
    /// The icmp packet type for the last probe for this hop.
    last_icmp_packet_type: Option<IcmpPacketType>,
    /// The history of round trip times across the last N rounds.
    samples: Vec<Duration>,
    /// The ICMP extensions for this hop.
    extensions: Option<Extensions>,
    mean: f64,
    m2: f64,
}

impl Hop {
    /// The time-to-live of this hop.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// The set of addresses that have responded for this time-to-live.
    pub fn addrs(&self) -> impl Iterator<Item = &IpAddr> {
        self.addrs.keys()
    }

    pub fn addrs_with_counts(&self) -> impl Iterator<Item = (&IpAddr, &usize)> {
        self.addrs.iter()
    }

    /// The number of unique address observed for this time-to-live.
    #[must_use]
    pub fn addr_count(&self) -> usize {
        self.addrs.len()
    }

    /// The total number of probes sent.
    #[must_use]
    pub fn total_sent(&self) -> usize {
        self.total_sent
    }

    /// The total number of probes responses received.
    #[must_use]
    pub fn total_recv(&self) -> usize {
        self.total_recv
    }

    /// The % of packets that are lost.
    #[must_use]
    pub fn loss_pct(&self) -> f64 {
        if self.total_sent > 0 {
            let lost = self.total_sent - self.total_recv;
            lost as f64 / self.total_sent as f64 * 100f64
        } else {
            0_f64
        }
    }

    /// The duration of the last probe.
    #[must_use]
    pub fn last_ms(&self) -> Option<f64> {
        self.last.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the best probe observed.
    #[must_use]
    pub fn best_ms(&self) -> Option<f64> {
        self.best.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the worst probe observed.
    #[must_use]
    pub fn worst_ms(&self) -> Option<f64> {
        self.worst.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The average duration of all probes.
    #[must_use]
    pub fn avg_ms(&self) -> f64 {
        if self.total_recv() > 0 {
            (self.total_time.as_secs_f64() * 1000_f64) / self.total_recv as f64
        } else {
            0_f64
        }
    }

    /// The standard deviation of all probes.
    #[must_use]
    pub fn stddev_ms(&self) -> f64 {
        if self.total_recv > 1 {
            (self.m2 / (self.total_recv - 1) as f64).sqrt()
        } else {
            0_f64
        }
    }

    /// The duration of the jitter probe observed.
    #[must_use]
    pub fn jitter_ms(&self) -> Option<f64> {
        self.jitter.map(|j| j.as_secs_f64() * 1000_f64)
    }

    /// The duration of the worst probe observed.
    #[must_use]
    pub fn jmax_ms(&self) -> Option<f64> {
        self.jmax.map(|x| x.as_secs_f64() * 1000_f64)
    }

    /// The jitter average duration of all probes.
    #[must_use]
    pub fn javg_ms(&self) -> f64 {
        self.javg
    }

    /// The jitter interval of all probes.
    #[must_use]
    pub fn jinta(&self) -> f64 {
        self.jinta
    }

    /// The source port for last probe for this hop.
    #[must_use]
    pub fn last_src_port(&self) -> u16 {
        self.last_src_port
    }

    /// The destination port for last probe for this hop.
    #[must_use]
    pub fn last_dest_port(&self) -> u16 {
        self.last_dest_port
    }

    /// The sequence number for the last probe for this hop.
    #[must_use]
    pub fn last_sequence(&self) -> u16 {
        self.last_sequence
    }

    /// The icmp packet type for the last probe for this hop.
    #[must_use]
    pub fn last_icmp_packet_type(&self) -> Option<IcmpPacketType> {
        self.last_icmp_packet_type
    }

    /// The last N samples.
    #[must_use]
    pub fn samples(&self) -> &[Duration] {
        &self.samples
    }

    #[must_use]
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl Default for Hop {
    fn default() -> Self {
        Self {
            ttl: 0,
            addrs: IndexMap::default(),
            total_sent: 0,
            total_recv: 0,
            total_time: Duration::default(),
            last: None,
            best: None,
            worst: None,
            jitter: None,
            javg: 0f64,
            jmax: None,
            jinta: 0f64,
            last_src_port: 0_u16,
            last_dest_port: 0_u16,
            last_sequence: 0_u16,
            last_icmp_packet_type: None,
            mean: 0f64,
            m2: 0f64,
            samples: Vec::default(),
            extensions: None,
        }
    }
}

/// Data for a single trace flow.
#[derive(Debug, Clone)]
struct FlowState {
    /// The maximum number of samples to record.
    max_samples: usize,
    /// The lowest ttl observed across all rounds.
    lowest_ttl: u8,
    /// The highest ttl observed across all rounds.
    highest_ttl: u8,
    /// The highest ttl observed for the latest round.
    highest_ttl_for_round: u8,
    /// The latest round received.
    round: Option<usize>,
    /// The total number of rounds received.
    round_count: usize,
    /// The hops in this trace.
    hops: Vec<Hop>,
}

impl FlowState {
    fn new(max_samples: usize) -> Self {
        Self {
            max_samples,
            lowest_ttl: 0,
            highest_ttl: 0,
            highest_ttl_for_round: 0,
            round: None,
            round_count: 0,
            hops: (0..MAX_TTL).map(|_| Hop::default()).collect(),
        }
    }

    fn hops(&self) -> &[Hop] {
        if self.lowest_ttl == 0 || self.highest_ttl == 0 {
            &[]
        } else {
            let start = (self.lowest_ttl as usize) - 1;
            let end = self.highest_ttl as usize;
            &self.hops[start..end]
        }
    }

    fn is_target(&self, hop: &Hop) -> bool {
        self.highest_ttl == hop.ttl
    }

    fn is_in_round(&self, hop: &Hop) -> bool {
        hop.ttl <= self.highest_ttl_for_round
    }

    fn target_hop(&self) -> &Hop {
        if self.highest_ttl > 0 {
            &self.hops[usize::from(self.highest_ttl) - 1]
        } else {
            &self.hops[0]
        }
    }

    fn round(&self) -> Option<usize> {
        self.round
    }

    fn round_count(&self) -> usize {
        self.round_count
    }

    fn update_from_round(&mut self, round: &TracerRound<'_>) {
        self.round_count += 1;
        self.highest_ttl = std::cmp::max(self.highest_ttl, round.largest_ttl.0);
        self.highest_ttl_for_round = round.largest_ttl.0;
        for probe in round.probes {
            self.update_from_probe(probe);
        }
    }

    fn update_from_probe(&mut self, probe: &ProbeState) {
        match probe {
            ProbeState::Complete(complete) => {
                self.update_lowest_ttl(complete.ttl);
                self.update_round(complete.round);
                let index = usize::from(complete.ttl.0) - 1;
                let hop = &mut self.hops[index];
                hop.ttl = complete.ttl.0;
                hop.total_sent += 1;
                hop.total_recv += 1;
                let dur = complete
                    .received
                    .duration_since(complete.sent)
                    .unwrap_or_default();
                let dur_ms = dur.as_secs_f64() * 1000_f64;
                hop.total_time += dur;
                // Before last is set use it to calc jitter
                let last_ms = hop.last_ms().unwrap_or_default();
                let jitter_ms = (dur_ms - last_ms).abs();
                let jitter_dur = Duration::from_secs_f64(jitter_ms / 1000_f64);
                hop.jitter = hop.last.and(Some(jitter_dur));
                hop.javg += (jitter_ms - hop.javg) / hop.total_recv as f64;
                // algorithm is from rfc1889, A.8 or rfc3550
                hop.jinta += jitter_ms.max(0.5) - ((hop.jinta + 8.0) / 16.0);
                hop.jmax = hop
                    .jmax
                    .map_or(Some(jitter_dur), |d| Some(d.max(jitter_dur)));
                hop.last = Some(dur);
                hop.samples.insert(0, dur);
                hop.best = hop.best.map_or(Some(dur), |d| Some(d.min(dur)));
                hop.worst = hop.worst.map_or(Some(dur), |d| Some(d.max(dur)));
                hop.mean += (dur_ms - hop.mean) / hop.total_recv as f64;
                hop.m2 += (dur_ms - hop.mean) * (dur_ms - hop.mean);
                if hop.samples.len() > self.max_samples {
                    hop.samples.pop();
                }
                let host = complete.host;
                *hop.addrs.entry(host).or_default() += 1;
                hop.extensions.clone_from(&complete.extensions);
                hop.last_src_port = complete.src_port.0;
                hop.last_dest_port = complete.dest_port.0;
                hop.last_sequence = complete.sequence.0;
                hop.last_icmp_packet_type = Some(complete.icmp_packet_type);
            }
            ProbeState::Awaited(awaited) => {
                self.update_lowest_ttl(awaited.ttl);
                self.update_round(awaited.round);
                let index = usize::from(awaited.ttl.0) - 1;
                self.hops[index].total_sent += 1;
                self.hops[index].ttl = awaited.ttl.0;
                self.hops[index].samples.insert(0, Duration::default());
                if self.hops[index].samples.len() > self.max_samples {
                    self.hops[index].samples.pop();
                }
                self.hops[index].last_src_port = awaited.src_port.0;
                self.hops[index].last_dest_port = awaited.dest_port.0;
                self.hops[index].last_sequence = awaited.sequence.0;
            }
            ProbeState::NotSent | ProbeState::Skipped => {}
        }
    }

    fn update_round(&mut self, round: Round) {
        self.round = match self.round {
            None => Some(round.0),
            Some(r) => Some(r.max(round.0)),
        }
    }

    fn update_lowest_ttl(&mut self, ttl: TimeToLive) {
        if self.lowest_ttl == 0 {
            self.lowest_ttl = ttl.0;
        } else {
            self.lowest_ttl = self.lowest_ttl.min(ttl.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompletionReason, Flags, IcmpPacketType, Port, Probe, ProbeComplete, ProbeState, Sequence,
        TimeToLive, TraceId,
    };
    use anyhow::anyhow;
    use serde::Deserialize;
    use std::collections::HashSet;
    use std::ops::Add;
    use std::str::FromStr;
    use std::time::SystemTime;
    use test_case::test_case;

    /// A test scenario.
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Scenario {
        /// the biggest ttl expected in this scenario
        largest_ttl: u8,
        /// The rounds of probe tracing data in this scenario.
        rounds: Vec<RoundData>,
        /// The expected outcome from running this scenario.
        expected: Expected,
    }

    /// A single round of tracing probe data.
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct RoundData {
        /// The probes in this round.
        probes: Vec<ProbeData>,
    }

    /// A single probe from a single round.
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    #[serde(try_from = "String")]
    struct ProbeData(ProbeState);

    impl TryFrom<String> for ProbeData {
        type Error = anyhow::Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            // format: {ttl} {status} {duration} {host} {sequence} {src_port} {dest_port}
            let values = value.split_ascii_whitespace().collect::<Vec<_>>();
            if values.len() == 7 {
                let ttl = TimeToLive(u8::from_str(values[0])?);
                let state = values[1].to_ascii_lowercase();
                let sequence = Sequence(u16::from_str(values[4])?);
                let src_port = Port(u16::from_str(values[5])?);
                let dest_port = Port(u16::from_str(values[6])?);
                let round = Round(0); // note we inject this later, see ProbeRound
                let sent = SystemTime::now();
                let flags = Flags::empty();
                let state = match state.as_str() {
                    "n" => Ok(ProbeState::NotSent),
                    "s" => Ok(ProbeState::Skipped),
                    "a" => Ok(ProbeState::Awaited(Probe::new(
                        sequence,
                        TraceId(0),
                        src_port,
                        dest_port,
                        ttl,
                        round,
                        sent,
                        flags,
                    ))),
                    "c" => {
                        let host = IpAddr::from_str(values[3])?;
                        let duration = Duration::from_millis(u64::from_str(values[2])?);
                        let received = sent.add(duration);
                        let icmp_packet_type = IcmpPacketType::NotApplicable;
                        Ok(ProbeState::Complete(
                            Probe::new(
                                sequence,
                                TraceId(0),
                                src_port,
                                dest_port,
                                ttl,
                                round,
                                sent,
                                flags,
                            )
                            .complete(
                                host,
                                received,
                                icmp_packet_type,
                                None,
                            ),
                        ))
                    }
                    _ => Err(anyhow!("unknown probe state")),
                }?;
                Ok(Self(state))
            } else {
                Err(anyhow!("failed to parse {}", value))
            }
        }
    }

    /// A helper struct so wwe may inject the round into the probes.
    struct ProbeRound(ProbeData, Round);

    impl From<ProbeRound> for ProbeState {
        fn from(value: ProbeRound) -> Self {
            let probe_data = value.0;
            let round = value.1;
            match probe_data.0 {
                Self::NotSent => Self::NotSent,
                Self::Skipped => Self::Skipped,
                Self::Awaited(awaited) => Self::Awaited(Probe { round, ..awaited }),
                Self::Complete(completed) => Self::Complete(ProbeComplete { round, ..completed }),
            }
        }
    }

    /// The expected outcome.
    #[derive(Deserialize, Debug, Clone)]
    #[serde(deny_unknown_fields)]
    struct Expected {
        /// The expected outcome per hop.
        hops: Vec<HopData>,
    }

    /// The expected outcome for a single hop.
    #[derive(Deserialize, Debug, Clone)]
    #[serde(deny_unknown_fields)]
    struct HopData {
        ttl: u8,
        total_sent: usize,
        total_recv: usize,
        loss_pct: f64,
        last_ms: Option<f64>,
        best_ms: Option<f64>,
        worst_ms: Option<f64>,
        avg_ms: f64,
        jitter: Option<f64>,
        javg: f64,
        jmax: Option<f64>,
        jinta: f64,
        addrs: HashMap<IpAddr, usize>,
        samples: Option<Vec<f64>>,
        last_src: u16,
        last_dest: u16,
        last_sequence: u16,
    }

    macro_rules! file {
        ($path:expr) => {{
            let yaml = include_str!(concat!("../tests/resources/backend/", $path));
            serde_yml::from_str(yaml).unwrap()
        }};
    }

    #[test_case(file!("ipv4_3probes_3hops_mixed_multi.yaml"))]
    #[test_case(file!("ipv4_3probes_3hops_completed.yaml"))]
    #[test_case(file!("ipv4_4probes_all_status.yaml"))]
    #[test_case(file!("ipv4_4probes_0latency.yaml"))]
    fn test_scenario(scenario: Scenario) {
        let mut trace = TraceState::new(StateConfig {
            max_flows: 1,
            ..StateConfig::default()
        });
        for (i, round) in scenario.rounds.into_iter().enumerate() {
            let probes = round
                .probes
                .into_iter()
                .map(|p| ProbeRound(p, Round(i)))
                .map(Into::into)
                .collect::<Vec<_>>();
            let largest_ttl = TimeToLive(scenario.largest_ttl);
            let tracer_round =
                TracerRound::new(&probes, largest_ttl, CompletionReason::TargetFound);
            trace.update_from_round(&tracer_round);
        }
        let actual_hops = trace.hops(TraceState::default_flow_id());
        let expected_hops = scenario.expected.hops;
        for (actual, expected) in actual_hops.iter().zip(expected_hops) {
            assert_eq!(actual.ttl(), expected.ttl);
            assert_eq!(
                actual.addrs().collect::<HashSet<_>>(),
                expected.addrs.keys().collect::<HashSet<_>>()
            );
            assert_eq!(actual.addr_count(), expected.addrs.len());
            assert_eq!(actual.total_sent(), expected.total_sent);
            assert_eq!(actual.total_recv(), expected.total_recv);
            assert_eq_optional(Some(actual.loss_pct()), Some(expected.loss_pct));
            assert_eq_optional(actual.last_ms(), expected.last_ms);
            assert_eq_optional(actual.best_ms(), expected.best_ms);
            assert_eq_optional(actual.worst_ms(), expected.worst_ms);
            assert_eq_optional(Some(actual.avg_ms()), Some(expected.avg_ms));
            assert_eq_optional(actual.jitter_ms(), expected.jitter);
            assert_eq_optional(Some(actual.javg_ms()), Some(expected.javg));
            assert_eq_optional(actual.jmax_ms(), expected.jmax);
            assert_eq_optional(Some(actual.jinta()), Some(expected.jinta));
            assert_eq!(actual.last_src_port(), expected.last_src);
            assert_eq!(actual.last_dest_port(), expected.last_dest);
            assert_eq!(actual.last_sequence(), expected.last_sequence);
            assert_eq!(
                Some(
                    actual
                        .samples()
                        .iter()
                        .map(|s| s.as_secs_f64() * 1000_f64)
                        .collect()
                ),
                expected.samples
            );
        }
    }

    #[allow(clippy::float_cmp)]
    fn assert_eq_optional(actual: Option<f64>, expected: Option<f64>) {
        match (actual, expected) {
            (Some(actual), Some(expected)) => assert_eq!(actual, expected),
            (Some(_), None) => panic!("actual {actual:?} but not expected"),
            (None, Some(_)) => panic!("expected {expected:?} but no actual"),
            (None, None) => {}
        }
    }
}
