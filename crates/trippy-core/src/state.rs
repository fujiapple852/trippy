use crate::config::StateConfig;
use crate::constants::MAX_TTL;
use crate::flows::{Flow, FlowId, FlowRegistry};
use crate::types::Checksum;
use crate::{Extensions, IcmpPacketType, ProbeStatus, Round, RoundId, TimeToLive};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::iter::once;
use std::net::IpAddr;
use std::time::Duration;

/// The state of a trace.
#[derive(Debug, Clone, Default)]
pub struct State {
    /// The configuration for the state.
    state_config: StateConfig,
    /// The flow id for the current round.
    round_flow_id: FlowId,
    /// Tracing state per registered flow id.
    state: HashMap<FlowId, FlowState>,
    /// Flow registry.
    registry: FlowRegistry,
    /// Tracing error message.
    error: Option<String>,
}

impl State {
    /// Create a new `State`.
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
    pub const fn default_flow_id() -> FlowId {
        FlowId(0)
    }

    /// Information about each hop for the combined default flow.
    #[must_use]
    pub fn hops(&self) -> &[Hop] {
        self.state[&Self::default_flow_id()].hops()
    }

    /// Information about each hop for a given flow.
    #[must_use]
    pub fn hops_for_flow(&self, flow_id: FlowId) -> &[Hop] {
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
    pub const fn round_flow_id(&self) -> FlowId {
        self.round_flow_id
    }

    /// The registry of flows in the trace.
    #[must_use]
    pub fn flows(&self) -> &[(Flow, FlowId)] {
        self.registry.flows()
    }

    /// The error message for the trace, if any.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn set_error(&mut self, error: Option<String>) {
        self.error = error;
    }

    /// The maximum number of samples to record per hop.
    #[must_use]
    pub const fn max_samples(&self) -> usize {
        self.state_config.max_samples
    }

    /// The maximum number of flows to record.
    #[must_use]
    pub const fn max_flows(&self) -> usize {
        self.state_config.max_flows
    }

    /// Update the tracing state from a `TracerRound`.
    pub fn update_from_round(&mut self, round: &Round<'_>) {
        let flow = Flow::from_hops(
            round
                .probes
                .iter()
                .filter_map(|probe| match probe {
                    ProbeStatus::Awaited(_) => Some(None),
                    ProbeStatus::Complete(completed) => Some(Some(completed.host)),
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

    fn update_trace_flow(&mut self, flow_id: FlowId, round: &Round<'_>) {
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
    /// The total probes that failed for this hop.
    total_failed: usize,
    /// The total forward loss for this hop.
    total_forward_lost: usize,
    /// The total backward loss for this hop.
    total_backward_lost: usize,
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
    /// The NAT detection status for the last probe for this hop.
    last_nat_status: NatStatus,
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
    pub const fn ttl(&self) -> u8 {
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
    pub const fn total_sent(&self) -> usize {
        self.total_sent
    }

    /// The total number of probes responses received.
    #[must_use]
    pub const fn total_recv(&self) -> usize {
        self.total_recv
    }

    /// The total number of probes with forward loss.
    #[must_use]
    pub const fn total_forward_loss(&self) -> usize {
        self.total_forward_lost
    }

    /// The total number of probes with backward loss.
    #[must_use]
    pub const fn total_backward_loss(&self) -> usize {
        self.total_backward_lost
    }

    /// The total number of probes that failed.
    #[must_use]
    pub const fn total_failed(&self) -> usize {
        self.total_failed
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

    /// The adjusted % of packets that are lost.
    #[must_use]
    pub fn adjusted_loss_pct(&self) -> f64 {
        if self.total_sent > 0 {
            let lost = self.total_forward_lost;
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
    pub const fn javg_ms(&self) -> f64 {
        self.javg
    }

    /// The jitter interval of all probes.
    #[must_use]
    pub const fn jinta(&self) -> f64 {
        self.jinta
    }

    /// The source port for last probe for this hop.
    #[must_use]
    pub const fn last_src_port(&self) -> u16 {
        self.last_src_port
    }

    /// The destination port for last probe for this hop.
    #[must_use]
    pub const fn last_dest_port(&self) -> u16 {
        self.last_dest_port
    }

    /// The sequence number for the last probe for this hop.
    #[must_use]
    pub const fn last_sequence(&self) -> u16 {
        self.last_sequence
    }

    /// The icmp packet type for the last probe for this hop.
    #[must_use]
    pub const fn last_icmp_packet_type(&self) -> Option<IcmpPacketType> {
        self.last_icmp_packet_type
    }

    /// The NAT detection status for the last probe for this hop.
    #[must_use]
    pub const fn last_nat_status(&self) -> NatStatus {
        self.last_nat_status
    }

    /// The last N samples.
    #[must_use]
    pub fn samples(&self) -> &[Duration] {
        &self.samples
    }

    #[must_use]
    pub const fn extensions(&self) -> Option<&Extensions> {
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
            total_forward_lost: 0,
            total_backward_lost: 0,
            total_failed: 0,
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
            last_nat_status: NatStatus::NotApplicable,
        }
    }
}

/// The state of a NAT detection for a `Hop`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NatStatus {
    /// NAT detection was not applicable.
    NotApplicable,
    /// NAT was not detected at this hop.
    NotDetected,
    /// NAT was detected at this hop.
    Detected,
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

    const fn is_target(&self, hop: &Hop) -> bool {
        self.highest_ttl_for_round == hop.ttl
    }

    const fn is_in_round(&self, hop: &Hop) -> bool {
        hop.ttl <= self.highest_ttl_for_round
    }

    fn target_hop(&self) -> &Hop {
        if self.highest_ttl_for_round > 0 {
            &self.hops[usize::from(self.highest_ttl_for_round) - 1]
        } else {
            &self.hops[0]
        }
    }

    const fn round(&self) -> Option<usize> {
        self.round
    }

    const fn round_count(&self) -> usize {
        self.round_count
    }

    fn update_from_round(&mut self, round: &Round<'_>) {
        self.round_count += 1;
        self.highest_ttl = std::cmp::max(self.highest_ttl, round.largest_ttl.0);
        self.highest_ttl_for_round = round.largest_ttl.0;
        let mut prev_hop_checksum = None;
        let mut prev_hop_carry = false;
        for probe in round.probes {
            self.update_from_probe(
                round.probes,
                probe,
                &mut prev_hop_checksum,
                &mut prev_hop_carry,
            );
        }
    }

    fn update_from_probe(
        &mut self,
        probes: &[ProbeStatus],
        probe: &ProbeStatus,
        prev_hop_checksum: &mut Option<u16>,
        prev_hop_carry: &mut bool,
    ) {
        match probe {
            ProbeStatus::Complete(complete) => {
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

                if let (Some(expected), Some(actual)) =
                    (complete.expected_udp_checksum, complete.actual_udp_checksum)
                {
                    let (nat_status, checksum) = nat_status(expected, actual, *prev_hop_checksum);
                    hop.last_nat_status = nat_status;
                    *prev_hop_checksum = Some(checksum);
                }
            }
            ProbeStatus::Awaited(awaited) => {
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
                if *prev_hop_carry {
                    self.hops[index].total_backward_lost += 1;
                } else if awaited.ttl.0 <= self.highest_ttl_for_round {
                    // TODO panicked: range end index 17 out of range for slice of length 5
                    let remaining = &probes[index..usize::from(self.highest_ttl_for_round)];
                    if remaining.len() > 1 {
                        let all_awaited = remaining
                            .iter()
                            .skip(1)
                            .all(|p| matches!(p, ProbeStatus::Awaited(_)));
                        if all_awaited {
                            self.hops[index].total_forward_lost += 1;
                            *prev_hop_carry = true;
                        }
                    }
                }
            }
            ProbeStatus::Failed(failed) => {
                self.update_lowest_ttl(failed.ttl);
                self.update_round(failed.round);
                let index = usize::from(failed.ttl.0) - 1;
                self.hops[index].total_sent += 1;
                self.hops[index].total_failed += 1;
                self.hops[index].ttl = failed.ttl.0;
                self.hops[index].samples.insert(0, Duration::default());
                if self.hops[index].samples.len() > self.max_samples {
                    self.hops[index].samples.pop();
                }
                self.hops[index].last_src_port = failed.src_port.0;
                self.hops[index].last_dest_port = failed.dest_port.0;
                self.hops[index].last_sequence = failed.sequence.0;
            }
            ProbeStatus::NotSent | ProbeStatus::Skipped => {}
        }
    }

    fn update_round(&mut self, round: RoundId) {
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

/// Determine the NAT detection status.
///
/// Returns a tuple of the NAT detection status and the checksum to use for the next hop.
const fn nat_status(
    expected: Checksum,
    actual: Checksum,
    prev_hop_checksum: Option<u16>,
) -> (NatStatus, u16) {
    if let Some(prev_hop_checksum) = prev_hop_checksum {
        // If the actual checksum matches the checksum of the previous probe
        // then we can assume NAT has not occurred.  Note that it is perfectly
        // valid for the expected checksum to differ from the actual checksum
        // in this case as the NAT'ed checksum "carries forward" throughout the
        // remainder of the hops on the path.
        if prev_hop_checksum == actual.0 {
            (NatStatus::NotDetected, prev_hop_checksum)
        } else {
            (NatStatus::Detected, actual.0)
        }
    } else {
        // If we have no prior checksum (i.e. this is the first probe that
        // responded) and the expected and actual checksums do not match then
        // we can assume NAT has occurred.
        if expected.0 == actual.0 {
            (NatStatus::NotDetected, actual.0)
        } else {
            (NatStatus::Detected, actual.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Checksum;
    use crate::{
        CompletionReason, Flags, IcmpPacketType, Port, Probe, ProbeComplete, ProbeStatus, Sequence,
        TimeToLive, TraceId,
    };
    use anyhow::anyhow;
    use serde::Deserialize;
    use std::collections::HashSet;
    use std::ops::Add;
    use std::str::FromStr;
    use std::time::SystemTime;
    use test_case::test_case;

    #[test_case(123, 123, None => (NatStatus::NotDetected, 123); "first hop matching checksum")]
    #[test_case(123, 321, None => (NatStatus::Detected, 321); "first hop non-matching checksum")]
    #[test_case(123, 123, Some(123) => (NatStatus::NotDetected, 123); "non-first hop matching checksum match previous")]
    #[test_case(999, 999, Some(321) => (NatStatus::Detected, 999); "non-first hop matching checksum not match previous")]
    #[test_case(777, 888, Some(321) => (NatStatus::Detected, 888); "non-first hop non-matching checksum not match previous")]
    const fn test_nat(expected: u16, actual: u16, prev: Option<u16>) -> (NatStatus, u16) {
        nat_status(Checksum(expected), Checksum(actual), prev)
    }

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
    struct ProbeData(ProbeStatus);

    impl TryFrom<String> for ProbeData {
        type Error = anyhow::Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            // format: {ttl} {status} {duration} {host} {sequence} {src_port} {dest_port} {checksum}
            let values = value.split_ascii_whitespace().collect::<Vec<_>>();
            if values.len() == 9 {
                let ttl = TimeToLive(u8::from_str(values[0])?);
                let state = values[1].to_ascii_lowercase();
                let sequence = Sequence(u16::from_str(values[4])?);
                let src_port = Port(u16::from_str(values[5])?);
                let dest_port = Port(u16::from_str(values[6])?);
                let round = RoundId(0); // note we inject this later, see ProbeRound
                let sent = SystemTime::now();
                let flags = Flags::empty();
                let state = match state.as_str() {
                    "n" => Ok(ProbeStatus::NotSent),
                    "s" => Ok(ProbeStatus::Skipped),
                    "a" => Ok(ProbeStatus::Awaited(Probe::new(
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
                        let expected_udp_checksum = Some(Checksum(u16::from_str(values[7])?));
                        let actual_udp_checksum = Some(Checksum(u16::from_str(values[8])?));
                        let icmp_packet_type = IcmpPacketType::NotApplicable;
                        Ok(ProbeStatus::Complete(
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
                                expected_udp_checksum,
                                actual_udp_checksum,
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

    /// A helper struct so we may inject the round into the probes.
    struct ProbeRound(ProbeData, RoundId);

    impl From<ProbeRound> for ProbeStatus {
        fn from(value: ProbeRound) -> Self {
            let probe_data = value.0;
            let round = value.1;
            match probe_data.0 {
                Self::NotSent => Self::NotSent,
                Self::Skipped => Self::Skipped,
                Self::Awaited(awaited) => Self::Awaited(Probe { round, ..awaited }),
                Self::Complete(completed) => Self::Complete(ProbeComplete { round, ..completed }),
                Self::Failed(failed) => Self::Failed(failed),
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
        last_nat_status: NatStatusWrapper,
    }

    /// A wrapper struct over `NatStatus` to allow deserialization.
    #[derive(Deserialize, Debug, Clone)]
    #[serde(try_from = "String")]
    struct NatStatusWrapper(NatStatus);

    impl TryFrom<String> for NatStatusWrapper {
        type Error = anyhow::Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            match value.to_ascii_lowercase().as_str() {
                "none" => Ok(Self(NatStatus::NotApplicable)),
                "nat" => Ok(Self(NatStatus::Detected)),
                "no_nat" => Ok(Self(NatStatus::NotDetected)),
                _ => Err(anyhow!("unknown nat status")),
            }
        }
    }

    macro_rules! file {
        ($path:expr) => {{
            let yaml = include_str!(concat!("../tests/resources/backend/", $path));
            serde_yaml::from_str(yaml).unwrap()
        }};
    }

    #[test_case(file!("ipv4_3probes_3hops_mixed_multi.yaml"))]
    #[test_case(file!("ipv4_3probes_3hops_completed.yaml"))]
    #[test_case(file!("ipv4_4probes_all_status.yaml"))]
    #[test_case(file!("ipv4_4probes_0latency.yaml"))]
    #[test_case(file!("ipv4_nat.yaml"))]
    fn test_scenario(scenario: Scenario) {
        let mut trace = State::new(StateConfig {
            max_flows: 1,
            ..StateConfig::default()
        });
        for (i, round) in scenario.rounds.into_iter().enumerate() {
            let probes = round
                .probes
                .into_iter()
                .map(|p| ProbeRound(p, RoundId(i)))
                .map(Into::into)
                .collect::<Vec<_>>();
            let largest_ttl = TimeToLive(scenario.largest_ttl);
            let tracer_round = Round::new(&probes, largest_ttl, CompletionReason::TargetFound);
            trace.update_from_round(&tracer_round);
        }
        let actual_hops = trace.hops();
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
            assert_eq!(actual.last_nat_status(), expected.last_nat_status.0);
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
