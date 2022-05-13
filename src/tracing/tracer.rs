use self::state::TracerState;
use crate::tracing::error::TraceResult;
use crate::tracing::net::{Network, ProbeResponse};
use crate::tracing::types::{MaxInflight, MaxRounds, Sequence, TimeToLive, TraceId};
use crate::tracing::TracerProtocol;
use crate::tracing::{IcmpPacketType, ProbeStatus};
use crate::tracing::{Probe, TracerConfig};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// The output from a round of tracing.
#[derive(Debug, Clone)]
pub struct TracerRound<'a> {
    /// The state of all `Probe` that were sent in the round.
    pub probes: &'a [Probe],
    /// The largest time-to-live (ttl) for which we received a reply in the round.
    pub largest_ttl: TimeToLive,
    /// Indicates what triggered the completion of the tracing round.
    pub reason: CompletionReason,
}

impl<'a> TracerRound<'a> {
    #[must_use]
    pub fn new(probes: &'a [Probe], largest_ttl: TimeToLive, reason: CompletionReason) -> Self {
        Self {
            probes,
            largest_ttl,
            reason,
        }
    }
}

/// Indicates what triggered the completion of the tracing round.
#[derive(Debug, Copy, Clone)]
pub enum CompletionReason {
    /// The round ended because the target was found.
    TargetFound,
    /// The round ended because the time exceeded the configured maximum round time.
    RoundTimeLimitExceeded,
}

/// Trace a path to a target.
#[derive(Debug, Clone)]
pub struct Tracer<F> {
    target_addr: IpAddr,
    protocol: TracerProtocol,
    trace_identifier: TraceId,
    max_rounds: Option<MaxRounds>,
    first_ttl: TimeToLive,
    max_ttl: TimeToLive,
    grace_duration: Duration,
    max_inflight: MaxInflight,
    initial_sequence: Sequence,
    read_timeout: Duration,
    min_round_duration: Duration,
    max_round_duration: Duration,
    publish: F,
}

impl<F: Fn(&TracerRound<'_>)> Tracer<F> {
    pub fn new(config: &TracerConfig, publish: F) -> Self {
        Self {
            target_addr: config.target_addr,
            protocol: config.protocol,
            trace_identifier: config.trace_identifier,
            max_rounds: config.max_rounds,
            first_ttl: config.first_ttl,
            max_ttl: config.max_ttl,
            grace_duration: config.grace_duration,
            max_inflight: config.max_inflight,
            initial_sequence: config.initial_sequence,
            read_timeout: config.read_timeout,
            min_round_duration: config.min_round_duration,
            max_round_duration: config.max_round_duration,
            publish,
        }
    }

    /// Run a continuous trace and publish results.
    ///
    /// TODO describe algorithm
    pub fn trace<N: Network>(self, mut network: N) -> TraceResult<()> {
        let mut state = TracerState::new(self.first_ttl, self.initial_sequence);
        while !state.finished(self.max_rounds) {
            self.send_request(&mut network, &mut state)?;
            self.recv_response(&mut network, &mut state)?;
            self.update_round(&mut state);
        }
        Ok(())
    }

    /// Send the next probe if required.
    ///
    /// Send a `Probe` for the next time-to-live (ttl) if all of the following are true:
    ///
    /// 1 - the target host has not been found
    /// 2 - the next ttl is not greater than the maximum allowed ttl
    /// 3 - if the target ttl of the target is known:
    ///       - the next ttl is not greater than the ttl of the target host observed from the prior round
    ///     otherwise:
    ///       - the number of unknown-in-flight probes is lower than the maximum allowed
    fn send_request<N: Network>(&self, network: &mut N, st: &mut TracerState) -> TraceResult<()> {
        let can_send_ttl = if let Some(target_ttl) = st.target_ttl() {
            st.ttl() <= target_ttl
        } else {
            st.ttl() - st.max_received_ttl().unwrap_or_default()
                < TimeToLive::from(self.max_inflight.0)
        };
        if !st.target_found() && st.ttl() <= self.max_ttl && can_send_ttl {
            match self.protocol {
                TracerProtocol::Icmp => network.send_icmp_probe(st.next_probe())?,
                TracerProtocol::Udp => network.send_udp_probe(st.next_probe())?,
                TracerProtocol::Tcp => network.send_tcp_probe(st.next_probe())?,
            }
        }
        Ok(())
    }

    /// Read and process the next incoming `ICMP` packet.
    ///
    /// We allow multiple probes to be in-flight at any time and we cannot guaranteed that responses will be
    /// received in-order.  We therefore maintain a buffer which holds details of each `Probe` which is
    /// indexed by the offset of the sequence number from the sequence number at the beginning of the round.  The
    /// sequence number is set in the outgoing `ICMP` `EchoRequest` (or `UDP` / `TCP`) packet and returned in both
    /// the `TimeExceeded` and `EchoReply` responses.
    ///
    /// Each incoming `ICMP` packet contains the original `ICMP` `EchoRequest` packet from which we can read the
    /// `identifier` that we set which we can now validate to ensure we only process responses which correspond to
    /// packets sent from this process.  For The `UDP` and `TCP` protocols, only packets destined for our src port will
    /// be delivered to us by the OS and so no other `identifier` is needed and so we allow the special case value of 0.
    ///
    /// When we process an `EchoReply` from the target host we extract the time-to-live from the corresponding
    /// original `EchoRequest`.  Note that this may not be the greatest time-to-live that was sent in the round as
    /// the algorithm will send `EchoRequest` wih larger time-to-live values before the `EchoReply` is received.
    fn recv_response<N: Network>(&self, network: &mut N, st: &mut TracerState) -> TraceResult<()> {
        let next = match self.protocol {
            TracerProtocol::Icmp => network.recv_probe_resp_icmp(self.read_timeout)?,
            TracerProtocol::Udp => network.recv_probe_resp_udp(self.read_timeout)?,
            TracerProtocol::Tcp => network.recv_probe_resp_tcp(self.read_timeout)?,
        };
        match next {
            Some(ProbeResponse::TimeExceeded(data)) => {
                let sequence = Sequence(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let is_target = ip == self.target_addr;
                let trace_id = TraceId::from(data.identifier);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    let probe = st
                        .probe_at(sequence)
                        .with_status(ProbeStatus::Complete)
                        .with_icmp_packet_type(IcmpPacketType::TimeExceeded)
                        .with_host(ip)
                        .with_received(received);
                    st.update_probe(sequence, probe, received, is_target);
                }
            }
            Some(ProbeResponse::DestinationUnreachable(data)) => {
                let sequence = Sequence(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let trace_id = TraceId::from(data.identifier);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    let probe = st
                        .probe_at(sequence)
                        .with_status(ProbeStatus::Complete)
                        .with_icmp_packet_type(IcmpPacketType::Unreachable)
                        .with_host(ip)
                        .with_received(received);
                    st.update_probe(sequence, probe, received, true);
                }
            }
            Some(ProbeResponse::EchoReply(data)) => {
                let sequence = Sequence(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let trace_id = TraceId::from(data.identifier);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    let probe = st
                        .probe_at(sequence)
                        .with_status(ProbeStatus::Complete)
                        .with_icmp_packet_type(IcmpPacketType::EchoReply)
                        .with_host(ip)
                        .with_received(received);
                    st.update_probe(sequence, probe, received, true);
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Check if the round is complete and publish the results.
    ///
    /// A round is considered to be complete when:
    ///
    /// 1 - the round has exceed the minimum round duration AND
    /// 2 - the duration since the last packet was received exceeds the grace period AND
    /// 3 - either:
    ///     A - the target has been found OR
    ///     B - the target has not been found and the round has exceeded the maximum round duration
    fn update_round(&self, st: &mut TracerState) {
        let now = SystemTime::now();
        let round_duration = now.duration_since(st.round_start()).unwrap_or_default();
        let round_min = round_duration > self.min_round_duration;
        let grace_exceeded = exceeds(st.received_time(), now, self.grace_duration);
        let round_max = round_duration > self.max_round_duration;
        let target_found = st.target_found();
        if round_min && grace_exceeded && target_found || round_max {
            self.publish_trace(st);
            st.advance_round(self.first_ttl);
        }
    }

    /// Publish details of all `Probe` in the completed round.
    ///
    /// If the round completed without receiving an `EchoReply` from the target host then we also publish the next
    /// `Probe` which is assumed to represent the TTL of the target host.
    fn publish_trace(&self, state: &TracerState) {
        let max_received_ttl = if let Some(target_ttl) = state.target_ttl() {
            target_ttl
        } else {
            state
                .max_received_ttl()
                .map_or(TimeToLive(0), |max_received_ttl| {
                    let max_sent_ttl = state.ttl() - TimeToLive(1);
                    max_sent_ttl.min(max_received_ttl + TimeToLive(1))
                })
        };
        let probes = state.probes();
        let largest_ttl = max_received_ttl;
        let reason = if state.target_found() {
            CompletionReason::TargetFound
        } else {
            CompletionReason::RoundTimeLimitExceeded
        };
        (self.publish)(&TracerRound::new(probes, largest_ttl, reason));
    }

    /// Check if the `TraceId` matches the expected value for this tracer.
    ///
    /// A special value of `0` is accepted for `udp` and `tcp` which do not have an identifier.
    fn check_trace_id(&self, trace_id: TraceId) -> bool {
        self.trace_identifier == trace_id || trace_id == TraceId::from(0)
    }
}

/// Mutable state needed for the tracing algorithm.
///
/// This is contained within a sub-module to ensure that mutations are only performed via methods on the
/// `TracerState` struct.
mod state {
    use crate::tracing::types::{MaxRounds, Round, Sequence, TimeToLive};
    use crate::tracing::Probe;
    use std::time::SystemTime;

    /// The maximum number of `Probe` entries in the buffer.
    ///
    /// This is effectively also the maximum number of time-to-live (TTL) we can support.  We only ever send TTL in
    /// the range 1..255 so this is technically one larger than we need.
    const BUFFER_SIZE: u16 = 256;

    /// The maximum sequence number.
    ///
    /// The sequence number is only ever wrapped between rounds and so we need to ensure that there are enough sequence
    /// numbers for a complete round (i.e. the max TTL, which is `BUFFER_SIZE`).
    const MAX_SEQUENCE: Sequence = Sequence(u16::MAX - BUFFER_SIZE);

    /// Mutable state needed for the tracing algorithm.
    #[derive(Debug)]
    pub struct TracerState {
        /// The state of all `Probe` requests and responses.
        buffer: [Probe; BUFFER_SIZE as usize],
        /// The initial sequence number configuration, used to reset sequence when it wraps around.
        initial_sequence: Sequence,
        /// An increasing sequence number for every `EchoRequest`.
        sequence: Sequence,
        /// The starting sequence number of the current round.
        round_sequence: Sequence,
        /// The time-to-live for the _next_ `EchoRequest` packet to be sent.
        ttl: TimeToLive,
        /// The current round.
        round: Round,
        /// The timestamp of when the current round started.
        round_start: SystemTime,
        /// Did we receive an `EchoReply` from the target host in this round?
        target_found: bool,
        /// The maximum time-to-live echo response packet we have received.
        max_received_ttl: Option<TimeToLive>,
        /// The observed time-to-live of the `EchoReply` from the target host.
        target_ttl: Option<TimeToLive>,
        /// The sequence of the `EchoReply` from the target host.
        target_seq: Option<Sequence>,
        /// The timestamp of the echo response packet.
        received_time: Option<SystemTime>,
    }

    impl TracerState {
        pub fn new(first_ttl: TimeToLive, initial_sequence: Sequence) -> Self {
            Self {
                buffer: [Probe::default(); BUFFER_SIZE as usize],
                initial_sequence,
                sequence: initial_sequence,
                round_sequence: initial_sequence,
                ttl: first_ttl,
                round: Round::from(0),
                round_start: SystemTime::now(),
                target_found: false,
                max_received_ttl: None,
                target_ttl: None,
                target_seq: None,
                received_time: None,
            }
        }

        /// Get a slice of `Probe` for the current round.
        pub fn probes(&self) -> &[Probe] {
            let round_size = self.sequence - self.round_sequence;
            &self.buffer[..round_size.0 as usize]
        }

        /// Get the `Probe` for `sequence`
        pub fn probe_at(&self, sequence: Sequence) -> Probe {
            self.buffer[usize::from(sequence - self.round_sequence)]
        }

        /// Find the first `Probe` for `ttl`.
        pub fn probe_for_ttl(&self, ttl: TimeToLive) -> Option<&Probe> {
            self.probes().iter().find(|p| p.ttl == ttl)
        }

        pub const fn ttl(&self) -> TimeToLive {
            self.ttl
        }

        pub const fn round_start(&self) -> SystemTime {
            self.round_start
        }

        pub const fn target_found(&self) -> bool {
            self.target_found
        }

        pub const fn max_received_ttl(&self) -> Option<TimeToLive> {
            self.max_received_ttl
        }

        pub const fn target_ttl(&self) -> Option<TimeToLive> {
            self.target_ttl
        }

        pub const fn received_time(&self) -> Option<SystemTime> {
            self.received_time
        }

        /// Is `sequence` in the current round?
        pub fn in_round(&self, sequence: Sequence) -> bool {
            sequence >= self.round_sequence && sequence.0 - self.round_sequence.0 < BUFFER_SIZE
        }

        /// Have all round completed?
        pub fn finished(&self, max_rounds: Option<MaxRounds>) -> bool {
            match max_rounds {
                None => false,
                Some(max_rounds) => self.round.0 > max_rounds.0,
            }
        }

        /// Create and return the next `Probe` at the current `sequence` and `ttl`.
        ///
        /// We post-increment `ttl` here and so in practice we only allow `ttl` values in the range `1..254` to allow
        /// us to use a `u8`.
        pub fn next_probe(&mut self) -> Probe {
            let probe = Probe::new(self.sequence, self.ttl, self.round, SystemTime::now());
            self.buffer[usize::from(self.sequence - self.round_sequence)] = probe;
            debug_assert!(self.ttl < TimeToLive(u8::MAX));
            self.ttl += TimeToLive::from(1);
            debug_assert!(self.sequence < Sequence(u16::MAX));
            self.sequence += Sequence(1);
            probe
        }

        /// Re-issue the `Probe` with the next sequence number.
        ///
        /// This will mark the `Probe` at the previous `sequence` as skipped and re-create it with the previous `ttl`
        /// and the current `sequence`.
        ///
        /// For example, if the sequence is `4` and the `ttl` is `5` prior to calling this method then afterwards:
        /// - The `Probe` at sequence `3` will be reset to default values (i.e. `NotSent` status)
        /// - A new `Probe` will be created at sequence `4` with a `ttl` of `5`
        pub fn reissue_probe(&mut self) -> Probe {
            self.buffer[usize::from(self.sequence - self.round_sequence) - 1] = Probe::default();
            let probe = Probe::new(
                self.sequence,
                self.ttl - TimeToLive(1),
                self.round,
                SystemTime::now(),
            );
            self.buffer[usize::from(self.sequence - self.round_sequence)] = probe;
            debug_assert!(self.sequence < Sequence(u16::MAX));
            self.sequence += Sequence(1);
            probe
        }

        /// Update the state of an `Probe`.
        ///
        /// We want to update:
        ///
        /// - the target ttl to be the time-to-live of the `Probe` request from the target
        /// - the maximum ttl we have observed this round
        /// - the latest packet received time
        ///
        /// The ICMP replies may arrive out-of-order and so we must be careful here to avoid overwriting the state with
        /// stale values.  We may also receive multiple replies from the target host with differing time-to-live values and
        /// so must ensure we use the time-to-live with the lowest sequence number.
        pub fn update_probe(
            &mut self,
            sequence: Sequence,
            probe: Probe,
            received_time: SystemTime,
            found: bool,
        ) {
            match (self.target_ttl, self.target_seq) {
                (None, _) if found => {
                    self.target_ttl = Some(probe.ttl);
                    self.target_seq = Some(sequence);
                }
                (Some(_), Some(target_seq)) if found && sequence < target_seq => {
                    self.target_ttl = Some(probe.ttl);
                    self.target_seq = Some(sequence);
                }
                _ => {}
            }
            self.buffer[usize::from(sequence - self.round_sequence)] = probe;
            self.max_received_ttl = match self.max_received_ttl {
                Some(max_received_ttl) => Some(max_received_ttl.max(probe.ttl)),
                None => Some(probe.ttl),
            };
            self.received_time = Some(received_time);
            self.target_found |= found;
        }

        /// Advance to the next round.
        ///
        /// If, during the rond which just completed, we went above the max sequence number then we reset it here.
        /// We do this here to avoid having to deal with the sequence number wrapping during a round, which is more
        /// problematic.
        pub fn advance_round(&mut self, first_ttl: TimeToLive) {
            if self.sequence >= MAX_SEQUENCE {
                self.sequence = self.initial_sequence;
            }
            self.target_found = false;
            self.round_sequence = self.sequence;
            self.received_time = None;
            self.round_start = SystemTime::now();
            self.max_received_ttl = None;
            self.round += Round::from(1);
            self.ttl = first_ttl;
            self.target_seq = None;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tracing::probe::IcmpPacketType;
        use crate::tracing::ProbeStatus;
        use rand::Rng;
        use std::net::{IpAddr, Ipv4Addr};

        #[allow(
            clippy::cognitive_complexity,
            clippy::too_many_lines,
            clippy::bool_assert_comparison
        )]
        #[test]
        fn test_state() {
            let mut state = TracerState::new(TimeToLive::from(1), Sequence(33000));

            // Validate the initial TracerState
            assert_eq!(state.round, Round(0));
            assert_eq!(state.sequence, Sequence(33000));
            assert_eq!(state.round_sequence, Sequence(33000));
            assert_eq!(state.ttl, TimeToLive(1));
            assert_eq!(state.target_seq, None);
            assert_eq!(state.max_received_ttl, None);
            assert_eq!(state.received_time, None);
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // The initial state of the probe before sending
            let prob_init = state.probe_at(Sequence(33000));
            assert_eq!(prob_init.sequence, Sequence(0));
            assert_eq!(prob_init.ttl, TimeToLive(0));
            assert_eq!(prob_init.round, Round(0));
            assert_eq!(prob_init.received, None);
            assert_eq!(prob_init.host, None);
            assert_eq!(prob_init.sent.is_some(), false);
            assert_eq!(prob_init.status, ProbeStatus::NotSent);
            assert_eq!(prob_init.icmp_packet_type, None);

            // Prepare probe 1 (round 0, sequence 33000, ttl 1) for sending
            let probe_1 = state.next_probe();
            assert_eq!(probe_1.sequence, Sequence(33000));
            assert_eq!(probe_1.ttl, TimeToLive(1));
            assert_eq!(probe_1.round, Round(0));
            assert_eq!(probe_1.received, None);
            assert_eq!(probe_1.host, None);
            assert_eq!(probe_1.sent.is_some(), true);
            assert_eq!(probe_1.status, ProbeStatus::Awaited);
            assert_eq!(probe_1.icmp_packet_type, None);

            // Update the state of the probe 1 after receiving a TimeExceeded
            let received_1 = SystemTime::now();
            let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let probe_1_recv = state
                .probe_at(Sequence(33000))
                .with_status(ProbeStatus::Complete)
                .with_icmp_packet_type(IcmpPacketType::TimeExceeded)
                .with_host(host)
                .with_received(received_1);
            state.update_probe(Sequence(33000), probe_1_recv, received_1, false);

            // Validate the state of the probe 1 after the update
            let probe_1_fetch = state.probe_at(Sequence(33000));
            assert_eq!(probe_1_fetch.sequence, Sequence(33000));
            assert_eq!(probe_1_fetch.ttl, TimeToLive(1));
            assert_eq!(probe_1_fetch.round, Round(0));
            assert_eq!(probe_1_fetch.received, Some(received_1));
            assert_eq!(probe_1_fetch.host, Some(host));
            assert_eq!(probe_1_fetch.sent.is_some(), true);
            assert_eq!(probe_1_fetch.status, ProbeStatus::Complete);
            assert_eq!(
                probe_1_fetch.icmp_packet_type,
                Some(IcmpPacketType::TimeExceeded)
            );

            // Validate the TracerState after the update
            assert_eq!(state.round, Round(0));
            assert_eq!(state.sequence, Sequence(33001));
            assert_eq!(state.round_sequence, Sequence(33000));
            assert_eq!(state.ttl, TimeToLive(2));
            assert_eq!(state.target_seq, None);
            assert_eq!(state.max_received_ttl, Some(TimeToLive(1)));
            assert_eq!(state.received_time, Some(received_1));
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // Validate the probes() iterator returns returns only a single probe
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = *probe_iter.next().unwrap();
                assert_eq!(probe_1_fetch, probe_next1);
                assert_eq!(None, probe_iter.next());
            }

            // Advance to the next round
            state.advance_round(TimeToLive(1));

            // Validate the TracerState after the round update
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33001));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(1));
            assert_eq!(state.target_seq, None);
            assert_eq!(state.max_received_ttl, None);
            assert_eq!(state.received_time, None);
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // Prepare probe 2 (round 1, sequence 33001, ttl 1) for sending
            let probe_2 = state.next_probe();
            assert_eq!(probe_2.sequence, Sequence(33001));
            assert_eq!(probe_2.ttl, TimeToLive(1));
            assert_eq!(probe_2.round, Round(1));
            assert_eq!(probe_2.received, None);
            assert_eq!(probe_2.host, None);
            assert_eq!(probe_2.sent.is_some(), true);
            assert_eq!(probe_2.status, ProbeStatus::Awaited);
            assert_eq!(probe_2.icmp_packet_type, None);

            // Prepare probe 3 (round 1, sequence 33002, ttl 2) for sending
            let probe_3 = state.next_probe();
            assert_eq!(probe_3.sequence, Sequence(33002));
            assert_eq!(probe_3.ttl, TimeToLive(2));
            assert_eq!(probe_3.round, Round(1));
            assert_eq!(probe_3.received, None);
            assert_eq!(probe_3.host, None);
            assert_eq!(probe_3.sent.is_some(), true);
            assert_eq!(probe_3.status, ProbeStatus::Awaited);
            assert_eq!(probe_3.icmp_packet_type, None);

            // Update the state of probe 2 after receiving a TimeExceeded
            let received_2 = SystemTime::now();
            let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let probe_2_recv = state
                .probe_at(Sequence(33001))
                .with_status(ProbeStatus::Complete)
                .with_icmp_packet_type(IcmpPacketType::TimeExceeded)
                .with_host(host)
                .with_received(received_2);
            state.update_probe(Sequence(33001), probe_2_recv, received_2, false);

            // Validate the TracerState after the update to probe 2
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33003));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(3));
            assert_eq!(state.target_seq, None);
            assert_eq!(state.max_received_ttl, Some(TimeToLive(1)));
            assert_eq!(state.received_time, Some(received_2));
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // Validate the probes() iterator returns the two probes in the states we expect
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = *probe_iter.next().unwrap();
                assert_eq!(probe_2_recv, probe_next1);
                let probe_next2 = *probe_iter.next().unwrap();
                assert_eq!(probe_3, probe_next2);
            }

            // Update the state of probe 3 after receiving a EchoReply
            let received_3 = SystemTime::now();
            let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let probe_3_recv = state
                .probe_at(Sequence(33002))
                .with_status(ProbeStatus::Complete)
                .with_icmp_packet_type(IcmpPacketType::EchoReply)
                .with_host(host)
                .with_received(received_3);
            state.update_probe(Sequence(33002), probe_3_recv, received_3, true);

            // Validate the TracerState after the update to probe 3
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33003));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(3));
            assert_eq!(state.target_seq, Some(Sequence(33002)));
            assert_eq!(state.max_received_ttl, Some(TimeToLive(2)));
            assert_eq!(state.received_time, Some(received_3));
            assert_eq!(state.target_ttl, Some(TimeToLive(2)));
            assert_eq!(state.target_found, true);

            // Validate the probes() iterator returns the two probes in the states we expect
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = *probe_iter.next().unwrap();
                assert_eq!(probe_2_recv, probe_next1);
                let probe_next2 = *probe_iter.next().unwrap();
                assert_eq!(probe_3_recv, probe_next2);
            }
        }

        #[test]
        fn test_sequence_wrap1() {
            // Start from MAX_SEQUENCE - 1 which is (65279 - 1) == 65278
            let initial_sequence = Sequence(65278);
            let mut state = TracerState::new(TimeToLive::from(1), initial_sequence);
            assert_eq!(state.round, Round(0));
            assert_eq!(state.sequence, initial_sequence);
            assert_eq!(state.round_sequence, initial_sequence);

            // Create a probe at seq 65278
            assert_eq!(state.next_probe().sequence, Sequence(65278));
            assert_eq!(state.sequence, Sequence(65279));

            // Validate the probes()
            {
                let mut iter = state.probes().iter();
                assert_eq!(iter.next().unwrap().sequence, Sequence(65278));
                iter.take(BUFFER_SIZE as usize - 1)
                    .for_each(|p| assert_eq!(p.sequence, Sequence(0)));
            }

            // Advance the round, which will wrap the sequence back to initial_sequence
            state.advance_round(TimeToLive::from(1));
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, initial_sequence);
            assert_eq!(state.round_sequence, initial_sequence);

            // Create a probe at seq 65278
            assert_eq!(state.next_probe().sequence, Sequence(65278));
            assert_eq!(state.sequence, Sequence(65279));

            // Validate the probes() again
            {
                let mut iter = state.probes().iter();
                assert_eq!(iter.next().unwrap().sequence, Sequence(65278));
                iter.take(BUFFER_SIZE as usize - 1)
                    .for_each(|p| assert_eq!(p.sequence, Sequence(0)));
            }
        }

        #[test]
        fn test_sequence_wrap2() {
            let total_rounds = 2000;
            let max_probe_per_round = 254;
            let mut state = TracerState::new(TimeToLive::from(1), Sequence(33000));
            for _ in 0..total_rounds {
                for _ in 0..max_probe_per_round {
                    let _probe = state.next_probe();
                }
                state.advance_round(TimeToLive::from(1));
            }
            assert_eq!(state.round, Round(2000));
            assert_eq!(state.round_sequence, Sequence(53320));
            assert_eq!(state.sequence, Sequence(53320));
        }

        #[test]
        fn test_sequence_wrap3() {
            let total_rounds = 2000;
            let max_probe_per_round = 20;
            let mut state = TracerState::new(TimeToLive::from(1), Sequence(33000));
            let mut rng = rand::thread_rng();
            for _ in 0..total_rounds {
                for _ in 0..rng.gen_range(0..max_probe_per_round) {
                    state.next_probe();
                }
                state.advance_round(TimeToLive::from(1));
            }
        }

        #[test]
        fn test_in_round() {
            let state = TracerState::new(TimeToLive::from(1), Sequence(33000));
            assert!(state.in_round(Sequence(33000)));
            assert!(state.in_round(Sequence(33255)));
            assert!(!state.in_round(Sequence(33256)));
        }
    }
}

/// Returns true if the duration between start and end is grater than a duration, false otherwise.
fn exceeds(start: Option<SystemTime>, end: SystemTime, dur: Duration) -> bool {
    start.map_or(false, |start| {
        end.duration_since(start).unwrap_or_default() > dur
    })
}
