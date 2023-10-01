use self::state::TracerState;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::Network;
use crate::tracing::probe::{
    ProbeResponse, ProbeResponseData, ProbeResponseSeq, ProbeResponseSeqIcmp, ProbeResponseSeqTcp,
    ProbeResponseSeqUdp,
};
use crate::tracing::types::{Sequence, TimeToLive, TraceId};
use crate::tracing::{MultipathStrategy, PortDirection, TracerProtocol};
use crate::tracing::{Probe, TracerConfig};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::instrument;

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
    config: TracerConfig,
    publish: F,
}

impl<F: Fn(&TracerRound<'_>)> Tracer<F> {
    #[instrument(skip_all)]
    pub fn new(config: &TracerConfig, publish: F) -> Self {
        tracing::debug!(?config);
        Self {
            config: *config,
            publish,
        }
    }

    /// Run a continuous trace and publish results.
    #[instrument(skip(self, network))]
    pub fn trace<N: Network>(self, mut network: N) -> TraceResult<()> {
        let mut state = TracerState::new(self.config);
        while !state.finished(self.config.max_rounds) {
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
    ///       - the next ttl is not greater than the ttl of the target host observed from the prior
    ///         round
    ///     otherwise:
    ///       - the number of unknown-in-flight probes is lower than the maximum allowed
    #[instrument(skip(self, network, st))]
    fn send_request<N: Network>(&self, network: &mut N, st: &mut TracerState) -> TraceResult<()> {
        let can_send_ttl = if let Some(target_ttl) = st.target_ttl() {
            st.ttl() <= target_ttl
        } else {
            st.ttl() - st.max_received_ttl().unwrap_or_default()
                < TimeToLive(self.config.max_inflight.0)
        };
        if !st.target_found() && st.ttl() <= self.config.max_ttl && can_send_ttl {
            match self.config.protocol {
                TracerProtocol::Icmp => {
                    network.send_probe(st.next_probe())?;
                }
                TracerProtocol::Udp => network.send_probe(st.next_probe())?,
                TracerProtocol::Tcp => {
                    let mut probe = if st.round_has_capacity() {
                        st.next_probe()
                    } else {
                        return Err(TracerError::InsufficientCapacity);
                    };
                    while let Err(err) = network.send_probe(probe) {
                        match err {
                            TracerError::AddressNotAvailable(_) => {
                                if st.round_has_capacity() {
                                    probe = st.reissue_probe();
                                } else {
                                    return Err(TracerError::InsufficientCapacity);
                                }
                            }
                            other => return Err(other),
                        }
                    }
                }
            };
        }
        Ok(())
    }

    /// Read and process the next incoming `ICMP` packet.
    ///
    /// We allow multiple probes to be in-flight at any time and we cannot guaranteed that responses
    /// will be received in-order.  We therefore maintain a buffer which holds details of each
    /// `Probe` which is indexed by the offset of the sequence number from the sequence number
    /// at the beginning of the round.  The sequence number is set in the outgoing `ICMP`
    /// `EchoRequest` (or `UDP` / `TCP`) packet and returned in both the `TimeExceeded` and
    /// `EchoReply` responses.
    ///
    /// Each incoming `ICMP` packet contains the original `ICMP` `EchoRequest` packet from which we
    /// can read the `identifier` that we set which we can now validate to ensure we only
    /// process responses which correspond to packets sent from this process.  For The `UDP` and
    /// `TCP` protocols, only packets destined for our src port will be delivered to us by the
    /// OS and so no other `identifier` is needed and so we allow the special case value of 0.
    ///
    /// When we process an `EchoReply` from the target host we extract the time-to-live from the
    /// corresponding original `EchoRequest`.  Note that this may not be the greatest
    /// time-to-live that was sent in the round as the algorithm will send `EchoRequest` with
    /// larger time-to-live values before the `EchoReply` is received.
    #[instrument(skip(self, network, st))]
    fn recv_response<N: Network>(&self, network: &mut N, st: &mut TracerState) -> TraceResult<()> {
        let next = network.recv_probe()?;
        match next {
            Some(ProbeResponse::TimeExceeded(data, extensions)) => {
                let (trace_id, sequence, received, host) = self.extract(&data);
                let is_target = host == self.config.target_addr;
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    st.complete_probe_time_exceeded(
                        sequence, host, received, is_target, extensions,
                    );
                }
            }
            Some(ProbeResponse::DestinationUnreachable(data, extensions)) => {
                let (trace_id, sequence, received, host) = self.extract(&data);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    st.complete_probe_unreachable(sequence, host, received, extensions);
                }
            }
            Some(ProbeResponse::EchoReply(data)) => {
                let (trace_id, sequence, received, host) = self.extract(&data);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    st.complete_probe_echo_reply(sequence, host, received);
                }
            }
            Some(ProbeResponse::TcpReply(data) | ProbeResponse::TcpRefused(data)) => {
                let (trace_id, sequence, received, host) = self.extract(&data);
                if self.check_trace_id(trace_id) && st.in_round(sequence) {
                    st.complete_probe_other(sequence, host, received);
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
    #[instrument(skip(self, st))]
    fn update_round(&self, st: &mut TracerState) {
        let now = SystemTime::now();
        let round_duration = now.duration_since(st.round_start()).unwrap_or_default();
        let round_min = round_duration > self.config.min_round_duration;
        let grace_exceeded = exceeds(st.received_time(), now, self.config.grace_duration);
        let round_max = round_duration > self.config.max_round_duration;
        let target_found = st.target_found();
        if round_min && grace_exceeded && target_found || round_max {
            self.publish_trace(st);
            st.advance_round(self.config.first_ttl);
        }
    }

    /// Publish details of all `Probe` in the completed round.
    ///
    /// If the round completed without receiving an `EchoReply` from the target host then we also
    /// publish the next `Probe` which is assumed to represent the TTL of the target host.
    #[instrument(skip(self, state))]
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
    #[instrument(skip(self))]
    fn check_trace_id(&self, trace_id: TraceId) -> bool {
        self.config.trace_identifier == trace_id || trace_id == TraceId(0)
    }

    /// Extract the `TraceId`, `Sequence`, `SystemTime` and `IpAddr` from the `ProbeResponseData` in
    /// a protocol specific way.
    #[instrument(skip(self))]
    fn extract(&self, resp: &ProbeResponseData) -> (TraceId, Sequence, SystemTime, IpAddr) {
        match resp.resp_seq {
            ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp {
                identifier,
                sequence,
            }) => (
                TraceId(identifier),
                Sequence(sequence),
                resp.recv,
                resp.addr,
            ),
            ProbeResponseSeq::Udp(ProbeResponseSeqUdp {
                identifier,
                src_port,
                dest_port,
                checksum,
            }) => {
                let sequence = match (self.config.multipath_strategy, self.config.port_direction) {
                    (MultipathStrategy::Classic, PortDirection::FixedDest(_)) => src_port,
                    (MultipathStrategy::Classic, _) => dest_port,
                    (MultipathStrategy::Paris, _) => checksum,
                    (MultipathStrategy::Dublin, _) => identifier,
                };
                (TraceId(0), Sequence(sequence), resp.recv, resp.addr)
            }
            ProbeResponseSeq::Tcp(ProbeResponseSeqTcp {
                src_port,
                dest_port,
            }) => {
                let sequence = match self.config.port_direction {
                    PortDirection::FixedSrc(_) => dest_port,
                    _ => src_port,
                };
                (TraceId(0), Sequence(sequence), resp.recv, resp.addr)
            }
        }
    }
}

/// Mutable state needed for the tracing algorithm.
///
/// This is contained within a sub-module to ensure that mutations are only performed via methods on
/// the `TracerState` struct.
mod state {
    use crate::tracing::constants::MAX_SEQUENCE_PER_ROUND;
    use crate::tracing::probe::Extensions;
    use crate::tracing::types::{MaxRounds, Port, Round, Sequence, TimeToLive, TraceId};
    use crate::tracing::{
        IcmpPacketType, MultipathStrategy, PortDirection, Probe, ProbeStatus, TracerConfig,
        TracerProtocol,
    };
    use std::array::from_fn;
    use std::net::IpAddr;
    use std::time::SystemTime;
    use tracing::instrument;

    /// The maximum number of `Probe` entries in the buffer.
    ///
    /// This is larger than maximum number of time-to-live (TTL) we can support to allow for skipped
    /// sequences.
    const BUFFER_SIZE: u16 = MAX_SEQUENCE_PER_ROUND;

    /// The maximum sequence number.
    ///
    /// The sequence number is only ever wrapped between rounds and so we need to ensure that there
    /// are enough sequence numbers for a complete round.
    ///
    /// A sequence number can be skipped if, for example, the port for that sequence number cannot
    /// be bound as it is already in use.
    ///
    /// To ensure each `Probe` is in the correct place in the buffer (i.e. the index into the buffer
    /// is always `Probe.sequence - round_sequence`), when we skip a sequence we leave the
    /// skipped `Probe` in-place and use the next slot for the next sequence.
    ///
    /// We cap the number of sequences that can potentially be skipped in a round to ensure that
    /// sequence number does not even need to wrap around during a round.
    ///
    /// We only ever send `ttl` in the range 1..255 and so we may use all buffer capacity, except
    /// the minimum needed to send up to a max `ttl` of 255 (a `ttl` of 0 is never sent).
    const MAX_SEQUENCE: Sequence = Sequence(u16::MAX - BUFFER_SIZE);

    /// Mutable state needed for the tracing algorithm.
    #[derive(Debug)]
    pub struct TracerState {
        /// Tracer configuration.
        config: TracerConfig,
        /// The state of all `Probe` requests and responses.
        buffer: [Probe; BUFFER_SIZE as usize],
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
        ///
        /// Note that this is _not_ reset each round and that it can also _change_ over time,
        /// including going _down_ as responses can be are received out-of-order.
        target_ttl: Option<TimeToLive>,
        /// The timestamp of the echo response packet.
        received_time: Option<SystemTime>,
    }

    impl TracerState {
        pub fn new(config: TracerConfig) -> Self {
            Self {
                config,
                buffer: from_fn(|_| Probe::default()),
                sequence: config.initial_sequence,
                round_sequence: config.initial_sequence,
                ttl: config.first_ttl,
                round: Round(0),
                round_start: SystemTime::now(),
                target_found: false,
                max_received_ttl: None,
                target_ttl: None,
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
            self.buffer[usize::from(sequence - self.round_sequence)].clone()
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

        /// Do we have capacity in the current round for another sequence?
        pub fn round_has_capacity(&self) -> bool {
            let round_size = self.sequence - self.round_sequence;
            round_size.0 < BUFFER_SIZE
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
        /// We post-increment `ttl` here and so in practice we only allow `ttl` values in the range
        /// `1..254` to allow us to use a `u8`.
        #[instrument(skip(self))]
        pub fn next_probe(&mut self) -> Probe {
            let (src_port, dest_port, identifier) = self.probe_data();
            let probe = Probe::new(
                self.sequence,
                identifier,
                src_port,
                dest_port,
                self.ttl,
                self.round,
                SystemTime::now(),
            );
            self.buffer[usize::from(self.sequence - self.round_sequence)] = probe.clone();
            debug_assert!(self.ttl < TimeToLive(u8::MAX));
            self.ttl += TimeToLive(1);
            debug_assert!(self.sequence < Sequence(u16::MAX));
            self.sequence += Sequence(1);
            probe
        }

        /// Re-issue the `Probe` with the next sequence number.
        ///
        /// This will mark the `Probe` at the previous `sequence` as skipped and re-create it with
        /// the previous `ttl` and the current `sequence`.
        ///
        /// For example, if the sequence is `4` and the `ttl` is `5` prior to calling this method
        /// then afterwards:
        /// - The `Probe` at sequence `3` will be reset to default values (i.e. `NotSent` status)
        /// - A new `Probe` will be created at sequence `4` with a `ttl` of `5`
        #[instrument(skip(self))]
        pub fn reissue_probe(&mut self) -> Probe {
            self.buffer[usize::from(self.sequence - self.round_sequence) - 1] = Probe::default();
            let (src_port, dest_port, identifier) = self.probe_data();
            let probe = Probe::new(
                self.sequence,
                identifier,
                src_port,
                dest_port,
                self.ttl - TimeToLive(1),
                self.round,
                SystemTime::now(),
            );
            self.buffer[usize::from(self.sequence - self.round_sequence)] = probe.clone();
            debug_assert!(self.sequence < Sequence(u16::MAX));
            self.sequence += Sequence(1);
            probe
        }

        /// Determine the `src_port`, `dest_port` and `identifier` for the current probe.
        ///
        /// This will differ depending on the `TracerProtocol`, `MultipathStrategy` &
        /// `PortDirection`.
        fn probe_data(&self) -> (Port, Port, TraceId) {
            match self.config.protocol {
                TracerProtocol::Icmp => self.probe_icmp_data(),
                TracerProtocol::Udp => self.probe_udp_data(),
                TracerProtocol::Tcp => self.probe_tcp_data(),
            }
        }

        /// Determine the `src_port`, `dest_port` and `identifier` for the current ICMP probe.
        fn probe_icmp_data(&self) -> (Port, Port, TraceId) {
            (Port(0), Port(0), self.config.trace_identifier)
        }

        /// Determine the `src_port`, `dest_port` and `identifier` for the current UDP probe.
        fn probe_udp_data(&self) -> (Port, Port, TraceId) {
            match self.config.multipath_strategy {
                MultipathStrategy::Classic => match self.config.port_direction {
                    PortDirection::FixedSrc(src_port) => {
                        (Port(src_port.0), Port(self.sequence.0), TraceId(0))
                    }
                    PortDirection::FixedDest(dest_port) => {
                        (Port(self.sequence.0), Port(dest_port.0), TraceId(0))
                    }
                    PortDirection::FixedBoth(_, _) | PortDirection::None => {
                        unimplemented!()
                    }
                },
                MultipathStrategy::Paris => {
                    let round_port = ((self.config.initial_sequence.0 as usize + self.round.0)
                        % usize::from(u16::MAX)) as u16;
                    match self.config.port_direction {
                        PortDirection::FixedSrc(src_port) => {
                            (Port(src_port.0), Port(round_port), TraceId(0))
                        }
                        PortDirection::FixedDest(dest_port) => {
                            (Port(round_port), Port(dest_port.0), TraceId(0))
                        }
                        PortDirection::FixedBoth(src_port, dest_port) => {
                            (Port(src_port.0), Port(dest_port.0), TraceId(0))
                        }
                        PortDirection::None => unimplemented!(),
                    }
                }
                MultipathStrategy::Dublin => {
                    let round_port = ((self.config.initial_sequence.0 as usize + self.round.0)
                        % usize::from(u16::MAX)) as u16;
                    match self.config.port_direction {
                        PortDirection::FixedSrc(src_port) => {
                            (Port(src_port.0), Port(round_port), TraceId(self.sequence.0))
                        }
                        PortDirection::FixedDest(dest_port) => (
                            Port(round_port),
                            Port(dest_port.0),
                            TraceId(self.sequence.0),
                        ),
                        PortDirection::FixedBoth(src_port, dest_port) => (
                            Port(src_port.0),
                            Port(dest_port.0),
                            TraceId(self.sequence.0),
                        ),
                        PortDirection::None => unimplemented!(),
                    }
                }
            }
        }
        /// Determine the `src_port`, `dest_port` and `identifier` for the current TCP probe.
        fn probe_tcp_data(&self) -> (Port, Port, TraceId) {
            let (src_port, dest_port) = match self.config.port_direction {
                PortDirection::FixedSrc(src_port) => (src_port.0, self.sequence.0),
                PortDirection::FixedDest(dest_port) => (self.sequence.0, dest_port.0),
                PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
            };
            (Port(src_port), Port(dest_port), TraceId(0))
        }

        /// Mark the `Probe` at `sequence` completed as `TimeExceeded` and update the round state.
        #[instrument(skip(self))]
        pub fn complete_probe_time_exceeded(
            &mut self,
            sequence: Sequence,
            host: IpAddr,
            received: SystemTime,
            is_target: bool,
            extensions: Option<Extensions>,
        ) {
            self.complete_probe(
                sequence,
                IcmpPacketType::TimeExceeded,
                host,
                received,
                is_target,
                extensions,
            );
        }

        /// Mark the `Probe` at `sequence` completed as `Unreachable` and update the round state.
        #[instrument(skip(self))]
        pub fn complete_probe_unreachable(
            &mut self,
            sequence: Sequence,
            host: IpAddr,
            received: SystemTime,
            extensions: Option<Extensions>,
        ) {
            self.complete_probe(
                sequence,
                IcmpPacketType::Unreachable,
                host,
                received,
                true,
                extensions,
            );
        }

        /// Mark the `Probe` at `sequence` completed as `EchoReply` and update the round state.
        #[instrument(skip(self))]
        pub fn complete_probe_echo_reply(
            &mut self,
            sequence: Sequence,
            host: IpAddr,
            received: SystemTime,
        ) {
            self.complete_probe(
                sequence,
                IcmpPacketType::EchoReply,
                host,
                received,
                true,
                None,
            );
        }

        /// Mark the `Probe` at `sequence` completed as `NotApplicable` and update the round state.
        #[instrument(skip(self))]
        pub fn complete_probe_other(
            &mut self,
            sequence: Sequence,
            host: IpAddr,
            received: SystemTime,
        ) {
            self.complete_probe(
                sequence,
                IcmpPacketType::NotApplicable,
                host,
                received,
                true,
                None,
            );
        }

        /// Update the state of a `Probe` and the trace.
        ///
        /// We want to update:
        ///
        /// - the `target_ttl` to be the time-to-live of the `Probe` request from the target
        /// - the `max_received_ttl` we have observed this round
        /// - the latest packet `received_time` in this round
        /// - whether the target has been found in this round
        ///
        /// The ICMP replies may arrive out-of-order and so we must be careful here to avoid
        /// overwriting the state with stale values.  We may also receive multiple replies
        /// from the target host with differing time-to-live values and so must ensure we
        /// use the time-to-live with the lowest sequence number.
        #[instrument(skip(self))]
        fn complete_probe(
            &mut self,
            sequence: Sequence,
            icmp_packet_type: IcmpPacketType,
            host: IpAddr,
            received: SystemTime,
            is_target: bool,
            extensions: Option<Extensions>,
        ) {
            // Retrieve and update the `Probe` at `sequence`.
            let probe = self
                .probe_at(sequence)
                .with_status(ProbeStatus::Complete)
                .with_icmp_packet_type(icmp_packet_type)
                .with_host(host)
                .with_received(received)
                .with_extensions(extensions);
            self.buffer[usize::from(sequence - self.round_sequence)] = probe.clone();

            // If this `Probe` found the target then we set the `target_tll` if not already set,
            // being careful to account for `Probes` being received out-of-order.
            //
            // If this `Probe` did not find the target but has a ttl that is greater or equal to the
            // target ttl (if known) then we reset the target ttl to None.  This is to
            // support Equal Cost Multi-path Routing (ECMP) cases where the number of
            // hops to the target will vary over the lifetime of the trace.
            self.target_ttl = if is_target {
                match self.target_ttl {
                    None => Some(probe.ttl),
                    Some(target_ttl) if probe.ttl < target_ttl => Some(probe.ttl),
                    Some(target_ttl) => Some(target_ttl),
                }
            } else {
                match self.target_ttl {
                    Some(target_ttl) if probe.ttl >= target_ttl => None,
                    Some(target_ttl) => Some(target_ttl),
                    None => None,
                }
            };

            self.max_received_ttl = match self.max_received_ttl {
                None => Some(probe.ttl),
                Some(max_received_ttl) => Some(max_received_ttl.max(probe.ttl)),
            };

            self.received_time = Some(received);
            self.target_found |= is_target;
        }

        /// Advance to the next round.
        ///
        /// If, during the rond which just completed, we went above the max sequence number then we
        /// reset it here. We do this here to avoid having to deal with the sequence number
        /// wrapping during a round, which is more problematic.
        #[instrument(skip(self))]
        pub fn advance_round(&mut self, first_ttl: TimeToLive) {
            if self.sequence >= MAX_SEQUENCE {
                self.sequence = self.config.initial_sequence;
            }
            self.target_found = false;
            self.round_sequence = self.sequence;
            self.received_time = None;
            self.round_start = SystemTime::now();
            self.max_received_ttl = None;
            self.round += Round(1);
            self.ttl = first_ttl;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tracing::probe::IcmpPacketType;
        use crate::tracing::types::{MaxInflight, PacketSize, PayloadPattern};
        use crate::tracing::ProbeStatus;
        use rand::Rng;
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Duration;

        #[allow(
            clippy::cognitive_complexity,
            clippy::too_many_lines,
            clippy::bool_assert_comparison
        )]
        #[test]
        fn test_state() {
            let mut state = TracerState::new(cfg(Sequence(33000)));

            // Validate the initial TracerState
            assert_eq!(state.round, Round(0));
            assert_eq!(state.sequence, Sequence(33000));
            assert_eq!(state.round_sequence, Sequence(33000));
            assert_eq!(state.ttl, TimeToLive(1));
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
            state.complete_probe_time_exceeded(Sequence(33000), host, received_1, false, None);

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
            assert_eq!(state.max_received_ttl, Some(TimeToLive(1)));
            assert_eq!(state.received_time, Some(received_1));
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // Validate the probes() iterator returns returns only a single probe
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = probe_iter.next().unwrap();
                assert_eq!(&probe_1_fetch, probe_next1);
                assert_eq!(None, probe_iter.next());
            }

            // Advance to the next round
            state.advance_round(TimeToLive(1));

            // Validate the TracerState after the round update
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33001));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(1));
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
            state.complete_probe_time_exceeded(Sequence(33001), host, received_2, false, None);
            let probe_2_recv = state.probe_at(Sequence(33001));

            // Validate the TracerState after the update to probe 2
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33003));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(3));
            assert_eq!(state.max_received_ttl, Some(TimeToLive(1)));
            assert_eq!(state.received_time, Some(received_2));
            assert_eq!(state.target_ttl, None);
            assert_eq!(state.target_found, false);

            // Validate the probes() iterator returns the two probes in the states we expect
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = probe_iter.next().unwrap();
                assert_eq!(&probe_2_recv, probe_next1);
                let probe_next2 = probe_iter.next().unwrap();
                assert_eq!(&probe_3, probe_next2);
            }

            // Update the state of probe 3 after receiving a EchoReply
            let received_3 = SystemTime::now();
            let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
            state.complete_probe_echo_reply(Sequence(33002), host, received_3);
            let probe_3_recv = state.probe_at(Sequence(33002));

            // Validate the TracerState after the update to probe 3
            assert_eq!(state.round, Round(1));
            assert_eq!(state.sequence, Sequence(33003));
            assert_eq!(state.round_sequence, Sequence(33001));
            assert_eq!(state.ttl, TimeToLive(3));
            assert_eq!(state.max_received_ttl, Some(TimeToLive(2)));
            assert_eq!(state.received_time, Some(received_3));
            assert_eq!(state.target_ttl, Some(TimeToLive(2)));
            assert_eq!(state.target_found, true);

            // Validate the probes() iterator returns the two probes in the states we expect
            {
                let mut probe_iter = state.probes().iter();
                let probe_next1 = probe_iter.next().unwrap();
                assert_eq!(&probe_2_recv, probe_next1);
                let probe_next2 = probe_iter.next().unwrap();
                assert_eq!(&probe_3_recv, probe_next2);
            }
        }

        #[test]
        fn test_sequence_wrap1() {
            // Start from MAX_SEQUENCE - 1 which is (65279 - 1) == 65278
            let initial_sequence = Sequence(65278);
            let mut state = TracerState::new(cfg(initial_sequence));
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
            state.advance_round(TimeToLive(1));
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
            let mut state = TracerState::new(cfg(Sequence(33000)));
            for _ in 0..total_rounds {
                for _ in 0..max_probe_per_round {
                    let _probe = state.next_probe();
                }
                state.advance_round(TimeToLive(1));
            }
            assert_eq!(state.round, Round(2000));
            assert_eq!(state.round_sequence, Sequence(33000));
            assert_eq!(state.sequence, Sequence(33000));
        }

        #[test]
        fn test_sequence_wrap3() {
            let total_rounds = 2000;
            let max_probe_per_round = 20;
            let mut state = TracerState::new(cfg(Sequence(33000)));
            let mut rng = rand::thread_rng();
            for _ in 0..total_rounds {
                for _ in 0..rng.gen_range(0..max_probe_per_round) {
                    state.next_probe();
                }
                state.advance_round(TimeToLive(1));
            }
        }

        #[test]
        fn test_sequence_wrap_with_skip() {
            let total_rounds = 2000;
            let max_probe_per_round = 254;
            let mut state = TracerState::new(cfg(Sequence(33000)));
            for _ in 0..total_rounds {
                for _ in 0..max_probe_per_round {
                    _ = state.next_probe();
                    _ = state.reissue_probe();
                }
                state.advance_round(TimeToLive(1));
            }
            assert_eq!(state.round, Round(2000));
            assert_eq!(state.round_sequence, Sequence(56876));
            assert_eq!(state.sequence, Sequence(56876));
        }

        #[test]
        fn test_in_round() {
            let state = TracerState::new(cfg(Sequence(33000)));
            assert!(state.in_round(Sequence(33000)));
            assert!(state.in_round(Sequence(34023)));
            assert!(!state.in_round(Sequence(34024)));
        }

        #[test]
        #[should_panic]
        fn test_in_delayed_probe_not_in_round() {
            let mut state = TracerState::new(cfg(Sequence(64000)));
            for _ in 0..55 {
                _ = state.next_probe();
            }
            state.advance_round(TimeToLive(1));
            assert!(!state.in_round(Sequence(64491)));
        }

        fn cfg(initial_sequence: Sequence) -> TracerConfig {
            TracerConfig {
                target_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                protocol: TracerProtocol::Icmp,
                trace_identifier: TraceId::default(),
                max_rounds: None,
                first_ttl: TimeToLive(1),
                max_ttl: TimeToLive(24),
                grace_duration: Duration::default(),
                max_inflight: MaxInflight::default(),
                initial_sequence,
                multipath_strategy: MultipathStrategy::Classic,
                port_direction: PortDirection::None,
                read_timeout: Duration::default(),
                min_round_duration: Duration::default(),
                max_round_duration: Duration::default(),
                packet_size: PacketSize::default(),
                payload_pattern: PayloadPattern::default(),
            }
        }
    }
}

/// Returns true if the duration between start and end is grater than a duration, false otherwise.
fn exceeds(start: Option<SystemTime>, end: SystemTime, dur: Duration) -> bool {
    start.map_or(false, |start| {
        end.duration_since(start).unwrap_or_default() > dur
    })
}
