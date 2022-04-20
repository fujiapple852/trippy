use self::state::TracerState;
use crate::icmp::config::IcmpTracerConfig;
use crate::icmp::error::TraceResult;
use crate::icmp::net::IcmpChannel;
use crate::icmp::net::IcmpResponse;
use crate::icmp::probe::{IcmpPacketType, ProbeStatus};
use crate::icmp::Probe;
use derive_more::{Add, AddAssign, From, Mul, Sub};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Index newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Mul, AddAssign)]
pub struct Index(pub usize);

/// Round newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, AddAssign)]
pub struct Round(pub usize);

/// Time-to-live (ttl) newtype.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Add, Sub, AddAssign,
)]
pub struct TimeToLive(pub u8);

/// Sequence number newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct Sequence(pub u16);

/// Trace Identifier newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct TraceId(pub u16);

/// Max Inflight newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct MaxInflight(pub u8);

/// TODO
#[derive(Debug, Clone)]
pub struct IcmpTracer<F> {
    target_addr: IpAddr,
    trace_identifier: TraceId,
    first_ttl: TimeToLive,
    max_ttl: TimeToLive,
    grace_duration: Duration,
    max_inflight: MaxInflight,
    read_timeout: Duration,
    min_round_duration: Duration,
    max_round_duration: Duration,
    publish: F,
}

impl<F: Fn(&Probe)> IcmpTracer<F> {
    pub fn new(config: &IcmpTracerConfig, publish: F) -> Self {
        Self {
            target_addr: config.target_addr,
            trace_identifier: config.trace_identifier,
            first_ttl: config.first_ttl,
            max_ttl: config.max_ttl,
            grace_duration: config.grace_duration,
            max_inflight: config.max_inflight,
            read_timeout: config.read_timeout,
            min_round_duration: config.min_round_duration,
            max_round_duration: config.max_round_duration,
            publish,
        }
    }

    /// Run a continuous trace and publish results to a channel.
    ///
    /// TODO describe algorithm
    pub fn trace(self) -> TraceResult<()> {
        let mut channel = IcmpChannel::new()?;
        let mut state = TracerState::new(self.first_ttl);
        loop {
            self.send_request(&mut channel, &mut state)?;
            self.recv_response(&mut channel, &mut state)?;
            self.update_round(&mut state);
        }
    }

    /// Send the next ICMP `EchoRequest` if required.
    ///
    /// Send the next time-to-live (ttl) `EchoRequest` if all of the following are true:
    ///
    /// 1 - the target host has not been found
    /// 2 - the next ttl is not greater than the maximum allowed ttl
    /// 3 - if the target ttl of the target is known:
    ///       - the next ttl is not greater than the ttl of the target host observed from the prior round
    ///     otherwise:
    ///       - the number of unknown-in-flight echo requests is lower than the maximum allowed
    fn send_request(&self, channel: &mut IcmpChannel, st: &mut TracerState) -> TraceResult<()> {
        let can_send_ttl = if let Some(target_ttl) = st.target_ttl() {
            st.ttl() <= target_ttl
        } else {
            st.ttl() - st.max_received_ttl().unwrap_or_default()
                < TimeToLive::from(self.max_inflight.0)
        };
        if !st.target_found() && st.ttl() <= self.max_ttl && can_send_ttl {
            channel.send(st.next_probe()?, self.target_addr, self.trace_identifier.0)?;
        }
        Ok(())
    }

    /// Read and process the next incoming ICMP packet.
    ///
    /// We allow multiple `EchoRequest` to be in-flight at any time and we cannot guaranteed that responses will be
    /// received in-order.  We therefore maintain a circular buffer which holds details of each `Probe` which is
    /// indexed by a sequence number (modulo the buffer size).  The sequence number is set in the `EchoRequest` and
    /// returned in both the `TimeExceeded` and `EchoReply` responses.
    ///
    /// Each incoming ICMP packet contains an `identifier` which we validate to ensure we only process responses
    /// which correspond to `EchoRequest` packets sent from this process.
    ///
    /// When we process an `EchoReply` from the target host we extract the time-to-live from the corresponding
    /// original `EchoRequest`.  Note that this may not be the greatest time-to-live that was sent in the round as
    /// the algorithm will send `EchoRequest` wih larger time-to-live values before the `EchoReply` is received.
    fn recv_response(&self, channel: &mut IcmpChannel, st: &mut TracerState) -> TraceResult<()> {
        match channel.receive(self.read_timeout)? {
            Some(IcmpResponse::TimeExceeded(data)) => {
                let sequence = Sequence::from(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let trace_id = TraceId::from(data.identifier);
                if self.trace_identifier == trace_id && st.in_round(sequence) {
                    let probe = st
                        .probe_at(sequence)
                        .with_status(ProbeStatus::Complete)
                        .with_icmp_packet_type(IcmpPacketType::TimeExceeded)
                        .with_host(ip)
                        .with_received(received);
                    st.update_probe(sequence, probe, received, false);
                }
            }
            Some(IcmpResponse::DestinationUnreachable(data)) => {
                let sequence = Sequence::from(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let trace_id = TraceId::from(data.identifier);
                if self.trace_identifier == trace_id && st.in_round(sequence) {
                    let probe = st
                        .probe_at(sequence)
                        .with_status(ProbeStatus::Complete)
                        .with_icmp_packet_type(IcmpPacketType::Unreachable)
                        .with_host(ip)
                        .with_received(received);
                    st.update_probe(sequence, probe, received, false);
                }
            }
            Some(IcmpResponse::EchoReply(data)) => {
                let sequence = Sequence::from(data.sequence);
                let received = data.recv;
                let ip = data.addr;
                let trace_id = TraceId::from(data.identifier);
                if self.trace_identifier == trace_id && st.in_round(sequence) {
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
    /// 2 - either:
    ///     A - the target has been found OR
    ///     B - the target has not been found and the round has exceeded the maximum round duration
    fn update_round(&self, st: &mut TracerState) {
        let now = SystemTime::now();
        let round_duration = now.duration_since(st.round_start()).unwrap_or_default();
        if round_duration > self.min_round_duration
            && exceeds(st.received_time(), now, self.grace_duration)
            && st.target_found()
            || round_duration > self.max_round_duration
        {
            self.publish_trace(st);
            st.advance_round(self.first_ttl);
        }
    }

    /// Publish details of all `Probe` in the completed round to a channel.
    ///
    /// If the round completed without receiving an `EchoReply` from the target host then we also publish the next
    /// `Probe` which is assumed to represent the TTL of the target host.
    fn publish_trace(&self, state: &TracerState) {
        let round_size = if let Some(target_ttl) = state.target_ttl() {
            // If we started at ttl N and found the target at ttl M then the round contains M - N + 1 entries
            target_ttl.0 - self.first_ttl.0 + 1
        } else {
            // If we did not receive any responses then the round is size 0
            // If we started at ttl N and received a max ttl response M then the round contains M - N + 2 entries,
            // where the 'extra' entry represents the next ttl which did not receive a response.  This is capped by the
            // maximum allowed round size and so the largest ttl may not be the 'extra' one.
            state.max_received_ttl().map_or(0, |max_received_ttl| {
                let size = max_received_ttl.0.saturating_sub(self.first_ttl.0) + 1;
                let max_allowed = self.max_ttl.0 - self.first_ttl.0;
                size.min(max_allowed) + 1
            })
        };
        state
            .probes()
            .take(usize::from(round_size))
            .for_each(|probe| {
                debug_assert_eq!(probe.round, state.round());
                debug_assert_ne!(probe.ttl.0, 0);
                (self.publish)(probe);
            });
    }
}

/// Mutable state needed for the tracing algorithm.
///
/// This is contained within a sub-module to ensure that mutations are only performed via methods on the
/// `TracerState` struct.
mod state {
    use crate::icmp::error::{TraceResult, TracerError};
    use crate::icmp::tracer::{Index, Round, Sequence, TimeToLive};
    use crate::icmp::util::RemModU16Max;
    use crate::icmp::Probe;
    use std::time::SystemTime;

    /// The maximum number of `Probe` entries in the circular buffer.
    ///
    /// This is effectively also the maximum time-to-live (TTL) we can support.
    const BUFFER_SIZE: u16 = 256;

    /// Mutable state needed for the tracing algorithm.
    #[derive(Debug)]
    pub struct TracerState {
        /// The state of all `Probe` requests and responses.
        buffer: [Probe; BUFFER_SIZE as usize],
        /// a monotonically increasing index for every `EchoRequest`.
        index: Index,
        /// The starting index of the current round.
        round_index: Index,
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
        pub fn new(first_ttl: TimeToLive) -> Self {
            Self {
                buffer: [Probe::default(); BUFFER_SIZE as usize],
                index: Index(0),
                round_index: Index::from(0),
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

        /// Get an iterator over the `Probe` in the current round.
        pub fn probes(&self) -> impl Iterator<Item = &Probe> + '_ {
            self.buffer
                .iter()
                .cycle()
                .skip(self.round_index.0 % usize::from(BUFFER_SIZE))
        }

        /// Get the `Probe` for `sequence`
        pub fn probe_at(&self, sequence: Sequence) -> Probe {
            self.buffer[usize::from(sequence.0 % BUFFER_SIZE)]
        }

        pub const fn ttl(&self) -> TimeToLive {
            self.ttl
        }

        pub const fn round(&self) -> Round {
            self.round
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
        ///
        /// TODO this is likely broken when sequence wraps.
        pub fn in_round(&self, sequence: Sequence) -> bool {
            sequence.0 >= self.round_index.0.rem_u16max()
        }

        /// Create and return the next `Probe` at the current `seq` and `ttl`.
        pub fn next_probe(&mut self) -> TraceResult<Probe> {
            let probe = Probe::new(self.index, self.ttl, self.round, SystemTime::now());
            self.buffer[self.index.0 % usize::from(BUFFER_SIZE)] = probe;
            self.ttl += TimeToLive::from(1);
            if self.index < Index::from(usize::MAX) {
                self.index += Index::from(1);
                Ok(probe)
            } else {
                Err(TracerError::Generic)
            }
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
            self.buffer[usize::from(sequence.0) % usize::from(BUFFER_SIZE)] = probe;
            self.max_received_ttl = match self.max_received_ttl {
                Some(max_received_ttl) => Some(max_received_ttl.max(probe.ttl)),
                None => Some(probe.ttl),
            };
            self.received_time = Some(received_time);
            self.target_found |= found;
        }

        /// Advance to the next round.
        pub fn advance_round(&mut self, first_ttl: TimeToLive) {
            self.target_found = false;
            self.round_index = self.index;
            self.received_time = None;
            self.round_start = SystemTime::now();
            self.max_received_ttl = None;
            self.round += Round::from(1);
            self.ttl = first_ttl;
            self.target_seq = None;
        }
    }
}

/// Returns true if the duration between start and end is grater than a duration, false otherwise.
fn exceeds(start: Option<SystemTime>, end: SystemTime, dur: Duration) -> bool {
    start.map_or(false, |start| {
        end.duration_since(start).unwrap_or_default() > dur
    })
}
