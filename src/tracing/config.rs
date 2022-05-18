use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Sequence, TimeToLive, TraceId,
};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

/// The maximum time-to-live value allowed.
const MAX_TTL: u8 = 254;

/// The maximum _starting_ sequence number allowed.
///
/// This ensures that there are sufficient sequence numbers available for at least one round.
const MAX_SEQUENCE: u16 = u16::MAX - MAX_TTL as u16 - 1;

/// The address family.
pub enum TracerAddrFamily {
    Ipv4,
    Ipv6,
}

/// The tracing protocol.
#[derive(Debug, Copy, Clone)]
pub enum TracerProtocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

impl Display for TracerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "icmp"),
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

/// Tracing algorithm configuration.
#[derive(Debug, Copy, Clone)]
pub struct TracerConfig {
    pub target_addr: IpAddr,
    pub protocol: TracerProtocol,
    pub trace_identifier: TraceId,
    pub max_rounds: Option<MaxRounds>,
    pub first_ttl: TimeToLive,
    pub max_ttl: TimeToLive,
    pub grace_duration: Duration,
    pub max_inflight: MaxInflight,
    pub initial_sequence: Sequence,
    pub read_timeout: Duration,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
}

impl TracerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_addr: IpAddr,
        protocol: TracerProtocol,
        max_rounds: Option<usize>,
        trace_identifier: u16,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        max_inflight: u8,
        initial_sequence: u16,
        read_timeout: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        packet_size: u16,
        payload_pattern: u8,
    ) -> TraceResult<Self> {
        if first_ttl > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "first_ttl ({}) > {}",
                first_ttl, MAX_TTL
            )));
        }
        if max_ttl > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "max_ttl ({}) > {}",
                first_ttl, MAX_TTL
            )));
        }
        if initial_sequence > MAX_SEQUENCE {
            return Err(TracerError::BadConfig(format!(
                "initial_sequence ({}) > {}",
                initial_sequence, MAX_SEQUENCE
            )));
        }
        Ok(Self {
            target_addr,
            protocol,
            trace_identifier: TraceId(trace_identifier),
            max_rounds: max_rounds.map(MaxRounds),
            first_ttl: TimeToLive(first_ttl),
            max_ttl: TimeToLive(max_ttl),
            grace_duration,
            max_inflight: MaxInflight(max_inflight),
            initial_sequence: Sequence(initial_sequence),
            read_timeout,
            min_round_duration,
            max_round_duration,
            packet_size: PacketSize(packet_size),
            payload_pattern: PayloadPattern(payload_pattern),
        })
    }
}
