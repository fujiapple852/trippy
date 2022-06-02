use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Port, Sequence, TimeToLive, TraceId,
    TypeOfService,
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
#[derive(Debug, Copy, Clone)]
pub enum TracerAddrFamily {
    /// Internet Protocol V4
    Ipv4,
    /// Internet Protocol V6
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

/// Whether to fix the src, dest or both ports for a trace.
#[derive(Debug, Copy, Clone)]
pub enum PortDirection {
    /// Trace without any source or destination port (i.e. for ICMP tracing).
    None,
    /// Trace from a fixed source port to a variable destination port (i.e. 5000 -> *).
    ///
    /// This is the default direction for UDP tracing.
    FixedSrc(Port),
    /// Trace from a variable source port to a fixed destination port (i.e. * -> 80).
    ///
    /// This is the default direction for TCP tracing.
    FixedDest(Port),
    /// Trace from a fixed source port to a fixed destination port (i.e. 5000 -> 80).
    ///
    /// When both ports are fixed another element of the IP header is required to vary per probe such that probes can
    /// be identified.  Typically this is only used for UDP, whereby the checksum is manipulated by adjusting the
    /// payload and therefore used as the identifier.
    ///
    /// Note that this case is not currently implemented.
    FixedBoth(Port, Port),
}

impl PortDirection {
    #[must_use]
    pub fn new_fixed_src(src: u16) -> Self {
        Self::FixedSrc(Port(src))
    }

    #[must_use]
    pub fn new_fixed_dest(dest: u16) -> Self {
        Self::FixedDest(Port(dest))
    }

    #[must_use]
    pub fn new_fixed_both(src: u16, dest: u16) -> Self {
        Self::FixedBoth(Port(src), Port(dest))
    }

    #[must_use]
    pub fn src(&self) -> Option<Port> {
        match *self {
            Self::FixedSrc(src) | Self::FixedBoth(src, _) => Some(src),
            _ => None,
        }
    }
    #[must_use]
    pub fn dest(&self) -> Option<Port> {
        match *self {
            Self::FixedDest(dest) | Self::FixedBoth(_, dest) => Some(dest),
            _ => None,
        }
    }
}

/// Tracer network channel configuration.
#[derive(Debug, Clone)]
pub struct TracerChannelConfig {
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub source_addr: Option<IpAddr>,
    pub interface: Option<String>,
    pub target_addr: IpAddr,
    pub identifier: TraceId,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub tos: TypeOfService,
    pub port_direction: PortDirection,
    pub read_timeout: Duration,
    pub tcp_connect_timeout: Duration,
}

impl TracerChannelConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        protocol: TracerProtocol,
        addr_family: TracerAddrFamily,
        source_addr: Option<IpAddr>,
        interface: Option<String>,
        target_addr: IpAddr,
        identifier: u16,
        packet_size: u16,
        payload_pattern: u8,
        tos: u8,
        port_direction: PortDirection,
        read_timeout: Duration,
        tcp_connect_timeout: Duration,
    ) -> Self {
        Self {
            protocol,
            addr_family,
            source_addr,
            interface,
            target_addr,
            identifier: TraceId(identifier),
            packet_size: PacketSize(packet_size),
            payload_pattern: PayloadPattern(payload_pattern),
            tos: TypeOfService(tos),
            port_direction,
            read_timeout,
            tcp_connect_timeout,
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
