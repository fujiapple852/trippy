use crate::tracing::constants::{MAX_SEQUENCE, MAX_TTL};
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Port, Sequence, TimeToLive, TraceId,
    TypeOfService,
};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

/// The privilege mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PrivilegeMode {
    /// Privileged mode.
    Privileged,
    /// Unprivileged mode.
    Unprivileged,
}

impl Display for PrivilegeMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Privileged => write!(f, "privileged"),
            Self::Unprivileged => write!(f, "unprivileged"),
        }
    }
}

/// The address family.
#[derive(Debug, Copy, Clone)]
pub enum TracerAddrFamily {
    /// Internet Protocol V4
    Ipv4,
    /// Internet Protocol V6
    Ipv6,
}

impl Display for TracerAddrFamily {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "v4"),
            Self::Ipv6 => write!(f, "v6"),
        }
    }
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

/// The [Equal-cost Multi-Path](https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing) routing strategy.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MultipathStrategy {
    /// The src or dest port is used to store the sequence number.
    ///
    /// This does _not_ allow fixing both the src and dest port and so `PortDirection::Both` and
    /// `SequenceField::Port` are mutually exclusive.
    Classic,
    /// The UDP `checksum` field is used to store the sequence number.
    ///
    /// a.k.a [`paris`](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum) traceroute approach.
    ///
    /// This requires that the UDP payload contains a well chosen value to ensure the UDP checksum
    /// remains valid for the packet and therefore this cannot be used along with a custom
    /// payload pattern.
    Paris,
    /// The IP `identifier` field is used to store the sequence number.
    ///
    /// a.k.a [`dublin](https://github.com/insomniacslk/dublin-traceroute) traceroute approach.
    ///
    /// The allow either the src or dest or both ports to be fixed.
    ///
    /// If either of the src or dest port may vary (i.e. `PortDirection::FixedSrc` or
    /// `PortDirection::FixedDest`) then the port number is set to be the `initial_sequence`
    /// plus the round number to ensure that there is a fixed `flowid` (protocol, src ip/port,
    /// dest ip/port) for all packets in a given tracing round.  Each round may
    /// therefore discover different paths.
    ///
    /// If both src and dest ports are fixed (i.e. `PortDirection::FixedBoth`) then every packet in
    /// every round will share the same `flowid` and thus only a single path will be
    /// discovered.
    Dublin,
}

impl Display for MultipathStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Classic => write!(f, "classic"),
            Self::Paris => write!(f, "paris"),
            Self::Dublin => write!(f, "dublin"),
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
    /// When both ports are fixed another element of the IP header is required to vary per probe
    /// such that probes can be identified.  Typically this is only used for UDP, whereby the
    /// checksum is manipulated by adjusting the payload and therefore used as the identifier.
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
    pub privilege_mode: PrivilegeMode,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub source_addr: IpAddr,
    pub target_addr: IpAddr,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub multipath_strategy: MultipathStrategy,
    pub tos: TypeOfService,
    pub icmp_extensions: bool,
    pub read_timeout: Duration,
    pub tcp_connect_timeout: Duration,
}

impl TracerChannelConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        privilege_mode: PrivilegeMode,
        protocol: TracerProtocol,
        addr_family: TracerAddrFamily,
        source_addr: IpAddr,
        target_addr: IpAddr,
        packet_size: u16,
        payload_pattern: u8,
        multipath_strategy: MultipathStrategy,
        tos: u8,
        icmp_extensions: bool,
        read_timeout: Duration,
        tcp_connect_timeout: Duration,
    ) -> Self {
        Self {
            privilege_mode,
            protocol,
            addr_family,
            source_addr,
            target_addr,
            packet_size: PacketSize(packet_size),
            payload_pattern: PayloadPattern(payload_pattern),
            multipath_strategy,
            tos: TypeOfService(tos),
            icmp_extensions,
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
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
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
        multipath_strategy: MultipathStrategy,
        port_direction: PortDirection,
        read_timeout: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        packet_size: u16,
        payload_pattern: u8,
    ) -> TraceResult<Self> {
        if first_ttl > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "first_ttl ({first_ttl}) > {MAX_TTL}"
            )));
        }
        if max_ttl > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "max_ttl ({first_ttl}) > {MAX_TTL}"
            )));
        }
        if initial_sequence > MAX_SEQUENCE {
            return Err(TracerError::BadConfig(format!(
                "initial_sequence ({initial_sequence}) > {MAX_SEQUENCE}"
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
            multipath_strategy,
            port_direction,
            read_timeout,
            min_round_duration,
            max_round_duration,
            packet_size: PacketSize(packet_size),
            payload_pattern: PayloadPattern(payload_pattern),
        })
    }
}
