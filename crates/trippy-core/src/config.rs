use crate::types::Port;
use crate::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Sequence, TimeToLive, TraceId,
    TypeOfService,
};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Default values for configuration.
pub mod defaults {
    use crate::config::IcmpExtensionParseMode;
    use crate::{MultipathStrategy, PrivilegeMode, Protocol};
    use std::time::Duration;

    /// The default value for `unprivileged`.
    pub const DEFAULT_PRIVILEGE_MODE: PrivilegeMode = PrivilegeMode::Privileged;

    /// The default value for `protocol`.
    pub const DEFAULT_STRATEGY_PROTOCOL: Protocol = Protocol::Icmp;

    /// The default value for `multipath-strategy`.
    pub const DEFAULT_STRATEGY_MULTIPATH: MultipathStrategy = MultipathStrategy::Classic;

    /// The default value for `icmp-extensions`.
    pub const DEFAULT_ICMP_EXTENSION_PARSE_MODE: IcmpExtensionParseMode =
        IcmpExtensionParseMode::Disabled;

    /// The default value for `max-inflight`.
    pub const DEFAULT_STRATEGY_MAX_INFLIGHT: u8 = 24;

    /// The default value for `first-ttl`.
    pub const DEFAULT_STRATEGY_FIRST_TTL: u8 = 1;

    /// The default value for `max-ttl`.
    pub const DEFAULT_STRATEGY_MAX_TTL: u8 = 64;

    /// The default value for `packet-size`.
    pub const DEFAULT_STRATEGY_PACKET_SIZE: u16 = 84;

    /// The default value for `payload-pattern`.
    pub const DEFAULT_STRATEGY_PAYLOAD_PATTERN: u8 = 0;

    /// The default value for `min-round-duration`.
    pub const DEFAULT_STRATEGY_MIN_ROUND_DURATION: Duration = Duration::from_millis(1000);

    /// The default value for `max-round-duration`.
    pub const DEFAULT_STRATEGY_MAX_ROUND_DURATION: Duration = Duration::from_millis(1000);

    /// The default value for `initial-sequence`.
    pub const DEFAULT_STRATEGY_INITIAL_SEQUENCE: u16 = 33434;

    /// The default value for `tos`.
    pub const DEFAULT_STRATEGY_TOS: u8 = 0;

    /// The default value for `read-timeout`.
    pub const DEFAULT_STRATEGY_READ_TIMEOUT: Duration = Duration::from_millis(10);

    /// The default value for `grace-duration`.
    pub const DEFAULT_STRATEGY_GRACE_DURATION: Duration = Duration::from_millis(100);

    /// The default TCP connect timeout.
    pub const DEFAULT_STRATEGY_TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(1000);

    /// The default value for `max-samples`.
    pub const DEFAULT_MAX_SAMPLES: usize = 256;

    /// The default value for `max-flows`.
    pub const DEFAULT_MAX_FLOWS: usize = 64;
}

/// The privilege mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PrivilegeMode {
    /// Privileged mode.
    Privileged,
    /// Unprivileged mode.
    Unprivileged,
}

impl PrivilegeMode {
    #[must_use]
    pub const fn is_unprivileged(self) -> bool {
        match self {
            Self::Privileged => false,
            Self::Unprivileged => true,
        }
    }
}

impl Display for PrivilegeMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Privileged => write!(f, "privileged"),
            Self::Unprivileged => write!(f, "unprivileged"),
        }
    }
}

/// The ICMP extension parsing mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IcmpExtensionParseMode {
    /// Do not parse ICMP extensions.
    Disabled,
    /// Parse ICMP extensions.
    Enabled,
}

impl IcmpExtensionParseMode {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Enabled => true,
        }
    }
}

impl Display for IcmpExtensionParseMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Enabled => write!(f, "enabled"),
        }
    }
}

/// The tracing protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Protocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

impl Display for Protocol {
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
    /// a.k.a. [`paris`](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum) traceroute approach.
    ///
    /// This requires that the UDP payload contains a well-chosen value to ensure the UDP checksum
    /// remains valid for the packet and therefore this cannot be used along with a custom
    /// payload pattern.
    Paris,
    /// The IP `identifier` field is used to store the sequence number.
    ///
    /// a.k.a. [`dublin`](https://github.com/insomniacslk/dublin-traceroute) traceroute approach.
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
    /// such that probes can be identified.  Typically, this is only used for UDP, whereby the
    /// checksum is manipulated by adjusting the payload and therefore used as the identifier.
    ///
    /// Note that this case is not currently implemented.
    FixedBoth(Port, Port),
}

impl PortDirection {
    #[must_use]
    pub const fn new_fixed_src(src: u16) -> Self {
        Self::FixedSrc(Port(src))
    }

    #[must_use]
    pub const fn new_fixed_dest(dest: u16) -> Self {
        Self::FixedDest(Port(dest))
    }

    #[must_use]
    pub const fn new_fixed_both(src: u16, dest: u16) -> Self {
        Self::FixedBoth(Port(src), Port(dest))
    }

    #[must_use]
    pub const fn src(&self) -> Option<Port> {
        match *self {
            Self::FixedSrc(src) | Self::FixedBoth(src, _) => Some(src),
            _ => None,
        }
    }
    #[must_use]
    pub const fn dest(&self) -> Option<Port> {
        match *self {
            Self::FixedDest(dest) | Self::FixedBoth(_, dest) => Some(dest),
            _ => None,
        }
    }
}

/// Tracer state configuration.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct StateConfig {
    /// The maximum number of samples to record per hop.
    ///
    /// Once the maximum number of samples has been reached the oldest sample
    /// is discarded (FIFO).
    pub max_samples: usize,
    /// The maximum number of flows to record.
    ///
    /// Once the maximum number of flows has been reached no new flows will be
    /// created, existing flows are updated and are never removed.
    pub max_flows: usize,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            max_samples: defaults::DEFAULT_MAX_SAMPLES,
            max_flows: defaults::DEFAULT_MAX_FLOWS,
        }
    }
}

/// Tracer network channel configuration.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ChannelConfig {
    pub privilege_mode: PrivilegeMode,
    pub protocol: Protocol,
    pub source_addr: IpAddr,
    pub target_addr: IpAddr,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub initial_sequence: Sequence,
    pub tos: TypeOfService,
    pub icmp_extension_parse_mode: IcmpExtensionParseMode,
    pub read_timeout: Duration,
    pub tcp_connect_timeout: Duration,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            privilege_mode: defaults::DEFAULT_PRIVILEGE_MODE,
            protocol: defaults::DEFAULT_STRATEGY_PROTOCOL,
            source_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            target_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            packet_size: PacketSize(defaults::DEFAULT_STRATEGY_PACKET_SIZE),
            payload_pattern: PayloadPattern(defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN),
            initial_sequence: Sequence(defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE),
            tos: TypeOfService(defaults::DEFAULT_STRATEGY_TOS),
            icmp_extension_parse_mode: defaults::DEFAULT_ICMP_EXTENSION_PARSE_MODE,
            read_timeout: defaults::DEFAULT_STRATEGY_READ_TIMEOUT,
            tcp_connect_timeout: defaults::DEFAULT_STRATEGY_TCP_CONNECT_TIMEOUT,
        }
    }
}

/// Tracing strategy configuration.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct StrategyConfig {
    pub target_addr: IpAddr,
    pub protocol: Protocol,
    pub trace_identifier: TraceId,
    pub max_rounds: Option<MaxRounds>,
    pub first_ttl: TimeToLive,
    pub max_ttl: TimeToLive,
    pub grace_duration: Duration,
    pub max_inflight: MaxInflight,
    pub initial_sequence: Sequence,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            target_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            protocol: defaults::DEFAULT_STRATEGY_PROTOCOL,
            trace_identifier: TraceId::default(),
            max_rounds: None,
            first_ttl: TimeToLive(defaults::DEFAULT_STRATEGY_FIRST_TTL),
            max_ttl: TimeToLive(defaults::DEFAULT_STRATEGY_MAX_TTL),
            grace_duration: defaults::DEFAULT_STRATEGY_GRACE_DURATION,
            max_inflight: MaxInflight(defaults::DEFAULT_STRATEGY_MAX_INFLIGHT),
            initial_sequence: Sequence(defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE),
            multipath_strategy: defaults::DEFAULT_STRATEGY_MULTIPATH,
            port_direction: PortDirection::None,
            min_round_duration: defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION,
            max_round_duration: defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION,
        }
    }
}
