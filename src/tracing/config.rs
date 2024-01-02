use crate::tracing::constants::{MAX_SEQUENCE, MAX_TTL};
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Port, Sequence, TimeToLive, TraceId,
    TypeOfService,
};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub mod defaults {
    use crate::tracing::{MultipathStrategy, PrivilegeMode, TracerAddrFamily, TracerProtocol};
    use std::time::Duration;

    /// The default value for `unprivileged`.
    pub const DEFAULT_PRIVILEGE_MODE: PrivilegeMode = PrivilegeMode::Privileged;

    /// The default value for `protocol`.
    pub const DEFAULT_STRATEGY_PROTOCOL: TracerProtocol = TracerProtocol::Icmp;

    /// The default value for `addr-family`.
    pub const DEFAULT_ADDRESS_FAMILY: TracerAddrFamily = TracerAddrFamily::Ipv4;

    /// The default value for `multipath-strategy`.
    pub const DEFAULT_STRATEGY_MULTIPATH: MultipathStrategy = MultipathStrategy::Classic;

    /// The default value for `icmp-extensions`.
    pub const DEFAULT_ICMP_EXTENSIONS: bool = false;

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
    pub const DEFAULT_STRATEGY_INITIAL_SEQUENCE: u16 = 33000;

    /// The default value for `tos`.
    pub const DEFAULT_STRATEGY_TOS: u8 = 0;

    /// The default value for `read-timeout`.
    pub const DEFAULT_STRATEGY_READ_TIMEOUT: Duration = Duration::from_millis(10);

    /// The default value for `grace-duration`.
    pub const DEFAULT_STRATEGY_GRACE_DURATION: Duration = Duration::from_millis(100);

    /// The default TCP connect timeout.
    pub const DEFAULT_STRATEGY_TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(1000);
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
    pub fn is_unprivileged(self) -> bool {
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

/// The address family.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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

/// Build a `ChannelConfig`.
#[derive(Debug)]
pub struct ChannelConfigBuilder {
    config: ChannelConfig,
}

impl ChannelConfigBuilder {
    /// Create a new `ChannelConfigBuilder` between a source and target.
    #[must_use]
    pub fn new(source_addr: IpAddr, target_addr: IpAddr) -> Self {
        Self {
            config: ChannelConfig {
                source_addr,
                target_addr,
                ..ChannelConfig::default()
            },
        }
    }

    /// Set the channel protocol.
    #[must_use]
    pub fn protocol(self, protocol: TracerProtocol) -> Self {
        Self {
            config: ChannelConfig {
                protocol,
                ..self.config
            },
        }
    }

    /// Set the channel privilege mode.
    #[must_use]
    pub fn privilege_mode(self, privilege_mode: PrivilegeMode) -> Self {
        Self {
            config: ChannelConfig {
                privilege_mode,
                ..self.config
            },
        }
    }

    /// Set the channel multipath strategy.
    #[must_use]
    pub fn multipath_strategy(self, multipath_strategy: MultipathStrategy) -> Self {
        Self {
            config: ChannelConfig {
                multipath_strategy,
                ..self.config
            },
        }
    }

    /// Set the channel packet size.
    #[must_use]
    pub fn packet_size(self, packet_size: PacketSize) -> Self {
        Self {
            config: ChannelConfig {
                packet_size,
                ..self.config
            },
        }
    }

    /// Set the channel payload pattern.
    #[must_use]
    pub fn payload_pattern(self, payload_pattern: PayloadPattern) -> Self {
        Self {
            config: ChannelConfig {
                payload_pattern,
                ..self.config
            },
        }
    }

    /// Set the channel type of service.
    #[must_use]
    pub fn tos(self, tos: TypeOfService) -> Self {
        Self {
            config: ChannelConfig { tos, ..self.config },
        }
    }

    /// Set the channel ICMP extensions mode.
    #[must_use]
    pub fn icmp_extensions(self, icmp_extensions: bool) -> Self {
        Self {
            config: ChannelConfig {
                icmp_extensions,
                ..self.config
            },
        }
    }

    /// Set the channel read timeout.
    #[must_use]
    pub fn read_timeout(self, read_timeout: Duration) -> Self {
        Self {
            config: ChannelConfig {
                read_timeout,
                ..self.config
            },
        }
    }

    /// Set the channel TCP connect timeout.
    #[must_use]
    pub fn tcp_connect_timeout(self, tcp_connect_timeout: Duration) -> Self {
        Self {
            config: ChannelConfig {
                tcp_connect_timeout,
                ..self.config
            },
        }
    }

    /// Build the `ChannelConfig` from this `ChannelConfigBuilder`.
    #[must_use]
    pub fn build(self) -> ChannelConfig {
        self.config
    }
}

/// Tracer network channel configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChannelConfig {
    pub privilege_mode: PrivilegeMode,
    pub protocol: TracerProtocol,
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

impl ChannelConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        privilege_mode: PrivilegeMode,
        protocol: TracerProtocol,
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

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            privilege_mode: defaults::DEFAULT_PRIVILEGE_MODE,
            protocol: defaults::DEFAULT_STRATEGY_PROTOCOL,
            source_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            target_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            packet_size: PacketSize(defaults::DEFAULT_STRATEGY_PACKET_SIZE),
            payload_pattern: PayloadPattern(defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN),
            multipath_strategy: defaults::DEFAULT_STRATEGY_MULTIPATH,
            tos: TypeOfService(defaults::DEFAULT_STRATEGY_TOS),
            icmp_extensions: defaults::DEFAULT_ICMP_EXTENSIONS,
            read_timeout: defaults::DEFAULT_STRATEGY_READ_TIMEOUT,
            tcp_connect_timeout: defaults::DEFAULT_STRATEGY_TCP_CONNECT_TIMEOUT,
        }
    }
}

/// Build a `Config`.
#[derive(Debug)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new `ConfigBuilder`.
    #[must_use]
    pub fn new(trace_identifier: TraceId, target_addr: IpAddr) -> Self {
        Self {
            config: Config {
                target_addr,
                trace_identifier,
                ..Config::default()
            },
        }
    }

    /// Set the tracer protocol.
    #[must_use]
    pub fn protocol(self, protocol: TracerProtocol) -> Self {
        Self {
            config: Config {
                protocol,
                ..self.config
            },
        }
    }

    /// Set the tracer maximum rounds.
    #[must_use]
    pub fn max_rounds(self, max_rounds: MaxRounds) -> Self {
        Self {
            config: Config {
                max_rounds: Some(max_rounds),
                ..self.config
            },
        }
    }

    /// Set the tracer first ttl.
    #[must_use]
    pub fn first_ttl(self, first_ttl: TimeToLive) -> Self {
        Self {
            config: Config {
                first_ttl,
                ..self.config
            },
        }
    }

    /// Set the tracer max ttl.
    #[must_use]
    pub fn max_ttl(self, max_ttl: TimeToLive) -> Self {
        Self {
            config: Config {
                max_ttl,
                ..self.config
            },
        }
    }

    /// Set the tracer grace duration.
    #[must_use]
    pub fn grace_duration(self, grace_duration: Duration) -> Self {
        Self {
            config: Config {
                grace_duration,
                ..self.config
            },
        }
    }

    /// Set the tracer max inflight.
    #[must_use]
    pub fn max_inflight(self, max_inflight: MaxInflight) -> Self {
        Self {
            config: Config {
                max_inflight,
                ..self.config
            },
        }
    }

    /// Set the tracer initial sequence.
    #[must_use]
    pub fn initial_sequence(self, initial_sequence: Sequence) -> Self {
        Self {
            config: Config {
                initial_sequence,
                ..self.config
            },
        }
    }

    /// Set the tracer multipath strategy.
    #[must_use]
    pub fn multipath_strategy(self, multipath_strategy: MultipathStrategy) -> Self {
        Self {
            config: Config {
                multipath_strategy,
                ..self.config
            },
        }
    }

    /// Set the tracer port direction.
    #[must_use]
    pub fn port_direction(self, port_direction: PortDirection) -> Self {
        Self {
            config: Config {
                port_direction,
                ..self.config
            },
        }
    }

    /// Set the tracer minimum round duration.
    #[must_use]
    pub fn min_round_duration(self, min_round_duration: Duration) -> Self {
        Self {
            config: Config {
                min_round_duration,
                ..self.config
            },
        }
    }

    /// Set the tracer maximum round duration.
    #[must_use]
    pub fn max_round_duration(self, max_round_duration: Duration) -> Self {
        Self {
            config: Config {
                max_round_duration,
                ..self.config
            },
        }
    }

    /// Build the `Config` from this `ConfigBuilder`.
    #[must_use]
    pub fn build(self) -> Config {
        self.config
    }
}

/// Tracing algorithm configuration.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Config {
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
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
}

impl Config {
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
        min_round_duration: Duration,
        max_round_duration: Duration,
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
            min_round_duration,
            max_round_duration,
        })
    }
}

impl Default for Config {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const TARGET_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

    #[test]
    fn test_channel_config_builder_minimal() {
        let cfg = ChannelConfigBuilder::new(SOURCE_ADDR, TARGET_ADDR).build();
        assert_eq!(SOURCE_ADDR, cfg.source_addr);
        assert_eq!(TARGET_ADDR, cfg.target_addr);
        assert_eq!(
            ChannelConfig {
                source_addr: SOURCE_ADDR,
                target_addr: TARGET_ADDR,
                ..Default::default()
            },
            cfg
        );
    }

    #[test]
    fn test_channel_config_builder_full() {
        let cfg = ChannelConfigBuilder::new(SOURCE_ADDR, TARGET_ADDR)
            .protocol(TracerProtocol::Tcp)
            .privilege_mode(PrivilegeMode::Unprivileged)
            .multipath_strategy(MultipathStrategy::Dublin)
            .packet_size(PacketSize(128))
            .payload_pattern(PayloadPattern(0xff))
            .tos(TypeOfService(0x1a))
            .icmp_extensions(true)
            .read_timeout(Duration::from_millis(50))
            .tcp_connect_timeout(Duration::from_millis(100))
            .build();
        assert_eq!(SOURCE_ADDR, cfg.source_addr);
        assert_eq!(TARGET_ADDR, cfg.target_addr);
        assert_eq!(TracerProtocol::Tcp, cfg.protocol);
        assert_eq!(PrivilegeMode::Unprivileged, cfg.privilege_mode);
        assert_eq!(MultipathStrategy::Dublin, cfg.multipath_strategy);
        assert_eq!(PacketSize(128), cfg.packet_size);
        assert_eq!(PayloadPattern(0xff), cfg.payload_pattern);
        assert_eq!(TypeOfService(0x1a), cfg.tos);
        assert!(cfg.icmp_extensions);
        assert_eq!(Duration::from_millis(50), cfg.read_timeout);
        assert_eq!(Duration::from_millis(100), cfg.tcp_connect_timeout);
    }

    #[test]
    fn test_config_builder_minimal() {
        let cfg = ConfigBuilder::new(TraceId(0), TARGET_ADDR).build();
        assert_eq!(TraceId(0), cfg.trace_identifier);
        assert_eq!(TARGET_ADDR, cfg.target_addr);
        assert_eq!(
            Config {
                trace_identifier: TraceId(0),
                target_addr: TARGET_ADDR,
                ..Default::default()
            },
            cfg
        );
    }

    #[test]
    fn test_config_builder_full() {
        let cfg = ConfigBuilder::new(TraceId(0), TARGET_ADDR)
            .protocol(TracerProtocol::Udp)
            .max_rounds(MaxRounds(10))
            .first_ttl(TimeToLive(2))
            .max_ttl(TimeToLive(16))
            .grace_duration(Duration::from_millis(100))
            .max_inflight(MaxInflight(22))
            .initial_sequence(Sequence(35000))
            .multipath_strategy(MultipathStrategy::Paris)
            .port_direction(PortDirection::FixedSrc(Port(33000)))
            .min_round_duration(Duration::from_millis(500))
            .max_round_duration(Duration::from_millis(1500))
            .build();
        assert_eq!(TraceId(0), cfg.trace_identifier);
        assert_eq!(TARGET_ADDR, cfg.target_addr);
        assert_eq!(TracerProtocol::Udp, cfg.protocol);
        assert_eq!(Some(MaxRounds(10)), cfg.max_rounds);
        assert_eq!(TimeToLive(2), cfg.first_ttl);
        assert_eq!(TimeToLive(16), cfg.max_ttl);
        assert_eq!(Duration::from_millis(100), cfg.grace_duration);
        assert_eq!(MaxInflight(22), cfg.max_inflight);
        assert_eq!(Sequence(35000), cfg.initial_sequence);
        assert_eq!(MultipathStrategy::Paris, cfg.multipath_strategy);
        assert_eq!(PortDirection::FixedSrc(Port(33000)), cfg.port_direction);
        assert_eq!(Duration::from_millis(500), cfg.min_round_duration);
        assert_eq!(Duration::from_millis(1500), cfg.max_round_duration);
    }
}
