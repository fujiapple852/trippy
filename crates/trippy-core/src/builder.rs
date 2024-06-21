use crate::config::{ChannelConfig, StateConfig, StrategyConfig};
use crate::constants::MAX_INITIAL_SEQUENCE;
use crate::error::TraceResult;
use crate::{
    IcmpExtensionParseMode, MaxInflight, MaxRounds, MultipathStrategy, PacketSize, PayloadPattern,
    PortDirection, PrivilegeMode, Protocol, Sequence, TimeToLive, TraceId, Tracer, TracerError,
    TypeOfService, MAX_TTL,
};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

/// A builder for creating instances of `Tracer`.
///
/// This builder provides a fluent API for configuring and constructing a `Tracer`.
///
/// # Examples
///
/// Basic usage:
///
/// ```no_run
/// # fn main() -> anyhow::Result<()> {
/// use trippy_core::{Builder, MultipathStrategy, Port, PortDirection, PrivilegeMode, Protocol};
///
/// let addr = std::net::IpAddr::from([1, 2, 3, 4]);
/// let tracer = Builder::new(addr)
///     .privilege_mode(PrivilegeMode::Unprivileged)
///     .protocol(Protocol::Udp)
///     .multipath_strategy(MultipathStrategy::Dublin)
///     .port_direction(PortDirection::FixedBoth(Port(33000), Port(3500)))
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`Tracer`] - A traceroute implementation.
#[derive(Debug)]
pub struct Builder {
    interface: Option<String>,
    source_addr: Option<IpAddr>,
    target_addr: IpAddr,
    privilege_mode: PrivilegeMode,
    protocol: Protocol,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    tos: TypeOfService,
    icmp_extension_parse_mode: IcmpExtensionParseMode,
    read_timeout: Duration,
    tcp_connect_timeout: Duration,
    trace_identifier: TraceId,
    max_rounds: Option<MaxRounds>,
    first_ttl: TimeToLive,
    max_ttl: TimeToLive,
    grace_duration: Duration,
    max_inflight: MaxInflight,
    initial_sequence: Sequence,
    multipath_strategy: MultipathStrategy,
    port_direction: PortDirection,
    min_round_duration: Duration,
    max_round_duration: Duration,
    max_samples: usize,
    max_flows: usize,
    drop_privileges: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            interface: None,
            source_addr: None,
            target_addr: ChannelConfig::default().target_addr,
            privilege_mode: ChannelConfig::default().privilege_mode,
            protocol: ChannelConfig::default().protocol,
            packet_size: ChannelConfig::default().packet_size,
            payload_pattern: ChannelConfig::default().payload_pattern,
            tos: ChannelConfig::default().tos,
            icmp_extension_parse_mode: ChannelConfig::default().icmp_extension_parse_mode,
            read_timeout: ChannelConfig::default().read_timeout,
            tcp_connect_timeout: ChannelConfig::default().tcp_connect_timeout,
            trace_identifier: StrategyConfig::default().trace_identifier,
            max_rounds: StrategyConfig::default().max_rounds,
            first_ttl: StrategyConfig::default().first_ttl,
            max_ttl: StrategyConfig::default().max_ttl,
            grace_duration: StrategyConfig::default().grace_duration,
            max_inflight: StrategyConfig::default().max_inflight,
            initial_sequence: StrategyConfig::default().initial_sequence,
            multipath_strategy: StrategyConfig::default().multipath_strategy,
            port_direction: StrategyConfig::default().port_direction,
            min_round_duration: StrategyConfig::default().min_round_duration,
            max_round_duration: StrategyConfig::default().max_round_duration,
            max_samples: StateConfig::default().max_samples,
            max_flows: StateConfig::default().max_flows,
            drop_privileges: false,
        }
    }
}

impl Builder {
    /// Initializes a new `Builder` for a given target address.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target IP address for the traceroute.
    #[must_use]
    pub fn new(target_addr: IpAddr) -> Self {
        Self {
            target_addr,
            ..Default::default()
        }
    }

    /// Sets the source address for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `source_addr` - An optional source IP address. If not specified, the source address will be determined automatically.
    #[must_use]
    pub fn source_addr(mut self, source_addr: Option<IpAddr>) -> Self {
        self.source_addr = source_addr;
        self
    }

    /// Sets the network interface to use for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `interface` - An optional name of the network interface.
    #[must_use]
    pub fn interface<S: Into<String>>(mut self, interface: Option<S>) -> Self {
        self.interface = interface.map(Into::into);
        self
    }

    /// Sets the protocol to use for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol to use.
    #[must_use]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Sets the trace identifier.
    ///
    /// # Arguments
    ///
    /// * `trace_id` - The trace identifier.
    #[must_use]
    pub fn trace_identifier(mut self, trace_id: u16) -> Self {
        self.trace_identifier = TraceId(trace_id);
        self
    }

    /// Sets the privilege mode for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `privilege_mode` - The privilege mode.
    #[must_use]
    pub fn privilege_mode(mut self, privilege_mode: PrivilegeMode) -> Self {
        self.privilege_mode = privilege_mode;
        self
    }

    /// Sets the multipath strategy for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `multipath_strategy` - The multipath strategy.
    #[must_use]
    pub fn multipath_strategy(mut self, multipath_strategy: MultipathStrategy) -> Self {
        self.multipath_strategy = multipath_strategy;
        self
    }

    /// Sets the packet size for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `packet_size` - The packet size in bytes.
    #[must_use]
    pub fn packet_size(mut self, packet_size: u16) -> Self {
        self.packet_size = PacketSize(packet_size);
        self
    }

    /// Sets the payload pattern for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `payload_pattern` - The payload pattern.
    #[must_use]
    pub fn payload_pattern(mut self, payload_pattern: u8) -> Self {
        self.payload_pattern = PayloadPattern(payload_pattern);
        self
    }

    /// Sets the type of service for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `tos` - The type of service.
    #[must_use]
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = TypeOfService(tos);
        self
    }

    /// Sets the ICMP extension parse mode for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `icmp_extension_parse_mode` - The ICMP extension parse mode.
    #[must_use]
    pub fn icmp_extension_parse_mode(mut self, icmp_extension_parse_mode: IcmpExtensionParseMode) -> Self {
        self.icmp_extension_parse_mode = icmp_extension_parse_mode;
        self
    }

    /// Sets the read timeout for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `read_timeout` - The read timeout.
    #[must_use]
    pub fn read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    /// Sets the TCP connect timeout for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `tcp_connect_timeout` - The TCP connect timeout.
    #[must_use]
    pub fn tcp_connect_timeout(mut self, tcp_connect_timeout: Duration) -> Self {
        self.tcp_connect_timeout = tcp_connect_timeout;
        self
    }

    /// Sets the maximum number of rounds for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `max_rounds` - The maximum number of rounds.
    #[must_use]
    pub fn max_rounds(mut self, max_rounds: Option<usize>) -> Self {
        self.max_rounds = max_rounds
            .and_then(|max_rounds| NonZeroUsize::new(max_rounds).map(MaxRounds));
        self
    }

    /// Sets the first TTL for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `first_ttl` - The first TTL.
    #[must_use]
    pub fn first_ttl(mut self, first_ttl: u8) -> Self {
        self.first_ttl = TimeToLive(first_ttl);
        self
    }

    /// Sets the maximum TTL for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `max_ttl` - The maximum TTL.
    #[must_use]
    pub fn max_ttl(mut self, max_ttl: u8) -> Self {
        self.max_ttl = TimeToLive(max_ttl);
        self
    }

    /// Sets the grace duration for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `grace_duration` - The grace duration.
    #[must_use]
    pub fn grace_duration(mut self, grace_duration: Duration) -> Self {
        self.grace_duration = grace_duration;
        self
    }

    /// Sets the maximum number of inflight probes for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `max_inflight` - The maximum number of inflight probes.
    #[must_use]
    pub fn max_inflight(mut self, max_inflight: u8) -> Self {
        self.max_inflight = MaxInflight(max_inflight);
        self
    }

    /// Sets the initial sequence number for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `initial_sequence` - The initial sequence number.
    #[must_use]
    pub fn initial_sequence(mut self, initial_sequence: u16) -> Self {
        self.initial_sequence = Sequence(initial_sequence);
        self
    }

    /// Sets the port direction for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `port_direction` - The port direction.
    #[must_use]
    pub fn port_direction(mut self, port_direction: PortDirection) -> Self {
        self.port_direction = port_direction;
        self
    }

    /// Sets the minimum round duration for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `min_round_duration` - The minimum round duration.
    #[must_use]
    pub fn min_round_duration(mut self, min_round_duration: Duration) -> Self {
        self.min_round_duration = min_round_duration;
        self
    }

    /// Sets the maximum round duration for the traceroute.
    ///
    /// # Arguments
    ///
    /// * `max_round_duration` - The maximum round duration.
    #[must_use]
    pub fn max_round_duration(mut self, max_round_duration: Duration) -> Self {
        self.max_round_duration = max_round_duration;
        self
    }

    /// Sets the maximum number of samples to record per hop.
    ///
    /// # Arguments
    ///
    /// * `max_samples` - The maximum number of samples.
    #[must_use]
    pub fn max_samples(mut self, max_samples: usize) -> Self {
        self.max_samples = max_samples;
        self
    }

    /// Sets the maximum number of flows to record.
    ///
    /// # Arguments
    ///
    /// * `max_flows` - The maximum number of flows.
    #[must_use]
    pub fn max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    /// Specifies whether to drop privileges after establishing the network connection.
    ///
    /// # Arguments
    ///
    /// * `drop_privileges` - Whether to drop privileges.
    #[must_use]
    pub fn drop_privileges(mut self, drop_privileges: bool) -> Self {
        self.drop_privileges = drop_privileges;
        self
    }

    /// Builds and returns a `Tracer` instance based on the configuration provided.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn build(self) -> TraceResult<Tracer> {
        if let (Protocol::Udp, PortDirection::None) | (Protocol::Tcp, PortDirection::None) = (self.protocol, self.port_direction) {
            return Err(TracerError::BadConfig("port_direction may not be None for udp or tcp protocol".to_string()));
        }
        if self.first_ttl.0 > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "first_ttl {} > {MAX_TTL}",
                self.first_ttl.0
            )));
        }
        if self.max_ttl.0 > MAX_TTL {
            return Err(TracerError::BadConfig(format!(
                "max_ttl {} > {MAX_TTL}",
                self.max_ttl.0
            )));
        }
        if self.initial_sequence.0 > MAX_INITIAL_SEQUENCE {
            return Err(TracerError::BadConfig(format!(
                "initial_sequence {} > {MAX_INITIAL_SEQUENCE}",
                self.initial_sequence.0
            )));
        }
        Ok(Tracer::new(
            self.interface,
            self.source_addr,
            self.target_addr,
            self.privilege_mode,
            self.protocol,
            self.packet_size,
            self.payload_pattern,
            self.tos,
            self.icmp_extension_parse_mode,
            self.read_timeout,
            self.tcp_connect_timeout,
            self.trace_identifier,
            self.max_rounds,
            self.first_ttl,
            self.max_ttl,
            self.grace_duration,
            self.max_inflight,
            self.initial_sequence,
            self.multipath_strategy,
            self.port_direction,
            self.min_round_duration,
            self.max_round_duration,
            self.max_samples,
            self.max_flows,
            self.drop_privileges,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, Port};
    use config::defaults;
    use std::net::Ipv4Addr;
    use std::num::NonZeroUsize;

    const SOURCE_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    const TARGET_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

    #[test]
    fn test_builder_minimal() {
        let tracer = Builder::new(TARGET_ADDR).build().unwrap();
        assert_eq!(TARGET_ADDR, tracer.target_addr());
        assert_eq!(None, tracer.source_addr());
        assert_eq!(None, tracer.interface());
        assert_eq!(defaults::DEFAULT_MAX_SAMPLES, tracer.max_samples());
        assert_eq!(defaults::DEFAULT_MAX_FLOWS, tracer.max_flows());
        assert_eq!(defaults::DEFAULT_STRATEGY_PROTOCOL, tracer.protocol());
        assert_eq!(TraceId::default(), tracer.trace_identifier());
        assert_eq!(defaults::DEFAULT_PRIVILEGE_MODE, tracer.privilege_mode());
        assert_eq!(
            defaults::DEFAULT_STRATEGY_MULTIPATH,
            tracer.multipath_strategy()
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_PACKET_SIZE,
            tracer.packet_size().0
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
            tracer.payload_pattern().0
        );
        assert_eq!(defaults::DEFAULT_STRATEGY_TOS, tracer.tos().0);
        assert_eq!(
            defaults::DEFAULT_ICMP_EXTENSION_PARSE_MODE,
            tracer.icmp_extension_parse_mode()
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_READ_TIMEOUT,
            tracer.read_timeout()
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_TCP_CONNECT_TIMEOUT,
            tracer.tcp_connect_timeout()
        );
        assert_eq!(None, tracer.max_rounds());
        assert_eq!(defaults::DEFAULT_STRATEGY_FIRST_TTL, tracer.first_ttl().0);
        assert_eq!(defaults::DEFAULT_STRATEGY_MAX_TTL, tracer.max_ttl().0);
        assert_eq!(
            defaults::DEFAULT_STRATEGY_GRACE_DURATION,
            tracer.grace_duration()
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_MAX_INFLIGHT,
            tracer.max_inflight().0
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
            tracer.initial_sequence().0
        );
        assert_eq!(PortDirection::None, tracer.port_direction());
        assert_eq!(
            defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION,
            tracer.min_round_duration()
        );
        assert_eq!(
            defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION,
            tracer.max_round_duration()
        );
    }

    #[test]
    fn test_builder_full() {
        let tracer = Builder::new(TARGET_ADDR)
            .source_addr(Some(SOURCE_ADDR))
            .interface(Some("eth0"))
            .max_samples(10)
            .max_flows(20)
            .protocol(Protocol::Udp)
            .trace_identifier(101)
            .privilege_mode(PrivilegeMode::Unprivileged)
            .multipath_strategy(MultipathStrategy::Paris)
            .packet_size(128)
            .payload_pattern(0xff)
            .tos(0x1a)
            .icmp_extension_parse_mode(IcmpExtensionParseMode::Enabled)
            .read_timeout(Duration::from_millis(50))
            .tcp_connect_timeout(Duration::from_millis(100))
            .max_rounds(Some(10))
            .first_ttl(2)
            .max_ttl(16)
            .grace_duration(Duration::from_millis(100))
            .max_inflight(22)
            .initial_sequence(35000)
            .port_direction(PortDirection::FixedSrc(Port(8080)))
            .min_round_duration(Duration::from_millis(500))
            .max_round_duration(Duration::from_millis(1500))
            .build()
            .unwrap();

        assert_eq!(TARGET_ADDR, tracer.target_addr());
        // note that source_addr is not set until the tracer is run
        assert_eq!(None, tracer.source_addr());
        assert_eq!(Some("eth0"), tracer.interface());
        assert_eq!(10, tracer.max_samples());
        assert_eq!(20, tracer.max_flows());
        assert_eq!(Protocol::Udp, tracer.protocol());
        assert_eq!(TraceId(101), tracer.trace_identifier());
        assert_eq!(PrivilegeMode::Unprivileged, tracer.privilege_mode());
        assert_eq!(MultipathStrategy::Paris, tracer.multipath_strategy());
        assert_eq!(PacketSize(128), tracer.packet_size());
        assert_eq!(PayloadPattern(0xff), tracer.payload_pattern());
        assert_eq!(TypeOfService(0x1a), tracer.tos());
        assert_eq!(
            IcmpExtensionParseMode::Enabled,
            tracer.icmp_extension_parse_mode()
        );
        assert_eq!(Duration::from_millis(50), tracer.read_timeout());
        assert_eq!(Duration::from_millis(100), tracer.tcp_connect_timeout());
        assert_eq!(
            Some(MaxRounds(NonZeroUsize::new(10).unwrap())),
            tracer.max_rounds()
        );
        assert_eq!(TimeToLive(2), tracer.first_ttl());
        assert_eq!(TimeToLive(16), tracer.max_ttl());
        assert_eq!(Duration::from_millis(100), tracer.grace_duration());
        assert_eq!(MaxInflight(22), tracer.max_inflight());
        assert_eq!(Sequence(35000), tracer.initial_sequence());
        assert_eq!(PortDirection::FixedSrc(Port(8080)), tracer.port_direction());
        assert_eq!(Duration::from_millis(500), tracer.min_round_duration());
        assert_eq!(Duration::from_millis(1500), tracer.max_round_duration());
    }

    #[test]
    fn test_zero_max_rounds() {
        let tracer = Builder::new(IpAddr::from([1, 2, 3, 4]))
            .max_rounds(Some(0))
            .build()
            .unwrap();
        assert_eq!(None, tracer.max_rounds());
    }

    #[test]
    fn test_invalid_initial_sequence() {
        let err = Builder::new(IpAddr::from([1, 2, 3, 4]))
            .initial_sequence(u16::MAX)
            .build()
            .unwrap_err();
        assert!(matches!(err, TracerError::BadConfig(s) if s == "initial_sequence 65535 > 64511"));
    }
}
