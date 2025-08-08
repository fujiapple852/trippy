use crate::config::{ChannelConfig, StateConfig, StrategyConfig};
use crate::constants::MAX_INITIAL_SEQUENCE;
use crate::error::Result;
use crate::{
    Error, IcmpExtensionParseMode, MaxInflight, MaxRounds, MultipathStrategy, PacketSize,
    PayloadPattern, PortDirection, PrivilegeMode, Protocol, Sequence, TimeToLive, TraceId, Tracer,
    TypeOfService, MAX_TTL,
};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

/// Build a tracer.
///
/// This is a convenience builder to simplify the creation of execution of a
/// tracer.
///
/// # Examples
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
///     .port_direction(PortDirection::FixedBoth(Port(33434), Port(3500)))
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
    /// Build a tracer builder for a given target.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use trippy_core::Builder;
    ///
    /// let addr = std::net::IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn new(target_addr: IpAddr) -> Self {
        Self {
            target_addr,
            ..Default::default()
        }
    }

    /// Set the source address.
    ///
    /// If not set then the source address will be discovered based on the
    /// target address and the interface.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let source_addr = IpAddr::from([192, 168, 1, 1]);
    /// let tracer = Builder::new(addr).source_addr(Some(source_addr)).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn source_addr(self, source_addr: Option<IpAddr>) -> Self {
        Self {
            source_addr,
            ..self
        }
    }

    /// Set the source interface.
    ///
    /// If the source interface is provided it will be used to look up the IPv4
    /// or IPv6 source address.
    ///
    /// If not provided the source address will be determined by OS based on
    /// the target IPv4 or IPv6 address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).interface(Some("eth0")).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn interface<S: Into<String>>(self, interface: Option<S>) -> Self {
        Self {
            interface: interface.map(Into::into),
            ..self
        }
    }

    /// Set the protocol.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::{Builder, Protocol};
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).protocol(Protocol::Udp).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn protocol(self, protocol: Protocol) -> Self {
        Self { protocol, ..self }
    }

    /// Set the trace identifier.
    ///
    /// If not set then 0 will be used as the trace identifier.
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).trace_identifier(12345).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn trace_identifier(self, trace_id: u16) -> Self {
        Self {
            trace_identifier: TraceId(trace_id),
            ..self
        }
    }

    /// Set the privilege mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::{Builder, PrivilegeMode};
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .privilege_mode(PrivilegeMode::Unprivileged)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn privilege_mode(self, privilege_mode: PrivilegeMode) -> Self {
        Self {
            privilege_mode,
            ..self
        }
    }

    /// Set the multipath strategy.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::{Builder, MultipathStrategy};
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .multipath_strategy(MultipathStrategy::Paris)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn multipath_strategy(self, multipath_strategy: MultipathStrategy) -> Self {
        Self {
            multipath_strategy,
            ..self
        }
    }

    /// Set the packet size.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).packet_size(128).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn packet_size(self, packet_size: u16) -> Self {
        Self {
            packet_size: PacketSize(packet_size),
            ..self
        }
    }

    /// Set the payload pattern.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).payload_pattern(0xff).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn payload_pattern(self, payload_pattern: u8) -> Self {
        Self {
            payload_pattern: PayloadPattern(payload_pattern),
            ..self
        }
    }

    /// Set the type of service.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).tos(0x1a).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn tos(self, tos: u8) -> Self {
        Self {
            tos: TypeOfService(tos),
            ..self
        }
    }

    /// Set the ICMP extensions mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::{Builder, IcmpExtensionParseMode};
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .icmp_extension_parse_mode(IcmpExtensionParseMode::Enabled)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn icmp_extension_parse_mode(
        self,
        icmp_extension_parse_mode: IcmpExtensionParseMode,
    ) -> Self {
        Self {
            icmp_extension_parse_mode,
            ..self
        }
    }

    /// Set the read timeout.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .read_timeout(Duration::from_millis(50))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn read_timeout(self, read_timeout: Duration) -> Self {
        Self {
            read_timeout,
            ..self
        }
    }

    /// Set the TCP connect timeout.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .tcp_connect_timeout(Duration::from_millis(100))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn tcp_connect_timeout(self, tcp_connect_timeout: Duration) -> Self {
        Self {
            tcp_connect_timeout,
            ..self
        }
    }

    /// Set the maximum number of rounds.
    ///
    /// If set to `None` then the tracer will run indefinitely, otherwise it
    /// will stop after the given number of rounds.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).max_rounds(Some(10)).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_rounds(self, max_rounds: Option<usize>) -> Self {
        Self {
            max_rounds: max_rounds
                .and_then(|max_rounds| NonZeroUsize::new(max_rounds).map(MaxRounds)),
            ..self
        }
    }

    /// Set the first ttl.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).first_ttl(2).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn first_ttl(self, first_ttl: u8) -> Self {
        Self {
            first_ttl: TimeToLive(first_ttl),
            ..self
        }
    }

    /// Set the maximum ttl.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).max_ttl(16).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_ttl(self, max_ttl: u8) -> Self {
        Self {
            max_ttl: TimeToLive(max_ttl),
            ..self
        }
    }

    /// Set the grace duration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .grace_duration(Duration::from_millis(100))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn grace_duration(self, grace_duration: Duration) -> Self {
        Self {
            grace_duration,
            ..self
        }
    }

    /// Set the max number of probes in flight at any given time.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).max_inflight(22).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_inflight(self, max_inflight: u8) -> Self {
        Self {
            max_inflight: MaxInflight(max_inflight),
            ..self
        }
    }

    /// Set the initial sequence number.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).initial_sequence(35000).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn initial_sequence(self, initial_sequence: u16) -> Self {
        Self {
            initial_sequence: Sequence(initial_sequence),
            ..self
        }
    }

    /// Set the port direction.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::{Builder, Port, PortDirection};
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .port_direction(PortDirection::FixedDest(Port(8080)))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn port_direction(self, port_direction: PortDirection) -> Self {
        Self {
            port_direction,
            ..self
        }
    }

    /// Set the minimum round duration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .min_round_duration(Duration::from_millis(500))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn min_round_duration(self, min_round_duration: Duration) -> Self {
        Self {
            min_round_duration,
            ..self
        }
    }

    /// Set the maximum round duration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use std::time::Duration;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr)
    ///     .max_round_duration(Duration::from_millis(1500))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_round_duration(self, max_round_duration: Duration) -> Self {
        Self {
            max_round_duration,
            ..self
        }
    }

    /// Set the maximum number of samples to record.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).max_samples(256).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_samples(self, max_samples: usize) -> Self {
        Self {
            max_samples,
            ..self
        }
    }

    /// Set the maximum number of flows to record.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).max_flows(64).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn max_flows(self, max_flows: usize) -> Self {
        Self { max_flows, ..self }
    }

    /// Drop privileges after connection is established.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).drop_privileges(true).build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn drop_privileges(self, drop_privileges: bool) -> Self {
        Self {
            drop_privileges,
            ..self
        }
    }

    /// Build the `Tracer`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> anyhow::Result<()> {
    /// use std::net::IpAddr;
    /// use trippy_core::Builder;
    ///
    /// let addr = IpAddr::from([1, 1, 1, 1]);
    /// let tracer = Builder::new(addr).build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return `Error::BadConfig` if the configuration is invalid.
    pub fn build(self) -> Result<Tracer> {
        match (self.protocol, self.port_direction) {
            (Protocol::Udp, PortDirection::None) => {
                return Err(Error::BadConfig(
                    "port_direction may not be None for udp protocol".to_string(),
                ));
            }
            (Protocol::Tcp, PortDirection::None) => {
                return Err(Error::BadConfig(
                    "port_direction may not be None for tcp protocol".to_string(),
                ));
            }
            _ => (),
        }
        if self.first_ttl.0 > MAX_TTL {
            return Err(Error::BadConfig(format!(
                "first_ttl {} > {MAX_TTL}",
                self.first_ttl.0
            )));
        }
        if self.max_ttl.0 > MAX_TTL {
            return Err(Error::BadConfig(format!(
                "max_ttl {} > {MAX_TTL}",
                self.max_ttl.0
            )));
        }
        if self.initial_sequence.0 > MAX_INITIAL_SEQUENCE {
            return Err(Error::BadConfig(format!(
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

    const SOURCE_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
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
        // note that `source_addr` is not set until the tracer is run
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
        assert!(matches!(err, Error::BadConfig(s) if s == "initial_sequence 65535 > 64511"));
    }
}
