use crate::tracing::error::TraceResult;
use crate::tracing::{
    ChannelConfig, Config, IcmpExtensionParseMode, MaxInflight, MaxRounds, MultipathStrategy,
    PacketSize, PayloadPattern, PortDirection, PrivilegeMode, Protocol, Sequence, SocketImpl,
    SourceAddr, TimeToLive, TraceId, Tracer, TracerChannel, TracerRound, TypeOfService,
};
use std::net::IpAddr;
use std::time::Duration;

/// Build and run a tracer.
///
/// This is a convenience builder to simplify the creation of execution of a
/// tracer.
///
/// The builder exposes all configuration items from`trippy::tracing::Config`
/// and `trippy::tracing::TracerChannel`.
///
/// # Examples:
///
/// ```no_run
/// use trippy::tracing::{Builder, MultipathStrategy, Port, PortDirection, PrivilegeMode, Protocol};
///
/// let addr = std::net::IpAddr::from([1, 2, 3, 4]);
/// Builder::new(addr, |round| println!("{:?}", round))
///     .privilege_mode(PrivilegeMode::Unprivileged)
///     .protocol(Protocol::Udp)
///     .multipath_strategy(MultipathStrategy::Dublin)
///     .port_direction(PortDirection::FixedBoth(Port(33000), Port(3500)))
///     .start()
///     .unwrap();
/// ```
pub struct Builder<F> {
    target_addr: IpAddr,
    on_round_handler: F,
    channel_config: ChannelConfig,
    tracer_config: Config,
    trace_identifier: Option<TraceId>,
    interface: Option<String>,
}

impl<F: Fn(&TracerRound<'_>)> Builder<F> {
    /// Build a tracer builder for a given target.
    pub fn new(target_addr: IpAddr, on_round_handler: F) -> Self {
        Self {
            target_addr,
            on_round_handler,
            channel_config: ChannelConfig::default(),
            tracer_config: Config::default(),
            trace_identifier: None,
            interface: None,
        }
    }

    /// Set the trace identifier.
    ///
    /// If not set then 0 will be used as the trace identifier.
    #[must_use]
    pub fn trace_identifier(self, trace_id: TraceId) -> Self {
        Self {
            trace_identifier: Some(trace_id),
            ..self
        }
    }

    /// Set the source interface.
    ///
    /// If the source interface is provided it will be used to lookup the IPv4
    /// or IPv6 source address.
    ///
    /// If not provided the source address will be determined by OS based on
    /// the target IPv4 or IPv6 address.
    #[must_use]
    pub fn interface(self, interface: &str) -> Self {
        Self {
            interface: Some(String::from(interface)),
            ..self
        }
    }

    /// Set the protocol.
    #[must_use]
    pub fn protocol(self, protocol: Protocol) -> Self {
        Self {
            channel_config: ChannelConfig {
                protocol,
                ..self.channel_config
            },
            tracer_config: Config {
                protocol,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the privilege mode.
    #[must_use]
    pub fn privilege_mode(self, privilege_mode: PrivilegeMode) -> Self {
        Self {
            channel_config: ChannelConfig {
                privilege_mode,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the multipath strategy.
    #[must_use]
    pub fn multipath_strategy(self, multipath_strategy: MultipathStrategy) -> Self {
        Self {
            tracer_config: Config {
                multipath_strategy,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the packet size.
    #[must_use]
    pub fn packet_size(self, packet_size: PacketSize) -> Self {
        Self {
            channel_config: ChannelConfig {
                packet_size,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the payload pattern.
    #[must_use]
    pub fn payload_pattern(self, payload_pattern: PayloadPattern) -> Self {
        Self {
            channel_config: ChannelConfig {
                payload_pattern,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the type of service.
    #[must_use]
    pub fn tos(self, tos: TypeOfService) -> Self {
        Self {
            channel_config: ChannelConfig {
                tos,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the ICMP extensions mode.
    #[must_use]
    pub fn icmp_extension_mode(self, icmp_extension_mode: IcmpExtensionParseMode) -> Self {
        Self {
            channel_config: ChannelConfig {
                icmp_extension_mode,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the read timeout.
    #[must_use]
    pub fn read_timeout(self, read_timeout: Duration) -> Self {
        Self {
            channel_config: ChannelConfig {
                read_timeout,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the TCP connect timeout.
    #[must_use]
    pub fn tcp_connect_timeout(self, tcp_connect_timeout: Duration) -> Self {
        Self {
            channel_config: ChannelConfig {
                tcp_connect_timeout,
                ..self.channel_config
            },
            ..self
        }
    }

    /// Set the maximum number of rounds.
    #[must_use]
    pub fn max_rounds(self, max_rounds: MaxRounds) -> Self {
        Self {
            tracer_config: Config {
                max_rounds: Some(max_rounds),
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the first ttl.
    #[must_use]
    pub fn first_ttl(self, first_ttl: TimeToLive) -> Self {
        Self {
            tracer_config: Config {
                first_ttl,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the maximum ttl.
    #[must_use]
    pub fn max_ttl(self, max_ttl: TimeToLive) -> Self {
        Self {
            tracer_config: Config {
                max_ttl,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the grace duration.
    #[must_use]
    pub fn grace_duration(self, grace_duration: Duration) -> Self {
        Self {
            tracer_config: Config {
                grace_duration,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the max inflight.
    #[must_use]
    pub fn max_inflight(self, max_inflight: MaxInflight) -> Self {
        Self {
            tracer_config: Config {
                max_inflight,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the initial sequence.
    #[must_use]
    pub fn initial_sequence(self, initial_sequence: Sequence) -> Self {
        Self {
            tracer_config: Config {
                initial_sequence,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the port direction.
    #[must_use]
    pub fn port_direction(self, port_direction: PortDirection) -> Self {
        Self {
            tracer_config: Config {
                port_direction,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the minimum round duration.
    #[must_use]
    pub fn min_round_duration(self, min_round_duration: Duration) -> Self {
        Self {
            tracer_config: Config {
                min_round_duration,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Set the maximum round duration.
    #[must_use]
    pub fn max_round_duration(self, max_round_duration: Duration) -> Self {
        Self {
            tracer_config: Config {
                max_round_duration,
                ..self.tracer_config
            },
            ..self
        }
    }

    /// Start the tracer.
    pub fn start(self) -> TraceResult<()> {
        let trace_identifier = self.trace_identifier.unwrap_or_default();
        let source_addr = SourceAddr::discover(
            self.target_addr,
            self.tracer_config.port_direction,
            self.interface.as_deref(),
        )?;
        let channel_config = ChannelConfig {
            source_addr,
            target_addr: self.target_addr,
            ..self.channel_config
        };
        let channel = TracerChannel::<SocketImpl>::connect(&channel_config)?;
        let tracer_config = Config {
            trace_identifier,
            target_addr: self.target_addr,
            ..self.tracer_config
        };
        let tracer = Tracer::new(&tracer_config, self.on_round_handler);
        tracer.trace(channel)?;
        Ok(())
    }
}
