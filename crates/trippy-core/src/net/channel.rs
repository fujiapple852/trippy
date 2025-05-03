use crate::config::ChannelConfig;
use crate::error::{Error, Result};
use crate::net::socket::Socket;
use crate::net::{ipv4::Ipv4, ipv6::Ipv6, platform, Network};
use crate::probe::{Probe, Response};
use crate::{Port, PrivilegeMode, Protocol};
use arrayvec::ArrayVec;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::instrument;

/// The maximum size of the IP packet we allow.
pub const MAX_PACKET_SIZE: usize = 1024;

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// A channel for sending and receiving `Probe` packets.
pub struct Channel<S: Socket> {
    protocol: Protocol,
    read_timeout: Duration,
    tcp_connect_timeout: Duration,
    send_socket: Option<S>,
    recv_socket: S,
    tcp_probes: ArrayVec<TcpProbe<S>, MAX_TCP_PROBES>,
    family_config: FamilyConfig,
}

/// The IP family configuration for the channel.
enum FamilyConfig {
    V4(Ipv4),
    V6(Ipv6),
}

impl<S: Socket> Channel<S> {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    #[instrument(skip_all, level = "trace")]
    pub fn connect(config: &ChannelConfig) -> Result<Self> {
        tracing::debug!(?config);
        if usize::from(config.packet_size.0) > MAX_PACKET_SIZE {
            return Err(Error::InvalidPacketSize(usize::from(config.packet_size.0)));
        }
        let raw = config.privilege_mode == PrivilegeMode::Privileged;
        platform::startup()?;
        let ipv4_length_order = platform::Ipv4ByteOrder::for_address(config.source_addr)?;
        let send_socket = match config.protocol {
            Protocol::Icmp => Some(make_icmp_send_socket(config.source_addr, raw)?),
            Protocol::Udp => Some(make_udp_send_socket(config.source_addr, raw)?),
            Protocol::Tcp => None,
        };
        let recv_socket = make_recv_socket(config.source_addr, raw)?;
        let family_config = match (config.source_addr, config.target_addr) {
            (IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => FamilyConfig::V4(Ipv4 {
                src_addr,
                dest_addr,
                byte_order: ipv4_length_order,
                packet_size: config.packet_size,
                payload_pattern: config.payload_pattern,
                privilege_mode: config.privilege_mode,
                tos: config.tos,
                protocol: config.protocol,
                icmp_extension_mode: config.icmp_extension_parse_mode,
            }),
            (IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => FamilyConfig::V6(Ipv6 {
                src_addr,
                dest_addr,
                packet_size: config.packet_size,
                payload_pattern: config.payload_pattern,
                privilege_mode: config.privilege_mode,
                tos: config.tos,
                protocol: config.protocol,
                icmp_extension_mode: config.icmp_extension_parse_mode,
                initial_sequence: config.initial_sequence,
            }),
            _ => unreachable!(),
        };
        Ok(Self {
            protocol: config.protocol,
            read_timeout: config.read_timeout,
            tcp_connect_timeout: config.tcp_connect_timeout,
            send_socket,
            recv_socket,
            tcp_probes: ArrayVec::new(),
            family_config,
        })
    }
}

impl<S: Socket> Network for Channel<S> {
    #[instrument(skip(self), level = "trace")]
    fn send_probe(&mut self, probe: Probe) -> Result<()> {
        tracing::debug!(?probe);
        match self.protocol {
            Protocol::Icmp => self.dispatch_icmp_probe(probe),
            Protocol::Udp => self.dispatch_udp_probe(probe),
            Protocol::Tcp => self.dispatch_tcp_probe(probe),
        }
    }
    #[instrument(skip_all, level = "trace")]
    fn recv_probe(&mut self) -> Result<Option<Response>> {
        let prob_response = match self.protocol {
            Protocol::Icmp | Protocol::Udp => self.recv_icmp_probe(),
            Protocol::Tcp => match self.recv_tcp_sockets()? {
                None => self.recv_icmp_probe(),
                resp => Ok(resp),
            },
        }?;
        if let Some(resp) = &prob_response {
            tracing::debug!(?resp);
        }
        Ok(prob_response)
    }
}

impl<S: Socket> Channel<S> {
    /// Dispatch a ICMP probe.
    #[instrument(skip_all, level = "trace")]
    fn dispatch_icmp_probe(&mut self, probe: Probe) -> Result<()> {
        match (&self.family_config, self.send_socket.as_mut()) {
            (FamilyConfig::V4(ipv4), Some(socket)) => ipv4.dispatch_icmp_probe(socket, probe),
            (FamilyConfig::V6(ipv6), Some(socket)) => ipv6.dispatch_icmp_probe(socket, probe),
            _ => unreachable!(),
        }
    }

    /// Dispatch a UDP probe.
    #[instrument(skip_all, level = "trace")]
    fn dispatch_udp_probe(&mut self, probe: Probe) -> Result<()> {
        match (&self.family_config, self.send_socket.as_mut()) {
            (FamilyConfig::V4(ipv4), Some(socket)) => ipv4.dispatch_udp_probe(socket, probe),
            (FamilyConfig::V6(ipv6), Some(socket)) => ipv6.dispatch_udp_probe(socket, probe),
            _ => unreachable!(),
        }
    }

    /// Dispatch a TCP probe.
    #[instrument(skip_all, level = "trace")]
    fn dispatch_tcp_probe(&mut self, probe: Probe) -> Result<()> {
        let socket = match &self.family_config {
            FamilyConfig::V4(ipv4) => ipv4.dispatch_tcp_probe(&probe),
            FamilyConfig::V6(ipv6) => ipv6.dispatch_tcp_probe(&probe),
        }?;
        self.tcp_probes.push(TcpProbe::new(
            socket,
            probe.src_port,
            probe.dest_port,
            SystemTime::now(),
        ));
        Ok(())
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any
    #[instrument(skip(self), level = "trace")]
    fn recv_icmp_probe(&mut self) -> Result<Option<Response>> {
        if self.recv_socket.is_readable(self.read_timeout)? {
            match &self.family_config {
                FamilyConfig::V4(ipv4) => ipv4.recv_icmp_probe(&mut self.recv_socket),
                FamilyConfig::V6(ipv6) => ipv6.recv_icmp_probe(&mut self.recv_socket),
            }
        } else {
            Ok(None)
        }
    }

    /// Generate synthetic `ProbeResponse` if a TCP socket is connected or if the connection was
    /// refused.
    ///
    /// Any TCP socket which has not connected or failed after a timeout will be removed.
    #[instrument(skip(self), level = "trace")]
    fn recv_tcp_sockets(&mut self) -> Result<Option<Response>> {
        self.tcp_probes
            .retain(|probe| probe.start.elapsed().unwrap_or_default() < self.tcp_connect_timeout);
        let found_index = self
            .tcp_probes
            .iter_mut()
            .enumerate()
            .find_map(|(index, probe)| {
                if probe.socket.is_writable().unwrap_or_default() {
                    Some(index)
                } else {
                    None
                }
            });
        if let Some(i) = found_index {
            let mut probe = self.tcp_probes.remove(i);
            match &self.family_config {
                FamilyConfig::V4(ipv4) => {
                    ipv4.recv_tcp_socket(&mut probe.socket, probe.src_port, probe.dest_port)
                }
                FamilyConfig::V6(ipv6) => {
                    ipv6.recv_tcp_socket(&mut probe.socket, probe.src_port, probe.dest_port)
                }
            }
        } else {
            Ok(None)
        }
    }
}

/// An entry in the TCP probes array.
struct TcpProbe<S: Socket> {
    socket: S,
    src_port: Port,
    dest_port: Port,
    start: SystemTime,
}

impl<S: Socket> TcpProbe<S> {
    pub const fn new(socket: S, src_port: Port, dest_port: Port, start: SystemTime) -> Self {
        Self {
            socket,
            src_port,
            dest_port,
            start,
        }
    }
}

/// Make a socket for sending raw `ICMP` packets.
#[instrument(level = "trace")]
fn make_icmp_send_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(_) => S::new_icmp_send_socket_ipv4(raw),
        IpAddr::V6(_) => S::new_icmp_send_socket_ipv6(raw),
    }?)
}

/// Make a socket for sending `UDP` packets.
#[instrument(level = "trace")]
fn make_udp_send_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(_) => S::new_udp_send_socket_ipv4(raw),
        IpAddr::V6(_) => S::new_udp_send_socket_ipv6(raw),
    }?)
}

/// Make a socket for receiving raw `ICMP` packets.
#[instrument(level = "trace")]
fn make_recv_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(ipv4addr) => S::new_recv_socket_ipv4(ipv4addr, raw),
        IpAddr::V6(ipv6addr) => S::new_recv_socket_ipv6(ipv6addr, raw),
    }?)
}
