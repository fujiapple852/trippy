use crate::config::{ChannelConfig, IcmpExtensionParseMode};
use crate::error::{Error, Result};
use crate::net::socket::Socket;
use crate::net::{ipv4, ipv6, platform, Network};
use crate::probe::{Probe, ProbeResponse};
use crate::types::{PacketSize, PayloadPattern, TypeOfService};
use crate::{Port, PrivilegeMode, Protocol, Sequence};
use arrayvec::ArrayVec;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::instrument;

/// The maximum size of the IP packet we allow.
pub const MAX_PACKET_SIZE: usize = 1024;

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// A channel for sending and receiving `Probe` packets.
pub struct TracerChannel<S: Socket> {
    privilege_mode: PrivilegeMode,
    protocol: Protocol,
    src_addr: IpAddr,
    ipv4_length_order: platform::Ipv4ByteOrder,
    dest_addr: IpAddr,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    initial_sequence: Sequence,
    tos: TypeOfService,
    icmp_extension_mode: IcmpExtensionParseMode,
    read_timeout: Duration,
    tcp_connect_timeout: Duration,
    send_socket: Option<S>,
    recv_socket: S,
    tcp_probes: ArrayVec<TcpProbe<S>, MAX_TCP_PROBES>,
}

impl<S: Socket> TracerChannel<S> {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    #[instrument(skip_all)]
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
        Ok(Self {
            privilege_mode: config.privilege_mode,
            protocol: config.protocol,
            src_addr: config.source_addr,
            ipv4_length_order,
            dest_addr: config.target_addr,
            packet_size: config.packet_size,
            payload_pattern: config.payload_pattern,
            initial_sequence: config.initial_sequence,
            tos: config.tos,
            icmp_extension_mode: config.icmp_extension_parse_mode,
            read_timeout: config.read_timeout,
            tcp_connect_timeout: config.tcp_connect_timeout,
            send_socket,
            recv_socket,
            tcp_probes: ArrayVec::new(),
        })
    }
}

impl<S: Socket> Network for TracerChannel<S> {
    #[instrument(skip(self))]
    fn send_probe(&mut self, probe: Probe) -> Result<()> {
        match self.protocol {
            Protocol::Icmp => self.dispatch_icmp_probe(probe),
            Protocol::Udp => self.dispatch_udp_probe(probe),
            Protocol::Tcp => self.dispatch_tcp_probe(probe),
        }
    }
    #[instrument(skip_all)]
    fn recv_probe(&mut self) -> Result<Option<ProbeResponse>> {
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

impl<S: Socket> TracerChannel<S> {
    /// Dispatch a ICMP probe.
    #[instrument(skip_all)]
    fn dispatch_icmp_probe(&mut self, probe: Probe) -> Result<()> {
        match (self.src_addr, self.dest_addr, self.send_socket.as_mut()) {
            (IpAddr::V4(src_addr), IpAddr::V4(dest_addr), Some(socket)) => {
                ipv4::dispatch_icmp_probe(
                    socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (IpAddr::V6(src_addr), IpAddr::V6(dest_addr), Some(socket)) => {
                ipv6::dispatch_icmp_probe(
                    socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.packet_size,
                    self.payload_pattern,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a UDP probe.
    #[instrument(skip_all)]
    fn dispatch_udp_probe(&mut self, probe: Probe) -> Result<()> {
        match (self.src_addr, self.dest_addr, self.send_socket.as_mut()) {
            (IpAddr::V4(src_addr), IpAddr::V4(dest_addr), Some(socket)) => {
                ipv4::dispatch_udp_probe(
                    socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.privilege_mode,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (IpAddr::V6(src_addr), IpAddr::V6(dest_addr), Some(socket)) => {
                ipv6::dispatch_udp_probe(
                    socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.privilege_mode,
                    self.packet_size,
                    self.payload_pattern,
                    self.initial_sequence,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a TCP probe.
    #[instrument(skip_all)]
    fn dispatch_tcp_probe(&mut self, probe: Probe) -> Result<()> {
        let socket = match (self.src_addr, self.dest_addr) {
            (IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => {
                ipv4::dispatch_tcp_probe(&probe, src_addr, dest_addr, self.tos)
            }
            (IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => {
                ipv6::dispatch_tcp_probe(&probe, src_addr, dest_addr)
            }
            _ => unreachable!(),
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
    #[instrument(skip(self))]
    fn recv_icmp_probe(&mut self) -> Result<Option<ProbeResponse>> {
        if self.recv_socket.is_readable(self.read_timeout)? {
            match self.dest_addr {
                IpAddr::V4(_) => ipv4::recv_icmp_probe(
                    &mut self.recv_socket,
                    self.protocol,
                    self.icmp_extension_mode,
                ),
                IpAddr::V6(_) => ipv6::recv_icmp_probe(
                    &mut self.recv_socket,
                    self.protocol,
                    self.icmp_extension_mode,
                ),
            }
        } else {
            Ok(None)
        }
    }

    /// Generate synthetic `ProbeResponse` if a TCP socket is connected or if the connection was
    /// refused.
    ///
    /// Any TCP socket which has not connected or failed after a timeout will be removed.
    #[instrument(skip(self))]
    fn recv_tcp_sockets(&mut self) -> Result<Option<ProbeResponse>> {
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
            match self.dest_addr {
                IpAddr::V4(_) => ipv4::recv_tcp_socket(
                    &mut probe.socket,
                    probe.src_port,
                    probe.dest_port,
                    self.dest_addr,
                ),
                IpAddr::V6(_) => ipv6::recv_tcp_socket(
                    &mut probe.socket,
                    probe.src_port,
                    probe.dest_port,
                    self.dest_addr,
                ),
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
    pub fn new(socket: S, src_port: Port, dest_port: Port, start: SystemTime) -> Self {
        Self {
            socket,
            src_port,
            dest_port,
            start,
        }
    }
}

/// Make a socket for sending raw `ICMP` packets.
#[instrument]
fn make_icmp_send_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(_) => S::new_icmp_send_socket_ipv4(raw),
        IpAddr::V6(_) => S::new_icmp_send_socket_ipv6(raw),
    }?)
}

/// Make a socket for sending `UDP` packets.
#[instrument]
fn make_udp_send_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(_) => S::new_udp_send_socket_ipv4(raw),
        IpAddr::V6(_) => S::new_udp_send_socket_ipv6(raw),
    }?)
}

/// Make a socket for receiving raw `ICMP` packets.
#[instrument]
fn make_recv_socket<S: Socket>(addr: IpAddr, raw: bool) -> Result<S> {
    Ok(match addr {
        IpAddr::V4(ipv4addr) => S::new_recv_socket_ipv4(ipv4addr, raw),
        IpAddr::V6(ipv6addr) => S::new_recv_socket_ipv6(ipv6addr, raw),
    }?)
}
