use crate::tracing::error::TracerError::AddressNotAvailable;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::platform::{discover_ip_length_byte_order, Ipv4TotalLengthByteOrder};
use crate::tracing::net::{ipv4, ipv6, Network, ProbeResponse, TcpProbeResponseData};
use crate::tracing::types::{PacketSize, PayloadPattern, TraceId, TypeOfService};
use crate::tracing::util::Required;
use crate::tracing::{
    net, PortDirection, Probe, TracerAddrFamily, TracerChannelConfig, TracerProtocol,
};
use arrayvec::ArrayVec;
use itertools::Itertools;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::time::{Duration, SystemTime};

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// The maximum size of the IP packet we allow.
pub const MAX_PACKET_SIZE: usize = 1024;

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    protocol: TracerProtocol,
    addr_family: TracerAddrFamily,
    src_addr: IpAddr,
    ipv4_length_order: Ipv4TotalLengthByteOrder,
    dest_addr: IpAddr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    tos: TypeOfService,
    port_direction: PortDirection,
    tcp_connect_timeout: Duration,
    icmp_send_socket: Socket,
    udp_send_socket: Socket,
    recv_socket: Socket,
    tcp_probes: ArrayVec<TcpProbe, MAX_TCP_PROBES>,
}

impl TracerChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    pub fn connect(config: &TracerChannelConfig) -> TraceResult<Self> {
        if usize::from(config.packet_size.0) > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(usize::from(
                config.packet_size.0,
            )));
        }
        let src_addr = net::make_src_addr(
            config.source_addr,
            config.target_addr,
            config.port_direction,
            config.interface.as_deref(),
            config.addr_family,
        )?;
        let ipv4_length_order = discover_ip_length_byte_order(src_addr)?;
        let icmp_send_socket = net::make_icmp_send_socket(config.addr_family)?;
        let udp_send_socket = net::make_udp_send_socket(config.addr_family)?;
        let recv_socket = net::make_recv_socket(config.addr_family)?;
        Ok(Self {
            protocol: config.protocol,
            addr_family: config.addr_family,
            src_addr,
            ipv4_length_order,
            dest_addr: config.target_addr,
            identifier: config.identifier,
            packet_size: config.packet_size,
            payload_pattern: config.payload_pattern,
            tos: config.tos,
            port_direction: config.port_direction,
            tcp_connect_timeout: config.tcp_connect_timeout,
            icmp_send_socket,
            udp_send_socket,
            recv_socket,
            tcp_probes: ArrayVec::new(),
        })
    }

    /// Get the source `IpAddr` of the channel.
    #[must_use]
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }
}

impl Network for TracerChannel {
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match self.protocol {
            TracerProtocol::Icmp => self.dispatch_icmp_probe(probe),
            TracerProtocol::Udp => self.dispatch_udp_probe(probe),
            TracerProtocol::Tcp => self.dispatch_tcp_probe(probe),
        }
    }

    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>> {
        match self.protocol {
            TracerProtocol::Icmp | TracerProtocol::Udp => self.recv_icmp_probe(),
            TracerProtocol::Tcp => Ok(self.recv_tcp_sockets()?.or(self.recv_icmp_probe()?)),
        }
    }
}

impl TracerChannel {
    fn dispatch_icmp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match (self.addr_family, self.src_addr, self.dest_addr) {
            (TracerAddrFamily::Ipv4, IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => {
                ipv4::dispatch_icmp_probe(
                    &mut self.icmp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.identifier,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (TracerAddrFamily::Ipv6, IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => {
                ipv6::dispatch_icmp_probe(
                    &mut self.icmp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.identifier,
                    self.packet_size,
                    self.payload_pattern,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a UDP probe.
    ///
    /// This covers both the IPv4 and IPv6 cases.
    fn dispatch_udp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match (self.addr_family, self.src_addr, self.dest_addr) {
            (TracerAddrFamily::Ipv4, IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => {
                ipv4::dispatch_udp_probe(
                    &mut self.udp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.port_direction,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (TracerAddrFamily::Ipv6, IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => {
                ipv6::dispatch_udp_probe(
                    &mut self.udp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.port_direction,
                    self.packet_size,
                    self.payload_pattern,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a TCP probe.
    ///
    /// This covers both the IPv4 and IPv6 cases.
    fn dispatch_tcp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        let (src_port, dest_port) = match self.port_direction {
            PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
            PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
            PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
        };
        let socket = match self.addr_family {
            TracerAddrFamily::Ipv4 => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)),
            TracerAddrFamily::Ipv6 => Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)),
        }?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        let local_addr = SocketAddr::new(self.src_addr, src_port);
        socket.bind(&SockAddr::from(local_addr))?;
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(self.dest_addr, dest_port);
        match socket.connect(&SockAddr::from(remote_addr)) {
            Ok(_) => {}
            Err(err) => {
                if let Some(code) = err.raw_os_error() {
                    if nix::Error::from_i32(code) != nix::Error::EINPROGRESS {
                        return match err.kind() {
                            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                                Err(AddressNotAvailable(local_addr))
                            }
                            _ => Err(TracerError::IoError(err)),
                        };
                    }
                } else {
                    return Err(TracerError::IoError(err));
                }
            }
        }
        self.tcp_probes
            .push(TcpProbe::new(socket, SystemTime::now()));
        Ok(())
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any
    fn recv_icmp_probe(&mut self) -> TraceResult<Option<ProbeResponse>> {
        match self.addr_family {
            TracerAddrFamily::Ipv4 => {
                ipv4::recv_icmp_probe(&mut self.recv_socket, self.protocol, self.port_direction)
            }
            TracerAddrFamily::Ipv6 => {
                ipv6::recv_icmp_probe(&mut self.recv_socket, self.protocol, self.port_direction)
            }
        }
    }

    /// Generate synthetic `ProbeResponse` if a TCP socket is connected or if the connection was refused.
    ///
    /// Any TCP socket which has not connected or failed after a timeout wil be removed.
    fn recv_tcp_sockets(&mut self) -> TraceResult<Option<ProbeResponse>> {
        self.tcp_probes
            .retain(|probe| probe.start.elapsed().unwrap_or_default() < self.tcp_connect_timeout);
        let found_index = self
            .tcp_probes
            .iter()
            .find_position(|&probe| net::is_writable(&probe.socket))
            .map(|(i, _)| i);
        if let Some(i) = found_index {
            let probe = self.tcp_probes.remove(i);
            let ttl = probe.socket.ttl()? as u8;
            match probe.socket.take_error()? {
                None => {
                    let addr = probe.socket.peer_addr()?.as_socket().req()?.ip();
                    probe.socket.shutdown(Shutdown::Both)?;
                    return Ok(Some(ProbeResponse::TcpReply(TcpProbeResponseData::new(
                        SystemTime::now(),
                        addr,
                        ttl,
                    ))));
                }
                Some(err) => {
                    if let Some(code) = err.raw_os_error() {
                        if nix::Error::from_i32(code) == nix::Error::ECONNREFUSED {
                            return Ok(Some(ProbeResponse::TcpRefused(TcpProbeResponseData::new(
                                SystemTime::now(),
                                self.dest_addr,
                                ttl,
                            ))));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

/// An entry in the TCP probes array.
#[derive(Debug)]
struct TcpProbe {
    socket: Socket,
    start: SystemTime,
}

impl TcpProbe {
    pub fn new(socket: Socket, start: SystemTime) -> Self {
        Self { socket, start }
    }
}
