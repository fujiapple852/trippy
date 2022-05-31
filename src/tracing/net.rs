use crate::tracing::error::TracerError::{AddressNotAvailable, InvalidSourceAddr};
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::packet::ipv4::Ipv4Packet;
use crate::tracing::types::{PacketSize, PayloadPattern, Port, TraceId, TypeOfService};
use crate::tracing::util::Required;
use crate::tracing::{PortDirection, Probe, TracerAddrFamily, TracerChannelConfig, TracerProtocol};
use arrayvec::ArrayVec;
use itertools::Itertools;
use nix::sys::select::FdSet;
use nix::sys::time::{TimeVal, TimeValLike};
use pnet::transport::{TransportReceiver, TransportSender};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, SystemTime};

/// The response to a probe.
#[derive(Debug, Copy, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData),
    DestinationUnreachable(ProbeResponseData),
    EchoReply(ProbeResponseData),
    TcpReply(TcpProbeResponseData),
    TcpRefused(TcpProbeResponseData),
}

/// The data in the probe response.
#[derive(Debug, Copy, Clone)]
pub struct ProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
}

impl ProbeResponseData {
    fn new(recv: SystemTime, addr: IpAddr, identifier: u16, sequence: u16) -> Self {
        Self {
            recv,
            addr,
            identifier,
            sequence,
        }
    }
}

/// The data in the TCP probe response.
#[derive(Debug, Copy, Clone)]
pub struct TcpProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub ttl: u8,
}

impl TcpProbeResponseData {
    fn new(recv: SystemTime, addr: IpAddr, ttl: u8) -> Self {
        Self { recv, addr, ttl }
    }
}

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send a `Probe`
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>>;
}

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// The maximum size of the IP packet we allow.
const MAX_PACKET_SIZE: usize = 1024;

/// The port used for local address discovery if not dest port is available.
const DISCOVERY_PORT: Port = Port(80);

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

/// The byte order to encode the `total length` field of the IPv4 header.
///
/// To quote directly from the `mtr` source code (from `check_length_order` in `probe_unix.c`):
///
/// "Nearly all fields in the IP header should be encoded in network byte
/// order prior to passing to send().  However, the required byte order of
/// the length field of the IP header is inconsistent between operating
/// systems and operating system versions.  FreeBSD 11 requires the length
/// field in network byte order, but some older versions of FreeBSD
/// require host byte order.  OS X requires the length field in host
/// byte order.  Linux will accept either byte order."
#[derive(Debug, Copy, Clone)]
pub enum Ipv4TotalLengthByteOrder {
    #[cfg(all(unix, not(target_os = "linux")))]
    Host,
    Network,
}

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
    icmp_read_timeout: Duration,
    tcp_connect_timeout: Duration,
    icmp_tx: TransportSender,
    icmp_rx: TransportReceiver,
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
        let src_addr = Self::make_src_addr(config)?;
        let ipv4_length_order = Self::discover_ip_length_byte_order(src_addr)?;
        let (icmp_tx, icmp_rx) = make_icmp_channel(config.addr_family)?;
        let icmp_send_socket = make_icmp_send_socket(config.addr_family)?;
        let udp_send_socket = make_udp_send_socket(config.addr_family)?;
        let recv_socket = make_recv_socket(config.addr_family)?;
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
            icmp_read_timeout: config.icmp_read_timeout,
            tcp_connect_timeout: config.tcp_connect_timeout,
            icmp_tx,
            icmp_rx,
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

    fn make_src_addr(config: &TracerChannelConfig) -> TraceResult<IpAddr> {
        match (config.source_addr, config.interface.as_ref()) {
            (Some(addr), None) => validate_local_addr(config.addr_family, addr),
            (None, Some(interface)) => lookup_interface_addr(config.addr_family, interface),
            (None, None) => discover_local_addr(
                config.addr_family,
                config.target_addr,
                config.port_direction.dest().unwrap_or(DISCOVERY_PORT).0,
            ),
            (Some(_), Some(_)) => unreachable!(),
        }
    }

    /// Discover the required byte ordering for the IPv4 header field `total_length`.
    ///
    /// This is achieved by creating a raw socket and attempting to send an `IPv4` packet to localhost with the
    /// `total_length` set in either host byte order or network byte order. The OS will return an `InvalidInput` error
    /// if the buffer provided is smaller than the `total_length` indicated, which will be the case when the byte order
    /// is set incorrectly.
    ///
    /// This is a little confusing as `Ipv4Packet::set_total_length` method will _always_ convert from host byte order
    /// to network byte order (which will be a no-op on big-endian system) and so to test the host byte order case
    /// we must ...
    ///
    /// For example, for a packet of length 4660 bytes (dec):
    ///
    /// For a little-endian architecture:
    ///
    /// Try        Host (LE)    Wire (BE)   Order (if succeeds)
    /// normal     34 12        12 34       `Ipv4TotalLengthByteOrder::Network`
    /// swapped    12 34        34 12       `Ipv4TotalLengthByteOrder::Host`
    ///
    /// For a big-endian architecture:
    ///
    /// Try        Host (BE)    Wire (BE)   Order (if succeeds)
    /// normal     12 34        12 34       `Ipv4TotalLengthByteOrder::Host`
    /// swapped    34 12        34 12       `Ipv4TotalLengthByteOrder::Network`
    ///
    /// TODO validate the latter cases on a BE system
    /// TODO what do we do for IPv6?
    #[cfg(all(unix, not(target_os = "linux")))]
    fn discover_ip_length_byte_order(src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
        match Self::test_send_local_ip4_packet(src_addr, 256_u16) {
            Ok(_) => Ok(Ipv4TotalLengthByteOrder::Network),
            Err(TracerError::IoError(io)) if io.kind() == ErrorKind::InvalidInput => {
                match Self::test_send_local_ip4_packet(src_addr, 256_u16.swap_bytes()) {
                    Ok(_) => Ok(Ipv4TotalLengthByteOrder::Host),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Open a raw socket and attempt to send an `ICMP` packet to a local address.
    ///
    /// The packet is actually of length `256` bytes but we set the `total_length` based on the input provided so as to
    /// test if the OS rejects the attempt.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn test_send_local_ip4_packet(src_addr: IpAddr, total_length: u16) -> TraceResult<usize> {
        let src_addr = match src_addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => unimplemented!(), // TODO
        };
        let mut buf = [0_u8; 256];
        let mut ipv4 = Ipv4Packet::new(&mut buf).req()?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_protocol(crate::tracing::packet::IpProtocol::Icmp);
        ipv4.set_ttl(255);
        ipv4.set_source(src_addr);
        ipv4.set_destination(std::net::Ipv4Addr::LOCALHOST);
        ipv4.set_total_length(total_length);
        let probe_socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(nix::libc::IPPROTO_RAW)),
        )?;
        probe_socket.set_header_included(true)?;
        let remote_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        Ok(probe_socket.send_to(ipv4.packet(), &SockAddr::from(remote_addr))?)
    }

    /// Discover the required byte ordering for the IPv4 header field `total_length`.
    ///
    /// Linux accepts either network byte order or host byte order for the `total_length` field and so we skip the
    /// check and return network bye order unconditionally.
    ///
    /// TODO move platform specifics into a separate module.
    #[cfg(target_os = "linux")]
    #[allow(clippy::unnecessary_wraps)]
    fn discover_ip_length_byte_order(_src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
        Ok(Ipv4TotalLengthByteOrder::Network)
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
            (TracerAddrFamily::Ipv6, _, _) => ipv6::dispatch_icmp_probe(
                &mut self.icmp_tx,
                probe,
                self.dest_addr,
                self.identifier,
                self.packet_size,
                self.payload_pattern,
            ),
            _ => unimplemented!(),
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
            (TracerAddrFamily::Ipv6, IpAddr::V6(_), IpAddr::V6(_)) => unimplemented!(),
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
            TracerAddrFamily::Ipv6 => ipv6::recv_icmp_probe(
                &mut self.icmp_rx,
                self.icmp_read_timeout,
                self.protocol,
                self.port_direction,
            ),
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
            .find_position(|&probe| is_writable(&probe.socket))
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

/// IPv4 implementation.
mod ipv4 {
    use crate::tracing::error::{TraceResult, TracerError};
    use crate::tracing::net::{
        Ipv4TotalLengthByteOrder, ProbeResponse, ProbeResponseData, MAX_PACKET_SIZE,
    };
    use crate::tracing::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
    use crate::tracing::packet::icmp::echo_reply::EchoReplyPacket;
    use crate::tracing::packet::icmp::echo_request::EchoRequestPacket;
    use crate::tracing::packet::icmp::time_exceeded::TimeExceededPacket;
    use crate::tracing::packet::icmp::{IcmpCode, IcmpPacket, IcmpType};
    use crate::tracing::packet::ipv4::Ipv4Packet;
    use crate::tracing::packet::udp::UdpPacket;
    use crate::tracing::packet::IpProtocol;
    use crate::tracing::types::{PacketSize, PayloadPattern, TraceId};
    use crate::tracing::util::Required;
    use crate::tracing::{PortDirection, Probe, TracerProtocol};
    use nix::libc::IPPROTO_RAW;
    use nix::sys::socket::{AddressFamily, SockaddrLike};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::tcp::TcpPacket;
    use pnet::transport::{
        transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
        TransportSender,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io::{ErrorKind, Read};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::SystemTime;

    /// The maximum size of UDP packet we allow.
    const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

    /// The maximum size of UDP payload we allow.
    const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

    /// The maximum size of UDP packet we allow.
    const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

    /// The maximum size of ICMP payload we allow.
    const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

    pub fn lookup_interface_addr(name: &str) -> TraceResult<IpAddr> {
        nix::ifaddrs::getifaddrs()
            .map_err(|_| TracerError::UnknownInterface(name.to_string()))?
            .into_iter()
            .find_map(|ia| {
                ia.address.and_then(|addr| match addr.family() {
                    Some(AddressFamily::Inet) if ia.interface_name == name => addr
                        .as_sockaddr_in()
                        .map(|sock_addr| IpAddr::V4(Ipv4Addr::from(sock_addr.ip()))),
                    _ => None,
                })
            })
            .ok_or_else(|| TracerError::UnknownInterface(name.to_string()))
    }

    pub fn make_icmp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
        let channel_type =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        Ok(transport_channel(1600, channel_type)?)
    }

    pub fn make_icmp_send_socket() -> TraceResult<Socket> {
        make_raw_socket()
    }

    pub fn make_udp_send_socket() -> TraceResult<Socket> {
        make_raw_socket()
    }

    pub fn make_recv_socket() -> TraceResult<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    // TODO refactor generic IPv4 sending for use by icmp and udp.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_icmp_probe(
        raw_send_socket: &mut Socket,
        probe: Probe,
        src_addr: Ipv4Addr,
        dest_addr: Ipv4Addr,
        identifier: TraceId,
        packet_size: PacketSize,
        payload_pattern: PayloadPattern,
        ipv4_length_order: Ipv4TotalLengthByteOrder,
    ) -> TraceResult<()> {
        let packet_size = usize::from(packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
        let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
        let mut icmp_payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
        let ipv4_packet_size = packet_size;
        let icmp_payload_size = icmp_payload_size(ipv4_packet_size);
        let icmp_packet_size = IcmpPacket::minimum_packet_size() + icmp_payload_size;
        let ipv4_total_length = (Ipv4Packet::minimum_packet_size() + icmp_packet_size) as u16;
        let ipv4_total_length_header = match ipv4_length_order {
            #[cfg(all(unix, not(target_os = "linux")))]
            Ipv4TotalLengthByteOrder::Host => ipv4_total_length.swap_bytes(),
            Ipv4TotalLengthByteOrder::Network => ipv4_total_length,
        };
        icmp_payload_buf
            .iter_mut()
            .for_each(|x| *x = payload_pattern.0);
        let mut icmp = EchoRequestPacket::new(&mut icmp_buf[..icmp_packet_size]).req()?;
        icmp.set_icmp_type(IcmpType::EchoRequest);
        icmp.set_icmp_code(IcmpCode(0));
        icmp.set_identifier(identifier.0);
        icmp.set_payload(&icmp_payload_buf[..icmp_payload_size]);
        icmp.set_sequence(probe.sequence.0);
        icmp.set_checksum(pnet::util::checksum(icmp.packet(), 1));
        let mut ipv4 = Ipv4Packet::new(&mut ipv4_buf[..ipv4_total_length as usize]).req()?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_total_length_header);
        ipv4.set_ttl(probe.ttl.0);
        ipv4.set_protocol(IpProtocol::Icmp);
        ipv4.set_source(src_addr);
        ipv4.set_destination(dest_addr);
        ipv4.set_payload(icmp.packet());
        let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dest_addr), 0));
        raw_send_socket.send_to(ipv4.packet(), &remote_addr)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_udp_probe(
        raw_send_socket: &mut Socket,
        probe: Probe,
        src_addr: Ipv4Addr,
        dest_addr: Ipv4Addr,
        port_direction: PortDirection,
        packet_size: PacketSize,
        payload_pattern: PayloadPattern,
        ipv4_length_order: Ipv4TotalLengthByteOrder,
    ) -> TraceResult<()> {
        let (src_port, dest_port) = match port_direction {
            PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
            PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
            PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
        };
        let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
        let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
        let mut udp_payload_buf = [0_u8; MAX_UDP_PAYLOAD_BUF];
        let ipv4_packet_size = usize::from(packet_size.0);
        let udp_payload_size = udp_payload_size(ipv4_packet_size);
        let udp_packet_size = UdpPacket::minimum_packet_size() + udp_payload_size;
        let ipv4_total_length = (Ipv4Packet::minimum_packet_size() + udp_packet_size) as u16;
        let ipv4_total_length_header = match ipv4_length_order {
            #[cfg(all(unix, not(target_os = "linux")))]
            Ipv4TotalLengthByteOrder::Host => ipv4_total_length.swap_bytes(),
            Ipv4TotalLengthByteOrder::Network => ipv4_total_length,
        };
        udp_payload_buf
            .iter_mut()
            .for_each(|x| *x = payload_pattern.0);
        let mut udp = UdpPacket::new(&mut udp_buf[..udp_packet_size as usize]).req()?;
        udp.set_source(src_port);
        udp.set_destination(dest_port);
        udp.set_length(udp_packet_size as u16);
        udp.set_payload(&udp_payload_buf[..udp_payload_size]);
        udp.set_checksum(checksum_v4(udp.packet(), src_addr, dest_addr));
        let mut ipv4 = Ipv4Packet::new(&mut ipv4_buf[..ipv4_total_length as usize]).req()?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_total_length_header);
        ipv4.set_ttl(probe.ttl.0);
        ipv4.set_protocol(IpProtocol::Udp);
        ipv4.set_source(src_addr);
        ipv4.set_destination(dest_addr);
        ipv4.set_payload(udp.packet());
        let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dest_addr), dest_port));
        raw_send_socket.send_to(ipv4.packet(), &remote_addr)?;
        Ok(())
    }

    pub fn recv_icmp_probe(
        recv_socket: &mut Socket,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<Option<ProbeResponse>> {
        let mut buf = [0_u8; MAX_PACKET_SIZE];
        match recv_socket.read(&mut buf) {
            Ok(_bytes_read) => {
                let ipv4 = Ipv4Packet::new_view(&buf).req()?;
                Ok(extract_probe_resp_v4(protocol, direction, &ipv4)?)
            }
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock => Ok(None),
                _ => Err(TracerError::IoError(err)),
            },
        }
    }

    fn make_raw_socket() -> TraceResult<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    fn icmp_payload_size(packet_size: usize) -> usize {
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let icmp_header_size = IcmpPacket::minimum_packet_size();
        packet_size - icmp_header_size - ip_header_size
    }

    fn udp_payload_size(packet_size: usize) -> usize {
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        packet_size - udp_header_size - ip_header_size
    }

    fn extract_probe_resp_v4(
        protocol: TracerProtocol,
        direction: PortDirection,
        ipv4: &Ipv4Packet<'_>,
    ) -> TraceResult<Option<ProbeResponse>> {
        let recv = SystemTime::now();
        let src = IpAddr::V4(ipv4.get_source());
        let icmp_v4 = IcmpPacket::new_view(ipv4.payload()).req()?;
        Ok(match icmp_v4.get_icmp_type() {
            IcmpType::TimeExceeded => {
                let packet = TimeExceededPacket::new_view(icmp_v4.packet()).req()?;
                let (id, seq) = extract_time_exceeded_v4(&packet, protocol, direction)?;
                Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                    recv, src, id, seq,
                )))
            }
            IcmpType::DestinationUnreachable => {
                let packet = DestinationUnreachablePacket::new_view(icmp_v4.packet()).req()?;
                let (id, seq) = extract_dest_unreachable_v4(&packet, protocol, direction)?;
                Some(ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, src, id, seq),
                ))
            }
            IcmpType::EchoReply => match protocol {
                TracerProtocol::Icmp => {
                    let packet = EchoReplyPacket::new_view(icmp_v4.packet()).req()?;
                    let id = packet.get_identifier();
                    let seq = packet.get_sequence();
                    Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                        recv, src, id, seq,
                    )))
                }
                TracerProtocol::Udp | TracerProtocol::Tcp => None,
            },
            _ => None,
        })
    }

    fn extract_time_exceeded_v4(
        packet: &TimeExceededPacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v4(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
                let (src, dest) = extract_udp_packet_v4(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
                let (src, dest) = extract_tcp_packet_v4(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedSrc(_) => dest,
                    _ => src,
                };
                (0, sequence)
            }
        })
    }

    fn extract_dest_unreachable_v4(
        packet: &DestinationUnreachablePacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v4(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let (src, dest) = extract_udp_packet_v4(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let (src, dest) = extract_tcp_packet_v4(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedSrc(_) => dest,
                    _ => src,
                };
                (0, sequence)
            }
        })
    }

    fn extract_echo_request_v4(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
        let ip4 = Ipv4Packet::new_view(payload).req()?;
        let header_len = usize::from(ip4.get_header_length() * 4);
        let nested_icmp = &payload[header_len..];
        let nested_echo = EchoRequestPacket::new_view(nested_icmp).req()?;
        Ok(nested_echo)
    }

    /// Get the src and dest ports from the original `UdpPacket` packet embedded in the payload.
    fn extract_udp_packet_v4(payload: &[u8]) -> TraceResult<(u16, u16)> {
        let ip4 = Ipv4Packet::new_view(payload).req()?;
        let header_len = usize::from(ip4.get_header_length() * 4);
        let nested_udp = &payload[header_len..];
        let nested = UdpPacket::new_view(nested_udp).req()?;
        Ok((nested.get_source(), nested.get_destination()))
    }

    /// Get the src and dest ports from the original `TcpPacket` packet embedded in the payload.
    ///
    /// Unlike the embedded `ICMP` and `UDP` packets, which have a minimum header size of 8 bytes, the `TCP` packet header
    /// is a minimum of 20 bytes.
    ///
    /// The `ICMP` packets we are extracting these from, such as `TimeExceeded`, only guarantee that 8 bytes of the
    /// original packet (plus the IP header) be returned and so we may not have a complete TCP packet.
    ///
    /// We therefore have to detect this situation and ensure we provide buffer a large enough for a complete TCP packet
    /// header.
    fn extract_tcp_packet_v4(payload: &[u8]) -> TraceResult<(u16, u16)> {
        let ip4 = Ipv4Packet::new_view(payload).req()?;
        let header_len = usize::from(ip4.get_header_length() * 4);
        let nested_tcp = &payload[header_len..];
        if nested_tcp.len() < TcpPacket::minimum_packet_size() {
            let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
            buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
            let tcp_packet = TcpPacket::new(&buf).req()?;
            Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
        } else {
            let tcp_packet = TcpPacket::new(nested_tcp).req()?;
            Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
        }
    }

    /// Calculate the IPV4 checksum.
    ///
    /// TODO uses pnet
    fn checksum_v4(bytes: &[u8], src_addr: Ipv4Addr, dest_addr: Ipv4Addr) -> u16 {
        pnet::util::ipv4_checksum(
            bytes,
            3,
            &[],
            &src_addr,
            &dest_addr,
            IpNextHeaderProtocols::Udp,
        )
    }
}

/// IPv6 implementation.
mod ipv6 {
    use crate::tracing::error::{TraceResult, TracerError};
    use crate::tracing::net::{ProbeResponse, ProbeResponseData, MAX_PACKET_SIZE};
    use crate::tracing::packet::udp::UdpPacket;
    use crate::tracing::types::{PacketSize, PayloadPattern, TraceId};
    use crate::tracing::util::Required;

    use crate::tracing::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
    use crate::tracing::packet::icmp::echo_reply::EchoReplyPacket;
    use crate::tracing::packet::icmp::echo_request::EchoRequestPacket;
    use crate::tracing::packet::icmp::time_exceeded::TimeExceededPacket;
    use crate::tracing::packet::icmp::{IcmpCode, IcmpPacket, IcmpType};
    use crate::tracing::packet::ipv6::Ipv6Packet;
    use crate::tracing::{PortDirection, Probe, TracerProtocol};
    use nix::sys::socket::{AddressFamily, SockaddrLike};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::util;
    use pnet::transport::{
        icmpv6_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
        TransportReceiver, TransportSender,
    };
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};

    pub fn lookup_interface_addr(name: &str) -> TraceResult<IpAddr> {
        nix::ifaddrs::getifaddrs()
            .map_err(|_| TracerError::UnknownInterface(name.to_string()))?
            .into_iter()
            .find_map(|ia| {
                ia.address.and_then(|addr| match addr.family() {
                    Some(AddressFamily::Inet6) if ia.interface_name == name => addr
                        .as_sockaddr_in6()
                        .map(|sock_addr| IpAddr::V6(sock_addr.ip())),
                    _ => None,
                })
            })
            .ok_or_else(|| TracerError::UnknownInterface(name.to_string()))
    }

    pub fn make_icmp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
        let channel_type =
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
        Ok(transport_channel(1600, channel_type)?)
    }

    pub fn make_icmp_send_socket() -> TraceResult<Socket> {
        let udp_socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        udp_socket.set_nonblocking(true)?;
        udp_socket.set_header_included(true)?;
        Ok(udp_socket)
    }

    pub fn make_udp_send_socket() -> TraceResult<Socket> {
        let udp_socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
        udp_socket.set_nonblocking(true)?;
        udp_socket.set_header_included(true)?;
        Ok(udp_socket)
    }

    pub fn make_recv_socket() -> TraceResult<Socket> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    pub fn dispatch_icmp_probe(
        icmp_tx: &mut TransportSender,
        probe: Probe,
        dest_addr: IpAddr,
        identifier: TraceId,
        packet_size: PacketSize,
        payload_pattern: PayloadPattern,
    ) -> TraceResult<()> {
        const MAX_ICMP_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();
        const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_BUF - EchoRequestPacket::minimum_packet_size();
        let packet_size = usize::from(packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv6Packet::minimum_packet_size();
        let icmp_header_size = EchoRequestPacket::minimum_packet_size();
        let mut icmp_buf = [0_u8; MAX_ICMP_BUF];
        let mut payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
        let icmp_buf_size = packet_size - ip_header_size;
        let payload_size = packet_size - icmp_header_size - ip_header_size;
        payload_buf.iter_mut().for_each(|x| *x = payload_pattern.0);
        let mut req = EchoRequestPacket::new(&mut icmp_buf[..icmp_buf_size]).req()?;
        req.set_icmp_type(IcmpType::EchoRequest);
        req.set_icmp_code(IcmpCode(0));
        req.set_identifier(identifier.0);
        req.set_payload(&payload_buf[..payload_size]);
        req.set_sequence(probe.sequence.0);
        req.set_checksum(util::checksum(req.packet(), 1));
        icmp_tx.set_ttl(probe.ttl.0)?;
        // TODO
        let legacy =
            pnet::packet::icmp::echo_request::EchoRequestPacket::new(req.packet()).unwrap();
        icmp_tx.send_to(legacy, dest_addr)?;
        Ok(())
    }

    pub fn recv_icmp_probe(
        icmp_rx: &mut TransportReceiver,
        icmp_read_timeout: Duration,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<Option<ProbeResponse>> {
        match icmpv6_packet_iter(icmp_rx).next_with_timeout(icmp_read_timeout)? {
            None => Ok(None),
            Some((icmp, ip)) => {
                // TODO just wrap the bytes from pnet for now
                use pnet::packet::Packet;
                let icmp = IcmpPacket::new_view(icmp.packet()).unwrap();
                Ok(extract_probe_resp_v6(protocol, direction, &icmp, ip)?)
            }
        }
    }

    fn extract_probe_resp_v6(
        protocol: TracerProtocol,
        direction: PortDirection,
        icmp_v6: &IcmpPacket<'_>,
        ip: IpAddr,
    ) -> TraceResult<Option<ProbeResponse>> {
        let recv = SystemTime::now();
        Ok(match icmp_v6.get_icmp_type() {
            IcmpType::TimeExceeded => {
                let packet = TimeExceededPacket::new_view(icmp_v6.packet()).req()?;
                let (id, seq) = extract_time_exceeded_v6(&packet, protocol, direction)?;
                Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                    recv, ip, id, seq,
                )))
            }
            IcmpType::DestinationUnreachable => {
                let packet = DestinationUnreachablePacket::new_view(icmp_v6.packet()).req()?;
                let (id, seq) = extract_dest_unreachable_v6(&packet, protocol, direction)?;
                Some(ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, ip, id, seq),
                ))
            }
            IcmpType::EchoReply => match protocol {
                TracerProtocol::Icmp => {
                    let packet = EchoReplyPacket::new_view(icmp_v6.packet()).req()?;
                    let id = packet.get_identifier();
                    let seq = packet.get_sequence();
                    Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                        recv, ip, id, seq,
                    )))
                }
                TracerProtocol::Udp | TracerProtocol::Tcp => None,
            },
            _ => None,
        })
    }

    fn extract_time_exceeded_v6(
        packet: &TimeExceededPacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v6(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
                let (src, dest) = extract_udp_packet_v6(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
                let (src, dest) = extract_tcp_packet_v6(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedSrc(_) => dest,
                    _ => src,
                };
                (0, sequence)
            }
        })
    }

    fn extract_dest_unreachable_v6(
        packet: &DestinationUnreachablePacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v6(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let (src, dest) = extract_udp_packet_v6(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let (src, dest) = extract_tcp_packet_v6(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedSrc(_) => dest,
                    _ => src,
                };
                (0, sequence)
            }
        })
    }

    fn extract_echo_request_v6(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
        let ip6 = Ipv6Packet::new_view(payload).req()?;
        let packet_size = payload.len();
        let payload_size = usize::from(ip6.get_payload_length());
        let header_size = packet_size - payload_size;
        let nested_icmp = &payload[header_size..];
        let nested_echo = EchoRequestPacket::new_view(nested_icmp).req()?;
        Ok(nested_echo)
    }

    fn extract_udp_packet_v6(payload: &[u8]) -> TraceResult<(u16, u16)> {
        let ip6 = Ipv6Packet::new_view(payload).req()?;
        let packet_size = payload.len();
        let payload_size = usize::from(ip6.get_payload_length());
        let header_size = packet_size - payload_size;
        let nested = &payload[header_size..];
        let nested_udp = UdpPacket::new_view(nested).req()?;
        Ok((nested_udp.get_source(), nested_udp.get_destination()))
    }

    // TODO
    fn extract_tcp_packet_v6(_payload: &[u8]) -> TraceResult<(u16, u16)> {
        unimplemented!()
    }
}

/// Lookup the address for a named interface.
fn lookup_interface_addr(addr_family: TracerAddrFamily, name: &str) -> TraceResult<IpAddr> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::lookup_interface_addr(name),
        TracerAddrFamily::Ipv6 => ipv6::lookup_interface_addr(name),
    }
}

/// Discover the local `IpAddr` that will be used to communicate with the given target `IpAddr`.
///
/// Note that no packets are transmitted by this method.
fn discover_local_addr(
    addr_family: TracerAddrFamily,
    target: IpAddr,
    port: u16,
) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(addr_family)?;
    socket.connect(&SockAddr::from(SocketAddr::new(target, port)))?;
    Ok(socket.local_addr()?.as_socket().req()?.ip())
}

/// Validate that we can bind to the source address.
fn validate_local_addr(addr_family: TracerAddrFamily, source_addr: IpAddr) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(addr_family)?;
    let addr = SocketAddr::new(source_addr, 0);
    match socket.bind(&SockAddr::from(addr)) {
        Ok(_) => Ok(source_addr),
        Err(_) => Err(InvalidSourceAddr(addr.ip())),
    }
}

/// Create a socket suitable for a given address.
fn udp_socket_for_addr_family(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    Ok(match addr_family {
        TracerAddrFamily::Ipv4 => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
        TracerAddrFamily::Ipv6 => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?,
    })
}

/// Create the communication channel needed for sending and receiving ICMP packets.
fn make_icmp_channel(
    addr_family: TracerAddrFamily,
) -> TraceResult<(TransportSender, TransportReceiver)> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_icmp_channel(),
        TracerAddrFamily::Ipv6 => ipv6::make_icmp_channel(),
    }
}

/// Make a socket for sending raw `ICMP` packets.
fn make_icmp_send_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_icmp_send_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_icmp_send_socket(),
    }
}

/// Make a socket for sending `UDP` packets.
fn make_udp_send_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_udp_send_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_udp_send_socket(),
    }
}

/// Make a socket for receiving raw `ICMP` packets.
fn make_recv_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_recv_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_recv_socket(),
    }
}

/// Is the socket writable?
fn is_writable(sock: &Socket) -> bool {
    let mut write = FdSet::new();
    write.insert(sock.as_raw_fd());
    let writable = nix::sys::select::select(
        None,
        None,
        Some(&mut write),
        None,
        Some(&mut TimeVal::zero()),
    )
    .expect("select");
    writable == 1
}
