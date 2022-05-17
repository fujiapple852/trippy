use crate::tracing::error::TracerError::{AddressNotAvailable, InvalidSourceAddr};
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{
    DestinationPort, PacketSize, PayloadPattern, SourcePort, TraceId, TypeOfService, Port
};
use crate::tracing::util::Required;
use crate::tracing::{Probe, TracerProtocol};
use arrayvec::ArrayVec;
use itertools::Itertools;
use nix::sys::select::FdSet;
use nix::sys::socket::{AddressFamily, SockaddrLike};
use nix::sys::time::{TimeVal, TimeValLike};
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use pnet::util;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
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

/// The maximum size of ICMP packet we allow.
const MAX_ICMP_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum ICMP payload size we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_BUF - EchoRequestPacket::minimum_packet_size();

/// The maximum size of UDP packet we allow.
const MAX_UDP_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum UDP payload size we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_BUF - UdpPacket::minimum_packet_size();

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
    /// When both ports are fixed another element of the IP header is required to vary per probe such that probes can
    /// be identified.  Typically this is only used for UDP, whereby the checksum is manipulated by adjusting the
    /// payload and therefore used as the identifier.
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
    protocol: TracerProtocol,
    source_addr: Option<IpAddr>,
    interface: Option<String>,
    target_addr: IpAddr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    tos: TypeOfService,
    source_port: SourcePort,
    destination_port: DestinationPort,
    icmp_read_timeout: Duration,
    tcp_connect_timeout: Duration,
}

impl TracerChannelConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        protocol: TracerProtocol,
        source_addr: Option<IpAddr>,
        interface: Option<String>,
        target_addr: IpAddr,
        identifier: u16,
        packet_size: u16,
        payload_pattern: u8,
        tos: u8,
        source_port: u16,
        destination_port: u16,
        icmp_read_timeout: Duration,
        tcp_connect_timeout: Duration,
    ) -> Self {
        Self {
            protocol,
            source_addr,
            interface,
            target_addr,
            identifier: TraceId(identifier),
            packet_size: PacketSize(packet_size),
            payload_pattern: PayloadPattern(payload_pattern),
            tos: TypeOfService(tos),
            source_port: SourcePort(source_port),
            destination_port: DestinationPort(destination_port),
            icmp_read_timeout,
            tcp_connect_timeout,
        }
    }
}

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    protocol: TracerProtocol,
    src_addr: IpAddr,
    dest_addr: IpAddr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    tos: TypeOfService,
    source_port: SourcePort,
    destination_port: DestinationPort,
    icmp_read_timeout: Duration,
    tcp_connect_timeout: Duration,
    icmp_tx: TransportSender,
    icmp_rx: TransportReceiver,
    tcp_probes: ArrayVec<TcpProbe, MAX_TCP_PROBES>,
}

impl TracerChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    pub fn connect(config: &TracerChannelConfig) -> TraceResult<Self> {
        let src_addr = Self::make_src_addr(config)?;
        let (icmp_tx, icmp_rx) = make_icmp_channel()?;
        Ok(Self {
            protocol: config.protocol,
            src_addr,
            dest_addr: config.target_addr,
            identifier: config.identifier,
            packet_size: config.packet_size,
            payload_pattern: config.payload_pattern,
            tos: config.tos,
            source_port: config.source_port,
            destination_port: config.destination_port,
            icmp_read_timeout: config.icmp_read_timeout,
            tcp_connect_timeout: config.tcp_connect_timeout,
            icmp_tx,
            icmp_rx,
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
            (Some(addr), None) => validate_local_ipv4_addr(addr),
            (None, Some(interface)) => lookup_interface_addr(interface),
            (None, None) => discover_ipv4_addr(config.target_addr, config.destination_port.0),
            (Some(_), Some(_)) => unreachable!(),
        }
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
        let packet_size = usize::from(self.packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let icmp_header_size = EchoRequestPacket::minimum_packet_size();
        let mut icmp_buf = [0_u8; MAX_ICMP_BUF];
        let mut payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
        let icmp_buf_size = packet_size - ip_header_size;
        let payload_size = packet_size - icmp_header_size - ip_header_size;
        payload_buf
            .iter_mut()
            .for_each(|x| *x = self.payload_pattern.0);
        let mut req = MutableEchoRequestPacket::new(&mut icmp_buf[..icmp_buf_size]).req()?;
        req.set_icmp_type(IcmpTypes::EchoRequest);
        req.set_icmp_code(echo_request::IcmpCodes::NoCode);
        req.set_identifier(self.identifier.0);
        req.set_payload(&payload_buf[..payload_size]);
        req.set_sequence_number(probe.sequence.0);
        req.set_checksum(util::checksum(req.packet(), 1));
        self.icmp_tx.set_ttl(probe.ttl.0)?;
        self.icmp_tx.send_to(req.to_immutable(), self.dest_addr)?;
        Ok(())
    }

    fn dispatch_udp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        let local_addr = SocketAddr::new(self.src_addr, self.source_port.0);
        match socket.bind(&SockAddr::from(local_addr)) {
            Ok(_) => {}
            Err(err) => {
                return match err.kind() {
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => Err(AddressNotAvailable),
                    _ => Err(TracerError::from(err)),
                };
            }
        };
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(self.dest_addr, probe.sequence.0);
        let packet_size = usize::from(self.packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        let mut payload_buf = [0_u8; MAX_UDP_PAYLOAD_BUF];
        let payload_size = packet_size - udp_header_size - ip_header_size;
        payload_buf
            .iter_mut()
            .for_each(|x| *x = self.payload_pattern.0);
        socket.send_to(&payload_buf[..payload_size], &SockAddr::from(remote_addr))?;
        Ok(())
    }

    fn dispatch_tcp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        let local_addr = SocketAddr::new(self.src_addr, probe.sequence.0);
        match socket.bind(&SockAddr::from(local_addr)) {
            Ok(_) => {}
            Err(err) => {
                return match err.kind() {
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => Err(AddressNotAvailable),
                    _ => Err(TracerError::from(err)),
                };
            }
        };
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(self.dest_addr, self.destination_port.0);
        match socket.connect(&SockAddr::from(remote_addr)) {
            Ok(_) => {}
            Err(err) => {
                if let Some(code) = err.raw_os_error() {
                    if nix::Error::from_i32(code) != nix::Error::EINPROGRESS {
                        return Err(TracerError::from(err));
                    }
                } else {
                    return Err(TracerError::from(err));
                }
            }
        }
        self.tcp_probes
            .push(TcpProbe::new(socket, SystemTime::now()));
        Ok(())
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any
    fn recv_icmp_probe(&mut self) -> TraceResult<Option<ProbeResponse>> {
        match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(self.icmp_read_timeout)? {
            None => Ok(None),
            Some((icmp, ip)) => Ok(extract_probe_resp(self.protocol, &icmp, ip)?),
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

///
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

/// Discover the local `IpAddr::V4` that will be used for the target `IpAddr`.
///
/// This is needed so we can can compute checksums for outgoing `TCP` packets.
///
/// Note that no packets are transmitted by this method.
fn discover_ipv4_addr(target: IpAddr, port: u16) -> TraceResult<IpAddr> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.connect(&SockAddr::from(SocketAddr::new(target, port)))?;
    Ok(socket.local_addr()?.as_socket().req()?.ip())
}

/// Validate that we can bind to the source address.
fn validate_local_ipv4_addr(source_addr: IpAddr) -> TraceResult<IpAddr> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr = SocketAddr::new(source_addr, 0);
    match socket.bind(&SockAddr::from(addr)) {
        Ok(_) => Ok(source_addr),
        Err(_) => Err(InvalidSourceAddr(addr.ip())),
    }
}

/// Lookup the IPv4 address for a named interface.
fn lookup_interface_addr(name: &str) -> TraceResult<IpAddr> {
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

/// Create the communication channel needed for sending and receiving ICMP packets.
fn make_icmp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
}

/// Extract a `ProbeResponse` from an ICMP packet.
fn extract_probe_resp(
    protocol: TracerProtocol,
    icmp: &IcmpPacket<'_>,
    ip: IpAddr,
) -> TraceResult<Option<ProbeResponse>> {
    let recv = SystemTime::now();
    Ok(match icmp.get_icmp_type() {
        IcmpTypes::TimeExceeded => {
            let packet = TimeExceededPacket::new(icmp.packet()).req()?;
            let (id, seq) = extract_time_exceeded(&packet, protocol)?;
            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                recv, ip, id, seq,
            )))
        }
        IcmpTypes::DestinationUnreachable => {
            let packet = DestinationUnreachablePacket::new(icmp.packet()).req()?;
            let (id, seq) = extract_dest_unreachable(&packet, protocol)?;
            Some(ProbeResponse::DestinationUnreachable(
                ProbeResponseData::new(recv, ip, id, seq),
            ))
        }
        IcmpTypes::EchoReply => match protocol {
            TracerProtocol::Icmp => {
                let packet = EchoReplyPacket::new(icmp.packet()).req()?;
                let id = packet.get_identifier();
                let seq = packet.get_sequence_number();
                Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                    recv, ip, id, seq,
                )))
            }
            TracerProtocol::Udp | TracerProtocol::Tcp => None,
        },
        _ => None,
    })
}

/// Extract `identifier` and `sequence` from a `TimeExceeded` packet.
fn extract_time_exceeded(
    packet: &TimeExceededPacket<'_>,
    protocol: TracerProtocol,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => {
            let echo_request = extract_echo_request(packet.payload())?;
            let identifier = echo_request.get_identifier();
            let sequence = echo_request.get_sequence_number();
            (identifier, sequence)
        }
        TracerProtocol::Udp => {
            let packet = TimeExceededPacket::new(packet.packet()).req()?;
            let sequence = extract_udp_packet(packet.payload())?;
            (0, sequence)
        }
        TracerProtocol::Tcp => {
            let packet = TimeExceededPacket::new(packet.packet()).req()?;
            let sequence = extract_tcp_packet(packet.payload())?;
            (0, sequence)
        }
    })
}

/// Extract `identifier` and `sequence` from a `DestinationUnreachable` packet.
fn extract_dest_unreachable(
    packet: &DestinationUnreachablePacket<'_>,
    protocol: TracerProtocol,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => {
            let echo_request = extract_echo_request(packet.payload())?;
            let identifier = echo_request.get_identifier();
            let sequence = echo_request.get_sequence_number();
            (identifier, sequence)
        }
        TracerProtocol::Udp => {
            let sequence = extract_udp_packet(packet.payload())?;
            (0, sequence)
        }
        TracerProtocol::Tcp => {
            let sequence = extract_tcp_packet(packet.payload())?;
            (0, sequence)
        }
    })
}

/// Get the original `EchoRequestPacket` packet embedded in the payload.
fn extract_echo_request(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
    let ip4 = Ipv4Packet::new(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_icmp = &payload[header_len..];
    let nested_echo = EchoRequestPacket::new(nested_icmp).req()?;
    Ok(nested_echo)
}

/// Get the original `UdpPacket` packet embedded in the payload.
fn extract_udp_packet(payload: &[u8]) -> TraceResult<u16> {
    let ip4 = Ipv4Packet::new(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_udp = &payload[header_len..];
    let nested = UdpPacket::new(nested_udp).req()?;
    Ok(nested.get_destination())
}

/// Get the original `TcpPacket` packet embedded in the payload.
///
/// Unlike the embedded `ICMP` and `UDP` packets, which have a minimum header size of 8 bytes, the `TCP` packet header
/// is a minimum of 20 bytes.
///
/// The `ICMP` packets we are extracting these from, such as `TimeExceeded`, only guarantee that 8 bytes of the
/// original packet (plus the IP header) be returned and so we may not have a complete TCP packet.
///
/// We therefore have to detect this situation and ensure we provide buffer a large enough for a complete TCP packet
/// header.
fn extract_tcp_packet(payload: &[u8]) -> TraceResult<u16> {
    let ip4 = Ipv4Packet::new(payload).unwrap();
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_tcp = &payload[header_len..];
    if nested_tcp.len() < TcpPacket::minimum_packet_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
        Ok(TcpPacket::new(&buf).req()?.get_source())
    } else {
        Ok(TcpPacket::new(nested_tcp).req()?.get_source())
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
