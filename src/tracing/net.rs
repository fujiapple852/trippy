use crate::tracing::error::TracerError::AddressNotAvailable;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::types::{DestinationPort, PacketSize, PayloadPattern, SourcePort, TraceId};
use crate::tracing::util::Required;
use crate::tracing::{Probe, TracerConfig};
use arrayvec::ArrayVec;
use itertools::Itertools;
use nix::sys::select::FdSet;
use nix::sys::time::{TimeVal, TimeValLike};
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{echo_request, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
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

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send an `ICMP` `Probe`
    fn send_icmp_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Send a `UDP` `Probe`.
    fn send_udp_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Send a `TCP` `Probe`.
    fn send_tcp_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a ICMP probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe_resp_icmp(&mut self) -> TraceResult<Option<ProbeResponse>>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a `Udp` probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe_resp_udp(&mut self) -> TraceResult<Option<ProbeResponse>>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a `Tcp` probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe_resp_tcp(&mut self) -> TraceResult<Option<ProbeResponse>>;
}

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    src_addr: IpAddr,
    dest_addr: IpAddr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    source_port: SourcePort,
    destination_port: DestinationPort,
    icmp_read_timeout: Duration,
    tcp_connect_timeout: Duration,
    icmp_tx: TransportSender,
    icmp_rx: TransportReceiver,
    udp_tx: TransportSender,
    tcp_probes: ArrayVec<TcpProbe, MAX_TCP_PROBES>,
}

impl TracerChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    pub fn new(config: &TracerConfig) -> TraceResult<Self> {
        let src_addr = discover_ipv4_addr(config.target_addr, config.destination_port.0)?;
        let (icmp_tx, icmp_rx) = make_icmp_channel()?;
        let (udp_tx, _) = make_udp_channel()?;
        Ok(Self {
            src_addr,
            dest_addr: config.target_addr,
            identifier: config.trace_identifier,
            packet_size: config.packet_size,
            payload_pattern: config.payload_pattern,
            source_port: config.source_port,
            destination_port: config.destination_port,
            icmp_read_timeout: config.read_timeout,
            tcp_connect_timeout: config.min_round_duration,
            icmp_tx,
            icmp_rx,
            udp_tx,
            tcp_probes: ArrayVec::new(),
        })
    }
}

impl Network for TracerChannel {
    fn send_icmp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        self.dispatch_icmp_probe(probe)
    }

    fn send_udp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        self.dispatch_udp_probe(probe)
    }

    fn send_tcp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        self.dispatch_tcp_probe(probe)
    }

    fn recv_probe_resp_icmp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        self.handle_icmp_socket_for_icmp()
    }

    fn recv_probe_resp_udp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        self.handle_icmp_socket_for_udp()
    }

    fn recv_probe_resp_tcp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        Ok(self
            .handle_tcp_socket()?
            .or(self.handle_icmp_socket_for_tcp()?))
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
        let packet_size = usize::from(self.packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        let mut udp_buf = [0_u8; MAX_UDP_BUF];
        let mut payload_buf = [0_u8; MAX_UDP_PAYLOAD_BUF];
        let udp_buf_size = packet_size - ip_header_size;
        let mut udp = MutableUdpPacket::new(&mut udp_buf[..udp_buf_size]).req()?;
        udp.set_source(self.source_port.0);
        udp.set_destination(probe.sequence.0);
        let payload_size = packet_size - udp_header_size - ip_header_size;
        udp.set_length((UdpPacket::minimum_packet_size() + payload_size) as u16);
        payload_buf
            .iter_mut()
            .for_each(|x| *x = self.payload_pattern.0);
        udp.set_payload(&payload_buf[..payload_size]);
        self.udp_tx.set_ttl(probe.ttl.0)?;
        self.udp_tx.send_to(udp.to_immutable(), self.dest_addr)?;
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

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any (ICMP protocol).
    pub fn handle_icmp_socket_for_icmp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(self.icmp_read_timeout)? {
                Some((icmp, ip)) => {
                    let recv = SystemTime::now();
                    match icmp.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            let packet = TimeExceededPacket::new(icmp.packet()).req()?;
                            let echo_request = extract_echo_request(packet.payload())?;
                            let identifier = echo_request.get_identifier();
                            let sequence = echo_request.get_sequence_number();
                            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                                recv, ip, identifier, sequence,
                            )))
                        }
                        IcmpTypes::DestinationUnreachable => {
                            let packet = DestinationUnreachablePacket::new(icmp.packet()).req()?;
                            let echo_request = extract_echo_request(packet.payload())?;
                            let identifier = echo_request.get_identifier();
                            let sequence = echo_request.get_sequence_number();
                            Some(ProbeResponse::DestinationUnreachable(
                                ProbeResponseData::new(recv, ip, identifier, sequence),
                            ))
                        }
                        IcmpTypes::EchoReply => {
                            let packet = EchoReplyPacket::new(icmp.packet()).req()?;
                            let identifier = packet.get_identifier();
                            let sequence = packet.get_sequence_number();
                            Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                                recv, ip, identifier, sequence,
                            )))
                        }
                        _ => None,
                    }
                }
                None => None,
            },
        )
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any (UDP protocol).
    pub fn handle_icmp_socket_for_udp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(self.icmp_read_timeout)? {
                Some((icmp, ip)) => {
                    let recv = SystemTime::now();
                    match icmp.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            let packet = TimeExceededPacket::new(icmp.packet()).req()?;
                            let sequence = extract_udp_probe(packet.payload())?;
                            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                                recv, ip, 0, sequence,
                            )))
                        }
                        IcmpTypes::DestinationUnreachable => {
                            let packet = DestinationUnreachablePacket::new(icmp.packet()).req()?;
                            let sequence = extract_udp_probe(packet.payload())?;
                            Some(ProbeResponse::DestinationUnreachable(
                                ProbeResponseData::new(recv, ip, 0, sequence),
                            ))
                        }
                        _ => None,
                    }
                }
                None => None,
            },
        )
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any (TCP protocol).
    pub fn handle_icmp_socket_for_tcp(&mut self) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(self.icmp_read_timeout)? {
                Some((icmp, ip)) => {
                    let recv = SystemTime::now();
                    match icmp.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            let packet = TimeExceededPacket::new(icmp.packet()).req()?;
                            let sequence = extract_tcp_probe(packet.payload())?;
                            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                                recv, ip, 0, sequence,
                            )))
                        }
                        IcmpTypes::DestinationUnreachable => {
                            let packet = DestinationUnreachablePacket::new(icmp.packet()).req()?;
                            let sequence = extract_tcp_probe(packet.payload())?;
                            Some(ProbeResponse::DestinationUnreachable(
                                ProbeResponseData::new(recv, ip, 0, sequence),
                            ))
                        }
                        _ => None,
                    }
                }
                None => None,
            },
        )
    }

    /// Generate synthetic `ProbeResponse` if a TCP socket is connected or if the connection was refused.
    ///
    /// Any TCP socket which has not connected or failed after a timeout wil be removed.
    pub fn handle_tcp_socket(&mut self) -> TraceResult<Option<ProbeResponse>> {
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
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
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

/// The response to a probe.
#[derive(Debug, Copy, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData),
    DestinationUnreachable(ProbeResponseData),
    EchoReply(ProbeResponseData),
    TcpReply(TcpProbeResponseData),
    TcpRefused(TcpProbeResponseData),
}

/// The data in probe response.
#[derive(Debug, Copy, Clone)]
pub struct ProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
}

impl ProbeResponseData {
    pub fn new(recv: SystemTime, addr: IpAddr, identifier: u16, sequence: u16) -> Self {
        Self {
            recv,
            addr,
            identifier,
            sequence,
        }
    }
}

///
#[derive(Debug, Copy, Clone)]
pub struct TcpProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub ttl: u8,
}

impl TcpProbeResponseData {
    pub fn new(recv: SystemTime, addr: IpAddr, ttl: u8) -> Self {
        Self { recv, addr, ttl }
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

/// Create the communication channel needed for sending and receiving ICMP packets.
fn make_icmp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
}

/// Create the communication channel needed for sending UDP packets.
fn make_udp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
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
fn extract_udp_probe(payload: &[u8]) -> TraceResult<u16> {
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
fn extract_tcp_probe(payload: &[u8]) -> TraceResult<u16> {
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
