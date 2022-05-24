use crate::tracing::error::TracerError::{AddressNotAvailable, InvalidSourceAddr};
use crate::tracing::error::{TraceResult, TracerError};
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

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    protocol: TracerProtocol,
    addr_family: TracerAddrFamily,
    src_addr: IpAddr,
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
        let (icmp_tx, icmp_rx) = make_icmp_channel(config.addr_family)?;
        Ok(Self {
            protocol: config.protocol,
            addr_family: config.addr_family,
            src_addr,
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
        match self.addr_family {
            TracerAddrFamily::Ipv4 => ipv4::dispatch_icmp_probe(
                &mut self.icmp_tx,
                probe,
                self.dest_addr,
                self.identifier,
                self.packet_size,
                self.payload_pattern,
            ),
            TracerAddrFamily::Ipv6 => ipv6::dispatch_icmp_probe(
                &mut self.icmp_tx,
                probe,
                self.dest_addr,
                self.identifier,
                self.packet_size,
                self.payload_pattern,
            ),
        }
    }

    /// Dispatch a UDP probe.
    ///
    /// This covers both the IPv4 and IPv6 cases.
    fn dispatch_udp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        let (src_port, dest_port) = match self.port_direction {
            PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
            PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
            PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
        };
        let socket = match self.addr_family {
            TracerAddrFamily::Ipv4 => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)),
            TracerAddrFamily::Ipv6 => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)),
        }?;
        socket.set_nonblocking(true)?;
        let local_addr = SocketAddr::new(self.src_addr, src_port);
        match socket.bind(&SockAddr::from(local_addr)) {
            Ok(_) => {}
            Err(err) => {
                return match err.kind() {
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                        Err(AddressNotAvailable(local_addr))
                    }
                    _ => Err(TracerError::IoError(err)),
                };
            }
        };
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let packet_size = usize::from(self.packet_size.0);
        let payload_size = match self.addr_family {
            TracerAddrFamily::Ipv4 => ipv4::udp_payload_size(packet_size),
            TracerAddrFamily::Ipv6 => ipv6::udp_payload_size(packet_size),
        };
        let mut payload_buf = [0_u8; MAX_PACKET_SIZE];
        payload_buf
            .iter_mut()
            .for_each(|x| *x = self.payload_pattern.0);
        let remote_addr = SocketAddr::new(self.dest_addr, dest_port);
        socket.send_to(&payload_buf[..payload_size], &SockAddr::from(remote_addr))?;
        Ok(())
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
            TracerAddrFamily::Ipv4 => ipv4::recv_icmp_probe(
                &mut self.icmp_rx,
                self.icmp_read_timeout,
                self.protocol,
                self.port_direction,
            ),
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
    use crate::tracing::net::{ProbeResponse, ProbeResponseData, MAX_PACKET_SIZE};
    use crate::tracing::types::{PacketSize, PayloadPattern, TraceId};
    use crate::tracing::util::Required;
    use crate::tracing::{PortDirection, Probe, TracerProtocol};
    use nix::sys::socket::{AddressFamily, SockaddrLike};
    use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
    use pnet::packet::icmp::echo_reply::EchoReplyPacket;
    use pnet::packet::icmp::echo_request::IcmpCodes;
    use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
    use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::util;
    use pnet::packet::Packet;
    use pnet::transport::{
        icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
        TransportReceiver, TransportSender,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    const MAX_ICMP_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();
    const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_BUF - EchoRequestPacket::minimum_packet_size();

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

    pub fn dispatch_icmp_probe(
        icmp_tx: &mut TransportSender,
        probe: Probe,
        dest_addr: IpAddr,
        identifier: TraceId,
        packet_size: PacketSize,
        payload_pattern: PayloadPattern,
    ) -> TraceResult<()> {
        let packet_size = usize::from(packet_size.0);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let icmp_header_size = EchoRequestPacket::minimum_packet_size();
        let mut icmp_buf = [0_u8; MAX_ICMP_BUF];
        let mut payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
        let icmp_buf_size = packet_size - ip_header_size;
        let payload_size = packet_size - icmp_header_size - ip_header_size;
        payload_buf.iter_mut().for_each(|x| *x = payload_pattern.0);
        let mut req = MutableEchoRequestPacket::new(&mut icmp_buf[..icmp_buf_size]).req()?;
        req.set_icmp_type(IcmpTypes::EchoRequest);
        req.set_icmp_code(IcmpCodes::NoCode);
        req.set_identifier(identifier.0);
        req.set_payload(&payload_buf[..payload_size]);
        req.set_sequence_number(probe.sequence.0);
        req.set_checksum(util::checksum(req.packet(), 1));
        icmp_tx.set_ttl(probe.ttl.0)?;
        icmp_tx.send_to(req.to_immutable(), dest_addr)?;
        Ok(())
    }

    pub fn recv_icmp_probe(
        icmp_rx: &mut TransportReceiver,
        icmp_read_timeout: Duration,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<Option<ProbeResponse>> {
        match icmp_packet_iter(icmp_rx).next_with_timeout(icmp_read_timeout)? {
            None => Ok(None),
            Some((icmp, ip)) => Ok(extract_probe_resp_v4(protocol, direction, &icmp, ip)?),
        }
    }

    pub fn udp_payload_size(packet_size: usize) -> usize {
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        packet_size - udp_header_size - ip_header_size
    }

    fn extract_probe_resp_v4(
        protocol: TracerProtocol,
        direction: PortDirection,
        icmp_v4: &IcmpPacket<'_>,
        ip: IpAddr,
    ) -> TraceResult<Option<ProbeResponse>> {
        let recv = SystemTime::now();
        Ok(match icmp_v4.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                let packet = TimeExceededPacket::new(icmp_v4.packet()).req()?;
                let (id, seq) = extract_time_exceeded_v4(&packet, protocol, direction)?;
                Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                    recv, ip, id, seq,
                )))
            }
            IcmpTypes::DestinationUnreachable => {
                let packet = DestinationUnreachablePacket::new(icmp_v4.packet()).req()?;
                let (id, seq) = extract_dest_unreachable_v4(&packet, protocol, direction)?;
                Some(ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, ip, id, seq),
                ))
            }
            IcmpTypes::EchoReply => match protocol {
                TracerProtocol::Icmp => {
                    let packet = EchoReplyPacket::new(icmp_v4.packet()).req()?;
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

    fn extract_time_exceeded_v4(
        packet: &TimeExceededPacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v4(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence_number();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let packet = TimeExceededPacket::new(packet.packet()).req()?;
                let (src, dest) = extract_udp_packet_v4(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let packet = TimeExceededPacket::new(packet.packet()).req()?;
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
                let sequence = echo_request.get_sequence_number();
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
        let ip4 = Ipv4Packet::new(payload).req()?;
        let header_len = usize::from(ip4.get_header_length() * 4);
        let nested_icmp = &payload[header_len..];
        let nested_echo = EchoRequestPacket::new(nested_icmp).req()?;
        Ok(nested_echo)
    }

    /// Get the src and dest ports from the original `UdpPacket` packet embedded in the payload.
    fn extract_udp_packet_v4(payload: &[u8]) -> TraceResult<(u16, u16)> {
        let ip4 = Ipv4Packet::new(payload).req()?;
        let header_len = usize::from(ip4.get_header_length() * 4);
        let nested_udp = &payload[header_len..];
        let nested = UdpPacket::new(nested_udp).req()?;
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
        let ip4 = Ipv4Packet::new(payload).unwrap();
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
}

/// IPv6 implementation.
mod ipv6 {
    use crate::tracing::error::{TraceResult, TracerError};
    use crate::tracing::net::{ProbeResponse, ProbeResponseData, MAX_PACKET_SIZE};
    use crate::tracing::types::{PacketSize, PayloadPattern, TraceId};
    use crate::tracing::util::Required;
    use crate::tracing::{PortDirection, Probe, TracerProtocol};
    use nix::sys::socket::{AddressFamily, SockaddrLike};
    use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
    use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
    use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
    use pnet::packet::icmpv6::echo_request::Icmpv6Codes;
    use pnet::packet::icmpv6::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
    use pnet::packet::icmpv6::Icmpv6Packet;
    use pnet::packet::icmpv6::Icmpv6Types;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::util;
    use pnet::packet::Packet;
    use pnet::transport::{
        icmpv6_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
        TransportReceiver, TransportSender,
    };
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
        let mut req = MutableEchoRequestPacket::new(&mut icmp_buf[..icmp_buf_size]).req()?;
        req.set_icmpv6_type(Icmpv6Types::EchoRequest);
        req.set_icmpv6_code(Icmpv6Codes::NoCode);
        req.set_identifier(identifier.0);
        req.set_payload(&payload_buf[..payload_size]);
        req.set_sequence_number(probe.sequence.0);
        req.set_checksum(util::checksum(req.packet(), 1));
        icmp_tx.set_ttl(probe.ttl.0)?;
        icmp_tx.send_to(req.to_immutable(), dest_addr)?;
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
            Some((icmp, ip)) => Ok(extract_probe_resp_v6(protocol, direction, &icmp, ip)?),
        }
    }

    pub fn udp_payload_size(packet_size: usize) -> usize {
        let ip_header_size = Ipv6Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        packet_size - udp_header_size - ip_header_size
    }

    fn extract_probe_resp_v6(
        protocol: TracerProtocol,
        direction: PortDirection,
        icmp_v6: &Icmpv6Packet<'_>,
        ip: IpAddr,
    ) -> TraceResult<Option<ProbeResponse>> {
        let recv = SystemTime::now();
        Ok(match icmp_v6.get_icmpv6_type() {
            Icmpv6Types::TimeExceeded => {
                let packet = TimeExceededPacket::new(icmp_v6.packet()).req()?;
                let (id, seq) = extract_time_exceeded_v6(&packet, protocol, direction)?;
                Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                    recv, ip, id, seq,
                )))
            }
            Icmpv6Types::DestinationUnreachable => {
                let packet = DestinationUnreachablePacket::new(icmp_v6.packet()).req()?;
                let (id, seq) = extract_dest_unreachable_v6(&packet, protocol, direction)?;
                Some(ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, ip, id, seq),
                ))
            }
            Icmpv6Types::EchoReply => match protocol {
                TracerProtocol::Icmp => {
                    let packet = EchoReplyPacket::new(icmp_v6.packet()).req()?;
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

    fn extract_time_exceeded_v6(
        packet: &TimeExceededPacket<'_>,
        protocol: TracerProtocol,
        direction: PortDirection,
    ) -> TraceResult<(u16, u16)> {
        Ok(match protocol {
            TracerProtocol::Icmp => {
                let echo_request = extract_echo_request_v6(packet.payload())?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence_number();
                (identifier, sequence)
            }
            TracerProtocol::Udp => {
                let packet = TimeExceededPacket::new(packet.packet()).req()?;
                let (src, dest) = extract_udp_packet_v6(packet.payload())?;
                let sequence = match direction {
                    PortDirection::FixedDest(_) => src,
                    _ => dest,
                };
                (0, sequence)
            }
            TracerProtocol::Tcp => {
                let packet = TimeExceededPacket::new(packet.packet()).req()?;
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
                let sequence = echo_request.get_sequence_number();
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
        let ip6 = pnet::packet::ipv6::Ipv6Packet::new(payload).req()?;
        let packet_size = payload.len();
        let payload_size = usize::from(ip6.get_payload_length());
        let header_size = packet_size - payload_size;
        let nested_icmp = &payload[header_size..];
        let nested_echo = EchoRequestPacket::new(nested_icmp).req()?;
        Ok(nested_echo)
    }

    fn extract_udp_packet_v6(payload: &[u8]) -> TraceResult<(u16, u16)> {
        let ip6 = Ipv6Packet::new(payload).req()?;
        let packet_size = payload.len();
        let payload_size = usize::from(ip6.get_payload_length());
        let header_size = packet_size - payload_size;
        let nested = &payload[header_size..];
        let nested_udp = UdpPacket::new(nested).req()?;
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
