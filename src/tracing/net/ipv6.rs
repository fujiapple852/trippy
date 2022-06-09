use crate::tracing::error::TracerError::AddressNotAvailable;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::packet::checksum::{icmp_ipv6_checksum, udp_ipv6_checksum};
use crate::tracing::packet::icmpv6::destination_unreachable::DestinationUnreachablePacket;
use crate::tracing::packet::icmpv6::echo_reply::EchoReplyPacket;
use crate::tracing::packet::icmpv6::echo_request::EchoRequestPacket;
use crate::tracing::packet::icmpv6::time_exceeded::TimeExceededPacket;
use crate::tracing::packet::icmpv6::{IcmpCode, IcmpPacket, IcmpType};
use crate::tracing::packet::ipv6::Ipv6Packet;
use crate::tracing::packet::tcp::TcpPacket;
use crate::tracing::packet::udp::UdpPacket;
use crate::tracing::probe::{ProbeResponse, ProbeResponseData, TcpProbeResponseData};
use crate::tracing::types::{PacketSize, PayloadPattern, Sequence, TraceId};
use crate::tracing::util::Required;
use crate::tracing::{PortDirection, Probe, TracerProtocol};
use nix::sys::socket::{AddressFamily, SockaddrLike};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::SystemTime;

/// The maximum size of UDP packet we allow.
const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of UDP payload we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

/// The maximum size of UDP packet we allow.
const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of ICMP payload we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

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

pub fn make_icmp_send_socket() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn make_udp_send_socket() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn make_recv_socket() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn dispatch_icmp_probe(
    icmp_send_socket: &mut Socket,
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
) -> TraceResult<()> {
    let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let echo_request = make_echo_request_icmp_packet(
        &mut icmp_buf,
        src_addr,
        dest_addr,
        identifier,
        probe.sequence,
        icmp_payload_size(packet_size),
        payload_pattern,
    )?;
    let local_addr = SocketAddr::new(IpAddr::V6(src_addr), 0);
    icmp_send_socket.bind(&SockAddr::from(local_addr))?;
    icmp_send_socket.set_unicast_hops_v6(u32::from(probe.ttl.0))?;
    let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V6(dest_addr), 0));
    icmp_send_socket.send_to(echo_request.packet(), &remote_addr)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn dispatch_udp_probe(
    udp_send_socket: &mut Socket,
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    port_direction: PortDirection,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
) -> TraceResult<()> {
    let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let (src_port, dest_port) = match port_direction {
        PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
        PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
        PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
    };
    let udp = make_udp_packet(
        &mut udp_buf,
        src_addr,
        dest_addr,
        src_port,
        dest_port,
        udp_payload_size(packet_size),
        payload_pattern,
    )?;
    let local_addr = SocketAddr::new(IpAddr::V6(src_addr), src_port);
    udp_send_socket.bind(&SockAddr::from(local_addr))?;
    udp_send_socket.set_unicast_hops_v6(u32::from(probe.ttl.0))?;

    // Note that we set the port to be 0 in the remote `SocketAddr` as the target port is encoded in the `UDP`
    // packet.  If we (redundantly) set the target port here then the send wil fail with `EINVAL`.
    let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V6(dest_addr), 0));
    udp_send_socket.send_to(udp.packet(), &remote_addr)?;
    Ok(())
}

pub fn dispatch_tcp_probe(
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    port_direction: PortDirection,
) -> TraceResult<Socket> {
    let (src_port, dest_port) = match port_direction {
        PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
        PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
        PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
    };
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    let local_addr = SocketAddr::new(IpAddr::V6(src_addr), src_port);
    socket.bind(&SockAddr::from(local_addr))?;
    socket.set_unicast_hops_v6(u32::from(probe.ttl.0))?;
    let remote_addr = SocketAddr::new(IpAddr::V6(dest_addr), dest_port);
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
    Ok(socket)
}

pub fn recv_icmp_probe(
    recv_socket: &mut Socket,
    protocol: TracerProtocol,
    direction: PortDirection,
) -> TraceResult<Option<ProbeResponse>> {
    let mut buf = [0_u8; MAX_PACKET_SIZE];
    match recv_socket.recv_from_into_buf(&mut buf) {
        Ok((_bytes_read, addr)) => {
            let icmp_v6 = IcmpPacket::new_view(&buf).req()?;
            let src_addr = *addr.as_socket_ipv6().req()?.ip();
            Ok(extract_probe_resp(protocol, direction, &icmp_v6, src_addr)?)
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock => Ok(None),
            _ => Err(TracerError::IoError(err)),
        },
    }
}

pub fn recv_tcp_socket(
    tcp_socket: &Socket,
    dest_addr: IpAddr,
) -> TraceResult<Option<ProbeResponse>> {
    let ttl = tcp_socket.unicast_hops_v6()? as u8;
    match tcp_socket.take_error()? {
        None => {
            let addr = tcp_socket.peer_addr()?.as_socket().req()?.ip();
            tcp_socket.shutdown(Shutdown::Both)?;
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
                        dest_addr,
                        ttl,
                    ))));
                }
            }
        }
    };
    Ok(None)
}

/// Create a `UdpPacket`
fn make_udp_packet(
    udp_buf: &mut [u8],
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    src_port: u16,
    dest_port: u16,
    payload_size: usize,
    payload_pattern: PayloadPattern,
) -> TraceResult<UdpPacket<'_>> {
    let udp_payload_buf = [payload_pattern.0; MAX_UDP_PAYLOAD_BUF];
    let udp_packet_size = UdpPacket::minimum_packet_size() + payload_size;
    let mut udp = UdpPacket::new(&mut udp_buf[..udp_packet_size as usize]).req()?;
    udp.set_source(src_port);
    udp.set_destination(dest_port);
    udp.set_length(udp_packet_size as u16);
    udp.set_payload(&udp_payload_buf[..payload_size]);
    udp.set_checksum(udp_ipv6_checksum(udp.packet(), src_addr, dest_addr));
    Ok(udp)
}

/// Create an ICMP `EchoRequest` packet.
fn make_echo_request_icmp_packet(
    icmp_buf: &mut [u8],
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    identifier: TraceId,
    sequence: Sequence,
    payload_size: usize,
    payload_pattern: PayloadPattern,
) -> TraceResult<EchoRequestPacket<'_>> {
    let mut payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
    payload_buf.iter_mut().for_each(|x| *x = payload_pattern.0);
    let packet_size = IcmpPacket::minimum_packet_size() + payload_size;
    let mut icmp = EchoRequestPacket::new(&mut icmp_buf[..packet_size]).req()?;
    icmp.set_icmp_type(IcmpType::EchoRequest);
    icmp.set_icmp_code(IcmpCode(0));
    icmp.set_identifier(identifier.0);
    icmp.set_payload(&payload_buf[..payload_size]);
    icmp.set_sequence(sequence.0);
    icmp.set_checksum(icmp_ipv6_checksum(icmp.packet(), src_addr, dest_addr));
    Ok(icmp)
}

fn icmp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv6Packet::minimum_packet_size();
    let icmp_header_size = IcmpPacket::minimum_packet_size();
    packet_size - icmp_header_size - ip_header_size
}

fn udp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv6Packet::minimum_packet_size();
    let udp_header_size = UdpPacket::minimum_packet_size();
    packet_size - udp_header_size - ip_header_size
}

fn extract_probe_resp(
    protocol: TracerProtocol,
    direction: PortDirection,
    icmp_v6: &IcmpPacket<'_>,
    src: Ipv6Addr,
) -> TraceResult<Option<ProbeResponse>> {
    let recv = SystemTime::now();
    let ip = IpAddr::V6(src);
    Ok(match icmp_v6.get_icmp_type() {
        IcmpType::TimeExceeded => {
            let packet = TimeExceededPacket::new_view(icmp_v6.packet()).req()?;
            let (id, seq) = extract_time_exceeded(&packet, protocol, direction)?;
            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                recv, ip, id, seq,
            )))
        }
        IcmpType::DestinationUnreachable => {
            let packet = DestinationUnreachablePacket::new_view(icmp_v6.packet()).req()?;
            let (id, seq) = extract_dest_unreachable(&packet, protocol, direction)?;
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

fn extract_time_exceeded(
    packet: &TimeExceededPacket<'_>,
    protocol: TracerProtocol,
    direction: PortDirection,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => extract_echo_request(packet.payload())?,
        TracerProtocol::Udp => {
            let (src, dest) = extract_udp_packet(packet.payload())?;
            let sequence = match direction {
                PortDirection::FixedDest(_) => src,
                _ => dest,
            };
            (0, sequence)
        }
        TracerProtocol::Tcp => {
            let (src, dest) = extract_tcp_packet(packet.payload())?;
            let sequence = match direction {
                PortDirection::FixedSrc(_) => dest,
                _ => src,
            };
            (0, sequence)
        }
    })
}

fn extract_dest_unreachable(
    packet: &DestinationUnreachablePacket<'_>,
    protocol: TracerProtocol,
    direction: PortDirection,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => extract_echo_request(packet.payload())?,
        TracerProtocol::Udp => {
            let (src, dest) = extract_udp_packet(packet.payload())?;
            let sequence = match direction {
                PortDirection::FixedDest(_) => src,
                _ => dest,
            };
            (0, sequence)
        }
        TracerProtocol::Tcp => {
            let (src, dest) = extract_tcp_packet(packet.payload())?;
            let sequence = match direction {
                PortDirection::FixedSrc(_) => dest,
                _ => src,
            };
            (0, sequence)
        }
    })
}

fn extract_echo_request(ipv6_bytes: &[u8]) -> TraceResult<(u16, u16)> {
    let ipv6 = Ipv6Packet::new_view(ipv6_bytes).req()?;
    let echo_request_packet = EchoRequestPacket::new_view(ipv6.payload()).req()?;
    Ok((
        echo_request_packet.get_identifier(),
        echo_request_packet.get_sequence(),
    ))
}

fn extract_udp_packet(ipv6_bytes: &[u8]) -> TraceResult<(u16, u16)> {
    let ipv6 = Ipv6Packet::new_view(ipv6_bytes).req()?;
    let udp_packet = UdpPacket::new_view(ipv6.payload()).req()?;
    Ok((udp_packet.get_source(), udp_packet.get_destination()))
}

fn extract_tcp_packet(ipv6_bytes: &[u8]) -> TraceResult<(u16, u16)> {
    // let ip6 = Ipv6Packet::new_view(payload).req()?;
    // let header_len = usize::from(ip6.get_payload_length() * 4);
    // let nested_tcp = &payload[header_len..];

    let ipv6 = Ipv6Packet::new_view(ipv6_bytes).req()?;
    let tcp_packet = TcpPacket::new_view(ipv6.payload()).req()?;
    Ok((tcp_packet.get_source(), tcp_packet.get_destination()))

    // if nested_tcp.len() < TcpPacket::minimum_packet_size() {
    //     let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
    //     buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
    //     let tcp_packet = TcpPacket::new_view(&buf).req()?;
    //     Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    // } else {
    //     let tcp_packet = TcpPacket::new_view(nested_tcp).req()?;
    //     Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    // }
}

/// An extension trait to allow `recv_from` method which writes to a `&mut [u8]`.
///
/// This is required for `socket2::Socket` which [does not currently provide] this method.
///
/// [does not currently provide]: https://github.com/rust-lang/socket2/issues/223
trait RecvFrom {
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)>;
}

impl RecvFrom for Socket {
    // Safety: the `recv` implementation promises not to write uninitialised
    // bytes to the `buf`fer, so this casting is safe.
    #![allow(unsafe_code)]
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)> {
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
        self.recv_from(buf)
    }
}
