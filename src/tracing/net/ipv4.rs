use crate::tracing::error::TracerError::AddressNotAvailable;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::platform;
use crate::tracing::net::platform::PlatformIpv4FieldByteOrder;
use crate::tracing::packet::checksum::{icmp_ipv4_checksum, udp_ipv4_checksum};
use crate::tracing::packet::icmpv4::destination_unreachable::DestinationUnreachablePacket;
use crate::tracing::packet::icmpv4::echo_reply::EchoReplyPacket;
use crate::tracing::packet::icmpv4::echo_request::EchoRequestPacket;
use crate::tracing::packet::icmpv4::time_exceeded::TimeExceededPacket;
use crate::tracing::packet::icmpv4::{IcmpCode, IcmpPacket, IcmpType};
use crate::tracing::packet::ipv4::Ipv4Packet;
use crate::tracing::packet::tcp::TcpPacket;
use crate::tracing::packet::udp::UdpPacket;
use crate::tracing::packet::IpProtocol;
use crate::tracing::probe::{ProbeResponse, ProbeResponseData, TcpProbeResponseData};
use crate::tracing::types::{PacketSize, PayloadPattern, Sequence, TraceId, TypeOfService};
use crate::tracing::util::Required;
use crate::tracing::{MultipathStrategy, PortDirection, Probe, TracerProtocol};
#[cfg(not(windows))]
use socket2::{SockAddr, Socket};
use std::io::{Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::time::SystemTime;
#[cfg(windows)]
use windows::Win32::Networking::WinSock::{sendto, SOCKET};

#[cfg(windows)]
type Socket = SOCKET;

/// The maximum size of UDP packet we allow.
const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum size of UDP payload we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

/// The maximum size of ICMP packet we allow.
const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum size of ICMP payload we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

/// The value for the IPv4 `flags_and_fragment_offset` field to set the `Don't fragment` bit.
///
/// 0100 0000 0000 0000
const DONT_FRAGMENT: u16 = 0x4000;

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_icmp_probe(
    icmp_send_socket: &mut Socket,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    ipv4_byte_order: PlatformIpv4FieldByteOrder,
) -> TraceResult<()> {
    let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
    let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let echo_request = make_echo_request_icmp_packet(
        &mut icmp_buf,
        identifier,
        probe.sequence,
        icmp_payload_size(packet_size),
        payload_pattern,
    )?;
    let ipv4 = make_ipv4_packet(
        &mut ipv4_buf,
        ipv4_byte_order,
        IpProtocol::Icmp,
        src_addr,
        dest_addr,
        probe.ttl.0,
        0,
        echo_request.packet(),
    )?;
    let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dest_addr), 0));
    icmp_send_socket.send_to(ipv4.packet(), &remote_addr)?;
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
#[allow(unsafe_code)]
pub fn dispatch_icmp_probe(
    icmp_send_socket: &mut Socket,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    ipv4_byte_order: PlatformIpv4FieldByteOrder,
) -> TraceResult<()> {
    use windows::Win32::Networking::WinSock::SOCKET_ERROR;

    let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
    let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let echo_request = make_echo_request_icmp_packet(
        &mut icmp_buf,
        identifier,
        probe.sequence,
        icmp_payload_size(packet_size),
        payload_pattern,
    )?;
    let ipv4 = make_ipv4_packet(
        &mut ipv4_buf,
        ipv4_byte_order,
        IpProtocol::Icmp,
        src_addr,
        dest_addr,
        probe.ttl.0,
        0,
        echo_request.packet(),
    )?;
    // let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dest_addr), 0));
    let (addr, addrlen) = platform::ipaddr_to_sockaddr(IpAddr::V4(dest_addr));
    #[allow(clippy::cast_possible_wrap)]
    let rc = unsafe {
        sendto(
            *icmp_send_socket,
            ipv4.packet(),
            packet_size as i32,
            std::ptr::addr_of!(addr).cast(),
            addrlen as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(TracerError::IoError(Error::last_os_error()));
    };
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_udp_probe(
    raw_send_socket: &mut Socket,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    initial_sequence: Sequence,
    multipath_strategy: MultipathStrategy,
    port_direction: PortDirection,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    ipv4_byte_order: PlatformIpv4FieldByteOrder,
) -> TraceResult<()> {
    let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
    let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let (src_port, dest_port, identifier) = match multipath_strategy {
        MultipathStrategy::Classic => match port_direction {
            PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0, 0),
            PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0, 0),
            PortDirection::FixedBoth(_, _) | PortDirection::None => {
                unimplemented!()
            }
        },
        MultipathStrategy::Paris => unimplemented!(),
        MultipathStrategy::Dublin => {
            let round_port =
                ((initial_sequence.0 as usize + probe.round.0) % usize::from(u16::MAX)) as u16;
            match port_direction {
                PortDirection::FixedSrc(src_port) => (src_port.0, round_port, probe.sequence.0),
                PortDirection::FixedDest(dest_port) => (round_port, dest_port.0, probe.sequence.0),
                PortDirection::FixedBoth(src_port, dest_port) => {
                    (src_port.0, dest_port.0, probe.sequence.0)
                }
                PortDirection::None => unimplemented!(),
            }
        }
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
    let ipv4 = make_ipv4_packet(
        &mut ipv4_buf,
        ipv4_byte_order,
        IpProtocol::Udp,
        src_addr,
        dest_addr,
        probe.ttl.0,
        identifier,
        udp.packet(),
    )?;
    let remote_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(dest_addr), dest_port));
    raw_send_socket.send_to(ipv4.packet(), &remote_addr)?;
    Ok(())
}

#[cfg(unix)]
pub fn dispatch_tcp_probe(
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    port_direction: PortDirection,
    tos: TypeOfService,
) -> TraceResult<Socket> {
    let (src_port, dest_port) = match port_direction {
        PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
        PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
        PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
    };
    let socket = platform::make_stream_socket_ipv4()?;
    let local_addr = SocketAddr::new(IpAddr::V4(src_addr), src_port);
    socket.bind(&SockAddr::from(local_addr))?;
    socket.set_ttl(u32::from(probe.ttl.0))?;
    socket.set_tos(u32::from(tos.0))?;
    let remote_addr = SocketAddr::new(IpAddr::V4(dest_addr), dest_port);
    match socket.connect(&SockAddr::from(remote_addr)) {
        Ok(_) => {}
        Err(err) => {
            if let Some(code) = err.raw_os_error() {
                if platform::is_not_in_progress_error(code) {
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

#[cfg(unix)]
pub fn recv_icmp_probe(
    recv_socket: &mut Socket,
    protocol: TracerProtocol,
    multipath_strategy: MultipathStrategy,
    direction: PortDirection,
) -> TraceResult<Option<ProbeResponse>> {
    let mut buf = [0_u8; MAX_PACKET_SIZE];
    match recv_socket.read(&mut buf) {
        Ok(_bytes_read) => {
            let ipv4 = Ipv4Packet::new_view(&buf).req()?;
            Ok(extract_probe_resp(
                protocol,
                multipath_strategy,
                direction,
                &ipv4,
            )?)
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock => Ok(None),
            _ => Err(TracerError::IoError(err)),
        },
    }
}

#[cfg(unix)]
pub fn recv_tcp_socket(
    tcp_socket: &Socket,
    dest_addr: IpAddr,
) -> TraceResult<Option<ProbeResponse>> {
    let ttl = tcp_socket.ttl()? as u8;
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
                if platform::is_conn_refused_error(code) {
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

/// Create an ICMP `EchoRequest` packet.
fn make_echo_request_icmp_packet(
    icmp_buf: &mut [u8],
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
    icmp.set_checksum(icmp_ipv4_checksum(icmp.packet()));
    Ok(icmp)
}

/// Create a `UdpPacket`
fn make_udp_packet(
    udp_buf: &mut [u8],
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload_size: usize,
    payload_pattern: PayloadPattern,
) -> TraceResult<UdpPacket<'_>> {
    let udp_payload_buf = [payload_pattern.0; MAX_UDP_PAYLOAD_BUF];
    let udp_packet_size = UdpPacket::minimum_packet_size() + payload_size;
    let mut udp = UdpPacket::new(&mut udp_buf[..udp_packet_size]).req()?;
    udp.set_source(src_port);
    udp.set_destination(dest_port);
    udp.set_length(udp_packet_size as u16);
    udp.set_payload(&udp_payload_buf[..payload_size]);
    udp.set_checksum(udp_ipv4_checksum(udp.packet(), src_addr, dest_addr));
    Ok(udp)
}

/// Create an `Ipv4Packet`.
#[allow(clippy::too_many_arguments)]
fn make_ipv4_packet<'a>(
    ipv4_buf: &'a mut [u8],
    ipv4_byte_order: PlatformIpv4FieldByteOrder,
    protocol: IpProtocol,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    ttl: u8,
    identification: u16,
    payload: &[u8],
) -> TraceResult<Ipv4Packet<'a>> {
    let ipv4_total_length = (Ipv4Packet::minimum_packet_size() + payload.len()) as u16;
    let ipv4_total_length_header = ipv4_byte_order.adjust_length(ipv4_total_length);
    let ipv4_flags_and_fragment_offset_header = ipv4_byte_order.adjust_length(DONT_FRAGMENT);
    let mut ipv4 = Ipv4Packet::new(&mut ipv4_buf[..ipv4_total_length as usize]).req()?;
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_total_length(ipv4_total_length_header);
    ipv4.set_ttl(ttl);
    ipv4.set_protocol(protocol);
    ipv4.set_source(src_addr);
    ipv4.set_destination(dest_addr);
    ipv4.set_payload(payload);
    ipv4.set_identification(identification);
    ipv4.set_flags_and_fragment_offset(ipv4_flags_and_fragment_offset_header);
    Ok(ipv4)
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

fn extract_probe_resp(
    protocol: TracerProtocol,
    multipath_strategy: MultipathStrategy,
    direction: PortDirection,
    ipv4: &Ipv4Packet<'_>,
) -> TraceResult<Option<ProbeResponse>> {
    let recv = SystemTime::now();
    let src = IpAddr::V4(ipv4.get_source());
    let icmp_v4 = IcmpPacket::new_view(ipv4.payload()).req()?;
    Ok(match icmp_v4.get_icmp_type() {
        IcmpType::TimeExceeded => {
            let packet = TimeExceededPacket::new_view(icmp_v4.packet()).req()?;
            let (id, seq) =
                extract_time_exceeded(&packet, protocol, multipath_strategy, direction)?;
            Some(ProbeResponse::TimeExceeded(ProbeResponseData::new(
                recv, src, id, seq,
            )))
        }
        IcmpType::DestinationUnreachable => {
            let packet = DestinationUnreachablePacket::new_view(icmp_v4.packet()).req()?;
            let (id, seq) =
                extract_dest_unreachable(&packet, protocol, multipath_strategy, direction)?;
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

fn extract_time_exceeded(
    packet: &TimeExceededPacket<'_>,
    protocol: TracerProtocol,
    multipath_strategy: MultipathStrategy,
    direction: PortDirection,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => {
            let echo_request = extract_echo_request(packet.payload())?;
            let identifier = echo_request.get_identifier();
            let sequence = echo_request.get_sequence();
            (identifier, sequence)
        }
        TracerProtocol::Udp => {
            let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
            let (src, dest, checksum, id) = extract_udp_packet(packet.payload())?;
            let sequence = match (multipath_strategy, direction) {
                (MultipathStrategy::Classic, PortDirection::FixedDest(_)) => src,
                (MultipathStrategy::Classic, _) => dest,
                (MultipathStrategy::Paris, _) => checksum,
                (MultipathStrategy::Dublin, _) => id,
            };
            (0, sequence)
        }
        TracerProtocol::Tcp => {
            let packet = TimeExceededPacket::new_view(packet.packet()).req()?;
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
    multipath_strategy: MultipathStrategy,
    direction: PortDirection,
) -> TraceResult<(u16, u16)> {
    Ok(match protocol {
        TracerProtocol::Icmp => {
            let echo_request = extract_echo_request(packet.payload())?;
            let identifier = echo_request.get_identifier();
            let sequence = echo_request.get_sequence();
            (identifier, sequence)
        }
        TracerProtocol::Udp => {
            let (src, dest, checksum, id) = extract_udp_packet(packet.payload())?;
            let sequence = match (multipath_strategy, direction) {
                (MultipathStrategy::Classic, PortDirection::FixedDest(_)) => src,
                (MultipathStrategy::Classic, _) => dest,
                (MultipathStrategy::Paris, _) => checksum,
                (MultipathStrategy::Dublin, _) => id,
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

fn extract_echo_request(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
    let ip4 = Ipv4Packet::new_view(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_icmp = &payload[header_len..];
    let nested_echo = EchoRequestPacket::new_view(nested_icmp).req()?;
    Ok(nested_echo)
}

/// Get the src and dest ports from the original `UdpPacket` packet embedded in the payload.
fn extract_udp_packet(payload: &[u8]) -> TraceResult<(u16, u16, u16, u16)> {
    let ip4 = Ipv4Packet::new_view(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_udp = &payload[header_len..];
    let nested = UdpPacket::new_view(nested_udp).req()?;
    Ok((
        nested.get_source(),
        nested.get_destination(),
        nested.get_checksum(),
        ip4.get_identification(),
    ))
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
fn extract_tcp_packet(payload: &[u8]) -> TraceResult<(u16, u16)> {
    let ip4 = Ipv4Packet::new_view(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_tcp = &payload[header_len..];
    if nested_tcp.len() < TcpPacket::minimum_packet_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
        let tcp_packet = TcpPacket::new_view(&buf).req()?;
        Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    } else {
        let tcp_packet = TcpPacket::new_view(nested_tcp).req()?;
        Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    }
}
