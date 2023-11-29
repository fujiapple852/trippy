use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::common::process_result;
use crate::tracing::net::platform;
use crate::tracing::net::socket::Socket;
use crate::tracing::packet::checksum::{icmp_ipv6_checksum, udp_ipv6_checksum};
use crate::tracing::packet::icmpv6::destination_unreachable::DestinationUnreachablePacket;
use crate::tracing::packet::icmpv6::echo_reply::EchoReplyPacket;
use crate::tracing::packet::icmpv6::echo_request::EchoRequestPacket;
use crate::tracing::packet::icmpv6::time_exceeded::TimeExceededPacket;
use crate::tracing::packet::icmpv6::{IcmpCode, IcmpPacket, IcmpType};
use crate::tracing::packet::ipv6::Ipv6Packet;
use crate::tracing::packet::tcp::TcpPacket;
use crate::tracing::packet::udp::UdpPacket;
use crate::tracing::packet::IpProtocol;
use crate::tracing::probe::{
    Extensions, ProbeResponse, ProbeResponseData, ProbeResponseSeq, ProbeResponseSeqIcmp,
    ProbeResponseSeqTcp, ProbeResponseSeqUdp,
};
use crate::tracing::types::{PacketSize, PayloadPattern, Sequence, TraceId};
use crate::tracing::{MultipathStrategy, PrivilegeMode, Probe, TracerProtocol};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;
use tracing::instrument;

/// The maximum size of UDP packet we allow.
const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of UDP payload we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

/// The maximum size of UDP packet we allow.
const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of ICMP payload we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

#[instrument(skip(icmp_send_socket, probe))]
pub fn dispatch_icmp_probe<S: Socket>(
    icmp_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
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
        probe.identifier,
        probe.sequence,
        icmp_payload_size(packet_size),
        payload_pattern,
    )?;
    icmp_send_socket.set_unicast_hops_v6(probe.ttl.0)?;
    let remote_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);
    icmp_send_socket.send_to(echo_request.packet(), remote_addr)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip(raw_send_socket, probe))]
pub fn dispatch_udp_probe<S: Socket>(
    raw_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    privilege_mode: PrivilegeMode,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    multipath_strategy: MultipathStrategy,
) -> TraceResult<()> {
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let payload_size = udp_payload_size(packet_size);
    let payload = &[payload_pattern.0; MAX_UDP_PAYLOAD_BUF][0..payload_size];
    match privilege_mode {
        PrivilegeMode::Privileged => dispatch_udp_probe_raw(
            raw_send_socket,
            probe,
            src_addr,
            dest_addr,
            payload,
            multipath_strategy,
        ),
        PrivilegeMode::Unprivileged => {
            dispatch_udp_probe_non_raw::<S>(probe, src_addr, dest_addr, payload)
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip(udp_send_socket, probe))]
fn dispatch_udp_probe_raw<S: Socket>(
    udp_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    payload: &[u8],
    multipath_strategy: MultipathStrategy,
) -> TraceResult<()> {
    let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
    let payload_paris = probe.sequence.0.to_be_bytes();
    let payload = if multipath_strategy == MultipathStrategy::Paris {
        payload_paris.as_slice()
    } else {
        payload
    };
    let mut udp = make_udp_packet(
        &mut udp_buf,
        src_addr,
        dest_addr,
        probe.src_port.0,
        probe.dest_port.0,
        payload,
    )?;
    if multipath_strategy == MultipathStrategy::Paris {
        let checksum = udp.get_checksum().to_be_bytes();
        let payload = u16::from_be_bytes(core::array::from_fn(|i| udp.payload()[i]));
        udp.set_checksum(payload);
        udp.set_payload(&checksum);
    }
    udp_send_socket.set_unicast_hops_v6(probe.ttl.0)?;
    // Note that we set the port to be 0 in the remote `SocketAddr` as the target port is encoded in
    // the `UDP` packet.  If we (redundantly) set the target port here then the send will fail
    // with `EINVAL`.
    let remote_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);
    udp_send_socket.send_to(udp.packet(), remote_addr)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip(probe))]
fn dispatch_udp_probe_non_raw<S: Socket>(
    probe: Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    payload: &[u8],
) -> TraceResult<()> {
    let local_addr = SocketAddr::new(IpAddr::V6(src_addr), probe.src_port.0);
    let remote_addr = SocketAddr::new(IpAddr::V6(dest_addr), probe.dest_port.0);
    let mut socket = S::new_udp_send_socket_ipv6(false)?;
    process_result(local_addr, socket.bind(local_addr))?;
    socket.set_unicast_hops_v6(probe.ttl.0)?;
    socket.send_to(payload, remote_addr)?;
    Ok(())
}

#[instrument(skip(probe))]
pub fn dispatch_tcp_probe<S: Socket>(
    probe: &Probe,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
) -> TraceResult<S> {
    let mut socket = S::new_stream_socket_ipv6()?;
    let local_addr = SocketAddr::new(IpAddr::V6(src_addr), probe.src_port.0);
    process_result(local_addr, socket.bind(local_addr))?;
    socket.set_unicast_hops_v6(probe.ttl.0)?;
    let remote_addr = SocketAddr::new(IpAddr::V6(dest_addr), probe.dest_port.0);
    process_result(remote_addr, socket.connect(remote_addr))?;
    Ok(socket)
}

#[instrument(skip(recv_socket))]
pub fn recv_icmp_probe<S: Socket>(
    recv_socket: &mut S,
    protocol: TracerProtocol,
    icmp_extensions: bool,
) -> TraceResult<Option<ProbeResponse>> {
    let mut buf = [0_u8; MAX_PACKET_SIZE];
    match recv_socket.recv_from(&mut buf) {
        Ok((bytes_read, addr)) => {
            let icmp_v6 = IcmpPacket::new_view(&buf[..bytes_read])?;
            let src_addr = match addr.as_ref().ok_or(TracerError::MissingAddr)? {
                SocketAddr::V6(addr) => addr.ip(),
                SocketAddr::V4(_) => panic!(),
            };
            Ok(extract_probe_resp(
                protocol,
                icmp_extensions,
                &icmp_v6,
                *src_addr,
            )?)
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock => Ok(None),
            _ => Err(TracerError::IoError(err)),
        },
    }
}

#[instrument(skip(tcp_socket))]
pub fn recv_tcp_socket<S: Socket>(
    tcp_socket: &mut S,
    sequence: Sequence,
    dest_addr: IpAddr,
) -> TraceResult<Option<ProbeResponse>> {
    let resp_seq = ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp::new(0, sequence.0));
    match tcp_socket.take_error()? {
        None => {
            let addr = tcp_socket
                .peer_addr()?
                .ok_or(TracerError::MissingAddr)?
                .ip();
            tcp_socket.shutdown()?;
            return Ok(Some(ProbeResponse::TcpReply(ProbeResponseData::new(
                SystemTime::now(),
                addr,
                resp_seq,
            ))));
        }
        Some(err) => {
            if let Some(code) = err.raw_os_error() {
                if platform::is_conn_refused_error(code) {
                    return Ok(Some(ProbeResponse::TcpRefused(ProbeResponseData::new(
                        SystemTime::now(),
                        dest_addr,
                        resp_seq,
                    ))));
                }
                if platform::is_host_unreachable_error(code) {
                    let error_addr = tcp_socket.icmp_error_info()?;
                    return Ok(Some(ProbeResponse::TimeExceeded(
                        ProbeResponseData::new(SystemTime::now(), error_addr, resp_seq),
                        None,
                    )));
                }
            }
        }
    };
    Ok(None)
}

/// Create a `UdpPacket`
fn make_udp_packet<'a>(
    udp_buf: &'a mut [u8],
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    src_port: u16,
    dest_port: u16,
    payload: &'_ [u8],
) -> TraceResult<UdpPacket<'a>> {
    let udp_packet_size = UdpPacket::minimum_packet_size() + payload.len();
    let mut udp = UdpPacket::new(&mut udp_buf[..udp_packet_size])?;
    udp.set_source(src_port);
    udp.set_destination(dest_port);
    udp.set_length(udp_packet_size as u16);
    udp.set_payload(payload);
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
    let payload_buf = [payload_pattern.0; MAX_ICMP_PAYLOAD_BUF];
    let packet_size = IcmpPacket::minimum_packet_size() + payload_size;
    let mut icmp = EchoRequestPacket::new(&mut icmp_buf[..packet_size])?;
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
    icmp_extensions: bool,
    icmp_v6: &IcmpPacket<'_>,
    src: Ipv6Addr,
) -> TraceResult<Option<ProbeResponse>> {
    let recv = SystemTime::now();
    let ip = IpAddr::V6(src);
    Ok(match icmp_v6.get_icmp_type() {
        IcmpType::TimeExceeded => {
            let packet = TimeExceededPacket::new_view(icmp_v6.packet())?;
            let (nested_ipv6, extension) = if icmp_extensions {
                let ipv6 = Ipv6Packet::new_view(packet.payload())?;
                let ext = packet.extension().map(Extensions::try_from).transpose()?;
                (ipv6, ext)
            } else {
                let ipv6 = Ipv6Packet::new_view(packet.payload_raw())?;
                (ipv6, None)
            };
            extract_probe_resp_seq(&nested_ipv6, protocol)?.map(|resp_seq| {
                ProbeResponse::TimeExceeded(ProbeResponseData::new(recv, ip, resp_seq), extension)
            })
        }
        IcmpType::DestinationUnreachable => {
            let packet = DestinationUnreachablePacket::new_view(icmp_v6.packet())?;
            let nested_ipv6 = Ipv6Packet::new_view(packet.payload())?;
            let extension = if icmp_extensions {
                packet.extension().map(Extensions::try_from).transpose()?
            } else {
                None
            };
            extract_probe_resp_seq(&nested_ipv6, protocol)?.map(|resp_seq| {
                ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, ip, resp_seq),
                    extension,
                )
            })
        }
        IcmpType::EchoReply => match protocol {
            TracerProtocol::Icmp => {
                let packet = EchoReplyPacket::new_view(icmp_v6.packet())?;
                let id = packet.get_identifier();
                let seq = packet.get_sequence();
                let resp_seq = ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp::new(id, seq));
                Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                    recv, ip, resp_seq,
                )))
            }
            TracerProtocol::Udp | TracerProtocol::Tcp => None,
        },
        _ => None,
    })
}

fn extract_probe_resp_seq(
    ipv6: &Ipv6Packet<'_>,
    protocol: TracerProtocol,
) -> TraceResult<Option<ProbeResponseSeq>> {
    Ok(match (protocol, ipv6.get_next_header()) {
        (TracerProtocol::Icmp, IpProtocol::IcmpV6) => {
            let (identifier, sequence) = extract_echo_request(ipv6)?;
            Some(ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp::new(
                identifier, sequence,
            )))
        }
        (TracerProtocol::Udp, IpProtocol::Udp) => {
            let (src_port, dest_port, checksum) = extract_udp_packet(ipv6)?;
            Some(ProbeResponseSeq::Udp(ProbeResponseSeqUdp::new(
                0, src_port, dest_port, checksum,
            )))
        }
        (TracerProtocol::Tcp, IpProtocol::Tcp) => {
            let (src_port, dest_port) = extract_tcp_packet(ipv6)?;
            Some(ProbeResponseSeq::Tcp(ProbeResponseSeqTcp::new(
                src_port, dest_port,
            )))
        }
        _ => None,
    })
}

fn extract_echo_request(ipv6: &Ipv6Packet<'_>) -> TraceResult<(u16, u16)> {
    let echo_request_packet = EchoRequestPacket::new_view(ipv6.payload())?;
    Ok((
        echo_request_packet.get_identifier(),
        echo_request_packet.get_sequence(),
    ))
}

fn extract_udp_packet(ipv6: &Ipv6Packet<'_>) -> TraceResult<(u16, u16, u16)> {
    let udp_packet = UdpPacket::new_view(ipv6.payload())?;
    Ok((
        udp_packet.get_source(),
        udp_packet.get_destination(),
        udp_packet.get_checksum(),
    ))
}

/// From [rfc4443] (section 2.4, point c):
///
///    "Every `ICMPv6` error message (type < 128) MUST include as much of
///    the IPv6 offending (invoking) packet (the packet that caused the
///    error) as possible without making the error message packet exceed
///    the minimum IPv6 MTU"
///
/// From [rfc2460] (section 5):
///
///    "IPv6 requires that every link in the internet have an MTU of 1280
///    octets or greater.  On any link that cannot convey a 1280-octet
///    packet in one piece, link-specific fragmentation and reassembly must
///    be provided at a layer below IPv6."
///
/// The maximum packet size we allow is 1024 and so we can safely assume that the originating IPv6
/// packet being extracted will be at least as large as the minimum IPv6 packet size.
///
/// [rfc4443]: https://datatracker.ietf.org/doc/html/rfc4443#section-2.4
/// [rfc2460]: https://datatracker.ietf.org/doc/html/rfc2460#section-5
fn extract_tcp_packet(ipv6: &Ipv6Packet<'_>) -> TraceResult<(u16, u16)> {
    let tcp_packet = TcpPacket::new_view(ipv6.payload())?;
    Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
}
