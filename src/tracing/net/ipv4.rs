use crate::tracing::config::IcmpExtensionParseMode;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::common::process_result;
use crate::tracing::net::platform;
use crate::tracing::net::socket::{Socket, SocketError};
use crate::tracing::packet::checksum::{icmp_ipv4_checksum, udp_ipv4_checksum};
use crate::tracing::packet::icmpv4::destination_unreachable::DestinationUnreachablePacket;
use crate::tracing::packet::icmpv4::echo_reply::EchoReplyPacket;
use crate::tracing::packet::icmpv4::echo_request::EchoRequestPacket;
use crate::tracing::packet::icmpv4::time_exceeded::TimeExceededPacket;
use crate::tracing::packet::icmpv4::{IcmpCode, IcmpPacket, IcmpTimeExceededCode, IcmpType};
use crate::tracing::packet::ipv4::Ipv4Packet;
use crate::tracing::packet::tcp::TcpPacket;
use crate::tracing::packet::udp::UdpPacket;
use crate::tracing::packet::IpProtocol;
use crate::tracing::probe::{
    Extensions, Probe, ProbeResponse, ProbeResponseData, ProbeResponseSeq, ProbeResponseSeqIcmp,
    ProbeResponseSeqTcp, ProbeResponseSeqUdp,
};
use crate::tracing::types::{PacketSize, PayloadPattern, Sequence, TraceId, TypeOfService};
use crate::tracing::{MultipathStrategy, PrivilegeMode, Protocol};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;
use tracing::instrument;

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

#[allow(clippy::too_many_arguments)]
#[instrument(skip(icmp_send_socket, probe))]
pub fn dispatch_icmp_probe<S: Socket>(
    icmp_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    ipv4_byte_order: platform::PlatformIpv4FieldByteOrder,
) -> TraceResult<()> {
    let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
    let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
    let packet_size = usize::from(packet_size.0);
    if packet_size > MAX_PACKET_SIZE {
        return Err(TracerError::InvalidPacketSize(packet_size));
    }
    let echo_request = make_echo_request_icmp_packet(
        &mut icmp_buf,
        probe.identifier,
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
    let remote_addr = SocketAddr::new(IpAddr::V4(dest_addr), 0);
    icmp_send_socket.send_to(ipv4.packet(), remote_addr)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip(raw_send_socket, probe))]
pub fn dispatch_udp_probe<S: Socket>(
    raw_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    privilege_mode: PrivilegeMode,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    multipath_strategy: MultipathStrategy,
    ipv4_byte_order: platform::PlatformIpv4FieldByteOrder,
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
            ipv4_byte_order,
        ),
        PrivilegeMode::Unprivileged => {
            dispatch_udp_probe_non_raw::<S>(probe, src_addr, dest_addr, payload)
        }
    }
}

/// Dispatch a UDP probe using a raw socket with `IP_HDRINCL` set.
///
/// As `IP_HDRINCL` is set we must supply the IP and UDP headers which allows us to set custom
/// values for certain fields such as the checksum as required by the Paris tracing strategy.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(raw_send_socket, probe))]
fn dispatch_udp_probe_raw<S: Socket>(
    raw_send_socket: &mut S,
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    payload: &[u8],
    multipath_strategy: MultipathStrategy,
    ipv4_byte_order: platform::PlatformIpv4FieldByteOrder,
) -> TraceResult<()> {
    let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
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
    let ipv4 = make_ipv4_packet(
        &mut ipv4_buf,
        ipv4_byte_order,
        IpProtocol::Udp,
        src_addr,
        dest_addr,
        probe.ttl.0,
        probe.identifier.0,
        udp.packet(),
    )?;
    let remote_addr = SocketAddr::new(IpAddr::V4(dest_addr), probe.dest_port.0);
    raw_send_socket.send_to(ipv4.packet(), remote_addr)?;
    Ok(())
}

/// Dispatch a UDP probe using a new UDP datagram socket.
#[instrument(skip(probe))]
fn dispatch_udp_probe_non_raw<S: Socket>(
    probe: Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    payload: &[u8],
) -> TraceResult<()> {
    let local_addr = SocketAddr::new(IpAddr::V4(src_addr), probe.src_port.0);
    let remote_addr = SocketAddr::new(IpAddr::V4(dest_addr), probe.dest_port.0);
    let mut socket = S::new_udp_dgram_socket_ipv4()?;
    process_result(local_addr, socket.bind(local_addr))?;
    socket.set_ttl(u32::from(probe.ttl.0))?;
    socket.send_to(payload, remote_addr)?;
    Ok(())
}

#[instrument(skip(probe))]
pub fn dispatch_tcp_probe<S: Socket>(
    probe: &Probe,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    tos: TypeOfService,
) -> TraceResult<S> {
    let mut socket = S::new_stream_socket_ipv4()?;
    let local_addr = SocketAddr::new(IpAddr::V4(src_addr), probe.src_port.0);
    process_result(local_addr, socket.bind(local_addr))?;
    socket.set_ttl(u32::from(probe.ttl.0))?;
    socket.set_tos(u32::from(tos.0))?;
    let remote_addr = SocketAddr::new(IpAddr::V4(dest_addr), probe.dest_port.0);
    process_result(remote_addr, socket.connect(remote_addr))?;
    Ok(socket)
}

#[instrument(skip(recv_socket))]
pub fn recv_icmp_probe<S: Socket>(
    recv_socket: &mut S,
    protocol: Protocol,
    icmp_extension_mode: IcmpExtensionParseMode,
) -> TraceResult<Option<ProbeResponse>> {
    let mut buf = [0_u8; MAX_PACKET_SIZE];
    match recv_socket.read(&mut buf) {
        Ok(bytes_read) => {
            let ipv4 = Ipv4Packet::new_view(&buf[..bytes_read])?;
            Ok(extract_probe_resp(protocol, icmp_extension_mode, &ipv4)?)
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
        Some(err) => match err {
            SocketError::ConnectionRefused => {
                return Ok(Some(ProbeResponse::TcpRefused(ProbeResponseData::new(
                    SystemTime::now(),
                    dest_addr,
                    resp_seq,
                ))));
            }
            SocketError::HostUnreachable => {
                let error_addr = tcp_socket.icmp_error_info()?;
                return Ok(Some(ProbeResponse::TimeExceeded(
                    ProbeResponseData::new(SystemTime::now(), error_addr, resp_seq),
                    None,
                )));
            }
            SocketError::Other(_) => {}
        },
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
    let payload_buf = [payload_pattern.0; MAX_ICMP_PAYLOAD_BUF];
    let packet_size = IcmpPacket::minimum_packet_size() + payload_size;
    let mut icmp = EchoRequestPacket::new(&mut icmp_buf[..packet_size])?;
    icmp.set_icmp_type(IcmpType::EchoRequest);
    icmp.set_icmp_code(IcmpCode(0));
    icmp.set_identifier(identifier.0);
    icmp.set_payload(&payload_buf[..payload_size]);
    icmp.set_sequence(sequence.0);
    icmp.set_checksum(icmp_ipv4_checksum(icmp.packet()));
    Ok(icmp)
}

/// Create a `UdpPacket`
fn make_udp_packet<'a>(
    udp_buf: &'a mut [u8],
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
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
    udp.set_checksum(udp_ipv4_checksum(udp.packet(), src_addr, dest_addr));
    Ok(udp)
}

/// Create an `Ipv4Packet`.
#[allow(clippy::too_many_arguments)]
fn make_ipv4_packet<'a>(
    ipv4_buf: &'a mut [u8],
    ipv4_byte_order: platform::PlatformIpv4FieldByteOrder,
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
    let mut ipv4 = Ipv4Packet::new(&mut ipv4_buf[..ipv4_total_length as usize])?;
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

#[instrument]
fn extract_probe_resp(
    protocol: Protocol,
    icmp_extension_mode: IcmpExtensionParseMode,
    ipv4: &Ipv4Packet<'_>,
) -> TraceResult<Option<ProbeResponse>> {
    let recv = SystemTime::now();
    let src = IpAddr::V4(ipv4.get_source());
    let icmp_v4 = IcmpPacket::new_view(ipv4.payload())?;
    let icmp_type = icmp_v4.get_icmp_type();
    let icmp_code = icmp_v4.get_icmp_code();
    Ok(match icmp_type {
        IcmpType::TimeExceeded => {
            if IcmpTimeExceededCode::from(icmp_code) == IcmpTimeExceededCode::TtlExpired {
                let packet = TimeExceededPacket::new_view(icmp_v4.packet())?;
                let (nested_ipv4, extension) = match icmp_extension_mode {
                    IcmpExtensionParseMode::Enabled => {
                        let ipv4 = Ipv4Packet::new_view(packet.payload())?;
                        let ext = packet.extension().map(Extensions::try_from).transpose()?;
                        (ipv4, ext)
                    }
                    IcmpExtensionParseMode::Disabled => {
                        let ipv4 = Ipv4Packet::new_view(packet.payload_raw())?;
                        (ipv4, None)
                    }
                };
                extract_probe_resp_seq(&nested_ipv4, protocol)?.map(|resp_seq| {
                    ProbeResponse::TimeExceeded(
                        ProbeResponseData::new(recv, src, resp_seq),
                        extension,
                    )
                })
            } else {
                None
            }
        }
        IcmpType::DestinationUnreachable => {
            let packet = DestinationUnreachablePacket::new_view(icmp_v4.packet())?;
            let nested_ipv4 = Ipv4Packet::new_view(packet.payload())?;
            let extension = match icmp_extension_mode {
                IcmpExtensionParseMode::Enabled => {
                    packet.extension().map(Extensions::try_from).transpose()?
                }
                IcmpExtensionParseMode::Disabled => None,
            };
            extract_probe_resp_seq(&nested_ipv4, protocol)?.map(|resp_seq| {
                ProbeResponse::DestinationUnreachable(
                    ProbeResponseData::new(recv, src, resp_seq),
                    extension,
                )
            })
        }
        IcmpType::EchoReply => match protocol {
            Protocol::Icmp => {
                let packet = EchoReplyPacket::new_view(icmp_v4.packet())?;
                let id = packet.get_identifier();
                let seq = packet.get_sequence();
                let resp_seq = ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp::new(id, seq));
                Some(ProbeResponse::EchoReply(ProbeResponseData::new(
                    recv, src, resp_seq,
                )))
            }
            Protocol::Udp | Protocol::Tcp => None,
        },
        _ => None,
    })
}

#[instrument]
fn extract_probe_resp_seq(
    ipv4: &Ipv4Packet<'_>,
    protocol: Protocol,
) -> TraceResult<Option<ProbeResponseSeq>> {
    Ok(match (protocol, ipv4.get_protocol()) {
        (Protocol::Icmp, IpProtocol::Icmp) => {
            let echo_request = extract_echo_request(ipv4)?;
            let identifier = echo_request.get_identifier();
            let sequence = echo_request.get_sequence();
            Some(ProbeResponseSeq::Icmp(ProbeResponseSeqIcmp::new(
                identifier, sequence,
            )))
        }
        (Protocol::Udp, IpProtocol::Udp) => {
            let (src_port, dest_port, checksum, identifier) = extract_udp_packet(ipv4)?;

            Some(ProbeResponseSeq::Udp(ProbeResponseSeqUdp::new(
                identifier,
                IpAddr::V4(ipv4.get_destination()),
                src_port,
                dest_port,
                checksum,
            )))
        }
        (Protocol::Tcp, IpProtocol::Tcp) => {
            let (src_port, dest_port) = extract_tcp_packet(ipv4)?;
            Some(ProbeResponseSeq::Tcp(ProbeResponseSeqTcp::new(
                IpAddr::V4(ipv4.get_destination()),
                src_port,
                dest_port,
            )))
        }
        _ => None,
    })
}

#[instrument]
fn extract_echo_request<'a>(ipv4: &'a Ipv4Packet<'a>) -> TraceResult<EchoRequestPacket<'a>> {
    Ok(EchoRequestPacket::new_view(ipv4.payload())?)
}

/// Get the src and dest ports from the original `UdpPacket` packet embedded in the payload.
#[instrument]
fn extract_udp_packet(ipv4: &Ipv4Packet<'_>) -> TraceResult<(u16, u16, u16, u16)> {
    let nested = UdpPacket::new_view(ipv4.payload())?;
    Ok((
        nested.get_source(),
        nested.get_destination(),
        nested.get_checksum(),
        ipv4.get_identification(),
    ))
}

/// Get the src and dest ports from the original `TcpPacket` packet embedded in the payload.
///
/// Unlike the embedded `ICMP` and `UDP` packets, which have a minimum header size of 8 bytes, the
/// `TCP` packet header is a minimum of 20 bytes.
///
/// The `ICMP` packets we are extracting these from, such as `TimeExceeded`, only guarantee that 8
/// bytes of the original packet (plus the IP header) be returned and so we may not have a complete
/// TCP packet.
///
/// We therefore have to detect this situation and ensure we provide buffer a large enough for a
/// complete TCP packet header.
#[instrument]
fn extract_tcp_packet(ipv4: &Ipv4Packet<'_>) -> TraceResult<(u16, u16)> {
    let nested_tcp = ipv4.payload();
    if nested_tcp.len() < TcpPacket::minimum_packet_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
        let tcp_packet = TcpPacket::new_view(&buf)?;
        Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    } else {
        let tcp_packet = TcpPacket::new_view(nested_tcp)?;
        Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocket_read;
    use crate::tracing::error::IoResult;
    use crate::tracing::net::socket::MockSocket;
    use crate::tracing::{Port, Round, TimeToLive};
    use mockall::predicate;
    use std::str::FromStr;

    // Test dispatching a IPv4/ICMP probe.
    #[test]
    fn test_dispatch_icmp_probe_no_payload() -> anyhow::Result<()> {
        let probe = Probe::new(
            Sequence(33000),
            TraceId(1234),
            Port(0),
            Port(0),
            TimeToLive(10),
            Round(0),
            SystemTime::now(),
        );
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let ipv4_byte_order = platform::PlatformIpv4FieldByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 1c 00 00 40 00 0a 01 00 00 01 02 03 04
            05 06 07 08 08 00 72 45 04 d2 80 e8
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        dispatch_icmp_probe(
            &mut mocket,
            probe,
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            ipv4_byte_order,
        )?;
        Ok(())
    }

    // This IPv4/ICMP TimeExceeded packet has code 1 ("Fragment reassembly
    // time exceeded") and must be ignored.
    //
    // Note this is not real packet and so the length and checksum are not
    // accurate.
    #[test]
    fn test_icmp_time_exceeded_fragment_reassembly_ignored() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
           45 20 2c 02 e4 5c 00 00 72 01 2e 04 67 4b 0b 34
           c0 a8 01 15 0b 01 1c 38 00 00 00 00 45 00 8c 05
           85 4e 20 00 30 11 ab d6 c0 a8 01 15 67 4b 0b 34
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let resp = recv_icmp_probe(&mut mocket, Protocol::Udp, IcmpExtensionParseMode::Enabled)?;
        assert!(resp.is_none());
        Ok(())
    }
}
