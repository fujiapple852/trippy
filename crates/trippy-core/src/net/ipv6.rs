use crate::config::IcmpExtensionParseMode;
use crate::error::{Error, ErrorKind, Result};
use crate::net::channel::MAX_PACKET_SIZE;
use crate::net::common::ErrorMapper;
use crate::net::socket::{Socket, SocketError};
use crate::probe::{
    Extensions, IcmpPacketCode, IcmpProtocolResponse, Probe, ProtocolResponse, Response,
    ResponseData, TcpProtocolResponse, UdpProtocolResponse,
};
use crate::types::{PacketSize, PayloadPattern, Sequence, TraceId};
use crate::{Flags, Port, PrivilegeMode, Protocol, TypeOfService};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;
use tracing::instrument;
use trippy_packet::checksum::{icmp_ipv6_checksum, udp_ipv6_checksum};
use trippy_packet::icmpv6::destination_unreachable::DestinationUnreachablePacket;
use trippy_packet::icmpv6::echo_reply::EchoReplyPacket;
use trippy_packet::icmpv6::echo_request::EchoRequestPacket;
use trippy_packet::icmpv6::time_exceeded::TimeExceededPacket;
use trippy_packet::icmpv6::{IcmpCode, IcmpPacket, IcmpTimeExceededCode, IcmpType};
use trippy_packet::ipv6::Ipv6Packet;
use trippy_packet::tcp::TcpPacket;
use trippy_packet::udp::UdpPacket;
use trippy_packet::IpProtocol;

/// The maximum size of UDP packet we allow.
const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of UDP payload we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

/// The maximum size of UDP packet we allow.
const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv6Packet::minimum_packet_size();

/// The maximum size of ICMP payload we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

/// The minimum size of ICMP packets we allow.
const MIN_PACKET_SIZE_ICMP: usize =
    Ipv6Packet::minimum_packet_size() + IcmpPacket::minimum_packet_size();

/// The minimum size of UDP packets we allow.
const MIN_PACKET_SIZE_UDP: usize =
    Ipv6Packet::minimum_packet_size() + UdpPacket::minimum_packet_size();

/// Magic prefix for IPv6/UDP/Dublin payloads.
const MAGIC: &[u8] = b"trippy";

/// IPv6 configuration.
#[derive(Debug)]
pub struct Ipv6 {
    pub src_addr: Ipv6Addr,
    pub dest_addr: Ipv6Addr,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub privilege_mode: PrivilegeMode,
    pub tos: TypeOfService,
    pub protocol: Protocol,
    pub icmp_extension_mode: IcmpExtensionParseMode,
    pub initial_sequence: Sequence,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            src_addr: Ipv6Addr::UNSPECIFIED,
            dest_addr: Ipv6Addr::UNSPECIFIED,
            packet_size: PacketSize(0),
            payload_pattern: PayloadPattern(0),
            privilege_mode: PrivilegeMode::Privileged,
            tos: TypeOfService(0),
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            initial_sequence: Sequence(0),
        }
    }
}

impl Ipv6 {
    /// Dispatch an ICMP probe.
    #[instrument(skip(self, icmp_send_socket), level = "trace")]
    pub fn dispatch_icmp_probe<S: Socket>(
        &self,
        icmp_send_socket: &mut S,
        probe: Probe,
    ) -> Result<()> {
        let mut icmp_buf = [0_u8; MAX_ICMP_PACKET_BUF];
        let packet_size = usize::from(self.packet_size.0);
        if !(MIN_PACKET_SIZE_ICMP..=MAX_PACKET_SIZE).contains(&packet_size) {
            return Err(Error::InvalidPacketSize(packet_size));
        }
        let echo_request = self.make_echo_request_icmp_packet(
            &mut icmp_buf,
            probe.identifier,
            probe.sequence,
            icmp_payload_size(packet_size),
        )?;
        icmp_send_socket.set_unicast_hops_v6(probe.ttl.0)?;
        icmp_send_socket.set_tclass_v6(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(IpAddr::V6(self.dest_addr), 0);
        icmp_send_socket.send_to(echo_request.packet(), remote_addr)?;
        Ok(())
    }

    /// Dispatch a UDP probe.
    #[instrument(skip(self, raw_send_socket), level = "trace")]
    pub fn dispatch_udp_probe<S: Socket>(
        &self,
        raw_send_socket: &mut S,
        probe: Probe,
    ) -> Result<()> {
        let packet_size = usize::from(self.packet_size.0);
        if !(MIN_PACKET_SIZE_UDP..=MAX_PACKET_SIZE).contains(&packet_size) {
            return Err(Error::InvalidPacketSize(packet_size));
        }
        let payload_size = udp_payload_size(packet_size);
        let payload = &[self.payload_pattern.0; MAX_UDP_PAYLOAD_BUF][0..payload_size];
        match self.privilege_mode {
            PrivilegeMode::Privileged => {
                self.dispatch_udp_probe_raw(raw_send_socket, probe, payload)
            }
            PrivilegeMode::Unprivileged => self.dispatch_udp_probe_non_raw::<S>(probe, payload),
        }
    }

    #[instrument(skip(self, udp_send_socket), level = "trace")]
    fn dispatch_udp_probe_raw<S: Socket>(
        &self,
        udp_send_socket: &mut S,
        probe: Probe,
        payload: &[u8],
    ) -> Result<()> {
        let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
        let mut dublin_payload = [self.payload_pattern.0; MAX_UDP_PAYLOAD_BUF];
        let payload_paris = probe.sequence.0.to_be_bytes();
        let payload = if probe.flags.contains(Flags::PARIS_CHECKSUM) {
            payload_paris.as_slice()
        } else if probe.flags.contains(Flags::DUBLIN_IPV6_PAYLOAD_LENGTH) {
            let payload_len = probe.sequence.0 - self.initial_sequence.0;
            dublin_payload[..MAGIC.len()].copy_from_slice(MAGIC);
            &dublin_payload[..usize::from(payload_len) + MAGIC.len()]
        } else {
            payload
        };
        let mut udp =
            self.make_udp_packet(&mut udp_buf, probe.src_port.0, probe.dest_port.0, payload)?;
        if probe.flags.contains(Flags::PARIS_CHECKSUM) {
            let checksum = udp.get_checksum().to_be_bytes();
            let payload = u16::from_be_bytes(core::array::from_fn(|i| udp.payload()[i]));
            udp.set_checksum(payload);
            udp.set_payload(&checksum);
        }
        udp_send_socket.set_unicast_hops_v6(probe.ttl.0)?;
        udp_send_socket.set_tclass_v6(u32::from(self.tos.0))?;
        // Note that we set the port to be 0 in the remote `SocketAddr` as the target port is
        // encoded in the `UDP` packet.  If we (redundantly) set the target port here then
        // the `send_to` will fail with `EINVAL`.
        let remote_addr = SocketAddr::new(IpAddr::V6(self.dest_addr), 0);
        udp_send_socket.send_to(udp.packet(), remote_addr)?;
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    fn dispatch_udp_probe_non_raw<S: Socket>(&self, probe: Probe, payload: &[u8]) -> Result<()> {
        let local_addr = SocketAddr::new(IpAddr::V6(self.src_addr), probe.src_port.0);
        let remote_addr = SocketAddr::new(IpAddr::V6(self.dest_addr), probe.dest_port.0);
        let mut socket = S::new_udp_send_socket_ipv6(false)?;
        socket
            .bind(local_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, local_addr))?;
        socket.set_unicast_hops_v6(probe.ttl.0)?;
        socket.set_tclass_v6(u32::from(self.tos.0))?;
        socket.send_to(payload, remote_addr)?;
        Ok(())
    }

    /// Dispatch a TCP probe.
    #[instrument(skip(self), level = "trace")]
    pub fn dispatch_tcp_probe<S: Socket>(&self, probe: &Probe) -> Result<S> {
        let mut socket = S::new_stream_socket_ipv6()?;
        let local_addr = SocketAddr::new(IpAddr::V6(self.src_addr), probe.src_port.0);
        socket
            .bind(local_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, local_addr))?;
        socket.set_unicast_hops_v6(probe.ttl.0)?;
        socket.set_tclass_v6(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(IpAddr::V6(self.dest_addr), probe.dest_port.0);
        socket
            .connect(remote_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, remote_addr))?;
        Ok(socket)
    }

    /// Receive an ICMP probe.
    #[instrument(skip(self, recv_socket), level = "trace")]
    pub fn recv_icmp_probe<S: Socket>(&self, recv_socket: &mut S) -> Result<Option<Response>> {
        let mut buf = [0_u8; MAX_PACKET_SIZE];
        match recv_socket.recv_from(&mut buf) {
            Ok((bytes_read, addr)) => {
                let icmp_v6 = IcmpPacket::new_view(&buf[..bytes_read])?;
                let src_addr = match addr.as_ref().ok_or(Error::MissingAddr)? {
                    SocketAddr::V6(addr) => addr.ip(),
                    SocketAddr::V4(_) => panic!(),
                };
                Ok(self.extract_probe_resp(&icmp_v6, *src_addr)?)
            }
            Err(err) => match err.kind() {
                ErrorKind::Std(io::ErrorKind::WouldBlock) => Ok(None),
                _ => Err(Error::IoError(err)),
            },
        }
    }

    /// Receive a TCP probe.
    #[instrument(skip(self, tcp_socket), level = "trace")]
    pub fn recv_tcp_socket<S: Socket>(
        &self,
        tcp_socket: &mut S,
        src_port: Port,
        dest_port: Port,
    ) -> Result<Option<Response>> {
        let proto_resp = ProtocolResponse::Tcp(TcpProtocolResponse::new(
            IpAddr::V6(self.dest_addr),
            src_port.0,
            dest_port.0,
            None,
        ));
        match tcp_socket.take_error()? {
            None => {
                let addr = tcp_socket.peer_addr()?.ok_or(Error::MissingAddr)?.ip();
                tcp_socket.shutdown()?;
                return Ok(Some(Response::TcpReply(ResponseData::new(
                    SystemTime::now(),
                    addr,
                    proto_resp,
                ))));
            }
            Some(err) => match err {
                SocketError::ConnectionRefused => {
                    return Ok(Some(Response::TcpRefused(ResponseData::new(
                        SystemTime::now(),
                        IpAddr::V6(self.dest_addr),
                        proto_resp,
                    ))));
                }
                SocketError::HostUnreachable => {
                    let error_addr = tcp_socket.icmp_error_info()?;
                    return Ok(Some(Response::TimeExceeded(
                        ResponseData::new(SystemTime::now(), error_addr, proto_resp),
                        IcmpPacketCode(1),
                        None,
                    )));
                }
                SocketError::Other(_) => {}
            },
        }
        Ok(None)
    }

    fn extract_probe_resp(
        &self,
        icmp_v6: &IcmpPacket<'_>,
        src: Ipv6Addr,
    ) -> Result<Option<Response>> {
        let recv = SystemTime::now();
        let ip = IpAddr::V6(src);
        let icmp_type = icmp_v6.get_icmp_type();
        let icmp_code = icmp_v6.get_icmp_code();
        Ok(match icmp_type {
            IcmpType::TimeExceeded => {
                if IcmpTimeExceededCode::from(icmp_code) == IcmpTimeExceededCode::TtlExpired {
                    let packet = TimeExceededPacket::new_view(icmp_v6.packet())?;
                    let (nested_ipv6, extension) = match self.icmp_extension_mode {
                        IcmpExtensionParseMode::Enabled => {
                            let ipv6 = Ipv6Packet::new_view(packet.payload())?;
                            let ext = packet.extension().map(Extensions::try_from).transpose()?;
                            (ipv6, ext)
                        }
                        IcmpExtensionParseMode::Disabled => {
                            let ipv6 = Ipv6Packet::new_view(packet.payload_raw())?;
                            (ipv6, None)
                        }
                    };
                    self.extract_probe_proto_resp(&nested_ipv6)?
                        .map(|proto_resp| {
                            Response::TimeExceeded(
                                ResponseData::new(recv, ip, proto_resp),
                                IcmpPacketCode(icmp_code.0),
                                extension,
                            )
                        })
                } else {
                    None
                }
            }
            IcmpType::DestinationUnreachable => {
                let packet = DestinationUnreachablePacket::new_view(icmp_v6.packet())?;
                let nested_ipv6 = Ipv6Packet::new_view(packet.payload())?;
                let extension = match self.icmp_extension_mode {
                    IcmpExtensionParseMode::Enabled => {
                        packet.extension().map(Extensions::try_from).transpose()?
                    }
                    IcmpExtensionParseMode::Disabled => None,
                };
                self.extract_probe_proto_resp(&nested_ipv6)?
                    .map(|proto_resp| {
                        Response::DestinationUnreachable(
                            ResponseData::new(recv, ip, proto_resp),
                            IcmpPacketCode(icmp_code.0),
                            extension,
                        )
                    })
            }
            IcmpType::EchoReply => match self.protocol {
                Protocol::Icmp => {
                    let packet = EchoReplyPacket::new_view(icmp_v6.packet())?;
                    let id = packet.get_identifier();
                    let seq = packet.get_sequence();
                    let proto_resp =
                        ProtocolResponse::Icmp(IcmpProtocolResponse::new(id, seq, None));
                    Some(Response::EchoReply(
                        ResponseData::new(recv, ip, proto_resp),
                        IcmpPacketCode(icmp_code.0),
                    ))
                }
                Protocol::Udp | Protocol::Tcp => None,
            },
            _ => None,
        })
    }

    fn extract_probe_proto_resp(&self, ipv6: &Ipv6Packet<'_>) -> Result<Option<ProtocolResponse>> {
        Ok(match (self.protocol, ipv6.get_next_header()) {
            (Protocol::Icmp, IpProtocol::IcmpV6) => {
                let (identifier, sequence) = extract_echo_request(ipv6)?;
                Some(ProtocolResponse::Icmp(IcmpProtocolResponse::new(
                    identifier,
                    sequence,
                    Some(TypeOfService(ipv6.get_traffic_class())),
                )))
            }
            (Protocol::Udp, IpProtocol::Udp) => {
                let (src_port, dest_port, actual_checksum, udp_payload_len) =
                    extract_udp_packet(ipv6)?;
                let has_magic = udp_payload_has_magic_prefix(ipv6)?;
                let payload_len = if has_magic {
                    udp_payload_len - MAGIC.len() as u16
                } else {
                    udp_payload_len
                };
                Some(ProtocolResponse::Udp(UdpProtocolResponse::new(
                    0,
                    IpAddr::V6(ipv6.get_destination_address()),
                    src_port,
                    dest_port,
                    Some(TypeOfService(ipv6.get_traffic_class())),
                    actual_checksum,
                    actual_checksum,
                    payload_len,
                    has_magic,
                )))
            }
            (Protocol::Tcp, IpProtocol::Tcp) => {
                let (src_port, dest_port) = extract_tcp_packet(ipv6)?;
                Some(ProtocolResponse::Tcp(TcpProtocolResponse::new(
                    IpAddr::V6(ipv6.get_destination_address()),
                    src_port,
                    dest_port,
                    Some(TypeOfService(ipv6.get_traffic_class())),
                )))
            }
            _ => None,
        })
    }

    /// Create a `UdpPacket`
    fn make_udp_packet<'a>(
        &self,
        udp_buf: &'a mut [u8],
        src_port: u16,
        dest_port: u16,
        payload: &'_ [u8],
    ) -> Result<UdpPacket<'a>> {
        let udp_packet_size = UdpPacket::minimum_packet_size() + payload.len();
        let mut udp = UdpPacket::new(&mut udp_buf[..udp_packet_size])?;
        udp.set_source(src_port);
        udp.set_destination(dest_port);
        udp.set_length(udp_packet_size as u16);
        udp.set_payload(payload);
        udp.set_checksum(udp_ipv6_checksum(
            udp.packet(),
            self.src_addr,
            self.dest_addr,
        ));
        Ok(udp)
    }

    /// Create an ICMP `EchoRequest` packet.
    fn make_echo_request_icmp_packet<'a>(
        &self,
        icmp_buf: &'a mut [u8],
        identifier: TraceId,
        sequence: Sequence,
        payload_size: usize,
    ) -> Result<EchoRequestPacket<'a>> {
        let payload_buf = [self.payload_pattern.0; MAX_ICMP_PAYLOAD_BUF];
        let packet_size = IcmpPacket::minimum_packet_size() + payload_size;
        let mut icmp = EchoRequestPacket::new(&mut icmp_buf[..packet_size])?;
        icmp.set_icmp_type(IcmpType::EchoRequest);
        icmp.set_icmp_code(IcmpCode(0));
        icmp.set_identifier(identifier.0);
        icmp.set_payload(&payload_buf[..payload_size]);
        icmp.set_sequence(sequence.0);
        icmp.set_checksum(icmp_ipv6_checksum(
            icmp.packet(),
            self.src_addr,
            self.dest_addr,
        ));
        Ok(icmp)
    }
}

const fn icmp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv6Packet::minimum_packet_size();
    let icmp_header_size = IcmpPacket::minimum_packet_size();
    packet_size - icmp_header_size - ip_header_size
}

const fn udp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv6Packet::minimum_packet_size();
    let udp_header_size = UdpPacket::minimum_packet_size();
    packet_size - udp_header_size - ip_header_size
}

fn extract_echo_request(ipv6: &Ipv6Packet<'_>) -> Result<(u16, u16)> {
    let echo_request_packet = EchoRequestPacket::new_view(ipv6.payload())?;
    Ok((
        echo_request_packet.get_identifier(),
        echo_request_packet.get_sequence(),
    ))
}

fn extract_udp_packet(ipv6: &Ipv6Packet<'_>) -> Result<(u16, u16, u16, u16)> {
    let udp_packet = UdpPacket::new_view(ipv6.payload())?;
    Ok((
        udp_packet.get_source(),
        udp_packet.get_destination(),
        udp_packet.get_checksum(),
        udp_packet.get_length() - UdpPacket::minimum_packet_size() as u16,
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
/// The maximum packet size we allow is 1024, and so we can safely assume that the originating IPv6
/// packet being extracted will be at least as large as the minimum IPv6 packet size.
///
/// [rfc4443]: https://datatracker.ietf.org/doc/html/rfc4443#section-2.4
/// [rfc2460]: https://datatracker.ietf.org/doc/html/rfc2460#section-5
fn extract_tcp_packet(ipv6: &Ipv6Packet<'_>) -> Result<(u16, u16)> {
    let tcp_packet = TcpPacket::new_view(ipv6.payload())?;
    Ok((tcp_packet.get_source(), tcp_packet.get_destination()))
}

fn udp_payload_has_magic_prefix(ipv6: &Ipv6Packet<'_>) -> Result<bool> {
    let udp_packet = UdpPacket::new_view(ipv6.payload())?;
    Ok(udp_packet.payload().starts_with(MAGIC))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IoResult;
    use crate::mocket_recv_from;
    use crate::net::socket::MockSocket;
    use crate::{Flags, Port, RoundId, TimeToLive};
    use mockall::predicate;
    use std::str::FromStr;
    use std::sync::Mutex;

    static MTX: Mutex<()> = Mutex::new(());

    // Test dispatching an IPv6/ICMP probe.
    #[test]
    fn test_dispatch_icmp_probe_no_payload() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let packet_size = PacketSize(48);
        let payload_pattern = PayloadPattern(0x00);
        let expected_send_to_buf = hex_literal::hex!("80 00 75 a2 04 d2 82 9a");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        ipv6.dispatch_icmp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_with_payload() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let packet_size = PacketSize(68);
        let payload_pattern = PayloadPattern(0xff);
        let expected_send_to_buf = hex_literal::hex!(
            "
            80 00 75 8e 04 d2 82 9a ff ff ff ff ff ff ff ff
            ff ff ff ff ff ff ff ff ff ff ff ff
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        ipv6.dispatch_icmp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_invalid_packet_size_low() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let packet_size = PacketSize(47);
        let payload_pattern = PayloadPattern(0x00);
        let mut mocket = MockSocket::new();
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        let err = ipv6.dispatch_icmp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_invalid_packet_size_high() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let packet_size = PacketSize(1025);
        let payload_pattern = PayloadPattern(0x00);
        let mut mocket = MockSocket::new();
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        let err = ipv6.dispatch_icmp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_privileged_no_payload() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(48);
        let payload_pattern = PayloadPattern(0x00);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!("00 7b 01 c8 00 08 7a ed");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_privileged_with_payload() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(56);
        let payload_pattern = PayloadPattern(0xaa);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!(
            "
            00 7b 01 c8 00 10 d0 32 aa aa aa aa aa aa aa aa
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_paris_privileged() -> anyhow::Result<()> {
        let probe = Probe {
            flags: Flags::PARIS_CHECKSUM,
            ..make_udp_probe(123, 456)
        };
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        // packet size and payload pattern are ignored for paris mode as a
        // fixed two byte payload is used to hold the sequence
        let packet_size = PacketSize(300);
        let payload_pattern = PayloadPattern(0xaa);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!(
            "
            00 7b 01 c8 00 0a 82 9a f8 4e
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    // Here we send probe 33007 (the 8th probe when starting from 33434) and
    // so the payload will be 13 octets in length (7 + 6 for the magic prefix
    // "trippy").
    #[test]
    fn test_dispatch_udp_probe_dublin_privileged() -> anyhow::Result<()> {
        let probe = Probe {
            flags: Flags::DUBLIN_IPV6_PAYLOAD_LENGTH,
            sequence: Sequence(33441),
            identifier: TraceId(33441),
            ..make_udp_probe(123, 456)
        };
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        // packet size and payload pattern are ignored for ipv6/udp/dublin mode.
        let packet_size = PacketSize(300);
        let payload_pattern = PayloadPattern(0xaa);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!(
            "
            00 7b 01 c8 00 15 82 76
            74 72 69 70 70 79 aa aa
            aa aa aa aa aa
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 0);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));
        mocket
            .expect_set_unicast_hops_v6()
            .times(1)
            .with(predicate::eq(10))
            .returning(|_| Ok(()));
        mocket
            .expect_set_tclass_v6()
            .times(1)
            .with(predicate::eq(0))
            .returning(|_| Ok(()));

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_unprivileged_no_payload() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Unprivileged;
        let packet_size = PacketSize(48);
        let payload_pattern = PayloadPattern(0x00);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!("");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 456);
        let expected_bind_addr = SocketAddr::new(IpAddr::V6(src_addr), 123);
        let expected_set_unicast_hops_v6 = 10;

        let mut mocket = MockSocket::new();

        let ctx = MockSocket::new_udp_send_socket_ipv6_context();
        ctx.expect().with(predicate::eq(false)).returning(move |_| {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_unicast_hops_v6()
                .times(1)
                .with(predicate::eq(expected_set_unicast_hops_v6))
                .returning(|_| Ok(()));

            mocket
                .expect_set_tclass_v6()
                .times(1)
                .with(predicate::eq(0))
                .returning(|_| Ok(()));

            mocket
                .expect_send_to()
                .with(
                    predicate::eq(expected_send_to_buf),
                    predicate::eq(expected_send_to_addr),
                )
                .times(1)
                .returning(|_, _| Ok(()));

            Ok(mocket)
        });

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_unprivileged_with_payload() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Unprivileged;
        let packet_size = PacketSize(56);
        let payload_pattern = PayloadPattern(0x1f);
        let initial_sequence = Sequence(33434);
        let expected_send_to_buf = hex_literal::hex!("1f 1f 1f 1f 1f 1f 1f 1f");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V6(dest_addr), 456);
        let expected_bind_addr = SocketAddr::new(IpAddr::V6(src_addr), 123);
        let expected_set_unicast_hops_v6 = 10;

        let mut mocket = MockSocket::new();

        let ctx = MockSocket::new_udp_send_socket_ipv6_context();
        ctx.expect().with(predicate::eq(false)).returning(move |_| {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_unicast_hops_v6()
                .times(1)
                .with(predicate::eq(expected_set_unicast_hops_v6))
                .returning(|_| Ok(()));

            mocket
                .expect_set_tclass_v6()
                .times(1)
                .with(predicate::eq(0))
                .returning(|_| Ok(()));

            mocket
                .expect_send_to()
                .with(
                    predicate::eq(expected_send_to_buf),
                    predicate::eq(expected_send_to_addr),
                )
                .times(1)
                .returning(|_, _| Ok(()));

            Ok(mocket)
        });

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        ipv6.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_invalid_packet_size_low() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(47);
        let payload_pattern = PayloadPattern(0x00);
        let initial_sequence = Sequence(33434);
        let mut mocket = MockSocket::new();
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        let err = ipv6.dispatch_udp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_invalid_packet_size_high() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(1025);
        let payload_pattern = PayloadPattern(0x00);
        let initial_sequence = Sequence(33434);
        let mut mocket = MockSocket::new();
        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            packet_size,
            payload_pattern,
            privilege_mode,
            initial_sequence,
            ..Default::default()
        };
        let err = ipv6.dispatch_udp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_tcp_probe() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6263:82a")?;
        let dest_addr = Ipv6Addr::from_str("2a00:1450:4009:815::200e")?;
        let expected_bind_addr = SocketAddr::new(IpAddr::V6(src_addr), 123);
        let expected_set_unicast_hops_v6 = 10;
        let expected_connect_addr = SocketAddr::new(IpAddr::V6(dest_addr), 456);

        let ctx = MockSocket::new_stream_socket_ipv6_context();
        ctx.expect().returning(move || {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_unicast_hops_v6()
                .times(1)
                .with(predicate::eq(expected_set_unicast_hops_v6))
                .returning(|_| Ok(()));

            mocket
                .expect_set_tclass_v6()
                .times(1)
                .with(predicate::eq(0))
                .returning(|_| Ok(()));

            mocket
                .expect_connect()
                .with(predicate::eq(expected_connect_addr))
                .times(1)
                .returning(|_| Ok(()));

            Ok(mocket)
        });

        let ipv6 = Ipv6 {
            src_addr,
            dest_addr,
            ..Default::default()
        };
        ipv6.dispatch_tcp_probe::<MockSocket>(&probe)?;
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_echo_reply() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            81 00 52 c0 55 b9 81 26 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::EchoReply(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Icmp(IcmpProtocolResponse {
                        identifier,
                        sequence,
                        tos,
                    }),
                ..
            },
            icmp_code,
        ) = resp
        else {
            panic!("expected EchoReply")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(21945, identifier);
        assert_eq!(33062, sequence);
        assert_eq!(None, tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_icmp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 4e c5 00 00 00 00 60 0f 08 00 00 2c 3a 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 04 4e 42 00 00 00 00 00 00 00 00 00 00 00 81
            80 00 53 c6 55 b9 81 20 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::TimeExceeded(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Icmp(IcmpProtocolResponse {
                        identifier,
                        sequence,
                        tos,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected TimeExceeded")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(21945, identifier);
        assert_eq!(33056, sequence);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_icmp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            01 00 ad ba 00 00 00 00 60 06 08 00 00 2c 3a 02
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            14 04 68 00 40 03 0c 02 00 00 00 00 00 00 00 69
            80 00 02 62 57 a5 80 ed 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::DestinationUnreachable(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Icmp(IcmpProtocolResponse {
                        identifier,
                        sequence,
                        tos,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected DestinationUnreachable")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(22437, identifier);
        assert_eq!(33005, sequence);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_udp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 7b a7 00 00 00 00 60 04 04 00 00 2c 11 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 04 4e 42 00 00 00 00 00 00 00 00 00 00 00 81
            58 a6 81 05 00 2c d0 f1 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::TimeExceeded(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Udp(UdpProtocolResponse {
                        identifier,
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                        expected_udp_checksum,
                        actual_udp_checksum,
                        payload_len,
                        has_magic,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected TimeExceeded")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(0, identifier);
        assert_eq!(IpAddr::V6(Ipv6Addr::from_str("2a04:4e42::81")?), dest_addr);
        assert_eq!(22694, src_port);
        assert_eq!(33029, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(53489, expected_udp_checksum);
        assert_eq!(53489, actual_udp_checksum);
        assert_eq!(36, payload_len);
        assert!(!has_magic);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_udp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            01 00 a5 f5 00 00 00 00 60 03 08 00 00 2c 11 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 1f 00 00 00 00 00 00 20 0e
            67 6d 81 5e 00 2c 94 12 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::DestinationUnreachable(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Udp(UdpProtocolResponse {
                        identifier,
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                        expected_udp_checksum,
                        actual_udp_checksum,
                        payload_len,
                        has_magic,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected DestinationUnreachable")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(0, identifier);
        assert_eq!(
            IpAddr::V6(Ipv6Addr::from_str("2a00:1450:4009:81f::200e")?),
            dest_addr
        );
        assert_eq!(26477, src_port);
        assert_eq!(33118, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(37906, expected_udp_checksum);
        assert_eq!(37906, actual_udp_checksum);
        assert_eq!(36, payload_len);
        assert!(!has_magic);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    // Here we receive a `TimeExceeded` in UDP/Dublin mode and so extract the
    // sequence from the length of the UDP payload, after subtracting the
    // length of the magic prefix "trippy" (11 - 6 == 5).
    //
    // Note we do not know if we are in UDP/Dublin mode when decoding the
    // packet and so the decision to reject the probe response is left to
    // the `tracer::Tracer::validate(..)` function.
    #[test]
    fn test_recv_icmp_probe_time_exceeded_udp_dublin_with_magic() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 23 6f 00 00 00 00 60 0e 0e 00 00 13 11 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 20 00 00 00 00 00 00 20 0e
            80 e8 13 88 00 13 9a 42 74 72 69 70 70 79 00 00
            00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::TimeExceeded(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Udp(UdpProtocolResponse {
                        identifier,
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                        expected_udp_checksum,
                        actual_udp_checksum,
                        payload_len,
                        has_magic,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected TimeExceeded")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(0, identifier);
        assert_eq!(
            IpAddr::V6(Ipv6Addr::from_str("2a00:1450:4009:820::200e")?),
            dest_addr
        );
        assert_eq!(33000, src_port);
        assert_eq!(5000, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(39490, expected_udp_checksum);
        assert_eq!(39490, actual_udp_checksum);
        assert_eq!(5, payload_len);
        assert!(has_magic);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_tcp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 f0 2d 00 00 00 00 68 0b 09 00 00 2c 06 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 15 00 00 00 00 00 00 20 0e
            81 0e 00 50 aa c4 08 e6 00 00 00 00 b0 c2 ff ff
            6d b4 00 00 02 04 04 c4 01 03 03 06 01 01 08 0a
            cc f7 44 c9 00 00 00 00 04 02 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::TimeExceeded(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Tcp(TcpProtocolResponse {
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected TimeExceeded")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(
            IpAddr::V6(Ipv6Addr::from_str("2a00:1450:4009:815::200e")?),
            dest_addr
        );
        assert_eq!(33038, src_port);
        assert_eq!(80, dest_port);
        assert_eq!(Some(TypeOfService(128)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_tcp_no_extensions() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            01 00 b1 e9 00 00 00 00 60 04 07 00 00 2c 06 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 21 00 00 00 00 00 00 20 0e
            81 24 00 7b 35 d2 32 c6 00 00 00 00 b0 c2 ff ff
            71 b2 00 00 02 04 04 c4 01 03 03 06 01 01 08 0a
            fa 0b 5e 7c 00 00 00 00 04 02 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));
        let ipv6 = Ipv6 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?.unwrap();

        let Response::DestinationUnreachable(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Tcp(TcpProtocolResponse {
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected DestinationUnreachable")
        };
        assert_eq!(recv_from_addr, addr);
        assert_eq!(
            IpAddr::V6(Ipv6Addr::from_str("2a00:1450:4009:821::200e")?),
            dest_addr
        );
        assert_eq!(33060, src_port);
        assert_eq!(123, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_icmp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 4e c5 00 00 00 00 60 0f 08 00 00 2c 3a 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 04 4e 42 00 00 00 00 00 00 00 00 00 00 00 81
            80 00 53 c6 55 b9 81 20 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(3)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));

        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv6 = Ipv6 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_udp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 7b a7 00 00 00 00 60 04 04 00 00 2c 11 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 04 4e 42 00 00 00 00 00 00 00 00 00 00 00 81
            58 a6 81 05 00 2c d0 f1 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(3)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));

        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv6 = Ipv6 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_tcp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let recv_from_addr = IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?);
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 00 f0 2d 00 00 00 00 68 0b 09 00 00 2c 06 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 15 00 00 00 00 00 00 20 0e
            81 0e 00 50 aa c4 08 e6 00 00 00 00 b0 c2 ff ff
            6d b4 00 00 02 04 04 c4 01 03 03 06 01 01 08 0a
            cc f7 44 c9 00 00 00 00 04 02 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(recv_from_addr, 0);
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(3)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));

        let ipv6 = Ipv6 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv6 = Ipv6 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_tcp_socket_tcp_reply() -> anyhow::Result<()> {
        let dest_addr = Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?;
        let expected_peer_addr = SocketAddr::new(IpAddr::V6(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket.expect_take_error().times(1).returning(|| Ok(None));
        mocket
            .expect_peer_addr()
            .times(1)
            .returning(move || Ok(Some(expected_peer_addr)));
        mocket.expect_shutdown().times(1).returning(|| Ok(()));

        let ipv6 = Ipv6 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv6
            .recv_tcp_socket(&mut mocket, Port(33434), Port(456))?
            .unwrap();

        let Response::TcpReply(ResponseData {
            addr,
            proto_resp:
                ProtocolResponse::Tcp(TcpProtocolResponse {
                    dest_addr,
                    src_port,
                    dest_port,
                    tos,
                }),
            ..
        }) = resp
        else {
            panic!("expected TcpReply")
        };
        assert_eq!(dest_addr, addr);
        assert_eq!(33434, src_port);
        assert_eq!(456, dest_port);
        assert_eq!(None, tos);
        Ok(())
    }

    #[test]
    fn test_recv_tcp_socket_tcp_refused() -> anyhow::Result<()> {
        let dest_addr = Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?;

        let mut mocket = MockSocket::new();
        mocket
            .expect_take_error()
            .times(1)
            .returning(|| Ok(Some(SocketError::ConnectionRefused)));

        let ipv6 = Ipv6 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv6
            .recv_tcp_socket(&mut mocket, Port(33434), Port(80))?
            .unwrap();

        let Response::TcpRefused(ResponseData {
            addr,
            proto_resp:
                ProtocolResponse::Tcp(TcpProtocolResponse {
                    dest_addr,
                    src_port,
                    dest_port,
                    tos,
                }),
            ..
        }) = resp
        else {
            panic!("expected TcpRefused")
        };
        assert_eq!(dest_addr, addr);
        assert_eq!(33434, src_port);
        assert_eq!(80, dest_port);
        assert_eq!(None, tos);
        Ok(())
    }

    #[test]
    fn test_recv_tcp_socket_tcp_host_unreachable() -> anyhow::Result<()> {
        let dest_addr = Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?;

        let mut mocket = MockSocket::new();
        mocket
            .expect_take_error()
            .times(1)
            .returning(|| Ok(Some(SocketError::HostUnreachable)));
        mocket
            .expect_icmp_error_info()
            .times(1)
            .returning(move || Ok(IpAddr::V6(dest_addr)));

        let ipv6 = Ipv6 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv6
            .recv_tcp_socket(&mut mocket, Port(33434), Port(80))?
            .unwrap();

        let Response::TimeExceeded(
            ResponseData {
                addr,
                proto_resp:
                    ProtocolResponse::Tcp(TcpProtocolResponse {
                        dest_addr,
                        src_port,
                        dest_port,
                        tos,
                    }),
                ..
            },
            icmp_code,
            extensions,
        ) = resp
        else {
            panic!("expected TimeExceeded")
        };
        assert_eq!(dest_addr, addr);
        assert_eq!(33434, src_port);
        assert_eq!(80, dest_port);
        assert_eq!(None, tos);
        assert_eq!(IcmpPacketCode(1), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    // This ICMPv6 packet has code 1 ("Fragment reassembly time exceeded")
    // and must be ignored.
    //
    // Note this is not real packet and so the length and checksum are not
    // accurate.
    #[test]
    fn test_icmp_time_exceeded_fragment_reassembly_ignored() -> anyhow::Result<()> {
        let expected_recv_from_buf = hex_literal::hex!(
            "
            03 01 da 90 00 00 00 00 60 0f 02 00 00 2c 11 01
            fd 7a 11 5c a1 e0 ab 12 48 43 cd 96 62 63 08 2a
            2a 00 14 50 40 09 08 15 00 00 00 00 00 00 20 0e
            95 ce 81 24 00 2c 65 f5 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let expected_recv_from_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from_str("2604:a880:ffff:6:1::41c")?),
            0,
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_recv_from()
            .times(1)
            .returning(mocket_recv_from!(
                expected_recv_from_buf,
                expected_recv_from_addr
            ));

        let ipv6 = Ipv6 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv6.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    fn make_icmp_probe() -> Probe {
        Probe::new(
            Sequence(33434),
            TraceId(1234),
            Port(0),
            Port(0),
            TimeToLive(10),
            RoundId(0),
            SystemTime::now(),
            Flags::empty(),
        )
    }

    fn make_udp_probe(src_port: u16, dest_port: u16) -> Probe {
        Probe::new(
            Sequence(33434),
            TraceId(1234),
            Port(src_port),
            Port(dest_port),
            TimeToLive(10),
            RoundId(0),
            SystemTime::now(),
            Flags::empty(),
        )
    }
}
