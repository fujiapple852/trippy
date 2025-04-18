use crate::config::IcmpExtensionParseMode;
use crate::error::{Error, ErrorKind, Result};
use crate::net::channel::MAX_PACKET_SIZE;
use crate::net::common::ErrorMapper;
use crate::net::platform;
use crate::net::socket::{Socket, SocketError};
use crate::probe::{
    Extensions, IcmpPacketCode, IcmpProtocolResponse, Probe, ProtocolResponse, Response,
    ResponseData, TcpProtocolResponse, UdpProtocolResponse,
};
use crate::types::{PacketSize, PayloadPattern, Sequence, TraceId, TypeOfService};
use crate::{Flags, Port, PrivilegeMode, Protocol};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;
use tracing::instrument;
use trippy_packet::checksum::{icmp_ipv4_checksum, udp_ipv4_checksum};
use trippy_packet::icmpv4::destination_unreachable::DestinationUnreachablePacket;
use trippy_packet::icmpv4::echo_reply::EchoReplyPacket;
use trippy_packet::icmpv4::echo_request::EchoRequestPacket;
use trippy_packet::icmpv4::time_exceeded::TimeExceededPacket;
use trippy_packet::icmpv4::{IcmpCode, IcmpPacket, IcmpTimeExceededCode, IcmpType};
use trippy_packet::ipv4::Ipv4Packet;
use trippy_packet::tcp::TcpPacket;
use trippy_packet::udp::UdpPacket;
use trippy_packet::IpProtocol;

/// The maximum size of UDP packet we allow.
const MAX_UDP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum size of UDP payload we allow.
const MAX_UDP_PAYLOAD_BUF: usize = MAX_UDP_PACKET_BUF - UdpPacket::minimum_packet_size();

/// The maximum size of ICMP packet we allow.
const MAX_ICMP_PACKET_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum size of ICMP payload we allow.
const MAX_ICMP_PAYLOAD_BUF: usize = MAX_ICMP_PACKET_BUF - IcmpPacket::minimum_packet_size();

/// The minimum size of ICMP packets we allow.
const MIN_PACKET_SIZE_ICMP: usize =
    Ipv4Packet::minimum_packet_size() + IcmpPacket::minimum_packet_size();

/// The minimum size of UDP packets we allow.
const MIN_PACKET_SIZE_UDP: usize =
    Ipv4Packet::minimum_packet_size() + UdpPacket::minimum_packet_size();

/// The value for the IPv4 `flags_and_fragment_offset` field to set the `Don't fragment` bit.
///
/// 0100 0000 0000 0000
const DONT_FRAGMENT: u16 = 0x4000;

/// IPv4 configuration.
#[derive(Debug)]
pub struct Ipv4 {
    pub src_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
    pub byte_order: platform::Ipv4ByteOrder,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub privilege_mode: PrivilegeMode,
    pub tos: TypeOfService,
    pub protocol: Protocol,
    pub icmp_extension_mode: IcmpExtensionParseMode,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            src_addr: Ipv4Addr::UNSPECIFIED,
            dest_addr: Ipv4Addr::UNSPECIFIED,
            byte_order: platform::Ipv4ByteOrder::Network,
            packet_size: PacketSize(0),
            payload_pattern: PayloadPattern(0),
            privilege_mode: PrivilegeMode::Privileged,
            tos: TypeOfService(0),
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
        }
    }
}

impl Ipv4 {
    /// Dispatch an ICMP probe.
    #[instrument(skip(self, icmp_send_socket), level = "trace")]
    pub fn dispatch_icmp_probe<S: Socket>(
        &self,
        icmp_send_socket: &mut S,
        probe: Probe,
    ) -> Result<()> {
        let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
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
        let ipv4 = self.make_ipv4_packet(
            &mut ipv4_buf,
            IpProtocol::Icmp,
            probe.ttl.0,
            0,
            echo_request.packet(),
        )?;
        let remote_addr = SocketAddr::new(IpAddr::V4(self.dest_addr), 0);
        icmp_send_socket
            .send_to(ipv4.packet(), remote_addr)
            .map_err(Error::IoError)
            .map_err(|err| ErrorMapper::probe_failed(err, ErrorKind::HostUnreachable))
            .map_err(|err| ErrorMapper::probe_failed(err, ErrorKind::NetUnreachable))
            .map_err(|err| ErrorMapper::probe_failed(err, INVALID_INPUT_KIND))?;
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

    /// Dispatch a UDP probe using a raw socket with `IP_HDRINCL` set.
    ///
    /// As `IP_HDRINCL` is set we must supply the IP and UDP headers which allows us to set custom
    /// values for certain fields such as the checksum as required by the Paris tracing strategy.
    #[instrument(skip(self, raw_send_socket), level = "trace")]
    fn dispatch_udp_probe_raw<S: Socket>(
        &self,
        raw_send_socket: &mut S,
        probe: Probe,
        payload: &[u8],
    ) -> Result<()> {
        let mut ipv4_buf = [0_u8; MAX_PACKET_SIZE];
        let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
        let payload_paris = probe.sequence.0.to_be_bytes();
        let payload = if probe.flags.contains(Flags::PARIS_CHECKSUM) {
            payload_paris.as_slice()
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
        let ipv4 = self.make_ipv4_packet(
            &mut ipv4_buf,
            IpProtocol::Udp,
            probe.ttl.0,
            probe.identifier.0,
            udp.packet(),
        )?;
        let remote_addr = SocketAddr::new(IpAddr::V4(self.dest_addr), probe.dest_port.0);
        raw_send_socket
            .send_to(ipv4.packet(), remote_addr)
            .map_err(Error::IoError)
            .map_err(|err| ErrorMapper::probe_failed(err, ErrorKind::HostUnreachable))
            .map_err(|err| ErrorMapper::probe_failed(err, ErrorKind::NetUnreachable))?;
        Ok(())
    }

    /// Dispatch a UDP probe using a new UDP datagram socket.
    #[instrument(skip(self), level = "trace")]
    fn dispatch_udp_probe_non_raw<S: Socket>(&self, probe: Probe, payload: &[u8]) -> Result<()> {
        let local_addr = SocketAddr::new(IpAddr::V4(self.src_addr), probe.src_port.0);
        let remote_addr = SocketAddr::new(IpAddr::V4(self.dest_addr), probe.dest_port.0);
        let mut socket = S::new_udp_send_socket_ipv4(false)?;
        socket
            .bind(local_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, local_addr))
            .map_err(|err| ErrorMapper::probe_failed(err, ADDR_NOT_AVAILABLE_KIND))?;
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        socket.send_to(payload, remote_addr)?;
        Ok(())
    }

    /// Dispatch a TCP probe.
    #[instrument(skip(self), level = "trace")]
    pub fn dispatch_tcp_probe<S: Socket>(&self, probe: &Probe) -> Result<S> {
        let mut socket = S::new_stream_socket_ipv4()?;
        let local_addr = SocketAddr::new(IpAddr::V4(self.src_addr), probe.src_port.0);
        socket
            .bind(local_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, local_addr))
            .map_err(|err| ErrorMapper::probe_failed(err, ADDR_NOT_AVAILABLE_KIND))?;
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(IpAddr::V4(self.dest_addr), probe.dest_port.0);
        socket
            .connect(remote_addr)
            .map_err(Error::IoError)
            .or_else(ErrorMapper::in_progress)
            .map_err(|err| ErrorMapper::addr_in_use(err, remote_addr))
            .map_err(|err| ErrorMapper::probe_failed(err, ErrorKind::NetUnreachable))?;
        Ok(socket)
    }

    /// Receive an ICMP probe response.
    #[instrument(skip(self, recv_socket), level = "trace")]
    pub fn recv_icmp_probe<S: Socket>(&self, recv_socket: &mut S) -> Result<Option<Response>> {
        let mut buf = [0_u8; MAX_PACKET_SIZE];
        match recv_socket.read(&mut buf) {
            Ok(bytes_read) => {
                let ipv4 = Ipv4Packet::new_view(&buf[..bytes_read])?;
                Ok(self.extract_probe_resp(&ipv4)?)
            }
            Err(err) => match err.kind() {
                ErrorKind::Std(io::ErrorKind::WouldBlock) => Ok(None),
                _ => Err(Error::IoError(err)),
            },
        }
    }

    /// Receive a TCP probe response.
    #[instrument(skip(self, tcp_socket), level = "trace")]
    pub fn recv_tcp_socket<S: Socket>(
        &self,
        tcp_socket: &mut S,
        src_port: Port,
        dest_port: Port,
    ) -> Result<Option<Response>> {
        let proto_resp = ProtocolResponse::Tcp(TcpProtocolResponse::new(
            IpAddr::V4(self.dest_addr),
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
                        IpAddr::V4(self.dest_addr),
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

    #[instrument(skip(self), level = "trace")]
    fn extract_probe_resp(&self, ipv4: &Ipv4Packet<'_>) -> Result<Option<Response>> {
        let recv = SystemTime::now();
        let src = IpAddr::V4(ipv4.get_source());
        let icmp_v4 = IcmpPacket::new_view(ipv4.payload())?;
        let icmp_type = icmp_v4.get_icmp_type();
        let icmp_code = icmp_v4.get_icmp_code();
        Ok(match icmp_type {
            IcmpType::TimeExceeded => {
                if IcmpTimeExceededCode::from(icmp_code) == IcmpTimeExceededCode::TtlExpired {
                    let packet = TimeExceededPacket::new_view(icmp_v4.packet())?;
                    let (nested_ipv4, extension) = match self.icmp_extension_mode {
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
                    self.extract_probe_proto_resp(&nested_ipv4)?
                        .map(|proto_resp| {
                            Response::TimeExceeded(
                                ResponseData::new(recv, src, proto_resp),
                                IcmpPacketCode(icmp_code.0),
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
                let extension = match self.icmp_extension_mode {
                    IcmpExtensionParseMode::Enabled => {
                        packet.extension().map(Extensions::try_from).transpose()?
                    }
                    IcmpExtensionParseMode::Disabled => None,
                };
                self.extract_probe_proto_resp(&nested_ipv4)?
                    .map(|proto_resp| {
                        Response::DestinationUnreachable(
                            ResponseData::new(recv, src, proto_resp),
                            IcmpPacketCode(icmp_code.0),
                            extension,
                        )
                    })
            }
            IcmpType::EchoReply => match self.protocol {
                Protocol::Icmp => {
                    let packet = EchoReplyPacket::new_view(icmp_v4.packet())?;
                    let id = packet.get_identifier();
                    let seq = packet.get_sequence();
                    let proto_resp =
                        ProtocolResponse::Icmp(IcmpProtocolResponse::new(id, seq, None));
                    Some(Response::EchoReply(
                        ResponseData::new(recv, src, proto_resp),
                        IcmpPacketCode(icmp_code.0),
                    ))
                }
                Protocol::Udp | Protocol::Tcp => None,
            },
            _ => None,
        })
    }

    #[instrument(skip(self), level = "trace")]
    fn extract_probe_proto_resp(&self, ipv4: &Ipv4Packet<'_>) -> Result<Option<ProtocolResponse>> {
        Ok(match (self.protocol, ipv4.get_protocol()) {
            (Protocol::Icmp, IpProtocol::Icmp) => {
                let echo_request = extract_echo_request(ipv4)?;
                let identifier = echo_request.get_identifier();
                let sequence = echo_request.get_sequence();
                Some(ProtocolResponse::Icmp(IcmpProtocolResponse::new(
                    identifier,
                    sequence,
                    Some(TypeOfService(ipv4.get_tos())),
                )))
            }
            (Protocol::Udp, IpProtocol::Udp) => {
                let (src_port, dest_port, actual_checksum, identifier, payload_length) =
                    extract_udp_packet(ipv4)?;
                let expected_checksum =
                    self.calc_udp_checksum(Port(src_port), Port(dest_port), payload_length)?;
                Some(ProtocolResponse::Udp(UdpProtocolResponse::new(
                    identifier,
                    IpAddr::V4(ipv4.get_destination()),
                    src_port,
                    dest_port,
                    Some(TypeOfService(ipv4.get_tos())),
                    expected_checksum,
                    actual_checksum,
                    payload_length,
                    false,
                )))
            }
            (Protocol::Tcp, IpProtocol::Tcp) => {
                let (src_port, dest_port) = extract_tcp_packet(ipv4)?;
                Some(ProtocolResponse::Tcp(TcpProtocolResponse::new(
                    IpAddr::V4(ipv4.get_destination()),
                    src_port,
                    dest_port,
                    Some(TypeOfService(ipv4.get_tos())),
                )))
            }
            _ => None,
        })
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
        icmp.set_checksum(icmp_ipv4_checksum(icmp.packet()));
        Ok(icmp)
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
        udp.set_checksum(udp_ipv4_checksum(
            udp.packet(),
            self.src_addr,
            self.dest_addr,
        ));
        Ok(udp)
    }

    /// Create an `Ipv4Packet`.
    fn make_ipv4_packet<'a>(
        &self,
        ipv4_buf: &'a mut [u8],
        protocol: IpProtocol,
        ttl: u8,
        identification: u16,
        payload: &[u8],
    ) -> Result<Ipv4Packet<'a>> {
        let ipv4_total_length = (Ipv4Packet::minimum_packet_size() + payload.len()) as u16;
        let ipv4_total_length_header = self.byte_order.adjust_length(ipv4_total_length);
        let ipv4_flags_and_fragment_offset_header = self.byte_order.adjust_length(DONT_FRAGMENT);
        let mut ipv4 = Ipv4Packet::new(&mut ipv4_buf[..ipv4_total_length as usize])?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_total_length_header);
        ipv4.set_ttl(ttl);
        ipv4.set_protocol(protocol);
        ipv4.set_source(self.src_addr);
        ipv4.set_destination(self.dest_addr);
        ipv4.set_tos(self.tos.0);
        ipv4.set_payload(payload);
        ipv4.set_identification(identification);
        ipv4.set_flags_and_fragment_offset(ipv4_flags_and_fragment_offset_header);
        Ok(ipv4)
    }

    /// Calculate the expected checksum for a UDP packet.
    ///
    /// Note that this calculation takes place for incoming UDP packet before
    /// packet validation and so this may not be a packet sent by us and so we
    /// cannot assume the payload size is within the bounds of `MAX_UDP_PAYLOAD_BUF`.
    pub fn calc_udp_checksum(
        &self,
        src_port: Port,
        dest_port: Port,
        payload_size: u16,
    ) -> Result<u16> {
        let mut udp_buf = [0_u8; MAX_UDP_PACKET_BUF];
        let size = usize::from(payload_size).min(MAX_UDP_PAYLOAD_BUF);
        let payload = &[self.payload_pattern.0; MAX_UDP_PAYLOAD_BUF][0..size];
        let udp = self.make_udp_packet(&mut udp_buf, src_port.0, dest_port.0, payload)?;
        Ok(udp.get_checksum())
    }
}

const ADDR_NOT_AVAILABLE_KIND: ErrorKind = ErrorKind::Std(io::ErrorKind::AddrNotAvailable);
const INVALID_INPUT_KIND: ErrorKind = ErrorKind::Std(io::ErrorKind::InvalidInput);

const fn icmp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv4Packet::minimum_packet_size();
    let icmp_header_size = IcmpPacket::minimum_packet_size();
    packet_size - icmp_header_size - ip_header_size
}

const fn udp_payload_size(packet_size: usize) -> usize {
    let ip_header_size = Ipv4Packet::minimum_packet_size();
    let udp_header_size = UdpPacket::minimum_packet_size();
    packet_size - udp_header_size - ip_header_size
}

#[instrument(level = "trace")]
fn extract_echo_request<'a>(ipv4: &'a Ipv4Packet<'a>) -> Result<EchoRequestPacket<'a>> {
    Ok(EchoRequestPacket::new_view(ipv4.payload())?)
}

/// Get the src and dest ports from the original `UdpPacket` packet embedded in the payload.
#[instrument(level = "trace")]
fn extract_udp_packet(ipv4: &Ipv4Packet<'_>) -> Result<(u16, u16, u16, u16, u16)> {
    let nested = UdpPacket::new_view(ipv4.payload())?;
    Ok((
        nested.get_source(),
        nested.get_destination(),
        nested.get_checksum(),
        ipv4.get_identification(),
        nested.get_length() - UdpPacket::minimum_packet_size() as u16,
    ))
}

/// Get the src and dest ports from the original `TcpPacket` packet embedded in the payload.
///
/// Unlike the embedded `ICMP` and `UDP` packets, which have a minimum header size of 8 bytes, the
/// `TCP` packet header is a minimum of 20 bytes.
///
/// The `ICMP` packets we are extracting these from, such as `TimeExceeded`, only guarantee that 8
/// bytes of the original packet (plus the IP header) be returned, and so we may not have a complete
/// TCP packet.
///
/// We therefore have to detect this situation and ensure we provide buffer a large enough for a
/// complete TCP packet header.
#[instrument(level = "trace")]
fn extract_tcp_packet(ipv4: &Ipv4Packet<'_>) -> Result<(u16, u16)> {
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
    use crate::error::IoResult;
    use crate::mocket_read;
    use crate::net::socket::MockSocket;
    use crate::{Flags, Port, RoundId, TimeToLive};
    use mockall::predicate;
    use std::str::FromStr;
    use std::sync::Mutex;

    static MTX: Mutex<()> = Mutex::new(());

    // Test dispatching a IPv4/ICMP probe.
    #[test]
    fn test_dispatch_icmp_probe_no_payload() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 1c 00 00 40 00 0a 01 00 00 01 02 03 04
            05 06 07 08 08 00 70 93 04 d2 82 9a
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

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        ipv4.dispatch_icmp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_with_payload() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(48);
        let payload_pattern = PayloadPattern(0xff);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 30 00 00 40 00 0a 01 00 00 01 02 03 04
            05 06 07 08 08 00 70 93 04 d2 82 9a ff ff ff ff
            ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
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

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        ipv4.dispatch_icmp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_invalid_packet_size_low() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(27);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let mut mocket = MockSocket::new();
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        let err = ipv4.dispatch_icmp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_invalid_packet_size_high() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(1025);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let mut mocket = MockSocket::new();
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            ..Default::default()
        };
        let err = ipv4.dispatch_icmp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_icmp_probe_with_tos() -> anyhow::Result<()> {
        let probe = make_icmp_probe();
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let tos = TypeOfService(0xE0);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 e0 00 1c 00 00 40 00 0a 01 00 00 01 02 03 04
            05 06 07 08 08 00 70 93 04 d2 82 9a
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

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            tos,
            ..Default::default()
        };
        ipv4.dispatch_icmp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_privileged_no_payload() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 1c 04 d2 40 00 0a 11 00 00 01 02 03 04
            05 06 07 08 00 7b 01 c8 00 08 ed 87
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_privileged_with_payload() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(38);
        let payload_pattern = PayloadPattern(0xaa);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 26 04 d2 40 00 0a 11 00 00 01 02 03 04
            05 06 07 08 00 7b 01 c8 00 12 98 1e aa aa aa aa
            aa aa aa aa aa aa
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_paris_privileged() -> anyhow::Result<()> {
        let probe = Probe {
            flags: Flags::PARIS_CHECKSUM,
            ..make_udp_probe(123, 456)
        };
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        // packet size and payload pattern are ignored for paris mode as a
        // fixed two byte payload is used to hold the sequence
        let packet_size = PacketSize(300);
        let payload_pattern = PayloadPattern(0xaa);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 1e 04 d2 40 00 0a 11 00 00 01 02 03 04
            05 06 07 08 00 7b 01 c8 00 0a 82 9a 6a e9
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_dublin_privileged() -> anyhow::Result<()> {
        let probe = Probe {
            // note: this is always set for UDP/Dublin but is a no-op for IPv4
            flags: Flags::DUBLIN_IPV6_PAYLOAD_LENGTH,
            identifier: TraceId(33434),
            ..make_udp_probe(123, 456)
        };
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0xaa);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 00 00 1c 82 9a 40 00 0a 11 00 00 01 02 03 04
            05 06 07 08 00 7b 01 c8 00 08 ed 87
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_unprivileged_no_payload() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Unprivileged;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!("");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);
        let expected_bind_addr = SocketAddr::new(IpAddr::V4(src_addr), 123);
        let expected_set_ttl = 10;
        let expected_set_tos = 0;

        let mut mocket = MockSocket::new();

        let ctx = MockSocket::new_udp_send_socket_ipv4_context();
        ctx.expect().with(predicate::eq(false)).returning(move |_| {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_ttl()
                .with(predicate::eq(expected_set_ttl))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_tos()
                .with(predicate::eq(expected_set_tos))
                .times(1)
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
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_unprivileged_with_payload() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Unprivileged;
        let packet_size = PacketSize(36);
        let payload_pattern = PayloadPattern(0x1f);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let expected_send_to_buf = hex_literal::hex!("1f 1f 1f 1f 1f 1f 1f 1f");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);
        let expected_bind_addr = SocketAddr::new(IpAddr::V4(src_addr), 123);
        let expected_set_ttl = 10;
        let expected_set_tos = 0;

        let mut mocket = MockSocket::new();

        let ctx = MockSocket::new_udp_send_socket_ipv4_context();
        ctx.expect().with(predicate::eq(false)).returning(move |_| {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_ttl()
                .with(predicate::eq(expected_set_ttl))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_tos()
                .with(predicate::eq(expected_set_tos))
                .times(1)
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
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_privileged_with_tos() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let tos = TypeOfService(0xE0);
        let expected_send_to_buf = hex_literal::hex!(
            "
            45 e0 00 1c 04 d2 40 00 0a 11 00 00 01 02 03 04
            05 06 07 08 00 7b 01 c8 00 08 ed 87
            "
        );
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket
            .expect_send_to()
            .with(
                predicate::eq(expected_send_to_buf),
                predicate::eq(expected_send_to_addr),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            tos,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_classic_unprivileged_with_tos() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Unprivileged;
        let packet_size = PacketSize(28);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let tos = TypeOfService(224);
        let expected_send_to_buf = hex_literal::hex!("");
        let expected_send_to_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);
        let expected_bind_addr = SocketAddr::new(IpAddr::V4(src_addr), 123);
        let expected_set_ttl = 10;
        let expected_set_tos = u32::from(tos.0);

        let mut mocket = MockSocket::new();

        let ctx = MockSocket::new_udp_send_socket_ipv4_context();
        ctx.expect().with(predicate::eq(false)).returning(move |_| {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_ttl()
                .with(predicate::eq(expected_set_ttl))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_tos()
                .with(predicate::eq(expected_set_tos))
                .times(1)
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
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            tos,
            ..Default::default()
        };
        ipv4.dispatch_udp_probe(&mut mocket, probe)?;
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_invalid_packet_size_low() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(27);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let mut mocket = MockSocket::new();
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        let err = ipv4.dispatch_udp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_udp_probe_invalid_packet_size_high() -> anyhow::Result<()> {
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let privilege_mode = PrivilegeMode::Privileged;
        let packet_size = PacketSize(1025);
        let payload_pattern = PayloadPattern(0x00);
        let byte_order = platform::Ipv4ByteOrder::Network;
        let mut mocket = MockSocket::new();
        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            byte_order,
            packet_size,
            payload_pattern,
            privilege_mode,
            ..Default::default()
        };
        let err = ipv4.dispatch_udp_probe(&mut mocket, probe).unwrap_err();
        assert!(matches!(err, Error::InvalidPacketSize(_)));
        Ok(())
    }

    #[test]
    fn test_dispatch_tcp_probe() -> anyhow::Result<()> {
        let _m = MTX.lock();
        let probe = make_udp_probe(123, 456);
        let src_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let dest_addr = Ipv4Addr::from_str("5.6.7.8")?;
        let tos = TypeOfService(224);
        let expected_bind_addr = SocketAddr::new(IpAddr::V4(src_addr), 123);
        let expected_set_ttl = 10;
        let expected_set_tos = u32::from(tos.0);
        let expected_connect_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let ctx = MockSocket::new_stream_socket_ipv4_context();
        ctx.expect().returning(move || {
            let mut mocket = MockSocket::new();
            mocket
                .expect_bind()
                .with(predicate::eq(expected_bind_addr))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_ttl()
                .with(predicate::eq(expected_set_ttl))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_set_tos()
                .with(predicate::eq(expected_set_tos))
                .times(1)
                .returning(|_| Ok(()));

            mocket
                .expect_connect()
                .with(predicate::eq(expected_connect_addr))
                .times(1)
                .returning(|_| Ok(()));

            Ok(mocket)
        });

        let ipv4 = Ipv4 {
            src_addr,
            dest_addr,
            tos,
            ..Default::default()
        };
        ipv4.dispatch_tcp_probe::<MockSocket>(&probe)?;
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_echo_reply() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 54 00 00 00 00 3b 01 50 02 8e fb de ce
            c0 a8 01 15 00 00 09 0f 75 d7 81 19 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("142.251.222.206")?), addr);
        assert_eq!(30167, identifier);
        assert_eq!(33049, sequence);
        assert_eq!(None, tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_icmp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
             45 20 00 70 07 d7 00 00 3b 01 e9 5d 8e fa 3d 81
             c0 a8 01 15 0b 00 f4 ff 00 00 00 00 45 60 00 54
             65 b0 40 00 01 01 e4 11 c0 a8 01 15 8e fb de ce
             08 00 01 11 75 d7 81 17 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("142.250.61.129")?), addr);
        assert_eq!(30167, identifier);
        assert_eq!(33047, sequence);
        assert_eq!(Some(TypeOfService(96)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_icmp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 38 00 00 40 00 70 01 33 ea 14 00 00 fe
            c0 a8 01 15 03 01 fc fe 00 00 00 00 45 00 00 54
            00 00 40 00 80 01 23 ee c0 a8 01 15 14 00 00 fe
            08 00 fb d9 7b 01 81 24
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("20.0.0.254")?), addr);
        assert_eq!(31489, identifier);
        assert_eq!(33060, sequence);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(IcmpPacketCode(1), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_udp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 c0 00 70 0e c8 00 00 40 01 e7 9e c0 a8 01 01
            c0 a8 01 15 0b 00 12 98 00 00 00 00 45 00 00 54
            90 69 00 00 01 11 0b ea c0 a8 01 15 8e fa cc 8e
            7c 55 81 06 00 40 e4 cb 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            src_addr: Ipv4Addr::from_str("192.168.1.21")?,
            dest_addr: Ipv4Addr::from_str("142.250.204.142")?,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("192.168.1.1")?), addr);
        assert_eq!(36969, identifier);
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from_str("142.250.204.142")?),
            dest_addr
        );
        assert_eq!(31829, src_port);
        assert_eq!(33030, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(58571, expected_udp_checksum);
        assert_eq!(58571, actual_udp_checksum);
        assert_eq!(56, payload_len);
        assert!(!has_magic);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_udp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 70 bc f6 00 00 39 01 f0 a7 09 09 09 09
            c0 a8 01 15 03 0a d1 16 00 00 00 00 45 20 00 54
            a2 09 00 00 01 11 43 a1 c0 a8 01 15 09 09 09 09
            80 0b 80 f2 00 40 2a a1 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            src_addr: Ipv4Addr::from_str("192.168.1.21")?,
            dest_addr: Ipv4Addr::from_str("9.9.9.9")?,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("9.9.9.9")?), addr);
        assert_eq!(41481, identifier);
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("9.9.9.9")?), dest_addr);
        assert_eq!(32779, src_port);
        assert_eq!(33010, dest_port);
        assert_eq!(Some(TypeOfService(32)), tos);
        assert_eq!(10913, expected_udp_checksum);
        assert_eq!(10913, actual_udp_checksum);
        assert_eq!(56, payload_len);
        assert!(!has_magic);
        assert_eq!(IcmpPacketCode(10), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_time_exceeded_tcp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 5c a6 9d 00 00 3b 01 54 e5 d1 55 f0 eb
            c0 a8 01 15 0b 00 12 79 00 00 00 00 45 80 00 40
            00 00 40 00 01 06 5b f2 c0 a8 01 15 8e fa cc 8e
            80 fd 00 50 61 f2 4d 4a 00 00 00 00 b0 02 ff ff
            14 05 00 00 02 04 05 b4 01 03 03 06 01 01 08 0a
            55 59 7f cd 00 00 00 00 04 02 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("209.85.240.235")?), addr);
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from_str("142.250.204.142")?),
            dest_addr
        );
        assert_eq!(33021, src_port);
        assert_eq!(80, dest_port);
        assert_eq!(Some(TypeOfService(128)), tos);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_destination_unreachable_tcp_no_extensions() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 5c d6 e0 00 00 39 01 d6 d1 09 09 09 09
            c0 a8 01 15 03 0a d0 f7 00 00 00 00 45 20 00 40
            00 00 00 00 01 06 e5 c9 c0 a8 01 15 09 09 09 09
            80 f2 27 1b 5e b1 fa c7 00 00 00 00 b0 02 ff ff
            a4 53 00 00 02 04 05 b4 01 03 03 06 01 01 08 0a
            1d 02 a0 50 00 00 00 00 04 02 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("9.9.9.9")?), addr);
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("9.9.9.9")?), dest_addr);
        assert_eq!(33010, src_port);
        assert_eq!(10011, dest_port);
        assert_eq!(Some(TypeOfService(32)), tos);
        assert_eq!(IcmpPacketCode(10), icmp_code);
        assert_eq!(None, extensions);
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_icmp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
             45 20 00 70 07 d7 00 00 3b 01 e9 5d 8e fa 3d 81
             c0 a8 01 15 0b 00 f4 ff 00 00 00 00 45 60 00 54
             65 b0 40 00 01 01 e4 11 c0 a8 01 15 8e fb de ce
             08 00 01 11 75 d7 81 17 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(3)
            .returning(mocket_read!(expected_read_buf));

        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv4 = Ipv4 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_udp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 c0 00 70 0e c8 00 00 40 01 e7 9e c0 a8 01 01
            c0 a8 01 15 0b 00 12 98 00 00 00 00 45 00 00 54
            90 69 00 00 01 11 0b ea c0 a8 01 15 8e fa cc 8e
            7c 55 81 06 00 40 e4 cb 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(3)
            .returning(mocket_read!(expected_read_buf));

        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv4 = Ipv4 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_icmp_probe_wrong_tcp_original_datagram_type_ignored() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 20 00 5c a6 9d 00 00 3b 01 54 e5 d1 55 f0 eb
            c0 a8 01 15 0b 00 12 79 00 00 00 00 45 80 00 40
            00 00 40 00 01 06 5b f2 c0 a8 01 15 8e fa cc 8e
            80 fd 00 50 61 f2 4d 4a 00 00 00 00 b0 02 ff ff
            14 05 00 00 02 04 05 b4 01 03 03 06 01 01 08 0a
            55 59 7f cd 00 00 00 00 04 02 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(3)
            .returning(mocket_read!(expected_read_buf));

        let ipv4 = Ipv4 {
            protocol: Protocol::Tcp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_some());

        let ipv4 = Ipv4 {
            protocol: Protocol::Icmp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());

        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    #[test]
    fn test_recv_tcp_socket_tcp_reply() -> anyhow::Result<()> {
        let dest_addr = Ipv4Addr::from_str("1.2.3.4")?;
        let expected_peer_addr = SocketAddr::new(IpAddr::V4(dest_addr), 456);

        let mut mocket = MockSocket::new();
        mocket.expect_take_error().times(1).returning(|| Ok(None));
        mocket
            .expect_peer_addr()
            .times(1)
            .returning(move || Ok(Some(expected_peer_addr)));
        mocket.expect_shutdown().times(1).returning(|| Ok(()));

        let ipv4 = Ipv4 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv4
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
        let dest_addr = Ipv4Addr::from_str("1.2.3.4")?;

        let mut mocket = MockSocket::new();
        mocket
            .expect_take_error()
            .times(1)
            .returning(|| Ok(Some(SocketError::ConnectionRefused)));

        let ipv4 = Ipv4 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv4
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
        let dest_addr = Ipv4Addr::from_str("1.2.3.4")?;

        let mut mocket = MockSocket::new();
        mocket
            .expect_take_error()
            .times(1)
            .returning(|| Ok(Some(SocketError::HostUnreachable)));
        mocket
            .expect_icmp_error_info()
            .times(1)
            .returning(move || Ok(IpAddr::V4(dest_addr)));

        let ipv4 = Ipv4 {
            dest_addr,
            ..Default::default()
        };
        let resp = ipv4
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

    // This IPv4/ICMP `TimeExceeded` packet has code 1 ("Fragment reassembly
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
        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            icmp_extension_mode: IcmpExtensionParseMode::Enabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?;
        assert!(resp.is_none());
        Ok(())
    }

    // This IPv4/ICMP `TimeExceeded` packet has an UDP Original Datagram
    // with a bogus length (claimed 2040 vs actual 56).
    //
    // This is a test to ensure that the UDP checksum validation is working for
    // packets which are larger than the maximum payload size.  This can occur
    // as unrelated ICMP packets are delivered to our socket and the filtering
    // occurs later on in the strategy module.
    //
    // The packet is not ignored and the UDP Original Datagram is parsed but
    // notice the expected UDP checksum does not match the actual checksum as
    // the calculation relies on the claimed payload length, which we restrict
    // to the maximum packet size we can send.
    #[test]
    fn test_recv_icmp_probe_udp_wrong_payload_size() -> anyhow::Result<()> {
        let expected_read_buf = hex_literal::hex!(
            "
            45 c0 00 70 0e c8 00 00 40 01 e7 9e c0 a8 01 01
            c0 a8 01 15 0b 00 12 98 00 00 00 00 45 00 00 54
            90 69 00 00 01 11 0b ea c0 a8 01 15 8e fa cc 8e
            7c 55 81 06 08 00 e4 cb 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
           "
        );
        let mut mocket = MockSocket::new();
        mocket
            .expect_read()
            .times(1)
            .returning(mocket_read!(expected_read_buf));
        let ipv4 = Ipv4 {
            protocol: Protocol::Udp,
            src_addr: Ipv4Addr::from_str("192.168.1.21")?,
            dest_addr: Ipv4Addr::from_str("9.9.9.9")?,
            icmp_extension_mode: IcmpExtensionParseMode::Disabled,
            ..Default::default()
        };
        let resp = ipv4.recv_icmp_probe(&mut mocket)?.unwrap();

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
        assert_eq!(IpAddr::V4(Ipv4Addr::from_str("192.168.1.1")?), addr);
        assert_eq!(36969, identifier);
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from_str("142.250.204.142")?),
            dest_addr
        );
        assert_eq!(31829, src_port);
        assert_eq!(33030, dest_port);
        assert_eq!(Some(TypeOfService(0)), tos);
        assert_eq!(9963, expected_udp_checksum);
        assert_eq!(58571, actual_udp_checksum);
        assert_eq!(2040, payload_len);
        assert!(!has_magic);
        assert_eq!(IcmpPacketCode(0), icmp_code);
        assert_eq!(None, extensions);
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
