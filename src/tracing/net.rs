use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::util::Required;
use crate::tracing::Probe;
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{echo_request, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use pnet::util;
use std::net::IpAddr;
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

/// The maximum size of TCP packet we allow.
const MAX_TCP_BUF: usize = MAX_PACKET_SIZE - Ipv4Packet::minimum_packet_size();

/// The maximum TCP payload size we allow.
const MAX_TCP_PAYLOAD_BUF: usize = MAX_UDP_BUF - TcpPacket::minimum_packet_size();

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send an `ICMP` `Probe`
    fn send_icmp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        id: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()>;

    /// Send a `UDP` `Probe`.
    fn send_udp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        source_port: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()>;

    /// Send a `TCP` `Probe`.
    fn send_tcp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        source_port: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a ICMP probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn receive_probe_response_icmp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a `Udp` probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn receive_probe_response_udp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>>;

    /// Receive the next Icmp packet and return an `IcmpResponse` for a `Tcp` probe.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn receive_probe_response_tcp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>>;
}

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    icmp_tx: TransportSender,
    icmp_rx: TransportReceiver,
    udp_tx: TransportSender,
    tcp_tx: TransportSender,
}

impl TracerChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability.
    pub fn new() -> TraceResult<Self> {
        let (icmp_tx, icmp_rx) = make_icmp_channel()?;
        let (udp_tx, _) = make_udp_channel()?;
        let (tcp_tx, _) = make_tcp_channel()?;
        Ok(Self {
            icmp_tx,
            icmp_rx,
            udp_tx,
            tcp_tx,
        })
    }
}

impl Network for TracerChannel {
    fn send_icmp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        id: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()> {
        let packet_size = usize::from(packet_size);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let icmp_header_size = EchoRequestPacket::minimum_packet_size();
        let mut icmp_buf = [0_u8; MAX_ICMP_BUF];
        let mut payload_buf = [0_u8; MAX_ICMP_PAYLOAD_BUF];
        let icmp_buf_size = packet_size - ip_header_size;
        let payload_size = packet_size - icmp_header_size - ip_header_size;
        payload_buf.iter_mut().for_each(|x| *x = payload_value);
        let mut req = MutableEchoRequestPacket::new(&mut icmp_buf[..icmp_buf_size]).req()?;
        req.set_icmp_type(IcmpTypes::EchoRequest);
        req.set_icmp_code(echo_request::IcmpCodes::NoCode);
        req.set_identifier(id);
        req.set_payload(&payload_buf[..payload_size]);
        req.set_sequence_number(probe.sequence.0);
        req.set_checksum(util::checksum(req.packet(), 1));
        self.icmp_tx.set_ttl(probe.ttl.0)?;
        self.icmp_tx.send_to(req.to_immutable(), ip)?;
        Ok(())
    }

    fn send_udp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        source_port: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()> {
        let packet_size = usize::from(packet_size);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let udp_header_size = UdpPacket::minimum_packet_size();
        let mut udp_buf = [0_u8; MAX_UDP_BUF];
        let mut payload_buf = [0_u8; MAX_UDP_PAYLOAD_BUF];
        let udp_buf_size = packet_size - ip_header_size;
        let mut udp = MutableUdpPacket::new(&mut udp_buf[..udp_buf_size]).req()?;
        udp.set_source(source_port);
        udp.set_destination(probe.sequence.0);
        let payload_size = packet_size - udp_header_size - ip_header_size;
        udp.set_length((UdpPacket::minimum_packet_size() + payload_size) as u16);
        payload_buf.iter_mut().for_each(|x| *x = payload_value);
        udp.set_payload(&payload_buf[..payload_size]);
        self.udp_tx.set_ttl(probe.ttl.0)?;
        self.udp_tx.send_to(udp.to_immutable(), ip)?;
        Ok(())
    }

    fn send_tcp_probe(
        &mut self,
        probe: Probe,
        ip: IpAddr,
        source_port: u16,
        packet_size: u16,
        payload_value: u8,
    ) -> TraceResult<()> {
        let packet_size = usize::from(packet_size);
        if packet_size > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(packet_size));
        }
        let ip_header_size = Ipv4Packet::minimum_packet_size();
        let tcp_header_size = TcpPacket::minimum_packet_size();
        let mut tcp_buf = [0_u8; MAX_TCP_BUF];
        let mut payload_buf = [0_u8; MAX_TCP_PAYLOAD_BUF];
        let tcp_buf_size = packet_size - ip_header_size;
        let payload_size = packet_size - tcp_header_size - ip_header_size;
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf[..tcp_buf_size]).req()?;
        tcp.set_source(source_port);
        tcp.set_destination(probe.sequence.0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_data_offset(5);
        payload_buf.iter_mut().for_each(|x| *x = payload_value);
        tcp.set_payload(&payload_buf[..payload_size]);
        self.tcp_tx.set_ttl(probe.ttl.0)?;
        self.tcp_tx.send_to(tcp.to_immutable(), ip)?;
        Ok(())
    }

    fn receive_probe_response_icmp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(timeout)? {
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

    fn receive_probe_response_udp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(timeout)? {
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

    fn receive_probe_response_tcp(
        &mut self,
        timeout: Duration,
    ) -> TraceResult<Option<ProbeResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.icmp_rx).next_with_timeout(timeout)? {
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
}

/// The response to a probe.
#[derive(Debug, Copy, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData),
    DestinationUnreachable(ProbeResponseData),
    EchoReply(ProbeResponseData),
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

/// Create the communication channel needed for sending and receiving ICMP packets.
pub fn make_icmp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
}

/// Create the communication channel needed for sending UDP packets.
pub fn make_udp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
}

/// Create the communication channel needed for sending TCP packets.
pub fn make_tcp_channel() -> TraceResult<(TransportSender, TransportReceiver)> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    let channel_type = TransportChannelType::Layer4(protocol);
    Ok(transport_channel(1600, channel_type)?)
}

/// Get the original `EchoRequestPacket` packet embedded in the payload.
pub fn extract_echo_request(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
    let ip4 = Ipv4Packet::new(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_icmp = &payload[header_len..];
    let nested_echo = EchoRequestPacket::new(nested_icmp).req()?;
    Ok(nested_echo)
}

/// Get the original `UdpPacket` packet embedded in the payload.
pub fn extract_udp_probe(payload: &[u8]) -> TraceResult<u16> {
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
pub fn extract_tcp_probe(payload: &[u8]) -> TraceResult<u16> {
    let ip4 = Ipv4Packet::new(payload).unwrap();
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_tcp = &payload[header_len..];
    if nested_tcp.len() < TcpPacket::minimum_packet_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        buf[..nested_tcp.len()].copy_from_slice(nested_tcp);
        Ok(TcpPacket::new(&buf).req()?.get_destination())
    } else {
        Ok(TcpPacket::new(nested_tcp).req()?.get_destination())
    }
}
