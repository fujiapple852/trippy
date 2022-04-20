use crate::icmp::error::TraceResult;
use crate::icmp::util::Required;
use crate::icmp::Probe;
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{echo_request, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use pnet::util;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// A channel for sending and receiving `ICMP` packets.
pub struct IcmpChannel {
    tx: TransportSender,
    rx: TransportReceiver,
}

impl IcmpChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability.
    pub fn new() -> TraceResult<Self> {
        let (tx, rx) = make_icmp_channel()?;
        Ok(Self { tx, rx })
    }

    /// Send an ICMP `EchoRequest`
    pub fn send(&mut self, echo: Probe, ip: IpAddr, id: u16) -> TraceResult<()> {
        let mut buf = [0u8; 64];
        let mut req = MutableEchoRequestPacket::new(&mut buf).req()?;
        req.set_icmp_type(IcmpTypes::EchoRequest);
        req.set_icmp_code(echo_request::IcmpCodes::NoCode);
        req.set_identifier(id);
        req.set_sequence_number(echo.sequence());
        req.set_checksum(util::checksum(req.packet(), 1));
        self.tx.set_ttl(echo.ttl.0)?;
        self.tx.send_to(req.to_immutable(), ip)?;
        Ok(())
    }

    /// Receive the next Icmp packet and return an `IcmpResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    pub fn receive(&mut self, timeout: Duration) -> TraceResult<Option<IcmpResponse>> {
        Ok(
            match icmp_packet_iter(&mut self.rx).next_with_timeout(timeout)? {
                Some((icmp, ip)) => {
                    let recv = SystemTime::now();
                    match icmp.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            let packet = TimeExceededPacket::new(icmp.packet()).req()?;
                            let echo_request = extract_echo_request(packet.payload())?;
                            let identifier = echo_request.get_identifier();
                            let sequence = echo_request.get_sequence_number();
                            Some(IcmpResponse::TimeExceeded(IcmpResponseData::new(
                                recv, ip, identifier, sequence,
                            )))
                        }
                        IcmpTypes::DestinationUnreachable => {
                            let packet = DestinationUnreachablePacket::new(icmp.packet()).req()?;
                            let echo_request = extract_echo_request(packet.payload())?;
                            let identifier = echo_request.get_identifier();
                            let sequence = echo_request.get_sequence_number();
                            Some(IcmpResponse::DestinationUnreachable(IcmpResponseData::new(
                                recv, ip, identifier, sequence,
                            )))
                        }
                        IcmpTypes::EchoReply => {
                            let packet = EchoReplyPacket::new(icmp.packet()).req()?;
                            let identifier = packet.get_identifier();
                            let sequence = packet.get_sequence_number();
                            Some(IcmpResponse::EchoReply(IcmpResponseData::new(
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
}

/// The response to an ICMP `EchoRequest`.
#[derive(Debug, Copy, Clone)]
pub enum IcmpResponse {
    TimeExceeded(IcmpResponseData),
    DestinationUnreachable(IcmpResponseData),
    EchoReply(IcmpResponseData),
}

/// The data in an `IcmpResponse`.
#[derive(Debug, Copy, Clone)]
pub struct IcmpResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
}

impl IcmpResponseData {
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

/// Get the `EchoRequestPacket` packet embedded in the payload.
pub fn extract_echo_request(payload: &[u8]) -> TraceResult<EchoRequestPacket<'_>> {
    let ip4 = Ipv4Packet::new(payload).req()?;
    let header_len = usize::from(ip4.get_header_length() * 4);
    let nested_icmp = &payload[header_len..];
    let nested_echo = EchoRequestPacket::new(nested_icmp).req()?;
    Ok(nested_echo)
}
