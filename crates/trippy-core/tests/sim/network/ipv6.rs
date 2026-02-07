use crate::simulation::{Protocol, Response, Simulation, SingleHost};
use std::net::{IpAddr, Ipv6Addr};
use tracing::{debug, info};
use trippy_packet::IpProtocol;
use trippy_packet::checksum::{icmp_ipv6_checksum, tcp_ipv6_checksum};
use trippy_packet::icmpv6::destination_unreachable::DestinationUnreachablePacket;
use trippy_packet::icmpv6::echo_reply::EchoReplyPacket;
use trippy_packet::icmpv6::echo_request::EchoRequestPacket;
use trippy_packet::icmpv6::time_exceeded::TimeExceededPacket;
use trippy_packet::icmpv6::{IcmpCode, IcmpType};
use trippy_packet::ipv6::Ipv6Packet;
use trippy_packet::tcp::TcpPacket;
use trippy_packet::udp::UdpPacket;

#[expect(clippy::too_many_lines)]
pub fn process(sim: &Simulation, packet_buf: &[u8]) -> anyhow::Result<Option<(u16, Vec<u8>)>> {
    let ipv6 = Ipv6Packet::new_view(packet_buf)?;
    debug!("read: {:?}", ipv6);
    let orig_datagram_length = Ipv6Packet::minimum_packet_size() + ipv6.payload().len();
    match (ipv6.get_next_header(), sim.protocol) {
        (IpProtocol::IcmpV6, Protocol::Icmp) => {
            let echo_request = EchoRequestPacket::new_view(ipv6.payload())?;
            if echo_request.get_identifier() != sim.icmp_identifier {
                debug!(
                    "skipping EchoRequest with unexpected id (exp={} act={}))",
                    echo_request.get_identifier(),
                    sim.icmp_identifier
                );
                return Ok(None);
            }
            debug!("payload in: {:?}", echo_request);
            info!(
                "received EchoRequest with hop_limit={} id={} seq={}",
                ipv6.get_hop_limit(),
                echo_request.get_identifier(),
                echo_request.get_sequence()
            );
        }
        (IpProtocol::Udp, Protocol::Udp) => {
            let udp = UdpPacket::new_view(ipv6.payload())?;
            debug!("payload in: {:?}", udp);
            info!(
                "received UdpPacket with hop_limit={} src={} dest={}",
                ipv6.get_hop_limit(),
                udp.get_source(),
                udp.get_destination()
            );
        }
        (IpProtocol::Tcp, Protocol::Tcp) => {
            let tcp = TcpPacket::new_view(ipv6.payload())?;
            debug!("payload in: {:?}", tcp);
            info!(
                "received TcpPacket with hop_limit={} src={} dest={}",
                ipv6.get_hop_limit(),
                tcp.get_source(),
                tcp.get_destination()
            );
        }
        _ => {
            return Ok(None);
        }
    }

    // if the hop limit is greater than the largest ttl in our sim we will reply as the last node in
    // the sim
    let index = std::cmp::min(usize::from(ipv6.get_hop_limit()) - 1, sim.hops.len() - 1);
    let (reply_addr, reply_delay_ms) = match sim.hops[index].resp {
        Response::NoResponse => {
            return Ok(None);
        }
        Response::SingleHost(SingleHost {
            addr: IpAddr::V6(addr),
            rtt_ms,
        }) => (addr, rtt_ms),
        Response::SingleHost(SingleHost { addr, .. }) => anyhow::bail!(
            "invalid simulation hop {}: expected IPv6 responder, got {}",
            index + 1,
            addr
        ),
    };

    // decide what response to send
    let (next_header, payload) = if IpAddr::V6(reply_addr) == sim.target {
        match sim.protocol {
            Protocol::Icmp => {
                info!(
                    "sending ICMPv6 EchoReply from {} to {} for hop_limit {} after {}ms delay",
                    reply_addr,
                    ipv6.get_source_address(),
                    ipv6.get_hop_limit(),
                    reply_delay_ms,
                );
                let echo_request = EchoRequestPacket::new_view(ipv6.payload())?;
                let mut packet_buf = vec![0_u8; EchoReplyPacket::minimum_packet_size()];
                let packet = make_echo_reply(
                    &mut packet_buf,
                    reply_addr,
                    ipv6.get_source_address(),
                    sim.icmp_identifier,
                    echo_request.get_sequence(),
                )?;
                debug!("payload out: {:?}", packet);
                (IpProtocol::IcmpV6, packet_buf)
            }
            Protocol::Udp => {
                info!(
                    "sending ICMPv6 DestinationUnreachable from {} to {} for hop_limit {} after {}ms delay",
                    reply_addr,
                    ipv6.get_source_address(),
                    ipv6.get_hop_limit(),
                    reply_delay_ms,
                );
                let length =
                    DestinationUnreachablePacket::minimum_packet_size() + orig_datagram_length;
                let mut packet_buf = vec![0_u8; length];
                let packet = make_destination_unreachable(
                    &mut packet_buf,
                    reply_addr,
                    ipv6.get_source_address(),
                    &ipv6.packet()[..orig_datagram_length],
                )?;
                debug!("payload out: {:?}", packet);
                (IpProtocol::IcmpV6, packet_buf)
            }
            Protocol::Tcp => {
                info!(
                    "sending TCP syn+ack from {} to {} for hop_limit {} after {}ms delay",
                    reply_addr,
                    ipv6.get_source_address(),
                    ipv6.get_hop_limit(),
                    reply_delay_ms,
                );
                let tcp_in = TcpPacket::new_view(ipv6.payload())?;
                let mut packet_buf = vec![0_u8; TcpPacket::minimum_packet_size()];
                let packet = make_tcp_syn_ack(&mut packet_buf, &ipv6, &tcp_in)?;
                debug!("payload out: {:?}", packet);
                (IpProtocol::Tcp, packet_buf)
            }
        }
    } else {
        info!(
            "sending ICMPv6 TimeExceeded from {} to {} for hop_limit {} after {}ms delay",
            reply_addr,
            ipv6.get_source_address(),
            ipv6.get_hop_limit(),
            reply_delay_ms,
        );
        let length = TimeExceededPacket::minimum_packet_size() + orig_datagram_length;
        let mut packet_buf = vec![0_u8; length];
        let packet = make_time_exceeded(
            &mut packet_buf,
            reply_addr,
            ipv6.get_source_address(),
            &ipv6.packet()[..orig_datagram_length],
        )?;
        debug!("payload out: {:?}", packet);
        (IpProtocol::IcmpV6, packet_buf)
    };

    let ipv6_length = Ipv6Packet::minimum_packet_size() + payload.len();
    let mut ipv6_buf = vec![0_u8; ipv6_length];
    make_ip(
        &mut ipv6_buf,
        reply_addr,
        ipv6.get_source_address(),
        next_header,
        &payload,
    )?;
    Ok(Some((reply_delay_ms, ipv6_buf)))
}

fn make_time_exceeded<'a>(
    buf: &'a mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    payload: &[u8],
) -> anyhow::Result<TimeExceededPacket<'a>> {
    let mut packet = TimeExceededPacket::new(buf)?;
    packet.set_icmp_type(IcmpType::TimeExceeded);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_payload(payload);
    packet.set_checksum(icmp_ipv6_checksum(packet.packet(), source, destination));
    Ok(packet)
}

fn make_echo_reply(
    buf: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    icmp_identifier: u16,
    sequence: u16,
) -> anyhow::Result<EchoReplyPacket<'_>> {
    let mut packet = EchoReplyPacket::new(buf)?;
    packet.set_icmp_type(IcmpType::EchoReply);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_identifier(icmp_identifier);
    packet.set_sequence(sequence);
    packet.set_checksum(icmp_ipv6_checksum(packet.packet(), source, destination));
    Ok(packet)
}

fn make_destination_unreachable<'a>(
    buf: &'a mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    payload: &[u8],
) -> anyhow::Result<DestinationUnreachablePacket<'a>> {
    let mut packet = DestinationUnreachablePacket::new(buf)?;
    packet.set_icmp_type(IcmpType::DestinationUnreachable);
    packet.set_icmp_code(IcmpCode(4));
    packet.set_payload(payload);
    packet.set_checksum(icmp_ipv6_checksum(packet.packet(), source, destination));
    Ok(packet)
}

fn make_tcp_syn_ack<'a>(
    buf: &'a mut [u8],
    ipv6: &Ipv6Packet<'_>,
    tcp_in: &TcpPacket<'_>,
) -> anyhow::Result<TcpPacket<'a>> {
    let mut packet = TcpPacket::new(buf)?;
    packet.set_data_offset(5);
    packet.set_source(tcp_in.get_destination());
    packet.set_destination(tcp_in.get_source());
    packet.set_sequence(0);
    packet.set_acknowledgement(tcp_in.get_sequence() + 1);
    packet.set_flags(0b0001_0010);
    packet.set_window_size(0xFFFF);
    packet.set_checksum(tcp_ipv6_checksum(
        packet.packet(),
        ipv6.get_destination_address(),
        ipv6.get_source_address(),
    ));
    Ok(packet)
}

fn make_ip<'a>(
    buf: &'a mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: IpProtocol,
    payload: &[u8],
) -> anyhow::Result<Ipv6Packet<'a>> {
    let mut packet = Ipv6Packet::new(buf)?;
    packet.set_version(6);
    packet.set_traffic_class(0);
    packet.set_flow_label(0);
    packet.set_payload_length(u16::try_from(payload.len())?);
    packet.set_next_header(next_header);
    packet.set_hop_limit(64);
    packet.set_source_address(source);
    packet.set_destination_address(destination);
    packet.set_payload(payload);
    Ok(packet)
}
