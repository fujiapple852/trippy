use crate::simulation::{Protocol, Response, Simulation, SingleHost};
use crate::tun_device::TunDevice;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use trippy_packet::checksum::{icmp_ipv4_checksum, ipv4_header_checksum, tcp_ipv4_checksum};
use trippy_packet::icmpv4::destination_unreachable::DestinationUnreachablePacket;
use trippy_packet::icmpv4::echo_reply::EchoReplyPacket;
use trippy_packet::icmpv4::echo_request::EchoRequestPacket;
use trippy_packet::icmpv4::time_exceeded::TimeExceededPacket;
use trippy_packet::icmpv4::{IcmpCode, IcmpType};
use trippy_packet::ipv4::Ipv4Packet;
use trippy_packet::tcp::TcpPacket;
use trippy_packet::udp::UdpPacket;
use trippy_packet::IpProtocol;

const READ_TIMEOUT: Duration = Duration::from_millis(10);

#[expect(clippy::too_many_lines)]
pub async fn run(
    tun: Arc<Mutex<TunDevice>>,
    sim: Arc<Simulation>,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let mut handles: Vec<JoinHandle<()>> = vec![];
    loop {
        let mut buf = [0_u8; 4096];
        let bytes_read = {
            let tun = tun.clone();
            tokio::select!(
                () = token.cancelled() => {
                    handles.into_iter().for_each(|h| h.abort());
                    return Ok(())
                },
                bytes_read = read_with_timeout(&mut buf, tun) => {
                    bytes_read?
                },
            )
        };
        if bytes_read == 0 {
            continue;
        }
        let ipv4 = Ipv4Packet::new_view(&buf[..bytes_read])?;
        if ipv4.get_version() != 4 {
            debug!("skipping ipv6 packet");
            continue;
        }
        debug!("read: {:?}", ipv4);

        let orig_datagram_length = usize::from(ipv4.get_header_length() * 4) + 8;

        match (ipv4.get_protocol(), sim.protocol) {
            (IpProtocol::Icmp, Protocol::Icmp) => {
                let echo_request = EchoRequestPacket::new_view(ipv4.payload())?;
                if echo_request.get_identifier() != sim.icmp_identifier {
                    debug!(
                        "skipping EchoRequest with unexpected id (exp={} act={}))",
                        echo_request.get_identifier(),
                        sim.icmp_identifier
                    );
                    continue;
                }
                debug!("payload in: {:?}", echo_request);
                info!(
                    "received EchoRequest with ttl={} id={} seq={}",
                    ipv4.get_ttl(),
                    echo_request.get_identifier(),
                    echo_request.get_sequence()
                );
            }
            (IpProtocol::Udp, Protocol::Udp) => {
                let udp = UdpPacket::new_view(ipv4.payload())?;
                debug!("payload in: {:?}", udp);
                info!(
                    "received UdpPacket with ttl={} src={} dest={}",
                    ipv4.get_ttl(),
                    udp.get_source(),
                    udp.get_destination()
                );
            }
            (IpProtocol::Tcp, Protocol::Tcp) => {
                let tcp = TcpPacket::new_view(ipv4.payload())?;
                debug!("payload in: {:?}", tcp);
                info!(
                    "received TcpPacket with ttl={} src={} dest={}",
                    ipv4.get_ttl(),
                    tcp.get_source(),
                    tcp.get_destination()
                );
            }
            _ => {
                continue;
            }
        }

        // if the ttl is greater than the largest ttl in our simulation we will reply as the last node in
        // the simulation
        let index = std::cmp::min(usize::from(ipv4.get_ttl()) - 1, sim.hops.len() - 1);
        let (reply_addr, reply_delay_ms) = match sim.hops[index].resp {
            Response::NoResponse => {
                continue;
            }
            Response::SingleHost(SingleHost {
                addr: IpAddr::V4(addr),
                rtt_ms,
            }) => (addr, rtt_ms),
            Response::SingleHost(_) => unimplemented!(),
        };

        // decide what response to send
        let (protocol, payload) = if IpAddr::V4(reply_addr) == sim.target {
            match sim.protocol {
                Protocol::Icmp => {
                    info!(
                        "sending ICMP EchoReply from {} to {} for ttl {} after {}ms delay",
                        reply_addr,
                        ipv4.get_source(),
                        ipv4.get_ttl(),
                        reply_delay_ms,
                    );
                    let echo_request = EchoRequestPacket::new_view(ipv4.payload())?;
                    let mut packet_buf = vec![0_u8; EchoReplyPacket::minimum_packet_size()];
                    let packet = make_echo_reply_v4(
                        &mut packet_buf,
                        sim.icmp_identifier,
                        echo_request.get_sequence(),
                    )?;
                    debug!("payload out: {:?}", packet);
                    (IpProtocol::Icmp, packet_buf)
                }
                Protocol::Udp => {
                    info!(
                        "sending ICMP DestinationUnreachable from {} to {} for ttl {} after {}ms delay",
                        reply_addr,
                        ipv4.get_source(),
                        ipv4.get_ttl(),
                        reply_delay_ms,
                    );
                    let length =
                        DestinationUnreachablePacket::minimum_packet_size() + orig_datagram_length;
                    let mut packet_buf = vec![0_u8; length];
                    let packet = make_destination_unreachable_v4(
                        &mut packet_buf,
                        &ipv4.packet()[..orig_datagram_length],
                    )?;
                    debug!("payload out: {:?}", packet);
                    (IpProtocol::Icmp, packet_buf)
                }
                Protocol::Tcp => {
                    info!(
                        "sending TCP syn+ack from {} to {} for ttl {} after {}ms delay",
                        reply_addr,
                        ipv4.get_source(),
                        ipv4.get_ttl(),
                        reply_delay_ms,
                    );
                    let tcp_in = TcpPacket::new_view(ipv4.payload())?;
                    let mut packet_buf = vec![0_u8; TcpPacket::minimum_packet_size()];
                    let packet = make_tcp_syn_ack(&mut packet_buf, &ipv4, &tcp_in)?;
                    debug!("payload out: {:?}", packet);
                    (IpProtocol::Tcp, packet_buf)
                }
            }
        } else {
            info!(
                "sending ICMP TimeExceeded from {} to {} for ttl {} after {}ms delay",
                reply_addr,
                ipv4.get_source(),
                ipv4.get_ttl(),
                reply_delay_ms,
            );
            let length = TimeExceededPacket::minimum_packet_size() + orig_datagram_length;
            let mut packet_buf = vec![0_u8; length];
            let packet =
                make_time_exceeded_v4(&mut packet_buf, &ipv4.packet()[..orig_datagram_length])?;
            debug!("payload out: {:?}", packet);
            (IpProtocol::Icmp, packet_buf)
        };

        let ipv4_length = Ipv4Packet::minimum_packet_size() + payload.len();
        let mut ipv4_buf = vec![0_u8; ipv4_length];
        make_ip_v4(
            &mut ipv4_buf,
            reply_addr,
            ipv4.get_source(),
            protocol,
            &payload,
        )?;

        let handle = {
            let tun = tun.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(u64::from(reply_delay_ms))).await;
                let ipv4 = Ipv4Packet::new_view(&ipv4_buf).unwrap();
                debug!("write: {:?}", ipv4);
                tun.lock().await.write(ipv4.packet()).await.expect("send");
            })
        };
        handles.push(handle);
    }
}

/// Read from the tun device with a timeout.
///
/// Note that the tun device is only locked for the timeout period
async fn read_with_timeout(buf: &mut [u8], tun: Arc<Mutex<TunDevice>>) -> io::Result<usize> {
    tokio::time::timeout(READ_TIMEOUT, tun.lock().await.read(buf))
        .await
        .unwrap_or(Ok(0))
}

fn make_time_exceeded_v4<'a>(
    buf: &'a mut [u8],
    payload: &[u8],
) -> anyhow::Result<TimeExceededPacket<'a>> {
    let mut packet = TimeExceededPacket::new(buf)?;
    packet.set_icmp_type(IcmpType::TimeExceeded);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_payload(payload);
    packet.set_checksum(icmp_ipv4_checksum(packet.packet()));
    Ok(packet)
}

fn make_echo_reply_v4(
    buf: &mut [u8],
    icmp_identifier: u16,
    sequence: u16,
) -> anyhow::Result<EchoReplyPacket<'_>> {
    let mut packet = EchoReplyPacket::new(buf)?;
    packet.set_icmp_type(IcmpType::EchoReply);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_identifier(icmp_identifier);
    packet.set_sequence(sequence);
    packet.set_checksum(icmp_ipv4_checksum(packet.packet()));
    Ok(packet)
}

fn make_destination_unreachable_v4<'a>(
    buf: &'a mut [u8],
    payload: &[u8],
) -> anyhow::Result<DestinationUnreachablePacket<'a>> {
    let mut packet = DestinationUnreachablePacket::new(buf)?;
    packet.set_icmp_type(IcmpType::DestinationUnreachable);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_payload(payload);
    packet.set_checksum(icmp_ipv4_checksum(packet.packet()));
    Ok(packet)
}

fn make_tcp_syn_ack<'a>(
    buf: &'a mut [u8],
    ipv4: &Ipv4Packet<'_>,
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
    packet.set_checksum(tcp_ipv4_checksum(
        packet.packet(),
        ipv4.get_destination(),
        ipv4.get_source(),
    ));
    Ok(packet)
}

fn make_ip_v4<'a>(
    buf: &'a mut [u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpProtocol,
    payload: &[u8],
) -> anyhow::Result<Ipv4Packet<'a>> {
    let ipv4_total_length = buf.len();
    let mut packet = Ipv4Packet::new(buf)?;
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_protocol(protocol);
    packet.set_ttl(64);
    packet.set_source(source);
    packet.set_destination(destination);
    packet.set_total_length(u16::try_from(ipv4_total_length)?);
    packet.set_checksum(ipv4_header_checksum(
        &packet.packet()[..Ipv4Packet::minimum_packet_size()],
    ));
    packet.set_payload(payload);
    Ok(packet)
}
