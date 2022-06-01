use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::util::Required;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};

/// The byte order to encode the `total length` field of the IPv4 header.
///
/// To quote directly from the `mtr` source code (from `check_length_order` in `probe_unix.c`):
///
/// "Nearly all fields in the IP header should be encoded in network byte
/// order prior to passing to send().  However, the required byte order of
/// the length field of the IP header is inconsistent between operating
/// systems and operating system versions.  FreeBSD 11 requires the length
/// field in network byte order, but some older versions of FreeBSD
/// require host byte order.  OS X requires the length field in host
/// byte order.  Linux will accept either byte order."
#[derive(Debug, Copy, Clone)]
pub enum Ipv4TotalLengthByteOrder {
    #[cfg(all(unix, not(target_os = "linux")))]
    Host,
    Network,
}

/// Discover the required byte ordering for the IPv4 header field `total_length`.
///
/// This is achieved by creating a raw socket and attempting to send an `IPv4` packet to localhost with the
/// `total_length` set in either host byte order or network byte order. The OS will return an `InvalidInput` error
/// if the buffer provided is smaller than the `total_length` indicated, which will be the case when the byte order
/// is set incorrectly.
///
/// This is a little confusing as `Ipv4Packet::set_total_length` method will _always_ convert from host byte order
/// to network byte order (which will be a no-op on big-endian system) and so to test the host byte order case
/// we must ...
///
/// For example, for a packet of length 4660 bytes (dec):
///
/// For a little-endian architecture:
///
/// Try        Host (LE)    Wire (BE)   Order (if succeeds)
/// normal     34 12        12 34       `Ipv4TotalLengthByteOrder::Network`
/// swapped    12 34        34 12       `Ipv4TotalLengthByteOrder::Host`
///
/// For a big-endian architecture:
///
/// Try        Host (BE)    Wire (BE)   Order (if succeeds)
/// normal     12 34        12 34       `Ipv4TotalLengthByteOrder::Host`
/// swapped    34 12        34 12       `Ipv4TotalLengthByteOrder::Network`
///
/// TODO validate the latter cases on a BE system
/// TODO what do we do for IPv6?
#[cfg(all(unix, not(target_os = "linux")))]
pub fn discover_ip_length_byte_order(src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
    match test_send_local_ip4_packet(src_addr, 256_u16) {
        Ok(_) => Ok(Ipv4TotalLengthByteOrder::Network),
        Err(TracerError::IoError(io)) if io.kind() == ErrorKind::InvalidInput => {
            match test_send_local_ip4_packet(src_addr, 256_u16.swap_bytes()) {
                Ok(_) => Ok(Ipv4TotalLengthByteOrder::Host),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

/// Open a raw socket and attempt to send an `ICMP` packet to a local address.
///
/// The packet is actually of length `256` bytes but we set the `total_length` based on the input provided so as to
/// test if the OS rejects the attempt.
#[cfg(all(unix, not(target_os = "linux")))]
fn test_send_local_ip4_packet(src_addr: IpAddr, total_length: u16) -> TraceResult<usize> {
    let src_addr = match src_addr {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => unimplemented!(), // TODO
    };
    let mut buf = [0_u8; 256];
    let mut ipv4 = crate::tracing::packet::ipv4::Ipv4Packet::new(&mut buf).req()?;
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_protocol(crate::tracing::packet::IpProtocol::Icmp);
    ipv4.set_ttl(255);
    ipv4.set_source(src_addr);
    ipv4.set_destination(std::net::Ipv4Addr::LOCALHOST);
    ipv4.set_total_length(total_length);
    let probe_socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_RAW)),
    )?;
    probe_socket.set_header_included(true)?;
    let remote_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
    Ok(probe_socket.send_to(ipv4.packet(), &SockAddr::from(remote_addr))?)
}

/// Discover the required byte ordering for the IPv4 header field `total_length`.
///
/// Linux accepts either network byte order or host byte order for the `total_length` field and so we skip the
/// check and return network bye order unconditionally.
///
/// TODO move platform specifics into a separate module.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn discover_ip_length_byte_order(_src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
    Ok(Ipv4TotalLengthByteOrder::Network)
}
