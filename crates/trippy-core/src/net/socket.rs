use crate::error::IoResult as Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[cfg_attr(test, mockall::automock)]
pub trait Socket
where
    Self: Sized,
{
    /// Create an IPv4 socket for sending ICMP probes.
    fn new_icmp_send_socket_ipv4(raw: bool) -> Result<Self>;
    /// Create an IPv6 socket for sending ICMP probes.
    fn new_icmp_send_socket_ipv6(raw: bool) -> Result<Self>;
    /// Create an IPv4 socket for sending UDP probes.
    fn new_udp_send_socket_ipv4(raw: bool) -> Result<Self>;
    /// Create an IPv6 socket for sending UDP probes.
    fn new_udp_send_socket_ipv6(raw: bool) -> Result<Self>;
    /// Create an IPv4 socket for receiving UDP probe responses.
    fn new_recv_socket_ipv4(addr: Ipv4Addr, raw: bool) -> Result<Self>;
    /// Create an IPv6 socket for receiving UDP probe responses.
    fn new_recv_socket_ipv6(addr: Ipv6Addr, raw: bool) -> Result<Self>;
    /// Create a IPv4/TCP socket for sending TCP probes.
    fn new_stream_socket_ipv4() -> Result<Self>;
    /// Create a IPv6/TCP socket for sending TCP probes.
    fn new_stream_socket_ipv6() -> Result<Self>;
    /// Create (non-raw) IPv4/UDP socket for local address validation.
    fn new_udp_dgram_socket_ipv4() -> Result<Self>;
    /// Create (non-raw) IPv6/UDP socket for local address validation.
    fn new_udp_dgram_socket_ipv6() -> Result<Self>;
    fn bind(&mut self, address: SocketAddr) -> Result<()>;
    fn set_tos(&mut self, tos: u32) -> Result<()>;
    fn set_tclass_v6(&mut self, tclass: u32) -> Result<()>;
    fn set_ttl(&mut self, ttl: u32) -> Result<()>;
    fn set_reuse_port(&mut self, reuse: bool) -> Result<()>;
    fn set_header_included(&mut self, included: bool) -> Result<()>;
    fn set_unicast_hops_v6(&mut self, hops: u8) -> Result<()>;
    fn connect(&mut self, address: SocketAddr) -> Result<()>;
    fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<()>;
    /// Returns true if the socket becomes readable before the timeout, false otherwise.
    fn is_readable(&mut self, timeout: Duration) -> Result<bool>;
    /// Returns true if the socket is currently writable, false otherwise.
    fn is_writable(&mut self) -> Result<bool>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>)>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn shutdown(&mut self) -> Result<()>;
    fn peer_addr(&mut self) -> Result<Option<SocketAddr>>;
    fn take_error(&mut self) -> Result<Option<SocketError>>;
    fn icmp_error_info(&mut self) -> Result<IpAddr>;
}

/// A socket error returned by `Socket::take_error`.
#[derive(Debug)]
pub enum SocketError {
    ConnectionRefused,
    #[allow(dead_code)]
    HostUnreachable,
    Other(#[expect(dead_code)] std::io::Error),
}

#[cfg(test)]
pub mod tests {
    #[macro_export]
    macro_rules! mocket_read {
        ($packet: expr) => {
            move |buf: &mut [u8]| -> IoResult<usize> {
                buf[..$packet.len()].copy_from_slice(&$packet);
                Ok(buf.len())
            }
        };
    }

    #[macro_export]
    macro_rules! mocket_recv_from {
        ($packet: expr, $addr: expr) => {
            move |buf: &mut [u8]| -> IoResult<(usize, Option<SocketAddr>)> {
                buf[..$packet.len()].copy_from_slice(&$packet);
                Ok((buf.len(), Some($addr)))
            }
        };
    }
}
