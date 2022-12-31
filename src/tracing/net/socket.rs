use std::io::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::Duration;

pub trait TracerSocket
where
    Self: Sized,
{
    /// Create an IPv4 socket for sending ICMP probes.
    fn new_icmp_send_socket_ipv4() -> Result<Self>;
    /// Create an IPv6 socket for sending ICMP probes.
    fn new_icmp_send_socket_ipv6() -> Result<Self>;
    /// Create an IPv4 socket for sending UDP probes.
    fn new_udp_send_socket_ipv4() -> Result<Self>;
    /// Create an IPv6 socket for sending UDP probes.
    fn new_udp_send_socket_ipv6() -> Result<Self>;
    /// Create an IPv4 socket for receiving UDP probe responses.
    fn new_recv_socket_ipv4(addr: Ipv4Addr) -> Result<Self>;
    /// Create an IPv6 socket for receiving UDP probe responses.
    fn new_recv_socket_ipv6(addr: Ipv6Addr) -> Result<Self>;
    /// Create a IPv4/TCP socket for sending TCP probes.
    fn new_stream_socket_ipv4() -> Result<Self>;
    /// Create a IPv6/TCP socket for sending TCP probes.
    fn new_stream_socket_ipv6() -> Result<Self>;
    /// Create (non-raw) IPv4/UDP socket for local address validation.
    fn new_udp_dgram_socket_ipv4() -> Result<Self>;
    /// Create (non-raw) IPv6/UDP socket for local address validation.
    fn new_udp_dgram_socket_ipv6() -> Result<Self>;
    fn bind(&mut self, address: SocketAddr) -> Result<()>;
    fn set_tos(&self, tos: u32) -> Result<()>;
    fn set_ttl(&self, ttl: u32) -> Result<()>;
    fn set_reuse_port(&self, reuse: bool) -> Result<()>;
    fn set_header_included(&self, included: bool) -> Result<()>;
    fn set_nonblocking(&self, nonblocking: bool) -> Result<()>;
    fn set_unicast_hops_v6(&self, hops: u8) -> Result<()>;
    fn connect(&self, address: SocketAddr) -> Result<()>;
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;
    /// Returns true if the socket becomes readable before the timeout, false otherwise.
    fn is_readable(&self, timeout: Duration) -> Result<bool>;
    /// Returns true if the socket is currently writeable, false otherwise.
    fn is_writable(&self) -> Result<bool>;
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>)>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn shutdown(&self, how: Shutdown) -> Result<()>;
    fn local_addr(&self) -> Result<Option<SocketAddr>>;
    fn peer_addr(&self) -> Result<Option<SocketAddr>>;
    fn take_error(&self) -> Result<Option<Error>>;
    fn icmp_error_info(&self) -> Result<IpAddr>;
    fn close(&self) -> Result<()>;
}
