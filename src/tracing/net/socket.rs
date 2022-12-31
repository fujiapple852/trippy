use std::io::{Error, Result};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::time::Duration;

pub trait TracerSocket {
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
