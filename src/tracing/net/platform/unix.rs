use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::socket::TracerSocket;
use crate::tracing::util::Required;
use nix::{
    sys::select::FdSet,
    sys::socket::{AddressFamily, SockaddrLike},
    sys::time::{TimeVal, TimeValLike},
};
use socket2::{Domain, Protocol, SockAddr, Type};
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// The size of the test packet to use for discovering the `total_length` byte order.
#[cfg(not(target_os = "linux"))]
const TEST_PACKET_LENGTH: u16 = 256;

/// Discover the required byte ordering for the IPv4 header fields `total_length`, `flags` and `fragment_offset`.
///
/// Linux accepts either network byte order or host byte order for the `total_length` field and so we skip the
/// check and return network byte order unconditionally.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

#[cfg(not(target_os = "linux"))]
pub fn for_address(addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    let addr = match addr {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => return Ok(PlatformIpv4FieldByteOrder::Network),
    };
    match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH) {
        Ok(_) => Ok(PlatformIpv4FieldByteOrder::Network),
        Err(TracerError::IoError(io)) if io.kind() == std::io::ErrorKind::InvalidInput => {
            match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH.swap_bytes()) {
                Ok(_) => Ok(PlatformIpv4FieldByteOrder::Host),
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
#[cfg(not(target_os = "linux"))]
fn test_send_local_ip4_packet(src_addr: Ipv4Addr, total_length: u16) -> TraceResult<usize> {
    let mut buf = [0_u8; TEST_PACKET_LENGTH as usize];
    let mut ipv4 = crate::tracing::packet::ipv4::Ipv4Packet::new(&mut buf).req()?;
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_protocol(crate::tracing::packet::IpProtocol::Icmp);
    ipv4.set_ttl(255);
    ipv4.set_source(src_addr);
    ipv4.set_destination(Ipv4Addr::LOCALHOST);
    ipv4.set_total_length(total_length);
    let probe_socket = Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        socket2::Protocol::from(nix::libc::IPPROTO_RAW),
    )?;
    probe_socket.set_header_included(true)?;
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    Ok(probe_socket.send_to(ipv4.packet(), remote_addr)?)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    nix::ifaddrs::getifaddrs()
        .map_err(|_| TracerError::UnknownInterface(name.to_string()))?
        .find_map(|ia| {
            ia.address.and_then(|addr| match addr.family() {
                Some(AddressFamily::Inet) if ia.interface_name == name => addr
                    .as_sockaddr_in()
                    .map(|sock_addr| IpAddr::V4(Ipv4Addr::from(sock_addr.ip()))),
                _ => None,
            })
        })
        .ok_or_else(|| TracerError::UnknownInterface(name.to_string()))
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    nix::ifaddrs::getifaddrs()
        .map_err(|_| TracerError::UnknownInterface(name.to_string()))?
        .find_map(|ia| {
            ia.address.and_then(|addr| match addr.family() {
                Some(AddressFamily::Inet6) if ia.interface_name == name => addr
                    .as_sockaddr_in6()
                    .map(|sock_addr| IpAddr::V6(sock_addr.ip())),
                _ => None,
            })
        })
        .ok_or_else(|| TracerError::UnknownInterface(name.to_string()))
}

#[allow(clippy::unnecessary_wraps)]
pub fn startup() -> TraceResult<()> {
    Ok(())
}

pub fn is_not_in_progress_error(code: i32) -> bool {
    nix::Error::from_i32(code) != nix::Error::EINPROGRESS
}

pub fn is_conn_refused_error(code: i32) -> bool {
    nix::Error::from_i32(code) == nix::Error::ECONNREFUSED
}

#[must_use]
pub fn is_host_unreachable_error(_code: i32) -> bool {
    false
}

/// Discover the local `IpAddr` that will be used to communicate with the given target `IpAddr`.
///
/// Note that no packets are transmitted by this method.
pub fn discover_local_addr(target_addr: IpAddr, port: u16) -> TraceResult<IpAddr> {
    let socket = match target_addr {
        IpAddr::V4(_) => Socket::new_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => Socket::new_udp_dgram_socket_ipv6(),
    }?;
    socket.connect(SocketAddr::new(target_addr, port))?;
    Ok(socket.local_addr()?.req()?.ip())
}

/// A network socket.
#[derive(Debug)]
pub struct Socket {
    inner: socket2::Socket,
}

impl Socket {
    fn new(domain: Domain, ty: Type, protocol: Protocol) -> io::Result<Self> {
        Ok(Self {
            inner: socket2::Socket::new(domain, ty, Some(protocol))?,
        })
    }

    fn new_raw_ipv4(protocol: Protocol) -> io::Result<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV4, Type::RAW, Some(protocol))?,
        })
    }

    fn new_raw_ipv6(protocol: Protocol) -> io::Result<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV6, Type::RAW, Some(protocol))?,
        })
    }
}

impl TracerSocket for Socket {
    fn new_icmp_send_socket_ipv4() -> io::Result<Self> {
        let socket = Self::new_raw_ipv4(Protocol::from(nix::libc::IPPROTO_RAW))?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }
    fn new_icmp_send_socket_ipv6() -> io::Result<Self> {
        let socket = Self::new_raw_ipv6(Protocol::ICMPV6)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    fn new_udp_send_socket_ipv4() -> io::Result<Self> {
        let socket = Self::new_raw_ipv4(Protocol::from(nix::libc::IPPROTO_RAW))?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }
    fn new_udp_send_socket_ipv6() -> io::Result<Self> {
        let socket = Self::new_raw_ipv6(Protocol::UDP)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    fn new_recv_socket_ipv4(_addr: Ipv4Addr) -> io::Result<Self> {
        let socket = Self::new_raw_ipv4(Protocol::ICMPV4)?;
        socket.set_nonblocking(true)?;
        socket.set_header_included(true)?;
        Ok(socket)
    }
    fn new_recv_socket_ipv6(_addr: Ipv6Addr) -> io::Result<Self> {
        let socket = Self::new_raw_ipv6(Protocol::ICMPV6)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    fn new_stream_socket_ipv4() -> io::Result<Self> {
        let socket = Self::new(Domain::IPV4, Type::STREAM, Protocol::TCP)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        Ok(socket)
    }
    fn new_stream_socket_ipv6() -> io::Result<Self> {
        let socket = Self::new(Domain::IPV6, Type::STREAM, Protocol::TCP)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        Ok(socket)
    }
    fn new_udp_dgram_socket_ipv4() -> io::Result<Self> {
        Self::new(Domain::IPV4, Type::DGRAM, Protocol::UDP)
    }
    fn new_udp_dgram_socket_ipv6() -> io::Result<Self> {
        Self::new(Domain::IPV6, Type::DGRAM, Protocol::UDP)
    }
    fn bind(&mut self, address: SocketAddr) -> io::Result<()> {
        self.inner.bind(&SockAddr::from(address))
    }
    fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.inner.set_tos(tos)
    }
    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }
    fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        self.inner.set_reuse_port(reuse)
    }
    fn set_header_included(&self, included: bool) -> io::Result<()> {
        self.inner.set_header_included(included)
    }
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
    fn set_unicast_hops_v6(&self, hops: u8) -> io::Result<()> {
        self.inner.set_unicast_hops_v6(u32::from(hops))
    }
    fn connect(&self, address: SocketAddr) -> io::Result<()> {
        self.inner.connect(&SockAddr::from(address))
    }
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, &SockAddr::from(addr))
    }
    fn is_readable(&self, timeout: Duration) -> io::Result<bool> {
        let mut read = FdSet::new();
        read.insert(self.inner.as_raw_fd());
        let readable = nix::sys::select::select(
            None,
            Some(&mut read),
            None,
            None,
            Some(&mut TimeVal::milliseconds(timeout.as_millis() as i64)),
        )?;
        Ok(readable == 1)
    }
    fn is_writable(&self) -> io::Result<bool> {
        let mut write = FdSet::new();
        write.insert(self.inner.as_raw_fd());
        let writable = nix::sys::select::select(
            None,
            None,
            Some(&mut write),
            None,
            Some(&mut TimeVal::zero()),
        )?;
        Ok(writable == 1)
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        self.inner.recv_from_into_buf(buf)
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.inner.local_addr()?.as_socket())
    }
    fn peer_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.inner.peer_addr()?.as_socket())
    }
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn icmp_error_info(&self) -> io::Result<IpAddr> {
        Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

/// An extension trait to allow `recv_from` method which writes to a `&mut [u8]`.
///
/// This is required for `socket2::Socket` which [does not currently provide] this method.
///
/// [does not currently provide]: https://github.com/rust-lang/socket2/issues/223
trait RecvFrom {
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)>;
}

impl RecvFrom for socket2::Socket {
    // Safety: the `recv` implementation promises not to write uninitialised
    // bytes to the `buf`fer, so this casting is safe.
    #![allow(unsafe_code)]
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
        self.recv_from(buf)
            .map(|(size, addr)| (size, addr.as_socket()))
    }
}
