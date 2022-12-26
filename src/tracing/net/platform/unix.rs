use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use nix::{
    sys::select::FdSet,
    sys::socket::{AddressFamily, SockaddrLike},
    sys::time::{TimeVal, TimeValLike},
};
use socket2::{Domain, Protocol, SockAddr, Type};
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::net::{Shutdown, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
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
    use crate::tracing::util::Required;
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
        Some(socket2::Protocol::from(nix::libc::IPPROTO_RAW)),
    )?;
    probe_socket.set_header_included(true)?;
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    Ok(probe_socket.send_to(ipv4.packet(), remote_addr)?)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    nix::ifaddrs::getifaddrs()
        .map_err(|_| TracerError::UnknownInterface(name.to_string()))?
        .into_iter()
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
        .into_iter()
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

pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_RAW)),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(nix::libc::IPPROTO_RAW)),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

pub fn make_recv_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

pub fn make_udp_dgram_socket_ipv4() -> TraceResult<Socket> {
    Ok(Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?)
}

/// Create a IPv4/TCP socket.
pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    Ok(socket)
}

pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn make_recv_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub fn make_udp_dgram_socket_ipv6() -> TraceResult<Socket> {
    Ok(Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?)
}

/// Create a IPv6/TCP socket.
pub fn make_stream_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    Ok(socket)
}

/// Returns true if the socket becomes readable before the timeout, false otherwise.
pub fn is_readable(sock: &Socket, timeout: Duration) -> TraceResult<bool> {
    let mut read = FdSet::new();
    read.insert(sock.as_raw_fd());
    let readable = nix::sys::select::select(
        None,
        Some(&mut read),
        None,
        None,
        Some(&mut TimeVal::milliseconds(timeout.as_millis() as i64)),
    )
    .map_err(|err| TracerError::IoError(std::io::Error::from(err)))?;
    Ok(readable == 1)
}

/// Returns true if the socket is currently writeable, false otherwise.
pub fn is_writable(sock: &Socket) -> TraceResult<bool> {
    let mut write = FdSet::new();
    write.insert(sock.as_raw_fd());
    let writable = nix::sys::select::select(
        None,
        None,
        Some(&mut write),
        None,
        Some(&mut TimeVal::zero()),
    )
    .map_err(|err| TracerError::IoError(std::io::Error::from(err)))?;
    Ok(writable == 1)
}

pub fn is_not_in_progress_error(code: i32) -> bool {
    nix::Error::from_i32(code) != nix::Error::EINPROGRESS
}

pub fn is_conn_refused_error(code: i32) -> bool {
    nix::Error::from_i32(code) == nix::Error::ECONNREFUSED
}

/// A network socket.
#[derive(Debug)]
pub struct Socket {
    inner: socket2::Socket,
}

impl Socket {
    pub fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        Ok(Self {
            inner: socket2::Socket::new(domain, ty, protocol)?,
        })
    }

    pub fn bind(&self, address: SocketAddr) -> io::Result<()> {
        self.inner.bind(&SockAddr::from(address))
    }

    pub fn set_tos(&self, tos: u32) -> io::Result<()> {
        self.inner.set_tos(tos)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    pub fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        self.inner.set_reuse_port(reuse)
    }

    pub fn set_header_included(&self, included: bool) -> io::Result<()> {
        self.inner.set_header_included(included)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub fn set_unicast_hops_v6(&self, hops: u32) -> io::Result<()> {
        self.inner.set_unicast_hops_v6(hops)
    }

    pub fn connect(&self, address: SocketAddr) -> io::Result<()> {
        self.inner.connect(&SockAddr::from(address))
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, &SockAddr::from(addr))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        self.inner.recv_from_into_buf(buf)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.inner.local_addr()?.as_socket())
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    #[allow(dead_code)]
    pub fn unicast_hops_v6(&self) -> io::Result<u32> {
        self.inner.unicast_hops_v6()
    }

    pub fn peer_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.inner.peer_addr()?.as_socket())
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    #[allow(dead_code)]
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
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
