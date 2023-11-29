use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{IoError, IoOperation};
use crate::tracing::error::{IoResult, TraceResult, TracerError};
use crate::tracing::net::socket::Socket;
use itertools::Itertools;
use nix::{
    sys::select::FdSet,
    sys::socket::{AddressFamily, SockaddrLike},
    sys::time::{TimeVal, TimeValLike},
    Error,
};
use socket2::{Domain, Protocol, SockAddr, Type};
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, SocketAddr};
use std::time::Duration;
use tracing::instrument;

/// The size of the test packet to use for discovering the `total_length` byte order.
#[cfg(not(target_os = "linux"))]
const TEST_PACKET_LENGTH: u16 = 256;

/// Discover the required byte ordering for the IPv4 header fields `total_length`, `flags` and
/// `fragment_offset`.
///
/// Linux accepts either network byte order or host byte order for the `total_length` field and so
/// we skip the check and return network byte order unconditionally.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

#[cfg(not(target_os = "linux"))]
#[instrument(ret)]
pub fn for_address(addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    let addr = match addr {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => return Ok(PlatformIpv4FieldByteOrder::Network),
    };
    match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH) {
        Ok(()) => Ok(PlatformIpv4FieldByteOrder::Network),
        Err(TracerError::IoError(io)) if io.kind() == std::io::ErrorKind::InvalidInput => {
            match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH.swap_bytes()) {
                Ok(()) => Ok(PlatformIpv4FieldByteOrder::Host),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

/// Attempt to send an `ICMP` packet to a local address.
///
/// The packet is actually of length `256` bytes but we set the `total_length` based on the input
/// provided so as to test if the OS rejects the attempt during the call to `send_to`.
///
/// Note that this implementation will try to create an `IPPROTO_ICMP` socket and if that fails it
/// will fallback to creating an `IPPROTO_RAW` socket.
#[cfg(not(target_os = "linux"))]
#[instrument(ret)]
fn test_send_local_ip4_packet(src_addr: Ipv4Addr, total_length: u16) -> TraceResult<()> {
    use crate::tracing::packet;
    let mut icmp_buf = [0_u8; packet::icmpv4::IcmpPacket::minimum_packet_size()];
    let mut icmp = packet::icmpv4::echo_request::EchoRequestPacket::new(&mut icmp_buf)?;
    icmp.set_icmp_type(packet::icmpv4::IcmpType::EchoRequest);
    icmp.set_icmp_code(packet::icmpv4::IcmpCode(0));
    icmp.set_identifier(0);
    icmp.set_sequence(0);
    icmp.set_checksum(packet::checksum::icmp_ipv4_checksum(icmp.packet()));
    let mut ipv4_buf = [0_u8; TEST_PACKET_LENGTH as usize];
    let mut ipv4 = packet::ipv4::Ipv4Packet::new(&mut ipv4_buf)?;
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_protocol(packet::IpProtocol::Icmp);
    ipv4.set_ttl(255);
    ipv4.set_source(src_addr);
    ipv4.set_destination(Ipv4Addr::LOCALHOST);
    ipv4.set_total_length(total_length);
    ipv4.set_payload(icmp.packet());
    let mut probe_socket = SocketImpl::new_dgram_ipv4(Protocol::ICMPV4)
        .or_else(|_| SocketImpl::new_raw_ipv4(Protocol::from(nix::libc::IPPROTO_RAW)))?;
    probe_socket.set_header_included(true)?;
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    probe_socket.send_to(ipv4.packet(), remote_addr)?;
    Ok(())
}

#[instrument(ret)]
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

#[instrument(ret)]
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
#[instrument]
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
#[instrument(ret)]
pub fn discover_local_addr(target_addr: IpAddr, port: u16) -> TraceResult<IpAddr> {
    let mut socket = match target_addr {
        IpAddr::V4(_) => SocketImpl::new_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => SocketImpl::new_udp_dgram_socket_ipv6(),
    }?;
    socket.connect(SocketAddr::new(target_addr, port))?;
    Ok(socket.local_addr()?.ok_or(TracerError::MissingAddr)?.ip())
}

/// A network socket.
pub struct SocketImpl {
    inner: socket2::Socket,
}

impl SocketImpl {
    fn new(domain: Domain, ty: Type, protocol: Protocol) -> IoResult<Self> {
        Ok(Self {
            inner: socket2::Socket::new(domain, ty, Some(protocol))
                .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?,
        })
    }

    fn new_raw_ipv4(protocol: Protocol) -> IoResult<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV4, Type::RAW, Some(protocol))
                .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?,
        })
    }

    fn new_raw_ipv6(protocol: Protocol) -> IoResult<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV6, Type::RAW, Some(protocol))
                .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?,
        })
    }

    fn new_dgram_ipv4(protocol: Protocol) -> IoResult<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(protocol))
                .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?,
        })
    }

    fn new_dgram_ipv6(protocol: Protocol) -> IoResult<Self> {
        Ok(Self {
            inner: socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(protocol))
                .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> IoResult<()> {
        self.inner
            .set_nonblocking(nonblocking)
            .map_err(|err| IoError::Other(err, IoOperation::SetNonBlocking))
    }

    fn local_addr(&self) -> IoResult<Option<SocketAddr>> {
        Ok(self
            .inner
            .local_addr()
            .map_err(|err| IoError::Other(err, IoOperation::LocalAddr))?
            .as_socket())
    }
}

impl Socket for SocketImpl {
    #[instrument]
    fn new_icmp_send_socket_ipv4(raw: bool) -> IoResult<Self> {
        if raw {
            let mut socket = Self::new_raw_ipv4(Protocol::from(nix::libc::IPPROTO_RAW))?;
            socket.set_nonblocking(true)?;
            socket.set_header_included(true)?;
            Ok(socket)
        } else {
            let mut socket = Self::new(Domain::IPV4, Type::DGRAM, Protocol::ICMPV4)?;
            socket.set_nonblocking(true)?;
            socket.set_header_included(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_icmp_send_socket_ipv6(raw: bool) -> IoResult<Self> {
        if raw {
            let socket = Self::new_raw_ipv6(Protocol::ICMPV6)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        } else {
            let socket = Self::new_dgram_ipv6(Protocol::ICMPV6)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_udp_send_socket_ipv4(raw: bool) -> IoResult<Self> {
        if raw {
            let mut socket = Self::new_raw_ipv4(Protocol::from(nix::libc::IPPROTO_RAW))?;
            socket.set_nonblocking(true)?;
            socket.set_header_included(true)?;
            Ok(socket)
        } else {
            let socket = Self::new_dgram_ipv4(Protocol::UDP)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_udp_send_socket_ipv6(raw: bool) -> IoResult<Self> {
        if raw {
            let socket = Self::new_raw_ipv6(Protocol::UDP)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        } else {
            let socket = Self::new_dgram_ipv6(Protocol::UDP)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_recv_socket_ipv4(addr: Ipv4Addr, raw: bool) -> IoResult<Self> {
        if raw {
            let mut socket = Self::new_raw_ipv4(Protocol::ICMPV4)?;
            socket.set_nonblocking(true)?;
            socket.set_header_included(true)?;
            Ok(socket)
        } else {
            let socket = Self::new(Domain::IPV4, Type::DGRAM, Protocol::ICMPV4)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_recv_socket_ipv6(addr: Ipv6Addr, raw: bool) -> IoResult<Self> {
        if raw {
            let socket = Self::new_raw_ipv6(Protocol::ICMPV6)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        } else {
            let socket = Self::new_dgram_ipv6(Protocol::ICMPV6)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
    #[instrument]
    fn new_stream_socket_ipv4() -> IoResult<Self> {
        let mut socket = Self::new(Domain::IPV4, Type::STREAM, Protocol::TCP)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        Ok(socket)
    }
    #[instrument]
    fn new_stream_socket_ipv6() -> IoResult<Self> {
        let mut socket = Self::new(Domain::IPV6, Type::STREAM, Protocol::TCP)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        Ok(socket)
    }
    #[instrument]
    fn new_udp_dgram_socket_ipv4() -> IoResult<Self> {
        Self::new_dgram_ipv4(Protocol::UDP)
    }
    #[instrument]
    fn new_udp_dgram_socket_ipv6() -> IoResult<Self> {
        Self::new_dgram_ipv6(Protocol::UDP)
    }
    #[instrument(skip(self))]
    fn bind(&mut self, address: SocketAddr) -> IoResult<()> {
        self.inner
            .bind(&SockAddr::from(address))
            .map_err(|err| IoError::Bind(err, address))
    }
    #[instrument(skip(self))]
    fn set_tos(&mut self, tos: u32) -> IoResult<()> {
        self.inner
            .set_tos(tos)
            .map_err(|err| IoError::Other(err, IoOperation::SetTos))
    }
    #[instrument(skip(self))]
    fn set_ttl(&mut self, ttl: u32) -> IoResult<()> {
        self.inner
            .set_ttl(ttl)
            .map_err(|err| IoError::Other(err, IoOperation::SetTtl))
    }
    #[instrument(skip(self))]
    fn set_reuse_port(&mut self, reuse: bool) -> IoResult<()> {
        self.inner
            .set_reuse_port(reuse)
            .map_err(|err| IoError::Other(err, IoOperation::SetReusePort))
    }
    #[instrument(skip(self))]
    fn set_header_included(&mut self, included: bool) -> IoResult<()> {
        self.inner
            .set_header_included(included)
            .map_err(|err| IoError::Other(err, IoOperation::SetHeaderIncluded))
    }
    #[instrument(skip(self))]
    fn set_unicast_hops_v6(&mut self, hops: u8) -> IoResult<()> {
        self.inner
            .set_unicast_hops_v6(u32::from(hops))
            .map_err(|err| IoError::Other(err, IoOperation::SetUnicastHopsV6))
    }
    #[instrument(skip(self))]
    fn connect(&mut self, address: SocketAddr) -> IoResult<()> {
        tracing::debug!(?address);
        self.inner
            .connect(&SockAddr::from(address))
            .map_err(|err| IoError::Connect(err, address))
    }
    #[instrument(skip(self, buf))]
    fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> IoResult<()> {
        tracing::debug!(buf = format!("{:02x?}", buf.iter().format(" ")), ?addr);
        self.inner
            .send_to(buf, &SockAddr::from(addr))
            .map_err(|err| IoError::SendTo(err, addr))?;
        Ok(())
    }
    #[instrument(skip(self))]
    fn is_readable(&mut self, timeout: Duration) -> IoResult<bool> {
        let mut read = FdSet::new();
        read.insert(&self.inner);
        let readable = nix::sys::select::select(
            None,
            Some(&mut read),
            None,
            None,
            Some(&mut TimeVal::milliseconds(timeout.as_millis() as i64)),
        );
        match readable {
            Ok(readable) => Ok(readable == 1),
            Err(Error::EINTR) => Ok(false),
            Err(err) => Err(IoError::Other(
                std::io::Error::from(err),
                IoOperation::Select,
            )),
        }
    }
    #[instrument(skip(self))]
    fn is_writable(&mut self) -> IoResult<bool> {
        let mut write = FdSet::new();
        write.insert(&self.inner);
        let writable = nix::sys::select::select(
            None,
            None,
            Some(&mut write),
            None,
            Some(&mut TimeVal::zero()),
        );
        match writable {
            Ok(writable) => Ok(writable == 1),
            Err(Error::EINTR) => Ok(false),
            Err(err) => Err(IoError::Other(
                std::io::Error::from(err),
                IoOperation::Select,
            )),
        }
    }
    #[instrument(skip(self, buf), ret)]
    fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, Option<SocketAddr>)> {
        let (bytes_read, addr) = self
            .inner
            .recv_from_into_buf(buf)
            .map_err(|err| IoError::Other(err, IoOperation::RecvFrom))?;
        tracing::debug!(
            buf = format!("{:02x?}", buf[..bytes_read].iter().format(" ")),
            bytes_read,
            ?addr
        );
        Ok((bytes_read, addr))
    }
    #[instrument(skip(self, buf), ret)]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let bytes_read = self
            .inner
            .read(buf)
            .map_err(|err| IoError::Other(err, IoOperation::Read))?;
        tracing::debug!(
            buf = format!("{:02x?}", buf[..bytes_read].iter().format(" ")),
            bytes_read
        );
        Ok(bytes_read)
    }
    #[instrument(skip(self))]
    fn shutdown(&mut self) -> IoResult<()> {
        self.inner
            .shutdown(Shutdown::Both)
            .map_err(|err| IoError::Other(err, IoOperation::Shutdown))
    }
    #[instrument(skip(self), ret)]
    fn peer_addr(&mut self) -> IoResult<Option<SocketAddr>> {
        let addr = self
            .inner
            .peer_addr()
            .map_err(|err| IoError::Other(err, IoOperation::PeerAddr))?
            .as_socket();
        tracing::debug!(?addr);
        Ok(addr)
    }
    #[instrument(skip(self), ret)]
    fn take_error(&mut self) -> IoResult<Option<io::Error>> {
        self.inner
            .take_error()
            .map_err(|err| IoError::Other(err, IoOperation::TakeError))
    }
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    #[instrument(skip(self), ret)]
    fn icmp_error_info(&mut self) -> IoResult<IpAddr> {
        Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    #[instrument(skip(self))]
    fn close(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl io::Read for SocketImpl {
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
