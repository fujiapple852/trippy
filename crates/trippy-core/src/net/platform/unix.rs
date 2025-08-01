use crate::error::Result;
use crate::net::platform::{Ipv4ByteOrder, Platform};
use std::net::IpAddr;

pub struct PlatformImpl;

impl Platform for PlatformImpl {
    fn byte_order_for_address(addr: IpAddr) -> Result<Ipv4ByteOrder> {
        address::for_address(addr)
    }
    fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
        address::lookup_interface_addr(addr, name)
    }
    fn discover_local_addr(target_addr: IpAddr, port: u16) -> Result<IpAddr> {
        address::discover_local_addr(target_addr, port)
    }
}

mod address {
    use crate::error::{Error, Result};
    use crate::net::platform::Ipv4ByteOrder;
    use crate::net::socket::Socket;
    use crate::net::SocketImpl;
    use nix::sys::socket::{AddressFamily, SockaddrLike};
    use std::net::{IpAddr, SocketAddr};
    use tracing::instrument;

    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv4Addr;

    /// The size of the test packet to use for discovering the `total_length` byte order.
    #[cfg(not(target_os = "linux"))]
    const TEST_PACKET_LENGTH: u16 = 256;

    /// Discover the required byte ordering for the IPv4 header fields `total_length`, `flags` and
    /// `fragment_offset`.
    ///
    /// Linux accepts either network byte order or host byte order for the `total_length` field, and
    /// so we skip the check and return network byte order unconditionally.
    #[cfg(target_os = "linux")]
    #[expect(clippy::unnecessary_wraps)]
    pub const fn for_address(_src_addr: IpAddr) -> Result<Ipv4ByteOrder> {
        Ok(Ipv4ByteOrder::Network)
    }

    #[cfg(not(target_os = "linux"))]
    #[instrument(ret, level = "trace")]
    pub fn for_address(addr: IpAddr) -> Result<Ipv4ByteOrder> {
        let addr = match addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Ok(Ipv4ByteOrder::Network),
        };
        match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH) {
            Ok(()) => Ok(Ipv4ByteOrder::Network),
            Err(Error::IoError(io))
                if io.kind() == crate::error::ErrorKind::Std(std::io::ErrorKind::InvalidInput) =>
            {
                match test_send_local_ip4_packet(addr, TEST_PACKET_LENGTH.swap_bytes()) {
                    Ok(()) => Ok(Ipv4ByteOrder::Host),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Attempt to send an `ICMP` packet to a local address.
    ///
    /// The packet is actually of length `256` bytes, but we set the `total_length` based on the
    /// input provided to test if the OS rejects the attempt during the call to `send_to`.
    ///
    /// Note that this implementation will try to create an `IPPROTO_ICMP` socket and if that fails
    /// it will fall back to creating an `IPPROTO_RAW` socket.
    #[cfg(not(target_os = "linux"))]
    #[instrument(ret, level = "trace")]
    fn test_send_local_ip4_packet(src_addr: Ipv4Addr, total_length: u16) -> Result<()> {
        use socket2::Protocol;
        let mut icmp_buf = [0_u8; trippy_packet::icmpv4::IcmpPacket::minimum_packet_size()];
        let mut icmp = trippy_packet::icmpv4::echo_request::EchoRequestPacket::new(&mut icmp_buf)?;
        icmp.set_icmp_type(trippy_packet::icmpv4::IcmpType::EchoRequest);
        icmp.set_icmp_code(trippy_packet::icmpv4::IcmpCode(0));
        icmp.set_identifier(0);
        icmp.set_sequence(0);
        icmp.set_checksum(trippy_packet::checksum::icmp_ipv4_checksum(icmp.packet()));
        let mut ipv4_buf = [0_u8; TEST_PACKET_LENGTH as usize];
        let mut ipv4 = trippy_packet::ipv4::Ipv4Packet::new(&mut ipv4_buf)?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_protocol(trippy_packet::IpProtocol::Icmp);
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

    pub fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
        match addr {
            IpAddr::V4(_) => lookup_interface_addr_ipv4(name),
            IpAddr::V6(_) => lookup_interface_addr_ipv6(name),
        }
    }

    #[instrument(ret, level = "trace")]
    fn lookup_interface_addr_ipv4(name: &str) -> Result<IpAddr> {
        nix::ifaddrs::getifaddrs()
            .map_err(|_| Error::UnknownInterface(name.to_string()))?
            .find_map(|ia| {
                ia.address.and_then(|addr| match addr.family() {
                    Some(AddressFamily::Inet) if ia.interface_name == name => addr
                        .as_sockaddr_in()
                        .map(|sock_addr| IpAddr::V4(sock_addr.ip())),
                    _ => None,
                })
            })
            .ok_or_else(|| Error::UnknownInterface(name.to_string()))
    }

    #[instrument(ret, level = "trace")]
    fn lookup_interface_addr_ipv6(name: &str) -> Result<IpAddr> {
        nix::ifaddrs::getifaddrs()
            .map_err(|_| Error::UnknownInterface(name.to_string()))?
            .find_map(|ia| {
                ia.address.and_then(|addr| match addr.family() {
                    Some(AddressFamily::Inet6) if ia.interface_name == name => addr
                        .as_sockaddr_in6()
                        .map(|sock_addr| IpAddr::V6(sock_addr.ip())),
                    _ => None,
                })
            })
            .ok_or_else(|| Error::UnknownInterface(name.to_string()))
    }

    // Note that no packets are transmitted by this method.
    #[instrument(ret, level = "trace")]
    pub fn discover_local_addr(target_addr: IpAddr, port: u16) -> Result<IpAddr> {
        let mut socket = match target_addr {
            IpAddr::V4(_) => SocketImpl::new_udp_dgram_socket_ipv4(),
            IpAddr::V6(_) => SocketImpl::new_udp_dgram_socket_ipv6(),
        }?;
        socket.connect(SocketAddr::new(target_addr, port))?;
        Ok(socket.local_addr()?.ok_or(Error::MissingAddr)?.ip())
    }
}

mod socket {
    use crate::error::{ErrorKind, IoError, IoOperation};
    use crate::error::{IoResult, Result};
    use crate::net::socket::{Socket, SocketError};
    use itertools::Itertools;
    use nix::{
        sys::select::FdSet,
        sys::time::{TimeVal, TimeValLike},
        Error,
    };
    use socket2::{Domain, Protocol, SockAddr, Type};
    use std::io;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::net::{Shutdown, SocketAddr};
    use std::os::fd::AsFd;
    use std::time::Duration;
    use tracing::instrument;

    #[instrument(level = "trace")]
    pub fn startup() -> Result<()> {
        Ok(())
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

        pub(super) fn new_raw_ipv4(protocol: Protocol) -> IoResult<Self> {
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

        pub(super) fn new_dgram_ipv4(protocol: Protocol) -> IoResult<Self> {
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

        pub(super) fn local_addr(&self) -> IoResult<Option<SocketAddr>> {
            Ok(self
                .inner
                .local_addr()
                .map_err(|err| IoError::Other(err, IoOperation::LocalAddr))?
                .as_socket())
        }
    }

    impl Socket for SocketImpl {
        #[instrument(level = "trace")]
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
        #[instrument(level = "trace")]
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
        #[instrument(level = "trace")]
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
        #[instrument(level = "trace")]
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
        #[instrument(level = "trace")]
        fn new_recv_socket_ipv4(_: Ipv4Addr, raw: bool) -> IoResult<Self> {
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
        #[instrument(level = "trace")]
        fn new_recv_socket_ipv6(_: Ipv6Addr, raw: bool) -> IoResult<Self> {
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
        #[instrument(level = "trace")]
        fn new_stream_socket_ipv4() -> IoResult<Self> {
            let mut socket = Self::new(Domain::IPV4, Type::STREAM, Protocol::TCP)?;
            socket.set_nonblocking(true)?;
            socket.set_reuse_port(true)?;
            Ok(socket)
        }
        #[instrument(level = "trace")]
        fn new_stream_socket_ipv6() -> IoResult<Self> {
            let mut socket = Self::new(Domain::IPV6, Type::STREAM, Protocol::TCP)?;
            socket.set_nonblocking(true)?;
            socket.set_reuse_port(true)?;
            Ok(socket)
        }
        #[instrument(level = "trace")]
        fn new_udp_dgram_socket_ipv4() -> IoResult<Self> {
            Self::new_dgram_ipv4(Protocol::UDP)
        }
        #[instrument(level = "trace")]
        fn new_udp_dgram_socket_ipv6() -> IoResult<Self> {
            Self::new_dgram_ipv6(Protocol::UDP)
        }
        #[instrument(skip(self), level = "trace")]
        fn bind(&mut self, address: SocketAddr) -> IoResult<()> {
            self.inner
                .bind(&SockAddr::from(address))
                .map_err(|err| IoError::Bind(err, address))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_tos(&mut self, tos: u32) -> IoResult<()> {
            self.inner
                .set_tos_v4(tos)
                .map_err(|err| IoError::Other(err, IoOperation::SetTos))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_tclass_v6(&mut self, tclass: u32) -> IoResult<()> {
            self.inner
                .set_tclass_v6(tclass)
                .map_err(|err| IoError::Other(err, IoOperation::SetTclassV6))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_ttl(&mut self, ttl: u32) -> IoResult<()> {
            self.inner
                .set_ttl_v4(ttl)
                .map_err(|err| IoError::Other(err, IoOperation::SetTtl))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_reuse_port(&mut self, reuse: bool) -> IoResult<()> {
            self.inner
                .set_reuse_port(reuse)
                .map_err(|err| IoError::Other(err, IoOperation::SetReusePort))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_header_included(&mut self, included: bool) -> IoResult<()> {
            self.inner
                .set_header_included_v4(included)
                .map_err(|err| IoError::Other(err, IoOperation::SetHeaderIncluded))
        }
        #[instrument(skip(self), level = "trace")]
        fn set_unicast_hops_v6(&mut self, hops: u8) -> IoResult<()> {
            self.inner
                .set_unicast_hops_v6(u32::from(hops))
                .map_err(|err| IoError::Other(err, IoOperation::SetUnicastHopsV6))
        }
        #[instrument(skip(self), level = "trace")]
        fn connect(&mut self, address: SocketAddr) -> IoResult<()> {
            tracing::trace!(?address);
            self.inner
                .connect(&SockAddr::from(address))
                .map_err(|err| IoError::Connect(err, address))
        }
        #[instrument(skip(self, buf), level = "trace")]
        fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> IoResult<()> {
            tracing::trace!(buf = format!("{:02x?}", buf.iter().format(" ")), ?addr);
            self.inner
                .send_to(buf, &SockAddr::from(addr))
                .map_err(|err| IoError::SendTo(err, addr))?;
            Ok(())
        }
        #[instrument(skip(self), level = "trace")]
        fn is_readable(&mut self, timeout: Duration) -> IoResult<bool> {
            let mut read = FdSet::new();
            read.insert(self.inner.as_fd());
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
        #[instrument(skip(self), level = "trace")]
        fn is_writable(&mut self) -> IoResult<bool> {
            let mut write = FdSet::new();
            write.insert(self.inner.as_fd());
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
        #[instrument(skip(self, buf), level = "trace")]
        fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, Option<SocketAddr>)> {
            let (bytes_read, addr) = self
                .inner
                .recv_from_into_buf(buf)
                .map_err(|err| IoError::Other(err, IoOperation::RecvFrom))?;
            tracing::trace!(
                buf = format!("{:02x?}", buf[..bytes_read].iter().format(" ")),
                bytes_read,
                ?addr
            );
            Ok((bytes_read, addr))
        }
        #[instrument(skip(self, buf), level = "trace")]
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            let bytes_read = self
                .inner
                .read(buf)
                .map_err(|err| IoError::Other(err, IoOperation::Read))?;
            tracing::trace!(
                buf = format!("{:02x?}", buf[..bytes_read].iter().format(" ")),
                bytes_read
            );
            Ok(bytes_read)
        }
        #[instrument(skip(self), level = "trace")]
        fn shutdown(&mut self) -> IoResult<()> {
            self.inner
                .shutdown(Shutdown::Both)
                .map_err(|err| IoError::Other(err, IoOperation::Shutdown))
        }
        #[instrument(skip(self), level = "trace")]
        fn peer_addr(&mut self) -> IoResult<Option<SocketAddr>> {
            let addr = self
                .inner
                .peer_addr()
                .map_err(|err| IoError::Other(err, IoOperation::PeerAddr))?
                .as_socket();
            tracing::trace!(?addr);
            Ok(addr)
        }
        #[instrument(skip(self), ret, level = "trace")]
        fn take_error(&mut self) -> IoResult<Option<SocketError>> {
            self.inner
                .take_error()
                .map(|err| {
                    err.map(|e| match e.raw_os_error() {
                        Some(errno) if Error::from_raw(errno) == Error::ECONNREFUSED => {
                            SocketError::ConnectionRefused
                        }
                        _ => SocketError::Other(e),
                    })
                })
                .map_err(|err| IoError::Other(err, IoOperation::TakeError))
        }
        #[instrument(skip(self), ret, level = "trace")]
        fn icmp_error_info(&mut self) -> IoResult<IpAddr> {
            Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
    }

    impl From<&io::Error> for ErrorKind {
        fn from(value: &io::Error) -> Self {
            if value.raw_os_error() == io::Error::from(Error::EINPROGRESS).raw_os_error() {
                Self::InProgress
            } else if value.raw_os_error() == io::Error::from(Error::EHOSTUNREACH).raw_os_error() {
                Self::HostUnreachable
            } else if value.raw_os_error() == io::Error::from(Error::ENETUNREACH).raw_os_error() {
                Self::NetUnreachable
            } else {
                Self::Std(value.kind())
            }
        }
    }

    // only used for unit tests
    impl From<ErrorKind> for io::Error {
        fn from(value: ErrorKind) -> Self {
            match value {
                ErrorKind::InProgress => Self::from(Error::EINPROGRESS),
                ErrorKind::HostUnreachable => Self::from(Error::EHOSTUNREACH),
                ErrorKind::NetUnreachable => Self::from(Error::ENETUNREACH),
                ErrorKind::Std(kind) => Self::from(kind),
            }
        }
    }

    impl Read for SocketImpl {
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
            let buf = unsafe {
                &mut *(std::ptr::from_mut::<[u8]>(buf) as *mut [std::mem::MaybeUninit<u8>])
            };
            self.recv_from(buf)
                .map(|(size, addr)| (size, addr.as_socket()))
        }
    }
}

pub use socket::{startup, SocketImpl};
