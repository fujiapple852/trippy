use super::byte_order::Ipv4ByteOrder;
use crate::error::{Error, ErrorKind, IoError, IoOperation, IoResult, Result};
use crate::net::channel::MAX_PACKET_SIZE;
use crate::net::platform::windows::adapter::Adapters;
use crate::net::platform::Platform;
use crate::net::socket::{Socket, SocketError};
use itertools::Itertools;
use socket2::{Domain, Protocol, SockAddr, Type};
use std::ffi::c_void;
use std::io::{Error as StdIoError, ErrorKind as StdErrorKind, Result as StdIoResult};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::windows::prelude::AsRawSocket;
use std::ptr::{addr_of, addr_of_mut, null_mut};
use std::time::Duration;
use tracing::instrument;
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FD_CONNECT, FD_WRITE, ICMP_ERROR_INFO, IN6_ADDR, IN6_ADDR_0, IN_ADDR,
    IN_ADDR_0, IPPROTO_RAW, IPPROTO_TCP, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_STORAGE, SOCKET_ERROR, SOL_SOCKET, SO_ERROR, SO_PORT_SCALABILITY,
    SO_REUSE_UNICASTPORT, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO, WSABUF, WSADATA,
    WSAEADDRNOTAVAIL, WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAENETUNREACH, WSAENOBUFS,
    WSA_IO_INCOMPLETE, WSA_IO_PENDING,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Execute a `Win32::Networking::WinSock` syscall.
///
/// The result of the syscall will be passed to the supplied boolean closure to determine if it
/// represents an error and if so returns the last OS error, otherwise the result of the syscall is
/// returned.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_fn: expr) => {{
        #[expect(unsafe_code)]
        let res = unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) };
        if $err_fn(res) {
            Err(StdIoError::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Execute a `Win32::NetworkManagement::IpHelper` syscall.
///
/// The raw result of the syscall is returned.
macro_rules! syscall_ip_helper {
    ($fn: ident ( $($arg: expr),* $(,)* )) => {{
        #[expect(unsafe_code)]
        unsafe { windows_sys::Win32::NetworkManagement::IpHelper::$fn($($arg, )*) }
    }};
}

/// Execute a `Win32::System::Threading` syscall.
///
/// The raw result of the syscall is returned.
macro_rules! syscall_threading {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[expect(unsafe_code)]
        unsafe { windows_sys::Win32::System::Threading::$fn($($arg, )*) }
    }};
}

pub struct PlatformImpl;

impl Platform for PlatformImpl {
    fn byte_order_for_address(_addr: IpAddr) -> Result<Ipv4ByteOrder> {
        Ok(Ipv4ByteOrder::Network)
    }

    fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
        match addr {
            IpAddr::V4(_) => lookup_interface_addr(&Adapters::ipv4()?, name),
            IpAddr::V6(_) => lookup_interface_addr(&Adapters::ipv6()?, name),
        }
    }

    fn discover_local_addr(target_addr: IpAddr, _port: u16) -> Result<IpAddr> {
        routing_interface_query(target_addr)
    }
}

#[instrument(level = "trace")]
pub fn startup() -> Result<()> {
    SocketImpl::startup().map_err(Error::IoError)
}

/// `WinSock` version 2.2
const WINSOCK_VERSION: u16 = 0x202;

/// A network socket.
pub struct SocketImpl {
    inner: socket2::Socket,
    ol: Box<OVERLAPPED>,
    buf: Box<[u8]>,
    from: Box<SOCKADDR_STORAGE>,
    from_len: i32,
    bytes_read: u32,
}

#[expect(clippy::cast_possible_wrap)]
impl SocketImpl {
    fn startup() -> IoResult<()> {
        let mut wsa_data = Self::new_wsa_data();
        syscall!(WSAStartup(WINSOCK_VERSION, addr_of_mut!(wsa_data)), |res| {
            res != 0
        })
        .map_err(|err| IoError::Other(err, IoOperation::Startup))
        .map(|_| ())
    }

    fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> IoResult<Self> {
        let inner = socket2::Socket::new(domain, ty, protocol)
            .map_err(|err| IoError::Other(err, IoOperation::NewSocket))?;
        let from = Box::new(Self::new_sockaddr_storage());
        let from_len = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;
        let ol = Box::new(Self::new_overlapped());
        let buf = Box::new([0; MAX_PACKET_SIZE]);
        Ok(Self {
            inner,
            ol,
            buf,
            from,
            from_len,
            bytes_read: 0,
        })
    }

    #[instrument(skip(self), level = "trace")]
    fn create_event(&mut self) -> IoResult<()> {
        self.ol.hEvent = syscall!(WSACreateEvent(), |res| { res == 0 || res == -1 })
            .map_err(|err| IoError::Other(err, IoOperation::WSACreateEvent))?;
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    fn wait_for_event(&self, timeout: Duration) -> IoResult<bool> {
        let millis = timeout.as_millis() as u32;
        let rc = syscall_threading!(WaitForSingleObject(self.ol.hEvent, millis));
        if rc == WAIT_TIMEOUT {
            return Ok(false);
        } else if rc == WAIT_FAILED {
            return Err(IoError::Other(
                StdIoError::last_os_error(),
                IoOperation::WaitForSingleObject,
            ));
        }
        Ok(true)
    }

    #[instrument(skip(self), level = "trace")]
    fn reset_event(&self) -> IoResult<()> {
        syscall!(WSAResetEvent(self.ol.hEvent), |res| { res == 0 })
            .map_err(|err| IoError::Other(err, IoOperation::WSAResetEvent))
            .map(|_| ())
    }

    #[instrument(skip(self, optval), level = "trace")]
    fn getsockopt<T>(&self, level: i32, optname: i32, mut optval: T) -> StdIoResult<T> {
        let mut optlen = size_of::<T>() as i32;
        syscall!(
            getsockopt(
                self.inner.as_raw_socket() as _,
                level,
                optname,
                addr_of_mut!(optval).cast(),
                &raw mut optlen,
            ),
            |res| res == SOCKET_ERROR
        )?;
        Ok(optval)
    }

    #[instrument(skip(self), level = "trace")]
    fn setsockopt_u32(&self, level: i32, optname: i32, optval: u32) -> StdIoResult<()> {
        let bytes = optval.to_ne_bytes();
        let optval = addr_of!(bytes).cast();
        syscall!(
            setsockopt(
                self.inner.as_raw_socket() as _,
                level,
                optname,
                optval,
                size_of::<u32>() as i32,
            ),
            |res| res == SOCKET_ERROR
        )
        .map(|_| ())
    }

    #[instrument(skip(self), level = "trace")]
    fn setsockopt_bool(&self, level: i32, optname: i32, optval: bool) -> StdIoResult<()> {
        self.setsockopt_u32(level, optname, u32::from(optval))
    }

    #[instrument(skip(self), level = "trace")]
    fn set_fail_connect_on_icmp_error(&self, enabled: bool) -> IoResult<()> {
        self.setsockopt_bool(IPPROTO_TCP, TCP_FAIL_CONNECT_ON_ICMP_ERROR as _, enabled)
            .map_err(|err| IoError::Other(err, IoOperation::SetTcpFailConnectOnIcmpError))
    }

    #[instrument(skip(self), level = "trace")]
    fn set_non_blocking(&self, is_non_blocking: bool) -> IoResult<()> {
        self.inner
            .set_nonblocking(is_non_blocking)
            .map_err(|err| IoError::Other(err, IoOperation::SetNonBlocking))
    }

    // TODO handle case where `WSARecvFrom` succeeded immediately.
    #[instrument(skip(self), level = "trace")]
    fn post_recv_from(&mut self) -> IoResult<()> {
        fn is_err(res: i32) -> bool {
            res == SOCKET_ERROR
                && StdIoError::last_os_error().raw_os_error() != Some(WSA_IO_PENDING)
        }
        let wbuf = WSABUF {
            len: MAX_PACKET_SIZE as u32,
            buf: self.buf.as_mut_ptr(),
        };
        syscall!(
            WSARecvFrom(
                self.inner.as_raw_socket() as usize,
                addr_of!(wbuf),
                1,
                null_mut(),
                &mut 0,
                addr_of_mut!(*self.from).cast(),
                addr_of_mut!(self.from_len),
                addr_of_mut!(*self.ol),
                None,
            ),
            is_err
        )
        .map_err(|err| IoError::Other(err, IoOperation::WSARecvFrom))?;
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    fn get_overlapped_result(&mut self) -> IoResult<()> {
        let mut bytes_read = 0;
        let mut flags = 0;
        let ol = *self.ol;
        syscall!(
            WSAGetOverlappedResult(
                self.inner.as_raw_socket() as _,
                addr_of!(ol),
                &raw mut bytes_read,
                0,
                &raw mut flags,
            ),
            |res| { res == 0 }
        )
        .map_err(|err| IoError::Other(err, IoOperation::WSAGetOverlappedResult))?;
        self.bytes_read = bytes_read;
        Ok(())
    }

    #[expect(unsafe_code)]
    const fn new_wsa_data() -> WSADATA {
        // Safety: an all-zero value is valid for `WSADATA`.
        unsafe { zeroed::<WSADATA>() }
    }

    #[expect(unsafe_code)]
    const fn new_sockaddr_storage() -> SOCKADDR_STORAGE {
        // Safety: an all-zero value is valid for `SOCKADDR_STORAGE`.
        unsafe { zeroed::<SOCKADDR_STORAGE>() }
    }

    #[expect(unsafe_code)]
    const fn new_overlapped() -> OVERLAPPED {
        // Safety: an all-zero value is valid for `OVERLAPPED.`
        unsafe { zeroed::<OVERLAPPED>() }
    }

    #[expect(unsafe_code)]
    const fn new_icmp_error_info() -> ICMP_ERROR_INFO {
        // Safety: an all-zero value is valid for `ICMP_ERROR_INFO`.
        unsafe { zeroed::<ICMP_ERROR_INFO>() }
    }
}

impl Drop for SocketImpl {
    fn drop(&mut self) {
        if self.ol.hEvent != -1 && self.ol.hEvent != 0 {
            syscall!(WSACloseEvent(self.ol.hEvent), |res| { res == 0 }).unwrap_or_default();
        }
    }
}

#[expect(clippy::cast_possible_wrap)]
impl Socket for SocketImpl {
    #[instrument(level = "trace")]
    fn new_icmp_send_socket_ipv4(raw: bool) -> IoResult<Self> {
        if raw {
            let mut sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
            sock.set_non_blocking(true)?;
            sock.set_header_included(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_icmp_send_socket_ipv6(raw: bool) -> IoResult<Self> {
        if raw {
            let sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
            sock.set_non_blocking(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_udp_send_socket_ipv4(raw: bool) -> IoResult<Self> {
        if raw {
            let mut sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
            sock.set_non_blocking(true)?;
            sock.set_header_included(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_udp_send_socket_ipv6(raw: bool) -> IoResult<Self> {
        if raw {
            let sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
            sock.set_non_blocking(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_recv_socket_ipv4(src_addr: Ipv4Addr, raw: bool) -> IoResult<Self> {
        if raw {
            let mut sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
            sock.bind(SocketAddr::new(IpAddr::V4(src_addr), 0))?;
            sock.post_recv_from()?;
            sock.set_non_blocking(true)?;
            sock.set_header_included(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_recv_socket_ipv6(src_addr: Ipv6Addr, raw: bool) -> IoResult<Self> {
        if raw {
            let mut sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
            sock.bind(SocketAddr::new(IpAddr::V6(src_addr), 0))?;
            sock.post_recv_from()?;
            sock.set_non_blocking(true)?;
            Ok(sock)
        } else {
            unimplemented!("non-raw socket is not supported on Windows")
        }
    }

    #[instrument(level = "trace")]
    fn new_stream_socket_ipv4() -> IoResult<Self> {
        let mut sock = Self::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    #[instrument(level = "trace")]
    fn new_stream_socket_ipv6() -> IoResult<Self> {
        let mut sock = Self::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    #[instrument(level = "trace")]
    fn new_udp_dgram_socket_ipv4() -> IoResult<Self> {
        Self::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
    }

    #[instrument(level = "trace")]
    fn new_udp_dgram_socket_ipv6() -> IoResult<Self> {
        Self::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
    }

    #[instrument(skip(self), level = "trace")]
    fn bind(&mut self, addr: SocketAddr) -> IoResult<()> {
        self.inner
            .bind(&SockAddr::from(addr))
            .map_err(|e| {
                if e.kind() == StdErrorKind::PermissionDenied {
                    StdIoError::from_raw_os_error(WSAEADDRNOTAVAIL)
                } else {
                    e
                }
            })
            .map_err(|err| IoError::Bind(err, addr))?;
        self.create_event()?;
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    fn set_tos(&mut self, tos: u32) -> IoResult<()> {
        self.inner
            .set_tos_v4(tos)
            .map_err(|err| IoError::Other(err, IoOperation::SetTos))
    }

    fn set_tclass_v6(&mut self, tclass: u32) -> IoResult<()> {
        if tclass > 0 {
            unimplemented!("setting tclass_v6 is not supported on Windows")
        }
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    fn set_ttl(&mut self, ttl: u32) -> IoResult<()> {
        self.inner
            .set_ttl_v4(ttl)
            .map_err(|err| IoError::Other(err, IoOperation::SetTtl))
    }

    #[instrument(skip(self), level = "trace")]
    fn set_reuse_port(&mut self, is_reuse_port: bool) -> IoResult<()> {
        self.setsockopt_bool(SOL_SOCKET as _, SO_REUSE_UNICASTPORT as _, is_reuse_port)
            .or_else(|_| {
                self.setsockopt_bool(SOL_SOCKET as _, SO_PORT_SCALABILITY as _, is_reuse_port)
            })
            .map_err(|err| IoError::Other(err, IoOperation::SetReusePort))
    }

    #[instrument(skip(self), level = "trace")]
    fn set_header_included(&mut self, is_header_included: bool) -> IoResult<()> {
        self.inner
            .set_header_included_v4(is_header_included)
            .map_err(|err| IoError::Other(err, IoOperation::SetHeaderIncluded))
    }

    #[instrument(skip(self), level = "trace")]
    fn set_unicast_hops_v6(&mut self, max_hops: u8) -> IoResult<()> {
        self.inner
            .set_unicast_hops_v6(max_hops.into())
            .map_err(|err| IoError::Other(err, IoOperation::SetUnicastHopsV6))
    }

    #[instrument(skip(self), level = "trace")]
    fn connect(&mut self, addr: SocketAddr) -> IoResult<()> {
        self.set_fail_connect_on_icmp_error(true)?;
        syscall!(
            WSAEventSelect(
                self.inner.as_raw_socket() as _,
                self.ol.hEvent,
                (FD_CONNECT | FD_WRITE) as _
            ),
            |res| res == SOCKET_ERROR
        )
        .map_err(|err| IoError::Other(err, IoOperation::WSAEventSelect))?;
        let res = self.inner.connect(&SockAddr::from(addr));
        match res {
            Ok(()) => Ok(()),
            Err(ref e) if e.kind() == StdErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(IoError::Connect(err, addr)),
        }
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
        if !self.wait_for_event(timeout)? {
            return Ok(false);
        }
        while let Err(err) = self.get_overlapped_result() {
            if err.kind() != ErrorKind::Std(StdIoError::from_raw_os_error(WSA_IO_INCOMPLETE).kind())
            {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    #[instrument(skip(self), level = "trace")]
    fn is_writable(&mut self) -> IoResult<bool> {
        if !self.wait_for_event(Duration::ZERO)? {
            return Ok(false);
        }
        while let Err(err) = self.get_overlapped_result() {
            if err.kind() != ErrorKind::Std(StdIoError::from_raw_os_error(WSA_IO_INCOMPLETE).kind())
            {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    #[instrument(skip(self, buf), level = "trace")]
    fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, Option<SocketAddr>)> {
        let addr = sockaddrptr_to_ipaddr(addr_of_mut!(*self.from))
            .map_err(|err| IoError::Other(err, IoOperation::RecvFrom))?;
        let len = self.read(buf)?;
        tracing::trace!(
            buf = format!("{:02x?}", buf[..len].iter().format(" ")),
            len,
            ?addr
        );
        Ok((len, Some(SocketAddr::new(addr, 0))))
    }

    #[instrument(skip(self, buf), ret, level = "trace")]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let bytes_read = std::cmp::min(self.bytes_read as usize, buf.len());
        buf[..bytes_read].copy_from_slice(&self.buf[..bytes_read]);
        tracing::trace!(buf = format!("{:02x?}", buf[..bytes_read].iter().format(" ")));
        self.post_recv_from()?;
        Ok(bytes_read)
    }

    #[instrument(skip(self), level = "trace")]
    fn shutdown(&mut self) -> IoResult<()> {
        self.inner
            .shutdown(std::net::Shutdown::Both)
            .map_err(|err| IoError::Other(err, IoOperation::Shutdown))
    }

    #[instrument(skip(self), ret, level = "trace")]
    fn peer_addr(&mut self) -> IoResult<Option<SocketAddr>> {
        Ok(self
            .inner
            .peer_addr()
            .map_err(|err| IoError::Other(err, IoOperation::PeerAddr))?
            .as_socket())
    }

    #[instrument(skip(self), ret, level = "trace")]
    fn take_error(&mut self) -> IoResult<Option<SocketError>> {
        match self.getsockopt(SOL_SOCKET as _, SO_ERROR as _, 0) {
            Ok(0) => Ok(None),
            Ok(errno) if errno == WSAEHOSTUNREACH => Ok(Some(SocketError::HostUnreachable)),
            Ok(errno) if errno == WSAECONNREFUSED => Ok(Some(SocketError::ConnectionRefused)),
            Ok(errno) => Ok(Some(SocketError::Other(StdIoError::from_raw_os_error(
                errno,
            )))),
            Err(e) => Err(e),
        }
        .map_err(|err| IoError::Other(err, IoOperation::TakeError))
    }

    #[instrument(skip(self), ret, level = "trace")]
    #[expect(unsafe_code)]
    fn icmp_error_info(&mut self) -> IoResult<IpAddr> {
        let icmp_error_info = self
            .getsockopt::<ICMP_ERROR_INFO>(
                IPPROTO_TCP as _,
                TCP_ICMP_ERROR_INFO as _,
                Self::new_icmp_error_info(),
            )
            .map_err(|err| IoError::Other(err, IoOperation::TcpIcmpErrorInfo))?;
        let src_addr = icmp_error_info.srcaddress;
        match unsafe { src_addr.si_family } {
            AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(unsafe {
                src_addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
            }))),
            AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
                src_addr.Ipv6.sin6_addr.u.Byte
            }))),
            _ => Err(IoError::Other(
                StdIoError::from(StdErrorKind::AddrNotAvailable),
                IoOperation::TcpIcmpErrorInfo,
            )),
        }
    }
}

// Note that we handle `WSAENOBUFS`, which can occurs when calling `send_to()`
// for ICMP and UDP.  We return it as `NetUnreachable` to piggyback on the
// existing error handling.
impl From<&StdIoError> for ErrorKind {
    fn from(value: &StdIoError) -> Self {
        if let Some(raw) = value.raw_os_error() {
            if raw == WSAEINPROGRESS {
                Self::InProgress
            } else if raw == WSAEHOSTUNREACH {
                Self::HostUnreachable
            } else if raw == WSAENETUNREACH || raw == WSAENOBUFS {
                Self::NetUnreachable
            } else {
                Self::Std(value.kind())
            }
        } else {
            Self::Std(value.kind())
        }
    }
}

// only used for unit tests
impl From<ErrorKind> for StdIoError {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::InProgress => Self::from_raw_os_error(WSAEINPROGRESS),
            ErrorKind::HostUnreachable => Self::from_raw_os_error(WSAEHOSTUNREACH),
            ErrorKind::NetUnreachable => Self::from_raw_os_error(WSAENETUNREACH),
            ErrorKind::Std(kind) => Self::from(kind),
        }
    }
}

/// NOTE under Windows, we cannot use a bind connect/getsockname as "If the socket
/// is using a connectionless protocol, the address may not be available until I/O
/// occurs on the socket."  We use `SIO_ROUTING_INTERFACE_QUERY` instead.
#[expect(clippy::cast_sign_loss)]
#[instrument(level = "trace")]
fn routing_interface_query(target: IpAddr) -> Result<IpAddr> {
    let mut src_buf = [0; 1024];
    let src: *mut c_void = src_buf.as_mut_ptr().cast();
    let mut bytes = 0;
    let socket = match target {
        IpAddr::V4(_) => SocketImpl::new_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => SocketImpl::new_udp_dgram_socket_ipv6(),
    }?;
    let (dest, destlen) = socketaddr_to_sockaddr(SocketAddr::new(target, 0));
    syscall!(
        WSAIoctl(
            socket.inner.as_raw_socket() as _,
            SIO_ROUTING_INTERFACE_QUERY,
            addr_of!(dest).cast(),
            destlen as u32,
            src,
            1024,
            addr_of_mut!(bytes),
            null_mut(),
            None,
        ),
        |res| res == SOCKET_ERROR
    )
    .map_err(|err| IoError::Other(err, IoOperation::SioRoutingInterfaceQuery))?;
    // Note that the `WSAIoctl` call potentially returns multiple results (see
    // <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
    // TBD We choose the first one arbitrarily.
    let sockaddr = src.cast::<SOCKADDR_STORAGE>();
    sockaddrptr_to_ipaddr(sockaddr)
        .map_err(|err| Error::IoError(IoError::Other(err, IoOperation::ConvertSocketAddress)))
}

#[expect(unsafe_code)]
fn sockaddrptr_to_ipaddr(sockaddr: *mut SOCKADDR_STORAGE) -> StdIoResult<IpAddr> {
    // Safety: TODO
    match sockaddr_to_socketaddr(unsafe { sockaddr.as_ref().unwrap() }) {
        Err(e) => Err(e),
        Ok(socketaddr) => match socketaddr {
            SocketAddr::V4(socketaddrv4) => Ok(IpAddr::V4(*socketaddrv4.ip())),
            SocketAddr::V6(socketaddrv6) => Ok(IpAddr::V6(*socketaddrv6.ip())),
        },
    }
}

#[expect(unsafe_code)]
fn sockaddr_to_socketaddr(sockaddr: &SOCKADDR_STORAGE) -> StdIoResult<SocketAddr> {
    let ptr = sockaddr as *const SOCKADDR_STORAGE;
    let af = sockaddr.ss_family;
    if af == AF_INET {
        let sockaddr_in_ptr = ptr.cast::<SOCKADDR_IN>();
        // Safety: TODO
        let sockaddr_in = unsafe { *sockaddr_in_ptr };
        let ipv4addr = u32::from_be(unsafe { sockaddr_in.sin_addr.S_un.S_addr });
        let port = sockaddr_in.sin_port;
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(ipv4addr),
            port,
        )))
    } else if af == AF_INET6 {
        let sockaddr_in6_ptr = ptr.cast::<SOCKADDR_IN6>();
        // Safety: TODO
        let sockaddr_in6 = unsafe { *sockaddr_in6_ptr };
        // TODO: check endianness
        // Safety: TODO
        let ipv6addr = unsafe { sockaddr_in6.sin6_addr.u.Byte };
        let port = sockaddr_in6.sin6_port;
        // Safety: TODO
        let scope_id = unsafe { sockaddr_in6.Anonymous.sin6_scope_id };
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(ipv6addr),
            port,
            sockaddr_in6.sin6_flowinfo,
            scope_id,
        )))
    } else {
        Err(StdIoError::new(
            StdErrorKind::Unsupported,
            format!("Unsupported address family: {af:?}"),
        ))
    }
}

#[expect(unsafe_code)]
#[expect(clippy::cast_possible_wrap)]
#[must_use]
fn socketaddr_to_sockaddr(socketaddr: SocketAddr) -> (SOCKADDR_STORAGE, i32) {
    #[repr(C)]
    union SockAddr {
        storage: SOCKADDR_STORAGE,
        in4: SOCKADDR_IN,
        in6: SOCKADDR_IN6,
    }

    let sockaddr = match socketaddr {
        SocketAddr::V4(socketaddrv4) => SockAddr {
            in4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: socketaddrv4.port().to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from(*socketaddrv4.ip()).to_be(),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        SocketAddr::V6(socketaddrv6) => SockAddr {
            in6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: socketaddrv6.port().to_be(),
                sin6_flowinfo: socketaddrv6.flowinfo(),
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: socketaddrv6.ip().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: socketaddrv6.scope_id(),
                },
            },
        },
    };

    (unsafe { sockaddr.storage }, size_of::<SockAddr>() as i32)
}

#[instrument(skip(adapters), ret, level = "trace")]
fn lookup_interface_addr(adapters: &Adapters, name: &str) -> Result<IpAddr> {
    adapters
        .iter()
        .find_map(|addr| {
            if addr.name.eq_ignore_ascii_case(name) {
                addr.addr
            } else {
                None
            }
        })
        .ok_or_else(|| Error::UnknownInterface(name.to_string()))
}

mod adapter {
    use crate::error::{Error, Result};
    use crate::net::platform::windows::sockaddrptr_to_ipaddr;
    use std::io::Error as StdIoError;
    use std::marker::PhantomData;
    use std::net::IpAddr;
    use std::ptr::null_mut;
    use widestring::WideCString;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6};

    /// Retrieve adapter address information.
    pub struct Adapters {
        buf: Vec<u8>,
    }

    impl Adapters {
        /// Retrieve IPv4 adapter details.
        pub fn ipv4() -> Result<Self> {
            Self::retrieve_addresses(AF_INET)
        }

        /// Retrieve IPv6 adapter details.
        pub fn ipv6() -> Result<Self> {
            Self::retrieve_addresses(AF_INET6)
        }

        /// Return an iterator of `AdapterAddress` in this `Adapters`.
        pub fn iter(&self) -> AdaptersIter<'_> {
            AdaptersIter::new(self)
        }

        // The maximum number of attempts to retrieve addresses.
        const MAX_ATTEMPTS: usize = 3;

        // The size of the buffer to use for the first retrieval attempt.
        const INITIAL_BUFFER_SIZE: u32 = 15000;

        // The flags to use when performing the adapter addresses retrieval.
        const ADDRESS_FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = IpHelper::GAA_FLAG_SKIP_ANYCAST
            | IpHelper::GAA_FLAG_SKIP_MULTICAST
            | IpHelper::GAA_FLAG_SKIP_DNS_SERVER;

        fn retrieve_addresses(family: ADDRESS_FAMILY) -> Result<Self> {
            let mut buf_len = Self::INITIAL_BUFFER_SIZE;
            let mut buf: Vec<u8>;
            for _ in 0..Self::MAX_ATTEMPTS {
                buf = vec![0_u8; buf_len as usize];
                let res = syscall_ip_helper!(GetAdaptersAddresses(
                    u32::from(family),
                    Self::ADDRESS_FLAGS,
                    null_mut(),
                    buf.as_mut_ptr().cast(),
                    &raw mut buf_len,
                ));
                if res == ERROR_BUFFER_OVERFLOW {
                    continue;
                }
                if res != NO_ERROR {
                    return Err(Error::UnknownInterface(format!(
                        "GetAdaptersAddresses returned error: {}",
                        StdIoError::from_raw_os_error(res.try_into().unwrap())
                    )));
                }
                return Ok(Self { buf });
            }
            Err(Error::UnknownInterface(format!(
                "GetAdaptersAddresses did not succeed after {} attempts",
                Self::MAX_ATTEMPTS
            )))
        }
    }

    /// A named adapter address.
    #[derive(Debug)]
    pub struct AdapterAddress {
        /// The adapter friendly name.
        pub name: String,
        /// The first adapter uni-cast `IpAddr`, if any.
        pub addr: Option<IpAddr>,
    }

    /// An iterator for `Adapters` which yields `AdapterAddress`
    pub struct AdaptersIter<'a> {
        next: *const IP_ADAPTER_ADDRESSES_LH,
        _data: PhantomData<&'a ()>,
    }

    impl<'a> AdaptersIter<'a> {
        /// Create an iterator for an `Adapters`.
        pub fn new(data: &'a Adapters) -> Self {
            let next = data.buf.as_ptr().cast();
            Self {
                next,
                // tie the lifetime of this iterator to the lifetime of the `Adapters`
                _data: PhantomData,
            }
        }
    }

    impl Iterator for AdaptersIter<'_> {
        type Item = AdapterAddress;

        fn next(&mut self) -> Option<Self::Item> {
            if self.next.is_null() {
                None
            } else {
                // Safety: `next` is not null and points to a valid `IP_ADAPTER_ADDRESSES_LH`
                #[expect(unsafe_code)]
                unsafe {
                    let friendly_name = WideCString::from_ptr_str((*self.next).FriendlyName)
                        .to_string()
                        .ok()?;
                    let addr = {
                        let first_unicast = (*self.next).FirstUnicastAddress;
                        if first_unicast.is_null() {
                            None
                        } else {
                            let socket_address = (*first_unicast).Address;
                            let sockaddr = socket_address.lpSockaddr;
                            Some(sockaddrptr_to_ipaddr(sockaddr.cast()).ok()?)
                        }
                    };
                    self.next = (*self.next).Next;
                    Some(AdapterAddress {
                        name: friendly_name,
                        addr,
                    })
                }
            }
        }
    }
}
