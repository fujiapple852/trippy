use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::platform::windows::adapter::Adapters;
use crate::tracing::net::socket::TracerSocket;
use socket2::{Domain, Protocol, SockAddr, Type};
use std::io::{Error, ErrorKind, Result};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::os::windows::prelude::AsRawSocket;
use std::ptr::{addr_of, addr_of_mut, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FD_CONNECT, FD_WRITE, ICMP_ERROR_INFO, IPPROTO_RAW, IPPROTO_TCP,
    SIO_ROUTING_INTERFACE_QUERY, SOCKET_ERROR, SOL_SOCKET, SO_ERROR, SO_PORT_SCALABILITY,
    SO_REUSE_UNICASTPORT, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO, WSABUF, WSADATA,
    WSAEADDRNOTAVAIL, WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEINPROGRESS, WSA_IO_INCOMPLETE,
    WSA_IO_PENDING,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Execute a `Win32::Networking::WinSock` syscall.
///
/// The result of the syscall will be passed to the supplied boolean closure to determine if it represents an error
/// and if so returns the last OS error, otherwise the result of the syscall is returned.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_fn: expr) => {{
        #[allow(unsafe_code)]
        let res = unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) };
        if $err_fn(res) {
            Err(Error::last_os_error())
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
        #[allow(unsafe_code)]
        unsafe { windows_sys::Win32::NetworkManagement::IpHelper::$fn($($arg, )*) }
    }};
}

/// Execute a `Win32::System::Threading` syscall.
///
/// The raw result of the syscall is returned.
macro_rules! syscall_threading {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code)]
        unsafe { windows_sys::Win32::System::Threading::$fn($($arg, )*) }
    }};
}

#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(&Adapters::ipv4()?, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(&Adapters::ipv6()?, name)
}

pub fn discover_local_addr(target: IpAddr, _port: u16) -> TraceResult<IpAddr> {
    routing_interface_query(target)
}

pub fn startup() -> Result<()> {
    Socket::startup()
}

#[must_use]
pub fn is_not_in_progress_error(code: i32) -> bool {
    code != WSAEINPROGRESS
}

#[must_use]
pub fn is_conn_refused_error(code: i32) -> bool {
    code == WSAECONNREFUSED
}

#[must_use]
pub fn is_host_unreachable_error(code: i32) -> bool {
    code == WSAEHOSTUNREACH
}

/// `WinSock` version 2.2
const WINSOCK_VERSION: u16 = 0x202;

/// A network socket.
pub struct Socket {
    inner: socket2::Socket,
    ol: Box<OVERLAPPED>,
    buf: Vec<u8>,
    from: Box<SockAddr>,
}

#[allow(clippy::cast_possible_wrap)]
impl Socket {
    fn startup() -> Result<()> {
        let mut wsa_data = Self::new_wsa_data();
        syscall!(WSAStartup(WINSOCK_VERSION, addr_of_mut!(wsa_data)), |res| {
            res != 0
        })
        .map(|_| ())
    }

    fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> Result<Self> {
        let inner = socket2::Socket::new(domain, ty, protocol)?;
        let from = Box::new(Self::new_sockaddr());
        let ol = Box::new(Self::new_overlapped());
        let buf = vec![0u8; MAX_PACKET_SIZE];
        Ok(Self {
            inner,
            ol,
            buf,
            from,
        })
    }

    fn create_event(&mut self) -> Result<()> {
        self.ol.hEvent = syscall!(WSACreateEvent(), |res| { res == 0 || res == -1 })?;
        Ok(())
    }

    fn wait_for_event(&self, timeout: Duration) -> Result<bool> {
        let millis = timeout.as_millis() as u32;
        let rc = syscall_threading!(WaitForSingleObject(self.ol.hEvent, millis));
        if rc == WAIT_TIMEOUT {
            return Ok(false);
        } else if rc == WAIT_FAILED {
            return Err(Error::last_os_error());
        }
        Ok(true)
    }

    fn reset_event(&self) -> Result<()> {
        syscall!(WSAResetEvent(self.ol.hEvent), |res| { res == 0 }).map(|_| ())
    }

    fn getsockopt<T>(&self, level: i32, optname: i32, mut optval: T) -> Result<T> {
        let mut optlen = size_of::<T>() as i32;
        syscall!(
            getsockopt(
                self.inner.as_raw_socket() as _,
                level,
                optname,
                addr_of_mut!(optval).cast(),
                &mut optlen,
            ),
            |res| res == SOCKET_ERROR
        )?;
        Ok(optval)
    }

    fn setsockopt_u32(&self, level: i32, optname: i32, optval: u32) -> Result<()> {
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

    fn setsockopt_bool(&self, level: i32, optname: i32, optval: bool) -> Result<()> {
        self.setsockopt_u32(level, optname, u32::from(optval))
    }

    fn set_fail_connect_on_icmp_error(&self, enabled: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_TCP, TCP_FAIL_CONNECT_ON_ICMP_ERROR as _, enabled)
    }

    fn set_non_blocking(&self, is_non_blocking: bool) -> Result<()> {
        self.inner.set_nonblocking(is_non_blocking)
    }

    // TODO handle case where `WSARecvFrom` succeeded immediately.
    fn post_recv_from(&mut self) -> Result<()> {
        fn is_err(res: i32) -> bool {
            res == SOCKET_ERROR && Error::last_os_error().raw_os_error() != Some(WSA_IO_PENDING)
        }
        let mut fromlen = self.from.len();
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
                self.from.as_mut_ptr(),
                addr_of_mut!(fromlen),
                addr_of_mut!(*self.ol),
                None,
            ),
            is_err
        )?;
        Ok(())
    }

    fn get_overlapped_result(&self) -> Result<(u32, u32)> {
        let mut bytes = 0;
        let mut flags = 0;
        let ol = *self.ol;
        syscall!(
            WSAGetOverlappedResult(
                self.inner.as_raw_socket() as _,
                addr_of!(ol),
                &mut bytes,
                0,
                &mut flags,
            ),
            |res| { res == 0 }
        )?;
        Ok((bytes, flags))
    }

    #[allow(unsafe_code)]
    fn new_wsa_data() -> WSADATA {
        // Safety: an all-zero value is valid for WSADATA.
        unsafe { zeroed::<WSADATA>() }
    }

    fn new_sockaddr() -> SockAddr {
        SockAddr::from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    }

    #[allow(unsafe_code)]
    fn new_overlapped() -> OVERLAPPED {
        // Safety: an all-zero value is valid for OVERLAPPED.
        unsafe { zeroed::<OVERLAPPED>() }
    }

    #[allow(unsafe_code)]
    fn new_icmp_error_info() -> ICMP_ERROR_INFO {
        // Safety: an all-zero value is valid for ICMP_ERROR_INFO.
        unsafe { zeroed::<ICMP_ERROR_INFO>() }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close().unwrap_or_default();
        if self.ol.hEvent != -1 && self.ol.hEvent != 0 {
            syscall!(WSACloseEvent(self.ol.hEvent), |res| { res == 0 }).unwrap_or_default();
        }
    }
}

#[allow(clippy::cast_possible_wrap)]
impl TracerSocket for Socket {
    fn new_icmp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_icmp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv4(src_addr: Ipv4Addr) -> Result<Self> {
        let mut sock = Self::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        sock.bind(SocketAddr::new(IpAddr::V4(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv6(src_addr: Ipv6Addr) -> Result<Self> {
        let mut sock = Self::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        sock.bind(SocketAddr::new(IpAddr::V6(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv4() -> Result<Self> {
        let sock = Self::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv6() -> Result<Self> {
        let sock = Self::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_udp_dgram_socket_ipv4() -> Result<Self> {
        Self::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
    }

    fn new_udp_dgram_socket_ipv6() -> Result<Self> {
        Self::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
    }

    fn bind(&mut self, source_socketaddr: SocketAddr) -> Result<()> {
        self.inner
            .bind(&SockAddr::from(source_socketaddr))
            .map_err(|e| {
                if e.kind() == ErrorKind::PermissionDenied {
                    Error::from_raw_os_error(WSAEADDRNOTAVAIL)
                } else {
                    e
                }
            })?;
        self.create_event()?;
        Ok(())
    }

    fn set_tos(&self, tos: u32) -> Result<()> {
        self.inner.set_tos(tos)
    }

    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.inner.set_ttl(ttl)
    }

    fn set_reuse_port(&self, is_reuse_port: bool) -> Result<()> {
        self.setsockopt_bool(SOL_SOCKET as _, SO_REUSE_UNICASTPORT as _, is_reuse_port)
            .or_else(|_| {
                self.setsockopt_bool(SOL_SOCKET as _, SO_PORT_SCALABILITY as _, is_reuse_port)
            })
    }

    fn set_header_included(&self, is_header_included: bool) -> Result<()> {
        self.inner.set_header_included(is_header_included)
    }

    fn set_unicast_hops_v6(&self, max_hops: u8) -> Result<()> {
        self.inner.set_unicast_hops_v6(max_hops.into())
    }

    fn connect(&self, dest_socketaddr: SocketAddr) -> Result<()> {
        self.set_fail_connect_on_icmp_error(true)?;
        syscall!(
            WSAEventSelect(
                self.inner.as_raw_socket() as _,
                self.ol.hEvent,
                (FD_CONNECT | FD_WRITE) as _
            ),
            |res| res == SOCKET_ERROR
        )?;
        let res = self.inner.connect(&SockAddr::from(dest_socketaddr));
        match res {
            Ok(()) => Ok(()),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn send_to(&self, packet: &[u8], dest_socketaddr: SocketAddr) -> Result<()> {
        self.inner
            .send_to(packet, &SockAddr::from(dest_socketaddr))?;
        Ok(())
    }

    fn is_readable(&self, timeout: Duration) -> Result<bool> {
        if !self.wait_for_event(timeout)? {
            return Ok(false);
        };
        while let Err(err) = self.get_overlapped_result() {
            if err.raw_os_error() != Some(WSA_IO_INCOMPLETE) {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    fn is_writable(&self) -> Result<bool> {
        if !self.wait_for_event(Duration::ZERO)? {
            return Ok(false);
        };
        while let Err(err) = self.get_overlapped_result() {
            if err.raw_os_error() != Some(WSA_IO_INCOMPLETE) {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>)> {
        let len = self.read(buf)?;
        Ok((len, self.from.as_socket()))
    }

    // TODO
    // we always copy and claim to have returned MAX_PACKET_SIZE bytes, regardless of how many bytes we actually
    // received.  The callers currently ignore this and just try to parse a packet from the buffer which isn't ideal.
    // Really we should record the actual number of bytes read in the `get_overlapped_result` call and return that here.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        buf.copy_from_slice(self.buf.as_slice());
        self.post_recv_from()?;
        Ok(MAX_PACKET_SIZE)
    }

    fn shutdown(&self) -> Result<()> {
        self.inner.shutdown(std::net::Shutdown::Both)
    }

    fn peer_addr(&self) -> Result<Option<SocketAddr>> {
        Ok(self.inner.peer_addr()?.as_socket())
    }

    fn take_error(&self) -> Result<Option<Error>> {
        match self.getsockopt(SOL_SOCKET as _, SO_ERROR as _, 0) {
            Ok(0) => Ok(None),
            Ok(errno) => Ok(Some(Error::from_raw_os_error(errno))),
            Err(e) => Err(e),
        }
    }

    #[allow(unsafe_code)]
    fn icmp_error_info(&self) -> Result<IpAddr> {
        let icmp_error_info = self.getsockopt::<ICMP_ERROR_INFO>(
            IPPROTO_TCP as _,
            TCP_ICMP_ERROR_INFO as _,
            Self::new_icmp_error_info(),
        )?;
        let src_addr = icmp_error_info.srcaddress;
        match unsafe { src_addr.si_family } {
            AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(unsafe {
                src_addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
            }))),
            AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
                src_addr.Ipv6.sin6_addr.u.Byte
            }))),
            _ => Err(Error::from(ErrorKind::AddrNotAvailable)),
        }
    }

    // Interestingly, Socket2 sockets don't seem to call closesocket on drop??
    fn close(&self) -> Result<()> {
        syscall!(closesocket(self.inner.as_raw_socket() as _), |res| res
            == SOCKET_ERROR)
        .map(|_| ())
    }
}

/// Determine the src `IpAddr` used for routing to a given target `IpAddr`.
///
/// under Windows, we cannot use a bind connect/getsockname as "If the socket is using a connectionless protocol, the
/// address may not be available until I/O occurs on the socket.".  Therefore we use `SIO_ROUTING_INTERFACE_QUERY`
/// instead.
///
/// Note that the `WSAIoctl` call potentially returns multiple results (see
/// <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
/// and we currently choose the first one arbitrarily.
#[allow(clippy::cast_sign_loss)]
fn routing_interface_query(target: IpAddr) -> TraceResult<IpAddr> {
    let mut src = Socket::new_sockaddr();
    let dest = SockAddr::from(SocketAddr::new(target, 0));
    let mut bytes = 0;
    let socket = match target {
        IpAddr::V4(_) => Socket::new_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => Socket::new_udp_dgram_socket_ipv6(),
    }?;
    syscall!(
        WSAIoctl(
            socket.inner.as_raw_socket() as _,
            SIO_ROUTING_INTERFACE_QUERY,
            dest.as_ptr().cast(),
            dest.len() as u32,
            src.as_mut_ptr().cast(),
            src.len() as u32,
            addr_of_mut!(bytes),
            null_mut(),
            None,
        ),
        |res| res == SOCKET_ERROR
    )?;
    Ok(src.as_socket().unwrap().ip())
}

fn lookup_interface_addr(adapters: &Adapters, name: &str) -> TraceResult<IpAddr> {
    adapters
        .iter()
        .find_map(|addr| {
            if addr.name.eq_ignore_ascii_case(name) {
                Some(addr.addr)
            } else {
                None
            }
        })
        .ok_or_else(|| TracerError::UnknownInterface(name.to_string()))
}

mod adapter {
    use crate::tracing::error::{TraceResult, TracerError};
    use socket2::SockAddr;
    use std::io::Error;
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
        pub fn ipv4() -> TraceResult<Self> {
            Self::retrieve_addresses(AF_INET)
        }

        /// Retrieve IPv6 adapter details.
        pub fn ipv6() -> TraceResult<Self> {
            Self::retrieve_addresses(AF_INET6)
        }

        /// Return a iterator of `AdapterAddress` in this `Adapters`.
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

        fn retrieve_addresses(family: ADDRESS_FAMILY) -> TraceResult<Self> {
            let mut buf_len = Self::INITIAL_BUFFER_SIZE;
            let mut buf: Vec<u8>;
            for _ in 0..Self::MAX_ATTEMPTS {
                buf = vec![0_u8; buf_len as usize];
                let res = syscall_ip_helper!(GetAdaptersAddresses(
                    u32::from(family),
                    Self::ADDRESS_FLAGS,
                    null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut buf_len,
                ));
                if res == ERROR_BUFFER_OVERFLOW {
                    continue;
                }
                if res != NO_ERROR {
                    return Err(TracerError::UnknownInterface(format!(
                        "GetAdaptersAddresses returned error: {}",
                        Error::from_raw_os_error(res.try_into().unwrap())
                    )));
                }
                return Ok(Self { buf });
            }
            Err(TracerError::UnknownInterface(format!(
                "GetAdaptersAddresses did not success after {} attempts",
                Self::MAX_ATTEMPTS
            )))
        }
    }

    /// A named adapter address.
    #[derive(Debug)]
    pub struct AdapterAddress {
        /// The adapter friendly name.
        pub name: String,
        /// The adapter IpAddress.
        pub addr: IpAddr,
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
                _data: PhantomData::default(),
            }
        }
    }

    impl Iterator for AdaptersIter<'_> {
        type Item = AdapterAddress;

        fn next(&mut self) -> Option<Self::Item> {
            if self.next.is_null() {
                None
            } else {
                // Safety: `next` is not null and points to a valid IP_ADAPTER_ADDRESSES_LH
                #[allow(unsafe_code)]
                unsafe {
                    let friendly_name = WideCString::from_ptr_str((*self.next).FriendlyName)
                        .to_string()
                        .ok()?;
                    let addr = {
                        let first_unicast = (*self.next).FirstUnicastAddress;
                        let socket_address = (*first_unicast).Address;
                        let sockaddr = socket_address.lpSockaddr;

                        // Safety: TODO
                        let (_, addr) = SockAddr::try_init(|s, _length| {
                            // TODO or memcpy?
                            *s = *sockaddr.cast();
                            Ok(())
                        })
                        .unwrap();
                        addr.as_socket().unwrap().ip()
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
