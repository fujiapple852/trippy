use super::byte_order::Ipv4ByteOrder;
use crate::error::Result;
use crate::net::platform::Platform;
use std::net::IpAddr;

pub struct PlatformImpl;

impl Platform for PlatformImpl {
    #[allow(clippy::unnecessary_wraps)]
    fn byte_order_for_address(_addr: IpAddr) -> Result<Ipv4ByteOrder> {
        Ok(Ipv4ByteOrder::Network)
    }

    fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
        address::lookup_interface_addr(addr, name)
    }

    fn discover_local_addr(target_addr: IpAddr, _port: u16) -> Result<IpAddr> {
        address::routing_interface_query(target_addr)
    }
}

/// Execute a `Win32::Networking::WinSock` syscall.
///
/// The result of the syscall will be passed to the supplied boolean closure to determine if it
/// represents an error and if so returns the last OS error, otherwise the result of the syscall is
/// returned.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_fn: expr) => {{
        #[allow(unsafe_code)]
        let res = unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) };
        if $err_fn(res) {
            Err(StdIoError::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

mod address {
    use crate::error::{Error, Result};
    use crate::error::{IoError, IoOperation};
    use crate::net::socket::Socket;
    use crate::net::SocketImpl;
    use socket2::SockAddr;
    use std::io::Error as StdIoError;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::windows::io::AsRawSocket;
    use std::ptr::{addr_of_mut, null_mut};
    use tracing::instrument;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_ROUTING_INTERFACE_QUERY, SOCKADDR_STORAGE, SOCKET_ERROR,
    };

    /// Execute a `Win32::NetworkManagement::IpHelper` syscall.
    ///
    /// The raw result of the syscall is returned.
    macro_rules! syscall_ip_helper {
        ($fn: ident ( $($arg: expr),* $(,)* )) => {{
            #[allow(unsafe_code)]
            unsafe { windows_sys::Win32::NetworkManagement::IpHelper::$fn($($arg, )*) }
        }};
    }

    /// NOTE under Windows, we cannot use a bind connect/getsockname as "If the socket
    /// is using a connectionless protocol, the address may not be available until I/O
    /// occurs on the socket."  We use `SIO_ROUTING_INTERFACE_QUERY` instead.
    #[allow(clippy::cast_sign_loss, clippy::redundant_closure_call)]
    #[instrument(level = "trace")]
    pub(super) fn routing_interface_query(target: IpAddr) -> Result<IpAddr> {
        let socket = match target {
            IpAddr::V4(_) => SocketImpl::new_udp_dgram_socket_ipv4(),
            IpAddr::V6(_) => SocketImpl::new_udp_dgram_socket_ipv6(),
        }?;
        let dest = SockAddr::from(SocketAddr::new(target, 0));
        let src = SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let mut bytes_returned = 0;
        syscall!(
            WSAIoctl(
                socket.inner.as_raw_socket() as _,
                SIO_ROUTING_INTERFACE_QUERY,
                dest.as_ptr().cast(),
                dest.len() as u32,
                src.as_ptr().cast_mut().cast(),
                size_of::<SOCKADDR_STORAGE>() as u32,
                addr_of_mut!(bytes_returned),
                null_mut(),
                None,
            ),
            |res| res == SOCKET_ERROR
        )
        .map_err(|err| IoError::Other(err, IoOperation::SioRoutingInterfaceQuery))?;
        if let Some(socket) = src.as_socket() {
            Ok(socket.ip())
        } else {
            // TODO
            Err(Error::Other("TODO".to_string()))
        }
    }

    #[instrument(skip(addr), ret, level = "trace")]
    pub(super) fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
        let adapters = match addr {
            IpAddr::V4(_) => adapter::Adapters::ipv4()?,
            IpAddr::V6(_) => adapter::Adapters::ipv6()?,
        };
        adapters
            .iter()
            .find_map(|addr| {
                if addr.name.eq_ignore_ascii_case(name) {
                    Some(addr.addr)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::UnknownInterface(name.to_string()))
    }

    mod adapter {
        use crate::error::{Error, Result};
        use socket2::SockAddr;
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
                        &mut buf_len,
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
            /// The adapter `IpAddress`.
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
                            let ((), addr) = SockAddr::try_init(|s, _length| {
                                // TODO or `memcpy`?
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
}

mod socket {
    use crate::error::{Error, ErrorKind, IoError, IoOperation, IoResult};
    use crate::net::channel::MAX_PACKET_SIZE;
    use crate::net::socket::{Socket, SocketError};
    use itertools::Itertools;
    use socket2::{Domain, Protocol, SockAddr, Type};
    use std::io::{Error as StdIoError, ErrorKind as StdErrorKind, Result as StdIoResult};
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::windows::io::AsRawSocket;
    use std::ptr::{addr_of, addr_of_mut, null_mut};
    use std::time::Duration;
    use tracing::instrument;
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_TIMEOUT};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, FD_CONNECT, FD_WRITE, ICMP_ERROR_INFO, IPPROTO_RAW, IPPROTO_TCP,
        SOCKADDR, SOCKADDR_STORAGE, SOCKET_ERROR, SOL_SOCKET, SO_ERROR, SO_PORT_SCALABILITY,
        SO_REUSE_UNICASTPORT, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO, WSABUF, WSADATA,
        WSAEADDRNOTAVAIL, WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAENETUNREACH,
        WSAENOBUFS, WSA_IO_INCOMPLETE, WSA_IO_PENDING,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    /// Execute a `Win32::System::Threading` syscall.
    ///
    /// The raw result of the syscall is returned.
    macro_rules! syscall_threading {
        ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
            #[allow(unsafe_code)]
            unsafe { windows_sys::Win32::System::Threading::$fn($($arg, )*) }
        }};
    }

    #[instrument(level = "trace")]
    pub fn startup() -> crate::error::Result<()> {
        SocketImpl::startup().map_err(Error::IoError)
    }

    /// `WinSock` version 2.2
    const WINSOCK_VERSION: u16 = 0x202;

    /// A network socket.
    pub struct SocketImpl {
        pub(super) inner: socket2::Socket,
        ol: Box<OVERLAPPED>,
        buf: Box<[u8]>,
        from: Box<SockAddr>,
        from_len: i32,
        bytes_read: u32,
    }

    #[allow(clippy::cast_possible_wrap, clippy::redundant_closure_call)]
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
            let from = Box::new(SockAddr::from(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )));
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

        // TODO handle case where `WSARecvFrom` succeeded immediately.
        #[instrument(skip(self), level = "trace")]
        fn post_recv_from(&mut self) -> IoResult<()> {
            fn is_err(res: i32) -> bool {
                res == SOCKET_ERROR
                    && StdIoError::last_os_error().raw_os_error() != Some(WSA_IO_PENDING)
            }
            let from_storage_ptr: *mut SOCKADDR = self.from.as_ptr().cast_mut().cast();
            let from_len_ptr = addr_of_mut!(self.from_len);
            let overlapped_ptr = addr_of_mut!(*self.ol);
            let wbuf = WSABUF {
                len: MAX_PACKET_SIZE as u32,
                buf: self.buf.as_mut_ptr(),
            };
            syscall!(
                WSARecvFrom(
                    self.inner.as_raw_socket() as _,
                    addr_of!(wbuf),
                    1,
                    null_mut(),
                    &mut 0,
                    from_storage_ptr,
                    from_len_ptr,
                    overlapped_ptr,
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
                    &mut bytes_read,
                    0,
                    &mut flags,
                ),
                |res| { res == 0 }
            )
            .map_err(|err| IoError::Other(err, IoOperation::WSAGetOverlappedResult))?;
            self.bytes_read = bytes_read;
            Ok(())
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
                    &mut optlen,
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

        #[allow(unsafe_code)]
        const fn new_wsa_data() -> WSADATA {
            // Safety: an all-zero value is valid for `WSADATA`.
            unsafe { zeroed::<WSADATA>() }
        }

        #[allow(unsafe_code)]
        const fn new_overlapped() -> OVERLAPPED {
            // Safety: an all-zero value is valid for `OVERLAPPED.`
            unsafe { zeroed::<OVERLAPPED>() }
        }

        #[allow(unsafe_code)]
        const fn new_icmp_error_info() -> ICMP_ERROR_INFO {
            // Safety: an all-zero value is valid for `ICMP_ERROR_INFO`.
            unsafe { zeroed::<ICMP_ERROR_INFO>() }
        }
    }

    #[allow(clippy::redundant_closure_call)]
    impl Drop for SocketImpl {
        fn drop(&mut self) {
            if self.ol.hEvent != -1 && self.ol.hEvent != 0 {
                syscall!(WSACloseEvent(self.ol.hEvent), |res| { res == 0 }).unwrap_or_default();
            }
        }
    }

    #[allow(clippy::cast_possible_wrap, clippy::redundant_closure_call)]
    impl Socket for SocketImpl {
        #[instrument(level = "trace")]
        fn new_icmp_send_socket_ipv4(raw: bool) -> IoResult<Self> {
            if raw {
                let mut sock =
                    Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
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
                let mut sock =
                    Self::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
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
                .set_tos(tos)
                .map_err(|err| IoError::Other(err, IoOperation::SetTos))
        }

        #[instrument(skip(self), level = "trace")]
        fn set_ttl(&mut self, ttl: u32) -> IoResult<()> {
            self.inner
                .set_ttl(ttl)
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
            };
            while let Err(err) = self.get_overlapped_result() {
                if err.kind()
                    != ErrorKind::Std(StdIoError::from_raw_os_error(WSA_IO_INCOMPLETE).kind())
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
            };
            while let Err(err) = self.get_overlapped_result() {
                if err.kind()
                    != ErrorKind::Std(StdIoError::from_raw_os_error(WSA_IO_INCOMPLETE).kind())
                {
                    return Err(err);
                }
            }
            self.reset_event()?;
            Ok(true)
        }

        #[instrument(skip(self, buf), level = "trace")]
        fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, Option<SocketAddr>)> {
            let addr = self.from.as_socket();
            let len = self.read(buf)?;
            tracing::trace!(
                buf = format!("{:02x?}", buf[..len].iter().format(" ")),
                len,
                ?addr
            );
            Ok((len, addr))
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
        #[allow(unsafe_code)]
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
}

pub use socket::{startup, SocketImpl};
