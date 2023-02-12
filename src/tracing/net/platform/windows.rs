use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::socket::TracerSocket;
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::mem::{align_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr::{addr_of, addr_of_mut, null_mut};
use std::time::Duration;
use widestring::WideCString;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WAIT_FAILED, WAIT_TIMEOUT};
use windows_sys::Win32::NetworkManagement::IpHelper;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, FD_CONNECT, FD_WRITE, FIONBIO, ICMP_ERROR_INFO, IN6_ADDR,
    IN6_ADDR_0, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO, IPPROTO_ICMP, IPPROTO_ICMPV6,
    IPPROTO_IP, IPPROTO_IPV6, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP, IPV6_UNICAST_HOPS, IP_HDRINCL,
    IP_TOS, IP_TTL, SD_BOTH, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    SOL_SOCKET, SO_ERROR, SO_PORT_SCALABILITY, SO_REUSE_UNICASTPORT,
    TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO, WSABUF, WSADATA, WSAECONNREFUSED,
    WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEWOULDBLOCK, WSA_IO_INCOMPLETE, WSA_IO_PENDING,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

macro_rules! syscall_threading {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code)]
        unsafe { windows_sys::Win32::System::Threading::$fn($($arg, )*) }
    }};
}

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code)]
        unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) }
    }};
}

macro_rules! syscall_invalid_socket {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = syscall!( $fn($($arg, )*) );
        if res == INVALID_SOCKET {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_zero {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = syscall!( $fn($($arg, )*) );
        if res != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_is_invalid {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = syscall!( $fn($($arg, )*) );
        if res == 0 || res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_bool {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = syscall!( $fn($($arg, )*) );
        if res == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_socket_error {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = syscall!( $fn($($arg, )*) );
        if res == SOCKET_ERROR {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET6, name)
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
    s: SOCKET,
    ol: Box<OVERLAPPED>,
    buf: Vec<u8>,
    from: Box<SOCKADDR_STORAGE>,
}

#[allow(clippy::cast_possible_wrap)]
#[allow(unsafe_code)]
impl Socket {
    fn startup() -> Result<()> {
        let mut wsa_data = unsafe { zeroed::<WSADATA>() };
        syscall_zero!(WSAStartup(WINSOCK_VERSION, addr_of_mut!(wsa_data))).map(|_| ())
    }

    fn new(af: ADDRESS_FAMILY, ty: u16, protocol: IPPROTO) -> Result<Self> {
        let s = syscall_invalid_socket!(socket(i32::from(af), i32::from(ty), protocol))?;
        let from = Box::new(unsafe { zeroed::<SOCKADDR_STORAGE>() });
        let ol = Box::new(unsafe { zeroed::<OVERLAPPED>() });
        let buf = vec![0u8; MAX_PACKET_SIZE];
        Ok(Self { s, ol, buf, from })
    }

    fn create_event(&mut self) -> Result<()> {
        self.ol.hEvent = syscall_is_invalid!(WSACreateEvent())?;
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
        syscall_bool!(WSAResetEvent(self.ol.hEvent)).map(|_| ())
    }

    fn getsockopt<T>(&self, level: i32, optname: i32) -> Result<T> {
        let mut optval = unsafe { zeroed::<T>() };
        let mut optlen = size_of::<T>() as i32;
        syscall_socket_error!(getsockopt(
            self.s,
            level,
            optname,
            addr_of_mut!(optval).cast(),
            &mut optlen,
        ))?;
        Ok(optval)
    }

    fn setsockopt_u32(&self, level: i32, optname: i32, optval: u32) -> Result<()> {
        syscall_socket_error!(setsockopt(
            self.s,
            level,
            optname,
            addr_of!(optval).cast(),
            size_of::<u32>() as i32,
        ))
        .map(|_| ())
    }

    fn setsockopt_bool(&self, level: i32, optname: i32, optval: bool) -> Result<()> {
        self.setsockopt_u32(level, optname, u32::from(optval))
    }

    fn set_fail_connect_on_icmp_error(&self, enabled: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_TCP, TCP_FAIL_CONNECT_ON_ICMP_ERROR as _, enabled)
    }

    // NOTE FIONBIO is really unsigned (in WinSock2.h)
    #[allow(clippy::cast_sign_loss)]
    fn set_non_blocking(&self, is_non_blocking: bool) -> Result<()> {
        let non_blocking: u32 = u32::from(is_non_blocking);
        syscall_socket_error!(WSAIoctl(
            self.s,
            FIONBIO as u32,
            addr_of!(non_blocking).cast(),
            size_of::<u32>() as u32,
            null_mut(),
            0,
            &mut 0,
            null_mut(),
            None,
        ))
        .map(|_| ())
    }

    fn post_recv_from(&mut self) -> Result<()> {
        let mut fromlen = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;
        let wbuf = WSABUF {
            len: MAX_PACKET_SIZE as u32,
            buf: self.buf.as_mut_ptr(),
        };
        let ret = syscall!(WSARecvFrom(
            self.s,
            addr_of!(wbuf),
            1,
            null_mut(),
            &mut 0,
            addr_of_mut!(*self.from).cast(),
            addr_of_mut!(fromlen),
            addr_of_mut!(*self.ol),
            None,
        ));
        if ret == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSA_IO_PENDING) {
                return Err(Error::last_os_error());
            }
        } else {
            // TODO no need to wait for an event, recv succeeded immediately! This should be handled
        }
        Ok(())
    }

    fn get_overlapped_result(&self) -> Result<(u32, u32)> {
        let mut bytes = 0;
        let mut flags = 0;
        let ol = *self.ol;
        syscall_bool!(WSAGetOverlappedResult(
            self.s,
            addr_of!(ol),
            &mut bytes,
            0,
            &mut flags,
        ))?;
        Ok((bytes, flags))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // TODO can we unconditionally close the socket?
        syscall_socket_error!(closesocket(self.s)).unwrap_or_default();
        if self.ol.hEvent != -1 && self.ol.hEvent != 0 {
            syscall_bool!(WSACloseEvent(self.ol.hEvent)).unwrap_or_default();
        }
    }
}

#[allow(clippy::cast_possible_wrap)]
impl TracerSocket for Socket {
    fn new_icmp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::new(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_icmp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::new(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::new(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::new(AF_INET6, SOCK_RAW, IPPROTO_UDP)?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv4(src_addr: Ipv4Addr) -> Result<Self> {
        let mut sock = Self::new(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
        sock.bind(SocketAddr::new(IpAddr::V4(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv6(src_addr: Ipv6Addr) -> Result<Self> {
        let mut sock = Self::new(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
        sock.bind(SocketAddr::new(IpAddr::V6(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv4() -> Result<Self> {
        let sock = Self::new(AF_INET, SOCK_STREAM, IPPROTO_TCP)?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv6() -> Result<Self> {
        let sock = Self::new(AF_INET6, SOCK_STREAM, IPPROTO_TCP)?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_udp_dgram_socket_ipv4() -> Result<Self> {
        Self::new(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    }

    fn new_udp_dgram_socket_ipv6() -> Result<Self> {
        Self::new(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    }

    fn bind(&mut self, source_socketaddr: SocketAddr) -> Result<()> {
        let (addr, addrlen) = socketaddr_to_sockaddr(source_socketaddr);
        // DEBUG
        // eprint!("bind[{}]: ", self.s);
        // let res = syscall_socket_error!(bind(self.s, addr_of!(addr).cast(), addrlen));
        // match res {
        //     Ok(_) => {
        //         eprintln!("ok");
        //     }
        //     Err(e) => {
        //         eprintln!("failed");
        //         return Err(e);
        //     }
        // };
        syscall_socket_error!(bind(self.s, addr_of!(addr).cast(), addrlen))?;
        self.create_event()?;
        Ok(())
    }

    fn set_tos(&self, tos: u32) -> Result<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TOS as _, tos)
    }

    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TTL as _, ttl)
    }

    fn set_reuse_port(&self, is_reuse_port: bool) -> Result<()> {
        self.setsockopt_bool(SOL_SOCKET as _, SO_REUSE_UNICASTPORT as _, is_reuse_port)
            .or_else(|_| {
        self.setsockopt_bool(SOL_SOCKET as _, SO_PORT_SCALABILITY as _, is_reuse_port)
            })
    }

    fn set_header_included(&self, is_header_included: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_IP as _, IP_HDRINCL as _, is_header_included)
    }

    fn set_unicast_hops_v6(&self, max_hops: u8) -> Result<()> {
        syscall_socket_error!(setsockopt(
            self.s,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS as i32,
            addr_of!(max_hops).cast(),
            size_of::<u8>() as i32,
        ))
        .map(|_| ())
    }

    fn connect(&self, dest_socketaddr: SocketAddr) -> Result<()> {
        self.set_fail_connect_on_icmp_error(true)?;
        syscall_socket_error!(WSAEventSelect(
            self.s,
            self.ol.hEvent,
            (FD_CONNECT | FD_WRITE) as _
        ))?;
        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        let rc = syscall!(connect(self.s, addr_of!(addr).cast(), addrlen));
        if rc == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSAEWOULDBLOCK) {
                return Err(Error::last_os_error());
            }
        } else {
            // TODO
        }
        Ok(())
    }

    fn send_to(&self, packet: &[u8], dest_socketaddr: SocketAddr) -> Result<()> {
        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        syscall_socket_error!(sendto(
            self.s,
            addr_of!(packet[0]),
            packet.len() as i32,
            0,
            addr_of!(addr).cast(),
            addrlen,
        ))
        .map(|_| ())
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
        let addr = sockaddrptr_to_ipaddr(addr_of_mut!(*self.from))?;
        let len = self.read(buf)?;
        Ok((len, Some(SocketAddr::new(addr, 0))))
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
        syscall_socket_error!(shutdown(self.s, SD_BOTH as i32)).map(|_| ())
    }

    #[allow(unsafe_code)]
    fn peer_addr(&self) -> Result<Option<SocketAddr>> {
        let mut name = unsafe { zeroed::<SOCKADDR_STORAGE>() };
        let mut namelen = size_of::<SOCKADDR_STORAGE>() as i32;
        syscall_socket_error!(getpeername(self.s, addr_of_mut!(name).cast(), &mut namelen))?;
        Ok(Some(sockaddr_to_socketaddr(&name)?))
    }

    fn take_error(&self) -> Result<Option<Error>> {
        match self.getsockopt(SOL_SOCKET as _, SO_ERROR as _) {
            Ok(0) => Ok(None),
            Ok(errno) => Ok(Some(Error::from_raw_os_error(errno))),
            Err(e) => Err(e),
        }
    }

    #[allow(unsafe_code)]
    fn icmp_error_info(&self) -> Result<IpAddr> {
        let icmp_error_info =
            self.getsockopt::<ICMP_ERROR_INFO>(IPPROTO_TCP as _, TCP_ICMP_ERROR_INFO as _)?;
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

    fn close(&self) -> Result<()> {
        syscall_socket_error!(closesocket(self.s)).map(|_| ())
    }
}

/// NOTE under Windows, we cannot use a blind connect/getsockname as "If the socket
/// is using a connectionless protocol, the address may not be available until I/O
/// occurs on the socket."  We use `SIO_ROUTING_INTERFACE_QUERY` instead.
#[allow(clippy::cast_sign_loss)]
fn routing_interface_query(target: IpAddr) -> TraceResult<IpAddr> {
    let src: *mut c_void = [0; 1024].as_mut_ptr().cast();
    let mut bytes = 0;
    let socket = match target {
        IpAddr::V4(_) => Socket::new_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => Socket::new_udp_dgram_socket_ipv6(),
    }?;
    let (dest, destlen) = socketaddr_to_sockaddr(SocketAddr::new(target, 0));
    syscall_socket_error!(WSAIoctl(
        socket.s,
        SIO_ROUTING_INTERFACE_QUERY,
        addr_of!(dest).cast(),
        destlen as u32,
        src,
        1024,
        addr_of_mut!(bytes),
        null_mut(),
        None,
    ))?;
    // Note that the WSAIoctl call potentially returns multiple results (see
    // <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
    // TBD We choose the first one arbitrarily.
    let sockaddr = src.cast::<SOCKADDR_STORAGE>();
    sockaddrptr_to_ipaddr(sockaddr).map_err(TracerError::IoError)
}

/// # Panics
///
/// Will panic if `FriendlyName` or `FistUnicastAddress.Address.lpSockaddr` raw pointer members of the `IP_ADAPTER_ADDRESSES_LH`
/// linked list structure are null or misaligned.
// inspired by <https://github.com/EstebanBorai/network-interface/blob/main/src/target/windows.rs>
#[allow(unsafe_code)]
fn lookup_interface_addr(family: ADDRESS_FAMILY, name: &str) -> TraceResult<IpAddr> {
    // Max tries allowed to call `GetAdaptersAddresses` on a loop basis
    const MAX_TRIES: usize = 3;
    let flags = IpHelper::GAA_FLAG_SKIP_ANYCAST
        | IpHelper::GAA_FLAG_SKIP_MULTICAST
        | IpHelper::GAA_FLAG_SKIP_DNS_SERVER;
    // Initial buffer size is 15k per <https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses>
    let mut buf_len: u32 = 15000;
    let mut layout;
    let mut list_ptr;
    let mut ip_adapter_addresses;
    let mut res;
    let mut i = 0;

    loop {
        layout = match Layout::from_size_align(
            buf_len as usize,
            align_of::<IpHelper::IP_ADAPTER_ADDRESSES_LH>(),
        ) {
            Ok(layout) => layout,
            Err(e) => {
                return Err(TracerError::UnknownInterface(format!(
                    "Could not compute layout for {buf_len} words: {e}"
                )));
            }
        };
        // Safety: TODO
        list_ptr = unsafe { alloc(layout) };
        if list_ptr.is_null() {
            return Err(TracerError::UnknownInterface(format!(
                "Could not allocate {buf_len} words for layout {layout:?}"
            )));
        }
        ip_adapter_addresses = list_ptr.cast();
        // Safety: TODO
        res = unsafe {
            IpHelper::GetAdaptersAddresses(
                u32::from(family),
                flags,
                null_mut(),
                ip_adapter_addresses,
                &mut buf_len,
            )
        };
        i += 1;

        if res != ERROR_BUFFER_OVERFLOW || i > MAX_TRIES {
            break;
        }
        // Safety: TODO
        unsafe { dealloc(list_ptr, layout) };
    }

    if res != NO_ERROR {
        return Err(TracerError::UnknownInterface(format!(
            "GetAdaptersAddresses returned error: {}",
            Error::from_raw_os_error(res.try_into().unwrap())
        )));
    }

    while !ip_adapter_addresses.is_null() {
        // Safety: TODO
        let friendly_name = unsafe {
            let friendly_name = (*ip_adapter_addresses).FriendlyName;
            WideCString::from_ptr_str(friendly_name)
                .to_string()
                .unwrap()
        };
        if name == friendly_name {
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            // Safety: TODO
            let current_unicast = unsafe { (*ip_adapter_addresses).FirstUnicastAddress };
            // while !current_unicast.is_null() {
            // Safety: TODO
            unsafe {
                let socket_address = (*current_unicast).Address;
                // let sockaddr = socket_address.lpSockaddr.as_ref().unwrap();
                let sockaddr = socket_address.lpSockaddr;
                let ip_addr = sockaddrptr_to_ipaddr(sockaddr.cast())?;
                dealloc(list_ptr, layout);
                return Ok(ip_addr);
            }
            // current_unicast = unsafe { (*current_unicast).Next };
            // }
        }
        // Safety: TODO
        ip_adapter_addresses = unsafe { (*ip_adapter_addresses).Next };
    }
    // Safety: TODO
    unsafe {
        dealloc(list_ptr, layout);
    }

    Err(TracerError::UnknownInterface(format!(
        "could not find address for {name}"
    )))
}

#[allow(unsafe_code)]
fn sockaddrptr_to_ipaddr(sockaddr: *mut SOCKADDR_STORAGE) -> Result<IpAddr> {
    // Safety: TODO
    match sockaddr_to_socketaddr(unsafe { sockaddr.as_ref().unwrap() }) {
        Err(e) => Err(e),
        Ok(socketaddr) => match socketaddr {
            SocketAddr::V4(socketaddrv4) => Ok(IpAddr::V4(*socketaddrv4.ip())),
            SocketAddr::V6(socketaddrv6) => Ok(IpAddr::V6(*socketaddrv6.ip())),
        },
    }
}

#[allow(unsafe_code)]
fn sockaddr_to_socketaddr(sockaddr: &SOCKADDR_STORAGE) -> Result<SocketAddr> {
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
        #[allow(clippy::cast_ptr_alignment)]
        let sockaddr_in6_ptr = ptr.cast::<SOCKADDR_IN6>();
        // Safety: TODO
        let sockaddr_in6 = unsafe { *sockaddr_in6_ptr };
        // Safety: TODO
        // TODO: check endianness
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
        Err(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported address family: {af:?}"),
        ))
    }
}

#[allow(unsafe_code)]
#[allow(clippy::cast_possible_wrap)]
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
