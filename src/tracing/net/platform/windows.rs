use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::socket::TracerSocket;
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::fmt::{self};
use std::io::{Error, ErrorKind, Result};
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr::{addr_of, addr_of_mut};
use std::time::Duration;
use windows::core::PSTR;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{
    bind, closesocket, connect, getpeername, getsockopt, sendto, setsockopt, shutdown, socket,
    WSACloseEvent, WSACreateEvent, WSAEventSelect, WSAGetOverlappedResult, WSAIoctl, WSARecvFrom,
    WSAResetEvent, WSAStartup, ADDRESS_FAMILY, AF_INET, AF_INET6, FD_CONNECT, FD_WRITE, FIONBIO,
    ICMP_ERROR_INFO, INVALID_SOCKET, IPPROTO, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP,
    IPPROTO_IPV6, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP, IPV6_UNICAST_HOPS, IP_HDRINCL, IP_TOS,
    IP_TTL, SD_BOTH, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_STORAGE,
    SOCKET, SOCKET_ERROR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_SOCKET, SO_ERROR,
    SO_PORT_SCALABILITY, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO, WSABUF, WSADATA,
    WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEWOULDBLOCK, WSA_IO_INCOMPLETE,
    WSA_IO_PENDING,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::IO::OVERLAPPED;

/// `WinSock` version 2.2
const WINSOCK_VERSION: u16 = 0x202;

macro_rules! syscall_raw {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        unsafe { $fn($($arg, )*) }
    }};
}

macro_rules! syscall_invalid_socket {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        let res = unsafe { $fn($($arg, )*) };
        if res == INVALID_SOCKET {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_zero {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        let res = unsafe { $fn($($arg, )*) };
        if res != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

macro_rules! syscall_is_invalid {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        let res = unsafe { $fn($($arg, )*) };
        if res.is_invalid() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

macro_rules! syscall_bool {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        let res = unsafe { $fn($($arg, )*) };
        if res.as_bool() == false {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

macro_rules! syscall_socket_error {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unsafe_code, unused_unsafe)]
        let res = unsafe { $fn($($arg, )*) };
        if res == SOCKET_ERROR {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

pub struct Socket {
    s: SOCKET,
    ol: Box<OVERLAPPED>,
    wbuf: Vec<u8>,
    wbuf_len: u32,
    from: Box<SOCKADDR_STORAGE>,
}

impl Socket {
    fn create(af: ADDRESS_FAMILY, r#type: u16, protocol: IPPROTO) -> Result<Self> {
        let s = syscall_invalid_socket!(socket(
            af.0.try_into().unwrap(),
            i32::from(r#type),
            protocol.0
        ))?;
        let from = Box::<SOCKADDR_STORAGE>::default();
        let ol = Box::<OVERLAPPED>::default();
        let wbuf = vec![0u8; MAX_PACKET_SIZE];
        let wbuf_len = MAX_PACKET_SIZE as u32;
        Ok(Self {
            s,
            ol,
            wbuf,
            wbuf_len,
            from,
        })
    }

    fn udp_from(target: IpAddr) -> Result<Self> {
        let s = match target {
            IpAddr::V4(_) => Self::create(AF_INET, SOCK_DGRAM, IPPROTO_UDP),
            IpAddr::V6(_) => Self::create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP),
        }?;
        Ok(s)
    }

    fn create_event(&mut self) -> Result<()> {
        self.ol.hEvent = syscall_is_invalid!(WSACreateEvent())?;
        Ok(())
    }

    fn wait_for_event(&self, timeout: Duration) -> Result<bool> {
        let millis = timeout.as_millis() as u32;
        let rc = syscall_raw!(WaitForSingleObject(self.ol.hEvent, millis));
        if rc == WAIT_TIMEOUT {
            return Ok(false);
        } else if rc == WAIT_FAILED {
            return Err(Error::last_os_error());
        }
        Ok(true)
    }

    // TODO should be &mut self ?
    fn reset_event(&self) -> Result<()> {
        Ok(syscall_bool!(WSAResetEvent(self.ol.hEvent))?)
    }

    // NOTE FIONBIO is really unsigned (in WinSock2.h)
    #[allow(clippy::cast_sign_loss)]
    fn set_non_blocking(&self, is_non_blocking: bool) -> Result<()> {
        let non_blocking: u32 = u32::from(is_non_blocking);
        Ok(syscall_socket_error!(WSAIoctl(
            self.s,
            FIONBIO as u32,
            Some(addr_of!(non_blocking).cast()),
            size_of::<u32>().try_into().unwrap(),
            None,
            0,
            &mut 0,
            None,
            None,
        ))?)
    }

    fn from(&mut self) -> Result<IpAddr> {
        sockaddrptr_to_ipaddr(addr_of_mut!(*self.from))
    }

    fn setsockopt_bool(&self, level: i32, optname: i32, optval: bool) -> Result<()> {
        self.setsockopt_u32(level, optname, u32::from(optval))
    }

    fn setsockopt_u32(&self, level: i32, optname: i32, optval: u32) -> Result<()> {
        let bytes_array = optval.to_ne_bytes();
        let bytes_slice_ref_option = Some(&bytes_array[..]);
        Ok(syscall_socket_error!(setsockopt(
            self.s,
            level,
            optname,
            bytes_slice_ref_option
        ))?)
    }

    fn get_overlapped_result(&self) -> Result<(u32, u32)> {
        let mut bytes = 0;
        let mut flags = 0;
        let ol = *self.ol;
        syscall_bool!(WSAGetOverlappedResult(
            self.s,
            addr_of!(ol),
            &mut bytes,
            false,
            &mut flags,
        ))?;
        Ok((bytes, flags))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn getsockopt<T: Default>(&self, level: i32, optname: i32) -> Result<T> {
        let mut optval = T::default();
        let mut optlen = size_of::<T>() as i32;
        syscall_socket_error!(getsockopt(
            self.s,
            level,
            optname,
            PSTR::from_raw(addr_of_mut!(optval).cast()),
            &mut optlen,
        ))?;
        Ok(optval)
    }

    fn is_writable_overlapped(&self) -> Result<bool> {
        if !self.wait_for_event(Duration::ZERO)? {
            return Ok(false);
        };
        while let Err(err) = self.get_overlapped_result() {
            if err.raw_os_error() != Some(WSA_IO_INCOMPLETE.0) {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_fail_connect_on_icmp_error(&self, enabled: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_TCP.0, TCP_FAIL_CONNECT_ON_ICMP_ERROR as _, enabled)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn post_recv_from(&mut self) -> Result<()> {
        let mut fromlen = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;
        let wbuf = WSABUF {
            len: self.wbuf_len,
            buf: PSTR::from_raw(self.wbuf.as_mut_ptr()),
        };
        let ret = syscall_raw!(WSARecvFrom(
            self.s,
            &[wbuf],
            Some(&mut 0),
            &mut 0,
            Some(addr_of_mut!(*self.from).cast()),
            Some(&mut fromlen),
            Some(&mut *self.ol),
            None,
        ));
        if ret == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSA_IO_PENDING.0) {
                return Err(Error::last_os_error());
            }
        } else {
            // TODO no need to wait for an event, recv succeeded immediately! This should be handled
        }
        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        syscall_socket_error!(closesocket(self.s)).unwrap_or_default();
        if !self.ol.hEvent.is_invalid() {
            syscall_bool!(WSACloseEvent(self.ol.hEvent)).unwrap_or_default();
        }
    }
}

impl TracerSocket for Socket {
    fn new_icmp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_icmp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv4() -> Result<Self> {
        let sock = Self::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_udp_send_socket_ipv6() -> Result<Self> {
        let sock = Self::create(AF_INET6, SOCK_RAW, IPPROTO_UDP)?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv4(src_addr: Ipv4Addr) -> Result<Self> {
        let mut sock = Self::create(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
        sock.bind(SocketAddr::new(IpAddr::V4(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        sock.set_header_included(true)?;
        Ok(sock)
    }

    fn new_recv_socket_ipv6(src_addr: Ipv6Addr) -> Result<Self> {
        let mut sock = Self::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
        sock.bind(SocketAddr::new(IpAddr::V6(src_addr), 0))?;
        sock.post_recv_from()?;
        sock.set_non_blocking(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv4() -> Result<Self> {
        let sock = Self::create(AF_INET, SOCK_STREAM, IPPROTO_TCP)?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_stream_socket_ipv6() -> Result<Self> {
        let sock = Self::create(AF_INET6, SOCK_STREAM, IPPROTO_TCP)?;
        sock.set_non_blocking(true)?;
        sock.set_reuse_port(true)?;
        Ok(sock)
    }

    fn new_udp_dgram_socket_ipv4() -> Result<Self> {
        Self::create(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    }

    fn new_udp_dgram_socket_ipv6() -> Result<Self> {
        Self::create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn bind(&mut self, source_socketaddr: SocketAddr) -> Result<()> {
        let (addr, addrlen) = socketaddr_to_sockaddr(source_socketaddr);
        syscall_socket_error!(bind(self.s, addr_of!(addr).cast(), addrlen as i32))?;
        self.create_event()?;
        Ok(())
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_tos(&self, tos: u32) -> Result<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TOS as _, tos)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TTL as _, ttl)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_reuse_port(&self, is_reuse_port: bool) -> Result<()> {
        self.setsockopt_bool(SOL_SOCKET as _, SO_PORT_SCALABILITY as _, is_reuse_port)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_header_included(&self, is_header_included: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_IP as _, IP_HDRINCL as _, is_header_included)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_unicast_hops_v6(&self, max_hops: u8) -> Result<()> {
        syscall_socket_error!(setsockopt(
            self.s,
            IPPROTO_IPV6.0,
            IPV6_UNICAST_HOPS as i32,
            Some(&[max_hops]),
        ))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn connect(&self, dest_socketaddr: SocketAddr) -> Result<()> {
        self.set_fail_connect_on_icmp_error(true)?;
        syscall_socket_error!(WSAEventSelect(
            self.s,
            self.ol.hEvent,
            (FD_CONNECT | FD_WRITE) as _
        ))?;
        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        let rc = syscall_raw!(connect(self.s, addr_of!(addr).cast(), addrlen as i32));
        if rc == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSAEWOULDBLOCK.0) {
                return Err(Error::last_os_error());
            }
        } else {
            // TODO
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_wrap)]
    fn send_to(&self, packet: &[u8], dest_socketaddr: SocketAddr) -> Result<()> {
        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        syscall_socket_error!(sendto(
            self.s,
            packet,
            0,
            addr_of!(addr).cast(),
            addrlen as i32,
        ))
    }

    fn is_readable(&self, timeout: Duration) -> Result<bool> {
        if !self.wait_for_event(timeout)? {
            return Ok(false);
        };
        while let Err(err) = self.get_overlapped_result() {
            if err.raw_os_error() != Some(WSA_IO_INCOMPLETE.0) {
                return Err(err);
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    fn is_writable(&self) -> Result<bool> {
        self.is_writable_overlapped()
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>)> {
        let addr = self.from()?;
        let len = self.read(buf)?;
        Ok((len, Some(SocketAddr::new(addr, 0))))
    }

    // #[allow(unsafe_code)]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // let buf_ptr = self.wbuf.buf.as_ptr();
        // // Safety: TODO
        // let slice = unsafe { std::slice::from_raw_parts(buf_ptr, self.wbuf.len as usize) };
        // buf.copy_from_slice(slice);

        buf.copy_from_slice(self.wbuf.as_slice());
        self.post_recv_from()?;
        Ok(self.wbuf_len as usize)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn shutdown(&self) -> Result<()> {
        Ok(syscall_socket_error!(shutdown(self.s, SD_BOTH as i32))?)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn peer_addr(&self) -> Result<Option<SocketAddr>> {
        let mut name = SOCKADDR_STORAGE::default();
        let mut namelen = size_of::<SOCKADDR_STORAGE>() as i32;
        syscall_socket_error!(getpeername(self.s, addr_of_mut!(name).cast(), &mut namelen))?;
        Ok(Some(sockaddr_to_socketaddr(&name)?))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn take_error(&self) -> Result<Option<Error>> {
        match self.getsockopt(SOL_SOCKET as _, SO_ERROR as _) {
            Ok(0) => Ok(None),
            Ok(errno) => Ok(Some(Error::from_raw_os_error(errno))),
            Err(e) => Err(e),
        }
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    fn icmp_error_info(&self) -> Result<IpAddr> {
        let icmp_error_info =
            self.getsockopt::<ICMP_ERROR_INFO>(IPPROTO_TCP.0 as _, TCP_ICMP_ERROR_INFO as _)?;
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
        syscall_socket_error!(closesocket(self.s))
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket").field("s", &self.s).finish()
    }
}

pub fn startup() -> Result<()> {
    let mut wsa_data = WSADATA::default();
    syscall_zero!(WSAStartup(WINSOCK_VERSION, addr_of_mut!(wsa_data)))
}

#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
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
    let mut ip_adapter_address;
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
                    "Could not compute layout for {} words: {}",
                    buf_len, e
                )));
            }
        };
        // Safety: TODO
        list_ptr = unsafe { alloc(layout) };
        if list_ptr.is_null() {
            return Err(TracerError::UnknownInterface(format!(
                "Could not allocate {} words for layout {:?}",
                buf_len, layout
            )));
        }
        ip_adapter_address = list_ptr.cast();
        // Safety: TODO
        res = unsafe {
            IpHelper::GetAdaptersAddresses(
                u32::from(family.0),
                flags,
                None,
                Some(ip_adapter_address),
                &mut buf_len,
            )
        };
        i += 1;

        if res != ERROR_BUFFER_OVERFLOW.0 || i > MAX_TRIES {
            break;
        }
        // Safety: TODO
        unsafe { dealloc(list_ptr, layout) };
    }

    if res != NO_ERROR.0 {
        return Err(TracerError::UnknownInterface(format!(
            "GetAdaptersAddresses returned error: {}",
            Error::from_raw_os_error(res.try_into().unwrap())
        )));
    }

    while !ip_adapter_address.is_null() {
        // Safety: TODO
        let friendly_name = unsafe { (*ip_adapter_address).FriendlyName.to_string().unwrap() };
        if name == friendly_name {
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            // Safety: TODO
            let current_unicast = unsafe { (*ip_adapter_address).FirstUnicastAddress };
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
        ip_adapter_address = unsafe { (*ip_adapter_address).Next };
    }
    // Safety: TODO
    unsafe {
        dealloc(list_ptr, layout);
    }

    Err(TracerError::UnknownInterface(format!(
        "could not find address for {}",
        name
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
        let ipv4addr = sockaddr_in.sin_addr;
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
        let ipv6addr = sockaddr_in6.sin6_addr;
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
#[must_use]
fn socketaddr_to_sockaddr(socketaddr: SocketAddr) -> (SOCKADDR_STORAGE, u32) {
    let mut storage = SOCKADDR_STORAGE::default();
    let len = match socketaddr {
        SocketAddr::V4(socketaddrv4) => {
            let sa: SOCKADDR_IN = socketaddrv4.into();
            // Safety: TODO
            unsafe {
                std::ptr::copy_nonoverlapping(
                    addr_of!(sa).cast::<u8>(),
                    addr_of_mut!(storage).cast::<u8>(),
                    size_of::<SOCKADDR_IN>(),
                );
            };
            size_of::<SOCKADDR_IN>() as u32
        }
        SocketAddr::V6(socketaddrv6) => {
            let sa: SOCKADDR_IN6 = socketaddrv6.into();
            // Safety: TODO
            unsafe {
                std::ptr::copy_nonoverlapping(
                    addr_of!(sa).cast::<u8>(),
                    addr_of_mut!(storage).cast::<u8>(),
                    size_of::<SOCKADDR_IN6>(),
                );
            };
            size_of::<SOCKADDR_IN6>() as u32
        }
    };
    (storage, len)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET6, name)
}

pub fn routing_interface_query(target: IpAddr) -> TraceResult<IpAddr> {
    let src: *mut c_void = [0; 1024].as_mut_ptr().cast();
    let mut bytes = 0;
    let socket = Socket::udp_from(target)?;
    let (dest, destlen) = socketaddr_to_sockaddr(SocketAddr::new(target, 0));
    syscall_socket_error!(WSAIoctl(
        socket.s,
        SIO_ROUTING_INTERFACE_QUERY,
        Some(addr_of!(dest).cast()),
        destlen,
        Some(src),
        1024,
        addr_of_mut!(bytes),
        None,
        None,
    ))?;
    // Note that the WSAIoctl call potentially returns multiple results (see
    // <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
    // TBD We choose the first one arbitrarily.
    let sockaddr = src.cast::<SOCKADDR_STORAGE>();
    sockaddrptr_to_ipaddr(sockaddr).map_err(TracerError::IoError)
}

/// NOTE under Windows, we cannot use a blind connect/getsockname as "If the socket
/// is using a connectionless protocol, the address may not be available until I/O
/// occurs on the socket."
/// We use `SIO_ROUTING_INTERFACE_QUERY` instead.
pub fn discover_local_addr(target: IpAddr, _port: u16) -> TraceResult<IpAddr> {
    routing_interface_query(target)
}

#[must_use]
pub fn is_not_in_progress_error(code: i32) -> bool {
    code != WSAEINPROGRESS.0
}

#[must_use]
pub fn is_conn_refused_error(code: i32) -> bool {
    code == WSAECONNREFUSED.0
}

#[must_use]
pub fn is_host_unreachable_error(code: i32) -> bool {
    code == WSAEHOSTUNREACH.0
}
