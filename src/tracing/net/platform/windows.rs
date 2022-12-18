use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use core::convert;
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::fmt::{self};
use std::io::{Error, ErrorKind, Result};
use std::mem::MaybeUninit;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use windows::core::PSTR;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{
    bind, closesocket, connect, getpeername, getsockopt, sendto, setsockopt, shutdown, socket,
    WSACleanup, WSACloseEvent, WSACreateEvent, WSAEventSelect, WSAGetOverlappedResult, WSAIoctl,
    WSARecvFrom, WSAResetEvent, WSAStartup, ADDRESS_FAMILY, AF_INET, AF_INET6, FD_CONNECT,
    FD_WRITE, FIONBIO, ICMP_ERROR_INFO, INVALID_SOCKET, IPPROTO, IPPROTO_ICMP, IPPROTO_ICMPV6,
    IPPROTO_IP, IPPROTO_IPV6, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP, IPV6_UNICAST_HOPS, IP_HDRINCL,
    IP_TOS, IP_TTL, SD_BOTH, SD_RECEIVE, SD_SEND, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    SOL_SOCKET, SO_ERROR, SO_PORT_SCALABILITY, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO,
    WSABUF, WSADATA, WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEWOULDBLOCK,
    WSA_IO_INCOMPLETE, WSA_IO_PENDING,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::IO::OVERLAPPED;

// type Socket = SOCKET;
pub struct Socket {
    s: SOCKET,
    ol: Box<OVERLAPPED>,
    wbuf: Box<WSABUF>,
    from: Box<SOCKADDR_STORAGE>,
}
impl Socket {
    #[allow(unsafe_code)]
    /// # Panics
    ///
    /// Will panic if `Layout` constructor fails to build a layout for `MAX_PACKET_SIZE` aligned on `WSABUF`.
    fn create(af: ADDRESS_FAMILY, r#type: u16, protocol: IPPROTO) -> TraceResult<Self> {
        let s = unsafe { socket(af.0.try_into().unwrap(), i32::from(r#type), protocol.0) };
        if s == INVALID_SOCKET {
            // eprintln!("make_socket: socket failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }

        let from = Box::new(SOCKADDR_STORAGE::default());

        let layout =
            Layout::from_size_align(MAX_PACKET_SIZE, std::mem::align_of::<WSABUF>()).unwrap();
        let ptr = unsafe { alloc(layout) };

        let wbuf = Box::new(WSABUF {
            len: MAX_PACKET_SIZE as u32,
            buf: PSTR::from_raw(ptr),
        });

        let ol = Box::new(OVERLAPPED::default());

        Ok(Self { s, ol, wbuf, from })
    }

    #[allow(unsafe_code)]
    #[must_use]
    pub fn buf_bytes(&self) -> Vec<u8> {
        let buf = self.wbuf.buf.as_ptr();
        let slice = unsafe { std::slice::from_raw_parts(buf, self.wbuf.len as usize) };
        slice.to_owned()
    }

    pub fn from(&mut self) -> TraceResult<IpAddr> {
        sockaddrptr_to_ipaddr(std::ptr::addr_of_mut!(*self.from))
    }

    #[allow(unsafe_code)]
    fn create_event(&mut self) -> TraceResult<()> {
        self.ol.hEvent = unsafe { WSACreateEvent() };
        if self.ol.hEvent.is_invalid() {
            // eprintln!("create_overlapped_event: WSACreateEvent failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("WSACreateEvent OK: {:?}", self.ol.hEvent);
        Ok(())
    }

    #[allow(unsafe_code)]
    fn wait_for_event(&self, timeout: Duration) -> TraceResult<bool> {
        let millis = timeout.as_millis() as u32;

        let rc = unsafe { WaitForSingleObject(self.ol.hEvent, millis) };
        if rc == WAIT_TIMEOUT {
            // eprintln!("WaitForSingleObject timed out");
            return Ok(false);
        } else if rc == WAIT_FAILED {
            // eprintln!("is_readable: WaitForSingleObject failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("WaitForSingleObject OK"); // WAIT_OBJECT_0
        Ok(true)
    }

    #[allow(unsafe_code)]
    fn reset_event(&self) -> TraceResult<()> {
        if !unsafe { WSAResetEvent(self.ol.hEvent) }.as_bool() {
            // eprintln!("is_readable: WSAResetEvent failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        Ok(())
    }

    pub fn udp_from(target: IpAddr) -> TraceResult<Self> {
        let s = match target {
            IpAddr::V4(_) => Self::create(AF_INET, SOCK_DGRAM, IPPROTO_UDP),
            IpAddr::V6(_) => Self::create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP),
        }?;
        Ok(s)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn bind(&mut self, source_socketaddr: SocketAddr) -> TraceResult<&Self> {
        let (addr, addrlen) = socketaddr_to_sockaddr(source_socketaddr);
        if unsafe { bind(self.s, std::ptr::addr_of!(addr).cast(), addrlen as i32) } == SOCKET_ERROR
        {
            // eprintln!("bind: failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        self.create_event()?;
        Ok(self)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn send_to(&self, packet: &[u8], dest_socketaddr: SocketAddr) -> TraceResult<()> {
        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        let rc = unsafe {
            sendto(
                self.s,
                packet,
                0,
                std::ptr::addr_of!(addr).cast(),
                addrlen as i32,
            )
        };
        if rc == SOCKET_ERROR {
            // eprintln!("sendto failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("sendto OK");
        Ok(())
    }

    #[allow(unsafe_code)]
    pub fn close(&self) -> TraceResult<()> {
        if unsafe { closesocket(self.s) } == SOCKET_ERROR {
            // eprintln!("closesocket: failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("close OK");
        Ok(())
    }

    // NOTE FIONBIO is really unsigned (in WinSock2.h)
    #[allow(clippy::cast_sign_loss)]
    #[allow(unsafe_code)]
    fn set_non_blocking(&self, is_non_blocking: bool) -> TraceResult<()> {
        let non_blocking: u32 = u32::from(is_non_blocking);
        if unsafe {
            WSAIoctl(
                self.s,
                FIONBIO as u32,
                Some(std::ptr::addr_of!(non_blocking).cast()),
                size_of::<u32>().try_into().unwrap(),
                None,
                0,
                &mut 0,
                None,
                None,
            )
        } == SOCKET_ERROR
        {
            // eprintln!("set_non_blocking: WSAIoctl failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // // eprintln!("WSAIoctl(non_blocking) OK");
        Ok(())
    }

    fn setsockopt_bool(&self, level: i32, optname: i32, optval: bool) -> Result<()> {
        self.setsockopt_u32(level, optname, u32::from(optval))
    }

    #[allow(unsafe_code)]
    fn setsockopt_u32(&self, level: i32, optname: i32, optval: u32) -> Result<()> {
        let bytes_array = optval.to_ne_bytes();
        let bytes_slice_ref_option = Some(&bytes_array[..]);
        if unsafe { setsockopt(self.s, level, optname, bytes_slice_ref_option) } == SOCKET_ERROR {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_header_included(&self, is_header_included: bool) -> TraceResult<()> {
        self.setsockopt_bool(IPPROTO_IP as _, IP_HDRINCL as _, is_header_included)
            .map_err(TracerError::IoError)
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn set_ttl(&self, ttl: u32) -> TraceResult<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TTL as _, ttl)
            .map_err(TracerError::IoError)
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn ttl(&self) -> Result<u32> {
        self.getsockopt(IPPROTO_IP as _, IP_TTL as _)
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn set_tos(&self, tos: u32) -> TraceResult<()> {
        self.setsockopt_u32(IPPROTO_IP as _, IP_TOS as _, tos)
            .map_err(TracerError::IoError)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_reuse_port(&self, is_reuse_port: bool) -> TraceResult<()> {
        self.setsockopt_bool(SOL_SOCKET as _, SO_PORT_SCALABILITY as _, is_reuse_port)
            .map_err(TracerError::IoError)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn set_unicast_hops_v6(&self, max_hops: u8) -> TraceResult<&Self> {
        if unsafe {
            setsockopt(
                self.s,
                IPPROTO_IPV6.0,
                IPV6_UNICAST_HOPS as i32,
                Some(&[max_hops]),
            )
        } == SOCKET_ERROR
        {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // // eprintln!("setsockopt(set_ipv6_max_hops) OK");
        Ok(self)
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn unicast_hops_v6(&self) -> Result<u32> {
        self.getsockopt(IPPROTO_IPV6.0, IPV6_UNICAST_HOPS as _)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn recv_from(&mut self) -> TraceResult<()> {
        let mut fromlen = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;

        let ret = unsafe {
            WSARecvFrom(
                self.s,
                &[*self.wbuf],
                Some(&mut 0),
                &mut 0,
                Some(std::ptr::addr_of_mut!(*self.from).cast()),
                Some(&mut fromlen),
                Some(&mut *self.ol),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSA_IO_PENDING.0) {
                // let internal = self.ol.Internal;
                // eprintln!(
                // "WSARecvFrom failed: Internal={}, System Error={}",
                // internal,
                // unsafe { RtlNtStatusToDosError(NTSTATUS(internal as i32)) }
                // );
                return Err(TracerError::IoError(Error::last_os_error()));
            }
            // eprintln!("WSARecvFrom pending");
        } else {
            // eprintln!("WSARecvFrom OK"); // TODO no need to wait for an event, recv succeeded immediately! This should be handled
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn get_overlapped_result(&self) -> TraceResult<(u32, u32)> {
        let mut bytes = 0;
        let mut flags = 0;
        let ol = *self.ol;
        if unsafe {
            WSAGetOverlappedResult(self, std::ptr::addr_of!(ol), &mut bytes, false, &mut flags)
        }
        .as_bool()
        {
            // eprintln!("WSAGetOverlappedResult returned {} bytes", bytes);
            return Ok((bytes, flags));
        }
        Err(TracerError::IoError(Error::from(ErrorKind::Other)))
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn connect(&self, dest_socketaddr: SocketAddr) -> Result<()> {
        self.set_fail_connect_on_icmp_error(true)?;

        if unsafe { WSAEventSelect(self.s, self.ol.hEvent, (FD_CONNECT | FD_WRITE) as _) }
            == SOCKET_ERROR
        {
            eprintln!("WSAEventSelect failed: {}", Error::last_os_error());
            return Err(Error::last_os_error());
        }

        let (addr, addrlen) = socketaddr_to_sockaddr(dest_socketaddr);
        let rc = unsafe { connect(self.s, std::ptr::addr_of!(addr).cast(), addrlen as i32) };
        if rc == SOCKET_ERROR {
            if Error::last_os_error().raw_os_error() != Some(WSAEWOULDBLOCK.0) {
                // eprintln!("connect failed: {}", Error::last_os_error());
                return Err(Error::last_os_error());
            }
            // eprintln!("connect pending");
        } else {
            // eprintln!("connect OK");
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn take_error(&self) -> Result<Option<Error>> {
        match self.getsockopt(SOL_SOCKET as _, SO_ERROR as _) {
            Ok(0) => Ok(None),
            Ok(errno) => {
                // eprintln!("Socket error: {}", errno);
                Ok(Some(Error::from_raw_os_error(errno)))
            }
            Err(e) => Err(e),
        }
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn icmp_error_info(&self) -> Result<IpAddr> {
        let icmp_error_info =
            self.getsockopt::<ICMP_ERROR_INFO>(IPPROTO_TCP.0 as _, TCP_ICMP_ERROR_INFO as _)?;
        let src_addr = icmp_error_info.srcaddress;
        match ADDRESS_FAMILY(u32::from(unsafe { src_addr.si_family })) {
            AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(unsafe {
                src_addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
            }))),
            AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
                src_addr.Ipv6.sin6_addr.u.Byte
            }))),
            _ => Err(Error::from(ErrorKind::AddrNotAvailable)),
        }
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    fn getsockopt<T>(&self, level: i32, optname: i32) -> Result<T> {
        let mut optval: MaybeUninit<T> = MaybeUninit::uninit();
        let mut optlen = std::mem::size_of::<T>() as i32;

        if unsafe {
            getsockopt(
                self.s,
                level,
                optname,
                PSTR::from_raw(optval.as_mut_ptr().cast()),
                &mut optlen,
            )
        } == SOCKET_ERROR
        {
            return Err(Error::last_os_error());
        }
        Ok(unsafe { optval.assume_init() })
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        let mut name: MaybeUninit<SOCKADDR_STORAGE> = MaybeUninit::uninit();
        let mut namelen = size_of::<SOCKADDR_STORAGE>() as i32;
        if unsafe { getpeername(self.s, name.as_mut_ptr().cast(), &mut namelen) } == SOCKET_ERROR {
            return Err(Error::last_os_error());
        }
        sockaddr_to_socketaddr(unsafe { &name.assume_init() })
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how = match how {
            Shutdown::Both => SD_BOTH,
            Shutdown::Read => SD_RECEIVE,
            Shutdown::Write => SD_SEND,
        } as i32;
        if unsafe { shutdown(self.s, how) } == SOCKET_ERROR {
            return Err(Error::last_os_error());
        }
        self.cleanup()
    }

    #[allow(unsafe_code)]
    fn _is_writable_select(&self) -> TraceResult<bool> {
        use windows::Win32::Networking::WinSock::{__WSAFDIsSet, select, FD_SET, TIMEVAL};

        let mut fds = FD_SET::default();
        let timeout = TIMEVAL::default();
        fds.fd_array[0] = self.s;
        fds.fd_count = 1;
        let rc = unsafe { select(1, None, Some(&mut fds), None, Some(&timeout)) };
        if rc == SOCKET_ERROR {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        let fdisset = unsafe { __WSAFDIsSet(self.s, &mut fds) };
        // if fdisset == 0 {
        //     eprintln!("FD_ISSET returns {}", fdisset);
        // } else {
        //     eprintln!("===========> FD_ISSET returns {}", fdisset);
        // }
        Ok(fdisset != 0)
    }

    fn is_writable_overlapped(&self) -> TraceResult<bool> {
        if !self.wait_for_event(Duration::ZERO)? {
            return Ok(false);
        };

        while self.get_overlapped_result().is_err() {
            if Error::last_os_error().raw_os_error() != Some(WSA_IO_INCOMPLETE.0) {
                // eprintln!(
                //     "is_readable: WSAGetOverlappedResult failed with WSA_ERROR: {:?}",
                //     err
                // );
                return Err(TracerError::IoError(Error::last_os_error()));
            }
        }
        self.reset_event()?;
        Ok(true)
    }

    #[allow(unsafe_code)]
    fn cleanup(&self) -> Result<()> {
        let layout =
            Layout::from_size_align(MAX_PACKET_SIZE, std::mem::align_of::<WSABUF>()).unwrap();

        if unsafe { closesocket(self.s) } == SOCKET_ERROR {
            return Err(Error::last_os_error());
        }
        if !self.ol.hEvent.is_invalid() && unsafe { WSACloseEvent(self.ol.hEvent) } == false {
            return Err(Error::last_os_error());
        }
        unsafe { dealloc(self.wbuf.buf.as_ptr(), layout) };
        // should we cleanup sock.from too?

        Ok(())
    }

    #[allow(clippy::cast_possible_wrap)]
    fn set_fail_connect_on_icmp_error(&self, enabled: bool) -> Result<()> {
        self.setsockopt_bool(IPPROTO_TCP.0, TCP_FAIL_CONNECT_ON_ICMP_ERROR as _, enabled)
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket").field("s", &self.s).finish()
    }
}

impl convert::From<Socket> for SOCKET {
    fn from(sock: Socket) -> Self {
        sock.s
    }
}
impl convert::From<&Socket> for SOCKET {
    fn from(sock: &Socket) -> Self {
        sock.s
    }
}
impl convert::From<&mut Socket> for SOCKET {
    fn from(sock: &mut Socket) -> Self {
        sock.s
    }
}

#[allow(unsafe_code)]
pub fn startup() -> TraceResult<()> {
    const WINSOCK_VERSION: u16 = 0x202; // 2.2

    let mut wsd = MaybeUninit::<WSADATA>::zeroed();
    let rc = unsafe { WSAStartup(WINSOCK_VERSION, wsd.as_mut_ptr()) };
    unsafe { wsd.assume_init() }; // extracts the WSDATA to ensure it gets dropped (it's not used ATM)
    if rc == 0 {
        // eprintln!("WSAStartup OK");
        Ok(())
    } else {
        // eprintln!("WSAStartup failed");
        Err(TracerError::IoError(Error::last_os_error()))
    }
}

#[allow(unsafe_code)]
/// # Panics
///
/// Will panic if `Layout` constructor fails to build a layout for `MAX_PACKET_SIZE` aligned on `WSABUF`.
pub fn cleanup(sockets: &[Socket]) -> TraceResult<()> {
    for sock in sockets {
        sock.cleanup()?;
    }
    if unsafe { WSACleanup() } == SOCKET_ERROR {
        return Err(TracerError::IoError(Error::last_os_error()));
    };
    Ok(())
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
                return Err(TracerError::ErrorString(format!(
                    "Could not compute layout for {} words: {}",
                    buf_len, e
                )))
            }
        };
        list_ptr = unsafe { alloc(layout) };
        if list_ptr.is_null() {
            return Err(TracerError::ErrorString(format!(
                "Could not allocate {} words for layout {:?}",
                buf_len, layout
            )));
        }
        ip_adapter_address = list_ptr.cast();

        res = unsafe {
            IpHelper::GetAdaptersAddresses(
                family,
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

        unsafe { dealloc(list_ptr, layout) };
    }

    if res != NO_ERROR.0 {
        return Err(TracerError::ErrorString(format!(
            "GetAdaptersAddresses returned error: {}",
            Error::from_raw_os_error(res.try_into().unwrap())
        )));
    }

    while !ip_adapter_address.is_null() {
        let friendly_name = unsafe { (*ip_adapter_address).FriendlyName.to_string().unwrap() };
        if name == friendly_name {
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            let current_unicast = unsafe { (*ip_adapter_address).FirstUnicastAddress };
            // while !current_unicast.is_null() {
            unsafe {
                let socket_address = (*current_unicast).Address;
                // let sockaddr = socket_address.lpSockaddr.as_ref().unwrap();
                let sockaddr = socket_address.lpSockaddr;
                let ip_addr = sockaddrptr_to_ipaddr(sockaddr.cast());
                dealloc(list_ptr, layout);
                return ip_addr;
            }
            // current_unicast = unsafe { (*current_unicast).Next };
            // }
        }
        ip_adapter_address = unsafe { (*ip_adapter_address).Next };
    }

    unsafe {
        dealloc(list_ptr, layout);
    }

    Err(TracerError::UnknownInterface(format!(
        "could not find address for {}",
        name
    )))
}

#[allow(unsafe_code)]
fn sockaddrptr_to_ipaddr(sockaddr: *mut SOCKADDR_STORAGE) -> TraceResult<IpAddr> {
    match sockaddr_to_socketaddr(unsafe { sockaddr.as_ref().unwrap() }) {
        Err(e) => Err(TracerError::IoError(e)),
        Ok(socketaddr) => match socketaddr {
            SocketAddr::V4(socketaddrv4) => Ok(IpAddr::V4(*socketaddrv4.ip())),
            SocketAddr::V6(socketaddrv6) => Ok(IpAddr::V6(*socketaddrv6.ip())),
        },
    }
}

#[allow(unsafe_code)]
pub fn sockaddr_to_socketaddr(sockaddr: &SOCKADDR_STORAGE) -> Result<SocketAddr> {
    let ptr = sockaddr as *const SOCKADDR_STORAGE;
    let af = u32::from(sockaddr.ss_family);
    if af == AF_INET.0 {
        let sockaddr_in_ptr = ptr.cast::<SOCKADDR_IN>();
        let sockaddr_in = unsafe { *sockaddr_in_ptr };
        let ipv4addr = sockaddr_in.sin_addr;
        let port = sockaddr_in.sin_port;
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(ipv4addr),
            port,
        )))
    } else if af == AF_INET6.0 {
        #[allow(clippy::cast_ptr_alignment)]
        let sockaddr_in6_ptr = ptr.cast::<SOCKADDR_IN6>();
        let sockaddr_in6 = unsafe { *sockaddr_in6_ptr };
        let ipv6addr = sockaddr_in6.sin6_addr;
        let port = sockaddr_in6.sin6_port;
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(ipv6addr),
            port,
            sockaddr_in6.sin6_flowinfo,
            unsafe { sockaddr_in6.Anonymous.sin6_scope_id },
        )))
    } else {
        Err(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported address family: {}", af),
        ))
    }
}

#[allow(unsafe_code)]
#[must_use]
// TODO this allocate a SOCKADDR_STORAGE, should we drop it manually later?
fn socketaddr_to_sockaddr(socketaddr: SocketAddr) -> (SOCKADDR_STORAGE, u32) {
    let (paddr, addrlen): (*const SOCKADDR_STORAGE, u32) = match socketaddr {
        SocketAddr::V4(socketaddrv4) => {
            let sa: SOCKADDR_IN = socketaddrv4.into();
            (
                std::ptr::addr_of!(sa).cast(),
                size_of::<SOCKADDR_IN>() as u32,
            )
        }
        SocketAddr::V6(socketaddrv6) => {
            let sa: SOCKADDR_IN6 = socketaddrv6.into();
            (
                std::ptr::addr_of!(sa).cast(),
                size_of::<SOCKADDR_IN6>() as u32,
            )
        }
    };
    (unsafe { *paddr }, addrlen)
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET6, name)
}

#[allow(unsafe_code)]
pub fn routing_interface_query(target: IpAddr) -> TraceResult<IpAddr> {
    let src: *mut c_void = [0; 1024].as_mut_ptr().cast();
    let bytes = MaybeUninit::<u32>::uninit().as_mut_ptr();
    let s = Socket::udp_from(target)?;
    let (dest, destlen) = socketaddr_to_sockaddr(SocketAddr::new(target, 0));
    let rc = unsafe {
        WSAIoctl(
            s,
            SIO_ROUTING_INTERFACE_QUERY,
            Some(std::ptr::addr_of!(dest).cast()),
            destlen,
            Some(src),
            1024,
            bytes,
            None,
            None,
        )
    };
    if rc == SOCKET_ERROR {
        eprintln!(
            "routing_interface_query: WSAIoctl failed: {}",
            Error::last_os_error()
        );
        return Err(TracerError::IoError(Error::last_os_error()));
    }
    // eprintln!("WSAIoctl(routing_interface_query) OK");

    /*
    NOTE The WSAIoctl call potentially returns multiple results (see
    <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
    TBD We choose the first one arbitrarily.
     */
    let sockaddr = src.cast::<SOCKADDR_STORAGE>();
    sockaddrptr_to_ipaddr(sockaddr)
}

pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
    // eprintln!("created ICMP send Socket {}", sock.s.0);
    sock.set_non_blocking(true)?;
    sock.set_header_included(true)?;
    Ok(sock)
}

pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
    // eprintln!("created UDP send Socket {}", sock.s.0);
    sock.set_non_blocking(true)?;
    sock.set_header_included(true)?;
    Ok(sock)
}

pub fn make_recv_socket_ipv4(src_addr: Ipv4Addr) -> TraceResult<Socket> {
    let mut sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
    // eprint!("ICMP recv ");
    sock.bind(SocketAddr::new(IpAddr::V4(src_addr), 0))?;
    sock.recv_from()?;
    sock.set_non_blocking(true)?;
    sock.set_header_included(true)?;
    Ok(sock)
}

pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
    // eprintln!("created ICMP send Socket {:?}", sock);
    sock.set_non_blocking(true)?;
    Ok(sock)
}

pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_UDP)?;
    sock.set_non_blocking(true)?;
    Ok(sock)
}

pub fn make_recv_socket_ipv6(src_addr: Ipv6Addr) -> TraceResult<Socket> {
    let mut sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
    // eprint!("ICMP recv ");
    sock.bind(SocketAddr::new(IpAddr::V6(src_addr), 0))?;
    sock.recv_from()?;
    // eprintln!("Created ICMP recv Socket {:?}", sock);
    sock.set_non_blocking(true)?;
    Ok(sock)
}

pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_STREAM, IPPROTO_TCP)?;
    sock.set_non_blocking(true)?;
    sock.set_reuse_port(true)?;
    Ok(sock)
}

pub fn make_stream_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_STREAM, IPPROTO_TCP)?;
    sock.set_non_blocking(true)?;
    sock.set_reuse_port(true)?;
    Ok(sock)
}

pub fn is_readable(sock: &Socket, timeout: Duration) -> TraceResult<bool> {
    if !sock.wait_for_event(timeout)? {
        return Ok(false);
    };

    while sock.get_overlapped_result().is_err() {
        if Error::last_os_error().raw_os_error() != Some(WSA_IO_INCOMPLETE.0) {
            // eprintln!(
            //     "is_readable: WSAGetOverlappedResult failed with WSA_ERROR: {:?}",
            //     err
            // );
            return Err(TracerError::IoError(Error::last_os_error()));
        }
    }
    sock.reset_event()?;

    Ok(true)
}

pub fn is_writable(sock: &Socket) -> TraceResult<bool> {
    // if false {
    //     sock.is_writable_select()
    // } else {
    sock.is_writable_overlapped()
    // }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn startup() {
        INIT.call_once(|| super::startup().unwrap());
    }

    #[test]
    fn test_ipv4_interface_lookup() {
        let res = lookup_interface_addr_ipv4("vEthernet (External Switch)").unwrap();
        let addr: IpAddr = "192.168.2.2".parse().unwrap();
        assert_eq!(res, addr);
    }

    #[test]
    fn test_ipv6_interface_lookup() {
        let res = lookup_interface_addr_ipv6("vEthernet (External Switch)").unwrap();
        let addr: IpAddr = "fe80::f31a:9c2f:4f14:105b".parse().unwrap();
        assert_eq!(res, addr);
    }

    #[test]
    fn set_and_get_ttl() {
        startup();
        let ttl = 46;
        let mut s = Socket::create(AF_INET, SOCK_STREAM, IPPROTO_TCP).unwrap();
        s.bind("192.168.2.2:0".parse().unwrap())
            .unwrap()
            .set_ttl(ttl)
            .unwrap();
        assert_eq!(s.ttl().unwrap(), ttl);
    }
}
