use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use core::convert;
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use windows::core::PSTR;
use windows::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_BUFFER_OVERFLOW, NO_ERROR, NTSTATUS, WAIT_FAILED, WAIT_TIMEOUT,
};
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{
    bind, closesocket, sendto, setsockopt, socket, WSACleanup, WSACloseEvent, WSACreateEvent,
    WSAGetLastError, WSAGetOverlappedResult, WSAIoctl, WSARecvFrom, WSAResetEvent, WSAStartup,
    WSAWaitForMultipleEvents, ADDRESS_FAMILY, AF_INET, AF_INET6, FIONBIO, INVALID_SOCKET, IPPROTO,
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP,
    IPV6_UNICAST_HOPS, IP_HDRINCL, SIO_ROUTING_INTERFACE_QUERY, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKET, SOCKET_ERROR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_SOCKET,
    SO_PORT_SCALABILITY, WSABUF, WSADATA, WSA_IO_INCOMPLETE, WSA_IO_PENDING,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::IO::OVERLAPPED;

// type Socket = SOCKET;
#[derive(Debug, Clone)]
pub struct Socket {
    pub s: SOCKET,
    pub ol: Overlapped,
    pub wbuf: WSABUF,
    pub from: SOCKADDR,
}
impl Socket {
    #[allow(unsafe_code)]
    /// # Panics
    ///
    /// Will panic if `Layout` constructor fails to build a layout for `MAX_PACKET_SIZE` aligned on `WSABUF`
    fn create(af: ADDRESS_FAMILY, r#type: u16, protocol: IPPROTO) -> TraceResult<Self> {
        let s = make_socket(af, r#type, protocol)?;

        let from = SOCKADDR::default();

        let layout =
            Layout::from_size_align(MAX_PACKET_SIZE, std::mem::align_of::<WSABUF>()).unwrap();
        let ptr = unsafe { alloc(layout) };

        let wbuf = WSABUF {
            len: MAX_PACKET_SIZE as u32,
            buf: PSTR::from_raw(ptr),
        };

        // let ol = create_overlapped_event()?;
        let ol = OVERLAPPED::default();

        Ok(Self {
            s,
            ol: Overlapped(ol),
            wbuf,
            from,
        })
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
    pub fn bind(&self, source_addr: IpAddr) -> TraceResult<&Self> {
        let (addr, addrlen) = ipaddr_to_sockaddr(source_addr);
        if unsafe { bind(self.s, std::ptr::addr_of!(addr).cast(), addrlen as i32) } == SOCKET_ERROR
        {
            eprintln!("bind: failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("bind OK");
        Ok(self)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn sendto(&self, packet: &[u8], dest_addr: IpAddr) -> TraceResult<()> {
        let (addr, addrlen) = ipaddr_to_sockaddr(dest_addr);
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
            eprintln!("dispatch_icmp_probe: sendto failed with error");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("sendto OK");
        Ok(())
    }

    #[allow(unsafe_code)]
    pub fn close(&self) -> TraceResult<()> {
        if unsafe { closesocket(self.s) } == SOCKET_ERROR {
            eprintln!("closesocket: failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("close OK");
        Ok(())
    }

    // NOTE FIONBIO is really unsigned (in WinSock2.h)
    #[allow(clippy::cast_sign_loss)]
    #[allow(unsafe_code)]
    fn set_non_blocking(self, is_non_blocking: bool) -> TraceResult<Self> {
        let non_blocking: u32 = if is_non_blocking { 1 } else { 0 };
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
            eprintln!("set_non_blocking: WSAIoctl failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("WSAIoctl(non_blocking) OK");
        Ok(self)
    }

    #[allow(unsafe_code)]
    fn set_header_included(self, is_header_included: bool) -> TraceResult<Self> {
        let u32_header_included: u32 = if is_header_included { 1 } else { 0 };
        let header_included = u32_header_included.to_ne_bytes();
        let optval = Some(&header_included[..]);
        if unsafe {
            setsockopt(
                self.s,
                IPPROTO_IP.try_into().unwrap(),
                IP_HDRINCL.try_into().unwrap(),
                optval,
            )
        } == SOCKET_ERROR
        {
            eprintln!("set_header_included: setsockopt failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("setsockopt(header_included) OK");
        Ok(self)
    }

    #[allow(unsafe_code)]
    fn set_reuse_port(self, is_reuse_port: bool) -> TraceResult<Self> {
        let reuse_port = [is_reuse_port.try_into().unwrap()];
        let optval = Some(&reuse_port[..]);
        if unsafe {
            setsockopt(
                self.s,
                SOL_SOCKET.try_into().unwrap(),
                SO_PORT_SCALABILITY.try_into().unwrap(),
                optval,
            )
        } == SOCKET_ERROR
        {
            eprintln!("set_reuse_port: setsockopt failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        // eprintln!("setsockopt(reuse_port) OK");
        Ok(self)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn set_ipv6_max_hops(&self, max_hops: u8) -> TraceResult<&Self> {
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
        // eprintln!("setsockopt(set_ipv6_max_hops) OK");
        Ok(self)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn recv_from(&mut self) -> TraceResult<()> {
        let mut fromlen = std::mem::size_of::<SOCKADDR>() as i32;

        let ret = unsafe {
            WSARecvFrom(
                self.s,
                &[self.wbuf],
                Some(&mut 0),
                &mut 0,
                Some(&mut self.from),
                Some(&mut fromlen),
                Some(&mut self.ol.0),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            let err = unsafe { WSAGetLastError() };
            if err != WSA_IO_PENDING {
                eprintln!(
                    "WSARecvFrom failed: Internal={}, System Error={}",
                    self.ol.0.Internal,
                    unsafe { RtlNtStatusToDosError(NTSTATUS(self.ol.0.Internal as i32)) }
                );
                return Err(TracerError::IoError(Error::last_os_error()));
            }
            eprintln!("WSARecvFrom pending");
        } else {
            eprintln!("WSARecvFrom OK"); // TODO no need to wait for an event, recv succeeded immediately! This should be handled
        };
        Ok(())
    }

    #[allow(unsafe_code)]
    fn get_overlapped_result(&self) -> TraceResult<(u32, u32)> {
        let mut bytes = 0;
        let mut flags = 0;
        let ol = self.ol.0;
        if unsafe { WSAGetOverlappedResult(self.s, &ol, &mut bytes, false, &mut flags) }.as_bool() {
            eprintln!("WSAGetOverlappedResult returned {} bytes", bytes);
            return Ok((bytes, flags));
        }
        Err(TracerError::IoError(Error::from(ErrorKind::Other)))
    }
}

impl Copy for Socket {}

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
#[derive(Clone)]
pub struct Overlapped(pub OVERLAPPED);
impl Overlapped {
    #[allow(unsafe_code)]
    pub fn create_event(&mut self) -> TraceResult<&Self> {
        let recv_ol = OVERLAPPED {
            hEvent: unsafe { WSACreateEvent() },
            ..Default::default()
        };
        if recv_ol.hEvent.is_invalid() {
            eprintln!("create_overlapped_event: WSACreateEvent failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("WSACreateEvent OK: {:?}", recv_ol.hEvent);
        self.0 = recv_ol;
        Ok(self)
    }

    #[allow(unsafe_code)]
    fn wait_for_event(&self, timeout: Duration) -> TraceResult<bool> {
        let millis = timeout.as_millis() as u32;
        let ev = self.0.hEvent;

        let rc = unsafe { WaitForSingleObject(ev, millis) };
        if rc == WAIT_TIMEOUT {
            eprintln!("WaitForSingleObject timed out");
            return Ok(false);
        } else if rc == WAIT_FAILED {
            eprintln!("is_readable: WaitForSingleObject failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("WaitForSingleObject OK"); // WAIT_OBJECT_0
        Ok(true)
    }

    #[allow(unsafe_code)]
    // we could use WaitForMultipleEvents instead, but it does not seem to change anything
    fn _wait_for_event(&self, timeout: Duration) -> TraceResult<bool> {
        let millis = timeout.as_millis() as u32;
        let ev = self.0.hEvent;
        let rc = unsafe { WSAWaitForMultipleEvents(&[ev], false, millis, false) };
        if rc == WAIT_TIMEOUT.0 {
            eprintln!("WSAWaitForMultipleEvents timed out");
            return Ok(false);
        } else if rc == WAIT_FAILED.0 {
            eprintln!("WSAWaitForMultipleEvents failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        eprintln!("WSAWaitForMultipleEvents={} (OK)", rc);
        Ok(true)
    }

    #[allow(unsafe_code)]
    fn reset_event(&self) -> TraceResult<&Self> {
        if !unsafe { WSAResetEvent(self.0.hEvent) }.as_bool() {
            eprintln!("is_readable: WSAResetEvent failed");
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        Ok(self)
    }
}

impl Copy for Overlapped {}

impl fmt::Debug for Overlapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Overlapped")
            .field("hEvent", &self.0.hEvent)
            .finish()
    }
}
impl convert::From<Overlapped> for OVERLAPPED {
    fn from(ol: Overlapped) -> Self {
        ol.0
    }
}
impl convert::From<&Overlapped> for OVERLAPPED {
    fn from(ol: &Overlapped) -> Self {
        ol.0
    }
}
impl convert::From<&mut Overlapped> for OVERLAPPED {
    fn from(ol: &mut Overlapped) -> Self {
        ol.0
    }
}

#[allow(unsafe_code)]
pub fn startup() -> TraceResult<()> {
    const WINSOCK_VERSION: u16 = 0x202; // 2.2

    let mut wsd = MaybeUninit::<WSADATA>::zeroed();
    let rc = unsafe { WSAStartup(WINSOCK_VERSION, wsd.as_mut_ptr()) };
    unsafe { wsd.assume_init() }; // extracts the WSDATA to ensure it gets dropped (it's not used ATM)
    if rc == 0 {
        eprintln!("WSAStartup OK");
        Ok(())
    } else {
        eprintln!("WSAStartup failed");
        Err(TracerError::IoError(Error::last_os_error()))
    }
}

#[allow(unsafe_code)]
/// # Panics
///
/// Will panic if `Layout` constructor fails to build a layout for `MAX_PACKET_SIZE` aligned on `WSABUF`.
pub fn cleanup(sockets: &[Socket]) -> TraceResult<()> {
    let layout = Layout::from_size_align(MAX_PACKET_SIZE, std::mem::align_of::<WSABUF>()).unwrap();
    for sock in sockets {
        if unsafe { closesocket(sock) } == SOCKET_ERROR {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        if !sock.ol.0.hEvent.is_invalid() && unsafe { WSACloseEvent(sock.ol.0.hEvent) } == false {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        unsafe { dealloc(sock.wbuf.buf.as_ptr(), layout) };
        // should we cleanup sock.from too?
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
                let sockaddr = socket_address.lpSockaddr.as_ref().unwrap();
                let ip_addr = sockaddrptr_to_ipaddr(sockaddr);
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
pub fn sockaddrptr_to_ipaddr(sockaddr: &SOCKADDR) -> TraceResult<IpAddr> {
    let ptr = sockaddr as *const SOCKADDR;
    let af = u32::from(sockaddr.sa_family);
    if af == AF_INET.0 {
        let sockaddr_in_ptr = ptr.cast::<SOCKADDR_IN>();
        let sockaddr_in = unsafe { *sockaddr_in_ptr };
        let ipv4addr = sockaddr_in.sin_addr;
        Ok(IpAddr::V4(Ipv4Addr::from(ipv4addr)))
    } else if af == AF_INET6.0 {
        #[allow(clippy::cast_ptr_alignment)]
        let sockaddr_in6_ptr = ptr.cast::<SOCKADDR_IN6>();
        let sockaddr_in6 = unsafe { *sockaddr_in6_ptr };
        let ipv6addr = sockaddr_in6.sin6_addr;
        Ok(IpAddr::V6(Ipv6Addr::from(ipv6addr)))
    } else {
        Err(TracerError::IoError(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported address family: {}", af),
        )))
    }
}

#[allow(unsafe_code)]
#[must_use]
fn ipaddr_to_sockaddr(source_addr: IpAddr) -> (SOCKADDR, u32) {
    let (paddr, addrlen): (*const SOCKADDR, u32) = match source_addr {
        IpAddr::V4(ipv4addr) => {
            let sa: SOCKADDR_IN = SocketAddrV4::new(ipv4addr, 0).into();
            (
                std::ptr::addr_of!(sa).cast(),
                size_of::<SOCKADDR_IN>() as u32,
            )
        }
        IpAddr::V6(ipv6addr) => {
            let sa: SOCKADDR_IN6 = SocketAddrV6::new(ipv6addr, 0, 0, 0).into();
            (
                std::ptr::addr_of!(sa).cast(),
                size_of::<SOCKADDR_IN6>() as u32,
            )
        }
    };
    unsafe { (*paddr, addrlen) }
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET6, name)
}

#[allow(unsafe_code)]
/// # Panics
///
/// Use of `as_ref()` on raw pointer returned by the `WSAIoctl`, which might be null or misaligned.
pub fn routing_interface_query(target: IpAddr) -> TraceResult<IpAddr> {
    let src: *mut c_void = [0; 1024].as_mut_ptr().cast();
    let bytes = MaybeUninit::<u32>::uninit().as_mut_ptr();
    let s = Socket::udp_from(target)?;
    let (dest, destlen) = ipaddr_to_sockaddr(target);
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
        eprintln!("routing_interface_query: WSAIoctl failed");
        return Err(TracerError::IoError(Error::last_os_error()));
    }
    eprintln!("WSAIoctl(routing_interface_query) OK");

    /*
    NOTE The WSAIoctl call potentially returns multiple results (see
    <https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedsocketoptionioctl7h.html>),
    TBD We choose the first one arbitrarily.
     */
    let sockaddr = unsafe { src.cast::<SOCKADDR>().as_ref().unwrap() };
    sockaddrptr_to_ipaddr(sockaddr)
}

#[allow(unsafe_code)]
fn make_socket(af: ADDRESS_FAMILY, r#type: u16, protocol: IPPROTO) -> TraceResult<SOCKET> {
    let s = unsafe { socket(af.0.try_into().unwrap(), i32::from(r#type), protocol.0) };
    if s == INVALID_SOCKET {
        eprintln!("make_socket: socket failed");
        Err(TracerError::IoError(Error::last_os_error()))
    } else {
        // eprintln!("socket OK");
        Ok(s)
    }
}

pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
    eprintln!("created ICMP send Socket {:?}", sock);
    sock.set_non_blocking(true)?.set_header_included(true)
}

pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
    eprintln!("created UDP send Socket {:?}", sock);
    sock.set_non_blocking(true)?.set_header_included(true)
}

pub fn make_recv_socket_ipv4(src_addr: Ipv4Addr) -> TraceResult<Socket> {
    let mut sock = Socket::create(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
    sock.bind(IpAddr::V4(src_addr))?;
    sock.ol.create_event()?;
    sock.recv_from()?;
    eprintln!("Created ICMP recv Socket {:?}", sock);
    sock.set_non_blocking(true)?.set_header_included(true)
}

pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
    eprintln!("created ICMP send Socket {:?}", sock);
    sock.set_non_blocking(true)
}

pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_UDP)?;
    sock.set_non_blocking(true)
}

pub fn make_recv_socket_ipv6(src_addr: Ipv6Addr) -> TraceResult<Socket> {
    let mut sock = Socket::create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
    sock.bind(IpAddr::V6(src_addr))?;
    sock.ol.create_event()?;
    sock.recv_from()?;
    eprintln!("Created ICMP recv Socket {:?}", sock);
    sock.set_non_blocking(true)
}

pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET, SOCK_STREAM, IPPROTO_TCP)?;
    sock.set_non_blocking(true)?.set_reuse_port(true)
}

pub fn make_stream_socket_ipv6() -> TraceResult<Socket> {
    let sock = Socket::create(AF_INET6, SOCK_STREAM, IPPROTO_TCP)?;
    sock.set_non_blocking(true)?.set_reuse_port(true)
}

#[allow(unsafe_code)]
pub fn is_readable(sock: &Socket, timeout: Duration) -> TraceResult<bool> {
    if !sock.ol.wait_for_event(timeout)? {
        return Ok(false);
    };

    while sock.get_overlapped_result().is_err() {
        let err = unsafe { WSAGetLastError() };
        if err != WSA_IO_INCOMPLETE {
            eprintln!(
                "is_readable: WSAGetOverlappedResult failed with WSA_ERROR: {:?}",
                err
            );
            return Err(TracerError::IoError(Error::last_os_error()));
        }
    }
    sock.ol.reset_event()?;

    Ok(true)
}

/// TODO
pub fn is_writable(_sock: &Socket) -> TraceResult<bool> {
    unimplemented!()
}

/// TODO
#[must_use]
pub fn is_not_in_progress_error(_code: i32) -> bool {
    unimplemented!()
}

/// TODO
#[must_use]
pub fn is_conn_refused_error(_code: i32) -> bool {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

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
}
