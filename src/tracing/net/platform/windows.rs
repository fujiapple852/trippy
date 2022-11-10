use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::alloc::{alloc, dealloc, Layout};
use std::cmp::Ordering;
use std::io::Error;
use std::mem;
use std::net::IpAddr;
use std::os::windows::prelude::AsRawSocket;
use std::time::Duration;
use widestring::WideCString;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper;
use windows_sys::Win32::Networking::WinSock::{
    select, ADDRESS_FAMILY, AF_INET, AF_INET6, FD_SET, IPPROTO_RAW, SOCKET_ADDRESS, TIMEVAL,
    WSAEINPROGRESS, WSAEREFUSED,
};

/// TODO
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

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
            mem::align_of::<IpHelper::IP_ADAPTER_ADDRESSES_LH>(),
        ) {
            Ok(layout) => layout,
            Err(e) => {
                return Err(TracerError::SystemError(format!(
                    "Could not compute layout for {} words: {}",
                    buf_len, e
                )))
            }
        };
        list_ptr = unsafe { alloc(layout) };
        if list_ptr.is_null() {
            return Err(TracerError::SystemError(format!(
                "Could not allocate {} words for layout {:?}",
                buf_len, layout
            )));
        }
        ip_adapter_address = list_ptr.cast();

        res = unsafe {
            IpHelper::GetAdaptersAddresses(
                family,
                flags,
                std::ptr::null_mut(),
                ip_adapter_address,
                &mut buf_len,
            )
        };
        i += 1;

        if res != ERROR_BUFFER_OVERFLOW || i > MAX_TRIES {
            break;
        }

        unsafe { dealloc(list_ptr, layout) };
    }

    if res != NO_ERROR {
        return Err(TracerError::SystemError(format!(
            "GetAdaptersAddresses returned error: {}",
            res
        )));
    }

    while !ip_adapter_address.is_null() {
        let friendly_name = unsafe { (*ip_adapter_address).FriendlyName };
        let friendly_name_string = unsafe {
            WideCString::from_ptr_str(friendly_name)
                .to_string()
                .unwrap()
        };
        if name == friendly_name_string {
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            let current_unicast = unsafe { (*ip_adapter_address).FirstUnicastAddress };
            // while !current_unicast.is_null() {
            unsafe {
                let socket_address = (*current_unicast).Address;
                let ip_addr = socket_address_to_ipaddr(&socket_address);
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
// Thank you <https://github.com/liranringel/ipconfig/blob/master/src/adapter.rs>
unsafe fn socket_address_to_ipaddr(socket_address: &SOCKET_ADDRESS) -> TraceResult<IpAddr> {
    let (_, sockaddr) = SockAddr::init(|storage, len| {
        #[allow(clippy::cast_sign_loss)]
        let sockaddr_len = socket_address.iSockaddrLength as usize;
        let dst: *mut u8 = storage.cast();
        let src: *const u8 = socket_address.lpSockaddr.cast();
        dst.copy_from_nonoverlapping(src, sockaddr_len);
        *len = socket_address.iSockaddrLength;
        Ok(())
    })
    .unwrap();
    sockaddr.as_socket().map(|s| s.ip()).ok_or_else(|| {
        TracerError::SystemError(format!(
            "could not extract address from socket_address {:?}",
            socket_address.lpSockaddr
        ))
    })
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

pub fn lookup_interface_addr_ipv6(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET6, name)
}

/// TOTEST
pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

/// TOTEST
pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

/// TODO
pub fn make_recv_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(true)?;
    socket.set_header_included(true)?;
    Ok(socket)
}

/// TODO
pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// TODO
pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// TODO
pub fn make_recv_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// TODO
pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    // see <https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ> for
    // discussion about SO_REUSEPORT & SO_REUSEADDR on various OS
    socket.set_reuse_address(true)?;
    Ok(socket)
}

/// TODO
pub fn make_stream_socket_ipv6() -> TraceResult<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    // see <https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ> for
    // discussion about SO_REUSEPORT & SO_REUSEADDR on various OS
    socket.set_reuse_address(true)?;
    Ok(socket)
}

/// TODO
#[allow(unsafe_code, clippy::cast_possible_wrap)]
pub fn is_readable(sock: &Socket, timeout: Duration) -> TraceResult<bool> {
    let mut timeval: TIMEVAL = unsafe { mem::zeroed::<TIMEVAL>() };
    timeval.tv_sec = timeout.as_secs() as i32;
    timeval.tv_usec = timeout.subsec_micros() as i32;
    let mut fds: FD_SET = unsafe { mem::zeroed::<FD_SET>() };
    fds.fd_count = 1;
    fds.fd_array[0] = sock.as_raw_socket() as usize;
    let readable = unsafe {
        select(
            1,
            &mut fds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &timeval,
        )
    };
    match 0.cmp(&readable) {
        Ordering::Less => Err(TracerError::IoError(Error::last_os_error())),
        Ordering::Equal => Err(TracerError::SystemError(
            "select: timeout expired".to_string(),
        )),
        Ordering::Greater => Ok(readable == 1),
    }
}

/// TODO
#[allow(unsafe_code)]
pub fn is_writable(sock: &Socket) -> TraceResult<bool> {
    let timeval: TIMEVAL = unsafe { mem::zeroed::<TIMEVAL>() };
    let mut fds: FD_SET = unsafe { mem::zeroed::<FD_SET>() };
    fds.fd_count = 1;
    fds.fd_array[0] = sock.as_raw_socket() as usize;
    let writable = unsafe {
        select(
            1,
            std::ptr::null_mut(),
            &mut fds,
            std::ptr::null_mut(),
            &timeval,
        )
    };
    match 0.cmp(&writable) {
        Ordering::Less => Err(TracerError::IoError(Error::last_os_error())),
        Ordering::Equal => Err(TracerError::SystemError(
            "select: timeout expired".to_string(),
        )),
        Ordering::Greater => Ok(writable == 1),
    }
}

/// TODO
pub fn is_in_progress_error(code: i32) -> bool {
    code != WSAEINPROGRESS
}

/// TODO
pub fn is_conn_refused_error(code: i32) -> bool {
    code == WSAEREFUSED
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ipv4_interface_lookup() {
        let res = lookup_interface_addr_ipv4("Ethernet 3").unwrap();
        let addr: IpAddr = "192.168.2.2".parse().unwrap();
        assert_eq!(res, addr);
    }

    #[test]
    fn test_ipv6_interface_lookup() {
        let res = lookup_interface_addr_ipv6("Ethernet 3").unwrap();
        let addr: IpAddr = "fe80::4460:bf4c:7f3d:6a12".parse().unwrap();
        assert_eq!(res, addr);
    }
}
