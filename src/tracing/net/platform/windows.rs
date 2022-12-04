use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::channel::MAX_PACKET_SIZE;
use crate::tracing::net::ipv6;
use std::alloc::{alloc, dealloc, Layout};
use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::ptr::addr_of_mut;
use std::time::Duration;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{
    socket, WSACreateEvent, ADDRESS_FAMILY, AF_INET, AF_INET6, INVALID_SOCKET, IPPROTO_ICMP,
    IPPROTO_ICMPV6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCK_RAW,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::IO::OVERLAPPED;

type Socket = SOCKET;

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
            // PANIC should not occur as GetAdaptersAddress should return valid PWSTR
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            let current_unicast = unsafe { (*ip_adapter_address).FirstUnicastAddress };
            // while !current_unicast.is_null() {
            unsafe {
                let socket_address = (*current_unicast).Address;
                let ip_addr = sockaddrptr_to_ipaddr(socket_address.lpSockaddr);
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
pub fn sockaddrptr_to_ipaddr(ptr: *mut SOCKADDR) -> TraceResult<IpAddr> {
    let af = unsafe { u32::from((*ptr).sa_family) };
    if af == AF_INET.0 {
        let ipv4addr = unsafe { (*(ptr.cast::<SOCKADDR_IN>())).sin_addr };
        Ok(IpAddr::V4(Ipv4Addr::from(ipv4addr)))
    } else if af == AF_INET6.0 {
        #[allow(clippy::cast_ptr_alignment)]
        let ipv6addr = unsafe { (*(ptr.cast::<SOCKADDR_IN6>())).sin6_addr };
        Ok(IpAddr::V6(Ipv6Addr::from(ipv6addr)))
    } else {
        Err(TracerError::IoError(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported address family: {}", af),
        )))
    }
}

#[allow(unsafe_code)]
pub fn ipaddr_to_sockaddr(source_addr: IpAddr) -> (SOCKADDR, u32) {
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

/// TODO
pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
#[allow(unsafe_code)]
pub fn make_recv_socket_ipv4() -> TraceResult<(Socket, OVERLAPPED)> {
    let s = unsafe {
        socket(
            AF_INET.0.try_into().unwrap(),
            i32::from(SOCK_RAW),
            IPPROTO_ICMP.0,
        )
    };
    if s == INVALID_SOCKET {
        return Err(TracerError::IoError(Error::last_os_error()));
    }

    let mut uninit = MaybeUninit::<OVERLAPPED>::zeroed();
    let ptr = uninit.as_mut_ptr();
    let mut recv_ol = unsafe {
        let ev = WSACreateEvent();
        if ev.is_invalid() {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        addr_of_mut!((*ptr).hEvent).write(ev);
        uninit.assume_init()
    };

    Ok((s, recv_ol))
}

/// TODO
pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
}

#[allow(unsafe_code)]
pub fn make_recv_socket_ipv6() -> TraceResult<(Socket, OVERLAPPED)> {
    let s = unsafe {
        socket(
            AF_INET6.0.try_into().unwrap(),
            i32::from(SOCK_RAW),
            IPPROTO_ICMPV6.0,
        )
    };
    if s == INVALID_SOCKET {
        return Err(TracerError::IoError(Error::last_os_error()));
    }

    let mut uninit = MaybeUninit::<OVERLAPPED>::zeroed();
    let ptr = uninit.as_mut_ptr();
    let mut recv_ol = unsafe {
        let ev = WSACreateEvent();
        if ev.is_invalid() {
            return Err(TracerError::IoError(Error::last_os_error()));
        }
        addr_of_mut!((*ptr).hEvent).write(ev);
        uninit.assume_init()
    };
    Ok((s, recv_ol))
}

/// TODO
pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_stream_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
#[allow(unsafe_code)]
pub fn is_readable(sock: &Socket, recv_ol: &OVERLAPPED, timeout: Duration) -> TraceResult<bool> {
    let rc =
        unsafe { WaitForSingleObject(recv_ol.hEvent, timeout.as_millis().try_into().unwrap()) };
    if rc == WAIT_FAILED {
        return Err(TracerError::IoError(Error::last_os_error()));
    }
    Ok(rc != WAIT_TIMEOUT)
}

/// TODO
pub fn is_writable(_sock: &Socket) -> TraceResult<bool> {
    unimplemented!()
}

/// TODO
pub fn is_not_in_progress_error(_code: i32) -> bool {
    unimplemented!()
}

/// TODO
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
