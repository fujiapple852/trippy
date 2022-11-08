use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use socket2::{SockAddr, Socket};
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::net::IpAddr;
use std::time::Duration;
use widestring::WideCString;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IPPROTO_RAW, SOCKET_ADDRESS,
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

/// TODO
pub fn make_icmp_send_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_send_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_recv_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_icmp_send_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_send_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_recv_socket_ipv6() -> TraceResult<Socket> {
    unimplemented!()
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
pub fn is_readable(_sock: &Socket, _timeout: Duration) -> TraceResult<bool> {
    unimplemented!()
}

/// TODO
pub fn is_writable(_sock: &Socket) -> TraceResult<bool> {
    unimplemented!()
}

/// TODO
pub fn is_in_progress_error(_code: i32) -> bool {
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
