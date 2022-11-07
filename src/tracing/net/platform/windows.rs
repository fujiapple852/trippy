use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use socket2::Socket;
use windows::Win32::Foundation::{NO_ERROR, ERROR_BUFFER_OVERFLOW};
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::net::{IpAddr};
use std::time::Duration;
use windows::core::PSTR;
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{AF_INET, ADDRESS_FAMILY, AF_INET6, WSAAddressToStringA, WSAGetLastError, WSADATA, WSAStartup, WSACleanup};

/// TODO
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

/// TODO
// inspired by <https://github.com/EstebanBorai/network-interface/blob/main/src/target/windows.rs>
#[allow(unsafe_code)]
fn lookup_interface_addr(family: ADDRESS_FAMILY, name: &str) -> TraceResult<IpAddr> {
    // Max tries allowed to call `GetAdaptersAddresses` on a loop basis
    const MAX_TRIES: usize = 3;
    let flags = IpHelper::GAA_FLAG_SKIP_ANYCAST|IpHelper::GAA_FLAG_SKIP_MULTICAST|IpHelper::GAA_FLAG_SKIP_DNS_SERVER;
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
                mem::align_of::<IpHelper::IP_ADAPTER_ADDRESSES_LH>()
            ) {
                Ok(layout) => layout,
                Err(e) =>  return Err(TracerError::SystemError(format!("Could not compute layout for {} words: {}", buf_len, e))),
            };
        list_ptr = unsafe { alloc(layout) };
        if list_ptr.is_null() {
            return Err(TracerError::SystemError(format!("Could not allocate {} words for layout {:?}", buf_len, layout)));
        }
        ip_adapter_address = list_ptr.cast();

        res = unsafe { IpHelper::GetAdaptersAddresses(family, flags, Some(std::ptr::null_mut()), Some(ip_adapter_address), &mut buf_len) };   
        i += 1;

        if res != ERROR_BUFFER_OVERFLOW.0 || i > MAX_TRIES {
            break;
        }

        unsafe { dealloc(list_ptr, layout) };
    }

    if res != NO_ERROR.0 {
        return Err(TracerError::SystemError(format!("GetAdaptersAddresses returned error: {}", res)));
    }

    unsafe {
        let mut lpwsadata: WSADATA = mem::zeroed();
        let res = WSAStartup(0x202, &mut lpwsadata);
        if res != 0 {
            return Err(TracerError::SystemError(format!("WSAStartup error: {}", WSAGetLastError().0 )))
        }
    }

    while ! ip_adapter_address.is_null() {
        let friendly_name = unsafe { (*ip_adapter_address).FriendlyName.to_string().unwrap() };
        if name ==  friendly_name {
            // NOTE this really should be a while over the linked list of FistUnicastAddress, and current_unicast would then be mutable
            // however, this is not supported by our function signature
            let current_unicast = unsafe { (*ip_adapter_address).FirstUnicastAddress };
            // while !current_unicast.is_null() {
                let lpsaaddress = unsafe { (*current_unicast).Address.lpSockaddr };
                let dwaddresslength = unsafe { (*current_unicast).Address.iSockaddrLength };
                let lpprotocolinfo = None;
                let mut addressstringlength: u32 = match family {
                    AF_INET => 16,
                    AF_INET6 => 46,
                    _ => return Err(TracerError::SystemError(format!("unsupported family: {}", family.0))),
                };
                let lpdwaddressstringlength = &mut addressstringlength as *mut u32;
                let lpszaddressstring = PSTR::from_raw(vec![0u8; addressstringlength as usize].as_mut_ptr());
                unsafe {
                    let res = WSAAddressToStringA(lpsaaddress, dwaddresslength as u32, lpprotocolinfo, lpszaddressstring, lpdwaddressstringlength);
                    if res != 0 {
                        WSACleanup();
                        return Err(TracerError::SystemError(format!("WSAAddressToStringA error: {}", WSAGetLastError().0)))
                    }
                    let address = lpszaddressstring.to_string().unwrap();
                    dealloc(list_ptr, layout);
                    WSACleanup();
                    return Ok(address.parse().unwrap());
                }
                // current_unicast = unsafe { (*current_unicast).Next };
            // }
        }
        ip_adapter_address = unsafe { (*ip_adapter_address).Next };
    }

    unsafe {
        dealloc(list_ptr, layout);
        WSACleanup();
    }

    Err(TracerError::UnknownInterface(format!("could not find address for {}", name)))
}

pub fn lookup_interface_addr_ipv4(name: &str) -> TraceResult<IpAddr> {
    lookup_interface_addr(AF_INET, name)
}

/// TODO
pub fn lookup_interface_addr_ipv6(_name: &str) -> TraceResult<IpAddr> {
    unimplemented!()
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
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_ipv4_interface_lookup() {
        assert_eq!(lookup_interface_addr_ipv4("Ethernet 3").unwrap(), IpAddr::V4(Ipv4Addr::new(192,168,2,2)));
    }
}