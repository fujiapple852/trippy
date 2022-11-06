use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use socket2::Socket;
use windows::Win32::Foundation::{ERROR_SUCCESS, ERROR_BUFFER_OVERFLOW};
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use windows::Win32::NetworkManagement::IpHelper;
use windows::Win32::Networking::WinSock::{AF_INET};

/// TODO
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

/// TODO
/// inspired by <https://github.com/EstebanBorai/network-interface/blob/main/src/target/windows.rs>
#[allow(unsafe_code)]
pub fn lookup_interface_addr_ipv4(_name: &str) -> TraceResult<IpAddr> {
    /// Max tries allowed to call `GetAdaptersAddresses` on a loop basis
    const MAX_TRIES: usize = 3;
    // Initial buffer size is 15k per <https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses>
    let mut buf_len: u32 = 15000;
    let mut i = 0;
    let flags = IpHelper::GAA_FLAG_SKIP_ANYCAST|IpHelper::GAA_FLAG_SKIP_MULTICAST|IpHelper::GAA_FLAG_SKIP_DNS_SERVER;
    let mut ip_adapter_address = std::ptr::null_mut();

    let mut res = ERROR_BUFFER_OVERFLOW.0;
    while res == ERROR_BUFFER_OVERFLOW.0 && i < MAX_TRIES {
        let layout = Layout::from_size_align(buf_len as usize, mem::align_of::<IpHelper::IP_ADAPTER_ADDRESSES_LH>()).expect("Could not compute layout for buffer size");
        let base_ptr = unsafe { alloc(layout) };
        if base_ptr.is_null() {
            return Err(TracerError::SystemError(format!("Could not allocate for layout {:?} of size {} words", layout, buf_len)));
        }

        ip_adapter_address = base_ptr.cast();
        res = unsafe { IpHelper::GetAdaptersAddresses(AF_INET, flags, Some(std::ptr::null_mut()), Some(ip_adapter_address), &mut buf_len) };
    
        if res == ERROR_BUFFER_OVERFLOW.0 { // buf_len too small, enlarge
            unsafe { dealloc(base_ptr, layout) };
            ip_adapter_address = std::ptr::null_mut();
        }
        else {
            break;
        }

        i += 1;
    }

    if res != ERROR_SUCCESS.0 {
        return Err(TracerError::SystemError(format!("GetAdaptersAddresses returned error: {}", res)));
    }

    unsafe {
        while ! ip_adapter_address.is_null() {
           let name = (*ip_adapter_address).FriendlyName.to_string().unwrap();
           println!("{}", name);
           ip_adapter_address = (*ip_adapter_address).Next;
        }
    }

    Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
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

    #[test]
    fn test_ipv4_interface_lookup() {
        assert!(lookup_interface_addr_ipv4("foo").is_ok());
    }
}