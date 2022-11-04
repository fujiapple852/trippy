use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::{TraceResult, TracerError};
use socket2::Socket;
use core::slice;
use std::alloc::{Layout, System, GlobalAlloc};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr::addr_of;
use std::time::Duration;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetInterfaceInfo, IP_INTERFACE_INFO, IP_ADAPTER_INDEX_MAP};

/// TODO
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

/// TODO
/// Inspired by <https://stackoverflow.com/questions/73693265/how-do-i-allocate-space-to-call-getinterfaceinfo-using-the-windows-crate>
/// Ignore <https://users.rust-lang.org/t/windows-crate-best-way-to-create-buffers-to-pass-to-windows-api/57290>
#[allow(unsafe_code)]
pub fn lookup_interface_addr_ipv4(_name: &str) -> TraceResult<IpAddr> {
    let mut raw_buf_len: u32 = 0;
    let mut ip_interface_info: *mut IP_INTERFACE_INFO = std::ptr::null_mut();

    // Perform the first call to know how many bytes to allocate
    unsafe {
        let ret_val = GetInterfaceInfo(Some(ip_interface_info), &mut raw_buf_len);
        if ret_val != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(TracerError::SystemError(format!("GetInterfaceInfo returned: {0}", ret_val)));
        }
    }

    let buf_len = match raw_buf_len.try_into() {
        Ok(buf_len) => buf_len,
        Err(e) => return Err(TracerError::SystemError(format!("Invalid {0} buffer length: {1}", raw_buf_len, e))),
    };
    let layout = match Layout::from_size_align(buf_len, mem::align_of::<IP_INTERFACE_INFO>()) {
        Ok(layout) => layout,
        Err(e) => return Err(TracerError::SystemError(format!("Could not align IP_INTERFACE_INFO to {0} bytes length: {1}", buf_len, e))),
    };
    unsafe {
        let base_ptr = System.alloc(layout); // TODO avoid memory leak in case of errors
        let ip_interface_info = base_ptr.cast();

        // Perform the second call to get the data
        let ret_val = GetInterfaceInfo(Some(ip_interface_info), &mut raw_buf_len);
        if ret_val != NO_ERROR.0 {
            return Err(TracerError::SystemError(format!("GetInterfaceInfo returned: {0}", ret_val)));
        }

        let adapter_ptr = addr_of!((*ip_interface_info).Adapter).cast::<IP_ADAPTER_INDEX_MAP>();
        let n_adapters = match (*ip_interface_info).NumAdapters.try_into() {
            Ok(n_adapters) => n_adapters,
            Err(e) => return Err(TracerError::SystemError(format!("Invalid adapter count: {0}", e))),
        };
        let adapters = slice::from_raw_parts(adapter_ptr, n_adapters);
        println!("Num adapters: {}", adapters.len());
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