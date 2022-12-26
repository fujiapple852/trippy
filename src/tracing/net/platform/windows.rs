use super::byte_order::PlatformIpv4FieldByteOrder;
use crate::tracing::error::TraceResult;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, SocketAddr};
use std::time::Duration;

/// TODO
#[allow(clippy::unnecessary_wraps)]
pub fn for_address(_src_addr: IpAddr) -> TraceResult<PlatformIpv4FieldByteOrder> {
    Ok(PlatformIpv4FieldByteOrder::Network)
}

#[allow(clippy::unnecessary_wraps)]
pub fn startup() -> TraceResult<()> {
    Ok(())
}

/// TODO
pub fn lookup_interface_addr_ipv4(_name: &str) -> TraceResult<IpAddr> {
    unimplemented!()
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
pub fn make_recv_socket_ipv4(_addr: Ipv4Addr) -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_stream_socket_ipv4() -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_dgram_socket_ipv4() -> TraceResult<Socket> {
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
pub fn make_recv_socket_ipv6(_addr: Ipv6Addr) -> TraceResult<Socket> {
    unimplemented!()
}

/// TODO
pub fn make_udp_dgram_socket_ipv6() -> TraceResult<Socket> {
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
pub fn is_not_in_progress_error(_code: i32) -> bool {
    unimplemented!()
}

/// TODO
pub fn is_conn_refused_error(_code: i32) -> bool {
    unimplemented!()
}

/// A network socket.
#[derive(Debug)]
pub struct Socket {}

#[allow(clippy::unused_self)]
impl Socket {
    /// TODO
    #[allow(dead_code)]
    pub fn new(_domain: (), _ty: (), _protocol: Option<()>) -> io::Result<Self> {
        unimplemented!()
    }

    /// TODO
    pub fn bind(&self, _address: SocketAddr) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn set_tos(&self, _tos: u32) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn set_reuse_port(&self, _reuse: bool) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn set_header_included(&self, _included: bool) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn set_unicast_hops_v6(&self, _hops: u32) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn connect(&self, _address: SocketAddr) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        unimplemented!()
    }

    /// TODO
    pub fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        unimplemented!()
    }

    pub fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }

    /// TODO
    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        unimplemented!()
    }

    /// TODO
    pub fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn as_raw_fd(&self) {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn unicast_hops_v6(&self) -> io::Result<u32> {
        unimplemented!()
    }

    /// TODO
    pub fn peer_addr(&self) -> io::Result<Option<SocketAddr>> {
        unimplemented!()
    }

    /// TODO
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        unimplemented!()
    }

    /// TODO
    #[allow(dead_code)]
    pub fn ttl(&self) -> io::Result<u32> {
        unimplemented!()
    }
}

impl io::Read for Socket {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}
