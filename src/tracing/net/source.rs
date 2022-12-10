use crate::tracing::error::TraceResult;
use crate::tracing::error::TracerError::InvalidSourceAddr;
use crate::tracing::net::platform;
use crate::tracing::types::Port;
use crate::tracing::util::Required;
use crate::tracing::PortDirection;
use socket2::{SockAddr, Socket};
use std::net::{IpAddr, SocketAddr};

/// The port used for local address discovery if not dest port is available.
const DISCOVERY_PORT: Port = Port(80);

/// Determine the source `IpAddr`.
pub fn discover_src_addr(
    source_addr: Option<IpAddr>,
    target_addr: IpAddr,
    port_direction: PortDirection,
    interface: Option<&str>,
) -> TraceResult<IpAddr> {
    match (source_addr, interface.as_ref()) {
        (Some(addr), None) => validate_local_addr(addr),
        (None, Some(interface)) => lookup_interface_addr(target_addr, interface),
        (None, None) => discover_local_addr(
            target_addr,
            port_direction.dest().unwrap_or(DISCOVERY_PORT).0,
        ),
        (Some(_), Some(_)) => unreachable!(),
    }
}

/// Lookup the address for a named interface.
fn lookup_interface_addr(addr: IpAddr, name: &str) -> TraceResult<IpAddr> {
    match addr {
        IpAddr::V4(_) => platform::lookup_interface_addr_ipv4(name),
        IpAddr::V6(_) => platform::lookup_interface_addr_ipv6(name),
    }
}

/// Discover the local `IpAddr` that will be used to communicate with the given target `IpAddr`.
///
/// Note that no packets are transmitted by this method.
fn discover_local_addr(target_addr: IpAddr, port: u16) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(target_addr)?;
    socket.connect(&SockAddr::from(SocketAddr::new(target_addr, port)))?;
    Ok(socket.local_addr()?.as_socket().req()?.ip())
}

/// Validate that we can bind to the source address.
fn validate_local_addr(addr: IpAddr) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(addr)?;
    let sock_addr = SocketAddr::new(addr, 0);
    match socket.bind(&SockAddr::from(sock_addr)) {
        Ok(_) => Ok(addr),
        Err(_) => Err(InvalidSourceAddr(sock_addr.ip())),
    }
}

/// Create a socket suitable for a given address.
fn udp_socket_for_addr_family(addr: IpAddr) -> TraceResult<Socket> {
    Ok(match addr {
        IpAddr::V4(_) => platform::make_udp_dgram_socket_ipv4()?,
        IpAddr::V6(_) => platform::make_udp_dgram_socket_ipv6()?,
    })
}
