use crate::tracing::error::TraceResult;
use crate::tracing::error::TracerError::InvalidSourceAddr;
use crate::tracing::net::platform;
use crate::tracing::net::platform::Socket;
use crate::tracing::types::Port;
use crate::tracing::PortDirection;
use std::net::{IpAddr, SocketAddr};

/// The port used for local address discovery if not dest port is available.
const DISCOVERY_PORT: Port = Port(80);

/// Discover or validate a source address.
pub struct SourceAddr;

impl SourceAddr {
    /// Discover the source `IpAddr`.
    pub fn discover(
        target_addr: IpAddr,
        port_direction: PortDirection,
        interface: Option<&str>,
    ) -> TraceResult<IpAddr> {
        let port = port_direction.dest().unwrap_or(DISCOVERY_PORT).0;
        match interface.as_ref() {
            Some(interface) => lookup_interface_addr(target_addr, interface),
            None => platform::discover_local_addr(target_addr, port),
        }
    }

    /// Validate that we can bind to the source `IpAddr`.
    pub fn validate(source_addr: IpAddr) -> TraceResult<IpAddr> {
        let mut socket = udp_socket_for_addr_family(source_addr)?;
        let sock_addr = SocketAddr::new(source_addr, 0);
        match socket.bind(sock_addr) {
            Ok(_) => {
                socket.close()?;
                Ok(source_addr)
            }
            Err(_) => Err(InvalidSourceAddr(sock_addr.ip())),
        }
    }
}

/// Create a socket suitable for a given address.
pub fn udp_socket_for_addr_family(addr: IpAddr) -> TraceResult<Socket> {
    match addr {
        IpAddr::V4(_) => platform::make_udp_dgram_socket_ipv4(),
        IpAddr::V6(_) => platform::make_udp_dgram_socket_ipv6(),
    }
}

/// Lookup the address for a named interface.
fn lookup_interface_addr(addr: IpAddr, name: &str) -> TraceResult<IpAddr> {
    match addr {
        IpAddr::V4(_) => platform::lookup_interface_addr_ipv4(name),
        IpAddr::V6(_) => platform::lookup_interface_addr_ipv6(name),
    }
}
