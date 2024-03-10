use crate::tracing::error::TraceResult;
use crate::tracing::error::TracerError::InvalidSourceAddr;
use crate::tracing::net::platform::Platform;
use crate::tracing::net::socket::Socket;
use crate::tracing::types::Port;
use crate::tracing::PortDirection;
use std::net::{IpAddr, SocketAddr};

/// The port used for local address discovery if not dest port is available.
const DISCOVERY_PORT: Port = Port(80);

/// Discover or validate a source address.
pub struct SourceAddr;

impl SourceAddr {
    /// Discover the source `IpAddr`.
    pub fn discover<S: Socket, P: Platform>(
        target_addr: IpAddr,
        port_direction: PortDirection,
        interface: Option<&str>,
    ) -> TraceResult<IpAddr> {
        let port = port_direction.dest().unwrap_or(DISCOVERY_PORT).0;
        match interface.as_ref() {
            Some(interface) => P::lookup_interface_addr(target_addr, interface),
            None => P::discover_local_addr(target_addr, port),
        }
    }

    /// Validate that we can bind to the source `IpAddr`.
    pub fn validate<S: Socket>(source_addr: IpAddr) -> TraceResult<IpAddr> {
        let mut socket = match source_addr {
            IpAddr::V4(_) => S::new_udp_dgram_socket_ipv4(),
            IpAddr::V6(_) => S::new_udp_dgram_socket_ipv6(),
        }?;
        let sock_addr = SocketAddr::new(source_addr, 0);
        match socket.bind(sock_addr) {
            Ok(()) => {
                socket.close()?;
                Ok(source_addr)
            }
            Err(_) => Err(InvalidSourceAddr(sock_addr.ip())),
        }
    }
}
