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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::net::platform::MockPlatform;
    use crate::tracing::net::socket::MockSocket;
    use mockall::predicate;
    use std::str::FromStr;
    use std::sync::Mutex;

    static MTX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_discover_local_addr_default_port() {
        let _m = MTX.lock();

        let direction = PortDirection::None;
        let interface = None;
        let expected_target = IpAddr::from_str("1.2.3.4").unwrap();
        let expected_port = DISCOVERY_PORT.0;
        let expected_src = IpAddr::from_str("192.168.0.1").unwrap();

        let ctx = MockPlatform::discover_local_addr_context();
        ctx.expect()
            .with(predicate::eq(expected_target), predicate::eq(expected_port))
            .times(1)
            .returning(move |_, _| Ok(expected_src));

        let src_addr =
            SourceAddr::discover::<MockSocket, MockPlatform>(expected_target, direction, interface)
                .unwrap();
        assert_eq!(expected_src, src_addr);
    }

    #[test]
    fn test_discover_local_addr_fixed_dest_port() {
        let _m = MTX.lock();

        let direction = PortDirection::FixedDest(Port(99));
        let interface = None;
        let expected_target = IpAddr::from_str("1.2.3.4").unwrap();
        let expected_port = 99;
        let expected_src = IpAddr::from_str("192.168.0.1").unwrap();

        let ctx = MockPlatform::discover_local_addr_context();
        ctx.expect()
            .with(predicate::eq(expected_target), predicate::eq(expected_port))
            .times(1)
            .returning(move |_, _| Ok(expected_src));

        let src_addr =
            SourceAddr::discover::<MockSocket, MockPlatform>(expected_target, direction, interface)
                .unwrap();
        assert_eq!(expected_src, src_addr);
    }

    #[test]
    fn test_discover_local_addr_fixed_both_port() {
        let _m = MTX.lock();

        let direction = PortDirection::FixedBoth(Port(1), Port(99));
        let interface = None;
        let expected_target = IpAddr::from_str("1.2.3.4").unwrap();
        let expected_port = 99;
        let expected_src = IpAddr::from_str("192.168.0.1").unwrap();

        let ctx = MockPlatform::discover_local_addr_context();
        ctx.expect()
            .with(predicate::eq(expected_target), predicate::eq(expected_port))
            .times(1)
            .returning(move |_, _| Ok(expected_src));

        let src_addr =
            SourceAddr::discover::<MockSocket, MockPlatform>(expected_target, direction, interface)
                .unwrap();
        assert_eq!(expected_src, src_addr);
    }

    #[test]
    fn test_discover_lookup_interface() {
        let _m = MTX.lock();

        let direction = PortDirection::None;
        let interface = Some("en0");
        let expected_target = IpAddr::from_str("1.2.3.4").unwrap();
        let expected_src = IpAddr::from_str("192.168.0.1").unwrap();
        let expected_interface = "en0";

        let ctx = MockPlatform::lookup_interface_addr_context();
        ctx.expect()
            .with(
                predicate::eq(expected_target),
                predicate::eq(expected_interface),
            )
            .times(1)
            .returning(move |_, _| Ok(expected_src));

        let src_addr =
            SourceAddr::discover::<MockSocket, MockPlatform>(expected_target, direction, interface)
                .unwrap();
        assert_eq!(expected_src, src_addr);
    }
}
