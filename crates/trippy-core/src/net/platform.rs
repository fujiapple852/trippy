pub mod byte_order;

pub use byte_order::Ipv4ByteOrder;
use std::net::IpAddr;

#[cfg(unix)]
mod unix;

use crate::error::Result;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::*;

/// Platform specific operations.
///
/// This trait defines platform-specific operations required by the network tracing functionality.
/// It abstracts over the differences between operating systems to provide a unified interface for
/// obtaining network-related information and performing network operations.
///
/// # Examples
///
/// Implementing the `Platform` trait for a custom platform:
///
/// ```no_run
/// use trippy_core::net::platform::{Platform, Ipv4ByteOrder};
/// use trippy_core::error::Result;
/// use std::net::IpAddr;
///
/// struct MyPlatform;
///
/// impl Platform for MyPlatform {
///     fn byte_order_for_address(addr: IpAddr) -> Result<Ipv4ByteOrder> {
///         // Implementation specific to the platform
///     }
///
///     fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr> {
///         // Implementation specific to the platform
///     }
///
///     fn discover_local_addr(target_addr: IpAddr, port: u16) -> Result<IpAddr> {
///         // Implementation specific to the platform
///     }
/// }
/// ```
///
/// # Errors
///
/// Implementations should return an error if any of the operations fail due to platform-specific
/// limitations or configurations.
///
/// # Panics
///
/// Implementations should avoid panicking and handle errors gracefully, returning them to the caller.
#[cfg_attr(test, mockall::automock)]
pub trait Platform {
    /// Determine the required byte ordering for IPv4 header fields.
    ///
    /// This method is used to determine the byte ordering for the `total_length`, `flags`, and
    /// `fragment_offset` fields of the IPv4 header, which may vary between different operating systems.
    ///
    /// # Parameters
    ///
    /// * `addr`: The IP address for which to determine the byte ordering.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the byte ordering required for the specified address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trippy_core::net::platform::{Platform, Ipv4ByteOrder};
    /// use std::net::IpAddr;
    ///
    /// let addr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    /// let byte_order = MyPlatform::byte_order_for_address(addr).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the byte ordering cannot be determined for the specified address.
    fn byte_order_for_address(addr: IpAddr) -> Result<Ipv4ByteOrder>;

    /// Lookup an `IpAddr` for an interface.
    ///
    /// If the interface has more than one address then an arbitrary address
    /// is selected and returned.
    ///
    /// # Parameters
    ///
    /// * `addr`: The type of IP address (IPv4 or IPv6) to lookup.
    /// * `name`: The name of the network interface.
    ///
    /// # Returns
    ///
    /// A `Result` containing the IP address associated with the specified interface.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trippy_core::net::platform::Platform;
    /// use std::net::IpAddr;
    ///
    /// let addr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    /// let interface_addr = MyPlatform::lookup_interface_addr(addr, "eth0").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the IP address cannot be found for the specified interface.
    fn lookup_interface_addr(addr: IpAddr, name: &str) -> Result<IpAddr>;

    /// Discover a local `IpAddr` which can route to the target address.
    ///
    /// This method is used to find a local IP address that can be used to route packets to the
    /// specified target address.
    ///
    /// # Parameters
    ///
    /// * `target_addr`: The target IP address for which to find a routing local IP address.
    /// * `port`: The target port number. This parameter may be used by some implementations to
    /// determine the routing IP address.
    ///
    /// # Returns
    ///
    /// A `Result` containing the local IP address that can route to the specified target address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use trippy_core::net::platform::Platform;
    /// use std::net::IpAddr;
    ///
    /// let target_addr = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
    /// let local_addr = MyPlatform::discover_local_addr(target_addr, 33434).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if a routing local IP address cannot be found for the specified target address.
    fn discover_local_addr(target_addr: IpAddr, port: u16) -> Result<IpAddr>;
}
