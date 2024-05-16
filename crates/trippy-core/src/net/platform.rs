pub mod byte_order;

pub use byte_order::Ipv4ByteOrder;
use std::net::IpAddr;

#[cfg(unix)]
mod unix;

use crate::error::TraceResult;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::*;

/// Platform specific operations.
#[cfg_attr(test, mockall::automock)]
pub trait Platform {
    /// Determine the required byte ordering for IPv4 header fields.
    fn byte_order_for_address(addr: IpAddr) -> TraceResult<Ipv4ByteOrder>;

    /// Lookup an `IpAddr` for an interface.
    ///
    /// If the interface has more than one address then an arbitrary address
    /// is selected and returned.
    fn lookup_interface_addr(addr: IpAddr, name: &str) -> TraceResult<IpAddr>;

    /// Discover a local `IpAddr` which can route to the target address.
    fn discover_local_addr(target_addr: IpAddr, port: u16) -> TraceResult<IpAddr>;
}
