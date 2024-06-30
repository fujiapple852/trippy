use crate::error::Result;
use crate::probe::{Probe, Response};

/// Common types and helper functions.
mod common;

/// IPv4 implementation.
mod ipv4;

/// IPv6 implementation.
mod ipv6;

/// ICMP extensions.
mod extension;

/// Platform specific network code.
mod platform;

/// A network socket.
mod socket;

/// A channel for sending and receiving probes.
pub mod channel;

/// Determine the source address.
pub mod source;

/// The platform specific socket type.
pub use platform::{PlatformImpl, SocketImpl};

/// An abstraction over a network interface for tracing.
#[cfg_attr(test, mockall::automock)]
pub trait Network {
    /// Send a `Probe`.
    fn send_probe(&mut self, probe: Probe) -> Result<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe(&mut self) -> Result<Option<Response>>;
}
