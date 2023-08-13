use crate::error::TraceResult;
use crate::probe::ProbeResponse;
use crate::Probe;

/// IPv4 implementation.
mod ipv4;

/// IPv6 implementation.
mod ipv6;

/// Platform specific network code.
mod platform;

/// A network socket.
mod socket;

/// A channel for sending and receiving probes.
pub mod channel;

/// Determine the source address.
pub mod source;

/// Packet wire formats.
pub mod packet;

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send a `Probe`.
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>>;
}
