use crate::tracing::error::TraceResult;
use crate::tracing::probe::ProbeResponse;
use crate::tracing::Probe;

/// IPv4 implementation.
mod ipv4;

/// IPv6 implementation.
mod ipv6;

/// Platform specific network code.
pub mod platform;

/// A channel for sending and receiving probes.
pub mod channel;

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send a `Probe`.
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>>;
}
