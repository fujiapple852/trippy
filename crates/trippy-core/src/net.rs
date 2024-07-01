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
///
/// The `Network` trait provides an interface for sending and receiving network probes,
/// abstracting over the specific network protocol (ICMP, UDP, TCP) used for tracing.
/// Implementations of this trait are responsible for managing the network communication,
/// including sending probes and receiving responses.
///
/// # Examples
///
/// Implementing the `Network` trait for a custom network interface:
///
/// ```no_run
/// use trippy_core::net::Network;
/// use trippy_core::probe::{Probe, Response};
/// use trippy_core::error::Result;
///
/// struct MyNetworkInterface;
///
/// impl Network for MyNetworkInterface {
///     fn send_probe(&mut self, probe: Probe) -> Result<()> {
///         // Implementation for sending a probe
///         Ok(())
///     }
///
///     fn recv_probe(&mut self) -> Result<Option<Response>> {
///         // Implementation for receiving a probe response
///         Ok(None)
///     }
/// }
/// ```
///
/// # Errors
///
/// Implementations should return an error if sending or receiving a probe fails.
///
/// # Panics
///
/// Implementations should avoid panicking and handle errors gracefully.
#[cfg_attr(test, mockall::automock)]
pub trait Network {
    /// Send a `Probe`.
    ///
    /// Sends a network tracing probe to the target host. The probe contains information
    /// such as the destination address, TTL, and protocol-specific headers.
    ///
    /// # Parameters
    ///
    /// * `probe`: The `Probe` to be sent.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of sending the probe.
    ///
    /// # Examples
    ///
    /// Sending a probe using a network interface:
    ///
    /// ```no_run
    /// # use trippy_core::net::{Network, PlatformImpl};
    /// # use trippy_core::probe::Probe;
    /// # use trippy_core::types::{Port, Sequence, TimeToLive, TraceId};
    /// # use std::time::SystemTime;
    /// # let mut network = PlatformImpl;
    /// let probe = Probe::new(
    ///     Sequence(1),
    ///     TraceId(123),
    ///     Port(33434),
    ///     Port(33435),
    ///     TimeToLive(64),
    ///     SystemTime::now(),
    /// );
    /// network.send_probe(probe).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the probe could not be sent.
    fn send_probe(&mut self, probe: Probe) -> Result<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Waits for a response to a previously sent probe and returns the response if received.
    /// The response includes information such as the source address, ICMP type, and TTL.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<Response>`. The `Option` is `None` if no response
    /// was received within a timeout period, or if the received packet does not match the
    /// expected response type.
    ///
    /// # Examples
    ///
    /// Receiving a probe response using a network interface:
    ///
    /// ```no_run
    /// # use trippy_core::net::{Network, PlatformImpl};
    /// # let mut network = PlatformImpl;
    /// if let Ok(Some(response)) = network.recv_probe() {
    ///     println!("Received response: {:?}", response);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if there was an issue receiving the probe response.
    fn recv_probe(&mut self) -> Result<Option<Response>>;
}
