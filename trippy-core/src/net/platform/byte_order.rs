use crate::error::TraceResult;
use crate::net::platform::for_address;
use std::net::IpAddr;

/// The byte order to encode the `total_length`, `flags` and `fragment_offset` fields of the IPv4 header.
///
/// To quote directly from the `mtr` source code (from `check_length_order` in `probe_unix.c`):
///
/// "Nearly all fields in the IP header should be encoded in network byte
/// order prior to passing to send().  However, the required byte order of
/// the length field of the IP header is inconsistent between operating
/// systems and operating system versions.  FreeBSD 11 requires the length
/// field in network byte order, but some older versions of FreeBSD
/// require host byte order.  OS X requires the length field in host
/// byte order.  Linux will accept either byte order."
#[derive(Debug, Copy, Clone)]
pub enum PlatformIpv4FieldByteOrder {
    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "windows")))]
    Host,
    Network,
}

impl PlatformIpv4FieldByteOrder {
    /// Discover the required byte ordering for the IPv4 header fields `total_length`, `flags` and `fragment_offset`.
    ///
    /// This is achieved by creating a raw socket and attempting to send an `IPv4` packet to localhost with the
    /// `total_length` set in either host byte order or network byte order. The OS will return an `InvalidInput` error
    /// if the buffer provided is smaller than the `total_length` indicated, which will be the case when the byte order
    /// is set incorrectly.
    ///
    /// This is a little confusing as `Ipv4Packet::set_total_length` method will _always_ convert from host byte order
    /// to network byte order (which will be a no-op on big-endian system) and so to test the host byte order case
    /// we must try both the normal and the swapped byte order.
    ///
    /// For example, for a packet of length 4660 bytes (dec):
    ///
    /// For a little-endian architecture:
    ///
    /// Try        Host (LE)    Wire (BE)   Order (if succeeds)
    /// normal     34 12        12 34       `PlatformIpv4FieldByteOrder::Network`
    /// swapped    12 34        34 12       `PlatformIpv4FieldByteOrder::Host`
    ///
    /// For a big-endian architecture:
    ///
    /// Try        Host (BE)    Wire (BE)   Order (if succeeds)
    /// normal     12 34        12 34       `Ipv4TotalLengthByteOrder::Host`
    /// swapped    34 12        34 12       `Ipv4TotalLengthByteOrder::Network`
    pub fn for_address(addr: IpAddr) -> TraceResult<Self> {
        for_address(addr)
    }

    /// Adjust the IPv4 `total_length` header.
    #[must_use]
    pub fn adjust_length(self, ipv4_total_length: u16) -> u16 {
        match self {
            #[cfg(all(unix, not(target_os = "linux"), not(target_os = "windows")))]
            Self::Host => ipv4_total_length.swap_bytes(),
            Self::Network => ipv4_total_length,
        }
    }
}
