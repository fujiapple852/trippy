//! Packet wire format parsing and building.
//!
//! The following packet are supported:
//! - `ICMPv4`
//! - `ICMPv6`
//! - `IPv4`
//! - `IPv6`
//! - `UDP`
//! - `TCP`
//! - `ICMP` extensions
//!
//! # Endianness
//!
//! The internal representation is held in network byte order (big-endian) and
//! all accessor methods take and return data in host byte order, converting as
//! necessary for the given architecture.
//!
//! # Example
//!
//! The following example parses an `UDP` packet and asserts its fields:
//!
//! ```rust
//! # fn main() -> anyhow::Result<()> {
//! use trippy_packet::udp::UdpPacket;
//!
//! let buf = hex_literal::hex!("68 bf 81 b6 00 40 ac be");
//! let packet = UdpPacket::new_view(&buf)?;
//! assert_eq!(26815, packet.get_source());
//! assert_eq!(33206, packet.get_destination());
//! assert_eq!(64, packet.get_length());
//! assert_eq!(44222, packet.get_checksum());
//! assert!(packet.payload().is_empty());
//! # Ok(())
//! # }
//! ```
//!
//! The following example builds an `ICMPv4` echo request packet:
//!
//! ```rust
//! # fn main() -> anyhow::Result<()> {
//! use trippy_packet::checksum::icmp_ipv4_checksum;
//! use trippy_packet::icmpv4::echo_request::EchoRequestPacket;
//! use trippy_packet::icmpv4::{IcmpCode, IcmpPacket, IcmpType};
//!
//! let mut buf = [0; IcmpPacket::minimum_packet_size()];
//! let mut icmp = EchoRequestPacket::new(&mut buf)?;
//! icmp.set_icmp_type(IcmpType::EchoRequest);
//! icmp.set_icmp_code(IcmpCode(0));
//! icmp.set_identifier(1234);
//! icmp.set_sequence(10);
//! icmp.set_checksum(icmp_ipv4_checksum(icmp.packet()));
//! assert_eq!(icmp.packet(), &hex_literal::hex!("08 00 f3 23 04 d2 00 0a"));
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

mod buffer;

/// Packet errors.
pub mod error;

/// Functions for calculating network checksums.
pub mod checksum;

/// `ICMPv4` packets.
pub mod icmpv4;

/// `ICMPv6` packets.
pub mod icmpv6;

/// `ICMP` extensions.
pub mod icmp_extension;

/// `IPv4` packets.
pub mod ipv4;

/// `IPv6` packets.
pub mod ipv6;

/// `UDP` packets.
pub mod udp;

/// `TCP` packets.
pub mod tcp;

/// The IP packet next layer protocol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IpProtocol {
    Icmp,
    IcmpV6,
    Udp,
    Tcp,
    Other(u8),
}

impl IpProtocol {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::IcmpV6 => 58,
            Self::Udp => 17,
            Self::Tcp => 6,
            Self::Other(id) => id,
        }
    }

    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self::Other(value)
    }
}

impl From<u8> for IpProtocol {
    fn from(id: u8) -> Self {
        match id {
            1 => Self::Icmp,
            58 => Self::IcmpV6,
            17 => Self::Udp,
            6 => Self::Tcp,
            p => Self::Other(p),
        }
    }
}

/// Format a payload as a hexadecimal string.
#[must_use]
pub fn fmt_payload(bytes: &[u8]) -> String {
    use itertools::Itertools as _;
    format!("{:02x}", bytes.iter().format(" "))
}
