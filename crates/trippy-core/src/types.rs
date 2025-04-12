use bitflags::bitflags;
use derive_more::{Add, AddAssign, Rem, Sub};
use std::num::NonZeroUsize;

/// `Round` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, AddAssign)]
pub struct RoundId(pub usize);

/// `MaxRound` newtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct MaxRounds(pub NonZeroUsize);

/// `TimeToLive` (ttl) newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, Add, Sub, AddAssign)]
pub struct TimeToLive(pub u8);

/// `Sequence` number newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, Add, Sub, AddAssign, Rem)]
pub struct Sequence(pub u16);

/// `TraceId` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct TraceId(pub u16);

/// `MaxInflight` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct MaxInflight(pub u8);

/// `PacketSize` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct PacketSize(pub u16);

/// `PayloadPattern` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct PayloadPattern(pub u8);

/// `TypeOfService` (aka `DSCP` & `ECN`) newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct TypeOfService(pub u8);

/// Port newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct Port(pub u16);

/// Checksum newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct Checksum(pub u16);

bitflags! {
    /// Probe flags.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Flags: u32 {
        /// Swap the checksum and payload (UDP only).
        const PARIS_CHECKSUM = 1;
        /// Encode the sequence number as the payload length (IPv6/UDP only)
        const DUBLIN_IPV6_PAYLOAD_LENGTH = 2;
    }
}

impl From<Sequence> for usize {
    fn from(sequence: Sequence) -> Self {
        sequence.0 as Self
    }
}

/// Explicit Congestion Notification (`ECN`).
///
/// This is used in the `ECN` field of the `IP` header.
///
/// - See [rfc3246](https://datatracker.ietf.org/doc/html/rfc3246) for more details.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Ecn {
    /// Not ECN-Capable Transport (00, 0 dec).
    NotECT,
    /// ECN Capable Transport(1) (01, 1 dec).
    ECT1,
    /// ECN Capable Transport(0) (10, 2 dec).
    ECT0,
    /// Congestion Experienced (11, 3 dec).
    CE,
}

/// Differentiated Services Code Point (`DSCP`).
///
/// This is used in the `DSCP` field of the `IP` header.
///
/// - See [rfc2474](https://datatracker.ietf.org/doc/html/rfc2474) for more details on `AFnn`.
/// - See [rfc2475](https://datatracker.ietf.org/doc/html/rfc2475) and
///   [rfc2476](https://datatracker.ietf.org/doc/html/rfc2476) for more details on `CSn`.
/// - See [rfc3168](https://datatracker.ietf.org/doc/html/rfc3168) for more details on `CE`.
/// - See [rfc5865](https://datatracker.ietf.org/doc/html/rfc5865) for more details on `VA`.
/// - See [rfc8622](https://datatracker.ietf.org/doc/html/rfc8622) for more details on `LE`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Dscp {
    /// Default Forwarding (000 000, 0 dec).
    ///
    /// aka Best Effort (`BE`) aka Class Selector 0 (`CS0`).
    ///
    /// See rfc2474 and 2475.
    DF,
    /// Assured Forwarding 11 (001 010, 10 dec).
    AF11,
    /// Assured Forwarding 12 (001 100, 12 dec).
    AF12,
    /// Assured Forwarding 13 (001 110, 14 dec).
    AF13,
    /// Assured Forwarding 21 (010 010, 18 dec).
    AF21,
    /// Assured Forwarding 22 (010 100, 20 dec).
    AF22,
    /// Assured Forwarding 23 (010 110, 22 dec).
    AF23,
    /// Assured Forwarding 31 (011 010, 26 dec).
    AF31,
    /// Assured Forwarding 32 (011 100, 28 dec).
    AF32,
    /// Assured Forwarding 33 (011 110, 30 dec).
    AF33,
    /// Assured Forwarding 41 (100 010, 34 dec).
    AF41,
    /// Assured Forwarding 42 (100 100, 36 dec).
    AF42,
    /// Assured Forwarding 43 (100 110, 38 dec).
    AF43,
    /// Class Selector 1 (001 000, 8 dec).
    CS1,
    /// Class Selector 2 (010 000, 16 dec).
    CS2,
    /// Class Selector 3 (011 000, 24 dec).
    CS3,
    /// Class Selector 4 (100 000, 32 dec).
    CS4,
    /// Class Selector 5 (101 000, 40 dec).
    CS5,
    /// Class Selector 6 (110 000, 48 dec).
    CS6,
    /// Class Selector 7 (111 000, 56 dec).
    CS7,
    /// High Priority Expedited Forwarding (101 110, 46 dec).
    EF,
    /// Voice Admit (101 100, 44 dec).
    VA,
    /// Lower Effort (000 001, 1 dec).
    LE,
    /// Other DSCP value (not defined in the standard).
    Other(u8),
}

impl TypeOfService {
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        self.split().0
    }
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        self.split().1
    }
    fn split(self) -> (Dscp, Ecn) {
        let dscp = match (self.0 & 0xfc) >> 2 {
            0 => Dscp::DF,
            10 => Dscp::AF11,
            12 => Dscp::AF12,
            14 => Dscp::AF13,
            18 => Dscp::AF21,
            20 => Dscp::AF22,
            22 => Dscp::AF23,
            26 => Dscp::AF31,
            28 => Dscp::AF32,
            30 => Dscp::AF33,
            34 => Dscp::AF41,
            36 => Dscp::AF42,
            38 => Dscp::AF43,
            8 => Dscp::CS1,
            16 => Dscp::CS2,
            24 => Dscp::CS3,
            32 => Dscp::CS4,
            40 => Dscp::CS5,
            48 => Dscp::CS6,
            56 => Dscp::CS7,
            46 => Dscp::EF,
            44 => Dscp::VA,
            1 => Dscp::LE,
            n => Dscp::Other(n),
        };
        let ecn = match self.0 & 0x3 {
            0 => Ecn::NotECT,
            1 => Ecn::ECT1,
            2 => Ecn::ECT0,
            3 => Ecn::CE,
            _ => unreachable!(),
        };
        (dscp, ecn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeOfService;
    use test_case::test_case;

    #[test_case(TypeOfService(0x0), Dscp::DF, Ecn::NotECT; "BE, Not-ECT")]
    #[test_case(TypeOfService(0xe0), Dscp::CS7, Ecn::NotECT; "CS7, Not-ECT")]
    #[test_case(TypeOfService(0xa), Dscp::Other(2), Ecn::ECT0; "Other, ECT0")]
    #[test_case(TypeOfService(0x8b), Dscp::AF41, Ecn::CE; "AF41, CE")]
    fn test_dscp_ecn(tos: TypeOfService, dscp: Dscp, ecn: Ecn) {
        assert_eq!(tos.dscp(), dscp);
        assert_eq!(tos.ecn(), ecn);
    }
}
