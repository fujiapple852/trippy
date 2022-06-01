use crate::tracing::packet::buffer::Buffer;
use std::fmt::{Debug, Formatter};

/// The type of `ICMPv6` packet.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Icmpv6Type {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    Other(u8),
}

impl Icmpv6Type {
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            Self::EchoRequest => 128,
            Self::EchoReply => 129,
            Self::DestinationUnreachable => 1,
            Self::TimeExceeded => 3,
            Self::Other(id) => *id,
        }
    }
}

impl From<u8> for Icmpv6Type {
    fn from(val: u8) -> Self {
        match val {
            128 => Self::EchoRequest,
            129 => Self::EchoReply,
            1 => Self::DestinationUnreachable,
            3 => Self::TimeExceeded,
            id => Self::Other(id),
        }
    }
}

/// The `ICMPv6` code.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Icmpv6Code(pub u8);

impl From<u8> for Icmpv6Code {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

const TYPE_OFFSET: usize = 0;
const CODE_OFFSET: usize = 1;
const CHECKSUM_OFFSET: usize = 2;

/// Represents an ICMP packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
/// data in host byte order, converting as necessary for the given architecture.
pub struct Icmpv6Packet<'a> {
    buf: Buffer<'a>,
}

impl<'a> Icmpv6Packet<'a> {
    pub fn new(packet: &'a mut [u8]) -> Option<Icmpv6Packet<'_>> {
        if packet.len() >= Self::minimum_packet_size() {
            Some(Self {
                buf: Buffer::Mutable(packet),
            })
        } else {
            None
        }
    }

    #[must_use]
    pub fn new_view(packet: &'a [u8]) -> Option<Icmpv6Packet<'_>> {
        if packet.len() >= Self::minimum_packet_size() {
            Some(Self {
                buf: Buffer::Immutable(packet),
            })
        } else {
            None
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        8
    }

    #[must_use]
    pub fn get_icmp_type(&self) -> Icmpv6Type {
        Icmpv6Type::from(self.buf.read(TYPE_OFFSET))
    }

    #[must_use]
    pub fn get_icmp_code(&self) -> Icmpv6Code {
        Icmpv6Code::from(self.buf.read(CODE_OFFSET))
    }

    #[must_use]
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
    }

    pub fn set_icmp_type(&mut self, val: Icmpv6Type) {
        *self.buf.write(TYPE_OFFSET) = val.id();
    }

    pub fn set_icmp_code(&mut self, val: Icmpv6Code) {
        *self.buf.write(CODE_OFFSET) = val.0;
    }

    pub fn set_checksum(&mut self, val: u16) {
        self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Debug for Icmpv6Packet<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Icmpv6Packet")
            .field("icmp_type", &self.get_icmp_type())
            .field("icmp_code", &self.get_icmp_code())
            .field("checksum", &self.get_checksum())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_type() {
        let mut buf = [0_u8; Icmpv6Packet::minimum_packet_size()];
        let mut packet = Icmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmp_type(Icmpv6Type::EchoRequest);
        assert_eq!(Icmpv6Type::EchoRequest, packet.get_icmp_type());
        assert_eq!([0x80], packet.packet()[0..1]);
        packet.set_icmp_type(Icmpv6Type::EchoReply);
        assert_eq!(Icmpv6Type::EchoReply, packet.get_icmp_type());
        assert_eq!([0x81], packet.packet()[0..1]);
        packet.set_icmp_type(Icmpv6Type::DestinationUnreachable);
        assert_eq!(Icmpv6Type::DestinationUnreachable, packet.get_icmp_type());
        assert_eq!([0x01], packet.packet()[0..1]);
        packet.set_icmp_type(Icmpv6Type::TimeExceeded);
        assert_eq!(Icmpv6Type::TimeExceeded, packet.get_icmp_type());
        assert_eq!([0x03], packet.packet()[0..1]);
        packet.set_icmp_type(Icmpv6Type::Other(255));
        assert_eq!(Icmpv6Type::Other(255), packet.get_icmp_type());
        assert_eq!([0xFF], packet.packet()[0..1]);
    }

    #[test]
    fn test_icmp_code() {
        let mut buf = [0_u8; Icmpv6Packet::minimum_packet_size()];
        let mut packet = Icmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmp_code(Icmpv6Code(0));
        assert_eq!(Icmpv6Code(0), packet.get_icmp_code());
        assert_eq!([0x00], packet.packet()[1..2]);
        packet.set_icmp_code(Icmpv6Code(5));
        assert_eq!(Icmpv6Code(5), packet.get_icmp_code());
        assert_eq!([0x05], packet.packet()[1..2]);
        packet.set_icmp_code(Icmpv6Code(255));
        assert_eq!(Icmpv6Code(255), packet.get_icmp_code());
        assert_eq!([0xFF], packet.packet()[1..2]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; Icmpv6Packet::minimum_packet_size()];
        let mut packet = Icmpv6Packet::new(&mut buf).unwrap();
        packet.set_checksum(0);
        assert_eq!(0, packet.get_checksum());
        assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
        packet.set_checksum(1999);
        assert_eq!(1999, packet.get_checksum());
        assert_eq!([0x07, 0xCF], packet.packet()[2..=3]);
        packet.set_checksum(u16::MAX);
        assert_eq!(u16::MAX, packet.get_checksum());
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }
}

pub mod echo_request {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::fmt_payload;
    use crate::tracing::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const IDENTIFIER_OFFSET: usize = 4;
    const SEQUENCE_OFFSET: usize = 6;

    /// Represents an `ICMPv6` `EchoRequest` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct EchoRequestPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> EchoRequestPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<EchoRequestPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<EchoRequestPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> Icmpv6Type {
            Icmpv6Type::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> Icmpv6Code {
            Icmpv6Code::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_identifier(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(IDENTIFIER_OFFSET))
        }

        #[must_use]
        pub fn get_sequence(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(SEQUENCE_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: Icmpv6Type) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: Icmpv6Code) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_identifier(&mut self, val: u16) {
            self.buf.set_bytes_two(IDENTIFIER_OFFSET, val.to_be_bytes());
        }

        pub fn set_sequence(&mut self, val: u16) {
            self.buf.set_bytes_two(SEQUENCE_OFFSET, val.to_be_bytes());
        }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size();
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
        }
    }

    impl Debug for EchoRequestPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EchoRequestPacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("identifier", &self.get_identifier())
                .field("sequence", &self.get_sequence())
                .field("payload", &fmt_payload(self.payload()))
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_icmp_type() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_icmp_type(Icmpv6Type::EchoRequest);
            assert_eq!(Icmpv6Type::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::EchoReply);
            assert_eq!(Icmpv6Type::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::DestinationUnreachable);
            assert_eq!(Icmpv6Type::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::TimeExceeded);
            assert_eq!(Icmpv6Type::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::Other(255));
            assert_eq!(Icmpv6Type::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(Icmpv6Code(0));
            assert_eq!(Icmpv6Code(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(5));
            assert_eq!(Icmpv6Code(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(255));
            assert_eq!(Icmpv6Code(255), packet.get_icmp_code());
            assert_eq!([0xFF], packet.packet()[1..2]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_checksum(0);
            assert_eq!(0, packet.get_checksum());
            assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
            packet.set_checksum(1999);
            assert_eq!(1999, packet.get_checksum());
            assert_eq!([0x07, 0xCF], packet.packet()[2..=3]);
            packet.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, packet.get_checksum());
            assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
        }

        #[test]
        fn test_identifier() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_identifier(0);
            assert_eq!(0, packet.get_identifier());
            assert_eq!([0x00, 0x00], packet.packet()[4..=5]);
            packet.set_identifier(1999);
            assert_eq!(1999, packet.get_identifier());
            assert_eq!([0x07, 0xCF], packet.packet()[4..=5]);
            packet.set_identifier(u16::MAX);
            assert_eq!(u16::MAX, packet.get_identifier());
            assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
        }

        #[test]
        fn test_sequence() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_sequence(0);
            assert_eq!(0, packet.get_sequence());
            assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
            packet.set_sequence(1999);
            assert_eq!(1999, packet.get_sequence());
            assert_eq!([0x07, 0xCF], packet.packet()[6..=7]);
            packet.set_sequence(u16::MAX);
            assert_eq!(u16::MAX, packet.get_sequence());
            assert_eq!([0xFF, 0xFF], packet.packet()[6..=7]);
        }
    }
}

pub mod echo_reply {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::fmt_payload;
    use crate::tracing::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const IDENTIFIER_OFFSET: usize = 4;
    const SEQUENCE_OFFSET: usize = 6;

    /// Represents an ICMP `EchoReply` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct EchoReplyPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> EchoReplyPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<EchoReplyPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<EchoReplyPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> Icmpv6Type {
            Icmpv6Type::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> Icmpv6Code {
            Icmpv6Code::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_identifier(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(IDENTIFIER_OFFSET))
        }

        #[must_use]
        pub fn get_sequence(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(SEQUENCE_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: Icmpv6Type) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: Icmpv6Code) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_identifier(&mut self, val: u16) {
            self.buf.set_bytes_two(IDENTIFIER_OFFSET, val.to_be_bytes());
        }

        pub fn set_sequence(&mut self, val: u16) {
            self.buf.set_bytes_two(SEQUENCE_OFFSET, val.to_be_bytes());
        }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size();
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
        }
    }

    impl Debug for EchoReplyPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EchoReplyPacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("identifier", &self.get_identifier())
                .field("sequence", &self.get_sequence())
                .field("payload", &fmt_payload(self.payload()))
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_icmp_type() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_icmp_type(Icmpv6Type::EchoRequest);
            assert_eq!(Icmpv6Type::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::EchoReply);
            assert_eq!(Icmpv6Type::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::DestinationUnreachable);
            assert_eq!(Icmpv6Type::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::TimeExceeded);
            assert_eq!(Icmpv6Type::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::Other(255));
            assert_eq!(Icmpv6Type::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(Icmpv6Code(0));
            assert_eq!(Icmpv6Code(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(5));
            assert_eq!(Icmpv6Code(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(255));
            assert_eq!(Icmpv6Code(255), packet.get_icmp_code());
            assert_eq!([0xFF], packet.packet()[1..2]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_checksum(0);
            assert_eq!(0, packet.get_checksum());
            assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
            packet.set_checksum(1999);
            assert_eq!(1999, packet.get_checksum());
            assert_eq!([0x07, 0xCF], packet.packet()[2..=3]);
            packet.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, packet.get_checksum());
            assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
        }

        #[test]
        fn test_identifier() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_identifier(0);
            assert_eq!(0, packet.get_identifier());
            assert_eq!([0x00, 0x00], packet.packet()[4..=5]);
            packet.set_identifier(1999);
            assert_eq!(1999, packet.get_identifier());
            assert_eq!([0x07, 0xCF], packet.packet()[4..=5]);
            packet.set_identifier(u16::MAX);
            assert_eq!(u16::MAX, packet.get_identifier());
            assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
        }

        #[test]
        fn test_sequence() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_sequence(0);
            assert_eq!(0, packet.get_sequence());
            assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
            packet.set_sequence(1999);
            assert_eq!(1999, packet.get_sequence());
            assert_eq!([0x07, 0xCF], packet.packet()[6..=7]);
            packet.set_sequence(u16::MAX);
            assert_eq!(u16::MAX, packet.get_sequence());
            assert_eq!([0xFF, 0xFF], packet.packet()[6..=7]);
        }
    }
}

pub mod time_exceeded {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::fmt_payload;
    use crate::tracing::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;

    /// Represents an ICMP `TimeExceeded` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct TimeExceededPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> TimeExceededPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<TimeExceededPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<TimeExceededPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> Icmpv6Type {
            Icmpv6Type::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> Icmpv6Code {
            Icmpv6Code::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: Icmpv6Type) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: Icmpv6Code) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size();
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
        }
    }

    impl Debug for TimeExceededPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TimeExceededPacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("payload", &fmt_payload(self.payload()))
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_icmp_type() {
            let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
            let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
            packet.set_icmp_type(Icmpv6Type::EchoRequest);
            assert_eq!(Icmpv6Type::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::EchoReply);
            assert_eq!(Icmpv6Type::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::DestinationUnreachable);
            assert_eq!(Icmpv6Type::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::TimeExceeded);
            assert_eq!(Icmpv6Type::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::Other(255));
            assert_eq!(Icmpv6Type::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
            let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(Icmpv6Code(0));
            assert_eq!(Icmpv6Code(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(5));
            assert_eq!(Icmpv6Code(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(255));
            assert_eq!(Icmpv6Code(255), packet.get_icmp_code());
            assert_eq!([0xFF], packet.packet()[1..2]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
            let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
            packet.set_checksum(0);
            assert_eq!(0, packet.get_checksum());
            assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
            packet.set_checksum(1999);
            assert_eq!(1999, packet.get_checksum());
            assert_eq!([0x07, 0xCF], packet.packet()[2..=3]);
            packet.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, packet.get_checksum());
            assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
        }
    }
}

pub mod destination_unreachable {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::fmt_payload;
    use crate::tracing::packet::icmpv6::{Icmpv6Code, Icmpv6Type};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const UNUSED_OFFSET: usize = 4;
    const NEXT_HOP_MTU_OFFSET: usize = 6;

    /// Represents an ICMP `DestinationUnreachable` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct DestinationUnreachablePacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> DestinationUnreachablePacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<DestinationUnreachablePacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<DestinationUnreachablePacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> Icmpv6Type {
            Icmpv6Type::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> Icmpv6Code {
            Icmpv6Code::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_unused(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(UNUSED_OFFSET))
        }

        #[must_use]
        pub fn get_next_hop_mtu(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(NEXT_HOP_MTU_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: Icmpv6Type) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: Icmpv6Code) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_unused(&mut self, val: u16) {
            self.buf.set_bytes_two(UNUSED_OFFSET, val.to_be_bytes());
        }

        pub fn set_next_hop_mtu(&mut self, val: u16) {
            self.buf
                .set_bytes_two(NEXT_HOP_MTU_OFFSET, val.to_be_bytes());
        }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size();
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
        }
    }

    impl Debug for DestinationUnreachablePacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DestinationUnreachablePacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("unused", &self.get_unused())
                .field("next_hop_mtu", &self.get_next_hop_mtu())
                .field("payload", &fmt_payload(self.payload()))
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_icmp_type() {
            let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
            let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
            packet.set_icmp_type(Icmpv6Type::EchoRequest);
            assert_eq!(Icmpv6Type::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::EchoReply);
            assert_eq!(Icmpv6Type::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::DestinationUnreachable);
            assert_eq!(Icmpv6Type::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::TimeExceeded);
            assert_eq!(Icmpv6Type::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(Icmpv6Type::Other(255));
            assert_eq!(Icmpv6Type::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
            let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
            packet.set_icmp_code(Icmpv6Code(0));
            assert_eq!(Icmpv6Code(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(5));
            assert_eq!(Icmpv6Code(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(Icmpv6Code(255));
            assert_eq!(Icmpv6Code(255), packet.get_icmp_code());
            assert_eq!([0xFF], packet.packet()[1..2]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
            let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
            packet.set_checksum(0);
            assert_eq!(0, packet.get_checksum());
            assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
            packet.set_checksum(1999);
            assert_eq!(1999, packet.get_checksum());
            assert_eq!([0x07, 0xCF], packet.packet()[2..=3]);
            packet.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, packet.get_checksum());
            assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
        }
    }
}
