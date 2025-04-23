use crate::buffer::Buffer;
use crate::error::{Error, Result};
use std::fmt::{Debug, Formatter};

/// The type of `ICMPv6` packet.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    Other(u8),
}

impl IcmpType {
    #[must_use]
    pub const fn id(&self) -> u8 {
        match self {
            Self::EchoRequest => 128,
            Self::EchoReply => 129,
            Self::DestinationUnreachable => 1,
            Self::TimeExceeded => 3,
            Self::Other(id) => *id,
        }
    }
}

impl From<u8> for IcmpType {
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
pub struct IcmpCode(pub u8);

impl From<u8> for IcmpCode {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

/// The code for `TimeExceeded` `ICMPv6` packet type.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum IcmpTimeExceededCode {
    /// Hop limit exceeded in transit.
    TtlExpired,
    /// Fragment reassembly time exceeded.
    FragmentReassembly,
    /// An unknown code.
    Unknown(u8),
}

impl From<IcmpCode> for IcmpTimeExceededCode {
    fn from(val: IcmpCode) -> Self {
        match val {
            IcmpCode(0) => Self::TtlExpired,
            IcmpCode(1) => Self::FragmentReassembly,
            IcmpCode(id) => Self::Unknown(id),
        }
    }
}

const TYPE_OFFSET: usize = 0;
const CODE_OFFSET: usize = 1;
const CHECKSUM_OFFSET: usize = 2;

/// Represents an ICMP packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods
/// take and return data in host byte order, converting as necessary for the given architecture.
pub struct IcmpPacket<'a> {
    buf: Buffer<'a>,
}

impl<'a> IcmpPacket<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Self> {
        if packet.len() >= Self::minimum_packet_size() {
            Ok(Self {
                buf: Buffer::Mutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("IcmpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &'a [u8]) -> Result<Self> {
        if packet.len() >= Self::minimum_packet_size() {
            Ok(Self {
                buf: Buffer::Immutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("IcmpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        8
    }

    #[must_use]
    pub fn get_icmp_type(&self) -> IcmpType {
        IcmpType::from(self.buf.read(TYPE_OFFSET))
    }

    #[must_use]
    pub fn get_icmp_code(&self) -> IcmpCode {
        IcmpCode::from(self.buf.read(CODE_OFFSET))
    }

    #[must_use]
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
    }

    pub fn set_icmp_type(&mut self, val: IcmpType) {
        *self.buf.write(TYPE_OFFSET) = val.id();
    }

    pub fn set_icmp_code(&mut self, val: IcmpCode) {
        *self.buf.write(CODE_OFFSET) = val.0;
    }

    pub fn set_checksum(&mut self, val: u16) {
        self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Debug for IcmpPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpPacket")
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
        let mut buf = [0_u8; IcmpPacket::minimum_packet_size()];
        let mut packet = IcmpPacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpType::EchoRequest);
        assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
        assert_eq!([0x80], packet.packet()[0..1]);
        packet.set_icmp_type(IcmpType::EchoReply);
        assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
        assert_eq!([0x81], packet.packet()[0..1]);
        packet.set_icmp_type(IcmpType::DestinationUnreachable);
        assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
        assert_eq!([0x01], packet.packet()[0..1]);
        packet.set_icmp_type(IcmpType::TimeExceeded);
        assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
        assert_eq!([0x03], packet.packet()[0..1]);
        packet.set_icmp_type(IcmpType::Other(255));
        assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
        assert_eq!([0xFF], packet.packet()[0..1]);
    }

    #[test]
    fn test_icmp_code() {
        let mut buf = [0_u8; IcmpPacket::minimum_packet_size()];
        let mut packet = IcmpPacket::new(&mut buf).unwrap();
        packet.set_icmp_code(IcmpCode(0));
        assert_eq!(IcmpCode(0), packet.get_icmp_code());
        assert_eq!([0x00], packet.packet()[1..2]);
        packet.set_icmp_code(IcmpCode(5));
        assert_eq!(IcmpCode(5), packet.get_icmp_code());
        assert_eq!([0x05], packet.packet()[1..2]);
        packet.set_icmp_code(IcmpCode(255));
        assert_eq!(IcmpCode(255), packet.get_icmp_code());
        assert_eq!([0xFF], packet.packet()[1..2]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; IcmpPacket::minimum_packet_size()];
        let mut packet = IcmpPacket::new(&mut buf).unwrap();
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
    fn test_new_insufficient_buffer() {
        const SIZE: usize = IcmpPacket::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = IcmpPacket::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("IcmpPacket"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = IcmpPacket::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = IcmpPacket::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("IcmpPacket"), SIZE, SIZE - 1),
            err
        );
    }
}

pub mod echo_request {
    use crate::buffer::Buffer;
    use crate::error::{Error, Result};
    use crate::fmt_payload;
    use crate::icmpv6::{IcmpCode, IcmpType};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const IDENTIFIER_OFFSET: usize = 4;
    const SEQUENCE_OFFSET: usize = 6;

    /// Represents an `ICMPv6` `EchoRequest` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct EchoRequestPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> EchoRequestPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("EchoRequestPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        pub fn new_view(packet: &'a [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("EchoRequestPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> IcmpType {
            IcmpType::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> IcmpCode {
            IcmpCode::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_identifier(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(IDENTIFIER_OFFSET))
        }

        #[must_use]
        pub fn get_sequence(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(SEQUENCE_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: IcmpType) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: IcmpCode) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_identifier(&mut self, val: u16) {
            self.buf.set_bytes(IDENTIFIER_OFFSET, val.to_be_bytes());
        }

        pub fn set_sequence(&mut self, val: u16) {
            self.buf.set_bytes(SEQUENCE_OFFSET, val.to_be_bytes());
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
            &self.buf.as_slice()[Self::minimum_packet_size()..]
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
            packet.set_icmp_type(IcmpType::EchoRequest);
            assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::EchoReply);
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::DestinationUnreachable);
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::TimeExceeded);
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::Other(255));
            assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
            let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(IcmpCode(0));
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(5));
            assert_eq!(IcmpCode(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(255));
            assert_eq!(IcmpCode(255), packet.get_icmp_code());
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

        #[test]
        fn test_view() {
            let buf = [0x80, 0x00, 0x16, 0x7c, 0x60, 0x9b, 0x82, 0x9a];
            let packet = EchoRequestPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!(5756, packet.get_checksum());
            assert_eq!(24731, packet.get_identifier());
            assert_eq!(33434, packet.get_sequence());
            assert!(packet.payload().is_empty());
        }

        #[test]
        fn test_new_insufficient_buffer() {
            const SIZE: usize = EchoRequestPacket::minimum_packet_size();
            let mut buf = [0_u8; SIZE - 1];
            let err = EchoRequestPacket::new(&mut buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("EchoRequestPacket"), SIZE, SIZE - 1),
                err
            );
        }

        #[test]
        fn test_new_view_insufficient_buffer() {
            const SIZE: usize = EchoRequestPacket::minimum_packet_size();
            let buf = [0_u8; SIZE - 1];
            let err = EchoRequestPacket::new_view(&buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("EchoRequestPacket"), SIZE, SIZE - 1),
                err
            );
        }
    }
}

pub mod echo_reply {
    use crate::buffer::Buffer;
    use crate::error::{Error, Result};
    use crate::fmt_payload;
    use crate::icmpv6::{IcmpCode, IcmpType};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const IDENTIFIER_OFFSET: usize = 4;
    const SEQUENCE_OFFSET: usize = 6;

    /// Represents an ICMP `EchoReply` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct EchoReplyPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> EchoReplyPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("EchoReplyPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        pub fn new_view(packet: &'a [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("EchoReplyPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> IcmpType {
            IcmpType::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> IcmpCode {
            IcmpCode::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_identifier(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(IDENTIFIER_OFFSET))
        }

        #[must_use]
        pub fn get_sequence(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(SEQUENCE_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: IcmpType) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: IcmpCode) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_identifier(&mut self, val: u16) {
            self.buf.set_bytes(IDENTIFIER_OFFSET, val.to_be_bytes());
        }

        pub fn set_sequence(&mut self, val: u16) {
            self.buf.set_bytes(SEQUENCE_OFFSET, val.to_be_bytes());
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
            &self.buf.as_slice()[Self::minimum_packet_size()..]
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
            packet.set_icmp_type(IcmpType::EchoRequest);
            assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::EchoReply);
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::DestinationUnreachable);
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::TimeExceeded);
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::Other(255));
            assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
            let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(IcmpCode(0));
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(5));
            assert_eq!(IcmpCode(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(255));
            assert_eq!(IcmpCode(255), packet.get_icmp_code());
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

        #[test]
        fn test_view() {
            let buf = [0x81, 0x00, 0x1e, 0x70, 0x60, 0x9b, 0x80, 0xf4];
            let packet = EchoReplyPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!(7792, packet.get_checksum());
            assert_eq!(24731, packet.get_identifier());
            assert_eq!(33012, packet.get_sequence());
            assert!(packet.payload().is_empty());
        }

        #[test]
        fn test_new_insufficient_buffer() {
            const SIZE: usize = EchoReplyPacket::minimum_packet_size();
            let mut buf = [0_u8; SIZE - 1];
            let err = EchoReplyPacket::new(&mut buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("EchoReplyPacket"), SIZE, SIZE - 1),
                err
            );
        }

        #[test]
        fn test_new_view_insufficient_buffer() {
            const SIZE: usize = EchoReplyPacket::minimum_packet_size();
            let buf = [0_u8; SIZE - 1];
            let err = EchoReplyPacket::new_view(&buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("EchoReplyPacket"), SIZE, SIZE - 1),
                err
            );
        }
    }
}

pub mod time_exceeded {
    use crate::buffer::Buffer;
    use crate::error::{Error, Result};
    use crate::fmt_payload;
    use crate::icmp_extension::extension_splitter::split;
    use crate::icmpv6::{IcmpCode, IcmpType};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const LENGTH_OFFSET: usize = 4;

    /// Represents an ICMP `TimeExceeded` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct TimeExceededPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> TimeExceededPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("TimeExceededPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        pub fn new_view(packet: &'a [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("TimeExceededPacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> IcmpType {
            IcmpType::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> IcmpCode {
            IcmpCode::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_length(&self) -> u8 {
            self.buf.read(LENGTH_OFFSET)
        }

        pub fn set_icmp_type(&mut self, val: IcmpType) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: IcmpCode) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_length(&mut self, val: u8) {
            *self.buf.write(LENGTH_OFFSET) = val;
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
            let (payload, _) = self.split_payload_extension();
            payload
        }

        #[must_use]
        pub fn payload_raw(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size()..]
        }

        #[must_use]
        pub fn extension(&self) -> Option<&[u8]> {
            let (_, extension) = self.split_payload_extension();
            extension
        }

        fn split_payload_extension(&self) -> (&[u8], Option<&[u8]>) {
            let length = usize::from(self.get_length()) * 8;
            let icmp_payload = &self.buf.as_slice()[Self::minimum_packet_size()..];
            split(length, icmp_payload)
        }
    }

    impl Debug for TimeExceededPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TimeExceededPacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("length", &self.get_length())
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
            packet.set_icmp_type(IcmpType::EchoRequest);
            assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::EchoReply);
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::DestinationUnreachable);
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::TimeExceeded);
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::Other(255));
            assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
            let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(IcmpCode(0));
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(5));
            assert_eq!(IcmpCode(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(255));
            assert_eq!(IcmpCode(255), packet.get_icmp_code());
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

        #[test]
        fn test_length() {
            let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
            let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
            packet.set_length(0);
            assert_eq!(0, packet.get_length());
            assert_eq!([0x00], packet.packet()[4..5]);
            packet.set_length(8);
            assert_eq!(8, packet.get_length());
            assert_eq!([0x08], packet.packet()[4..5]);
            packet.set_length(u8::MAX);
            assert_eq!(u8::MAX, packet.get_length());
            assert_eq!([0xFF], packet.packet()[4..5]);
        }

        #[test]
        fn test_view() {
            let buf = [0x03, 0x00, 0xf4, 0xee, 0x11, 0x00, 0x00, 0x00];
            let packet = TimeExceededPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!(62702, packet.get_checksum());
            assert_eq!(17, packet.get_length());
            assert!(packet.payload().is_empty());
        }

        #[test]
        fn test_view_large() {
            let mut buf = [0x0_u8; 128];
            buf[..8].copy_from_slice(&[0x03, 0x00, 0xf4, 0xee, 0x20, 0x00, 0x00, 0x00]);
            let packet = TimeExceededPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!(62702, packet.get_checksum());
            assert_eq!(32, packet.get_length());
            assert_eq!(&[0x0_u8; 120], packet.payload());
            assert_eq!(None, packet.extension());
        }

        #[test]
        fn test_new_insufficient_buffer() {
            const SIZE: usize = TimeExceededPacket::minimum_packet_size();
            let mut buf = [0_u8; SIZE - 1];
            let err = TimeExceededPacket::new(&mut buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("TimeExceededPacket"), SIZE, SIZE - 1),
                err
            );
        }

        #[test]
        fn test_new_view_insufficient_buffer() {
            const SIZE: usize = TimeExceededPacket::minimum_packet_size();
            let buf = [0_u8; SIZE - 1];
            let err = TimeExceededPacket::new_view(&buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(String::from("TimeExceededPacket"), SIZE, SIZE - 1),
                err
            );
        }
    }
}

pub mod destination_unreachable {
    use crate::buffer::Buffer;
    use crate::error::{Error, Result};
    use crate::fmt_payload;
    use crate::icmp_extension::extension_splitter::split;
    use crate::icmpv6::{IcmpCode, IcmpType};
    use std::fmt::{Debug, Formatter};

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;
    const LENGTH_OFFSET: usize = 4;
    const NEXT_HOP_MTU_OFFSET: usize = 6;

    /// Represents an ICMP `DestinationUnreachable` packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct DestinationUnreachablePacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> DestinationUnreachablePacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("DestinationUnreachablePacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        pub fn new_view(packet: &'a [u8]) -> Result<Self> {
            if packet.len() >= Self::minimum_packet_size() {
                Ok(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                Err(Error::InsufficientPacketBuffer(
                    String::from("DestinationUnreachablePacket"),
                    Self::minimum_packet_size(),
                    packet.len(),
                ))
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
        }

        #[must_use]
        pub fn get_icmp_type(&self) -> IcmpType {
            IcmpType::from(self.buf.read(TYPE_OFFSET))
        }

        #[must_use]
        pub fn get_icmp_code(&self) -> IcmpCode {
            IcmpCode::from(self.buf.read(CODE_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_length(&self) -> u8 {
            self.buf.read(LENGTH_OFFSET)
        }

        #[must_use]
        pub fn get_next_hop_mtu(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(NEXT_HOP_MTU_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: IcmpType) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: IcmpCode) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_length(&mut self, val: u8) {
            *self.buf.write(LENGTH_OFFSET) = val;
        }

        pub fn set_next_hop_mtu(&mut self, val: u16) {
            self.buf.set_bytes(NEXT_HOP_MTU_OFFSET, val.to_be_bytes());
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
            let (payload, _) = self.split_payload_extension();
            payload
        }

        #[must_use]
        pub fn payload_raw(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size()..]
        }

        #[must_use]
        pub fn extension(&self) -> Option<&[u8]> {
            let (_, extension) = self.split_payload_extension();
            extension
        }

        fn split_payload_extension(&self) -> (&[u8], Option<&[u8]>) {
            // From rfc4884:
            //
            // "For ICMPv6 messages, the length attribute represents 64-bit words"
            let length = usize::from(self.get_length()) * 8;
            let icmp_payload = &self.buf.as_slice()[Self::minimum_packet_size()..];
            split(length, icmp_payload)
        }
    }

    impl Debug for DestinationUnreachablePacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DestinationUnreachablePacket")
                .field("icmp_type", &self.get_icmp_type())
                .field("icmp_code", &self.get_icmp_code())
                .field("checksum", &self.get_checksum())
                .field("length", &self.get_length())
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
            packet.set_icmp_type(IcmpType::EchoRequest);
            assert_eq!(IcmpType::EchoRequest, packet.get_icmp_type());
            assert_eq!([0x80], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::EchoReply);
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!([0x81], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::DestinationUnreachable);
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x01], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::TimeExceeded);
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x03], packet.packet()[0..1]);
            packet.set_icmp_type(IcmpType::Other(255));
            assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.packet()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
            let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
            packet.set_icmp_code(IcmpCode(0));
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(5));
            assert_eq!(IcmpCode(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.packet()[1..2]);
            packet.set_icmp_code(IcmpCode(255));
            assert_eq!(IcmpCode(255), packet.get_icmp_code());
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

        #[test]
        fn test_length() {
            let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
            let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
            packet.set_length(0);
            assert_eq!(0, packet.get_length());
            assert_eq!([0x00], packet.packet()[4..5]);
            packet.set_length(8);
            assert_eq!(8, packet.get_length());
            assert_eq!([0x08], packet.packet()[4..5]);
            packet.set_length(u8::MAX);
            assert_eq!(u8::MAX, packet.get_length());
            assert_eq!([0xFF], packet.packet()[4..5]);
        }

        #[test]
        fn test_view() {
            let buf = [0x01, 0x03, 0xdf, 0xdc, 0x00, 0x00, 0x00, 0x00];
            let packet = DestinationUnreachablePacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!(IcmpCode(3), packet.get_icmp_code());
            assert_eq!(57308, packet.get_checksum());
            assert_eq!(0, packet.get_length());
            assert!(packet.payload().is_empty());
        }

        #[test]
        fn test_view_large() {
            let mut buf = [0x0_u8; 128];
            buf[..8].copy_from_slice(&[0x01, 0x03, 0xdf, 0xdc, 0x20, 0x00, 0x00, 0x00]);
            let packet = DestinationUnreachablePacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!(IcmpCode(3), packet.get_icmp_code());
            assert_eq!(57308, packet.get_checksum());
            assert_eq!(32, packet.get_length());
            assert_eq!(&[0x0_u8; 120], packet.payload());
            assert_eq!(None, packet.extension());
        }

        #[test]
        fn test_new_insufficient_buffer() {
            const SIZE: usize = DestinationUnreachablePacket::minimum_packet_size();
            let mut buf = [0_u8; SIZE - 1];
            let err = DestinationUnreachablePacket::new(&mut buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(
                    String::from("DestinationUnreachablePacket"),
                    SIZE,
                    SIZE - 1
                ),
                err
            );
        }

        #[test]
        fn test_new_view_insufficient_buffer() {
            const SIZE: usize = DestinationUnreachablePacket::minimum_packet_size();
            let buf = [0_u8; SIZE - 1];
            let err = DestinationUnreachablePacket::new_view(&buf).unwrap_err();
            assert_eq!(
                Error::InsufficientPacketBuffer(
                    String::from("DestinationUnreachablePacket"),
                    SIZE,
                    SIZE - 1
                ),
                err
            );
        }
    }
}
