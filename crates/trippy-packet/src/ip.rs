use crate::buffer::Buffer;
use crate::error::{Error, Result};
use std::fmt::{Debug, Formatter};

/// The IP packet version.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
    Other(u8),
}

impl IpVersion {
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 6,
            Self::Other(id) => id,
        }
    }

    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self::Other(value)
    }
}

impl From<u8> for IpVersion {
    fn from(id: u8) -> Self {
        match id {
            4 => Self::Ipv4,
            6 => Self::Ipv6,
            p => Self::Other(p),
        }
    }
}

const VERSION_OFFSET: usize = 0;

/// Represents a generic IP packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods
/// take and return data in host byte order, converting as necessary for the given architecture.
pub struct IpPacket<'a> {
    buf: Buffer<'a>,
}

impl<'a> IpPacket<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Self> {
        if packet.len() >= Self::minimum_packet_size() {
            Ok(Self {
                buf: Buffer::Mutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("IpPacket"),
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
                String::from("IpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        20
    }

    #[must_use]
    pub fn get_version(&self) -> IpVersion {
        IpVersion::from((self.buf.read(VERSION_OFFSET) & 0xF0) >> 4)
    }

    pub fn set_version(&mut self, val: IpVersion) {
        *self.buf.write(VERSION_OFFSET) =
            (self.buf.read(VERSION_OFFSET) & 0x0F) | ((val.id() & 0x0F) << 4);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Debug for IpPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpPacket")
            .field("version", &self.get_version())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let mut buf = [0_u8; IpPacket::minimum_packet_size()];
        let mut packet = IpPacket::new(&mut buf).unwrap();
        packet.set_version(IpVersion::Ipv4);
        assert_eq!(IpVersion::Ipv4, packet.get_version());
        assert_eq!([0x40], packet.packet()[..1]);
        packet.set_version(IpVersion::Ipv6);
        assert_eq!(IpVersion::Ipv6, packet.get_version());
        assert_eq!([0x60], packet.packet()[..1]);
        packet.set_version(IpVersion::Other(15));
        assert_eq!(IpVersion::Other(15), packet.get_version());
        assert_eq!([0xF0], packet.packet()[..1]);
    }

    #[test]
    fn test_view_ipv4_packet() {
        let buf = hex_literal::hex!(
            "
           45 00 00 54 a2 71 00 00 15 11 9a ee 7f 00 00 01
           de 9a 56 12
           "
        );
        let packet = IpPacket::new_view(&buf).unwrap();
        assert_eq!(IpVersion::Ipv4, packet.get_version());
    }

    #[test]
    fn test_view_ipv6_packet() {
        let buf = hex_literal::hex!(
            "
           60 06 05 00 00 20 06 40 fe 80 00 00 00 00 00 00
           1c 8d 7d 69 d0 b6 81 82 fe 80 00 00 00 00 00 00
           08 11 03 f6 76 01 6c 3f
           "
        );
        let packet = IpPacket::new_view(&buf).unwrap();
        assert_eq!(IpVersion::Ipv6, packet.get_version());
    }

    #[test]
    fn test_new_insufficient_buffer() {
        const SIZE: usize = IpPacket::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = IpPacket::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("IpPacket"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = IpPacket::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = IpPacket::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("IpPacket"), SIZE, SIZE - 1),
            err
        );
    }
}
