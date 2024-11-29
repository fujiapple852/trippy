use crate::buffer::Buffer;
use crate::error::{Error, Result};
use crate::fmt_payload;
use std::fmt::{Debug, Formatter};

const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const LENGTH_OFFSET: usize = 4;
const CHECKSUM_OFFSET: usize = 6;

/// Represents a UDP Packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods
/// take and return data in host byte order, converting as necessary for the given architecture.
pub struct UdpPacket<'a> {
    buf: Buffer<'a>,
}

impl UdpPacket<'_> {
    pub fn new(packet: &mut [u8]) -> Result<UdpPacket<'_>> {
        if packet.len() >= UdpPacket::minimum_packet_size() {
            Ok(UdpPacket {
                buf: Buffer::Mutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("UdpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &[u8]) -> Result<UdpPacket<'_>> {
        if packet.len() >= UdpPacket::minimum_packet_size() {
            Ok(UdpPacket {
                buf: Buffer::Immutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("UdpPacket"),
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
    pub fn get_source(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(SOURCE_PORT_OFFSET))
    }

    #[must_use]
    pub fn get_destination(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(DESTINATION_PORT_OFFSET))
    }

    #[must_use]
    pub fn get_length(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(LENGTH_OFFSET))
    }

    #[must_use]
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
    }

    pub fn set_source(&mut self, val: u16) {
        self.buf.set_bytes(SOURCE_PORT_OFFSET, val.to_be_bytes());
    }

    pub fn set_destination(&mut self, val: u16) {
        self.buf
            .set_bytes(DESTINATION_PORT_OFFSET, val.to_be_bytes());
    }

    pub fn set_length(&mut self, val: u16) {
        self.buf.set_bytes(LENGTH_OFFSET, val.to_be_bytes());
    }

    pub fn set_checksum(&mut self, val: u16) {
        self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size();
        self.buf.as_slice_mut()[current_offset..current_offset + vals.len()].copy_from_slice(vals);
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

impl Debug for UdpPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            .field("length", &self.get_length())
            .field("checksum", &self.get_checksum())
            .field("payload", &fmt_payload(self.payload()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.set_source(0);
        assert_eq!(0, packet.get_source());
        assert_eq!([0x00, 0x00], packet.packet()[..=1]);
        packet.set_source(80);
        assert_eq!(80, packet.get_source());
        assert_eq!([0x00, 0x50], packet.packet()[..=1]);
        packet.set_source(443);
        assert_eq!(443, packet.get_source());
        assert_eq!([0x01, 0xBB], packet.packet()[..=1]);
        packet.set_source(u16::MAX);
        assert_eq!(u16::MAX, packet.get_source());
        assert_eq!([0xFF, 0xFF], packet.packet()[..=1]);
    }

    #[test]
    fn test_destination() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.set_destination(0);
        assert_eq!(0, packet.get_destination());
        assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
        packet.set_destination(80);
        assert_eq!(80, packet.get_destination());
        assert_eq!([0x00, 0x50], packet.packet()[2..=3]);
        packet.set_destination(443);
        assert_eq!(443, packet.get_destination());
        assert_eq!([0x01, 0xBB], packet.packet()[2..=3]);
        packet.set_destination(u16::MAX);
        assert_eq!(u16::MAX, packet.get_destination());
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }

    #[test]
    fn test_length() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.set_length(0);
        assert_eq!(0, packet.get_length());
        assert_eq!([0x00, 0x00], packet.packet()[4..=5]);
        packet.set_length(202);
        assert_eq!(202, packet.get_length());
        assert_eq!([0x00, 0xCA], packet.packet()[4..=5]);
        packet.set_length(1025);
        assert_eq!(1025, packet.get_length());
        assert_eq!([0x04, 0x01], packet.packet()[4..=5]);
        packet.set_length(u16::MAX);
        assert_eq!(u16::MAX, packet.get_length());
        assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.set_checksum(0);
        assert_eq!(0, packet.get_checksum());
        assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
        packet.set_checksum(202);
        assert_eq!(202, packet.get_checksum());
        assert_eq!([0x00, 0xCA], packet.packet()[6..=7]);
        packet.set_checksum(1025);
        assert_eq!(1025, packet.get_checksum());
        assert_eq!([0x04, 0x01], packet.packet()[6..=7]);
        packet.set_checksum(u16::MAX);
        assert_eq!(u16::MAX, packet.get_checksum());
        assert_eq!([0xFF, 0xFF], packet.packet()[6..=7]);
    }

    #[test]
    fn test_view() {
        let buf = [0x68, 0xbf, 0x81, 0xb6, 0x00, 0x40, 0xac, 0xbe];
        let packet = UdpPacket::new_view(&buf).unwrap();
        assert_eq!(26815, packet.get_source());
        assert_eq!(33206, packet.get_destination());
        assert_eq!(64, packet.get_length());
        assert_eq!(44222, packet.get_checksum());
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn test_new_insufficient_buffer() {
        const SIZE: usize = UdpPacket::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = UdpPacket::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("UdpPacket"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = UdpPacket::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = UdpPacket::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("UdpPacket"), SIZE, SIZE - 1),
            err
        );
    }
}
