use crate::tracing::packet::buffer::Buffer;
use crate::tracing::packet::fmt_payload;
use std::fmt::{Debug, Formatter};

const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const SEQUENCE_OFFSET: usize = 4;
const ACKNOWLEDGEMENT_OFFSET: usize = 8;
const DATA_OFFSET_OFFSET: usize = 12;
const RESERVED_OFFSET: usize = 12;
const FLAGS_OFFSET: usize = 12;
const WINDOW_SIZE_OFFSET: usize = 14;
const CHECKSUM_OFFSET: usize = 16;
const URGENT_POINTER_OFFSET: usize = 18;

/// Represents an TCP Packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
/// data in host byte order, converting as necessary for the given architecture.
pub struct TcpPacket<'a> {
    buf: Buffer<'a>,
}

impl<'a> TcpPacket<'a> {
    pub fn new(packet: &mut [u8]) -> Option<TcpPacket<'_>> {
        if packet.len() >= Self::minimum_packet_size() {
            Some(TcpPacket {
                buf: Buffer::Mutable(packet),
            })
        } else {
            None
        }
    }

    #[must_use]
    pub fn new_view(packet: &[u8]) -> Option<TcpPacket<'_>> {
        if packet.len() >= Self::minimum_packet_size() {
            Some(TcpPacket {
                buf: Buffer::Immutable(packet),
            })
        } else {
            None
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        20
    }

    #[must_use]
    pub fn get_source(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(SOURCE_PORT_OFFSET))
    }

    #[must_use]
    pub fn get_destination(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(DESTINATION_PORT_OFFSET))
    }

    #[must_use]
    pub fn get_sequence(&self) -> u32 {
        u32::from_be_bytes(self.buf.get_bytes_four(SEQUENCE_OFFSET))
    }

    #[must_use]
    pub fn get_acknowledgement(&self) -> u32 {
        u32::from_be_bytes(self.buf.get_bytes_four(ACKNOWLEDGEMENT_OFFSET))
    }

    #[must_use]
    pub fn get_data_offset(&self) -> u8 {
        (self.buf.read(DATA_OFFSET_OFFSET) & 0xf0) >> 4
    }

    #[must_use]
    pub fn get_reserved(&self) -> u8 {
        (self.buf.read(RESERVED_OFFSET) & 0xe) >> 1
    }

    #[must_use]
    pub fn get_flags(&self) -> u16 {
        u16::from_be_bytes([
            (self.buf.read(FLAGS_OFFSET) & 0x1),
            self.buf.read(FLAGS_OFFSET + 1),
        ])
    }

    #[must_use]
    pub fn get_window_size(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(WINDOW_SIZE_OFFSET))
    }

    #[must_use]
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
    }

    #[must_use]
    pub fn get_urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes_two(URGENT_POINTER_OFFSET))
    }

    #[must_use]
    pub fn get_options_raw(&self) -> &[u8] {
        let current_offset = Self::minimum_packet_size();
        let end = std::cmp::min(
            current_offset + self.tcp_options_length(),
            self.buf.as_slice().len(),
        );
        &self.buf.as_slice()[current_offset..end]
    }

    pub fn set_source(&mut self, val: u16) {
        self.buf
            .set_bytes_two(SOURCE_PORT_OFFSET, val.to_be_bytes());
    }

    pub fn set_destination(&mut self, val: u16) {
        self.buf
            .set_bytes_two(DESTINATION_PORT_OFFSET, val.to_be_bytes());
    }

    pub fn set_sequence(&mut self, val: u32) {
        self.buf.set_bytes_four(SEQUENCE_OFFSET, val.to_be_bytes());
    }

    pub fn set_acknowledgement(&mut self, val: u32) {
        self.buf
            .set_bytes_four(ACKNOWLEDGEMENT_OFFSET, val.to_be_bytes());
    }

    pub fn set_data_offset(&mut self, val: u8) {
        *self.buf.write(DATA_OFFSET_OFFSET) =
            (self.buf.read(DATA_OFFSET_OFFSET) & 0xf) | ((val & 0xf) << 4);
    }

    pub fn set_reserved(&mut self, val: u8) {
        *self.buf.write(RESERVED_OFFSET) =
            (self.buf.read(RESERVED_OFFSET) & 0xf1) | ((val & 0x7) << 1);
    }

    pub fn set_flags(&mut self, val: u16) {
        let bytes = val.to_be_bytes();
        *self.buf.write(FLAGS_OFFSET) = (self.buf.read(FLAGS_OFFSET) & 0xfe) | (bytes[0] & 0x1);
        *self.buf.write(FLAGS_OFFSET + 1) = bytes[1];
    }

    pub fn set_window_size(&mut self, val: u16) {
        self.buf
            .set_bytes_two(WINDOW_SIZE_OFFSET, val.to_be_bytes());
    }

    pub fn set_checksum(&mut self, val: u16) {
        self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
    }

    pub fn set_urgent_pointer(&mut self, val: u16) {
        self.buf
            .set_bytes_two(URGENT_POINTER_OFFSET, val.to_be_bytes());
    }

    // TODO
    // pub fn set_options(&mut self) {
    //     unimplemented!()
    // }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size() + self.tcp_options_length();
        self.buf.as_slice_mut()[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }

    fn payload(&self) -> &[u8] {
        let start = Self::minimum_packet_size() + self.tcp_options_length();
        if self.buf.as_slice().len() <= start {
            return &[];
        }
        &self.buf.as_slice()[start..]
    }

    fn tcp_options_length(&self) -> usize {
        let data_offset = self.get_data_offset();
        if data_offset > 5 {
            data_offset as usize * 4 - 20
        } else {
            0
        }
    }
}

impl Debug for TcpPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpPacket")
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            .field("sequence", &self.get_sequence())
            .field("acknowledgement", &self.get_acknowledgement())
            .field("data_offset", &self.get_data_offset())
            .field("reserved", &self.get_reserved())
            .field("flags", &self.get_flags())
            .field("window_size", &self.get_window_size())
            .field("checksum", &self.get_checksum())
            .field("urgent_pointer", &self.get_urgent_pointer())
            .field("options", &self.get_options_raw())
            .field("payload", &fmt_payload(self.payload()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
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
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
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
    fn test_sequence() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_sequence(0);
        assert_eq!(0, packet.get_sequence());
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[4..=7]);
        packet.set_sequence(123_456);
        assert_eq!(123_456, packet.get_sequence());
        assert_eq!([0x00, 0x01, 0xE2, 0x40], packet.packet()[4..=7]);
        packet.set_sequence(u32::MAX);
        assert_eq!(u32::MAX, packet.get_sequence());
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[4..=7]);
    }

    #[test]
    fn test_acknowledgement() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_acknowledgement(0);
        assert_eq!(0, packet.get_acknowledgement());
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[8..=11]);
        packet.set_acknowledgement(123_456);
        assert_eq!(123_456, packet.get_acknowledgement());
        assert_eq!([0x00, 0x01, 0xE2, 0x40], packet.packet()[8..=11]);
        packet.set_acknowledgement(u32::MAX);
        assert_eq!(u32::MAX, packet.get_acknowledgement());
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[8..=11]);
    }

    #[test]
    fn test_data_offset() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_data_offset(0);
        assert_eq!(0, packet.get_data_offset());
        assert_eq!([0x00], packet.packet()[12..13]);
        packet.set_data_offset(15);
        assert_eq!(15, packet.get_data_offset());
        assert_eq!([0xf0], packet.packet()[12..13]);
    }

    #[test]
    fn test_reserved() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_reserved(0);
        assert_eq!(0, packet.get_reserved());
        assert_eq!([0x00], packet.packet()[12..13]);
        packet.set_reserved(7);
        assert_eq!(7, packet.get_reserved());
        assert_eq!([0x0e], packet.packet()[12..13]);
    }

    #[test]
    fn test_flags() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_flags(0);
        assert_eq!(0, packet.get_flags());
        assert_eq!([0x00, 0x00], packet.packet()[12..=13]);
        packet.set_flags(511);
        assert_eq!(511, packet.get_flags());
        assert_eq!([0x01, 0xff], packet.packet()[12..=13]);
    }

    #[test]
    fn test_window_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_window_size(0);
        assert_eq!(0, packet.get_window_size());
        assert_eq!([0x00, 0x00], packet.packet()[14..=15]);
        packet.set_window_size(80);
        assert_eq!(80, packet.get_window_size());
        assert_eq!([0x00, 0x50], packet.packet()[14..=15]);
        packet.set_window_size(443);
        assert_eq!(443, packet.get_window_size());
        assert_eq!([0x01, 0xBB], packet.packet()[14..=15]);
        packet.set_window_size(u16::MAX);
        assert_eq!(u16::MAX, packet.get_window_size());
        assert_eq!([0xFF, 0xFF], packet.packet()[14..=15]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_checksum(0);
        assert_eq!(0, packet.get_checksum());
        assert_eq!([0x00, 0x00], packet.packet()[16..=17]);
        packet.set_checksum(80);
        assert_eq!(80, packet.get_checksum());
        assert_eq!([0x00, 0x50], packet.packet()[16..=17]);
        packet.set_checksum(443);
        assert_eq!(443, packet.get_checksum());
        assert_eq!([0x01, 0xBB], packet.packet()[16..=17]);
        packet.set_checksum(u16::MAX);
        assert_eq!(u16::MAX, packet.get_checksum());
        assert_eq!([0xFF, 0xFF], packet.packet()[16..=17]);
    }

    #[test]
    fn test_urgent_pointer() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_urgent_pointer(0);
        assert_eq!(0, packet.get_urgent_pointer());
        assert_eq!([0x00, 0x00], packet.packet()[18..=19]);
        packet.set_urgent_pointer(80);
        assert_eq!(80, packet.get_urgent_pointer());
        assert_eq!([0x00, 0x50], packet.packet()[18..=19]);
        packet.set_urgent_pointer(443);
        assert_eq!(443, packet.get_urgent_pointer());
        assert_eq!([0x01, 0xBB], packet.packet()[18..=19]);
        packet.set_urgent_pointer(u16::MAX);
        assert_eq!(u16::MAX, packet.get_urgent_pointer());
        assert_eq!([0xFF, 0xFF], packet.packet()[18..=19]);
    }
}
