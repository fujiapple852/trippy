use crate::error::{Error, Result};
use bytemuck::{Pod, Zeroable};
use std::fmt::{Debug, Formatter};
use crate::fmt_payload;

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct TcpHeader {
    pub source: u16,
    pub destination: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub data_offset_reserved_flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

pub struct TcpPacket<'a> {
    header: &'a mut TcpHeader,
    payload: &'a mut [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<TcpPacket<'a>> {
        if packet.len() >= TcpPacket::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at_mut(std::mem::size_of::<TcpHeader>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(TcpPacket { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("TcpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &'a [u8]) -> Result<TcpPacket<'a>> {
        if packet.len() >= TcpPacket::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at(std::mem::size_of::<TcpHeader>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(TcpPacket { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("TcpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        std::mem::size_of::<TcpHeader>()
    }

    #[must_use]
    pub fn get_data_offset(&self) -> u8 {
        (self.header.data_offset_reserved_flags & 0xf000) as u8 >> 12
    }

    #[must_use]
    pub fn get_reserved(&self) -> u8 {
        (self.header.data_offset_reserved_flags & 0x0e00) as u8 >> 9
    }

    #[must_use]
    pub fn get_flags(&self) -> u16 {
        self.header.data_offset_reserved_flags & 0x01ff
    }

    #[must_use]
    pub fn get_options_raw(&self) -> &[u8] {
        let current_offset = Self::minimum_packet_size();
        let end = std::cmp::min(
            current_offset + self.tcp_options_length(),
            self.payload.len(),
        );
        &self.payload[current_offset..end]
    }

    pub fn set_data_offset(&mut self, val: u8) {
        self.header.data_offset_reserved_flags =
            (self.header.data_offset_reserved_flags & 0x0fff) | ((val as u16) << 12);
    }

    pub fn set_reserved(&mut self, val: u8) {
        self.header.data_offset_reserved_flags =
            (self.header.data_offset_reserved_flags & 0xf1ff) | ((val as u16) << 9);
    }

    pub fn set_flags(&mut self, val: u16) {
        self.header.data_offset_reserved_flags =
            (self.header.data_offset_reserved_flags & 0xfe00) | (val & 0x01ff);
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size() + self.tcp_options_length();
        self.payload[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.header as *const _ as *const u8, self.payload.len() + std::mem::size_of::<TcpHeader>()) }
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = TcpPacket::minimum_packet_size() + self.tcp_options_length();
        &self.payload[start..]
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
            .field("source", &self.header.source)
            .field("destination", &self.header.destination)
            .field("sequence", &self.header.sequence)
            .field("acknowledgement", &self.header.acknowledgement)
            .field("data_offset", &self.get_data_offset())
            .field("reserved", &self.get_reserved())
            .field("flags", &self.get_flags())
            .field("window_size", &self.header.window_size)
            .field("checksum", &self.header.checksum)
            .field("urgent_pointer", &self.header.urgent_pointer)
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
        packet.header.source = 0;
        assert_eq!(0, packet.header.source);
        assert_eq!([0x00, 0x00], packet.packet()[..=1]);
        packet.header.source = 80;
        assert_eq!(80, packet.header.source);
        assert_eq!([0x00, 0x50], packet.packet()[..=1]);
        packet.header.source = 443;
        assert_eq!(443, packet.header.source);
        assert_eq!([0x01, 0xBB], packet.packet()[..=1]);
        packet.header.source = u16::MAX;
        assert_eq!(u16::MAX, packet.header.source);
        assert_eq!([0xFF, 0xFF], packet.packet()[..=1]);
    }

    #[test]
    fn test_destination() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.destination = 0;
        assert_eq!(0, packet.header.destination);
        assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
        packet.header.destination = 80;
        assert_eq!(80, packet.header.destination);
        assert_eq!([0x00, 0x50], packet.packet()[2..=3]);
        packet.header.destination = 443;
        assert_eq!(443, packet.header.destination);
        assert_eq!([0x01, 0xBB], packet.packet()[2..=3]);
        packet.header.destination = u16::MAX;
        assert_eq!(u16::MAX, packet.header.destination);
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }

    #[test]
    fn test_sequence() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.sequence = 0;
        assert_eq!(0, packet.header.sequence);
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[4..=7]);
        packet.header.sequence = 123_456;
        assert_eq!(123_456, packet.header.sequence);
        assert_eq!([0x00, 0x01, 0xE2, 0x40], packet.packet()[4..=7]);
        packet.header.sequence = u32::MAX;
        assert_eq!(u32::MAX, packet.header.sequence);
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[4..=7]);
    }

    #[test]
    fn test_acknowledgement() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.acknowledgement = 0;
        assert_eq!(0, packet.header.acknowledgement);
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[8..=11]);
        packet.header.acknowledgement = 123_456;
        assert_eq!(123_456, packet.header.acknowledgement);
        assert_eq!([0x00, 0x01, 0xE2, 0x40], packet.packet()[8..=11]);
        packet.header.acknowledgement = u32::MAX;
        assert_eq!(u32::MAX, packet.header.acknowledgement);
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[8..=11]);
    }

    #[test]
    fn test_data_offset() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_data_offset(0);
        assert_eq!(0, packet.get_data_offset());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_data_offset(15);
        assert_eq!(15, packet.get_data_offset());
        assert_eq!([0xf0, 0x00], packet.packet()[12..14]);
    }

    #[test]
    fn test_reserved() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_reserved(0);
        assert_eq!(0, packet.get_reserved());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_reserved(7);
        assert_eq!(7, packet.get_reserved());
        assert_eq!([0x0e, 0x00], packet.packet()[12..14]);
    }

    #[test]
    fn test_flags() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_flags(0);
        assert_eq!(0, packet.get_flags());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_flags(511);
        assert_eq!(511, packet.get_flags());
        assert_eq!([0x01, 0xff], packet.packet()[12..14]);
    }

    #[test]
    fn test_data_offset_and_reserved() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_data_offset(0);
        packet.set_reserved(0);
        assert_eq!(0, packet.get_data_offset());
        assert_eq!(0, packet.get_reserved());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_data_offset(15);
        packet.set_reserved(7);
        assert_eq!(15, packet.get_data_offset());
        assert_eq!(7, packet.get_reserved());
        assert_eq!([0xfe, 0x00], packet.packet()[12..14]);
    }

    #[test]
    fn test_reserved_and_flags() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_reserved(0);
        packet.set_flags(0);
        assert_eq!(0, packet.get_flags());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_reserved(7);
        packet.set_flags(511);
        assert_eq!(511, packet.get_flags());
        assert_eq!([0x0f, 0xff], packet.packet()[12..14]);
    }

    #[test]
    fn test_data_offset_and_reserved_and_flags() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.set_data_offset(0);
        packet.set_reserved(0);
        packet.set_flags(0);
        assert_eq!(0, packet.get_flags());
        assert_eq!([0x00, 0x00], packet.packet()[12..14]);
        packet.set_data_offset(15);
        packet.set_reserved(7);
        packet.set_flags(511);
        assert_eq!(511, packet.get_flags());
        assert_eq!([0xff, 0xff], packet.packet()[12..14]);
    }

    #[test]
    fn test_window_size() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.window_size = 0;
        assert_eq!(0, packet.header.window_size);
        assert_eq!([0x00, 0x00], packet.packet()[14..=15]);
        packet.header.window_size = 80;
        assert_eq!(80, packet.header.window_size);
        assert_eq!([0x00, 0x50], packet.packet()[14..=15]);
        packet.header.window_size = 443;
        assert_eq!(443, packet.header.window_size);
        assert_eq!([0x01, 0xBB], packet.packet()[14..=15]);
        packet.header.window_size = u16::MAX;
        assert_eq!(u16::MAX, packet.header.window_size);
        assert_eq!([0xFF, 0xFF], packet.packet()[14..=15]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.checksum = 0;
        assert_eq!(0, packet.header.checksum);
        assert_eq!([0x00, 0x00], packet.packet()[16..=17]);
        packet.header.checksum = 80;
        assert_eq!(80, packet.header.checksum);
        assert_eq!([0x00, 0x50], packet.packet()[16..=17]);
        packet.header.checksum = 443;
        assert_eq!(443, packet.header.checksum);
        assert_eq!([0x01, 0xBB], packet.packet()[16..=17]);
        packet.header.checksum = u16::MAX;
        assert_eq!(u16::MAX, packet.header.checksum);
        assert_eq!([0xFF, 0xFF], packet.packet()[16..=17]);
    }

    #[test]
    fn test_urgent_pointer() {
        let mut buf = [0_u8; TcpPacket::minimum_packet_size()];
        let mut packet = TcpPacket::new(&mut buf).unwrap();
        packet.header.urgent_pointer = 0;
        assert_eq!(0, packet.header.urgent_pointer);
        assert_eq!([0x00, 0x00], packet.packet()[18..=19]);
        packet.header.urgent_pointer = 80;
        assert_eq!(80, packet.header.urgent_pointer);
        assert_eq!([0x00, 0x50], packet.packet()[18..=19]);
        packet.header.urgent_pointer = 443;
        assert_eq!(443, packet.header.urgent_pointer);
        assert_eq!([0x01, 0xBB], packet.packet()[18..=19]);
        packet.header.urgent_pointer = u16::MAX;
        assert_eq!(u16::MAX, packet.header.urgent_pointer);
        assert_eq!([0xFF, 0xFF], packet.packet()[18..=19]);
    }

    #[test]
    fn test_view() {
        let buf = [
            0x01, 0xbb, 0xe5, 0xd7, 0x60, 0xb0, 0x76, 0x50, 0x8e, 0x03, 0x46, 0xa2, 0x80, 0x10,
            0x00, 0x80, 0x3e, 0xdc, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x10, 0x52, 0xf6, 0xd4,
            0xea, 0x3a, 0x2a, 0x51,
        ];
        let packet = TcpPacket::new_view(&buf).unwrap();
        assert_eq!(443, packet.header.source);
        assert_eq!(58839, packet.header.destination);
        assert_eq!(1_622_177_360, packet.header.sequence);
        assert_eq!(2_382_579_362, packet.header.acknowledgement);
        assert_eq!(8, packet.get_data_offset());
        assert_eq!(0, packet.get_reserved());
        assert_eq!(0x10, packet.get_flags());
        assert_eq!(128, packet.header.window_size);
        assert_eq!(0x3edc, packet.header.checksum);
        assert_eq!(0, packet.header.urgent_pointer);
        assert_eq!(12, packet.tcp_options_length());
        assert_eq!(
            &[0x01, 0x01, 0x08, 0x0a, 0x10, 0x52, 0xf6, 0xd4, 0xea, 0x3a, 0x2a, 0x51],
            packet.get_options_raw()
        );
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn test_new_insufficient_buffer() {
        const SIZE: usize = TcpPacket::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = TcpPacket::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("TcpPacket"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = TcpPacket::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = TcpPacket::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("TcpPacket"), SIZE, SIZE - 1),
            err
        );
    }
}
