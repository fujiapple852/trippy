use crate::error::{Error, Result};
use bytemuck::{Pod, Zeroable};
use std::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub struct UdpPacket<'a> {
    header: &'a mut UdpHeader,
    payload: &'a mut [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<UdpPacket<'a>> {
        if packet.len() >= UdpPacket::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at_mut(std::mem::size_of::<UdpHeader>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(UdpPacket { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("UdpPacket"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &'a [u8]) -> Result<UdpPacket<'a>> {
        if packet.len() >= UdpPacket::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at(std::mem::size_of::<UdpHeader>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(UdpPacket { header, payload })
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
        std::mem::size_of::<UdpHeader>()
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        self.payload.copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.header as *const _ as *const u8, self.payload.len() + std::mem::size_of::<UdpHeader>()) }
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.header.source_port = 0;
        assert_eq!(0, packet.header.source_port);
        assert_eq!([0x00, 0x00], packet.packet()[..=1]);
        packet.header.source_port = 80;
        assert_eq!(80, packet.header.source_port);
        assert_eq!([0x00, 0x50], packet.packet()[..=1]);
        packet.header.source_port = 443;
        assert_eq!(443, packet.header.source_port);
        assert_eq!([0x01, 0xBB], packet.packet()[..=1]);
        packet.header.source_port = u16::MAX;
        assert_eq!(u16::MAX, packet.header.source_port);
        assert_eq!([0xFF, 0xFF], packet.packet()[..=1]);
    }

    #[test]
    fn test_destination() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.header.destination_port = 0;
        assert_eq!(0, packet.header.destination_port);
        assert_eq!([0x00, 0x00], packet.packet()[2..=3]);
        packet.header.destination_port = 80;
        assert_eq!(80, packet.header.destination_port);
        assert_eq!([0x00, 0x50], packet.packet()[2..=3]);
        packet.header.destination_port = 443;
        assert_eq!(443, packet.header.destination_port);
        assert_eq!([0x01, 0xBB], packet.packet()[2..=3]);
        packet.header.destination_port = u16::MAX;
        assert_eq!(u16::MAX, packet.header.destination_port);
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }

    #[test]
    fn test_length() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.header.length = 0;
        assert_eq!(0, packet.header.length);
        assert_eq!([0x00, 0x00], packet.packet()[4..=5]);
        packet.header.length = 202;
        assert_eq!(202, packet.header.length);
        assert_eq!([0x00, 0xCA], packet.packet()[4..=5]);
        packet.header.length = 1025;
        assert_eq!(1025, packet.header.length);
        assert_eq!([0x04, 0x01], packet.packet()[4..=5]);
        packet.header.length = u16::MAX;
        assert_eq!(u16::MAX, packet.header.length);
        assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
    }

    #[test]
    fn test_checksum() {
        let mut buf = [0_u8; UdpPacket::minimum_packet_size()];
        let mut packet = UdpPacket::new(&mut buf).unwrap();
        packet.header.checksum = 0;
        assert_eq!(0, packet.header.checksum);
        assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
        packet.header.checksum = 202;
        assert_eq!(202, packet.header.checksum);
        assert_eq!([0x00, 0xCA], packet.packet()[6..=7]);
        packet.header.checksum = 1025;
        assert_eq!(1025, packet.header.checksum);
        assert_eq!([0x04, 0x01], packet.packet()[6..=7]);
        packet.header.checksum = u16::MAX;
        assert_eq!(u16::MAX, packet.header.checksum);
        assert_eq!([0xFF, 0xFF], packet.packet()[6..=7]);
    }

    #[test]
    fn test_view() {
        let buf = [0x68, 0xbf, 0x81, 0xb6, 0x00, 0x40, 0xac, 0xbe];
        let packet = UdpPacket::new_view(&buf).unwrap();
        assert_eq!(26815, packet.header.source_port);
        assert_eq!(33206, packet.header.destination_port);
        assert_eq!(64, packet.header.length);
        assert_eq!(44222, packet.header.checksum);
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
