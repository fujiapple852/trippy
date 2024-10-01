use crate::error::{Error, Result};
use bytemuck::{Pod, Zeroable};
use std::fmt::{Debug, Formatter};
use std::net::Ipv6Addr;
use crate::{fmt_payload, IpProtocol};

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct Ipv6Header {
    pub version_traffic_class_flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
}

pub struct Ipv6Packet<'a> {
    header: &'a mut Ipv6Header,
    payload: &'a mut [u8],
}

impl<'a> Ipv6Packet<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Ipv6Packet<'a>> {
        if packet.len() >= Ipv6Packet::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at_mut(std::mem::size_of::<Ipv6Header>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(Ipv6Packet { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("Ipv6Packet"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &'a [u8]) -> Result<Ipv6Packet<'a>> {
        if packet.len() >= Ipv6Packet::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at(std::mem::size_of::<Ipv6Header>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(Ipv6Packet { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("Ipv6Packet"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        std::mem::size_of::<Ipv6Header>()
    }

    #[must_use]
    pub fn get_version(&self) -> u8 {
        (self.header.version_traffic_class_flow_label >> 28) as u8
    }

    #[must_use]
    pub fn get_traffic_class(&self) -> u8 {
        ((self.header.version_traffic_class_flow_label >> 20) & 0xff) as u8
    }

    #[must_use]
    pub fn get_flow_label(&self) -> u32 {
        self.header.version_traffic_class_flow_label & 0x000fffff
    }

    #[must_use]
    pub fn get_payload_length(&self) -> u16 {
        self.header.payload_length
    }

    #[must_use]
    pub fn get_next_header(&self) -> IpProtocol {
        IpProtocol::from(self.header.next_header)
    }

    #[must_use]
    pub fn get_hop_limit(&self) -> u8 {
        self.header.hop_limit
    }

    #[must_use]
    pub fn get_source_address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.header.source_address)
    }

    #[must_use]
    pub fn get_destination_address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.header.destination_address)
    }

    pub fn set_version(&mut self, val: u8) {
        self.header.version_traffic_class_flow_label =
            (self.header.version_traffic_class_flow_label & 0x0fffffff) | ((val as u32) << 28);
    }

    pub fn set_traffic_class(&mut self, val: u8) {
        self.header.version_traffic_class_flow_label =
            (self.header.version_traffic_class_flow_label & 0xf00fffff) | ((val as u32) << 20);
    }

    pub fn set_flow_label(&mut self, val: u32) {
        self.header.version_traffic_class_flow_label =
            (self.header.version_traffic_class_flow_label & 0xfff00000) | (val & 0x000fffff);
    }

    pub fn set_payload_length(&mut self, val: u16) {
        self.header.payload_length = val;
    }

    pub fn set_next_header(&mut self, val: IpProtocol) {
        self.header.next_header = val.id();
    }

    pub fn set_hop_limit(&mut self, val: u8) {
        self.header.hop_limit = val;
    }

    pub fn set_source_address(&mut self, val: Ipv6Addr) {
        self.header.source_address = val.octets();
    }

    pub fn set_destination_address(&mut self, val: Ipv6Addr) {
        self.header.destination_address = val.octets();
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size();
        self.payload[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.header as *const _ as *const u8, self.payload.len() + std::mem::size_of::<Ipv6Header>()) }
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = Ipv6Packet::minimum_packet_size();
        &self.payload[start..]
    }
}

impl Debug for Ipv6Packet<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv6Packet")
            .field("version", &self.get_version())
            .field("traffic_class", &self.get_traffic_class())
            .field("flow_label", &self.get_flow_label())
            .field("payload_length", &self.get_payload_length())
            .field("next_header", &self.get_next_header())
            .field("hop_limit", &self.get_hop_limit())
            .field("source_address", &self.get_source_address())
            .field("destination_address", &self.get_destination_address())
            .field("payload", &fmt_payload(self.payload()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_version() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_version(5);
        assert_eq!(5, packet.get_version());
        assert_eq!([0x50], packet.packet()[..1]);
        packet.set_version(15);
        assert_eq!(15, packet.get_version());
        assert_eq!([0xF0], packet.packet()[..1]);
    }

    #[test]
    fn test_traffic_class() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_traffic_class(0);
        assert_eq!(0, packet.get_traffic_class());
        assert_eq!([0x00, 0x00], packet.packet()[..2]);
        packet.set_traffic_class(63);
        assert_eq!(63, packet.get_traffic_class());
        assert_eq!([0x03, 0xF0], packet.packet()[..2]);
    }

    #[test]
    fn test_version_and_traffic_class() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_version(15);
        packet.set_traffic_class(63);
        assert_eq!(15, packet.get_version());
        assert_eq!(63, packet.get_traffic_class());
        assert_eq!([0xF3, 0xF0], packet.packet()[..2]);
    }

    #[test]
    fn test_flow_label() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_flow_label(0);
        assert_eq!(0, packet.get_flow_label());
        assert_eq!([0x00, 0x00, 0x00], packet.packet()[1..=3]);
        packet.set_flow_label(500_000);
        assert_eq!(500_000, packet.get_flow_label());
        assert_eq!([0x07, 0xA1, 0x20], packet.packet()[1..=3]);
        packet.set_flow_label(1_048_575);
        assert_eq!(1_048_575, packet.get_flow_label());
        assert_eq!([0x0F, 0xFF, 0xFF], packet.packet()[1..=3]);
    }

    #[test]
    fn test_payload_length() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_payload_length(0);
        assert_eq!(0, packet.get_payload_length());
        assert_eq!([0x00, 0x00], packet.packet()[4..=5]);
        packet.set_payload_length(120);
        assert_eq!(120, packet.get_payload_length());
        assert_eq!([0x00, 0x78], packet.packet()[4..=5]);
        packet.set_payload_length(65535);
        assert_eq!(65535, packet.get_payload_length());
        assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
    }

    #[test]
    fn test_next_header() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_next_header(IpProtocol::Icmp);
        assert_eq!(IpProtocol::Icmp, packet.get_next_header());
        assert_eq!([0x01], packet.packet()[6..7]);
        packet.set_next_header(IpProtocol::IcmpV6);
        assert_eq!(IpProtocol::IcmpV6, packet.get_next_header());
        assert_eq!([0x3A], packet.packet()[6..7]);
        packet.set_next_header(IpProtocol::Udp);
        assert_eq!(IpProtocol::Udp, packet.get_next_header());
        assert_eq!([0x11], packet.packet()[6..7]);
        packet.set_next_header(IpProtocol::Tcp);
        assert_eq!(IpProtocol::Tcp, packet.get_next_header());
        assert_eq!([0x06], packet.packet()[6..7]);
        packet.set_next_header(IpProtocol::Other(123));
        assert_eq!(IpProtocol::Other(123), packet.get_next_header());
        assert_eq!([0x7B], packet.packet()[6..7]);
        packet.set_next_header(IpProtocol::Other(255));
        assert_eq!(IpProtocol::Other(255), packet.get_next_header());
        assert_eq!([0xFF], packet.packet()[6..7]);
    }

    #[test]
    fn test_hop_limit() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_hop_limit(0);
        assert_eq!(0, packet.get_hop_limit());
        assert_eq!([0x00], packet.packet()[7..8]);
        packet.set_hop_limit(120);
        assert_eq!(120, packet.get_hop_limit());
        assert_eq!([0x78], packet.packet()[7..8]);
        packet.set_hop_limit(255);
        assert_eq!(255, packet.get_hop_limit());
        assert_eq!([0xFF], packet.packet()[7..8]);
    }

    #[test]
    fn test_source_address() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_source_address(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, packet.get_source_address());
        assert_eq!(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ],
            packet.packet()[8..=23]
        );
        packet.set_source_address(Ipv6Addr::from_str("2404:6800:4005:812::200e").unwrap());
        assert_eq!(
            Ipv6Addr::from_str("2404:6800:4005:812::200e").unwrap(),
            packet.get_source_address()
        );
        assert_eq!(
            [
                0x24, 0x04, 0x68, 0x00, 0x40, 0x05, 0x08, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x0E
            ],
            packet.packet()[8..=23]
        );
    }

    #[test]
    fn test_destination_address() {
        let mut buf = [0_u8; Ipv6Packet::minimum_packet_size()];
        let mut packet = Ipv6Packet::new(&mut buf).unwrap();
        packet.set_destination_address(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, packet.get_destination_address());
        assert_eq!(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ],
            packet.packet()[24..=39]
        );
        packet.set_destination_address(Ipv6Addr::from_str("2404:6800:4005:812::200e").unwrap());
        assert_eq!(
            Ipv6Addr::from_str("2404:6800:4005:812::200e").unwrap(),
            packet.get_destination_address()
        );
        assert_eq!(
            [
                0x24, 0x04, 0x68, 0x00, 0x40, 0x05, 0x08, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x0E
            ],
            packet.packet()[24..=39]
        );
    }

    #[test]
    fn test_view() {
        let buf = [
            0x60, 0x06, 0x05, 0x00, 0x00, 0x20, 0x06, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1c, 0x8d, 0x7d, 0x69, 0xd0, 0xb6, 0x81, 0x82, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x03, 0xf6, 0x76, 0x01, 0x6c, 0x3f,
        ];
        let packet = Ipv6Packet::new_view(&buf).unwrap();
        assert_eq!(6, packet.get_version());
        assert_eq!(0, packet.get_traffic_class());
        assert_eq!(394_496, packet.get_flow_label());
        assert_eq!(32, packet.get_payload_length());
        assert_eq!(IpProtocol::Tcp, packet.get_next_header());
        assert_eq!(64, packet.get_hop_limit());
        assert_eq!(
            Ipv6Addr::from_str("fe80::1c8d:7d69:d0b6:8182").unwrap(),
            packet.get_source_address()
        );
        assert_eq!(
            Ipv6Addr::from_str("fe80::811:3f6:7601:6c3f").unwrap(),
            packet.get_destination_address()
        );
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn test_new_insufficient_buffer() {
        const SIZE: usize = Ipv6Packet::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = Ipv6Packet::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("Ipv6Packet"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = Ipv6Packet::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = Ipv6Packet::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("Ipv6Packet"), SIZE, SIZE - 1),
            err
        );
    }
}
