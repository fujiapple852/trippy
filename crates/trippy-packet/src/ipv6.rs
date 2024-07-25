use crate::buffer::Buffer;
use crate::error::{Error, Result};
use crate::{fmt_payload, IpProtocol};
use std::fmt::{Debug, Formatter};
use std::net::Ipv6Addr;

const VERSION_OFFSET: usize = 0;
const TRAFFIC_CLASS_OFFSET: usize = 0;
const FLOW_LABEL_OFFSET: usize = 1;
const PAYLOAD_LENGTH_OFFSET: usize = 4;
const NEXT_HEADER_OFFSET: usize = 6;
const HOP_LIMIT_OFFSET: usize = 7;
const SOURCE_ADDRESS_OFFSET: usize = 8;
const DESTINATION_ADDRESS_OFFSET: usize = 24;

/// Represents an IPv6 Packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods
/// take and return data in host byte order, converting as necessary for the given architecture.
pub struct Ipv6Packet<'a> {
    buf: Buffer<'a>,
}

impl<'a> Ipv6Packet<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Self> {
        if packet.len() >= Self::minimum_packet_size() {
            Ok(Self {
                buf: Buffer::Mutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("Ipv6Packet"),
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
                String::from("Ipv6Packet"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    #[must_use]
    pub const fn minimum_packet_size() -> usize {
        40
    }

    #[must_use]
    pub fn get_version(&self) -> u8 {
        (self.buf.read(VERSION_OFFSET) & 0xf0) >> 4
    }

    #[must_use]
    pub fn get_traffic_class(&self) -> u8 {
        let b0 = ((self.buf.read(TRAFFIC_CLASS_OFFSET)) & 0xf) << 4;
        let b1 = ((self.buf.read(TRAFFIC_CLASS_OFFSET + 1)) & 0xf0) >> 4;
        b0 | b1
    }

    #[must_use]
    pub fn get_flow_label(&self) -> u32 {
        let b1 = (self.buf.read(FLOW_LABEL_OFFSET)) & 0xf;
        let b2 = self.buf.read(FLOW_LABEL_OFFSET + 1);
        let b3 = self.buf.read(FLOW_LABEL_OFFSET + 2);
        u32::from_be_bytes([0, b1, b2, b3])
    }

    #[must_use]
    pub fn get_payload_length(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(PAYLOAD_LENGTH_OFFSET))
    }

    #[must_use]
    pub fn get_next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.read(NEXT_HEADER_OFFSET))
    }

    #[must_use]
    pub fn get_hop_limit(&self) -> u8 {
        self.buf.read(HOP_LIMIT_OFFSET)
    }

    #[must_use]
    pub fn get_source_address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.buf.get_bytes(SOURCE_ADDRESS_OFFSET))
    }

    #[must_use]
    pub fn get_destination_address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.buf.get_bytes(DESTINATION_ADDRESS_OFFSET))
    }

    pub fn set_version(&mut self, val: u8) {
        *self.buf.write(VERSION_OFFSET) =
            (self.buf.read(VERSION_OFFSET) & 0xf) | ((val & 0xf) << 4);
    }

    pub fn set_traffic_class(&mut self, val: u8) {
        *self.buf.write(TRAFFIC_CLASS_OFFSET) =
            (self.buf.read(TRAFFIC_CLASS_OFFSET) & 0xf0) | ((val & 0xf0) >> 4);
        *self.buf.write(TRAFFIC_CLASS_OFFSET + 1) =
            (self.buf.read(TRAFFIC_CLASS_OFFSET + 1) & 0xf) | ((val & 0xf) << 4);
    }

    pub fn set_flow_label(&mut self, val: u32) {
        let bytes = val.to_be_bytes();
        *self.buf.write(FLOW_LABEL_OFFSET) = (self.buf.read(FLOW_LABEL_OFFSET) & 0xf0) | bytes[1];
        *self.buf.write(FLOW_LABEL_OFFSET + 1) = bytes[2];
        *self.buf.write(FLOW_LABEL_OFFSET + 2) = bytes[3];
    }

    pub fn set_payload_length(&mut self, val: u16) {
        self.buf.set_bytes(PAYLOAD_LENGTH_OFFSET, val.to_be_bytes());
    }

    pub fn set_next_header(&mut self, val: IpProtocol) {
        *self.buf.write(NEXT_HEADER_OFFSET) = val.id();
    }

    pub fn set_hop_limit(&mut self, val: u8) {
        *self.buf.write(HOP_LIMIT_OFFSET) = val;
    }

    pub fn set_source_address(&mut self, val: Ipv6Addr) {
        self.buf.set_bytes(SOURCE_ADDRESS_OFFSET, val.octets());
    }

    pub fn set_destination_address(&mut self, val: Ipv6Addr) {
        self.buf.set_bytes(DESTINATION_ADDRESS_OFFSET, val.octets());
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size();
        debug_assert!(
            vals.len() <= self.get_payload_length() as usize,
            "vals.len() <= len"
        );
        self.buf.as_slice_mut()[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = Self::minimum_packet_size();
        let end = std::cmp::min(
            Self::minimum_packet_size() + self.get_payload_length() as usize,
            self.buf.as_slice().len(),
        );
        if self.buf.as_slice().len() <= start {
            return &[];
        }
        &self.buf.as_slice()[start..end]
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
