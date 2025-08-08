use crate::buffer::Buffer;
use crate::error::{Error, Result};
use crate::{fmt_payload, IpProtocol};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;

const VERSION_OFFSET: usize = 0;
const IHL_OFFSET: usize = 0;
const DSCP_OFFSET: usize = 1;
const ECN_OFFSET: usize = 1;
const TOTAL_LENGTH_OFFSET: usize = 2;
const IDENTIFICATION_OFFSET: usize = 4;
const FLAGS_AND_FRAGMENT_OFFSET_OFFSET: usize = 6;
const TIME_TO_LIVE_OFFSET: usize = 8;
const PROTOCOL_OFFSET: usize = 9;
const CHECKSUM_OFFSET: usize = 10;
const SOURCE_OFFSET: usize = 12;
const DESTINATION_OFFSET: usize = 16;

/// Represents an IPv4 Packet.
///
/// The internal representation is held in network byte order (big-endian) and all accessor methods
/// take and return data in host byte order, converting as necessary for the given architecture.
pub struct Ipv4Packet<'a> {
    buf: Buffer<'a>,
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Self> {
        if packet.len() >= Self::minimum_packet_size() {
            Ok(Self {
                buf: Buffer::Mutable(packet),
            })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("Ipv4Packet"),
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
                String::from("Ipv4Packet"),
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
    pub fn get_version(&self) -> u8 {
        (self.buf.read(VERSION_OFFSET) & 0xf0) >> 4
    }

    #[must_use]
    pub fn get_header_length(&self) -> u8 {
        self.buf.read(IHL_OFFSET) & 0xf
    }

    #[must_use]
    pub fn get_dscp(&self) -> u8 {
        (self.buf.read(DSCP_OFFSET) & 0xfc) >> 2
    }

    #[must_use]
    pub fn get_ecn(&self) -> u8 {
        self.buf.read(ECN_OFFSET) & 0x3
    }

    #[must_use]
    pub fn get_tos(&self) -> u8 {
        (self.get_dscp() << 2) | self.get_ecn()
    }

    #[must_use]
    pub fn get_total_length(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(TOTAL_LENGTH_OFFSET))
    }

    #[must_use]
    pub fn get_identification(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(IDENTIFICATION_OFFSET))
    }

    #[must_use]
    pub fn get_flags_and_fragment_offset(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(FLAGS_AND_FRAGMENT_OFFSET_OFFSET))
    }

    #[must_use]
    pub fn get_ttl(&self) -> u8 {
        self.buf.read(TIME_TO_LIVE_OFFSET)
    }

    #[must_use]
    pub fn get_protocol(&self) -> IpProtocol {
        IpProtocol::from(self.buf.read(PROTOCOL_OFFSET))
    }

    #[must_use]
    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
    }

    #[must_use]
    pub fn get_source(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.buf.get_bytes(SOURCE_OFFSET))
    }

    #[must_use]
    pub fn get_destination(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.buf.get_bytes(DESTINATION_OFFSET))
    }

    #[must_use]
    pub fn get_options_raw(&self) -> &[u8] {
        let current_offset = Self::minimum_packet_size();
        let end = std::cmp::min(
            current_offset + ipv4_options_length(self),
            self.buf.as_slice().len(),
        );
        &self.buf.as_slice()[current_offset..end]
    }

    pub fn set_version(&mut self, val: u8) {
        *self.buf.write(VERSION_OFFSET) =
            (self.buf.read(VERSION_OFFSET) & 0xf) | ((val & 0xf) << 4);
    }

    pub fn set_header_length(&mut self, val: u8) {
        *self.buf.write(IHL_OFFSET) = (self.buf.read(IHL_OFFSET) & 0xf0) | (val & 0xf);
    }

    pub fn set_dscp(&mut self, val: u8) {
        *self.buf.write(DSCP_OFFSET) = (self.buf.read(DSCP_OFFSET) & 0x3) | ((val & 0x3f) << 2);
    }

    pub fn set_ecn(&mut self, val: u8) {
        *self.buf.write(ECN_OFFSET) = (self.buf.read(ECN_OFFSET) & 0xfc) | (val & 0x3);
    }

    pub fn set_tos(&mut self, val: u8) {
        self.set_dscp((val & 0xfc) >> 2);
        self.set_ecn(val & 0x3);
    }

    pub fn set_total_length(&mut self, val: u16) {
        self.buf.set_bytes(TOTAL_LENGTH_OFFSET, val.to_be_bytes());
    }

    pub fn set_identification(&mut self, val: u16) {
        self.buf.set_bytes(IDENTIFICATION_OFFSET, val.to_be_bytes());
    }

    pub fn set_flags_and_fragment_offset(&mut self, val: u16) {
        self.buf
            .set_bytes(FLAGS_AND_FRAGMENT_OFFSET_OFFSET, val.to_be_bytes());
    }

    pub fn set_ttl(&mut self, val: u8) {
        *self.buf.write(TIME_TO_LIVE_OFFSET) = val;
    }

    pub fn set_protocol(&mut self, val: IpProtocol) {
        *self.buf.write(PROTOCOL_OFFSET) = val.id();
    }

    pub fn set_checksum(&mut self, val: u16) {
        self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
    }

    pub fn set_source(&mut self, val: Ipv4Addr) {
        self.buf.set_bytes(SOURCE_OFFSET, val.octets());
    }

    pub fn set_destination(&mut self, val: Ipv4Addr) {
        self.buf.set_bytes(DESTINATION_OFFSET, val.octets());
    }

    pub fn get_options_raw_mut(&mut self) -> &mut [u8] {
        use std::cmp::min;
        let current_offset = Self::minimum_packet_size();
        let end = min(
            current_offset + ipv4_options_length(self),
            self.buf.as_slice().len(),
        );
        &mut self.buf.as_slice_mut()[current_offset..end]
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size() + ipv4_options_length(self);
        self.buf.as_slice_mut()[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = Ipv4Packet::minimum_packet_size() + ipv4_options_length(self);
        &self.buf.as_slice()[start..]
    }
}

fn ipv4_options_length(ipv4: &Ipv4Packet<'_>) -> usize {
    (ipv4.get_header_length() as usize * 4).saturating_sub(Ipv4Packet::minimum_packet_size())
}

impl Debug for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Packet")
            .field("version", &self.get_version())
            .field("header_length", &self.get_header_length())
            .field("dscp", &self.get_dscp())
            .field("ecn", &self.get_ecn())
            .field("total_length", &self.get_total_length())
            .field("identification", &self.get_identification())
            .field(
                "flags_and_fragment_offset",
                &self.get_flags_and_fragment_offset(),
            )
            .field("ttl", &self.get_ttl())
            .field("protocol", &self.get_protocol())
            .field("checksum", &self.get_checksum())
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            .field("options_raw", &self.get_options_raw())
            .field("payload", &fmt_payload(self.payload()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_version(4);
        assert_eq!(4, packet.get_version());
        assert_eq!([0x40], packet.packet()[..1]);
        packet.set_version(15);
        assert_eq!(15, packet.get_version());
        assert_eq!([0xF0], packet.packet()[..1]);
    }

    #[test]
    fn test_header_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_header_length(5);
        assert_eq!(5, packet.get_header_length());
        assert_eq!([0x05], packet.packet()[..1]);
        packet.set_header_length(15);
        assert_eq!(15, packet.get_header_length());
        assert_eq!([0x0F], packet.packet()[..1]);
    }

    #[test]
    fn test_version_and_header_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_version(4);
        packet.set_header_length(5);
        assert_eq!(4, packet.get_version());
        assert_eq!(5, packet.get_header_length());
        assert_eq!([0x45], packet.packet()[..1]);
        packet.set_version(15);
        packet.set_header_length(15);
        assert_eq!(15, packet.get_version());
        assert_eq!(15, packet.get_header_length());
        assert_eq!([0xFF], packet.packet()[..1]);
    }

    #[test]
    fn test_dscp() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_dscp(63);
        assert_eq!(63, packet.get_dscp());
        assert_eq!([0xFC], packet.packet()[1..2]);
    }

    #[test]
    fn test_ecn() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_ecn(3);
        assert_eq!(3, packet.get_ecn());
        assert_eq!([0x03], packet.packet()[1..2]);
    }

    #[test]
    fn test_dscp_and_ecn() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_dscp(63);
        packet.set_ecn(3);
        assert_eq!(63, packet.get_dscp());
        assert_eq!(3, packet.get_ecn());
        assert_eq!([0xFF], packet.packet()[1..2]);
    }

    #[test]
    fn test_tos() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_tos(224);
        assert_eq!(224, packet.get_tos());
        assert_eq!(56, packet.get_dscp());
        assert_eq!(0, packet.get_ecn());
        assert_eq!([0xE0], packet.packet()[1..2]);
        packet.set_tos(255);
        assert_eq!(255, packet.get_tos());
        assert_eq!(63, packet.get_dscp());
        assert_eq!(3, packet.get_ecn());
        assert_eq!([0xFF], packet.packet()[1..2]);
    }

    #[test]
    fn test_total_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_total_length(84);
        assert_eq!(84, packet.get_total_length());
        assert_eq!([0x00, 0x54], packet.packet()[2..=3]);
        packet.set_total_length(65535);
        assert_eq!(65535, packet.get_total_length());
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }

    #[test]
    fn test_identification() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_identification(32);
        assert_eq!(32, packet.get_identification());
        assert_eq!([0x00, 0x20], packet.packet()[4..=5]);
        packet.set_identification(u16::MAX);
        assert_eq!(u16::MAX, packet.get_identification());
        assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
    }

    #[test]
    fn test_flags() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_flags_and_fragment_offset(0);
        assert_eq!(0, packet.get_flags_and_fragment_offset());
        assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
        // The Don't Fragment (DF) bit set:
        packet.set_flags_and_fragment_offset(0x4000);
        assert_eq!(0x4000, packet.get_flags_and_fragment_offset());
        assert_eq!([0x40, 0x00], packet.packet()[6..=7]);
    }

    #[test]
    fn test_time_to_live() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_ttl(16);
        assert_eq!(16, packet.get_ttl());
        assert_eq!([0x10], packet.packet()[8..9]);
        packet.set_ttl(u8::MAX);
        assert_eq!(u8::MAX, packet.get_ttl());
        assert_eq!([0xFF], packet.packet()[8..9]);
    }

    #[test]
    fn test_protocol() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_protocol(IpProtocol::Icmp);
        assert_eq!(IpProtocol::Icmp, packet.get_protocol());
        assert_eq!([0x01], packet.packet()[9..10]);
        packet.set_protocol(IpProtocol::IcmpV6);
        assert_eq!(IpProtocol::IcmpV6, packet.get_protocol());
        assert_eq!([0x3A], packet.packet()[9..10]);
        packet.set_protocol(IpProtocol::Udp);
        assert_eq!(IpProtocol::Udp, packet.get_protocol());
        assert_eq!([0x11], packet.packet()[9..10]);
        packet.set_protocol(IpProtocol::Tcp);
        assert_eq!(IpProtocol::Tcp, packet.get_protocol());
        assert_eq!([0x06], packet.packet()[9..10]);
        packet.set_protocol(IpProtocol::Other(123));
        assert_eq!(IpProtocol::Other(123), packet.get_protocol());
        assert_eq!([0x7B], packet.packet()[9..10]);
        packet.set_protocol(IpProtocol::Other(255));
        assert_eq!(IpProtocol::Other(255), packet.get_protocol());
        assert_eq!([0xFF], packet.packet()[9..10]);
    }

    #[test]
    fn test_header_checksum() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_checksum(0);
        assert_eq!(0, packet.get_checksum());
        assert_eq!([0x00, 0x00], packet.packet()[10..=11]);
        packet.set_checksum(12345);
        assert_eq!(12345, packet.get_checksum());
        assert_eq!([0x30, 0x39], packet.packet()[10..=11]);
        packet.set_checksum(u16::MAX);
        assert_eq!(u16::MAX, packet.get_checksum());
        assert_eq!([0x0FF, 0xFF], packet.packet()[10..=11]);
    }

    #[test]
    fn test_source() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_source(Ipv4Addr::LOCALHOST);
        assert_eq!(Ipv4Addr::LOCALHOST, packet.get_source());
        assert_eq!([0x07F, 0x00, 0x00, 0x01], packet.packet()[12..=15]);
        packet.set_source(Ipv4Addr::UNSPECIFIED);
        assert_eq!(Ipv4Addr::UNSPECIFIED, packet.get_source());
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[12..=15]);
        packet.set_source(Ipv4Addr::BROADCAST);
        assert_eq!(Ipv4Addr::BROADCAST, packet.get_source());
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[12..=15]);
        packet.set_source(Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12));
        assert_eq!(Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12), packet.get_source());
        assert_eq!([0xDE, 0x9A, 0x56, 0x12], packet.packet()[12..=15]);
    }

    #[test]
    fn test_destination() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.set_destination(Ipv4Addr::LOCALHOST);
        assert_eq!(Ipv4Addr::LOCALHOST, packet.get_destination());
        assert_eq!([0x07F, 0x00, 0x00, 0x01], packet.packet()[16..=19]);
        packet.set_destination(Ipv4Addr::UNSPECIFIED);
        assert_eq!(Ipv4Addr::UNSPECIFIED, packet.get_destination());
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[16..=19]);
        packet.set_destination(Ipv4Addr::BROADCAST);
        assert_eq!(Ipv4Addr::BROADCAST, packet.get_destination());
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[16..=19]);
        packet.set_destination(Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12));
        assert_eq!(
            Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12),
            packet.get_destination()
        );
        assert_eq!([0xDE, 0x9A, 0x56, 0x12], packet.packet()[16..=19]);
    }

    #[test]
    fn test_view() {
        let buf = [
            0x45, 0x00, 0x00, 0x54, 0xa2, 0x71, 0x00, 0x00, 0x15, 0x11, 0x9a, 0xee, 0x7f, 0x00,
            0x00, 0x01, 0xde, 0x9a, 0x56, 0x12,
        ];
        let packet = Ipv4Packet::new_view(&buf).unwrap();
        assert_eq!(4, packet.get_version());
        assert_eq!(5, packet.get_header_length());
        assert_eq!(0, packet.get_dscp());
        assert_eq!(0, packet.get_ecn());
        assert_eq!(84, packet.get_total_length());
        assert_eq!(41585, packet.get_identification());
        assert_eq!(0, packet.get_flags_and_fragment_offset());
        assert_eq!(21, packet.get_ttl());
        assert_eq!(IpProtocol::Udp, packet.get_protocol());
        assert_eq!(39662, packet.get_checksum());
        assert_eq!(Ipv4Addr::LOCALHOST, packet.get_source());
        assert_eq!(
            Ipv4Addr::new(0xde, 0x9a, 0x56, 0x12),
            packet.get_destination()
        );
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn test_new_insufficient_buffer() {
        const SIZE: usize = Ipv4Packet::minimum_packet_size();
        let mut buf = [0_u8; SIZE - 1];
        let err = Ipv4Packet::new(&mut buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("Ipv4Packet"), SIZE, SIZE - 1),
            err
        );
    }

    #[test]
    fn test_new_view_insufficient_buffer() {
        const SIZE: usize = Ipv4Packet::minimum_packet_size();
        let buf = [0_u8; SIZE - 1];
        let err = Ipv4Packet::new_view(&buf).unwrap_err();
        assert_eq!(
            Error::InsufficientPacketBuffer(String::from("Ipv4Packet"), SIZE, SIZE - 1),
            err
        );
    }
}
