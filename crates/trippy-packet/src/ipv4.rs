use crate::error::{Error, Result};
use bytemuck::{Pod, Zeroable};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use crate::{fmt_payload, IpProtocol};

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

pub struct Ipv4Packet<'a> {
    header: &'a mut Ipv4Header,
    payload: &'a mut [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(packet: &'a mut [u8]) -> Result<Ipv4Packet<'a>> {
        if packet.len() >= Ipv4Packet::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at_mut(std::mem::size_of::<Ipv4Header>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(Ipv4Packet { header, payload })
        } else {
            Err(Error::InsufficientPacketBuffer(
                String::from("Ipv4Packet"),
                Self::minimum_packet_size(),
                packet.len(),
            ))
        }
    }

    pub fn new_view(packet: &'a [u8]) -> Result<Ipv4Packet<'a>> {
        if packet.len() >= Ipv4Packet::minimum_packet_size() {
            let (header_bytes, payload) = packet.split_at(std::mem::size_of::<Ipv4Header>());
            let header = bytemuck::from_bytes_mut(header_bytes);
            Ok(Ipv4Packet { header, payload })
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
        std::mem::size_of::<Ipv4Header>()
    }

    #[must_use]
    pub fn get_options_raw(&self) -> &[u8] {
        let current_offset = Self::minimum_packet_size();
        let end = std::cmp::min(
            current_offset + ipv4_options_length(self),
            self.payload.len(),
        );
        &self.payload[current_offset..end]
    }

    pub fn get_options_raw_mut(&mut self) -> &mut [u8] {
        use std::cmp::min;
        let current_offset = Self::minimum_packet_size();
        let end = min(
            current_offset + ipv4_options_length(self),
            self.payload.len(),
        );
        &mut self.payload[current_offset..end]
    }

    pub fn set_payload(&mut self, vals: &[u8]) {
        let current_offset = Self::minimum_packet_size() + ipv4_options_length(self);
        self.payload[current_offset..current_offset + vals.len()].copy_from_slice(vals);
    }

    #[must_use]
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.header as *const _ as *const u8, self.payload.len() + std::mem::size_of::<Ipv4Header>()) }
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = Ipv4Packet::minimum_packet_size() + ipv4_options_length(self);
        &self.payload[start..]
    }
}

fn ipv4_options_length(ipv4: &Ipv4Packet<'_>) -> usize {
    (ipv4.header.version_ihl as usize * 4).saturating_sub(Ipv4Packet::minimum_packet_size())
}

impl Debug for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Packet")
            .field("version", &((self.header.version_ihl & 0xf0) >> 4))
            .field("header_length", &(self.header.version_ihl & 0xf))
            .field("dscp", &((self.header.dscp_ecn & 0xfc) >> 2))
            .field("ecn", &(self.header.dscp_ecn & 0x3))
            .field("total_length", &self.header.total_length)
            .field("identification", &self.header.identification)
            .field(
                "flags_and_fragment_offset",
                &self.header.flags_fragment_offset,
            )
            .field("ttl", &self.header.ttl)
            .field("protocol", &IpProtocol::from(self.header.protocol))
            .field("checksum", &self.header.checksum)
            .field("source", &Ipv4Addr::from(self.header.source))
            .field("destination", &Ipv4Addr::from(self.header.destination))
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
        packet.header.version_ihl = (packet.header.version_ihl & 0xf) | ((4 & 0xf) << 4);
        assert_eq!(4, (packet.header.version_ihl & 0xf0) >> 4);
        assert_eq!([0x40], packet.packet()[..1]);
        packet.header.version_ihl = (packet.header.version_ihl & 0xf) | ((15 & 0xf) << 4);
        assert_eq!(15, (packet.header.version_ihl & 0xf0) >> 4);
        assert_eq!([0xF0], packet.packet()[..1]);
    }

    #[test]
    fn test_header_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.version_ihl = (packet.header.version_ihl & 0xf0) | (5 & 0xf);
        assert_eq!(5, packet.header.version_ihl & 0xf);
        assert_eq!([0x05], packet.packet()[..1]);
        packet.header.version_ihl = (packet.header.version_ihl & 0xf0) | (15 & 0xf);
        assert_eq!(15, packet.header.version_ihl & 0xf);
        assert_eq!([0x0F], packet.packet()[..1]);
    }

    #[test]
    fn test_version_and_header_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.version_ihl = (packet.header.version_ihl & 0xf) | ((4 & 0xf) << 4);
        packet.header.version_ihl = (packet.header.version_ihl & 0xf0) | (5 & 0xf);
        assert_eq!(4, (packet.header.version_ihl & 0xf0) >> 4);
        assert_eq!(5, packet.header.version_ihl & 0xf);
        assert_eq!([0x45], packet.packet()[..1]);
        packet.header.version_ihl = (packet.header.version_ihl & 0xf) | ((15 & 0xf) << 4);
        packet.header.version_ihl = (packet.header.version_ihl & 0xf0) | (15 & 0xf);
        assert_eq!(15, (packet.header.version_ihl & 0xf0) >> 4);
        assert_eq!(15, packet.header.version_ihl & 0xf);
        assert_eq!([0xFF], packet.packet()[..1]);
    }

    #[test]
    fn test_dscp() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.dscp_ecn = (packet.header.dscp_ecn & 0x3) | ((63 & 0x3f) << 2);
        assert_eq!(63, (packet.header.dscp_ecn & 0xfc) >> 2);
        assert_eq!([0x00, 0xFC], packet.packet()[..2]);
    }

    #[test]
    fn test_ecn() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.dscp_ecn = (packet.header.dscp_ecn & 0xfc) | (3 & 0x3);
        assert_eq!(3, packet.header.dscp_ecn & 0x3);
        assert_eq!([0x00, 0x03], packet.packet()[..2]);
    }

    #[test]
    fn test_dscp_and_ecn() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.dscp_ecn = (packet.header.dscp_ecn & 0x3) | ((63 & 0x3f) << 2);
        packet.header.dscp_ecn = (packet.header.dscp_ecn & 0xfc) | (3 & 0x3);
        assert_eq!(63, (packet.header.dscp_ecn & 0xfc) >> 2);
        assert_eq!(3, packet.header.dscp_ecn & 0x3);
        assert_eq!([0x00, 0xFF], packet.packet()[..2]);
    }

    #[test]
    fn test_total_length() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.total_length = 84;
        assert_eq!(84, packet.header.total_length);
        assert_eq!([0x00, 0x54], packet.packet()[2..=3]);
        packet.header.total_length = 65535;
        assert_eq!(65535, packet.header.total_length);
        assert_eq!([0xFF, 0xFF], packet.packet()[2..=3]);
    }

    #[test]
    fn test_identification() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.identification = 32;
        assert_eq!(32, packet.header.identification);
        assert_eq!([0x00, 0x20], packet.packet()[4..=5]);
        packet.header.identification = u16::MAX;
        assert_eq!(u16::MAX, packet.header.identification);
        assert_eq!([0xFF, 0xFF], packet.packet()[4..=5]);
    }

    #[test]
    fn test_flags() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.flags_fragment_offset = 0;
        assert_eq!(0, packet.header.flags_fragment_offset);
        assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
        // The Don't Fragment (DF) bit set:
        packet.header.flags_fragment_offset = 0x4000;
        assert_eq!(0x4000, packet.header.flags_fragment_offset);
        assert_eq!([0x40, 0x00], packet.packet()[6..=7]);
    }

    #[test]
    fn test_time_to_live() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.ttl = 16;
        assert_eq!(16, packet.header.ttl);
        assert_eq!([0x10], packet.packet()[8..9]);
        packet.header.ttl = u8::MAX;
        assert_eq!(u8::MAX, packet.header.ttl);
        assert_eq!([0xFF], packet.packet()[8..9]);
    }

    #[test]
    fn test_protocol() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.protocol = IpProtocol::Icmp.id();
        assert_eq!(IpProtocol::Icmp, IpProtocol::from(packet.header.protocol));
        assert_eq!([0x01], packet.packet()[9..10]);
        packet.header.protocol = IpProtocol::IcmpV6.id();
        assert_eq!(IpProtocol::IcmpV6, IpProtocol::from(packet.header.protocol));
        assert_eq!([0x3A], packet.packet()[9..10]);
        packet.header.protocol = IpProtocol::Udp.id();
        assert_eq!(IpProtocol::Udp, IpProtocol::from(packet.header.protocol));
        assert_eq!([0x11], packet.packet()[9..10]);
        packet.header.protocol = IpProtocol::Tcp.id();
        assert_eq!(IpProtocol::Tcp, IpProtocol::from(packet.header.protocol));
        assert_eq!([0x06], packet.packet()[9..10]);
        packet.header.protocol = IpProtocol::Other(123).id();
        assert_eq!(IpProtocol::Other(123), IpProtocol::from(packet.header.protocol));
        assert_eq!([0x7B], packet.packet()[9..10]);
        packet.header.protocol = IpProtocol::Other(255).id();
        assert_eq!(IpProtocol::Other(255), IpProtocol::from(packet.header.protocol));
        assert_eq!([0xFF], packet.packet()[9..10]);
    }

    #[test]
    fn test_header_checksum() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.checksum = 0;
        assert_eq!(0, packet.header.checksum);
        assert_eq!([0x00, 0x00], packet.packet()[10..=11]);
        packet.header.checksum = 12345;
        assert_eq!(12345, packet.header.checksum);
        assert_eq!([0x30, 0x39], packet.packet()[10..=11]);
        packet.header.checksum = u16::MAX;
        assert_eq!(u16::MAX, packet.header.checksum);
        assert_eq!([0xFF, 0xFF], packet.packet()[10..=11]);
    }

    #[test]
    fn test_source() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.source = Ipv4Addr::LOCALHOST.octets();
        assert_eq!(Ipv4Addr::LOCALHOST, Ipv4Addr::from(packet.header.source));
        assert_eq!([0x7F, 0x00, 0x00, 0x01], packet.packet()[12..=15]);
        packet.header.source = Ipv4Addr::UNSPECIFIED.octets();
        assert_eq!(Ipv4Addr::UNSPECIFIED, Ipv4Addr::from(packet.header.source));
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[12..=15]);
        packet.header.source = Ipv4Addr::BROADCAST.octets();
        assert_eq!(Ipv4Addr::BROADCAST, Ipv4Addr::from(packet.header.source));
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[12..=15]);
        packet.header.source = Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12).octets();
        assert_eq!(Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12), Ipv4Addr::from(packet.header.source));
        assert_eq!([0xDE, 0x9A, 0x56, 0x12], packet.packet()[12..=15]);
    }

    #[test]
    fn test_destination() {
        let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
        let mut packet = Ipv4Packet::new(&mut buf).unwrap();
        packet.header.destination = Ipv4Addr::LOCALHOST.octets();
        assert_eq!(Ipv4Addr::LOCALHOST, Ipv4Addr::from(packet.header.destination));
        assert_eq!([0x7F, 0x00, 0x00, 0x01], packet.packet()[16..=19]);
        packet.header.destination = Ipv4Addr::UNSPECIFIED.octets();
        assert_eq!(Ipv4Addr::UNSPECIFIED, Ipv4Addr::from(packet.header.destination));
        assert_eq!([0x00, 0x00, 0x00, 0x00], packet.packet()[16..=19]);
        packet.header.destination = Ipv4Addr::BROADCAST.octets();
        assert_eq!(Ipv4Addr::BROADCAST, Ipv4Addr::from(packet.header.destination));
        assert_eq!([0xFF, 0xFF, 0xFF, 0xFF], packet.packet()[16..=19]);
        packet.header.destination = Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12).octets();
        assert_eq!(Ipv4Addr::new(0xDE, 0x9A, 0x56, 0x12), Ipv4Addr::from(packet.header.destination));
        assert_eq!([0xDE, 0x9A, 0x56, 0x12], packet.packet()[16..=19]);
    }

    #[test]
    fn test_view() {
        let buf = [
            0x45, 0x00, 0x00, 0x54, 0xa2, 0x71, 0x00, 0x00, 0x15, 0x11, 0x9a, 0xee, 0x7f, 0x00,
            0x00, 0x01, 0xde, 0x9a, 0x56, 0x12,
        ];
        let packet = Ipv4Packet::new_view(&buf).unwrap();
        assert_eq!(4, (packet.header.version_ihl & 0xf0) >> 4);
        assert_eq!(5, packet.header.version_ihl & 0xf);
        assert_eq!(0, (packet.header.dscp_ecn & 0xfc) >> 2);
        assert_eq!(0, packet.header.dscp_ecn & 0x3);
        assert_eq!(84, packet.header.total_length);
        assert_eq!(41585, packet.header.identification);
        assert_eq!(0, packet.header.flags_fragment_offset);
        assert_eq!(21, packet.header.ttl);
        assert_eq!(IpProtocol::Udp, IpProtocol::from(packet.header.protocol));
        assert_eq!(39662, packet.header.checksum);
        assert_eq!(Ipv4Addr::new(0x7F, 0x00, 0x00, 0x01), Ipv4Addr::from(packet.header.source));
        assert_eq!(Ipv4Addr::new(0xde, 0x9a, 0x56, 0x12), Ipv4Addr::from(packet.header.destination));
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
