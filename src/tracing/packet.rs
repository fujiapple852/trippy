/// A byte buffer that holds a mutable or immutable byte slice.
#[derive(Debug)]
pub enum Buffer<'a> {
    Immutable(&'a [u8]),
    Mutable(&'a mut [u8]),
}

impl<'a> Buffer<'a> {
    fn as_slice(&self) -> &[u8] {
        match &self {
            Buffer::Immutable(packet) => packet,
            Buffer::Mutable(packet) => packet,
        }
    }

    /// Get two bytes from the packet at a given byte offset.
    fn get_bytes_two(&self, offset: usize) -> [u8; 2] {
        [self.read(offset), self.read(offset + 1)]
    }

    /// Set two bytes in the packet at a given offset.
    pub fn set_bytes_two(&mut self, offset: usize, bytes: [u8; 2]) {
        *self.write(offset) = bytes[0];
        *self.write(offset + 1) = bytes[1];
    }

    pub fn read(&self, offset: usize) -> u8 {
        match &self {
            Buffer::Immutable(packet) => packet[offset],
            Buffer::Mutable(packet) => packet[offset],
        }
    }

    pub fn write(&mut self, offset: usize) -> &mut u8 {
        match self {
            Buffer::Immutable(_) => panic!("write operation called on readonly buffer"),
            Buffer::Mutable(packet) => &mut packet[offset],
        }
    }

    fn as_slice_mut(&mut self) -> &mut [u8] {
        match self {
            Buffer::Immutable(_) => panic!("write operation called on readonly buffer"),
            Buffer::Mutable(packet) => *packet,
        }
    }
}

pub mod ipv4 {
    use crate::tracing::packet::{fmt_payload, Buffer};
    use std::fmt::{Debug, Formatter};
    use std::net::Ipv4Addr;

    const VERSION_OFFSET: usize = 0;
    const IHL_OFFSET: usize = 0;
    const DSCP_OFFSET: usize = 1;
    const ECN_OFFSET: usize = 1;
    const TOTAL_LENGTH_OFFSET: usize = 2;
    const IDENTIFICATION_OFFSET: usize = 4;
    const FLAGS_OFFSET: usize = 6;
    const FRAGMENT_OFFSET_OFFSET: usize = 6;
    const TIME_TO_LIVE_OFFSET: usize = 8;
    const PROTOCOL_OFFSET: usize = 9;
    const CHECKSUM_OFFSET: usize = 10;
    const SOURCE_OFFSET: usize = 12;
    const DESTINATION_OFFSET: usize = 16;

    ///
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum IpProtocol {
        Icmp,
        IcmpV6,
        Udp,
        Tcp,
        Other(u8),
    }

    impl IpProtocol {
        pub fn id(self) -> u8 {
            match self {
                Self::Icmp => 1,
                Self::IcmpV6 => 58,
                Self::Udp => 17,
                Self::Tcp => 6,
                Self::Other(id) => id,
            }
        }

        #[must_use]
        pub fn new(value: u8) -> Self {
            Self::Other(value)
        }
    }

    /// Represents an IPv4 Packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct Ipv4Packet<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> Ipv4Packet<'a> {
        pub fn new(packet: &mut [u8]) -> Option<Ipv4Packet<'_>> {
            if packet.len() >= Ipv4Packet::minimum_packet_size() {
                Some(Ipv4Packet {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &[u8]) -> Option<Ipv4Packet<'_>> {
            if packet.len() >= Ipv4Packet::minimum_packet_size() {
                Some(Ipv4Packet {
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
        pub fn get_total_length(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(TOTAL_LENGTH_OFFSET))
        }

        #[must_use]
        pub fn get_identification(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(IDENTIFICATION_OFFSET))
        }

        #[must_use]
        pub fn get_flags(&self) -> u8 {
            (self.buf.read(FLAGS_OFFSET) & 0xe0) >> 5
        }

        #[must_use]
        pub fn get_fragment_offset(&self) -> u16 {
            u16::from_be_bytes([
                self.buf.read(FRAGMENT_OFFSET_OFFSET) & 0x1f,
                self.buf.read(FRAGMENT_OFFSET_OFFSET + 1),
            ])
        }

        #[must_use]
        pub fn get_ttl(&self) -> u8 {
            self.buf.read(TIME_TO_LIVE_OFFSET)
        }

        #[must_use]
        pub fn get_protocol(&self) -> IpProtocol {
            match self.buf.read(PROTOCOL_OFFSET) {
                1 => IpProtocol::Icmp,
                58 => IpProtocol::IcmpV6,
                17 => IpProtocol::Udp,
                6 => IpProtocol::Tcp,
                id => IpProtocol::Other(id),
            }
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        #[must_use]
        pub fn get_source(&self) -> Ipv4Addr {
            Ipv4Addr::new(
                self.buf.read(SOURCE_OFFSET),
                self.buf.read(SOURCE_OFFSET + 1),
                self.buf.read(SOURCE_OFFSET + 2),
                self.buf.read(SOURCE_OFFSET + 3),
            )
        }

        #[must_use]
        pub fn get_destination(&self) -> Ipv4Addr {
            Ipv4Addr::new(
                self.buf.read(DESTINATION_OFFSET),
                self.buf.read(DESTINATION_OFFSET + 1),
                self.buf.read(DESTINATION_OFFSET + 2),
                self.buf.read(DESTINATION_OFFSET + 3),
            )
        }

        #[must_use]
        pub fn get_options_raw(&self) -> &[u8] {
            use std::cmp::min;
            let current_offset = Self::minimum_packet_size();
            let end = min(
                current_offset + ipv4_options_length(self),
                self.buf.as_slice().len(),
            );
            &self.buf.as_slice()[current_offset..end]
        }

        // pub fn get_options(&self) -> Vec<Ipv4Option> {
        //     use std::cmp::min;
        //     let _self = self;
        //     let current_offset = Ipv4Packet::minimum_packet_size();
        //     let end = min(
        //         current_offset + ipv4_options_length(&_self.to_immutable()),
        //         _self.packet.len(),
        //     );
        //     Ipv4OptionIterable {
        //         buf: &_self.packet[current_offset..end],
        //     }
        //         .map(|packet| packet.from_packet())
        //         .collect::<Vec<_>>()
        // }

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

        pub fn set_total_length(&mut self, val: u16) {
            self.buf
                .set_bytes_two(TOTAL_LENGTH_OFFSET, val.to_be_bytes());
        }

        pub fn set_identification(&mut self, val: u16) {
            self.buf
                .set_bytes_two(IDENTIFICATION_OFFSET, val.to_be_bytes());
        }

        pub fn set_flags(&mut self, val: u8) {
            *self.buf.write(FLAGS_OFFSET) =
                (self.buf.read(FLAGS_OFFSET) & 0x1f) | ((val & 0x7) << 5);
        }

        pub fn set_fragment_offset(&mut self, val: u16) {
            let bytes = val.to_be_bytes();
            let flags = self.buf.read(FRAGMENT_OFFSET_OFFSET) & 0xe0;
            *self.buf.write(FRAGMENT_OFFSET_OFFSET) = flags | (bytes[0] & 0x1f);
            *self.buf.write(FRAGMENT_OFFSET_OFFSET + 1) = bytes[1];
        }

        pub fn set_ttl(&mut self, val: u8) {
            *self.buf.write(TIME_TO_LIVE_OFFSET) = val;
        }

        pub fn set_protocol(&mut self, val: IpProtocol) {
            *self.buf.write(PROTOCOL_OFFSET) = val.id();
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        pub fn set_source(&mut self, val: Ipv4Addr) {
            let vals = val.octets();
            *self.buf.write(SOURCE_OFFSET) = vals[0];
            *self.buf.write(SOURCE_OFFSET + 1) = vals[1];
            *self.buf.write(SOURCE_OFFSET + 2) = vals[2];
            *self.buf.write(SOURCE_OFFSET + 3) = vals[3];
        }

        pub fn set_destination(&mut self, val: Ipv4Addr) {
            let vals = val.octets();
            *self.buf.write(DESTINATION_OFFSET) = vals[0];
            *self.buf.write(DESTINATION_OFFSET + 1) = vals[1];
            *self.buf.write(DESTINATION_OFFSET + 2) = vals[2];
            *self.buf.write(DESTINATION_OFFSET + 3) = vals[3];
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

        // pub fn set_options(&mut self, vals: &[Ipv4Option]) {
        //     let _self = self;
        //     let mut current_offset = Ipv4Packet::minimum_packet_size();
        //     let end = current_offset + ipv4_options_length(&_self.to_immutable());
        //     for val in vals.into_iter() {
        //         let mut packet =
        //             MutableIpv4OptionPacket::new(&mut _self.packet[current_offset..]).unwrap();
        //         packet.populate(val);
        //         current_offset += packet.packet_size();
        //         if !(current_offset <= end) {
        //             ::core::panicking::panic("assertion failed: current_offset <= end")
        //         };
        //     }
        // }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size() + ipv4_options_length(self);
            debug_assert!(
                (vals.len() <= ipv4_payload_length(self)),
                "vals.len() <= len"
            );
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            let start = Self::minimum_packet_size() + ipv4_options_length(self);
            let end = std::cmp::min(
                Self::minimum_packet_size() + ipv4_options_length(self) + ipv4_payload_length(self),
                self.buf.as_slice().len(),
            );
            if self.buf.as_slice().len() <= start {
                return &[];
            }
            &self.buf.as_slice()[start..end]
        }
    }

    fn ipv4_options_length(ipv4: &Ipv4Packet<'_>) -> usize {
        (ipv4.get_header_length() as usize * 4).saturating_sub(Ipv4Packet::minimum_packet_size())
    }

    fn ipv4_payload_length(ipv4: &Ipv4Packet<'_>) -> usize {
        (ipv4.get_total_length() as usize).saturating_sub(ipv4.get_header_length() as usize * 4)
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
                .field("flags", &self.get_flags())
                .field("fragment_offset", &self.get_fragment_offset())
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
            assert_eq!([0x00, 0xFC], packet.packet()[..2]);
        }

        #[test]
        fn test_ecn() {
            let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
            let mut packet = Ipv4Packet::new(&mut buf).unwrap();
            packet.set_ecn(3);
            assert_eq!(3, packet.get_ecn());
            assert_eq!([0x00, 0x03], packet.packet()[..2]);
        }

        #[test]
        fn test_dscp_and_ecn() {
            let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
            let mut packet = Ipv4Packet::new(&mut buf).unwrap();
            packet.set_dscp(63);
            packet.set_ecn(3);
            assert_eq!(63, packet.get_dscp());
            assert_eq!(3, packet.get_ecn());
            assert_eq!([0x00, 0xFF], packet.packet()[..2]);
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
            packet.set_flags(2);
            assert_eq!(2, packet.get_flags());
            assert_eq!([0x40], packet.packet()[6..7]);
            packet.set_flags(7);
            assert_eq!(7, packet.get_flags());
            assert_eq!([0xE0], packet.packet()[6..7]);
        }

        #[test]
        fn test_fragment_offset() {
            let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
            let mut packet = Ipv4Packet::new(&mut buf).unwrap();
            packet.set_fragment_offset(0);
            assert_eq!(0, packet.get_fragment_offset());
            assert_eq!([0x00, 0x00], packet.packet()[6..=7]);
            packet.set_fragment_offset(500);
            assert_eq!(500, packet.get_fragment_offset());
            assert_eq!([0x01, 0xF4], packet.packet()[6..=7]);
            packet.set_fragment_offset(8191);
            assert_eq!(8191, packet.get_fragment_offset());
            assert_eq!([0x1F, 0xFF], packet.packet()[6..=7]);
        }

        #[test]
        fn test_flags_and_fragment_offset() {
            let mut buf = [0_u8; Ipv4Packet::minimum_packet_size()];
            let mut packet = Ipv4Packet::new(&mut buf).unwrap();
            packet.set_flags(3);
            packet.set_fragment_offset(99);
            assert_eq!(3, packet.get_flags());
            assert_eq!(99, packet.get_fragment_offset());
            assert_eq!([0x60, 0x63], packet.packet()[6..=7]);
            packet.set_flags(7);
            packet.set_fragment_offset(8191);
            assert_eq!(7, packet.get_flags());
            assert_eq!(8191, packet.get_fragment_offset());
            assert_eq!([0xFF, 0xFF], packet.packet()[6..=7]);
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

        // #[test]
        // fn test_options() {
        //     let mut buf = [0_u8; Ipv4Packet2::minimum_packet_size()];
        //     let mut packet = Ipv4Packet2::new(&mut buf).unwrap();
        //     assert!(false)
        // }

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
            assert_eq!(0, packet.get_flags());
            assert_eq!(0, packet.get_fragment_offset());
            assert_eq!(21, packet.get_ttl());
            assert_eq!(IpProtocol::Udp, packet.get_protocol());
            assert_eq!(39662, packet.get_checksum());
            assert_eq!(Ipv4Addr::new(0x07F, 0x00, 0x00, 0x01), packet.get_source());
            assert_eq!(
                Ipv4Addr::new(0xde, 0x9a, 0x56, 0x12),
                packet.get_destination()
            );
            assert!(packet.payload().is_empty());
        }
    }
}

pub mod udp {
    use crate::tracing::packet::Buffer;
    use std::fmt::{Debug, Formatter};

    const SOURCE_PORT_OFFSET: usize = 0;
    const DESTINATION_PORT_OFFSET: usize = 2;
    const LENGTH_OFFSET: usize = 4;
    const CHECKSUM_OFFSET: usize = 6;

    /// Represents an UDP Packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct UdpPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> UdpPacket<'a> {
        pub fn new(packet: &mut [u8]) -> Option<UdpPacket<'_>> {
            if packet.len() >= UdpPacket::minimum_packet_size() {
                Some(UdpPacket {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &[u8]) -> Option<UdpPacket<'_>> {
            if packet.len() >= UdpPacket::minimum_packet_size() {
                Some(UdpPacket {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub const fn minimum_packet_size() -> usize {
            8
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
        pub fn get_length(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(LENGTH_OFFSET))
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        pub fn set_source(&mut self, val: u16) {
            self.buf
                .set_bytes_two(SOURCE_PORT_OFFSET, val.to_be_bytes());
        }

        pub fn set_destination(&mut self, val: u16) {
            self.buf
                .set_bytes_two(DESTINATION_PORT_OFFSET, val.to_be_bytes());
        }

        pub fn set_length(&mut self, val: u16) {
            self.buf.set_bytes_two(LENGTH_OFFSET, val.to_be_bytes());
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
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
            &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
        }
    }

    impl Debug for UdpPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UdpPacket")
                .field("source", &self.get_source())
                .field("destination", &self.get_destination())
                .field("length", &self.get_length())
                .field("checksum", &self.get_checksum())
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
    }
}

pub mod icmp {
    use crate::tracing::packet::Buffer;
    use std::fmt::{Debug, Formatter};

    /// The type of ICMP packet.
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
        pub fn id(&self) -> u8 {
            match self {
                IcmpType::EchoRequest => 8,
                IcmpType::EchoReply => 0,
                IcmpType::DestinationUnreachable => 3,
                IcmpType::TimeExceeded => 11,
                IcmpType::Other(id) => *id,
            }
        }
    }

    impl From<u8> for IcmpType {
        fn from(val: u8) -> Self {
            match val {
                8 => Self::EchoRequest,
                0 => Self::EchoReply,
                3 => Self::DestinationUnreachable,
                11 => Self::TimeExceeded,
                id => Self::Other(id),
            }
        }
    }

    /// The ICMP code.
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
    pub struct IcmpCode(pub u8);

    impl From<u8> for IcmpCode {
        fn from(val: u8) -> Self {
            Self(val)
        }
    }

    const TYPE_OFFSET: usize = 0;
    const CODE_OFFSET: usize = 1;
    const CHECKSUM_OFFSET: usize = 2;

    /// Represents an ICMP packet.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
    /// data in host byte order, converting as necessary for the given architecture.
    pub struct IcmpPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> IcmpPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<IcmpPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<IcmpPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Immutable(packet),
                })
            } else {
                None
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
            u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
        }

        pub fn set_icmp_type(&mut self, val: IcmpType) {
            *self.buf.write(TYPE_OFFSET) = val.id();
        }

        pub fn set_icmp_code(&mut self, val: IcmpCode) {
            *self.buf.write(CODE_OFFSET) = val.0;
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
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
            assert_eq!([0x08], packet.buf.as_slice()[0..1]);
            packet.set_icmp_type(IcmpType::EchoReply);
            assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
            assert_eq!([0x00], packet.buf.as_slice()[0..1]);
            packet.set_icmp_type(IcmpType::DestinationUnreachable);
            assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
            assert_eq!([0x03], packet.buf.as_slice()[0..1]);
            packet.set_icmp_type(IcmpType::TimeExceeded);
            assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
            assert_eq!([0x0B], packet.buf.as_slice()[0..1]);
            packet.set_icmp_type(IcmpType::Other(255));
            assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
            assert_eq!([0xFF], packet.buf.as_slice()[0..1]);
        }

        #[test]
        fn test_icmp_code() {
            let mut buf = [0_u8; IcmpPacket::minimum_packet_size()];
            let mut packet = IcmpPacket::new(&mut buf).unwrap();
            packet.set_icmp_code(IcmpCode(0));
            assert_eq!(IcmpCode(0), packet.get_icmp_code());
            assert_eq!([0x00], packet.buf.as_slice()[1..2]);
            packet.set_icmp_code(IcmpCode(5));
            assert_eq!(IcmpCode(5), packet.get_icmp_code());
            assert_eq!([0x05], packet.buf.as_slice()[1..2]);
            packet.set_icmp_code(IcmpCode(255));
            assert_eq!(IcmpCode(255), packet.get_icmp_code());
            assert_eq!([0xFF], packet.buf.as_slice()[1..2]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; IcmpPacket::minimum_packet_size()];
            let mut packet = IcmpPacket::new(&mut buf).unwrap();
            packet.set_checksum(0);
            assert_eq!(0, packet.get_checksum());
            assert_eq!([0x00, 0x00], packet.buf.as_slice()[2..=3]);
            packet.set_checksum(1999);
            assert_eq!(1999, packet.get_checksum());
            assert_eq!([0x07, 0xCF], packet.buf.as_slice()[2..=3]);
            packet.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, packet.get_checksum());
            assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[2..=3]);
        }
    }

    pub mod echo_request {
        use crate::tracing::packet::{fmt_payload, Buffer};
        use crate::tracing::{IcmpCode, IcmpType};
        use std::fmt::{Debug, Formatter};

        const TYPE_OFFSET: usize = 0;
        const CODE_OFFSET: usize = 1;
        const CHECKSUM_OFFSET: usize = 2;
        const IDENTIFIER_OFFSET: usize = 4;
        const SEQUENCE_OFFSET: usize = 6;

        /// Represents an ICMP `EchoRequest` packet.
        ///
        /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
        /// data in host byte order, converting as necessary for the given architecture.
        pub struct EchoRequestPacket<'a> {
            buf: Buffer<'a>,
        }

        impl<'a> EchoRequestPacket<'a> {
            pub fn new(packet: &'a mut [u8]) -> Option<EchoRequestPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Mutable(packet),
                    })
                } else {
                    None
                }
            }

            #[must_use]
            pub fn new_view(packet: &'a [u8]) -> Option<EchoRequestPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Immutable(packet),
                    })
                } else {
                    None
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
                u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
            }

            #[must_use]
            pub fn get_identifier(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(IDENTIFIER_OFFSET))
            }

            #[must_use]
            pub fn get_sequence(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(SEQUENCE_OFFSET))
            }

            pub fn set_icmp_type(&mut self, val: IcmpType) {
                *self.buf.write(TYPE_OFFSET) = val.id();
            }

            pub fn set_icmp_code(&mut self, val: IcmpCode) {
                *self.buf.write(CODE_OFFSET) = val.0;
            }

            pub fn set_checksum(&mut self, val: u16) {
                self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
            }

            pub fn set_identifier(&mut self, val: u16) {
                self.buf.set_bytes_two(IDENTIFIER_OFFSET, val.to_be_bytes());
            }

            pub fn set_sequence(&mut self, val: u16) {
                self.buf.set_bytes_two(SEQUENCE_OFFSET, val.to_be_bytes());
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
                &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
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
                assert_eq!([0x08], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::EchoReply);
                assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
                assert_eq!([0x00], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::DestinationUnreachable);
                assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
                assert_eq!([0x03], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::TimeExceeded);
                assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
                assert_eq!([0x0B], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::Other(255));
                assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
                assert_eq!([0xFF], packet.buf.as_slice()[0..1]);
            }

            #[test]
            fn test_icmp_code() {
                let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
                let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
                packet.set_icmp_code(IcmpCode(0));
                assert_eq!(IcmpCode(0), packet.get_icmp_code());
                assert_eq!([0x00], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(5));
                assert_eq!(IcmpCode(5), packet.get_icmp_code());
                assert_eq!([0x05], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(255));
                assert_eq!(IcmpCode(255), packet.get_icmp_code());
                assert_eq!([0xFF], packet.buf.as_slice()[1..2]);
            }

            #[test]
            fn test_checksum() {
                let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
                let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
                packet.set_checksum(0);
                assert_eq!(0, packet.get_checksum());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(1999);
                assert_eq!(1999, packet.get_checksum());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(u16::MAX);
                assert_eq!(u16::MAX, packet.get_checksum());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[2..=3]);
            }

            #[test]
            fn test_identifier() {
                let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
                let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
                packet.set_identifier(0);
                assert_eq!(0, packet.get_identifier());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[4..=5]);
                packet.set_identifier(1999);
                assert_eq!(1999, packet.get_identifier());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[4..=5]);
                packet.set_identifier(u16::MAX);
                assert_eq!(u16::MAX, packet.get_identifier());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[4..=5]);
            }

            #[test]
            fn test_sequence() {
                let mut buf = [0_u8; EchoRequestPacket::minimum_packet_size()];
                let mut packet = EchoRequestPacket::new(&mut buf).unwrap();
                packet.set_sequence(0);
                assert_eq!(0, packet.get_sequence());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[6..=7]);
                packet.set_sequence(1999);
                assert_eq!(1999, packet.get_sequence());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[6..=7]);
                packet.set_sequence(u16::MAX);
                assert_eq!(u16::MAX, packet.get_sequence());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[6..=7]);
            }
        }
    }

    pub mod echo_reply {
        use crate::tracing::packet::{fmt_payload, Buffer};
        use crate::tracing::{IcmpCode, IcmpType};
        use std::fmt::{Debug, Formatter};

        const TYPE_OFFSET: usize = 0;
        const CODE_OFFSET: usize = 1;
        const CHECKSUM_OFFSET: usize = 2;
        const IDENTIFIER_OFFSET: usize = 4;
        const SEQUENCE_OFFSET: usize = 6;

        /// Represents an ICMP `EchoReply` packet.
        ///
        /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
        /// data in host byte order, converting as necessary for the given architecture.
        pub struct EchoReplyPacket<'a> {
            buf: Buffer<'a>,
        }

        impl<'a> EchoReplyPacket<'a> {
            pub fn new(packet: &'a mut [u8]) -> Option<EchoReplyPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Mutable(packet),
                    })
                } else {
                    None
                }
            }

            #[must_use]
            pub fn new_view(packet: &'a [u8]) -> Option<EchoReplyPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Immutable(packet),
                    })
                } else {
                    None
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
                u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
            }

            #[must_use]
            pub fn get_identifier(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(IDENTIFIER_OFFSET))
            }

            #[must_use]
            pub fn get_sequence(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(SEQUENCE_OFFSET))
            }

            pub fn set_icmp_type(&mut self, val: IcmpType) {
                *self.buf.write(TYPE_OFFSET) = val.id();
            }

            pub fn set_icmp_code(&mut self, val: IcmpCode) {
                *self.buf.write(CODE_OFFSET) = val.0;
            }

            pub fn set_checksum(&mut self, val: u16) {
                self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
            }

            pub fn set_identifier(&mut self, val: u16) {
                self.buf.set_bytes_two(IDENTIFIER_OFFSET, val.to_be_bytes());
            }

            pub fn set_sequence(&mut self, val: u16) {
                self.buf.set_bytes_two(SEQUENCE_OFFSET, val.to_be_bytes());
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
                &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
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
                assert_eq!([0x08], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::EchoReply);
                assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
                assert_eq!([0x00], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::DestinationUnreachable);
                assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
                assert_eq!([0x03], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::TimeExceeded);
                assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
                assert_eq!([0x0B], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::Other(255));
                assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
                assert_eq!([0xFF], packet.buf.as_slice()[0..1]);
            }

            #[test]
            fn test_icmp_code() {
                let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
                let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
                packet.set_icmp_code(IcmpCode(0));
                assert_eq!(IcmpCode(0), packet.get_icmp_code());
                assert_eq!([0x00], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(5));
                assert_eq!(IcmpCode(5), packet.get_icmp_code());
                assert_eq!([0x05], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(255));
                assert_eq!(IcmpCode(255), packet.get_icmp_code());
                assert_eq!([0xFF], packet.buf.as_slice()[1..2]);
            }

            #[test]
            fn test_checksum() {
                let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
                let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
                packet.set_checksum(0);
                assert_eq!(0, packet.get_checksum());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(1999);
                assert_eq!(1999, packet.get_checksum());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(u16::MAX);
                assert_eq!(u16::MAX, packet.get_checksum());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[2..=3]);
            }

            #[test]
            fn test_identifier() {
                let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
                let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
                packet.set_identifier(0);
                assert_eq!(0, packet.get_identifier());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[4..=5]);
                packet.set_identifier(1999);
                assert_eq!(1999, packet.get_identifier());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[4..=5]);
                packet.set_identifier(u16::MAX);
                assert_eq!(u16::MAX, packet.get_identifier());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[4..=5]);
            }

            #[test]
            fn test_sequence() {
                let mut buf = [0_u8; EchoReplyPacket::minimum_packet_size()];
                let mut packet = EchoReplyPacket::new(&mut buf).unwrap();
                packet.set_sequence(0);
                assert_eq!(0, packet.get_sequence());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[6..=7]);
                packet.set_sequence(1999);
                assert_eq!(1999, packet.get_sequence());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[6..=7]);
                packet.set_sequence(u16::MAX);
                assert_eq!(u16::MAX, packet.get_sequence());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[6..=7]);
            }
        }
    }

    pub mod time_exceeded {
        use crate::tracing::packet::{fmt_payload, Buffer};
        use crate::tracing::{IcmpCode, IcmpType};
        use std::fmt::{Debug, Formatter};

        const TYPE_OFFSET: usize = 0;
        const CODE_OFFSET: usize = 1;
        const CHECKSUM_OFFSET: usize = 2;

        /// Represents an ICMP `TimeExceeded` packet.
        ///
        /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
        /// data in host byte order, converting as necessary for the given architecture.
        pub struct TimeExceededPacket<'a> {
            buf: Buffer<'a>,
        }

        impl<'a> TimeExceededPacket<'a> {
            pub fn new(packet: &'a mut [u8]) -> Option<TimeExceededPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Mutable(packet),
                    })
                } else {
                    None
                }
            }

            #[must_use]
            pub fn new_view(packet: &'a [u8]) -> Option<TimeExceededPacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Immutable(packet),
                    })
                } else {
                    None
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
                u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
            }

            pub fn set_icmp_type(&mut self, val: IcmpType) {
                *self.buf.write(TYPE_OFFSET) = val.id();
            }

            pub fn set_icmp_code(&mut self, val: IcmpCode) {
                *self.buf.write(CODE_OFFSET) = val.0;
            }

            pub fn set_checksum(&mut self, val: u16) {
                self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
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
                &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
            }
        }

        impl Debug for TimeExceededPacket<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("TimeExceededPacket")
                    .field("icmp_type", &self.get_icmp_type())
                    .field("icmp_code", &self.get_icmp_code())
                    .field("checksum", &self.get_checksum())
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
                assert_eq!([0x08], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::EchoReply);
                assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
                assert_eq!([0x00], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::DestinationUnreachable);
                assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
                assert_eq!([0x03], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::TimeExceeded);
                assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
                assert_eq!([0x0B], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::Other(255));
                assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
                assert_eq!([0xFF], packet.buf.as_slice()[0..1]);
            }

            #[test]
            fn test_icmp_code() {
                let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
                let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
                packet.set_icmp_code(IcmpCode(0));
                assert_eq!(IcmpCode(0), packet.get_icmp_code());
                assert_eq!([0x00], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(5));
                assert_eq!(IcmpCode(5), packet.get_icmp_code());
                assert_eq!([0x05], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(255));
                assert_eq!(IcmpCode(255), packet.get_icmp_code());
                assert_eq!([0xFF], packet.buf.as_slice()[1..2]);
            }

            #[test]
            fn test_checksum() {
                let mut buf = [0_u8; TimeExceededPacket::minimum_packet_size()];
                let mut packet = TimeExceededPacket::new(&mut buf).unwrap();
                packet.set_checksum(0);
                assert_eq!(0, packet.get_checksum());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(1999);
                assert_eq!(1999, packet.get_checksum());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(u16::MAX);
                assert_eq!(u16::MAX, packet.get_checksum());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[2..=3]);
            }
        }
    }

    pub mod destination_unreachable {
        use crate::tracing::packet::{fmt_payload, Buffer};
        use crate::tracing::{IcmpCode, IcmpType};
        use std::fmt::{Debug, Formatter};

        const TYPE_OFFSET: usize = 0;
        const CODE_OFFSET: usize = 1;
        const CHECKSUM_OFFSET: usize = 2;
        const UNUSED_OFFSET: usize = 4;
        const NEXT_HOP_MTU_OFFSET: usize = 6;

        /// Represents an ICMP `DestinationUnreachable` packet.
        ///
        /// The internal representation is held in network byte order (big-endian) and all accessor methods take and return
        /// data in host byte order, converting as necessary for the given architecture.
        pub struct DestinationUnreachablePacket<'a> {
            buf: Buffer<'a>,
        }

        impl<'a> DestinationUnreachablePacket<'a> {
            pub fn new(packet: &'a mut [u8]) -> Option<DestinationUnreachablePacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Mutable(packet),
                    })
                } else {
                    None
                }
            }

            #[must_use]
            pub fn new_view(packet: &'a [u8]) -> Option<DestinationUnreachablePacket<'_>> {
                if packet.len() >= Self::minimum_packet_size() {
                    Some(Self {
                        buf: Buffer::Immutable(packet),
                    })
                } else {
                    None
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
                u16::from_be_bytes(self.buf.get_bytes_two(CHECKSUM_OFFSET))
            }

            #[must_use]
            pub fn get_unused(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(UNUSED_OFFSET))
            }

            #[must_use]
            pub fn get_next_hop_mtu(&self) -> u16 {
                u16::from_be_bytes(self.buf.get_bytes_two(NEXT_HOP_MTU_OFFSET))
            }

            pub fn set_icmp_type(&mut self, val: IcmpType) {
                *self.buf.write(TYPE_OFFSET) = val.id();
            }

            pub fn set_icmp_code(&mut self, val: IcmpCode) {
                *self.buf.write(CODE_OFFSET) = val.0;
            }

            pub fn set_checksum(&mut self, val: u16) {
                self.buf.set_bytes_two(CHECKSUM_OFFSET, val.to_be_bytes());
            }

            pub fn set_unused(&mut self, val: u16) {
                self.buf.set_bytes_two(UNUSED_OFFSET, val.to_be_bytes());
            }

            pub fn set_next_hop_mtu(&mut self, val: u16) {
                self.buf
                    .set_bytes_two(NEXT_HOP_MTU_OFFSET, val.to_be_bytes());
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
                &self.buf.as_slice()[Self::minimum_packet_size() as usize..]
            }
        }

        impl Debug for DestinationUnreachablePacket<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("DestinationUnreachablePacket")
                    .field("icmp_type", &self.get_icmp_type())
                    .field("icmp_code", &self.get_icmp_code())
                    .field("checksum", &self.get_checksum())
                    .field("unused", &self.get_unused())
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
                assert_eq!([0x08], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::EchoReply);
                assert_eq!(IcmpType::EchoReply, packet.get_icmp_type());
                assert_eq!([0x00], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::DestinationUnreachable);
                assert_eq!(IcmpType::DestinationUnreachable, packet.get_icmp_type());
                assert_eq!([0x03], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::TimeExceeded);
                assert_eq!(IcmpType::TimeExceeded, packet.get_icmp_type());
                assert_eq!([0x0B], packet.buf.as_slice()[0..1]);
                packet.set_icmp_type(IcmpType::Other(255));
                assert_eq!(IcmpType::Other(255), packet.get_icmp_type());
                assert_eq!([0xFF], packet.buf.as_slice()[0..1]);
            }

            #[test]
            fn test_icmp_code() {
                let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
                let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
                packet.set_icmp_code(IcmpCode(0));
                assert_eq!(IcmpCode(0), packet.get_icmp_code());
                assert_eq!([0x00], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(5));
                assert_eq!(IcmpCode(5), packet.get_icmp_code());
                assert_eq!([0x05], packet.buf.as_slice()[1..2]);
                packet.set_icmp_code(IcmpCode(255));
                assert_eq!(IcmpCode(255), packet.get_icmp_code());
                assert_eq!([0xFF], packet.buf.as_slice()[1..2]);
            }

            #[test]
            fn test_checksum() {
                let mut buf = [0_u8; DestinationUnreachablePacket::minimum_packet_size()];
                let mut packet = DestinationUnreachablePacket::new(&mut buf).unwrap();
                packet.set_checksum(0);
                assert_eq!(0, packet.get_checksum());
                assert_eq!([0x00, 0x00], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(1999);
                assert_eq!(1999, packet.get_checksum());
                assert_eq!([0x07, 0xCF], packet.buf.as_slice()[2..=3]);
                packet.set_checksum(u16::MAX);
                assert_eq!(u16::MAX, packet.get_checksum());
                assert_eq!([0xFF, 0xFF], packet.buf.as_slice()[2..=3]);
            }
        }
    }
}

fn fmt_payload(bytes: &[u8]) -> String {
    use itertools::Itertools as _;
    format!("{:02x}", bytes.iter().format(" "))
}
