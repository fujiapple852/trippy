pub mod extension_structure {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::icmp_extension::extension_object::ExtensionObjectPacket;

    /// Represents an ICMP `ExtensionsPacket` pseudo object.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct ExtensionsPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> ExtensionsPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<ExtensionsPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<ExtensionsPacket<'_>> {
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
            4
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn header(&self) -> &[u8] {
            &self.buf.as_slice()[..Self::minimum_packet_size()]
        }

        /// An iterator of Extension Objects contained within this `ExtensionsPacket`.
        #[must_use]
        pub fn objects(&self) -> ExtensionObjectIter<'_> {
            ExtensionObjectIter::new(&self.buf)
        }
    }

    pub struct ExtensionObjectIter<'a> {
        buf: &'a Buffer<'a>,
        offset: usize,
    }

    impl<'a> ExtensionObjectIter<'a> {
        #[must_use]
        pub fn new(buf: &'a Buffer<'_>) -> Self {
            Self {
                buf,
                offset: ExtensionsPacket::minimum_packet_size(),
            }
        }
    }

    impl<'a> Iterator for ExtensionObjectIter<'a> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            if self.offset >= self.buf.as_slice().len() {
                None
            } else {
                let object_bytes = &self.buf.as_slice()[self.offset..];
                if let Some(object) = ExtensionObjectPacket::new_view(object_bytes) {
                    let length = object.get_length();
                    // If a malformed extension object has a length of 0 then we end iteration.
                    if length == 0 {
                        return None;
                    }
                    self.offset += usize::from(length);
                    Some(object_bytes)
                } else {
                    None
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tracing::packet::icmp_extension::extension_header::ExtensionHeaderPacket;
        use crate::tracing::packet::icmp_extension::extension_object::{
            ClassNum, ClassSubType, ExtensionObjectPacket,
        };

        #[test]
        fn test_header() {
            let buf = [
                0x20, 0x00, 0x99, 0x3a, 0x00, 0x08, 0x01, 0x01, 0x04, 0xbb, 0x41, 0x01,
            ];
            let extensions = ExtensionsPacket::new_view(&buf).unwrap();
            let header = ExtensionHeaderPacket::new_view(extensions.header()).unwrap();
            assert_eq!(2, header.get_version());
            assert_eq!(0x993A, header.get_checksum());
        }

        #[test]
        fn test_object_iterator() {
            let buf = [
                0x20, 0x00, 0x99, 0x3a, 0x00, 0x08, 0x01, 0x01, 0x04, 0xbb, 0x41, 0x01,
            ];
            let extensions = ExtensionsPacket::new_view(&buf).unwrap();
            let mut object_iter = extensions.objects();
            let object_bytes = object_iter.next().unwrap();
            let object = ExtensionObjectPacket::new_view(object_bytes).unwrap();
            assert_eq!(8, object.get_length());
            assert_eq!(
                ClassNum::MultiProtocolLabelSwitchingLabelStack,
                object.get_class_num()
            );
            assert_eq!(ClassSubType(1), object.get_class_subtype());
            assert_eq!([0x04, 0xbb, 0x41, 0x01], object.payload());
            assert!(object_iter.next().is_none());
        }

        #[test]
        fn test_object_iterator_zero_length() {
            let buf = [
                0x20, 0x00, 0x99, 0x3a, 0x00, 0x00, 0x01, 0x01, 0x04, 0xbb, 0x41, 0x01,
            ];
            let extensions = ExtensionsPacket::new_view(&buf).unwrap();
            let mut object_iter = extensions.objects();
            assert!(object_iter.next().is_none());
        }
    }
}

pub mod extension_header {
    use crate::tracing::packet::buffer::Buffer;
    use std::fmt::{Debug, Formatter};

    const VERSION_OFFSET: usize = 0;
    const CHECKSUM_OFFSET: usize = 2;

    /// Represents an ICMP `ExtensionHeaderPacket`.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct ExtensionHeaderPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> ExtensionHeaderPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<ExtensionHeaderPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<ExtensionHeaderPacket<'_>> {
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
            4
        }

        #[must_use]
        pub fn get_version(&self) -> u8 {
            (self.buf.read(VERSION_OFFSET) & 0xf0) >> 4
        }

        #[must_use]
        pub fn get_checksum(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(CHECKSUM_OFFSET))
        }

        pub fn set_version(&mut self, val: u8) {
            *self.buf.write(VERSION_OFFSET) =
                (self.buf.read(VERSION_OFFSET) & 0xf) | ((val & 0xf) << 4);
        }

        pub fn set_checksum(&mut self, val: u16) {
            self.buf.set_bytes(CHECKSUM_OFFSET, val.to_be_bytes());
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }
    }

    impl Debug for ExtensionHeaderPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ExtensionHeader")
                .field("version", &self.get_version())
                .field("checksum", &self.get_checksum())
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_version() {
            let mut buf = [0_u8; ExtensionHeaderPacket::minimum_packet_size()];
            let mut extension = ExtensionHeaderPacket::new(&mut buf).unwrap();
            extension.set_version(0);
            assert_eq!(0, extension.get_version());
            assert_eq!([0x00], extension.packet()[0..1]);
            extension.set_version(2);
            assert_eq!(2, extension.get_version());
            assert_eq!([0x20], extension.packet()[0..1]);
            extension.set_version(15);
            assert_eq!(15, extension.get_version());
            assert_eq!([0xF0], extension.packet()[0..1]);
        }

        #[test]
        fn test_checksum() {
            let mut buf = [0_u8; ExtensionHeaderPacket::minimum_packet_size()];
            let mut extension = ExtensionHeaderPacket::new(&mut buf).unwrap();
            extension.set_checksum(0);
            assert_eq!(0, extension.get_checksum());
            assert_eq!([0x00, 0x00], extension.packet()[2..=3]);
            extension.set_checksum(1999);
            assert_eq!(1999, extension.get_checksum());
            assert_eq!([0x07, 0xCF], extension.packet()[2..=3]);
            extension.set_checksum(39226);
            assert_eq!(39226, extension.get_checksum());
            assert_eq!([0x99, 0x3A], extension.packet()[2..=3]);
            extension.set_checksum(u16::MAX);
            assert_eq!(u16::MAX, extension.get_checksum());
            assert_eq!([0xFF, 0xFF], extension.packet()[2..=3]);
        }

        #[test]
        fn test_extension_header_view() {
            let buf = [
                0x20, 0x00, 0x99, 0x3a, 0x00, 0x08, 0x01, 0x01, 0x04, 0xbb, 0x41, 0x01,
            ];
            let extension = ExtensionHeaderPacket::new_view(&buf).unwrap();
            assert_eq!(2, extension.get_version());
            assert_eq!(0x993A, extension.get_checksum());
        }
    }
}

pub mod extension_object {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::fmt_payload;
    use std::fmt::{Debug, Formatter};

    /// The ICMP Extension Object Class Num.
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
    pub enum ClassNum {
        MultiProtocolLabelSwitchingLabelStack,
        InterfaceInformationObject,
        InterfaceIdentificationObject,
        ExtendedInformation,
        Other(u8),
    }

    impl ClassNum {
        #[must_use]
        pub fn id(&self) -> u8 {
            match self {
                Self::MultiProtocolLabelSwitchingLabelStack => 1,
                Self::InterfaceInformationObject => 2,
                Self::InterfaceIdentificationObject => 3,
                Self::ExtendedInformation => 4,
                Self::Other(id) => *id,
            }
        }
    }

    impl From<u8> for ClassNum {
        fn from(val: u8) -> Self {
            match val {
                1 => Self::MultiProtocolLabelSwitchingLabelStack,
                2 => Self::InterfaceInformationObject,
                3 => Self::InterfaceIdentificationObject,
                4 => Self::ExtendedInformation,
                id => Self::Other(id),
            }
        }
    }

    /// The ICMP Extension Object Class Sub-type.
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
    pub struct ClassSubType(pub u8);

    impl From<u8> for ClassSubType {
        fn from(val: u8) -> Self {
            Self(val)
        }
    }

    const LENGTH_OFFSET: usize = 0;
    const CLASS_NUM_OFFSET: usize = 2;
    const CLASS_SUBTYPE_OFFSET: usize = 3;

    /// Represents an ICMP `ExtensionObjectPacket`.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct ExtensionObjectPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> ExtensionObjectPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<ExtensionObjectPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<ExtensionObjectPacket<'_>> {
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
            4
        }

        pub fn set_length(&mut self, val: u16) {
            self.buf.set_bytes(LENGTH_OFFSET, val.to_be_bytes());
        }

        pub fn set_class_num(&mut self, val: ClassNum) {
            *self.buf.write(CLASS_NUM_OFFSET) = val.id();
        }

        pub fn set_class_subtype(&mut self, val: ClassSubType) {
            *self.buf.write(CLASS_SUBTYPE_OFFSET) = val.0;
        }

        pub fn set_payload(&mut self, vals: &[u8]) {
            let current_offset = Self::minimum_packet_size();
            self.buf.as_slice_mut()[current_offset..current_offset + vals.len()]
                .copy_from_slice(vals);
        }

        #[must_use]
        pub fn get_length(&self) -> u16 {
            u16::from_be_bytes(self.buf.get_bytes(LENGTH_OFFSET))
        }

        #[must_use]
        pub fn get_class_num(&self) -> ClassNum {
            ClassNum::from(self.buf.read(CLASS_NUM_OFFSET))
        }

        #[must_use]
        pub fn get_class_subtype(&self) -> ClassSubType {
            ClassSubType::from(self.buf.read(CLASS_SUBTYPE_OFFSET))
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }

        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.buf.as_slice()[Self::minimum_packet_size()..usize::from(self.get_length())]
        }
    }

    impl Debug for ExtensionObjectPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ExtensionObject")
                .field("length", &self.get_length())
                .field("class_num", &self.get_class_num())
                .field("class_subtype", &self.get_class_subtype())
                .field("payload", &fmt_payload(self.payload()))
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_length() {
            let mut buf = [0_u8; ExtensionObjectPacket::minimum_packet_size()];
            let mut extension = ExtensionObjectPacket::new(&mut buf).unwrap();
            extension.set_length(0);
            assert_eq!(0, extension.get_length());
            assert_eq!([0x00, 0x00], extension.packet()[0..=1]);
            extension.set_length(8);
            assert_eq!(8, extension.get_length());
            assert_eq!([0x00, 0x08], extension.packet()[0..=1]);
            extension.set_length(u16::MAX);
            assert_eq!(u16::MAX, extension.get_length());
            assert_eq!([0xFF, 0xFF], extension.packet()[0..=1]);
        }

        #[test]
        fn test_class_num() {
            let mut buf = [0_u8; ExtensionObjectPacket::minimum_packet_size()];
            let mut extension = ExtensionObjectPacket::new(&mut buf).unwrap();
            extension.set_class_num(ClassNum::MultiProtocolLabelSwitchingLabelStack);
            assert_eq!(
                ClassNum::MultiProtocolLabelSwitchingLabelStack,
                extension.get_class_num()
            );
            assert_eq!([0x01], extension.packet()[2..3]);
            extension.set_class_num(ClassNum::InterfaceInformationObject);
            assert_eq!(
                ClassNum::InterfaceInformationObject,
                extension.get_class_num()
            );
            assert_eq!([0x02], extension.packet()[2..3]);
            extension.set_class_num(ClassNum::InterfaceIdentificationObject);
            assert_eq!(
                ClassNum::InterfaceIdentificationObject,
                extension.get_class_num()
            );
            assert_eq!([0x03], extension.packet()[2..3]);
            extension.set_class_num(ClassNum::ExtendedInformation);
            assert_eq!(ClassNum::ExtendedInformation, extension.get_class_num());
            assert_eq!([0x04], extension.packet()[2..3]);
            extension.set_class_num(ClassNum::Other(255));
            assert_eq!(ClassNum::Other(255), extension.get_class_num());
            assert_eq!([0xFF], extension.packet()[2..3]);
        }

        #[test]
        fn test_class_subtype() {
            let mut buf = [0_u8; ExtensionObjectPacket::minimum_packet_size()];
            let mut extension = ExtensionObjectPacket::new(&mut buf).unwrap();
            extension.set_class_subtype(ClassSubType(0));
            assert_eq!(ClassSubType(0), extension.get_class_subtype());
            assert_eq!([0x00], extension.packet()[3..4]);
            extension.set_class_subtype(ClassSubType(1));
            assert_eq!(ClassSubType(1), extension.get_class_subtype());
            assert_eq!([0x01], extension.packet()[3..4]);
            extension.set_class_subtype(ClassSubType(255));
            assert_eq!(ClassSubType(255), extension.get_class_subtype());
            assert_eq!([0xff], extension.packet()[3..4]);
        }

        #[test]
        fn test_extension_header_view() {
            let buf = [0x00, 0x08, 0x01, 0x01, 0x04, 0xbb, 0x41, 0x01];
            let object = ExtensionObjectPacket::new_view(&buf).unwrap();
            assert_eq!(8, object.get_length());
            assert_eq!(
                ClassNum::MultiProtocolLabelSwitchingLabelStack,
                object.get_class_num()
            );
            assert_eq!(ClassSubType(1), object.get_class_subtype());
            assert_eq!([0x04, 0xbb, 0x41, 0x01], object.payload());
        }
    }
}

pub mod extension_splitter {
    use crate::tracing::packet::icmp_extension::extension_header::ExtensionHeaderPacket;

    const ICMP_ORIG_DATAGRAM_MIN_LENGTH: usize = 128;
    const MIN_HEADER: usize = ExtensionHeaderPacket::minimum_packet_size();

    /// Separate an ICMP payload from ICMP extensions as defined in rfc4884.
    ///
    /// Applies to `TimeExceeded` and `DestinationUnreachable` ICMP messages only.
    ///
    /// From rfc4884 (section 3) entitled "Summary of Changes to ICMP":
    ///
    /// "When the ICMP Extension Structure is appended to an ICMP message
    /// and that ICMP message contains an "original datagram" field, the
    /// "original datagram" field MUST contain at least 128 octets."
    #[must_use]
    pub fn split(rfc4884_length: u8, icmp_payload: &[u8]) -> (&[u8], Option<&[u8]>) {
        let length = usize::from(rfc4884_length * 4);
        if length > icmp_payload.len() {
            return (&[], None);
        }
        if icmp_payload.len() > ICMP_ORIG_DATAGRAM_MIN_LENGTH {
            if length > ICMP_ORIG_DATAGRAM_MIN_LENGTH {
                // a 'compliant' ICMP extension longer than 128 octets.
                do_split(length, icmp_payload)
            } else if length > 0 {
                // a 'compliant' ICMP extension padded to at least 128 octets.
                match do_split(ICMP_ORIG_DATAGRAM_MIN_LENGTH, icmp_payload) {
                    (&[], ext) => (&[], ext),
                    (payload, extension) => (&payload[..length], extension),
                }
            } else {
                // a 'non-compliant' ICMP extension padded to 128 octets.
                do_split(ICMP_ORIG_DATAGRAM_MIN_LENGTH, icmp_payload)
            }
        } else {
            // no extension present
            (icmp_payload, None)
        }
    }

    /// Split the ICMP payload into payload and extension parts.
    ///
    /// If the extension is not empty and is at least as long as the minimum
    /// extension header then Some(extension) is returned.
    ///
    /// If the extension is empty then None is returned.
    ///
    /// If the extension is non-empty but not as long as the minimum extension
    /// header then the payload is invalid and so we return an empty payload
    /// and extension.
    fn do_split(index: usize, icmp_payload: &[u8]) -> (&[u8], Option<&[u8]>) {
        match icmp_payload.split_at(index) {
            (payload, extension) if extension.len() >= MIN_HEADER => (payload, Some(extension)),
            (payload, extension) if extension.is_empty() => (payload, None),
            _ => (&[], None),
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::tracing::packet::icmp_extension::extension_header::ExtensionHeaderPacket;
        use crate::tracing::packet::icmp_extension::extension_object::{
            ClassNum, ClassSubType, ExtensionObjectPacket,
        };
        use crate::tracing::packet::icmp_extension::extension_splitter::split;
        use crate::tracing::packet::icmp_extension::extension_structure::ExtensionsPacket;
        use crate::tracing::packet::icmpv4::echo_request::EchoRequestPacket;
        use crate::tracing::packet::icmpv4::time_exceeded::TimeExceededPacket;
        use crate::tracing::packet::icmpv4::{IcmpCode, IcmpType};
        use crate::tracing::packet::ipv4::Ipv4Packet;
        use std::net::Ipv4Addr;

        #[test]
        fn test_split_empty_payload() {
            let icmp_payload: [u8; 0] = [];
            let (payload, extension) = split(0, &icmp_payload);
            assert!(payload.is_empty() && extension.is_none());
        }

        // Test ICMP payload which is 12 bytes and has rfc4884 length of 3 (12
        // bytes) so payload is 12 bytes and there is no extension.
        #[test]
        fn test_split_payload_with_compliant_empty_extension() {
            let rfc4884_length = 3;
            let icmp_payload: [u8; 12] = [0; 12];
            let (payload, extension) = split(rfc4884_length, &icmp_payload);
            assert_eq!(payload, &[0; 12]);
            assert_eq!(extension, None);
        }

        // Test ICMP payload with a minimal compliant extension.
        #[test]
        fn test_split_payload_with_compliant_minimal_extension() {
            let icmp_payload: [u8; 132] = [0; 132];
            let (payload, extension) = split(32, &icmp_payload);
            assert_eq!(payload, &[0; 128]);
            assert_eq!(extension, Some([0; 4].as_slice()));
        }

        // Test handling of an ICMP payload which has an rfc4884 length that
        // is longer than the original datagram.
        #[test]
        fn test_split_payload_with_invalid_rfc4884_length() {
            let icmp_payload: [u8; 128] = [0; 128];
            let (payload, extension) = split(33, &icmp_payload);
            assert!(payload.is_empty() && extension.is_none());
        }

        // Test handling of an ICMP payload which has a compliant extension
        // which is not as long as the minimum size for an ICMP extension
        // header (4 bytes).
        #[test]
        fn test_split_payload_with_compliant_invalid_extension() {
            let icmp_payload: [u8; 129] = [0; 129];
            let (payload, extension) = split(32, &icmp_payload);
            assert!(payload.is_empty() && extension.is_none());
        }

        // This ICMP TimeExceeded packet which contains single `MPLS` extension
        // object with a single member.  The packet does not have a `length`
        // field and is therefore rfc4884 non-complaint.
        #[test]
        #[allow(clippy::cognitive_complexity)]
        fn test_split_extension_ipv4_time_exceeded_non_compliant_mpls() {
            let buf = hex_literal::hex!(
                "
               0b 00 f4 ff 00 00 00 00 45 00 00 54 cc 1c 40 00
               01 01 b5 f4 c0 a8 01 15 5d b8 d8 22 08 00 0f e3
               65 da 82 42 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 20 00 99 3a 00 08 01 01
               04 bb 41 01
               "
            );
            let time_exceeded_packet = TimeExceededPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::TimeExceeded, time_exceeded_packet.get_icmp_type());
            assert_eq!(IcmpCode(0), time_exceeded_packet.get_icmp_code());
            assert_eq!(62719, time_exceeded_packet.get_checksum());
            assert_eq!(0, time_exceeded_packet.get_length());
            assert_eq!(&buf[8..136], time_exceeded_packet.payload());
            assert_eq!(Some(&buf[136..]), time_exceeded_packet.extension());

            let nested_ipv4 = Ipv4Packet::new_view(time_exceeded_packet.payload()).unwrap();
            assert_eq!(Ipv4Addr::from([192, 168, 1, 21]), nested_ipv4.get_source());
            assert_eq!(
                Ipv4Addr::from([93, 184, 216, 34]),
                nested_ipv4.get_destination()
            );
            assert_eq!(&buf[28..136], nested_ipv4.payload());

            let nested_echo = EchoRequestPacket::new_view(nested_ipv4.payload()).unwrap();
            assert_eq!(IcmpCode(0), nested_echo.get_icmp_code());
            assert_eq!(IcmpType::EchoRequest, nested_echo.get_icmp_type());
            assert_eq!(0x0FE3, nested_echo.get_checksum());
            assert_eq!(26074, nested_echo.get_identifier());
            assert_eq!(33346, nested_echo.get_sequence());
            assert_eq!(&buf[36..136], nested_echo.payload());

            let extensions =
                ExtensionsPacket::new_view(time_exceeded_packet.extension().unwrap()).unwrap();

            let extension_header = ExtensionHeaderPacket::new_view(extensions.header()).unwrap();
            assert_eq!(2, extension_header.get_version());
            assert_eq!(0x993A, extension_header.get_checksum());

            let object_bytes = extensions.objects().next().unwrap();
            let extension_object = ExtensionObjectPacket::new_view(object_bytes).unwrap();

            assert_eq!(8, extension_object.get_length());
            assert_eq!(
                ClassNum::MultiProtocolLabelSwitchingLabelStack,
                extension_object.get_class_num()
            );
            assert_eq!(ClassSubType(1), extension_object.get_class_subtype());
            assert_eq!([0x04, 0xbb, 0x41, 0x01], extension_object.payload());
        }

        // This ICMP TimeExceeded packet does not have any ICMP extensions.
        // It has a rfc4884 complaint `length` field.
        #[test]
        fn test_split_extension_ipv4_time_exceeded_compliant_no_extension() {
            let buf = hex_literal::hex!(
                "
               0b 00 f4 ee 00 11 00 00 45 00 00 54 a2 ee 40 00
               01 01 df 22 c0 a8 01 15 5d b8 d8 22 08 00 0f e1
               65 da 82 44 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00
               "
            );
            let time_exceeded_packet = TimeExceededPacket::new_view(&buf).unwrap();
            assert_eq!(IcmpType::TimeExceeded, time_exceeded_packet.get_icmp_type());
            assert_eq!(IcmpCode(0), time_exceeded_packet.get_icmp_code());
            assert_eq!(62702, time_exceeded_packet.get_checksum());
            assert_eq!(17, time_exceeded_packet.get_length());
            assert_eq!(&buf[8..76], time_exceeded_packet.payload());
            assert_eq!(None, time_exceeded_packet.extension());

            let nested_ipv4 = Ipv4Packet::new_view(&buf[8..76]).unwrap();
            assert_eq!(Ipv4Addr::from([192, 168, 1, 21]), nested_ipv4.get_source());
            assert_eq!(
                Ipv4Addr::from([93, 184, 216, 34]),
                nested_ipv4.get_destination()
            );
            assert_eq!(&buf[28..76], nested_ipv4.payload());

            let nested_echo = EchoRequestPacket::new_view(nested_ipv4.payload()).unwrap();
            assert_eq!(IcmpCode(0), nested_echo.get_icmp_code());
            assert_eq!(IcmpType::EchoRequest, nested_echo.get_icmp_type());
            assert_eq!(0x0FE1, nested_echo.get_checksum());
            assert_eq!(26074, nested_echo.get_identifier());
            assert_eq!(33348, nested_echo.get_sequence());
            assert_eq!(&buf[36..76], nested_echo.payload());
        }

        // This is an real example that was observed in the wild whilst testing.
        //
        // It has a rfc4884 complaint `length` field set to be 17 and so has
        // an original datagram if length 68 octet (17 * 4 = 68) but is padded
        // to be 128 octets.
        //
        // See https://github.com/fujiapple852/trippy/issues/804 for further
        // discussion and analysis of this case.
        #[test]
        fn test_split_extension_ipv4_time_exceeded_compliant_extension() {
            let buf = hex_literal::hex!(
                "
               0b 00 f4 ee 00 11 00 00 45 00 00 54 20 c3 40 00
               02 01 b5 7e 64 63 08 2a 5d b8 d8 22 08 00 11 8d
               65 83 80 ef 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 20 00 78 56 00 08 01 01
               65 9f 01 01
               "
            );
            let time_exceeded_packet = TimeExceededPacket::new_view(&buf).unwrap();
            assert_eq!(68, time_exceeded_packet.payload().len());
            assert_eq!(12, time_exceeded_packet.extension().unwrap().len());
            let extensions =
                ExtensionsPacket::new_view(time_exceeded_packet.extension().unwrap()).unwrap();

            let extension_header = ExtensionHeaderPacket::new_view(extensions.header()).unwrap();
            assert_eq!(2, extension_header.get_version());
            assert_eq!(0x7856, extension_header.get_checksum());

            let object_bytes = extensions.objects().next().unwrap();
            let extension_object = ExtensionObjectPacket::new_view(object_bytes).unwrap();

            assert_eq!(8, extension_object.get_length());
            assert_eq!(
                ClassNum::MultiProtocolLabelSwitchingLabelStack,
                extension_object.get_class_num()
            );
            assert_eq!(ClassSubType(1), extension_object.get_class_subtype());
            assert_eq!([0x65, 0x9f, 0x01, 0x01], extension_object.payload());

            let mpls_stack = MplsLabelStackPacket::new_view(extension_object.payload()).unwrap();
            let mpls_stack_member_bytes = mpls_stack.members().next().unwrap();
            let mpls_stack_member =
                MplsLabelStackMemberPacket::new_view(mpls_stack_member_bytes).unwrap();
            assert_eq!(416_240, mpls_stack_member.get_label());
            assert_eq!(0, mpls_stack_member.get_exp());
            assert_eq!(1, mpls_stack_member.get_bos());
            assert_eq!(1, mpls_stack_member.get_ttl());
        }
    }
}
