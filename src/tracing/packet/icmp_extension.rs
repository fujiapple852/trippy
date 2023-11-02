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
