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
                    self.offset += usize::from(object.get_length());
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

pub mod mpls_label_stack {
    use crate::tracing::packet::buffer::Buffer;
    use crate::tracing::packet::icmp_extension::mpls_label_stack_member::MplsLabelStackMemberPacket;

    /// Represents an ICMP `MplsLabelStackPacket`.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct MplsLabelStackPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> MplsLabelStackPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<MplsLabelStackPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<MplsLabelStackPacket<'_>> {
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
        pub fn members(&self) -> MplsLabelStackIter<'_> {
            MplsLabelStackIter::new(&self.buf)
        }
    }

    pub struct MplsLabelStackIter<'a> {
        buf: &'a Buffer<'a>,
        offset: usize,
        bos: u8,
    }

    impl<'a> MplsLabelStackIter<'a> {
        #[must_use]
        pub fn new(buf: &'a Buffer<'_>) -> Self {
            Self {
                buf,
                offset: 0,
                bos: 0,
            }
        }
    }

    impl<'a> Iterator for MplsLabelStackIter<'a> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            if self.bos > 0 || self.offset >= self.buf.as_slice().len() {
                None
            } else {
                let member_bytes = &self.buf.as_slice()[self.offset..];
                if let Some(member) = MplsLabelStackMemberPacket::new_view(member_bytes) {
                    self.bos = member.get_bos();
                    self.offset += MplsLabelStackMemberPacket::minimum_packet_size();
                    Some(member_bytes)
                } else {
                    None
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_stack_member_iterator() {
            let buf = [0x04, 0xbb, 0x41, 0x01];
            let stack = MplsLabelStackPacket::new_view(&buf).unwrap();
            let mut member_iter = stack.members();
            let member_bytes = member_iter.next().unwrap();
            let member = MplsLabelStackMemberPacket::new_view(member_bytes).unwrap();
            assert_eq!(19380, member.get_label());
            assert_eq!(0, member.get_exp());
            assert_eq!(1, member.get_bos());
            assert_eq!(1, member.get_ttl());
            assert!(member_iter.next().is_none());
        }
    }
}

pub mod mpls_label_stack_member {
    use crate::tracing::packet::buffer::Buffer;
    use std::fmt::{Debug, Formatter};

    const LABEL_OFFSET: usize = 0;
    const EXP_OFFSET: usize = 2;
    const BOS_OFFSET: usize = 2;
    const TTL_OFFSET: usize = 3;

    /// Represents an ICMP `MplsLabelStackMemberPacket`.
    ///
    /// The internal representation is held in network byte order (big-endian) and all accessor
    /// methods take and return data in host byte order, converting as necessary for the given
    /// architecture.
    pub struct MplsLabelStackMemberPacket<'a> {
        buf: Buffer<'a>,
    }

    impl<'a> MplsLabelStackMemberPacket<'a> {
        pub fn new(packet: &'a mut [u8]) -> Option<MplsLabelStackMemberPacket<'_>> {
            if packet.len() >= Self::minimum_packet_size() {
                Some(Self {
                    buf: Buffer::Mutable(packet),
                })
            } else {
                None
            }
        }

        #[must_use]
        pub fn new_view(packet: &'a [u8]) -> Option<MplsLabelStackMemberPacket<'_>> {
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
        pub fn get_label(&self) -> u32 {
            u32::from_be_bytes([
                0x0,
                self.buf.read(LABEL_OFFSET),
                self.buf.read(LABEL_OFFSET + 1),
                self.buf.read(LABEL_OFFSET + 2),
            ]) >> 4
        }

        #[must_use]
        pub fn get_exp(&self) -> u8 {
            (self.buf.read(EXP_OFFSET) & 0x0e) >> 1
        }

        #[must_use]
        pub fn get_bos(&self) -> u8 {
            self.buf.read(BOS_OFFSET) & 0x01
        }

        #[must_use]
        pub fn get_ttl(&self) -> u8 {
            self.buf.read(TTL_OFFSET)
        }

        pub fn set_label(&mut self, val: u32) {
            let bytes = (val << 4).to_be_bytes();
            *self.buf.write(LABEL_OFFSET) = bytes[1];
            *self.buf.write(LABEL_OFFSET + 1) = bytes[2];
            *self.buf.write(LABEL_OFFSET + 2) =
                (self.buf.read(LABEL_OFFSET + 2) & 0x0f) | (bytes[3] & 0xf0);
        }

        pub fn set_exp(&mut self, exp: u8) {
            *self.buf.write(EXP_OFFSET) = (self.buf.read(EXP_OFFSET) & 0xf1) | ((exp << 1) & 0x0e);
        }

        pub fn set_bos(&mut self, bos: u8) {
            *self.buf.write(BOS_OFFSET) = (self.buf.read(BOS_OFFSET) & 0xfe) | (bos & 0x01);
        }

        pub fn set_ttl(&mut self, ttl: u8) {
            *self.buf.write(TTL_OFFSET) = ttl;
        }

        #[must_use]
        pub fn packet(&self) -> &[u8] {
            self.buf.as_slice()
        }
    }

    impl Debug for MplsLabelStackMemberPacket<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MplsLabelStackMember")
                .field("label", &self.get_label())
                .field("exp", &self.get_exp())
                .field("bos", &self.get_bos())
                .field("ttl", &self.get_ttl())
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_label() {
            let mut buf = [0_u8; MplsLabelStackMemberPacket::minimum_packet_size()];
            let mut mpls_extension = MplsLabelStackMemberPacket::new(&mut buf).unwrap();
            mpls_extension.set_label(0);
            assert_eq!(0, mpls_extension.get_label());
            assert_eq!([0x00, 0x00, 0x00], mpls_extension.packet()[0..3]);
            mpls_extension.set_label(19380);
            assert_eq!(19380, mpls_extension.get_label());
            assert_eq!([0x04, 0xbb, 0x40], mpls_extension.packet()[0..3]);
            mpls_extension.set_label(1_048_575);
            assert_eq!(1_048_575, mpls_extension.get_label());
            assert_eq!([0xff, 0xff, 0xf0], mpls_extension.packet()[0..3]);
        }

        #[test]
        fn test_exp() {
            let mut buf = [0_u8; MplsLabelStackMemberPacket::minimum_packet_size()];
            let mut mpls_extension = MplsLabelStackMemberPacket::new(&mut buf).unwrap();
            mpls_extension.set_exp(0);
            assert_eq!(0, mpls_extension.get_exp());
            assert_eq!([0x00], mpls_extension.packet()[2..3]);
            mpls_extension.set_exp(7);
            assert_eq!(7, mpls_extension.get_exp());
            assert_eq!([0x0e], mpls_extension.packet()[2..3]);
        }

        #[test]
        fn test_bos() {
            let mut buf = [0_u8; MplsLabelStackMemberPacket::minimum_packet_size()];
            let mut mpls_extension = MplsLabelStackMemberPacket::new(&mut buf).unwrap();
            mpls_extension.set_bos(0);
            assert_eq!(0, mpls_extension.get_bos());
            assert_eq!([0x00], mpls_extension.packet()[2..3]);
            mpls_extension.set_bos(1);
            assert_eq!(1, mpls_extension.get_bos());
            assert_eq!([0x01], mpls_extension.packet()[2..3]);
        }

        #[test]
        fn test_ttl() {
            let mut buf = [0_u8; MplsLabelStackMemberPacket::minimum_packet_size()];
            let mut mpls_extension = MplsLabelStackMemberPacket::new(&mut buf).unwrap();
            mpls_extension.set_ttl(0);
            assert_eq!(0, mpls_extension.get_ttl());
            assert_eq!([0x00], mpls_extension.packet()[3..4]);
            mpls_extension.set_ttl(1);
            assert_eq!(1, mpls_extension.get_ttl());
            assert_eq!([0x01], mpls_extension.packet()[3..4]);
            mpls_extension.set_ttl(255);
            assert_eq!(255, mpls_extension.get_ttl());
            assert_eq!([0xff], mpls_extension.packet()[3..4]);
        }

        #[test]
        fn test_combined() {
            let mut buf = [0_u8; MplsLabelStackMemberPacket::minimum_packet_size()];
            let mut mpls_extension = MplsLabelStackMemberPacket::new(&mut buf).unwrap();
            mpls_extension.set_label(19380);
            mpls_extension.set_exp(0);
            mpls_extension.set_bos(1);
            mpls_extension.set_ttl(1);
            assert_eq!(19380, mpls_extension.get_label());
            assert_eq!(0, mpls_extension.get_exp());
            assert_eq!(1, mpls_extension.get_bos());
            assert_eq!(1, mpls_extension.get_ttl());
            assert_eq!([0x04, 0xbb, 0x41, 0x01], mpls_extension.packet()[0..4]);
            mpls_extension.set_label(1_048_575);
            mpls_extension.set_exp(7);
            mpls_extension.set_bos(1);
            mpls_extension.set_ttl(255);
            assert_eq!(1_048_575, mpls_extension.get_label());
            assert_eq!(7, mpls_extension.get_exp());
            assert_eq!(1, mpls_extension.get_bos());
            assert_eq!(255, mpls_extension.get_ttl());
            assert_eq!([0xff, 0xff, 0xff, 0xff], mpls_extension.packet()[0..4]);
        }

        #[test]
        fn test_view() {
            let buf = [0x04, 0xbb, 0x41, 0x01];
            let object = MplsLabelStackMemberPacket::new_view(&buf).unwrap();
            assert_eq!(19380, object.get_label());
            assert_eq!(0, object.get_exp());
            assert_eq!(1, object.get_bos());
            assert_eq!(1, object.get_ttl());
        }
    }
}

pub mod extension_splitter {
    const ICMP_ORIG_DATAGRAM_MIN_LENGTH: usize = 128;

    /// Separate an ICMP payload from ICMP extensions as defined in rfc4884.
    ///
    /// Applies to `TimeExceeded` and `DestinationUnreachable` ICMP messages only.
    #[must_use]
    pub fn split(rfc4884_length: u8, icmp_payload: &[u8]) -> (&[u8], Option<&[u8]>) {
        let orig_datagram_length = usize::from(rfc4884_length * 4);

        // TODO what to do if the claimed orig_datagram_length is bigger than the actual payload?
        // we could truncate or we can err or we could return empty?
        if orig_datagram_length > icmp_payload.len() {
            return (&[], None);
        }

        if orig_datagram_length > 0 {
            // compliant message case
            if icmp_payload.len() > orig_datagram_length {
                // extension case (untested): the icmp_payload is longer than the orig_datagram and so whatever remains must be an extension
                let extension_len = icmp_payload.len() - orig_datagram_length;
                let extension =
                    &icmp_payload[orig_datagram_length..orig_datagram_length + extension_len];
                (
                    &icmp_payload[..orig_datagram_length - extension_len],
                    Some(extension),
                )
            } else {
                (&icmp_payload[..orig_datagram_length], None)
            }
            //    "Specifically, when a TRACEROUTE application operating in non-
            //    compliant mode receives a sufficiently long ICMP message that does
            //    not specify a length attribute, it will parse for a valid extension
            //    header at a fixed location, assuming a 128-octet "original datagram"
            //    field."
            // TODO - have to include length of the extension header here?  MTR does
        } else if orig_datagram_length == 0 && icmp_payload.len() > ICMP_ORIG_DATAGRAM_MIN_LENGTH {
            // extension present, non-compliant message
            let extension_len = icmp_payload.len() - ICMP_ORIG_DATAGRAM_MIN_LENGTH;
            let extension = &icmp_payload
                [ICMP_ORIG_DATAGRAM_MIN_LENGTH..ICMP_ORIG_DATAGRAM_MIN_LENGTH + extension_len];
            (
                &icmp_payload[..icmp_payload.len() - extension_len],
                Some(extension),
            )
        } else {
            // no extension present
            (icmp_payload, None)
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::tracing::packet::icmp_extension::extension_header::ExtensionHeaderPacket;
        use crate::tracing::packet::icmp_extension::extension_object::{
            ClassNum, ClassSubType, ExtensionObjectPacket,
        };
        use crate::tracing::packet::icmp_extension::extension_structure::ExtensionsPacket;
        use crate::tracing::packet::icmp_extension::mpls_label_stack::MplsLabelStackPacket;
        use crate::tracing::packet::icmp_extension::mpls_label_stack_member::MplsLabelStackMemberPacket;
        use crate::tracing::packet::icmpv4::echo_request::EchoRequestPacket;
        use crate::tracing::packet::icmpv4::time_exceeded::TimeExceededPacket;
        use crate::tracing::packet::icmpv4::{IcmpCode, IcmpType};
        use crate::tracing::packet::ipv4::Ipv4Packet;
        use std::net::Ipv4Addr;

        // This ICMP TimeExceeded packet which contains single `MPLS` extension object with a single member.  The
        // packet does not have a `length` field and is therefore rfc4884 non-complaint.
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

            let nested_ipv4 = Ipv4Packet::new_view(&buf[8..136]).unwrap();
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

            let mpls_stack = MplsLabelStackPacket::new_view(extension_object.payload()).unwrap();
            let mpls_stack_member_bytes = mpls_stack.members().next().unwrap();
            let mpls_stack_member =
                MplsLabelStackMemberPacket::new_view(mpls_stack_member_bytes).unwrap();
            assert_eq!(19380, mpls_stack_member.get_label());
            assert_eq!(0, mpls_stack_member.get_exp());
            assert_eq!(1, mpls_stack_member.get_bos());
            assert_eq!(1, mpls_stack_member.get_ttl());
        }

        // This ICMP TimeExceeded packet does not have any ICMP extensions.  It has a rfc4884 complaint `length` field.
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
    }
}
