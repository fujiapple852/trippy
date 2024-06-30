use crate::error::Error;
use crate::probe::{Extension, Extensions, MplsLabelStack, MplsLabelStackMember, UnknownExtension};
use trippy_packet::icmp_extension::extension_header::ExtensionHeaderPacket;
use trippy_packet::icmp_extension::extension_object::{ClassNum, ExtensionObjectPacket};
use trippy_packet::icmp_extension::extension_structure::ExtensionsPacket;
use trippy_packet::icmp_extension::mpls_label_stack::MplsLabelStackPacket;
use trippy_packet::icmp_extension::mpls_label_stack_member::MplsLabelStackMemberPacket;

/// The supported ICMP extension version number.
const ICMP_EXTENSION_VERSION: u8 = 2;

impl TryFrom<&[u8]> for Extensions {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(ExtensionsPacket::new_view(value)?)
    }
}

impl TryFrom<ExtensionsPacket<'_>> for Extensions {
    type Error = Error;

    fn try_from(value: ExtensionsPacket<'_>) -> Result<Self, Self::Error> {
        let header = ExtensionHeaderPacket::new_view(value.header())?;
        if header.get_version() != ICMP_EXTENSION_VERSION {
            return Ok(Self::default());
        }
        let extensions = value
            .objects()
            .flat_map(ExtensionObjectPacket::new_view)
            .map(|obj| match obj.get_class_num() {
                ClassNum::MultiProtocolLabelSwitchingLabelStack => {
                    MplsLabelStackPacket::new_view(obj.payload())
                        .map(|mpls| Extension::Mpls(MplsLabelStack::from(mpls)))
                }
                _ => Ok(Extension::Unknown(UnknownExtension::from(obj))),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { extensions })
    }
}

impl From<MplsLabelStackPacket<'_>> for MplsLabelStack {
    fn from(value: MplsLabelStackPacket<'_>) -> Self {
        Self {
            members: value
                .members()
                .flat_map(MplsLabelStackMemberPacket::new_view)
                .map(MplsLabelStackMember::from)
                .collect(),
        }
    }
}

impl From<MplsLabelStackMemberPacket<'_>> for MplsLabelStackMember {
    fn from(value: MplsLabelStackMemberPacket<'_>) -> Self {
        Self {
            label: value.get_label(),
            exp: value.get_exp(),
            bos: value.get_bos(),
            ttl: value.get_ttl(),
        }
    }
}

impl From<ExtensionObjectPacket<'_>> for UnknownExtension {
    fn from(value: ExtensionObjectPacket<'_>) -> Self {
        Self {
            class_num: value.get_class_num().id(),
            class_subtype: value.get_class_subtype().0,
            bytes: value.payload().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert a single MPLS extension which contains two labels.
    #[test]
    fn test_convert_mpls_extensions() {
        let buf = hex_literal::hex!("20 00 96 53 00 0c 01 01 06 9f 18 01 00 00 29 ff");
        let exts = Extensions::try_from(buf.as_slice()).unwrap();
        assert_eq!(1, exts.extensions.len());
        match &exts.extensions[0] {
            Extension::Mpls(mpls) => {
                assert_eq!(2, mpls.members.len());
                assert_eq!(27121, mpls.members[0].label);
                assert_eq!(1, mpls.members[0].ttl);
                assert_eq!(4, mpls.members[0].exp);
                assert_eq!(0, mpls.members[0].bos);
                assert_eq!(2, mpls.members[1].label);
                assert_eq!(255, mpls.members[1].ttl);
                assert_eq!(4, mpls.members[1].exp);
                assert_eq!(1, mpls.members[1].bos);
            }
            Extension::Unknown(_) => panic!("expected Extension::Mpls"),
        }
    }

    /// Convert a single unknown extension.
    #[test]
    fn test_convert_unknown_extensions() {
        let buf = hex_literal::hex!("20 00 96 53 00 0c 99 01 06 9f 18 01 00 00 29 ff");
        let exts = Extensions::try_from(buf.as_slice()).unwrap();
        assert_eq!(1, exts.extensions.len());
        match &exts.extensions[0] {
            Extension::Unknown(unknown) => {
                assert_eq!(0x99, unknown.class_num);
                assert_eq!(0x01, unknown.class_subtype);
                assert_eq!(
                    hex_literal::hex!("06 9f 18 01 00 00 29 ff"),
                    unknown.bytes.as_slice()
                );
            }
            Extension::Mpls(_) => panic!("expected Extension::Unknown"),
        }
    }

    /// Convert an extension with an unknown header version.
    #[test]
    fn test_convert_unknown_version() {
        let buf = hex_literal::hex!("30 00 96 53 00 0c 99 01 06 9f 18 01 00 00 29 ff");
        let exts = Extensions::try_from(buf.as_slice()).unwrap();
        assert_eq!(0, exts.extensions.len());
    }
}
