use crate::tracing::error::TracerError;
use crate::tracing::packet::icmp_extension::extension_header::ExtensionHeaderPacket;
use crate::tracing::packet::icmp_extension::extension_object::{ClassNum, ExtensionObjectPacket};
use crate::tracing::packet::icmp_extension::extension_structure::ExtensionsPacket;
use crate::tracing::packet::icmp_extension::mpls_label_stack::MplsLabelStackPacket;
use crate::tracing::packet::icmp_extension::mpls_label_stack_member::MplsLabelStackMemberPacket;
use crate::tracing::probe::{
    Extension, Extensions, MplsLabelStack, MplsLabelStackMember, UnknownExtension,
};
use crate::tracing::util::Required;

/// The supported ICMP extension version number.
const ICMP_EXTENSION_VERSION: u8 = 2;

impl TryFrom<&[u8]> for Extensions {
    type Error = TracerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(ExtensionsPacket::new_view(value).req()?)
    }
}

impl TryFrom<ExtensionsPacket<'_>> for Extensions {
    type Error = TracerError;

    fn try_from(value: ExtensionsPacket<'_>) -> Result<Self, Self::Error> {
        let header = ExtensionHeaderPacket::new_view(value.header()).req()?;
        if header.get_version() != ICMP_EXTENSION_VERSION {
            return Ok(Self::default());
        }
        let extensions = value
            .objects()
            .flat_map(|obj| ExtensionObjectPacket::new_view(obj).req())
            .map(|obj| match obj.get_class_num() {
                ClassNum::MultiProtocolLabelSwitchingLabelStack => {
                    MplsLabelStackPacket::new_view(obj.payload())
                        .req()
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
                .flat_map(|member| MplsLabelStackMemberPacket::new_view(member).req())
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
