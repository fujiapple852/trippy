mod buffer;

/// Functions for calculating network checksums.
pub mod checksum;

/// `ICMPv4` packets.
pub mod icmpv4;

/// `ICMPv6` packets.
pub mod icmpv6;

/// `ICMP` extensions.
pub mod icmp_extension;

/// `IPv4` packets.
pub mod ipv4;

/// `IPv6` packets.
pub mod ipv6;

/// `UDP` packets.
pub mod udp;

/// `TCP` packets.
pub mod tcp;

fn fmt_payload(bytes: &[u8]) -> String {
    use itertools::Itertools as _;
    format!("{:02x}", bytes.iter().format(" "))
}

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
    #[must_use]
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

impl From<u8> for IpProtocol {
    fn from(id: u8) -> Self {
        match id {
            1 => Self::Icmp,
            58 => Self::IcmpV6,
            17 => Self::Udp,
            6 => Self::Tcp,
            p => Self::Other(p),
        }
    }
}
