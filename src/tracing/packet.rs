mod buffer;

/// ICMP packets.
pub mod icmp;

/// IPv4 packets.
pub mod ipv4;

/// UDP packets.
pub mod udp;

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
