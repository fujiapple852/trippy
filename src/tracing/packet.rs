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
