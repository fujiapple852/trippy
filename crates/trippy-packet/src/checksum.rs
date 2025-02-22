//! Checksum implementations for ICMP & UDP over IPv4 and IPV6.
//!
//! This code is derived from [`libpnet`] which is available under the Apache 2.0 license.
//!
//! [`libpnet`]: https://github.com/libpnet/libpnet

use crate::IpProtocol;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Calculate the checksum for an `Ipv4` header.
#[must_use]
pub fn ipv4_header_checksum(data: &[u8]) -> u16 {
    checksum(data, 5)
}

/// Calculate the checksum for an `Ipv4` `ICMP` packet.
#[must_use]
pub fn icmp_ipv4_checksum(data: &[u8]) -> u16 {
    checksum(data, 1)
}

/// Calculate the checksum for an `Ipv4` `ICMP` packet.
#[must_use]
pub fn icmp_ipv6_checksum(data: &[u8], src_addr: Ipv6Addr, dest_addr: Ipv6Addr) -> u16 {
    ipv6_checksum(data, 1, src_addr, dest_addr, IpProtocol::IcmpV6)
}

/// Calculate the checksum for an `IPv4` `UDP` packet.
#[must_use]
pub fn udp_ipv4_checksum(data: &[u8], src_addr: Ipv4Addr, dest_addr: Ipv4Addr) -> u16 {
    ipv4_checksum(data, 3, src_addr, dest_addr, IpProtocol::Udp)
}

/// Calculate the checksum for an `IPv4` `TCP` packet.
#[must_use]
pub fn tcp_ipv4_checksum(data: &[u8], src_addr: Ipv4Addr, dest_addr: Ipv4Addr) -> u16 {
    ipv4_checksum(data, 8, src_addr, dest_addr, IpProtocol::Tcp)
}

/// Calculate the checksum for an `IPv6` `UDP` packet.
#[must_use]
pub fn udp_ipv6_checksum(data: &[u8], src_addr: Ipv6Addr, dest_addr: Ipv6Addr) -> u16 {
    ipv6_checksum(data, 3, src_addr, dest_addr, IpProtocol::Udp)
}

fn checksum(data: &[u8], ignore_word: usize) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let sum = sum_be_words(data, ignore_word);
    finalize_checksum(sum)
}

fn ipv4_checksum(
    data: &[u8],
    ignore_word: usize,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    next_level_protocol: IpProtocol,
) -> u16 {
    let mut sum = 0u32;
    sum += ipv4_word_sum(source);
    sum += ipv4_word_sum(destination);
    sum += u32::from(next_level_protocol.id());
    sum += data.len() as u32;
    sum += sum_be_words(data, ignore_word);
    finalize_checksum(sum)
}

fn ipv4_word_sum(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    (((u32::from(octets[0])) << 8) | u32::from(octets[1]))
        + (((u32::from(octets[2])) << 8) | u32::from(octets[3]))
}

/// Calculate the checksum for a packet built on IPv6.
fn ipv6_checksum(
    data: &[u8],
    ignore_word: usize,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_level_protocol: IpProtocol,
) -> u16 {
    let mut sum = 0u32;
    sum += ipv6_word_sum(source);
    sum += ipv6_word_sum(destination);
    sum += u32::from(next_level_protocol.id());
    sum += data.len() as u32;
    sum += sum_be_words(data, ignore_word);
    finalize_checksum(sum)
}

fn ipv6_word_sum(ip: Ipv6Addr) -> u32 {
    ip.segments().iter().map(|x| u32::from(*x)).sum()
}

fn sum_be_words(data: &[u8], ignore_word: usize) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let len = data.len();
    let mut cur_data = data;
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != ignore_word {
            sum += u32::from(u16::from_be_bytes(cur_data[0..2].try_into().unwrap()));
        }
        cur_data = &cur_data[2..];
        i += 1;
    }
    if i != ignore_word && len & 1 != 0 {
        sum += u32::from(data[len - 1]) << 8;
    }
    sum
}

const fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::str::FromStr;

    #[test]
    fn test_empty_ipv4_checksum() {
        let src_addr = Ipv4Addr::from_str("192.168.1.201").unwrap();
        let dest_addr = Ipv4Addr::from_str("142.250.66.46").unwrap();
        assert_eq!(0, ipv4_header_checksum(&[]));
        assert_eq!(0, icmp_ipv4_checksum(&[]));
        assert_eq!(27732, udp_ipv4_checksum(&[], src_addr, dest_addr));
        assert_eq!(27743, tcp_ipv4_checksum(&[], src_addr, dest_addr));
    }

    #[test]
    fn test_empty_ipv6_checksum() {
        let src_addr = Ipv6Addr::from_str("fe80::811:3f6:7601:6c3f").unwrap();
        let dest_addr = Ipv6Addr::from_str("fe80::1c8d:7d69:d0b6:8182").unwrap();
        assert_eq!(10316, icmp_ipv6_checksum(&[], src_addr, dest_addr));
        assert_eq!(10357, udp_ipv6_checksum(&[], src_addr, dest_addr));
    }

    #[test]
    fn test_odd_length() {
        assert_eq!(65535, ipv4_header_checksum(&[0x00]));
    }

    #[test]
    fn test_icmp_ipv4_checksum() {
        let bytes = [
            0x0b, 0x00, 0x88, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x54, 0xb0, 0xde,
            0x00, 0x00, 0x01, 0x11, 0x75, 0x21, 0xc0, 0xa8, 0x01, 0xc9, 0x8e, 0xfa, 0x42, 0x2e,
            0x62, 0x57, 0x81, 0x95, 0x00, 0x40, 0x87, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(35051, icmp_ipv4_checksum(&bytes));
    }

    #[test]
    fn test_icmp_ipv6_checksum() {
        let src_addr = Ipv6Addr::from_str("fe80::811:3f6:7601:6c3f").unwrap();
        let dest_addr = Ipv6Addr::from_str("fe80::1c8d:7d69:d0b6:8182").unwrap();
        let bytes = [
            0x88, 0x00, 0x73, 0x6a, 0x40, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x11, 0x03, 0xf6, 0x76, 0x01, 0x6c, 0x3f,
        ];
        assert_eq!(29546, icmp_ipv6_checksum(&bytes, src_addr, dest_addr));
    }

    #[test]
    fn test_udp_ipv4_checksum() {
        let src_addr = Ipv4Addr::from_str("192.168.1.201").unwrap();
        let dest_addr = Ipv4Addr::from_str("142.250.66.46").unwrap();
        let bytes = [
            0x62, 0x57, 0x81, 0xa8, 0x00, 0x40, 0x87, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(34772, udp_ipv4_checksum(&bytes, src_addr, dest_addr));
    }

    #[test]
    fn test_udp_ipv6_checksum() {
        let src_addr = Ipv6Addr::from_str("2406:da18:599:2d01:fa25:98be:5ab1:87a5").unwrap();
        let dest_addr = Ipv6Addr::from_str("2404:6800:4003:c02::8b").unwrap();
        let bytes = [
            0x10, 0x13, 0x80, 0xeb, 0x00, 0x2c, 0xf0, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(61454, udp_ipv6_checksum(&bytes, src_addr, dest_addr));
    }

    #[test]
    fn test_ipv4_header_checksum() {
        let bytes = hex!("45 00 0f fc 38 c0 00 00 40 01 2e 3b 0a 00 00 02 0a 00 00 01");
        assert_eq!(0x1e3f, ipv4_header_checksum(&bytes));
    }

    #[test]
    fn test_tcp_ipv4_checksum() {
        let bytes = hex!("00 50 80 ea 00 00 00 00 95 9d 2e c7 50 12 ff ff 55 cc 00 00");
        assert_eq!(
            0x55cc,
            tcp_ipv4_checksum(
                &bytes,
                Ipv4Addr::new(10, 0, 0, 103),
                Ipv4Addr::new(10, 0, 0, 1)
            )
        );
    }
}
