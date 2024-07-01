use crate::types::{Flags, Port, RoundId, Sequence, TimeToLive, TraceId};
use std::net::IpAddr;
use std::time::SystemTime;

/// Represents a network tracing probe.
///
/// A `Probe` is a packet sent across the network to trace the path to a target host.
/// It contains information such as sequence number, trace identifier, ports, and TTL.
///
/// # Examples
///
/// Creating a probe:
///
/// ```
/// use trippy_core::probe::Probe;
/// use trippy_core::types::{Flags, Port, RoundId, Sequence, TimeToLive, TraceId};
/// use std::time::SystemTime;
///
/// let probe = Probe::new(
///     Sequence(1),
///     TraceId(2),
///     Port(33434),
///     Port(33435),
///     TimeToLive(64),
///     RoundId(1),
///     SystemTime::now(),
///     Flags::empty(),
/// );
/// ```
///
/// # Errors
///
/// This struct does not directly return errors, but errors may occur when sending or receiving probes.
///
/// # Panics
///
/// This struct does not panic under normal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The sequence of the probe.
    pub sequence: Sequence,
    /// The trace identifier.
    pub identifier: TraceId,
    /// The source port (UDP/TCP only)
    pub src_port: Port,
    /// The destination port (UDP/TCP only)
    pub dest_port: Port,
    /// The TTL of the probe.
    pub ttl: TimeToLive,
    /// Which round the probe belongs to.
    pub round: RoundId,
    /// Timestamp when the probe was sent.
    pub sent: SystemTime,
    /// Probe flags.
    pub flags: Flags,
}

impl Probe {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        sequence: Sequence,
        identifier: TraceId,
        src_port: Port,
        dest_port: Port,
        ttl: TimeToLive,
        round: RoundId,
        sent: SystemTime,
        flags: Flags,
    ) -> Self {
        Self {
            sequence,
            identifier,
            src_port,
            dest_port,
            ttl,
            round,
            sent,
            flags,
        }
    }

    /// A response has been received and the probe is now complete.
    #[must_use]
    pub const fn complete(
        self,
        host: IpAddr,
        received: SystemTime,
        icmp_packet_type: IcmpPacketType,
        extensions: Option<Extensions>,
    ) -> ProbeComplete {
        ProbeComplete {
            sequence: self.sequence,
            identifier: self.identifier,
            src_port: self.src_port,
            dest_port: self.dest_port,
            ttl: self.ttl,
            round: self.round,
            sent: self.sent,
            host,
            received,
            icmp_packet_type,
            extensions,
        }
    }
}

/// Represents the completion of a probe with a response.
///
/// `ProbeComplete` is created when a probe sent across the network receives a response.
/// It contains additional information about the response such as the responding host,
/// the time the response was received, and any ICMP extensions.
///
/// # Examples
///
/// Creating a completed probe:
///
/// ```
/// use trippy_core::probe::{Probe, ProbeComplete, IcmpPacketType};
/// use trippy_core::types::{Flags, Port, RoundId, Sequence, TimeToLive, TraceId};
/// use std::net::IpAddr;
/// use std::str::FromStr;
/// use std::time::SystemTime;
///
/// let probe = Probe::new(
///     Sequence(1),
///     TraceId(2),
///     Port(33434),
///     Port(33435),
///     TimeToLive(64),
///     RoundId(1),
///     SystemTime::now(),
///     Flags::empty(),
/// );
///
/// let completed_probe = probe.complete(
///     IpAddr::from_str("192.0.2.1").unwrap(),
///     SystemTime::now(),
///     IcmpPacketType::EchoReply,
///     None,
/// );
/// ```
///
/// # Errors
///
/// This struct does not directly return errors, but errors may occur when processing probe responses.
///
/// # Panics
///
/// This struct does not panic under normal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeComplete {
    /// The sequence of the probe.
    pub sequence: Sequence,
    /// The trace identifier.
    pub identifier: TraceId,
    /// The source port (UDP/TCP only)
    pub src_port: Port,
    /// The destination port (UDP/TCP only)
    pub dest_port: Port,
    /// The TTL of the probe.
    pub ttl: TimeToLive,
    /// Which round the probe belongs to.
    pub round: RoundId,
    /// Timestamp when the probe was sent.
    pub sent: SystemTime,
    /// The host which responded to the probe.
    pub host: IpAddr,
    /// Timestamp when the response to the probe was received.
    pub received: SystemTime,
    /// The type of ICMP response packet received for the probe.
    pub icmp_packet_type: IcmpPacketType,
    /// The ICMP response extensions.
    pub extensions: Option<Extensions>,
}

/// The type of ICMP packet received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpPacketType {
    /// `TimeExceeded` packet.
    TimeExceeded(IcmpPacketCode),
    /// `EchoReply` packet.
    EchoReply(IcmpPacketCode),
    /// Unreachable packet.
    Unreachable(IcmpPacketCode),
    /// Non-ICMP response (i.e. for some `UDP` & `TCP` probes).
    NotApplicable,
}

/// The code of `TimeExceeded`, `EchoReply` and `Unreachable` ICMP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpPacketCode(pub u8);

/// The response to a probe.
#[derive(Debug, Clone)]
pub enum Response {
    TimeExceeded(ResponseData, IcmpPacketCode, Option<Extensions>),
    DestinationUnreachable(ResponseData, IcmpPacketCode, Option<Extensions>),
    EchoReply(ResponseData, IcmpPacketCode),
    TcpReply(ResponseData),
    TcpRefused(ResponseData),
}

/// The ICMP extensions for a probe response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions {
    pub extensions: Vec<Extension>,
}

/// A probe response extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    Unknown(UnknownExtension),
    Mpls(MplsLabelStack),
}

impl Default for Extension {
    fn default() -> Self {
        Self::Unknown(UnknownExtension::default())
    }
}

/// The members of a MPLS probe response extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsLabelStack {
    pub members: Vec<MplsLabelStackMember>,
}

/// A member of a MPLS probe response extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsLabelStackMember {
    pub label: u32,
    pub exp: u8,
    pub bos: u8,
    pub ttl: u8,
}

/// An unknown ICMP extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnknownExtension {
    pub class_num: u8,
    pub class_subtype: u8,
    pub bytes: Vec<u8>,
}

/// The data in the probe response.
#[derive(Debug, Clone)]
pub struct ResponseData {
    /// Timestamp of the probe response.
    pub recv: SystemTime,
    /// The `IpAddr` that responded to the probe.
    pub addr: IpAddr,
    /// Information about the sequence number of the probe response.
    pub resp_seq: ResponseSeq,
}

impl ResponseData {
    pub const fn new(recv: SystemTime, addr: IpAddr, resp_seq: ResponseSeq) -> Self {
        Self {
            recv,
            addr,
            resp_seq,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResponseSeq {
    Icmp(ResponseSeqIcmp),
    Udp(ResponseSeqUdp),
    Tcp(ResponseSeqTcp),
}

/// The data in the response to an ICMP probe.
#[derive(Debug, Clone)]
pub struct ResponseSeqIcmp {
    /// The ICMP identifier.
    pub identifier: u16,
    /// The ICMP sequence number.
    pub sequence: u16,
}

impl ResponseSeqIcmp {
    pub const fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            identifier,
            sequence,
        }
    }
}

/// The data in the response to a UDP probe.
#[derive(Debug, Clone)]
pub struct ResponseSeqUdp {
    /// The IPv4 identifier.
    ///
    /// This will be the sequence number for IPv4/Dublin.
    pub identifier: u16,
    /// The destination IP address.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub dest_addr: IpAddr,
    /// The source port.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub src_port: u16,
    /// The destination port.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub dest_port: u16,
    /// The UDP checksum.
    ///
    /// This will contain the sequence number for IPv4 and IPv6 Paris.
    pub checksum: u16,
    /// The length of the UDP payload.
    ///
    /// This payload length will be the sequence number (offset from the
    /// initial sequence number) for IPv6 Dublin.  Note that this length
    /// does not include the length of the MAGIC payload prefix.
    pub payload_len: u16,
    /// Whether the response had the MAGIC payload prefix.
    ///
    /// This will be true for IPv6 Dublin for probe responses which
    /// originated from the tracer and is used to validate the probe response.
    pub has_magic: bool,
}

impl ResponseSeqUdp {
    pub const fn new(
        identifier: u16,
        dest_addr: IpAddr,
        src_port: u16,
        dest_port: u16,
        checksum: u16,
        payload_len: u16,
        has_magic: bool,
    ) -> Self {
        Self {
            identifier,
            dest_addr,
            src_port,
            dest_port,
            checksum,
            payload_len,
            has_magic,
        }
    }
}

/// The data in the response to an TCP probe.
#[derive(Debug, Clone)]
pub struct ResponseSeqTcp {
    /// The destination IP address.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub dest_addr: IpAddr,
    /// The source port.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub src_port: u16,
    /// The destination port.
    ///
    /// This is used to validate the probe response matches the expected values.
    pub dest_port: u16,
}

impl ResponseSeqTcp {
    pub const fn new(dest_addr: IpAddr, src_port: u16, dest_port: u16) -> Self {
        Self {
            dest_addr,
            src_port,
            dest_port,
        }
    }
}

#[cfg(test)]
impl ProbeStatus {
    #[must_use]
    pub fn try_into_awaited(self) -> Option<Probe> {
        if let Self::Awaited(awaited) = self {
            Some(awaited)
        } else {
            None
        }
    }

    #[must_use]
    pub fn try_into_complete(self) -> Option<ProbeComplete> {
        if let Self::Complete(complete) = self {
            Some(complete)
        } else {
            None
        }
    }
}
