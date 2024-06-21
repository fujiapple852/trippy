use crate::types::{Flags, Port, Round, Sequence, TimeToLive, TraceId};
use std::net::IpAddr;
use std::time::SystemTime;

/// A tracing probe.
///
/// `ProbeState` represents the current state of a probe within the tracing process.
/// It can be one of several states indicating whether the probe has been sent, skipped,
/// is awaiting a response, or has completed with a response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProbeState {
    /// The probe has not been sent.
    #[default]
    NotSent,
    /// The probe was skipped.
    Skipped,
    /// The probe has been sent and is awaiting a response.
    Awaited(Probe),
    /// The probe has been sent and a response has been received.
    Complete(ProbeComplete),
}

/// A probe that was sent and is awaiting a response.
///
/// `Probe` contains information about a probe that has been sent out and is currently
/// awaiting a response. It includes details such as the sequence number, trace identifier,
/// source and destination ports, TTL, round number, and the time the probe was sent.
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
    pub round: Round,
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
        round: Round,
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
    pub fn complete(
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

/// A probe that has been sent and a response has been received.
///
/// `ProbeComplete` represents a probe for which a response has been received. It includes
/// all the information from the original `Probe` as well as the host that responded, the time
/// the response was received, the type of ICMP response packet received, and any ICMP response
/// extensions.
///
/// Either an `EchoReply`, `DestinationUnreachable` or `TimeExceeded` has been received.
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
    pub round: Round,
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
///
/// `IcmpPacketType` enumerates the different types of ICMP packets that can be received in
/// response to a probe. It includes `TimeExceeded`, `EchoReply`, `Unreachable`, and a special
/// `NotApplicable` type for non-ICMP responses (e.g., for some UDP and TCP probes).
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
///
/// `IcmpPacketCode` represents the code field of ICMP packets, providing additional information
/// about the packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpPacketCode(pub u8);

/// The response to a probe.
///
/// `ProbeResponse` represents the different types of responses that can be received to a probe,
/// including `TimeExceeded`, `DestinationUnreachable`, `EchoReply`, `TcpReply`, and `TcpRefused`.
/// It encapsulates the response data and any relevant ICMP extensions.
#[derive(Debug, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData, IcmpPacketCode, Option<Extensions>),
    DestinationUnreachable(ProbeResponseData, IcmpPacketCode, Option<Extensions>),
    EchoReply(ProbeResponseData, IcmpPacketCode),
    TcpReply(ProbeResponseData),
    TcpRefused(ProbeResponseData),
}

/// The ICMP extensions for a probe response.
///
/// `Extensions` encapsulates the ICMP extensions that may be included in a probe response.
/// It supports both known extensions (e.g., MPLS label stacks) and unknown extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions {
    pub extensions: Vec<Extension>,
}

/// A probe response extension.
///
/// `Extension` represents a probe response extension. It can be either a known extension type
/// (e.g., `MplsLabelStack`) or an unknown extension type (`UnknownExtension`).
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
///
/// `MplsLabelStack` represents a MPLS label stack extension in a probe response. It contains
/// a list of MPLS label stack members.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsLabelStack {
    pub members: Vec<MplsLabelStackMember>,
}

/// A member of a MPLS probe response extension.
///
/// `MplsLabelStackMember` represents a single member of a MPLS label stack extension. It includes
/// the label, experimental bits (exp), bottom of stack (bos) flag, and time-to-live (ttl) value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsLabelStackMember {
    pub label: u32,
    pub exp: u8,
    pub bos: u8,
    pub ttl: u8,
}

/// An unknown ICMP extension.
///
/// `UnknownExtension` represents an unknown ICMP extension. It includes the class number,
/// class subtype, and the raw bytes of the extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnknownExtension {
    pub class_num: u8,
    pub class_subtype: u8,
    pub bytes: Vec<u8>,
}

/// The data in the probe response.
///
/// `ProbeResponseData` encapsulates the common data present in all types of probe responses,
/// including the time the response was received, the IP address of the responder, and the
/// sequence information specific to the type of probe response.
#[derive(Debug, Clone)]
pub struct ProbeResponseData {
    /// Timestamp of the probe response.
    pub recv: SystemTime,
    /// The `IpAddr` that responded to the probe.
    pub addr: IpAddr,
    /// Information about the sequence number of the probe response.
    pub resp_seq: ProbeResponseSeq,
}

impl ProbeResponseData {
    pub fn new(recv: SystemTime, addr: IpAddr, resp_seq: ProbeResponseSeq) -> Self {
        Self {
            recv,
            addr,
            resp_seq,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProbeResponseSeq {
    Icmp(ProbeResponseSeqIcmp),
    Udp(ProbeResponseSeqUdp),
    Tcp(ProbeResponseSeqTcp),
}

/// The data in the response to an ICMP probe.
///
/// `ProbeResponseSeqIcmp` contains the identifier and sequence number of the ICMP response
/// to a probe. It is used to validate the response matches the expected values.
#[derive(Debug, Clone)]
pub struct ProbeResponseSeqIcmp {
    /// The ICMP identifier.
    pub identifier: u16,
    /// The ICMP sequence number.
    pub sequence: u16,
}

impl ProbeResponseSeqIcmp {
    pub fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            identifier,
            sequence,
        }
    }
}

/// The data in the response to a UDP probe.
///
/// `ProbeResponseSeqUdp` contains information specific to the response to a UDP probe,
/// including the IPv4 identifier, destination address, source and destination ports,
/// UDP checksum, payload length, and whether the response had the MAGIC payload prefix.
#[derive(Debug, Clone)]
pub struct ProbeResponseSeqUdp {
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

impl ProbeResponseSeqUdp {
    pub fn new(
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
///
/// `ProbeResponseSeqTcp` contains information specific to the response to a TCP probe,
/// including the destination address, source and destination ports. It is used to validate
/// the probe response matches the expected values.
#[derive(Debug, Clone)]
pub struct ProbeResponseSeqTcp {
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

impl ProbeResponseSeqTcp {
    pub fn new(dest_addr: IpAddr, src_port: u16, dest_port: u16) -> Self {
        Self {
            dest_addr,
            src_port,
            dest_port,
        }
    }
}

#[cfg(test)]
impl ProbeState {
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
