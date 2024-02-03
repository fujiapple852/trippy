use crate::tracing::types::{Port, Round, Sequence, TimeToLive, TraceId};
use std::net::IpAddr;
use std::time::SystemTime;

/// A tracing probe.
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
}

impl Probe {
    #[must_use]
    pub const fn new(
        sequence: Sequence,
        identifier: TraceId,
        src_port: Port,
        dest_port: Port,
        ttl: TimeToLive,
        round: Round,
        sent: SystemTime,
    ) -> Self {
        Self {
            sequence,
            identifier,
            src_port,
            dest_port,
            ttl,
            round,
            sent,
        }
    }

    /// A response has been received and the probe is now complete.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpPacketType {
    /// TimeExceeded packet.
    TimeExceeded,
    /// EchoReply packet.
    EchoReply,
    /// Unreachable packet.
    Unreachable,
    /// Non-ICMP response (i.e. for some `UDP` & `TCP` probes).
    NotApplicable,
}

/// The response to a probe.
#[derive(Debug, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData, Option<Extensions>),
    DestinationUnreachable(ProbeResponseData, Option<Extensions>),
    EchoReply(ProbeResponseData),
    TcpReply(ProbeResponseData),
    TcpRefused(ProbeResponseData),
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
pub struct ProbeResponseData {
    /// Timestamp of the probe response.
    pub recv: SystemTime,
    /// The IpAddr that responded to the probe.
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

#[derive(Debug, Clone)]
pub struct ProbeResponseSeqIcmp {
    pub identifier: u16,
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

#[derive(Debug, Clone)]
pub struct ProbeResponseSeqUdp {
    pub identifier: u16,
    pub dest_addr: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub checksum: u16,
}

impl ProbeResponseSeqUdp {
    pub fn new(
        identifier: u16,
        dest_addr: IpAddr,
        src_port: u16,
        dest_port: u16,
        checksum: u16,
    ) -> Self {
        Self {
            identifier,
            dest_addr,
            src_port,
            dest_port,
            checksum,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResponseSeqTcp {
    pub dest_addr: IpAddr,
    pub src_port: u16,
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
