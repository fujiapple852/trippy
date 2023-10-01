use crate::tracing::types::{Port, Round, Sequence, TimeToLive, TraceId};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// The state of an ICMP echo request/response
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    pub sent: Option<SystemTime>,
    /// The status of the probe.
    pub status: ProbeStatus,
    /// The host which responded to the probe.
    pub host: Option<IpAddr>,
    /// Timestamp when the response to the probe was received.
    pub received: Option<SystemTime>,
    /// The type of ICMP response packet received for the probe.
    pub icmp_packet_type: Option<IcmpPacketType>,
    /// The ICMP response extensions.
    pub extensions: Option<Extensions>,
}

impl Probe {
    #[allow(clippy::too_many_arguments)]
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
            sent: Some(sent),
            status: ProbeStatus::Awaited,
            host: None,
            received: None,
            icmp_packet_type: None,
            extensions: None,
        }
    }

    /// The duration of this probe.
    #[must_use]
    pub fn duration(&self) -> Duration {
        match (self.sent, self.received) {
            (Some(sent), Some(recv)) => recv.duration_since(sent).unwrap_or_default(),
            (Some(sent), None) => sent.elapsed().unwrap_or_default(),
            _ => Duration::default(),
        }
    }

    #[must_use]
    pub fn with_status(self, status: ProbeStatus) -> Self {
        Self { status, ..self }
    }

    #[must_use]
    pub fn with_icmp_packet_type(self, icmp_packet_type: IcmpPacketType) -> Self {
        Self {
            icmp_packet_type: Some(icmp_packet_type),
            ..self
        }
    }

    #[must_use]
    pub fn with_host(self, host: IpAddr) -> Self {
        Self {
            host: Some(host),
            ..self
        }
    }

    #[must_use]
    pub fn with_received(self, received: SystemTime) -> Self {
        Self {
            received: Some(received),
            ..self
        }
    }

    #[must_use]
    pub fn with_extensions(self, extensions: Option<Extensions>) -> Self {
        Self { extensions, ..self }
    }
}

/// The status of a `Echo` for a single TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The probe has not been sent.
    NotSent,
    /// The probe has been sent and we are awaiting the response.
    Awaited,
    /// The probe has been sent and a response (`EchoReply`, `DestinationUnreachable` or
    /// `TimeExceeded`) has been received.
    Complete,
}

impl Default for ProbeStatus {
    fn default() -> Self {
        Self::NotSent
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Extension {
    #[default]
    Unknown,
    Mpls(MplsLabelStack),
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
    pub src_port: u16,
    pub dest_port: u16,
    pub checksum: u16,
}

impl ProbeResponseSeqUdp {
    pub fn new(identifier: u16, src_port: u16, dest_port: u16, checksum: u16) -> Self {
        Self {
            identifier,
            src_port,
            dest_port,
            checksum,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResponseSeqTcp {
    pub src_port: u16,
    pub dest_port: u16,
}

impl ProbeResponseSeqTcp {
    pub fn new(src_port: u16, dest_port: u16) -> Self {
        Self {
            src_port,
            dest_port,
        }
    }
}
