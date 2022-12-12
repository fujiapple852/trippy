use crate::tracing::types::{Round, Sequence, TimeToLive};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// The state of an ICMP echo request/response
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Probe {
    /// The sequence of the probe.
    pub sequence: Sequence,
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
}

impl Probe {
    #[must_use]
    pub const fn new(sequence: Sequence, ttl: TimeToLive, round: Round, sent: SystemTime) -> Self {
        Self {
            sequence,
            ttl,
            round,
            sent: Some(sent),
            status: ProbeStatus::Awaited,
            host: None,
            received: None,
            icmp_packet_type: None,
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
    pub const fn with_status(self, status: ProbeStatus) -> Self {
        Self { status, ..self }
    }

    #[must_use]
    pub const fn with_icmp_packet_type(self, icmp_packet_type: IcmpPacketType) -> Self {
        Self {
            icmp_packet_type: Some(icmp_packet_type),
            ..self
        }
    }

    #[must_use]
    pub const fn with_host(self, host: IpAddr) -> Self {
        Self {
            host: Some(host),
            ..self
        }
    }

    #[must_use]
    pub const fn with_received(self, received: SystemTime) -> Self {
        Self {
            received: Some(received),
            ..self
        }
    }
}

/// The status of a `Echo` for a single TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The probe has not been sent.
    NotSent,
    /// The probe has been sent and we are awaiting the response.
    Awaited,
    /// The probe has been sent and a response (`EchoReply`, `DestinationUnreachable` or `TimeExceeded`) has
    /// been received.
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
#[derive(Debug, Copy, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData),
    DestinationUnreachable(ProbeResponseData),
    EchoReply(ProbeResponseData),
    TcpReply(TcpProbeResponseData),
    TcpRefused(TcpProbeResponseData),
}

/// The data in the probe response.
#[derive(Debug, Copy, Clone)]
pub struct ProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
}

impl ProbeResponseData {
    pub fn new(recv: SystemTime, addr: IpAddr, identifier: u16, sequence: u16) -> Self {
        Self {
            recv,
            addr,
            identifier,
            sequence,
        }
    }
}

/// The data in the TCP probe response.
#[derive(Debug, Copy, Clone)]
pub struct TcpProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub sequence: u16,
}

impl TcpProbeResponseData {
    pub fn new(recv: SystemTime, addr: IpAddr, sequence: u16) -> Self {
        Self {
            recv,
            addr,
            sequence,
        }
    }
}
