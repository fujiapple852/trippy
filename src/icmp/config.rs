use crate::icmp::tracer::{MaxInflight, PacketSize, PayloadPattern, TimeToLive, TraceId};
use std::net::IpAddr;
use std::time::Duration;

/// TODO
#[derive(Debug, Copy, Clone)]
pub struct IcmpTracerConfig {
    pub target_addr: IpAddr,
    pub trace_identifier: TraceId,
    pub first_ttl: TimeToLive,
    pub max_ttl: TimeToLive,
    pub grace_duration: Duration,
    pub max_inflight: MaxInflight,
    pub read_timeout: Duration,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
}

impl IcmpTracerConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        target_addr: IpAddr,
        trace_identifier: u16,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        max_inflight: u8,
        read_timeout: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        packet_size: u16,
        payload_pattern: u8,
    ) -> Self {
        Self {
            target_addr,
            trace_identifier: TraceId::from(trace_identifier),
            first_ttl: TimeToLive::from(first_ttl),
            max_ttl: TimeToLive::from(max_ttl),
            grace_duration,
            max_inflight: MaxInflight::from(max_inflight),
            read_timeout,
            min_round_duration,
            max_round_duration,
            packet_size: PacketSize::from(packet_size),
            payload_pattern: PayloadPattern::from(payload_pattern),
        }
    }
}
