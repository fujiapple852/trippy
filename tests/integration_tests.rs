use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use trippy::tracing::{CompletionReason, MultipathStrategy, PortDirection, SocketImpl, SourceAddr, Tracer, TracerAddrFamily, TracerChannel, TracerChannelConfig, TracerConfig, TracerProtocol};

#[test]
fn test_it() -> anyhow::Result<()> {
    let max_rounds = Some(1);
    let first_ttl = 1;
    let max_ttl = 30;
    let grace_duration = Duration::from_millis(50);
    let max_inflight = 20;
    let min_round_duration = Duration::from_millis(1000);
    let max_round_duration = Duration::from_millis(1000);
    let protocol = TracerProtocol::Icmp;
    let addr_family = TracerAddrFamily::Ipv4;
    let port_direction = PortDirection::None;
    let target_addr = IpAddr::V4(Ipv4Addr::new(142, 250, 187, 206));
    let source_addr = SourceAddr::discover(target_addr, port_direction, None)?;
    let identifier = 0;
    let packet_size = 28;
    let payload_pattern = 0;
    let tos = 0;
    let initial_sequence = 33000;
    let multipath_strategy = MultipathStrategy::Classic;
    let read_timeout = Duration::from_millis(50);
    let tcp_connect_timeout = Duration::from_millis(0);
    let channel_config = TracerChannelConfig::new(
        protocol,
        addr_family,
        source_addr,
        target_addr,
        packet_size,
        payload_pattern,
        multipath_strategy,
        tos,
        read_timeout,
        tcp_connect_timeout,
    );
    let tracer_config = TracerConfig::new(
        target_addr,
        protocol,
        max_rounds,
        identifier,
        first_ttl,
        max_ttl,
        grace_duration,
        max_inflight,
        initial_sequence,
        multipath_strategy,
        port_direction,
        read_timeout,
        min_round_duration,
        max_round_duration,
        packet_size,
        payload_pattern,
    )?;
    let channel = TracerChannel::<SocketImpl>::connect(&channel_config)?;
    let tracer = Tracer::new(&tracer_config, |round| {
        eprintln!("{:?}", round);
        assert_eq!(CompletionReason::TargetFound, round.reason);
        assert!(round.probes.len() > 5);
    });
    tracer.trace(channel)?;
    Ok(())
}
