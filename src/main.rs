#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate
)]
#![forbid(unsafe_code)]

use crate::backend::Trace;
use crate::caps::{drop_caps, ensure_caps};
use crate::config::{
    validate_dns, validate_grace_duration, validate_max_inflight, validate_multi,
    validate_packet_size, validate_read_timeout, validate_report_cycles, validate_round_duration,
    validate_source_port, validate_ttl, validate_tui_refresh_rate, Mode, TraceProtocol,
};
use crate::dns::{DnsResolver, DnsResolverConfig};
use crate::frontend::{TuiConfig, TuiTraceInfo};
use crate::report::{
    run_report_csv, run_report_json, run_report_stream, run_report_table_markdown,
    run_report_table_pretty,
};
use clap::Parser;
use config::Args;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use trippy::tracing::{TracerChannel, TracerConfig};

mod backend;
mod caps;
mod config;
mod dns;
mod frontend;
mod report;

#[allow(clippy::too_many_lines)]
fn main() -> anyhow::Result<()> {
    let pid = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
    let args = Args::parse();
    let targets = args.targets;
    let protocol = match args.protocol {
        TraceProtocol::Icmp => trippy::tracing::TracerProtocol::Icmp,
        TraceProtocol::Udp => trippy::tracing::TracerProtocol::Udp,
        TraceProtocol::Tcp => trippy::tracing::TracerProtocol::Tcp,
    };
    let read_timeout = humantime::parse_duration(&args.read_timeout)?;
    let min_round_duration = humantime::parse_duration(&args.min_round_duration)?;
    let max_round_duration = humantime::parse_duration(&args.max_round_duration)?;
    let grace_duration = humantime::parse_duration(&args.grace_duration)?;
    let source_port = args.source_port.unwrap_or_else(|| pid.max(1024));
    let tui_refresh_rate = humantime::parse_duration(&args.tui_refresh_rate)?;
    let report_cycles = args.report_cycles;
    let dns_timeout = humantime::parse_duration(&args.dns_timeout)?;
    let max_rounds = match args.mode {
        Mode::Stream | Mode::Tui => None,
        Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json => Some(report_cycles),
    };
    validate_multi(args.mode, args.protocol, &targets);
    validate_ttl(args.first_ttl, args.max_ttl);
    validate_max_inflight(args.max_inflight);
    validate_read_timeout(read_timeout);
    validate_round_duration(min_round_duration, max_round_duration);
    validate_grace_duration(grace_duration);
    validate_packet_size(args.packet_size);
    validate_source_port(source_port);
    validate_tui_refresh_rate(tui_refresh_rate);
    validate_report_cycles(args.report_cycles);
    validate_dns(args.dns_resolve_method, args.dns_lookup_as_info);
    let resolver =
        DnsResolver::start(DnsResolverConfig::new(args.dns_resolve_method, dns_timeout))?;
    ensure_caps()?;
    let traces: Vec<_> = targets
        .iter()
        .map(|target| {
            let target_addr: IpAddr = resolver.lookup(target)?[0];
            let trace_data = Arc::new(RwLock::new(Trace::new(args.tui_max_samples)));
            Ok(TuiTraceInfo::new(
                trace_data,
                target.clone(),
                target_addr,
                protocol.to_string(),
                args.first_ttl,
                args.max_ttl,
                grace_duration,
                min_round_duration,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (i, info) in traces.iter().enumerate() {
        let tracer_config = TracerConfig::new(
            info.target_addr,
            protocol,
            max_rounds,
            pid + i as u16,
            args.first_ttl,
            args.max_ttl,
            grace_duration,
            args.max_inflight,
            args.initial_sequence,
            read_timeout,
            min_round_duration,
            max_round_duration,
            args.packet_size,
            args.payload_pattern,
            source_port,
        )?;
        start_backend(tracer_config, info.data.clone())?;
    }
    drop_caps()?;
    match args.mode {
        Mode::Tui => {
            let tui_config = TuiConfig::new(
                tui_refresh_rate,
                args.tui_preserve_screen,
                args.tui_address_mode,
                args.dns_lookup_as_info,
                args.tui_max_addresses_per_hop,
                args.tui_max_samples,
            );
            frontend::run_frontend(traces, tui_config, resolver)?;
        }
        Mode::Stream => run_report_stream(
            &traces[0].target_hostname,
            traces[0].target_addr,
            traces[0].min_round_duration,
            &traces[0].data,
        ),
        Mode::Csv => run_report_csv(
            &traces[0].target_hostname,
            traces[0].target_addr,
            report_cycles,
            &resolver,
            &traces[0].data,
        ),
        Mode::Json => run_report_json(
            &traces[0].target_hostname,
            traces[0].target_addr,
            report_cycles,
            &resolver,
            &traces[0].data,
        ),
        Mode::Pretty => run_report_table_pretty(report_cycles, &resolver, &traces[0].data),
        Mode::Markdown => run_report_table_markdown(report_cycles, &resolver, &traces[0].data),
    }
    Ok(())
}

/// Create the network channel and then dropping all capabilities.
fn start_backend(
    tracer_config: TracerConfig,
    trace_data: Arc<RwLock<Trace>>,
) -> anyhow::Result<()> {
    let channel = TracerChannel::new(
        tracer_config.target_addr,
        tracer_config.trace_identifier,
        tracer_config.packet_size,
        tracer_config.payload_pattern,
        tracer_config.source_port,
    )?;
    thread::Builder::new()
        .name(format!("tracer-{}", tracer_config.trace_identifier.0))
        .spawn(move || {
            drop_caps().expect("failed to drop capabilities in tracer thread");
            backend::run_backend(&tracer_config, channel, trace_data).expect("backend failed");
        })?;

    Ok(())
}
