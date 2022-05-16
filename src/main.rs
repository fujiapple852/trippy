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
use crate::config::{Mode, TrippyConfig};
use crate::dns::{DnsResolver, DnsResolverConfig};
use crate::frontend::TuiConfig;
use anyhow::anyhow;
use clap::Parser;
use config::Args;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use trippy::tracing::{TracerChannel, TracerConfig, TracerProtocol};

mod backend;
mod caps;
mod config;
mod dns;
mod frontend;
mod report;

fn main() -> anyhow::Result<()> {
    let pid = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
    let cfg = TrippyConfig::try_from((Args::parse(), pid))?;
    ensure_caps()?;
    let resolver = DnsResolver::start(DnsResolverConfig::new(
        cfg.dns_resolve_method,
        cfg.dns_timeout,
    ))?;
    let traces: Vec<_> = cfg
        .targets
        .iter()
        .map(|target| make_trace_info(&cfg, &resolver, target))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (i, info) in traces.iter().enumerate() {
        let trace_identifier = pid + i as u16;
        let tracer_config = make_tracer_config(&cfg, info.target_addr, trace_identifier)?;
        start_backend(tracer_config, info.data.clone())?;
    }
    drop_caps()?;
    run_frontend(&cfg, resolver, traces)?;
    Ok(())
}

/// Create a network channel in a thread and drop all capabilities.
fn start_backend(
    tracer_config: TracerConfig,
    trace_data: Arc<RwLock<Trace>>,
) -> anyhow::Result<()> {
    let channel = TracerChannel::connect(&tracer_config)?;
    thread::Builder::new()
        .name(format!("tracer-{}", tracer_config.trace_identifier.0))
        .spawn(move || {
            drop_caps().expect("failed to drop capabilities in tracer thread");
            backend::run_backend(&tracer_config, channel, trace_data).expect("backend failed");
        })?;
    Ok(())
}

/// Run the TUI, stream or report.
fn run_frontend(
    args: &TrippyConfig,
    resolver: DnsResolver,
    traces: Vec<TraceInfo>,
) -> anyhow::Result<()> {
    match args.mode {
        Mode::Tui => frontend::run_frontend(traces, make_tui_config(args), resolver)?,
        Mode::Stream => report::run_report_stream(&traces[0]),
        Mode::Csv => report::run_report_csv(&traces[0], args.report_cycles, &resolver),
        Mode::Json => report::run_report_json(&traces[0], args.report_cycles, &resolver),
        Mode::Pretty => report::run_report_table_pretty(&traces[0], args.report_cycles, &resolver),
        Mode::Markdown => report::run_report_table_md(&traces[0], args.report_cycles, &resolver),
    }
    Ok(())
}

/// Make the tracer configuration.
fn make_tracer_config(
    args: &TrippyConfig,
    target_addr: IpAddr,
    trace_identifier: u16,
) -> anyhow::Result<TracerConfig> {
    Ok(TracerConfig::new(
        target_addr,
        args.protocol,
        args.max_rounds,
        trace_identifier,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.max_inflight,
        args.initial_sequence,
        args.read_timeout,
        args.min_round_duration,
        args.max_round_duration,
        args.packet_size,
        args.payload_pattern,
        args.source_port,
        args.destination_port,
    )?)
}

/// Make the per-trace information.
fn make_trace_info(
    args: &TrippyConfig,
    resolver: &DnsResolver,
    target: &str,
) -> anyhow::Result<TraceInfo> {
    let target_addr: IpAddr = resolver
        .lookup(target)
        .map_err(|e| anyhow!("failed to resolve target: {} ({})", target, e))?
        .into_iter()
        .find(|addr| matches!(addr, IpAddr::V4(_)))
        .unwrap();
    let trace_data = Arc::new(RwLock::new(Trace::new(args.tui_max_samples)));
    Ok(TraceInfo::new(
        trace_data,
        target.to_string(),
        target_addr,
        args.destination_port,
        args.protocol,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.min_round_duration,
    ))
}

/// Make the TUI configuration.
fn make_tui_config(args: &TrippyConfig) -> TuiConfig {
    TuiConfig::new(
        args.tui_refresh_rate,
        args.tui_preserve_screen,
        args.tui_address_mode,
        args.dns_lookup_as_info,
        args.max_addrs,
        args.tui_max_samples,
    )
}

/// Information about a `Trace` needed for the Tui, stream and reports.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub data: Arc<RwLock<Trace>>,
    pub target_hostname: String,
    pub target_addr: IpAddr,
    pub target_port: u16,
    pub protocol: TracerProtocol,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub grace_duration: Duration,
    pub min_round_duration: Duration,
}

impl TraceInfo {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        data: Arc<RwLock<Trace>>,
        target_hostname: String,
        target_addr: IpAddr,
        target_port: u16,
        protocol: TracerProtocol,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        min_round_duration: Duration,
    ) -> Self {
        Self {
            data,
            target_hostname,
            target_addr,
            target_port,
            protocol,
            first_ttl,
            max_ttl,
            grace_duration,
            min_round_duration,
        }
    }
}
