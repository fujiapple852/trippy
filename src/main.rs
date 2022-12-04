#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate,
    clippy::struct_excessive_bools
)]
#![forbid(unsafe_code)]
use crate::backend::Trace;
use crate::caps::{drop_caps, ensure_caps};
use crate::config::{Mode, TrippyConfig};
use crate::dns::{DnsResolver, DnsResolverConfig};
use crate::frontend::TuiConfig;
use anyhow::{anyhow, Error};
use clap::Parser;
use config::Args;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use trippy::tracing::{
    MultipathStrategy, PortDirection, TracerAddrFamily, TracerChannel, TracerChannelConfig,
    TracerConfig, TracerProtocol,
};

mod backend;
mod caps;
mod config;
mod dns;
mod frontend;
mod report;

fn main() -> anyhow::Result<()> {
    let pid = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
    let cfg = TrippyConfig::try_from((Args::parse(), pid))?;
    let resolver = start_dns_resolver(&cfg)?;
    ensure_caps()?;
    let traces: Vec<_> = cfg
        .targets
        .iter()
        .enumerate()
        .map(|(i, target_host)| start_tracer(&cfg, target_host, pid + i as u16, &resolver))
        .collect::<anyhow::Result<Vec<_>>>()?;
    drop_caps()?;
    run_frontend(&cfg, resolver, traces)?;
    Ok(())
}

/// Start the DNS resolver.
fn start_dns_resolver(cfg: &TrippyConfig) -> anyhow::Result<DnsResolver> {
    Ok(match cfg.addr_family {
        TracerAddrFamily::Ipv4 => DnsResolver::start(DnsResolverConfig::new_ipv4(
            cfg.dns_resolve_method,
            cfg.dns_timeout,
        ))?,
        TracerAddrFamily::Ipv6 => DnsResolver::start(DnsResolverConfig::new_ipv6(
            cfg.dns_resolve_method,
            cfg.dns_timeout,
        ))?,
    })
}

/// Start a tracer to a given target.
fn start_tracer(
    cfg: &TrippyConfig,
    target_host: &str,
    trace_identifier: u16,
    resolver: &DnsResolver,
) -> Result<TraceInfo, Error> {
    let target_addr: IpAddr = resolver
        .lookup(target_host)
        .map_err(|e| anyhow!("failed to resolve target: {} ({})", target_host, e))?
        .into_iter()
        .find(|addr| {
            matches!(
                (cfg.addr_family, addr),
                (TracerAddrFamily::Ipv4, IpAddr::V4(_)) | (TracerAddrFamily::Ipv6, IpAddr::V6(_))
            )
        })
        .ok_or_else(|| {
            anyhow!(
                "failed to find an {:?} address for target: {}",
                cfg.addr_family,
                target_host
            )
        })?;
    let source_addr = TracerChannel::discover_src_addr(
        cfg.addr_family,
        cfg.source_addr,
        target_addr,
        cfg.port_direction,
        cfg.interface.as_deref(),
    )?;
    let trace_data = Arc::new(RwLock::new(Trace::new(cfg.tui_max_samples)));
    let channel_config = make_channel_config(cfg, source_addr, target_addr, trace_identifier);
    let tracer_config = make_tracer_config(cfg, target_addr, trace_identifier)?;
    {
        let trace_data = trace_data.clone();
        thread::Builder::new()
            .name(format!("tracer-{}", tracer_config.trace_identifier.0))
            .spawn(move || {
                drop_caps().expect("failed to drop capabilities in tracer thread");
                backend::run_backend(&tracer_config, &channel_config, trace_data)
                    .expect("failed to run tracer backend");
            })?;
    }
    Ok(make_trace_info(
        cfg,
        trace_data,
        source_addr,
        target_host.to_string(),
        target_addr,
    ))
}

/// Run the TUI, stream or report.
fn run_frontend(
    args: &TrippyConfig,
    resolver: DnsResolver,
    traces: Vec<TraceInfo>,
) -> anyhow::Result<()> {
    match args.mode {
        Mode::Tui => frontend::run_frontend(traces, make_tui_config(args), resolver)?,
        Mode::Stream => report::run_report_stream(&traces[0])?,
        Mode::Csv => report::run_report_csv(&traces[0], args.report_cycles, &resolver)?,
        Mode::Json => report::run_report_json(&traces[0], args.report_cycles, &resolver)?,
        Mode::Pretty => report::run_report_table_pretty(&traces[0], args.report_cycles, &resolver)?,
        Mode::Markdown => report::run_report_table_md(&traces[0], args.report_cycles, &resolver)?,
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
    )?)
}

/// Make the tracer configuration.
fn make_channel_config(
    args: &TrippyConfig,
    source_addr: IpAddr,
    target_addr: IpAddr,
    trace_identifier: u16,
) -> TracerChannelConfig {
    TracerChannelConfig::new(
        args.protocol,
        args.addr_family,
        source_addr,
        target_addr,
        trace_identifier,
        args.packet_size,
        args.payload_pattern,
        args.tos,
        args.initial_sequence,
        args.multipath_strategy,
        args.port_direction,
        args.read_timeout,
        args.min_round_duration,
    )
}

/// Make the per-trace information.
fn make_trace_info(
    args: &TrippyConfig,
    trace_data: Arc<RwLock<Trace>>,
    source_addr: IpAddr,
    target: String,
    target_addr: IpAddr,
) -> TraceInfo {
    TraceInfo::new(
        trace_data,
        source_addr,
        target,
        target_addr,
        args.multipath_strategy,
        args.port_direction,
        args.protocol,
        args.addr_family,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.min_round_duration,
    )
}

/// Make the TUI configuration.
fn make_tui_config(args: &TrippyConfig) -> TuiConfig {
    TuiConfig::new(
        args.tui_refresh_rate,
        args.tui_preserve_screen,
        args.tui_address_mode,
        args.dns_lookup_as_info,
        args.tui_max_addrs,
        args.tui_max_samples,
    )
}

/// Information about a `Trace` needed for the Tui, stream and reports.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub data: Arc<RwLock<Trace>>,
    pub source_addr: IpAddr,
    pub target_hostname: String,
    pub target_addr: IpAddr,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
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
        source_addr: IpAddr,
        target_hostname: String,
        target_addr: IpAddr,
        multipath_strategy: MultipathStrategy,
        port_direction: PortDirection,
        protocol: TracerProtocol,
        addr_family: TracerAddrFamily,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        min_round_duration: Duration,
    ) -> Self {
        Self {
            data,
            source_addr,
            target_hostname,
            target_addr,
            multipath_strategy,
            port_direction,
            protocol,
            addr_family,
            first_ttl,
            max_ttl,
            grace_duration,
            min_round_duration,
        }
    }
}
