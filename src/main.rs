#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate,
    clippy::struct_excessive_bools,
    clippy::cognitive_complexity,
    clippy::option_option
)]
#![deny(unsafe_code)]

use crate::backend::Trace;
use crate::config::{LogFormat, LogSpanEvents, Mode, TrippyConfig};
use crate::dns::{DnsResolver, DnsResolverConfig};
use crate::geoip::GeoIpLookup;
use crate::platform::Platform;
use anyhow::{anyhow, Error};
use clap::Parser;
use config::Args;
use frontend::TuiConfig;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing_chrome::{ChromeLayerBuilder, FlushGuard};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use trippy::tracing::{
    MultipathStrategy, PortDirection, TracerAddrFamily, TracerChannelConfig, TracerConfig,
    TracerProtocol,
};
use trippy::tracing::{PrivilegeMode, SourceAddr};

mod backend;
mod config;
mod dns;
mod frontend;
mod geoip;
mod platform;
mod report;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    Platform::acquire_privileges()?;
    let platform = Platform::discover()?;
    let cfg = TrippyConfig::try_from((args, &platform))?;
    let _guard = configure_logging(&cfg);
    let resolver = start_dns_resolver(&cfg)?;
    let geoip_lookup = create_geoip_lookup(&cfg)?;
    let traces: Vec<_> = cfg
        .targets
        .iter()
        .enumerate()
        .map(|(i, target_host)| start_tracer(&cfg, target_host, platform.pid + i as u16, &resolver))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Platform::drop_privileges()?;
    run_frontend(&cfg, resolver, geoip_lookup, traces)?;
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

fn create_geoip_lookup(cfg: &TrippyConfig) -> anyhow::Result<GeoIpLookup> {
    if let Some(path) = cfg.geoip_mmdb_file.as_ref() {
        GeoIpLookup::from_file(path)
    } else {
        Ok(GeoIpLookup::empty())
    }
}

fn configure_logging(cfg: &TrippyConfig) -> Option<FlushGuard> {
    if cfg.verbose {
        let fmt_span = match cfg.log_span_events {
            LogSpanEvents::Off => FmtSpan::NONE,
            LogSpanEvents::Active => FmtSpan::ACTIVE,
            LogSpanEvents::Full => FmtSpan::FULL,
        };
        match cfg.log_format {
            LogFormat::Compact => {
                tracing_subscriber::fmt()
                    .with_span_events(fmt_span)
                    .with_env_filter(&cfg.log_filter)
                    .compact()
                    .init();
            }
            LogFormat::Pretty => {
                tracing_subscriber::fmt()
                    .with_span_events(fmt_span)
                    .with_env_filter(&cfg.log_filter)
                    .pretty()
                    .init();
            }
            LogFormat::Json => {
                tracing_subscriber::fmt()
                    .with_span_events(fmt_span)
                    .with_env_filter(&cfg.log_filter)
                    .json()
                    .init();
            }
            LogFormat::Chrome => {
                let (chrome_layer, guard) = ChromeLayerBuilder::new()
                    .writer(std::io::stdout())
                    .include_args(true)
                    .build();
                tracing_subscriber::registry().with(chrome_layer).init();
                return Some(guard);
            }
        }
    }
    None
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
    let source_addr = match cfg.source_addr {
        None => SourceAddr::discover(target_addr, cfg.port_direction, cfg.interface.as_deref())?,
        Some(addr) => SourceAddr::validate(addr)?,
    };
    let trace_data = Arc::new(RwLock::new(Trace::new(cfg.tui_max_samples)));
    let channel_config = make_channel_config(cfg, source_addr, target_addr);
    let tracer_config = make_tracer_config(cfg, target_addr, trace_identifier)?;
    {
        let trace_data = trace_data.clone();
        thread::Builder::new()
            .name(format!("tracer-{}", tracer_config.trace_identifier.0))
            .spawn(move || {
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
    geoip_lookup: GeoIpLookup,
    traces: Vec<TraceInfo>,
) -> anyhow::Result<()> {
    match args.mode {
        Mode::Tui => frontend::run_frontend(traces, make_tui_config(args), resolver, geoip_lookup)?,
        Mode::Stream => report::run_report_stream(&traces[0])?,
        Mode::Csv => report::run_report_csv(&traces[0], args.report_cycles, &resolver)?,
        Mode::Json => report::run_report_json(&traces[0], args.report_cycles, &resolver)?,
        Mode::Pretty => report::run_report_table_pretty(&traces[0], args.report_cycles, &resolver)?,
        Mode::Markdown => report::run_report_table_md(&traces[0], args.report_cycles, &resolver)?,
        Mode::Silent => report::run_report_silent(&traces[0], args.report_cycles)?,
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
        args.multipath_strategy,
        args.port_direction,
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
) -> TracerChannelConfig {
    TracerChannelConfig::new(
        args.privilege_mode,
        args.protocol,
        args.addr_family,
        source_addr,
        target_addr,
        args.packet_size,
        args.payload_pattern,
        args.multipath_strategy,
        args.tos,
        args.icmp_extensions,
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
        args.privilege_mode,
        args.multipath_strategy,
        args.port_direction,
        args.protocol,
        args.addr_family,
        args.first_ttl,
        args.max_ttl,
        args.grace_duration,
        args.min_round_duration,
        args.max_round_duration,
        args.max_inflight,
        args.initial_sequence,
        args.read_timeout,
        args.packet_size,
        args.payload_pattern,
        args.interface.clone(),
        args.geoip_mmdb_file.clone(),
    )
}

/// Make the TUI configuration.
fn make_tui_config(args: &TrippyConfig) -> TuiConfig {
    TuiConfig::new(
        args.tui_refresh_rate,
        args.tui_preserve_screen,
        args.tui_address_mode,
        args.dns_lookup_as_info,
        args.tui_as_mode,
        args.tui_geoip_mode,
        args.tui_max_addrs,
        args.tui_max_samples,
        args.tui_theme,
        &args.tui_bindings,
    )
}

/// Information about a `Trace` needed for the Tui, stream and reports.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub data: Arc<RwLock<Trace>>,
    pub source_addr: IpAddr,
    pub target_hostname: String,
    pub target_addr: IpAddr,
    pub privilege_mode: PrivilegeMode,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub grace_duration: Duration,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub read_timeout: Duration,
    pub packet_size: u16,
    pub payload_pattern: u8,
    pub interface: Option<String>,
    pub geoip_mmdb_file: Option<String>,
}

impl TraceInfo {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        data: Arc<RwLock<Trace>>,
        source_addr: IpAddr,
        target_hostname: String,
        target_addr: IpAddr,
        privilege_mode: PrivilegeMode,
        multipath_strategy: MultipathStrategy,
        port_direction: PortDirection,
        protocol: TracerProtocol,
        addr_family: TracerAddrFamily,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        max_inflight: u8,
        initial_sequence: u16,
        read_timeout: Duration,
        packet_size: u16,
        payload_pattern: u8,
        interface: Option<String>,
        geoip_mmdb_file: Option<String>,
    ) -> Self {
        Self {
            data,
            source_addr,
            target_hostname,
            target_addr,
            privilege_mode,
            multipath_strategy,
            port_direction,
            protocol,
            addr_family,
            first_ttl,
            max_ttl,
            grace_duration,
            min_round_duration,
            max_round_duration,
            max_inflight,
            initial_sequence,
            read_timeout,
            packet_size,
            payload_pattern,
            interface,
            geoip_mmdb_file,
        }
    }
}
