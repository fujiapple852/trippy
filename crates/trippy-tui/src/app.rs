use crate::config::{LogFormat, LogSpanEvents, Mode, TrippyConfig};
use crate::frontend::TuiConfig;
use crate::geoip::GeoIpLookup;
use crate::locale::set_locale;
use crate::{frontend, report};
use anyhow::{anyhow, Error};
use std::net::IpAddr;
use tracing_chrome::{ChromeLayerBuilder, FlushGuard};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use trippy_core::{Builder, Tracer};
use trippy_dns::{DnsResolver, Resolver};
use trippy_privilege::Privilege;

/// Run the trippy application.
pub fn run_trippy(cfg: &TrippyConfig, pid: u16) -> anyhow::Result<()> {
    set_locale(cfg.tui_locale.as_deref());
    let _guard = configure_logging(cfg);
    let resolver = start_dns_resolver(cfg)?;
    let geoip_lookup = create_geoip_lookup(cfg)?;
    let addrs = resolve_targets(cfg, &resolver)?;
    if addrs.is_empty() {
        return Err(anyhow!(
            "failed to find any valid IP addresses for {} for address family {}",
            cfg.targets.join(", "),
            cfg.addr_family,
        ));
    }
    let traces = start_tracers(cfg, &addrs, pid)?;
    Privilege::drop_privileges()?;
    run_frontend(cfg, resolver, geoip_lookup, traces)
}

/// Start all tracers.
fn start_tracers(
    cfg: &TrippyConfig,
    addrs: &[TargetInfo],
    pid: u16,
) -> anyhow::Result<Vec<TraceInfo>> {
    addrs
        .iter()
        .enumerate()
        .map(|(i, TargetInfo { hostname, addr })| {
            start_tracer(cfg, hostname, *addr, pid + i as u16)
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

/// Start a tracer to a given target.
fn start_tracer(
    cfg: &TrippyConfig,
    target_host: &str,
    target_addr: IpAddr,
    trace_identifier: u16,
) -> Result<TraceInfo, Error> {
    let (tracer, _) = Builder::new(target_addr)
        .interface(cfg.interface.clone())
        .source_addr(cfg.source_addr)
        .privilege_mode(cfg.privilege_mode)
        .protocol(cfg.protocol)
        .packet_size(cfg.packet_size)
        .payload_pattern(cfg.payload_pattern)
        .tos(cfg.tos)
        .icmp_extension_parse_mode(cfg.icmp_extension_parse_mode)
        .read_timeout(cfg.read_timeout)
        .tcp_connect_timeout(cfg.min_round_duration)
        .trace_identifier(trace_identifier)
        .max_rounds(cfg.max_rounds)
        .first_ttl(cfg.first_ttl)
        .max_ttl(cfg.max_ttl)
        .grace_duration(cfg.grace_duration)
        .max_inflight(cfg.max_inflight)
        .initial_sequence(cfg.initial_sequence)
        .multipath_strategy(cfg.multipath_strategy)
        .port_direction(cfg.port_direction)
        .min_round_duration(cfg.min_round_duration)
        .max_round_duration(cfg.max_round_duration)
        .max_flows(cfg.max_flows())
        .max_samples(cfg.max_samples)
        .drop_privileges(true)
        .build()?
        .spawn()?;
    Ok(make_trace_info(tracer, target_host.to_string()))
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
        Mode::Stream => report::stream::report(&traces[0], &resolver)?,
        Mode::Csv => report::csv::report(&traces[0], args.report_cycles, &resolver)?,
        Mode::Json => report::json::report(&traces[0], args.report_cycles, &resolver)?,
        Mode::Pretty => report::table::report_pretty(&traces[0], args.report_cycles, &resolver)?,
        Mode::Markdown => report::table::report_md(&traces[0], args.report_cycles, &resolver)?,
        Mode::Dot => report::dot::report(&traces[0], args.report_cycles)?,
        Mode::Flows => report::flows::report(&traces[0], args.report_cycles)?,
        Mode::Silent => report::silent::report(&traces[0], args.report_cycles)?,
    }
    Ok(())
}

/// Resolve targets.
fn resolve_targets(cfg: &TrippyConfig, resolver: &DnsResolver) -> anyhow::Result<Vec<TargetInfo>> {
    cfg.targets
        .iter()
        .flat_map(|target| match resolver.lookup(target) {
            Ok(addrs) => addrs
                .into_iter()
                .enumerate()
                .take_while(|(i, _)| if cfg.dns_resolve_all { true } else { *i == 0 })
                .map(|(i, addr)| {
                    let hostname = if cfg.dns_resolve_all {
                        format!("{} [{}]", target, i + 1)
                    } else {
                        target.to_string()
                    };
                    Ok(TargetInfo { hostname, addr })
                })
                .collect::<Vec<_>>()
                .into_iter(),
            Err(e) => {
                vec![Err(anyhow!("failed to resolve target: {} ({})", target, e))].into_iter()
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

/// Start the DNS resolver.
fn start_dns_resolver(cfg: &TrippyConfig) -> anyhow::Result<DnsResolver> {
    Ok(DnsResolver::start(trippy_dns::Config::new(
        cfg.dns_resolve_method,
        cfg.addr_family,
        cfg.dns_timeout,
        cfg.dns_ttl,
    ))?)
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

/// Make the TUI configuration.
fn make_tui_config(args: &TrippyConfig) -> TuiConfig {
    TuiConfig::new(
        args.tui_refresh_rate,
        args.tui_privacy,
        args.tui_privacy_max_ttl,
        args.tui_preserve_screen,
        args.tui_address_mode,
        args.dns_lookup_as_info,
        args.tui_as_mode,
        args.tui_icmp_extension_mode,
        args.tui_geoip_mode,
        args.tui_max_addrs,
        args.tui_theme,
        &args.tui_bindings,
        &args.tui_custom_columns,
        args.geoip_mmdb_file.clone(),
        args.dns_resolve_all,
    )
}

/// Make the per-trace information.
const fn make_trace_info(tracer: Tracer, target: String) -> TraceInfo {
    TraceInfo::new(tracer, target)
}

/// Information about a `Trace` needed for the Tui, stream and reports.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub data: Tracer,
    pub target_hostname: String,
}

impl TraceInfo {
    #[must_use]
    pub const fn new(data: Tracer, target_hostname: String) -> Self {
        Self {
            data,
            target_hostname,
        }
    }
}

/// Information about a tracing target.
#[derive(Debug, Clone)]
struct TargetInfo {
    pub hostname: String,
    pub addr: IpAddr,
}
