use anyhow::anyhow;
use binding::TuiCommandItem;
use clap::{Command, CommandFactory, ValueEnum};
use clap_complete::{generate, Generator};
use file::ConfigFile;
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use strum::VariantNames;
use theme::TuiThemeItem;
use trippy::tracing::{
    MultipathStrategy, PortDirection, PrivilegeMode, TracerAddrFamily, TracerProtocol,
};

mod binding;
mod cmd;
mod constants;
mod file;
mod theme;

use crate::platform::Platform;
pub use binding::{TuiBindings, TuiKeyBinding};
pub use cmd::Args;
pub use constants::MAX_HOPS;
pub use theme::{TuiColor, TuiTheme};

/// The tool mode.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Display interactive TUI.
    Tui,
    /// Display a continuous stream of tracing data
    Stream,
    /// Generate an pretty text table report for N cycles.
    Pretty,
    /// Generate a markdown text table report for N cycles.
    Markdown,
    /// Generate a CSV report for N cycles.
    Csv,
    /// Generate a JSON report for N cycles.
    Json,
    /// Do not generate any tracing output for N cycles.
    Silent,
}

/// The tracing protocol.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

/// The address family.
#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressFamily {
    /// Internet Protocol V4
    Ipv4,
    /// Internet Protocol V6
    Ipv6,
}

/// The strategy Equal-cost Multi-Path routing strategy.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MultipathStrategyConfig {
    /// The src or dest port is used to store the sequence number.
    Classic,
    /// The UDP `checksum` field is used to store the sequence number.
    Paris,
    /// The IP `identifier` field is used to store the sequence number.
    Dublin,
}

/// How to render the addresses.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressMode {
    /// Show IP address only.
    IP,
    /// Show reverse-lookup DNS hostname only.
    Host,
    /// Show both IP address and reverse-lookup DNS hostname.
    Both,
}

/// How to render AS information.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AsMode {
    /// Show the ASN.
    Asn,
    /// Display the AS prefix.
    Prefix,
    /// Display the country code.
    CountryCode,
    /// Display the registry name.
    Registry,
    /// Display the allocated date.
    Allocated,
    /// Display the AS name.
    Name,
}

/// How to render `GeoIp` information in the hop table.
///
/// Note that the hop details view is always shown using the `Long` representation.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeoIpMode {
    /// Do not display GeoIp data.
    Off,
    /// Show short format.
    ///
    /// The `city` name is shown, `subdivision` and `country` codes are shown, `continent` is not
    /// displayed.
    ///
    /// For example:
    ///
    /// `Los Angeles, CA, US`
    Short,
    /// Show long format.
    ///
    /// The `city`, `subdivision`, `country` and `continent` names are shown.
    ///
    /// `Los Angeles, California, United States, North America`
    Long,
    /// Show latitude and Longitude format.
    ///
    /// `lat=34.0544, long=-118.2441`
    Location,
}

/// How DNS queries will be resolved.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsResolveMethod {
    /// Resolve using the OS resolver.
    System,
    /// Resolve using the `/etc/resolv.conf` DNS configuration.
    Resolv,
    /// Resolve using the Google `8.8.8.8` DNS service.
    Google,
    /// Resolve using the Cloudflare `1.1.1.1` DNS service.
    Cloudflare,
}

/// How to format log data.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    /// Display log data in a compact format.
    Compact,
    /// Display log data in a pretty format.
    Pretty,
    /// Display log data in a json format.
    Json,
    /// Display log data in Chrome trace format.
    Chrome,
}

/// How to log event spans.
#[derive(Debug, Copy, Clone, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogSpanEvents {
    /// Do not display event spans.
    Off,
    /// Display enter and exit event spans.
    Active,
    /// Display all event spans.
    Full,
}

/// Fully parsed and validate configuration.
pub struct TrippyConfig {
    pub targets: Vec<String>,
    pub protocol: TracerProtocol,
    pub addr_family: TracerAddrFamily,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub grace_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub tos: u8,
    pub icmp_extensions: bool,
    pub read_timeout: Duration,
    pub packet_size: u16,
    pub payload_pattern: u8,
    pub source_addr: Option<IpAddr>,
    pub interface: Option<String>,
    pub multipath_strategy: MultipathStrategy,
    pub port_direction: PortDirection,
    pub dns_timeout: Duration,
    pub dns_resolve_method: DnsResolveMethod,
    pub dns_lookup_as_info: bool,
    pub tui_max_samples: usize,
    pub tui_preserve_screen: bool,
    pub tui_refresh_rate: Duration,
    pub tui_address_mode: AddressMode,
    pub tui_as_mode: AsMode,
    pub tui_geoip_mode: GeoIpMode,
    pub tui_max_addrs: Option<u8>,
    pub tui_theme: TuiTheme,
    pub tui_bindings: TuiBindings,
    pub mode: Mode,
    pub privilege_mode: PrivilegeMode,
    pub report_cycles: usize,
    pub geoip_mmdb_file: Option<String>,
    pub max_rounds: Option<usize>,
    pub verbose: bool,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub log_span_events: LogSpanEvents,
}

impl TryFrom<(Args, &Platform)> for TrippyConfig {
    type Error = anyhow::Error;

    #[allow(clippy::too_many_lines)]
    fn try_from(data: (Args, &Platform)) -> Result<Self, Self::Error> {
        let (
            args,
            &Platform {
                pid,
                has_privileges,
                needs_privileges,
            },
        ) = data;
        if args.print_tui_theme_items {
            println!(
                "TUI theme color items: {}",
                TuiThemeItem::VARIANTS.join(", ")
            );
            process::exit(0);
        }
        if args.print_tui_binding_commands {
            println!(
                "TUI binding commands: {}",
                TuiCommandItem::VARIANTS.join(", ")
            );
            process::exit(0);
        }
        if let Some(generator) = args.generate {
            let mut cmd = Args::command();
            print_completions(generator, &mut cmd);
            process::exit(0);
        }
        let cfg_file = if let Some(cfg) = args.config_file {
            file::read_config_file(cfg)?
        } else if let Some(cfg) = file::read_default_config_file()? {
            cfg
        } else {
            ConfigFile::default()
        };
        let cfg_file_trace = cfg_file.trippy.unwrap_or_default();
        let cfg_file_strategy = cfg_file.strategy.unwrap_or_default();
        let cfg_file_tui_bindings = cfg_file.bindings.unwrap_or_default();
        let cfg_file_tui_theme_colors = cfg_file.theme_colors.unwrap_or_default();
        let cfg_file_tui = cfg_file.tui.unwrap_or_default();
        let cfg_file_dns = cfg_file.dns.unwrap_or_default();
        let cfg_file_report = cfg_file.report.unwrap_or_default();
        let mode = cfg_layer(args.mode, cfg_file_trace.mode, constants::DEFAULT_MODE);
        let unprivileged = cfg_layer_bool_flag(
            args.unprivileged,
            cfg_file_trace.unprivileged,
            constants::DEFAULT_UNPRIVILEGED,
        );

        let privilege_mode = if unprivileged {
            PrivilegeMode::Unprivileged
        } else {
            PrivilegeMode::Privileged
        };

        let verbose = args.verbose;
        let log_format = cfg_layer(
            args.log_format,
            cfg_file_trace.log_format,
            constants::DEFAULT_LOG_FORMAT,
        );
        let log_filter = cfg_layer(
            args.log_filter,
            cfg_file_trace.log_filter,
            String::from(constants::DEFAULT_LOG_FILTER),
        );
        let log_span_events = cfg_layer(
            args.log_span_events,
            cfg_file_trace.log_span_events,
            constants::DEFAULT_LOG_SPAN_EVENTS,
        );
        let protocol = cfg_layer(
            args.protocol,
            cfg_file_strategy.protocol,
            constants::DEFAULT_STRATEGY_PROTOCOL,
        );
        let target_port = cfg_layer_opt(args.target_port, cfg_file_strategy.target_port);
        let source_port = cfg_layer_opt(args.source_port, cfg_file_strategy.source_port);
        let source_address = cfg_layer_opt(args.source_address, cfg_file_strategy.source_address);
        let interface = cfg_layer_opt(args.interface, cfg_file_strategy.interface);
        let min_round_duration = cfg_layer(
            args.min_round_duration,
            cfg_file_strategy.min_round_duration,
            String::from(constants::DEFAULT_STRATEGY_MIN_ROUND_DURATION),
        );
        let max_round_duration = cfg_layer(
            args.max_round_duration,
            cfg_file_strategy.max_round_duration,
            String::from(constants::DEFAULT_STRATEGY_MAX_ROUND_DURATION),
        );
        let initial_sequence = cfg_layer(
            args.initial_sequence,
            cfg_file_strategy.initial_sequence,
            constants::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
        );
        let multipath_strategy_cfg = cfg_layer(
            args.multipath_strategy,
            cfg_file_strategy.multipath_strategy,
            constants::DEFAULT_STRATEGY_MULTIPATH,
        );
        let grace_duration = cfg_layer(
            args.grace_duration,
            cfg_file_strategy.grace_duration,
            String::from(constants::DEFAULT_STRATEGY_GRACE_DURATION),
        );
        let max_inflight = cfg_layer(
            args.max_inflight,
            cfg_file_strategy.max_inflight,
            constants::DEFAULT_STRATEGY_MAX_INFLIGHT,
        );
        let first_ttl = cfg_layer(
            args.first_ttl,
            cfg_file_strategy.first_ttl,
            constants::DEFAULT_STRATEGY_FIRST_TTL,
        );
        let max_ttl = cfg_layer(
            args.max_ttl,
            cfg_file_strategy.max_ttl,
            constants::DEFAULT_STRATEGY_MAX_TTL,
        );
        let packet_size = cfg_layer(
            args.packet_size,
            cfg_file_strategy.packet_size,
            constants::DEFAULT_STRATEGY_PACKET_SIZE,
        );
        let payload_pattern = cfg_layer(
            args.payload_pattern,
            cfg_file_strategy.payload_pattern,
            constants::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
        );
        let tos = cfg_layer(
            args.tos,
            cfg_file_strategy.tos,
            constants::DEFAULT_STRATEGY_TOS,
        );

        let icmp_extensions = cfg_layer_bool_flag(
            args.icmp_extensions,
            cfg_file_strategy.icmp_extensions,
            false,
        );

        let read_timeout = cfg_layer(
            args.read_timeout,
            cfg_file_strategy.read_timeout,
            String::from(constants::DEFAULT_STRATEGY_READ_TIMEOUT),
        );
        let tui_max_samples = cfg_layer(
            args.tui_max_samples,
            cfg_file_tui.tui_max_samples,
            constants::DEFAULT_TUI_MAX_SAMPLES,
        );
        let tui_preserve_screen = cfg_layer_bool_flag(
            args.tui_preserve_screen,
            cfg_file_tui.tui_preserve_screen,
            constants::DEFAULT_TUI_PRESERVE_SCREEN,
        );
        let tui_refresh_rate = cfg_layer(
            args.tui_refresh_rate,
            cfg_file_tui.tui_refresh_rate,
            String::from(constants::DEFAULT_TUI_REFRESH_RATE),
        );
        let tui_address_mode = cfg_layer(
            args.tui_address_mode,
            cfg_file_tui.tui_address_mode,
            constants::DEFAULT_TUI_ADDRESS_MODE,
        );
        let tui_as_mode = cfg_layer(
            args.tui_as_mode,
            cfg_file_tui.tui_as_mode,
            constants::DEFAULT_TUI_AS_MODE,
        );
        let tui_geoip_mode = cfg_layer(
            args.tui_geoip_mode,
            cfg_file_tui.tui_geoip_mode,
            constants::DEFAULT_TUI_GEOIP_MODE,
        );
        let tui_max_addrs = cfg_layer_opt(args.tui_max_addrs, cfg_file_tui.tui_max_addrs);
        let dns_resolve_method = cfg_layer(
            args.dns_resolve_method,
            cfg_file_dns.dns_resolve_method,
            constants::DEFAULT_DNS_RESOLVE_METHOD,
        );
        let dns_lookup_as_info = cfg_layer_bool_flag(
            args.dns_lookup_as_info,
            cfg_file_dns.dns_lookup_as_info,
            constants::DEFAULT_DNS_LOOKUP_AS_INFO,
        );
        let dns_timeout = cfg_layer(
            args.dns_timeout,
            cfg_file_dns.dns_timeout,
            String::from(constants::DEFAULT_DNS_TIMEOUT),
        );
        let report_cycles = cfg_layer(
            args.report_cycles,
            cfg_file_report.report_cycles,
            constants::DEFAULT_REPORT_CYCLES,
        );
        let geoip_mmdb_file = cfg_layer_opt(args.geoip_mmdb_file, cfg_file_tui.geoip_mmdb_file);
        let protocol = match (args.udp, args.tcp, protocol) {
            (false, false, Protocol::Icmp) => TracerProtocol::Icmp,
            (false, false, Protocol::Udp) | (true, _, _) => TracerProtocol::Udp,
            (false, false, Protocol::Tcp) | (_, true, _) => TracerProtocol::Tcp,
        };
        let read_timeout = humantime::parse_duration(&read_timeout)?;
        let min_round_duration = humantime::parse_duration(&min_round_duration)?;
        let max_round_duration = humantime::parse_duration(&max_round_duration)?;
        let grace_duration = humantime::parse_duration(&grace_duration)?;
        let source_addr = source_address
            .as_ref()
            .map(|addr| {
                IpAddr::from_str(addr)
                    .map_err(|_| anyhow!("invalid source IP address format: {}", addr))
            })
            .transpose()?;
        let addr_family = match (args.ipv4, args.ipv6, cfg_file_strategy.addr_family) {
            (false, false, Some(AddressFamily::Ipv4) | None) | (true, _, _) => {
                TracerAddrFamily::Ipv4
            }
            (false, false, Some(AddressFamily::Ipv6)) | (_, true, _) => TracerAddrFamily::Ipv6,
        };
        let multipath_strategy = match (multipath_strategy_cfg, addr_family) {
            (MultipathStrategyConfig::Classic, _) => Ok(MultipathStrategy::Classic),
            (MultipathStrategyConfig::Paris, TracerAddrFamily::Ipv4) => {
                Ok(MultipathStrategy::Paris)
            }
            (MultipathStrategyConfig::Paris, TracerAddrFamily::Ipv6) => Err(anyhow!(
                "Paris multipath strategy not implemented for IPv6 yet!"
            )),
            (MultipathStrategyConfig::Dublin, TracerAddrFamily::Ipv4) => {
                Ok(MultipathStrategy::Dublin)
            }
            (MultipathStrategyConfig::Dublin, TracerAddrFamily::Ipv6) => Err(anyhow!(
                "Dublin multipath strategy not implemented for IPv6 yet!"
            )),
        }?;
        let port_direction = match (protocol, source_port, target_port, multipath_strategy_cfg) {
            (TracerProtocol::Icmp, _, _, _) => PortDirection::None,
            (TracerProtocol::Udp, None, None, _) => PortDirection::new_fixed_src(pid.max(1024)),
            (TracerProtocol::Udp, Some(src), None, _) => {
                validate_source_port(src)?;
                PortDirection::new_fixed_src(src)
            }
            (TracerProtocol::Tcp, None, None, _) => PortDirection::new_fixed_dest(80),
            (TracerProtocol::Tcp, Some(src), None, _) => PortDirection::new_fixed_src(src),
            (_, None, Some(dest), _) => PortDirection::new_fixed_dest(dest),
            (
                TracerProtocol::Udp,
                Some(src),
                Some(dest),
                MultipathStrategyConfig::Dublin | MultipathStrategyConfig::Paris,
            ) => {
                validate_source_port(src)?;
                PortDirection::new_fixed_both(src, dest)
            }
            (_, Some(_), Some(_), _) => {
                return Err(anyhow!(
                    "only one of source-port and target-port may be fixed (except IPv4/udp protocol with dublin or paris strategy)"
                ));
            }
        };
        let tui_refresh_rate = humantime::parse_duration(&tui_refresh_rate)?;
        let dns_timeout = humantime::parse_duration(&dns_timeout)?;
        let max_rounds = match mode {
            Mode::Stream | Mode::Tui => None,
            Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json | Mode::Silent => {
                Some(report_cycles)
            }
        };
        let tui_max_addrs = match tui_max_addrs {
            Some(n) if n > 0 => Some(n),
            _ => None,
        };
        validate_privilege(privilege_mode, has_privileges, needs_privileges)?;
        validate_logging(mode, verbose)?;
        validate_strategy(multipath_strategy, unprivileged)?;
        validate_multi(mode, protocol, &args.targets)?;
        validate_ttl(first_ttl, max_ttl)?;
        validate_max_inflight(max_inflight)?;
        validate_read_timeout(read_timeout)?;
        validate_round_duration(min_round_duration, max_round_duration)?;
        validate_grace_duration(grace_duration)?;
        validate_packet_size(packet_size)?;
        validate_tui_refresh_rate(tui_refresh_rate)?;
        validate_report_cycles(report_cycles)?;
        validate_dns(dns_resolve_method, dns_lookup_as_info)?;
        validate_geoip(tui_geoip_mode, &geoip_mmdb_file)?;
        let tui_theme_items = args
            .tui_theme_colors
            .into_iter()
            .collect::<HashMap<TuiThemeItem, TuiColor>>();
        let tui_theme = TuiTheme::from((tui_theme_items, cfg_file_tui_theme_colors));
        let tui_binding_items = args
            .tui_key_bindings
            .into_iter()
            .collect::<HashMap<TuiCommandItem, TuiKeyBinding>>();
        let tui_bindings = TuiBindings::from((tui_binding_items, cfg_file_tui_bindings));
        validate_bindings(&tui_bindings)?;
        Ok(Self {
            targets: args.targets,
            protocol,
            addr_family,
            first_ttl,
            max_ttl,
            min_round_duration,
            max_round_duration,
            grace_duration,
            max_inflight,
            initial_sequence,
            multipath_strategy,
            read_timeout,
            packet_size,
            payload_pattern,
            tos,
            icmp_extensions,
            source_addr,
            interface,
            port_direction,
            dns_timeout,
            dns_resolve_method,
            dns_lookup_as_info,
            tui_max_samples,
            tui_preserve_screen,
            tui_refresh_rate,
            tui_address_mode,
            tui_as_mode,
            tui_geoip_mode,
            tui_max_addrs,
            tui_theme,
            tui_bindings,
            mode,
            privilege_mode,
            report_cycles,
            geoip_mmdb_file,
            max_rounds,
            verbose,
            log_format,
            log_filter,
            log_span_events,
        })
    }
}

fn print_completions<G: Generator>(gen: G, cmd: &mut Command) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}

fn cfg_layer<T>(fst: Option<T>, snd: Option<T>, def: T) -> T {
    match (fst, snd) {
        (Some(val), _) | (None, Some(val)) => val,
        (None, None) => def,
    }
}

fn cfg_layer_opt<T>(fst: Option<T>, snd: Option<T>) -> Option<T> {
    match (fst, snd) {
        (Some(val), _) | (None, Some(val)) => Some(val),
        (None, None) => None,
    }
}

fn cfg_layer_bool_flag(fst: bool, snd: Option<bool>, default: bool) -> bool {
    match (fst, snd) {
        (true, _) => true,
        (false, Some(val)) => val,
        (false, None) => default,
    }
}

fn validate_privilege(
    privilege_mode: PrivilegeMode,
    has_privileges: bool,
    needs_privileges: bool,
) -> anyhow::Result<()> {
    const PRIVILEGE_URL: &str = "https://github.com/fujiapple852/trippy#privileges";
    match (privilege_mode, has_privileges, needs_privileges) {
        (PrivilegeMode::Privileged, true, _) | (PrivilegeMode::Unprivileged, _, false) => Ok(()),
        (PrivilegeMode::Privileged, false, true) => Err(anyhow!(format!(
            "privileges are required\n\nsee {} for details",
            PRIVILEGE_URL
        ))),
        (PrivilegeMode::Privileged, false, false) => Err(anyhow!(format!(
            "privileges are required (hint: try adding -u to run in unprivileged mode)\n\nsee {} for details",
            PRIVILEGE_URL
        ))),
        (PrivilegeMode::Unprivileged, false, true) => Err(anyhow!(format!(
            "unprivileged mode not supported on this platform\n\nsee {} for details",
            PRIVILEGE_URL
        ))),
        (PrivilegeMode::Unprivileged, true, true) => Err(anyhow!(format!(
            "unprivileged mode not supported on this platform (hint: process is privileged so disable unprivileged mode)\n\nsee {} for details",
            PRIVILEGE_URL
        ))),
    }
}

fn validate_logging(mode: Mode, verbose: bool) -> anyhow::Result<()> {
    if matches!(mode, Mode::Tui) && verbose {
        Err(anyhow!("cannot enable verbose logging in tui mode"))
    } else {
        Ok(())
    }
}

/// Validate the tracing strategy against the privilege mode.
fn validate_strategy(strategy: MultipathStrategy, unprivileged: bool) -> anyhow::Result<()> {
    match (strategy, unprivileged) {
        (MultipathStrategy::Dublin, true) => Err(anyhow!(
            "Dublin tracing strategy cannot be used in unprivileged mode"
        )),
        (MultipathStrategy::Paris, true) => Err(anyhow!(
            "Paris tracing strategy cannot be used in unprivileged mode"
        )),
        _ => Ok(()),
    }
}

/// We only allow multiple targets to be specified for the Tui and for `Icmp` tracing.
fn validate_multi(mode: Mode, protocol: TracerProtocol, targets: &[String]) -> anyhow::Result<()> {
    match (mode, protocol) {
        (Mode::Stream | Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json, _)
            if targets.len() > 1 =>
        {
            Err(anyhow!(
                "only a single target may be specified for this mode"
            ))
        }
        (_, TracerProtocol::Tcp | TracerProtocol::Udp) if targets.len() > 1 => Err(anyhow!(
            "only a single target may be specified for TCP and UDP tracing"
        )),
        _ => Ok(()),
    }
}

/// Validate `first_ttl` and `max_ttl`.
fn validate_ttl(first_ttl: u8, max_ttl: u8) -> anyhow::Result<()> {
    if (first_ttl as usize) < 1 || (first_ttl as usize) > MAX_HOPS {
        Err(anyhow!(
            "first-ttl ({first_ttl}) must be in the range 1..{MAX_HOPS}"
        ))
    } else if (max_ttl as usize) < 1 || (max_ttl as usize) > MAX_HOPS {
        Err(anyhow!(
            "max-ttl ({max_ttl}) must be in the range 1..{MAX_HOPS}"
        ))
    } else if first_ttl > max_ttl {
        Err(anyhow!(
            "first-ttl ({first_ttl}) must be less than or equal to max-ttl ({max_ttl})"
        ))
    } else {
        Ok(())
    }
}

/// Validate `max_inflight`.
fn validate_max_inflight(max_inflight: u8) -> anyhow::Result<()> {
    if max_inflight == 0 {
        Err(anyhow!(
            "max-inflight ({}) must be greater than zero",
            max_inflight
        ))
    } else {
        Ok(())
    }
}

/// Validate `read_timeout`.
fn validate_read_timeout(read_timeout: Duration) -> anyhow::Result<()> {
    if read_timeout < constants::MIN_READ_TIMEOUT_MS
        || read_timeout > constants::MAX_READ_TIMEOUT_MS
    {
        Err(anyhow!(
            "read-timeout ({:?}) must be between {:?} and {:?} inclusive",
            read_timeout,
            constants::MIN_READ_TIMEOUT_MS,
            constants::MAX_READ_TIMEOUT_MS
        ))
    } else {
        Ok(())
    }
}

/// Validate `min_round_duration` and `max_round_duration`.
fn validate_round_duration(
    min_round_duration: Duration,
    max_round_duration: Duration,
) -> anyhow::Result<()> {
    if min_round_duration > max_round_duration {
        Err(anyhow!(
            "max-round-duration ({:?}) must not be less than min-round-duration ({:?})",
            max_round_duration,
            min_round_duration
        ))
    } else {
        Ok(())
    }
}

/// Validate `grace_duration`.
fn validate_grace_duration(grace_duration: Duration) -> anyhow::Result<()> {
    if grace_duration < constants::MIN_GRACE_DURATION_MS
        || grace_duration > constants::MAX_GRACE_DURATION_MS
    {
        Err(anyhow!(
            "grace-duration ({:?}) must be between {:?} and {:?} inclusive",
            grace_duration,
            constants::MIN_GRACE_DURATION_MS,
            constants::MAX_GRACE_DURATION_MS
        ))
    } else {
        Ok(())
    }
}

/// Validate `packet_size`.
fn validate_packet_size(packet_size: u16) -> anyhow::Result<()> {
    if (constants::MIN_PACKET_SIZE..=constants::MAX_PACKET_SIZE).contains(&packet_size) {
        Ok(())
    } else {
        Err(anyhow!(
            "packet-size ({}) must be between {} and {} inclusive",
            packet_size,
            constants::MIN_PACKET_SIZE,
            constants::MAX_PACKET_SIZE
        ))
    }
}

/// Validate `source_port`.
fn validate_source_port(source_port: u16) -> anyhow::Result<()> {
    if source_port < 1024 {
        Err(anyhow!("source-port ({}) must be >= 1024", source_port))
    } else {
        Ok(())
    }
}

/// Validate `tui_refresh_rate`.
fn validate_tui_refresh_rate(tui_refresh_rate: Duration) -> anyhow::Result<()> {
    if tui_refresh_rate < constants::TUI_MIN_REFRESH_RATE_MS
        || tui_refresh_rate > constants::TUI_MAX_REFRESH_RATE_MS
    {
        Err(anyhow!(
            "tui-refresh-rate ({:?}) must be between {:?} and {:?} inclusive",
            tui_refresh_rate,
            constants::TUI_MIN_REFRESH_RATE_MS,
            constants::TUI_MAX_REFRESH_RATE_MS
        ))
    } else {
        Ok(())
    }
}

/// Validate `report_cycles`.
fn validate_report_cycles(report_cycles: usize) -> anyhow::Result<()> {
    if report_cycles == 0 {
        Err(anyhow!(
            "report-cycles ({}) must be greater than zero",
            report_cycles
        ))
    } else {
        Ok(())
    }
}

/// Validate `dns_resolve_method` and `dns_lookup_as_info`.
fn validate_dns(
    dns_resolve_method: DnsResolveMethod,
    dns_lookup_as_info: bool,
) -> anyhow::Result<()> {
    match dns_resolve_method {
        DnsResolveMethod::System if dns_lookup_as_info => Err(anyhow!(
            "AS lookup not supported by resolver `system` (use '-r' to choose another resolver)"
        )),
        _ => Ok(()),
    }
}

fn validate_geoip(
    tui_geoip_mode: GeoIpMode,
    geoip_mmdb_file: &Option<String>,
) -> anyhow::Result<()> {
    if matches!(
        tui_geoip_mode,
        GeoIpMode::Short | GeoIpMode::Long | GeoIpMode::Location
    ) && geoip_mmdb_file.is_none()
    {
        Err(anyhow!(
            "geoip-mmdb-file must be given for tui-geoip-mode of `{tui_geoip_mode:?}`"
        ))
    } else {
        Ok(())
    }
}

/// Validate key bindings.
fn validate_bindings(bindings: &TuiBindings) -> anyhow::Result<()> {
    let duplicates = bindings.find_duplicates();
    if duplicates.is_empty() {
        Ok(())
    } else {
        let dup_str = duplicates.iter().join(", ");
        Err(anyhow!("Duplicate key bindings: {dup_str}"))
    }
}
