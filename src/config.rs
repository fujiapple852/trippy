use crate::platform::Platform;
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
use trippy::dns::ResolveMethod;
use trippy::tracing::{
    MultipathStrategy, PortDirection, PrivilegeMode, TracerAddrFamily, TracerProtocol,
};

mod binding;
mod cmd;
mod columns;
mod constants;
mod file;
mod theme;

use crate::config::cmd::{Commands, CommonArgs, DotArgs, FlowsArgs, ReportArgs, TuiArgs};
pub use binding::{TuiBindings, TuiKeyBinding};
pub use cmd::Args;
pub use columns::{TuiColumn, TuiColumns};
pub use constants::MAX_HOPS;
pub use theme::{TuiColor, TuiTheme};

/// The tool mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportType {
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressFamily {
    /// Internet Protocol V4
    Ipv4,
    /// Internet Protocol V6
    Ipv6,
}

/// The strategy Equal-cost Multi-Path routing strategy.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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

/// How to render `icmp` extensions in the hops table.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IcmpExtensionMode {
    /// Do not show `icmp` extensions.
    Off,
    /// Show MPLS label(s) only.
    Mpls,
    /// Show full `icmp` extension data for all known extensions.
    ///
    /// For MPLS the fields shown are `label`, `ttl`, `exp` & `bos`.
    Full,
    /// Show full `icmp` extension data for all classes.
    ///
    /// This is the same as `Full`, but also shows `class`, `subtype` and
    /// `object` for unknown extensions.
    All,
}

/// How to render `GeoIp` information in the hop table.
///
/// Note that the hop details view is always shown using the `Long` representation.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsResolveMethodConfig {
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogSpanEvents {
    /// Do not display event spans.
    Off,
    /// Display enter and exit event spans.
    Active,
    /// Display all event spans.
    Full,
}

/// Fully parsed and validated configuration.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TrippyConfig {
    pub common: TrippyConfigCommon,
    pub mode: TrippyConfigMode,
}

impl TrippyConfig {
    pub fn max_rounds(&self) -> Option<usize> {
        match &self.mode {
            TrippyConfigMode::Tui(_) | TrippyConfigMode::Stream => None,
            TrippyConfigMode::Dot(cfg) => Some(cfg.report_cycles),
            TrippyConfigMode::Flows(cfg) => Some(cfg.report_cycles),
            TrippyConfigMode::Report(cfg) => Some(cfg.report_cycles),
        }
    }

    pub fn max_samples(&self) -> usize {
        match &self.mode {
            TrippyConfigMode::Tui(cfg) => cfg.tui_max_samples,
            _ => TrippyConfigTui::default().tui_max_samples,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TrippyConfigMode {
    Tui(TrippyConfigTui),
    Stream,
    Dot(TrippyConfigDot),
    Flows(TrippyConfigFlows),
    Report(TrippyConfigReport),
}

impl Default for TrippyConfigMode {
    fn default() -> Self {
        Self::Tui(TrippyConfigTui::default())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfigCommon {
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
    pub dns_resolve_method: ResolveMethod,
    pub dns_lookup_as_info: bool,
    pub privilege_mode: PrivilegeMode,
    pub dns_resolve_all: bool,
    pub geoip_mmdb_file: Option<String>,
    pub verbose: bool,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub log_span_events: LogSpanEvents,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfigTui {
    pub tui_max_samples: usize,
    pub tui_max_flows: usize,
    pub tui_preserve_screen: bool,
    pub tui_refresh_rate: Duration,
    pub tui_privacy_max_ttl: u8,
    pub tui_address_mode: AddressMode,
    pub tui_as_mode: AsMode,
    pub tui_custom_columns: TuiColumns,
    pub tui_icmp_extension_mode: IcmpExtensionMode,
    pub tui_geoip_mode: GeoIpMode,
    pub tui_max_addrs: Option<u8>,
    pub tui_theme: TuiTheme,
    pub tui_bindings: TuiBindings,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfigFlows {
    pub report_cycles: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfigDot {
    pub report_cycles: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfigReport {
    pub report_type: ReportType,
    pub report_cycles: usize,
}

impl TrippyConfig {
    pub fn from(args: Args, platform: &Platform) -> anyhow::Result<Self> {
        let cfg_file = if let Some(cfg) = &args.tui.common.config_file {
            file::read_config_file(cfg)?
        } else if let Some(cfg) = file::read_default_config_file()? {
            cfg
        } else {
            ConfigFile::default()
        };
        Self::build_config(args, cfg_file, platform)
    }

    #[allow(clippy::too_many_lines)]
    fn build_config_common(
        common: CommonArgs,
        cfg_file: ConfigFile,
        platform: &Platform,
    ) -> anyhow::Result<TrippyConfigCommon> {
        let &Platform {
            pid,
            has_privileges,
            needs_privileges,
        } = platform;
        let cfg_file_trace = cfg_file.trippy.unwrap_or_default();
        let cfg_file_strategy = cfg_file.strategy.unwrap_or_default();
        let cfg_file_tui = cfg_file.tui.unwrap_or_default();
        let cfg_file_dns = cfg_file.dns.unwrap_or_default();
        let unprivileged = cfg_layer_bool_flag(
            common.unprivileged,
            cfg_file_trace.unprivileged,
            constants::DEFAULT_UNPRIVILEGED,
        );
        let privilege_mode = if unprivileged {
            PrivilegeMode::Unprivileged
        } else {
            PrivilegeMode::Privileged
        };
        let dns_resolve_all = cfg_layer_bool_flag(
            common.dns_resolve_all,
            cfg_file_dns.dns_resolve_all,
            constants::DEFAULT_DNS_RESOLVE_ALL,
        );
        let verbose = common.verbose;
        let log_format = cfg_layer(
            common.log_format,
            cfg_file_trace.log_format,
            constants::DEFAULT_LOG_FORMAT,
        );
        let log_filter = cfg_layer(
            common.log_filter,
            cfg_file_trace.log_filter,
            String::from(constants::DEFAULT_LOG_FILTER),
        );
        let log_span_events = cfg_layer(
            common.log_span_events,
            cfg_file_trace.log_span_events,
            constants::DEFAULT_LOG_SPAN_EVENTS,
        );
        let protocol = cfg_layer(
            common.protocol,
            cfg_file_strategy.protocol,
            constants::DEFAULT_STRATEGY_PROTOCOL,
        );
        let target_port = cfg_layer_opt(common.target_port, cfg_file_strategy.target_port);
        let source_port = cfg_layer_opt(common.source_port, cfg_file_strategy.source_port);
        let source_address = cfg_layer_opt(common.source_address, cfg_file_strategy.source_address);
        let interface = cfg_layer_opt(common.interface, cfg_file_strategy.interface);
        let min_round_duration = cfg_layer(
            common.min_round_duration,
            cfg_file_strategy.min_round_duration,
            String::from(constants::DEFAULT_STRATEGY_MIN_ROUND_DURATION),
        );
        let max_round_duration = cfg_layer(
            common.max_round_duration,
            cfg_file_strategy.max_round_duration,
            String::from(constants::DEFAULT_STRATEGY_MAX_ROUND_DURATION),
        );
        let initial_sequence = cfg_layer(
            common.initial_sequence,
            cfg_file_strategy.initial_sequence,
            constants::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
        );
        let multipath_strategy_cfg = cfg_layer(
            common.multipath_strategy,
            cfg_file_strategy.multipath_strategy,
            constants::DEFAULT_STRATEGY_MULTIPATH,
        );
        let grace_duration = cfg_layer(
            common.grace_duration,
            cfg_file_strategy.grace_duration,
            String::from(constants::DEFAULT_STRATEGY_GRACE_DURATION),
        );
        let max_inflight = cfg_layer(
            common.max_inflight,
            cfg_file_strategy.max_inflight,
            constants::DEFAULT_STRATEGY_MAX_INFLIGHT,
        );
        let first_ttl = cfg_layer(
            common.first_ttl,
            cfg_file_strategy.first_ttl,
            constants::DEFAULT_STRATEGY_FIRST_TTL,
        );
        let max_ttl = cfg_layer(
            common.max_ttl,
            cfg_file_strategy.max_ttl,
            constants::DEFAULT_STRATEGY_MAX_TTL,
        );
        let packet_size = cfg_layer(
            common.packet_size,
            cfg_file_strategy.packet_size,
            constants::DEFAULT_STRATEGY_PACKET_SIZE,
        );
        let payload_pattern = cfg_layer(
            common.payload_pattern,
            cfg_file_strategy.payload_pattern,
            constants::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
        );
        let tos = cfg_layer(
            common.tos,
            cfg_file_strategy.tos,
            constants::DEFAULT_STRATEGY_TOS,
        );
        let icmp_extensions = cfg_layer_bool_flag(
            common.icmp_extensions,
            cfg_file_strategy.icmp_extensions,
            constants::DEFAULT_ICMP_EXTENSIONS,
        );
        let read_timeout = cfg_layer(
            common.read_timeout,
            cfg_file_strategy.read_timeout,
            String::from(constants::DEFAULT_STRATEGY_READ_TIMEOUT),
        );
        let dns_resolve_method_config = cfg_layer(
            common.dns_resolve_method,
            cfg_file_dns.dns_resolve_method,
            constants::DEFAULT_DNS_RESOLVE_METHOD,
        );
        let dns_lookup_as_info = cfg_layer_bool_flag(
            common.dns_lookup_as_info,
            cfg_file_dns.dns_lookup_as_info,
            constants::DEFAULT_DNS_LOOKUP_AS_INFO,
        );
        let dns_timeout = cfg_layer(
            common.dns_timeout,
            cfg_file_dns.dns_timeout,
            String::from(constants::DEFAULT_DNS_TIMEOUT),
        );
        let geoip_mmdb_file = cfg_layer_opt(common.geoip_mmdb_file, cfg_file_tui.geoip_mmdb_file);
        let protocol = match (common.udp, common.tcp, common.icmp, protocol) {
            (false, false, false, Protocol::Udp) | (true, _, _, _) => TracerProtocol::Udp,
            (false, false, false, Protocol::Tcp) | (_, true, _, _) => TracerProtocol::Tcp,
            (false, false, false, Protocol::Icmp) | (_, _, true, _) => TracerProtocol::Icmp,
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
        let addr_family = match (common.ipv4, common.ipv6, cfg_file_strategy.addr_family) {
            (false, false, None) => addr_family(constants::DEFAULT_ADDRESS_FAMILY),
            (false, false, Some(AddressFamily::Ipv4)) | (true, _, _) => TracerAddrFamily::Ipv4,
            (false, false, Some(AddressFamily::Ipv6)) | (_, true, _) => TracerAddrFamily::Ipv6,
        };
        let multipath_strategy = match (multipath_strategy_cfg, addr_family) {
            (MultipathStrategyConfig::Classic, _) => Ok(MultipathStrategy::Classic),
            (MultipathStrategyConfig::Paris, _) => Ok(MultipathStrategy::Paris),
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
        let dns_resolve_method = match dns_resolve_method_config {
            DnsResolveMethodConfig::System => ResolveMethod::System,
            DnsResolveMethodConfig::Resolv => ResolveMethod::Resolv,
            DnsResolveMethodConfig::Google => ResolveMethod::Google,
            DnsResolveMethodConfig::Cloudflare => ResolveMethod::Cloudflare,
        };
        let dns_timeout = humantime::parse_duration(&dns_timeout)?;
        validate_privilege(privilege_mode, has_privileges, needs_privileges)?;
        validate_strategy(multipath_strategy, unprivileged)?;
        validate_ttl(first_ttl, max_ttl)?;
        validate_max_inflight(max_inflight)?;
        validate_read_timeout(read_timeout)?;
        validate_round_duration(min_round_duration, max_round_duration)?;
        validate_grace_duration(grace_duration)?;
        validate_packet_size(packet_size)?;
        validate_dns(dns_resolve_method, dns_lookup_as_info)?;
        Ok(TrippyConfigCommon {
            targets: common.targets,
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
            privilege_mode,
            dns_resolve_all,
            geoip_mmdb_file,
            verbose,
            log_format,
            log_filter,
            log_span_events,
        })
    }

    fn build_config_tui(common: TuiArgs, cfg_file: ConfigFile) -> anyhow::Result<TrippyConfigTui> {
        let cfg_file_tui_bindings = cfg_file.bindings.unwrap_or_default();
        let cfg_file_tui_theme_colors = cfg_file.theme_colors.unwrap_or_default();
        let cfg_file_tui = cfg_file.tui.unwrap_or_default();
        let tui_max_samples = cfg_layer(
            common.tui_max_samples,
            cfg_file_tui.tui_max_samples,
            constants::DEFAULT_TUI_MAX_SAMPLES,
        );
        let tui_max_flows = cfg_layer(
            common.tui_max_flows,
            cfg_file_tui.tui_max_flows,
            constants::DEFAULT_TUI_MAX_FLOWS,
        );
        let tui_preserve_screen = cfg_layer_bool_flag(
            common.tui_preserve_screen,
            cfg_file_tui.tui_preserve_screen,
            constants::DEFAULT_TUI_PRESERVE_SCREEN,
        );
        let tui_refresh_rate = cfg_layer(
            common.tui_refresh_rate,
            cfg_file_tui.tui_refresh_rate,
            String::from(constants::DEFAULT_TUI_REFRESH_RATE),
        );
        let tui_privacy_max_ttl = cfg_layer(
            common.tui_privacy_max_ttl,
            cfg_file_tui.tui_privacy_max_ttl,
            constants::DEFAULT_TUI_PRIVACY_MAX_TTL,
        );
        let tui_address_mode = cfg_layer(
            common.tui_address_mode,
            cfg_file_tui.tui_address_mode,
            constants::DEFAULT_TUI_ADDRESS_MODE,
        );
        let tui_as_mode = cfg_layer(
            common.tui_as_mode,
            cfg_file_tui.tui_as_mode,
            constants::DEFAULT_TUI_AS_MODE,
        );
        let columns = cfg_layer(
            common.tui_custom_columns,
            cfg_file_tui.tui_custom_columns,
            String::from(constants::DEFAULT_CUSTOM_COLUMNS),
        );
        let tui_custom_columns = TuiColumns::try_from(columns.as_str())?;
        let tui_icmp_extension_mode = cfg_layer(
            common.tui_icmp_extension_mode,
            cfg_file_tui.tui_icmp_extension_mode,
            constants::DEFAULT_TUI_ICMP_EXTENSION_MODE,
        );
        let tui_geoip_mode = cfg_layer(
            common.tui_geoip_mode,
            cfg_file_tui.tui_geoip_mode,
            constants::DEFAULT_TUI_GEOIP_MODE,
        );
        let tui_max_addrs = cfg_layer_opt(common.tui_max_addrs, cfg_file_tui.tui_max_addrs);
        let tui_refresh_rate = humantime::parse_duration(&tui_refresh_rate)?;
        let tui_max_addrs = match tui_max_addrs {
            Some(n) if n > 0 => Some(n),
            _ => None,
        };
        validate_tui_refresh_rate(tui_refresh_rate)?;
        validate_tui_custom_columns(&tui_custom_columns)?;
        let tui_theme_items = common
            .tui_theme_colors
            .into_iter()
            .collect::<HashMap<TuiThemeItem, TuiColor>>();
        let tui_theme = TuiTheme::from((tui_theme_items, cfg_file_tui_theme_colors));
        let tui_binding_items = common
            .tui_key_bindings
            .into_iter()
            .collect::<HashMap<TuiCommandItem, TuiKeyBinding>>();
        let tui_bindings = TuiBindings::from((tui_binding_items, cfg_file_tui_bindings));
        validate_bindings(&tui_bindings)?;
        Ok(TrippyConfigTui {
            tui_max_samples,
            tui_max_flows,
            tui_preserve_screen,
            tui_refresh_rate,
            tui_privacy_max_ttl,
            tui_address_mode,
            tui_as_mode,
            tui_custom_columns,
            tui_icmp_extension_mode,
            tui_geoip_mode,
            tui_max_addrs,
            tui_theme,
            tui_bindings,
        })
    }

    fn build_config_report(
        args: &ReportArgs,
        cfg_file: ConfigFile,
    ) -> anyhow::Result<TrippyConfigReport> {
        let cfg_file_report = cfg_file.report.unwrap_or_default();
        let report_cycles = cfg_layer(
            args.report_cycles,
            cfg_file_report.report_cycles,
            constants::DEFAULT_REPORT_CYCLES,
        );
        let report_type = cfg_layer(
            args.report_type,
            cfg_file_report.report_type,
            constants::DEFAULT_REPORT_TYPE,
        );
        validate_report_cycles(report_cycles)?;
        Ok(TrippyConfigReport {
            report_type,
            report_cycles,
        })
    }

    fn build_config_flows(
        args: &FlowsArgs,
        cfg_file: ConfigFile,
    ) -> anyhow::Result<TrippyConfigFlows> {
        let cfg_file_report = cfg_file.report.unwrap_or_default();
        let report_cycles = cfg_layer(
            args.report_cycles,
            cfg_file_report.report_cycles,
            constants::DEFAULT_REPORT_CYCLES,
        );
        validate_report_cycles(report_cycles)?;
        Ok(TrippyConfigFlows { report_cycles })
    }

    fn build_config_dot(args: &DotArgs, cfg_file: ConfigFile) -> anyhow::Result<TrippyConfigDot> {
        let cfg_file_report = cfg_file.report.unwrap_or_default();
        let report_cycles = cfg_layer(
            args.report_cycles,
            cfg_file_report.report_cycles,
            constants::DEFAULT_REPORT_CYCLES,
        );
        validate_report_cycles(report_cycles)?;
        Ok(TrippyConfigDot { report_cycles })
    }

    fn build_config(args: Args, cfg_file: ConfigFile, platform: &Platform) -> anyhow::Result<Self> {
        if args.mode.is_some() {
            println!("The --mode (-m) argument has been deprecated, specify a command instead");
            process::exit(0);
        }
        Ok(match args.command {
            Some(Commands::Tui(tui)) => {
                let common =
                    Self::build_config_common(tui.common.clone(), cfg_file.clone(), platform)?;
                let tui = Self::build_config_tui(tui, cfg_file)?;
                validate_geoip(tui.tui_geoip_mode, &common.geoip_mmdb_file)?;
                validate_multi(common.protocol, &common.targets, common.dns_resolve_all)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Tui(tui),
                }
            }
            Some(Commands::Stream(stream)) => {
                let common = Self::build_config_common(stream.common, cfg_file, platform)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Stream,
                }
            }
            Some(Commands::Dot(dot)) => {
                let common =
                    Self::build_config_common(dot.common.clone(), cfg_file.clone(), platform)?;
                let dot = Self::build_config_dot(&dot, cfg_file)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Dot(dot),
                }
            }
            Some(Commands::Flows(flows)) => {
                let common =
                    Self::build_config_common(flows.common.clone(), cfg_file.clone(), platform)?;
                let flows = Self::build_config_flows(&flows, cfg_file)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Flows(flows),
                }
            }
            Some(Commands::Report(dot)) => {
                let common =
                    Self::build_config_common(dot.common.clone(), cfg_file.clone(), platform)?;
                let report = Self::build_config_report(&dot, cfg_file)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Report(report),
                }
            }
            Some(Commands::Generate(gen)) => {
                let mut cmd = Args::command();
                print_completions(gen.shell, &mut cmd);
                process::exit(0);
            }
            Some(Commands::ConfigTemplate) => {
                println!("{}", include_str!("../trippy-config-sample.toml"));
                process::exit(0);
            }
            Some(Commands::ThemeItems) => {
                println!(
                    "TUI theme color items: {}",
                    TuiThemeItem::VARIANTS.join(", ")
                );
                process::exit(0);
            }
            Some(Commands::Bindings) => {
                println!(
                    "TUI binding commands: {}",
                    TuiCommandItem::VARIANTS.join(", ")
                );
                process::exit(0);
            }
            None => {
                let common =
                    Self::build_config_common(args.tui.common.clone(), cfg_file.clone(), platform)?;
                let tui = Self::build_config_tui(args.tui, cfg_file)?;
                Self {
                    common,
                    mode: TrippyConfigMode::Tui(tui),
                }
            }
        })
    }
}

impl Default for TrippyConfigCommon {
    fn default() -> Self {
        Self {
            targets: vec![],
            protocol: protocol(constants::DEFAULT_STRATEGY_PROTOCOL),
            addr_family: addr_family(constants::DEFAULT_ADDRESS_FAMILY),
            first_ttl: constants::DEFAULT_STRATEGY_FIRST_TTL,
            max_ttl: constants::DEFAULT_STRATEGY_MAX_TTL,
            min_round_duration: duration(constants::DEFAULT_STRATEGY_MIN_ROUND_DURATION),
            max_round_duration: duration(constants::DEFAULT_STRATEGY_MAX_ROUND_DURATION),
            grace_duration: duration(constants::DEFAULT_STRATEGY_GRACE_DURATION),
            max_inflight: constants::DEFAULT_STRATEGY_MAX_INFLIGHT,
            initial_sequence: constants::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
            tos: constants::DEFAULT_STRATEGY_TOS,
            icmp_extensions: constants::DEFAULT_ICMP_EXTENSIONS,
            read_timeout: duration(constants::DEFAULT_STRATEGY_READ_TIMEOUT),
            packet_size: constants::DEFAULT_STRATEGY_PACKET_SIZE,
            payload_pattern: constants::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
            source_addr: None,
            interface: None,
            multipath_strategy: multipath_strategy(constants::DEFAULT_STRATEGY_MULTIPATH),
            port_direction: PortDirection::None,
            dns_timeout: duration(constants::DEFAULT_DNS_TIMEOUT),
            dns_resolve_method: dns_resolve_method(constants::DEFAULT_DNS_RESOLVE_METHOD),
            dns_lookup_as_info: constants::DEFAULT_DNS_LOOKUP_AS_INFO,
            privilege_mode: privilege_mode(constants::DEFAULT_UNPRIVILEGED),
            dns_resolve_all: constants::DEFAULT_DNS_RESOLVE_ALL,
            geoip_mmdb_file: None,
            verbose: false,
            log_format: constants::DEFAULT_LOG_FORMAT,
            log_filter: String::from(constants::DEFAULT_LOG_FILTER),
            log_span_events: constants::DEFAULT_LOG_SPAN_EVENTS,
        }
    }
}

impl Default for TrippyConfigTui {
    fn default() -> Self {
        Self {
            tui_max_samples: constants::DEFAULT_TUI_MAX_SAMPLES,
            tui_max_flows: constants::DEFAULT_TUI_MAX_FLOWS,
            tui_preserve_screen: constants::DEFAULT_TUI_PRESERVE_SCREEN,
            tui_refresh_rate: duration(constants::DEFAULT_TUI_REFRESH_RATE),
            tui_privacy_max_ttl: constants::DEFAULT_TUI_PRIVACY_MAX_TTL,
            tui_address_mode: constants::DEFAULT_TUI_ADDRESS_MODE,
            tui_as_mode: constants::DEFAULT_TUI_AS_MODE,
            tui_icmp_extension_mode: constants::DEFAULT_TUI_ICMP_EXTENSION_MODE,
            tui_geoip_mode: constants::DEFAULT_TUI_GEOIP_MODE,
            tui_max_addrs: None,
            tui_theme: TuiTheme::default(),
            tui_bindings: TuiBindings::default(),
            tui_custom_columns: TuiColumns::default(),
        }
    }
}

impl Default for TrippyConfigFlows {
    fn default() -> Self {
        Self {
            report_cycles: constants::DEFAULT_REPORT_CYCLES,
        }
    }
}

impl Default for TrippyConfigDot {
    fn default() -> Self {
        Self {
            report_cycles: constants::DEFAULT_REPORT_CYCLES,
        }
    }
}

impl Default for TrippyConfigReport {
    fn default() -> Self {
        Self {
            report_type: constants::DEFAULT_REPORT_TYPE,
            report_cycles: constants::DEFAULT_REPORT_CYCLES,
        }
    }
}

fn duration(duration: &str) -> Duration {
    humantime::parse_duration(duration).expect("valid duration")
}

fn protocol(protocol: Protocol) -> TracerProtocol {
    match protocol {
        Protocol::Icmp => TracerProtocol::Icmp,
        Protocol::Udp => TracerProtocol::Udp,
        Protocol::Tcp => TracerProtocol::Tcp,
    }
}

fn privilege_mode(unprivileged: bool) -> PrivilegeMode {
    if unprivileged {
        PrivilegeMode::Unprivileged
    } else {
        PrivilegeMode::Privileged
    }
}

fn dns_resolve_method(dns_resolve_method: DnsResolveMethodConfig) -> ResolveMethod {
    match dns_resolve_method {
        DnsResolveMethodConfig::System => ResolveMethod::System,
        DnsResolveMethodConfig::Resolv => ResolveMethod::Resolv,
        DnsResolveMethodConfig::Google => ResolveMethod::Google,
        DnsResolveMethodConfig::Cloudflare => ResolveMethod::Cloudflare,
    }
}

fn multipath_strategy(multipath_strategy: MultipathStrategyConfig) -> MultipathStrategy {
    match multipath_strategy {
        MultipathStrategyConfig::Classic => MultipathStrategy::Classic,
        MultipathStrategyConfig::Paris => MultipathStrategy::Paris,
        MultipathStrategyConfig::Dublin => MultipathStrategy::Dublin,
    }
}

fn addr_family(addr_family: AddressFamily) -> TracerAddrFamily {
    match addr_family {
        AddressFamily::Ipv4 => TracerAddrFamily::Ipv4,
        AddressFamily::Ipv6 => TracerAddrFamily::Ipv6,
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

fn validate_tui_custom_columns(tui_custom_columns: &TuiColumns) -> anyhow::Result<()> {
    let duplicates = tui_custom_columns.find_duplicates();
    if tui_custom_columns.0.is_empty() {
        Err(anyhow!(
            "Missing or no custom columns - The command line or config file value is blank"
        ))
    } else if duplicates.is_empty() {
        Ok(())
    } else {
        let dup_str = duplicates.iter().join(", ");
        Err(anyhow!("Duplicate custom columns: {dup_str}"))
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
fn validate_multi(
    protocol: TracerProtocol,
    targets: &[String],
    dns_resolve_all: bool,
) -> anyhow::Result<()> {
    match protocol {
        _ if targets.len() > 1 || dns_resolve_all => Err(anyhow!(
            "only a single target may be specified for this mode"
        )),
        TracerProtocol::Tcp | TracerProtocol::Udp if targets.len() > 1 || dns_resolve_all => Err(
            anyhow!("only a single target may be specified for TCP and UDP tracing"),
        ),
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
fn validate_dns(dns_resolve_method: ResolveMethod, dns_lookup_as_info: bool) -> anyhow::Result<()> {
    match dns_resolve_method {
        ResolveMethod::System if dns_lookup_as_info => Err(anyhow!(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let args = args(&["trip", "example.com"]);
        let cfg_file = ConfigFile::default();
        let platform = Platform::dummy_for_test();
        let config = TrippyConfig::build_config(args, cfg_file, &platform).unwrap();
        let expected = TrippyConfig {
            common: TrippyConfigCommon {
                targets: vec![String::from("example.com")],
                ..TrippyConfigCommon::default()
            },
            ..TrippyConfig::default()
        };
        pretty_assertions::assert_eq!(expected, config);
    }

    #[test]
    fn test_config_sample() {
        let args = args(&["trip", "example.com"]);
        let cfg_file: ConfigFile =
            toml::from_str(include_str!("../trippy-config-sample.toml")).unwrap();
        let platform = Platform::dummy_for_test();
        let config = TrippyConfig::build_config(args, cfg_file, &platform).unwrap();
        let expected = TrippyConfig {
            common: TrippyConfigCommon {
                targets: vec![String::from("example.com")],
                ..TrippyConfigCommon::default()
            },
            ..TrippyConfig::default()
        };
        pretty_assertions::assert_eq!(expected, config);
    }

    fn args(args: &[&str]) -> Args {
        use clap::Parser;
        Args::parse_from(args.iter().map(std::ffi::OsString::from))
    }
}
