use crate::platform::Platform;
use anyhow::anyhow;
use clap::ValueEnum;
use clap_complete::Shell;
use file::ConfigFile;
use humantime::format_duration;
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use trippy::dns::{IpAddrFamily, ResolveMethod};
use trippy::tracing::{
    defaults, IcmpExtensionParseMode, MultipathStrategy, PortDirection, PrivilegeMode, Protocol,
};

mod binding;
mod cmd;
mod columns;
mod constants;
mod file;
mod theme;

pub use binding::{TuiBindings, TuiCommandItem, TuiKeyBinding};
pub use cmd::Args;
pub use columns::{TuiColumn, TuiColumns};
pub use constants::MAX_HOPS;
pub use theme::{TuiColor, TuiTheme, TuiThemeItem};

/// The tool mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
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
    /// Generate a Graphviz DOT file for N cycles.
    Dot,
    /// Display all flows.
    Flows,
    /// Do not generate any tracing output for N cycles.
    Silent,
}

/// The tracing protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolConfig {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

impl From<Protocol> for ProtocolConfig {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::Icmp => Self::Icmp,
            Protocol::Udp => Self::Udp,
            Protocol::Tcp => Self::Tcp,
        }
    }
}

/// The address family.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressFamilyConfig {
    /// Ipv4 only.
    Ipv4,
    /// Ipv6 only.
    Ipv6,
    /// Ipv6 with a fallback to Ipv4
    #[serde(rename = "ipv6-then-ipv4")]
    Ipv6ThenIpv4,
    /// Ipv4 with a fallback to Ipv6
    #[serde(rename = "ipv4-then-ipv6")]
    Ipv4ThenIpv6,
}

impl From<IpAddrFamily> for AddressFamilyConfig {
    fn from(value: IpAddrFamily) -> Self {
        match value {
            IpAddrFamily::Ipv4Only => Self::Ipv4,
            IpAddrFamily::Ipv6Only => Self::Ipv6,
            IpAddrFamily::Ipv6thenIpv4 => Self::Ipv6ThenIpv4,
            IpAddrFamily::Ipv4thenIpv6 => Self::Ipv4ThenIpv6,
        }
    }
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

impl From<MultipathStrategy> for MultipathStrategyConfig {
    fn from(value: MultipathStrategy) -> Self {
        match value {
            MultipathStrategy::Classic => Self::Classic,
            MultipathStrategy::Paris => Self::Paris,
            MultipathStrategy::Dublin => Self::Dublin,
        }
    }
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

/// The action to perform.
#[derive(Debug, Eq, PartialEq)]
pub enum TrippyAction {
    /// Run Trippy.
    Trippy(TrippyConfig),
    /// Print all TUI theme items and exit.
    PrintTuiThemeItems,
    /// Print all TUI commands that can be bound and exit.
    PrintTuiBindingCommands,
    /// Print a template toml config file and exit.
    PrintConfigTemplate,
    /// Generate shell completion and exit.
    PrintShellCompletions(Shell),
}

impl TrippyAction {
    pub fn from(args: Args, platform: &Platform) -> anyhow::Result<Self> {
        Ok(if args.print_tui_theme_items {
            Self::PrintTuiThemeItems
        } else if args.print_tui_binding_commands {
            Self::PrintTuiBindingCommands
        } else if args.print_config_template {
            Self::PrintConfigTemplate
        } else if let Some(shell) = args.generate {
            Self::PrintShellCompletions(shell)
        } else {
            Self::Trippy(TrippyConfig::from(args, platform)?)
        })
    }
}

/// Fully parsed and validated configuration.
#[derive(Debug, Eq, PartialEq)]
pub struct TrippyConfig {
    pub targets: Vec<String>,
    pub protocol: Protocol,
    pub addr_family: IpAddrFamily,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub grace_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub tos: u8,
    pub icmp_extension_parse_mode: IcmpExtensionParseMode,
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
    pub mode: Mode,
    pub privilege_mode: PrivilegeMode,
    pub dns_resolve_all: bool,
    pub report_cycles: usize,
    pub geoip_mmdb_file: Option<String>,
    pub max_rounds: Option<usize>,
    pub verbose: bool,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub log_span_events: LogSpanEvents,
}

impl TrippyConfig {
    pub fn from(args: Args, platform: &Platform) -> anyhow::Result<Self> {
        let cfg_file = if let Some(cfg) = &args.config_file {
            file::read_config_file(cfg)?
        } else if let Some(cfg) = file::read_default_config_file()? {
            cfg
        } else {
            ConfigFile::default()
        };
        Self::build_config(args, cfg_file, platform)
    }

    #[allow(clippy::too_many_lines)]
    fn build_config(args: Args, cfg_file: ConfigFile, platform: &Platform) -> anyhow::Result<Self> {
        let &Platform {
            pid,
            has_privileges,
            needs_privileges,
        } = platform;
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
            defaults::DEFAULT_PRIVILEGE_MODE.is_unprivileged(),
        );
        let privilege_mode = if unprivileged {
            PrivilegeMode::Unprivileged
        } else {
            PrivilegeMode::Privileged
        };
        let dns_resolve_all = cfg_layer_bool_flag(
            args.dns_resolve_all,
            cfg_file_dns.dns_resolve_all,
            constants::DEFAULT_DNS_RESOLVE_ALL,
        );
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
            ProtocolConfig::from(defaults::DEFAULT_STRATEGY_PROTOCOL),
        );
        let addr_family_cfg = cfg_layer(
            args.addr_family,
            cfg_file_strategy.addr_family,
            constants::DEFAULT_ADDR_FAMILY,
        );
        let target_port = cfg_layer_opt(args.target_port, cfg_file_strategy.target_port);
        let source_port = cfg_layer_opt(args.source_port, cfg_file_strategy.source_port);
        let source_address = cfg_layer_opt(args.source_address, cfg_file_strategy.source_address);
        let interface = cfg_layer_opt(args.interface, cfg_file_strategy.interface);
        let min_round_duration = cfg_layer(
            args.min_round_duration,
            cfg_file_strategy.min_round_duration,
            format_duration(defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION).to_string(),
        );
        let max_round_duration = cfg_layer(
            args.max_round_duration,
            cfg_file_strategy.max_round_duration,
            format_duration(defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION).to_string(),
        );
        let initial_sequence = cfg_layer(
            args.initial_sequence,
            cfg_file_strategy.initial_sequence,
            defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
        );
        let multipath_strategy_cfg = cfg_layer(
            args.multipath_strategy,
            cfg_file_strategy.multipath_strategy,
            MultipathStrategyConfig::from(defaults::DEFAULT_STRATEGY_MULTIPATH),
        );
        let grace_duration = cfg_layer(
            args.grace_duration,
            cfg_file_strategy.grace_duration,
            format_duration(defaults::DEFAULT_STRATEGY_GRACE_DURATION).to_string(),
        );
        let max_inflight = cfg_layer(
            args.max_inflight,
            cfg_file_strategy.max_inflight,
            defaults::DEFAULT_STRATEGY_MAX_INFLIGHT,
        );
        let first_ttl = cfg_layer(
            args.first_ttl,
            cfg_file_strategy.first_ttl,
            defaults::DEFAULT_STRATEGY_FIRST_TTL,
        );
        let max_ttl = cfg_layer(
            args.max_ttl,
            cfg_file_strategy.max_ttl,
            defaults::DEFAULT_STRATEGY_MAX_TTL,
        );
        let packet_size = cfg_layer(
            args.packet_size,
            cfg_file_strategy.packet_size,
            defaults::DEFAULT_STRATEGY_PACKET_SIZE,
        );
        let payload_pattern = cfg_layer(
            args.payload_pattern,
            cfg_file_strategy.payload_pattern,
            defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
        );
        let tos = cfg_layer(
            args.tos,
            cfg_file_strategy.tos,
            defaults::DEFAULT_STRATEGY_TOS,
        );
        let icmp_extensions = cfg_layer_bool_flag(
            args.icmp_extensions,
            cfg_file_strategy.icmp_extensions,
            defaults::DEFAULT_ICMP_EXTENSION_PARSE_MODE.is_enabled(),
        );
        let icmp_extension_parse_mode = if icmp_extensions {
            IcmpExtensionParseMode::Enabled
        } else {
            IcmpExtensionParseMode::Disabled
        };
        let read_timeout = cfg_layer(
            args.read_timeout,
            cfg_file_strategy.read_timeout,
            format_duration(defaults::DEFAULT_STRATEGY_READ_TIMEOUT).to_string(),
        );
        let tui_max_samples = cfg_layer(
            args.tui_max_samples,
            cfg_file_tui.tui_max_samples,
            constants::DEFAULT_TUI_MAX_SAMPLES,
        );
        let tui_max_flows = cfg_layer(
            args.tui_max_flows,
            cfg_file_tui.tui_max_flows,
            constants::DEFAULT_TUI_MAX_FLOWS,
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
        let tui_privacy_max_ttl = cfg_layer(
            args.tui_privacy_max_ttl,
            cfg_file_tui.tui_privacy_max_ttl,
            constants::DEFAULT_TUI_PRIVACY_MAX_TTL,
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
        let columns = cfg_layer(
            args.tui_custom_columns,
            cfg_file_tui.tui_custom_columns,
            String::from(constants::DEFAULT_CUSTOM_COLUMNS),
        );
        let tui_custom_columns = TuiColumns::try_from(columns.as_str())?;
        let tui_icmp_extension_mode = cfg_layer(
            args.tui_icmp_extension_mode,
            cfg_file_tui.tui_icmp_extension_mode,
            constants::DEFAULT_TUI_ICMP_EXTENSION_MODE,
        );
        let tui_geoip_mode = cfg_layer(
            args.tui_geoip_mode,
            cfg_file_tui.tui_geoip_mode,
            constants::DEFAULT_TUI_GEOIP_MODE,
        );
        let tui_max_addrs = cfg_layer_opt(args.tui_max_addrs, cfg_file_tui.tui_max_addrs);
        let dns_resolve_method_config = cfg_layer(
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
        let protocol = match (args.udp, args.tcp, args.icmp, protocol) {
            (false, false, false, ProtocolConfig::Udp) | (true, _, _, _) => Protocol::Udp,
            (false, false, false, ProtocolConfig::Tcp) | (_, true, _, _) => Protocol::Tcp,
            (false, false, false, ProtocolConfig::Icmp) | (_, _, true, _) => Protocol::Icmp,
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

        #[allow(clippy::match_same_arms)]
        let addr_family = match (
            args.ipv4,
            args.ipv6,
            addr_family_cfg,
            multipath_strategy_cfg,
        ) {
            (false, false, AddressFamilyConfig::Ipv4, _) => IpAddrFamily::Ipv4Only,
            (false, false, AddressFamilyConfig::Ipv6, _) => IpAddrFamily::Ipv6Only,
            // we "downgrade" to `Ipv4Only` for `Dublin` rather than fail.
            (false, false, AddressFamilyConfig::Ipv4ThenIpv6, MultipathStrategyConfig::Dublin) => {
                IpAddrFamily::Ipv4Only
            }
            (false, false, AddressFamilyConfig::Ipv6ThenIpv4, MultipathStrategyConfig::Dublin) => {
                IpAddrFamily::Ipv4Only
            }
            (false, false, AddressFamilyConfig::Ipv4ThenIpv6, _) => IpAddrFamily::Ipv4thenIpv6,
            (false, false, AddressFamilyConfig::Ipv6ThenIpv4, _) => IpAddrFamily::Ipv6thenIpv4,
            (true, _, _, _) => IpAddrFamily::Ipv4Only,
            (_, true, _, _) => IpAddrFamily::Ipv6Only,
        };

        #[allow(clippy::match_same_arms)]
        let multipath_strategy = match (multipath_strategy_cfg, addr_family) {
            (MultipathStrategyConfig::Classic, _) => Ok(MultipathStrategy::Classic),
            (MultipathStrategyConfig::Paris, _) => Ok(MultipathStrategy::Paris),
            (
                MultipathStrategyConfig::Dublin,
                IpAddrFamily::Ipv4Only | IpAddrFamily::Ipv4thenIpv6 | IpAddrFamily::Ipv6thenIpv4,
            ) => Ok(MultipathStrategy::Dublin),
            (MultipathStrategyConfig::Dublin, IpAddrFamily::Ipv6Only) => Err(anyhow!(
                "Dublin multipath strategy not implemented for IPv6 yet!"
            )),
        }?;

        let port_direction = match (protocol, source_port, target_port, multipath_strategy_cfg) {
            (Protocol::Icmp, _, _, _) => PortDirection::None,
            (Protocol::Udp, None, None, _) => PortDirection::new_fixed_src(pid.max(1024)),
            (Protocol::Udp, Some(src), None, _) => {
                validate_source_port(src)?;
                PortDirection::new_fixed_src(src)
            }
            (Protocol::Tcp, None, None, _) => PortDirection::new_fixed_dest(80),
            (Protocol::Tcp, Some(src), None, _) => PortDirection::new_fixed_src(src),
            (_, None, Some(dest), _) => PortDirection::new_fixed_dest(dest),
            (
                Protocol::Udp,
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
        let dns_resolve_method = match dns_resolve_method_config {
            DnsResolveMethodConfig::System => ResolveMethod::System,
            DnsResolveMethodConfig::Resolv => ResolveMethod::Resolv,
            DnsResolveMethodConfig::Google => ResolveMethod::Google,
            DnsResolveMethodConfig::Cloudflare => ResolveMethod::Cloudflare,
        };
        let dns_timeout = humantime::parse_duration(&dns_timeout)?;
        let max_rounds = match mode {
            Mode::Stream | Mode::Tui => None,
            Mode::Pretty
            | Mode::Markdown
            | Mode::Csv
            | Mode::Json
            | Mode::Dot
            | Mode::Flows
            | Mode::Silent => Some(report_cycles),
        };
        let tui_max_addrs = match tui_max_addrs {
            Some(n) if n > 0 => Some(n),
            _ => None,
        };
        validate_privilege(privilege_mode, has_privileges, needs_privileges)?;
        validate_logging(mode, verbose)?;
        validate_strategy(multipath_strategy, unprivileged)?;
        validate_protocol_strategy(protocol, multipath_strategy)?;
        validate_multi(mode, protocol, &args.targets, dns_resolve_all)?;
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
        validate_tui_custom_columns(&tui_custom_columns)?;
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
            icmp_extension_parse_mode,
            source_addr,
            interface,
            port_direction,
            dns_timeout,
            dns_resolve_method,
            dns_lookup_as_info,
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
            mode,
            privilege_mode,
            dns_resolve_all,
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

impl Default for TrippyConfig {
    fn default() -> Self {
        Self {
            targets: vec![],
            protocol: defaults::DEFAULT_STRATEGY_PROTOCOL,
            addr_family: dns_resolve_family(constants::DEFAULT_ADDR_FAMILY),
            first_ttl: defaults::DEFAULT_STRATEGY_FIRST_TTL,
            max_ttl: defaults::DEFAULT_STRATEGY_MAX_TTL,
            min_round_duration: defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION,
            max_round_duration: defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION,
            grace_duration: defaults::DEFAULT_STRATEGY_GRACE_DURATION,
            max_inflight: defaults::DEFAULT_STRATEGY_MAX_INFLIGHT,
            initial_sequence: defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE,
            tos: defaults::DEFAULT_STRATEGY_TOS,
            icmp_extension_parse_mode: defaults::DEFAULT_ICMP_EXTENSION_PARSE_MODE,
            read_timeout: defaults::DEFAULT_STRATEGY_READ_TIMEOUT,
            packet_size: defaults::DEFAULT_STRATEGY_PACKET_SIZE,
            payload_pattern: defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN,
            source_addr: None,
            interface: None,
            multipath_strategy: defaults::DEFAULT_STRATEGY_MULTIPATH,
            port_direction: PortDirection::None,
            dns_timeout: duration(constants::DEFAULT_DNS_TIMEOUT),
            dns_resolve_method: dns_resolve_method(constants::DEFAULT_DNS_RESOLVE_METHOD),
            dns_lookup_as_info: constants::DEFAULT_DNS_LOOKUP_AS_INFO,
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
            mode: constants::DEFAULT_MODE,
            privilege_mode: defaults::DEFAULT_PRIVILEGE_MODE,
            dns_resolve_all: constants::DEFAULT_DNS_RESOLVE_ALL,
            report_cycles: constants::DEFAULT_REPORT_CYCLES,
            geoip_mmdb_file: None,
            max_rounds: None,
            verbose: false,
            log_format: constants::DEFAULT_LOG_FORMAT,
            log_filter: String::from(constants::DEFAULT_LOG_FILTER),
            log_span_events: constants::DEFAULT_LOG_SPAN_EVENTS,
            tui_custom_columns: TuiColumns::default(),
        }
    }
}

fn duration(duration: &str) -> Duration {
    humantime::parse_duration(duration).expect("valid duration")
}

fn dns_resolve_method(dns_resolve_method: DnsResolveMethodConfig) -> ResolveMethod {
    match dns_resolve_method {
        DnsResolveMethodConfig::System => ResolveMethod::System,
        DnsResolveMethodConfig::Resolv => ResolveMethod::Resolv,
        DnsResolveMethodConfig::Google => ResolveMethod::Google,
        DnsResolveMethodConfig::Cloudflare => ResolveMethod::Cloudflare,
    }
}

fn dns_resolve_family(dns_resolve_family: AddressFamilyConfig) -> IpAddrFamily {
    match dns_resolve_family {
        AddressFamilyConfig::Ipv4 => IpAddrFamily::Ipv4Only,
        AddressFamilyConfig::Ipv6 => IpAddrFamily::Ipv6Only,
        AddressFamilyConfig::Ipv6ThenIpv4 => IpAddrFamily::Ipv6thenIpv4,
        AddressFamilyConfig::Ipv4ThenIpv6 => IpAddrFamily::Ipv4thenIpv6,
    }
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

/// Validate privileges.
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

/// Validate the TUI custom columns.
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

/// Validate the logging mode.
fn validate_logging(mode: Mode, verbose: bool) -> anyhow::Result<()> {
    if matches!(mode, Mode::Tui) && verbose {
        Err(anyhow!("cannot enable verbose logging in tui mode"))
    } else {
        Ok(())
    }
}

/// Validate the multipath strategy against the privilege mode.
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

/// Validate the protocol against the multipath strategy.
fn validate_protocol_strategy(
    protocol: Protocol,
    strategy: MultipathStrategy,
) -> anyhow::Result<()> {
    match (protocol, strategy) {
        (Protocol::Tcp | Protocol::Icmp, MultipathStrategy::Classic) | (Protocol::Udp, _) => Ok(()),
        (Protocol::Icmp, MultipathStrategy::Paris) => {
            Err(anyhow!("Paris multipath strategy not support for icmp"))
        }
        (Protocol::Icmp, MultipathStrategy::Dublin) => {
            Err(anyhow!("Dublin multipath strategy not support for icmp"))
        }
        (Protocol::Tcp, MultipathStrategy::Paris) => Err(anyhow!(
            "Paris multipath strategy not yet supported for tcp"
        )),
        (Protocol::Tcp, MultipathStrategy::Dublin) => Err(anyhow!(
            "Dublin multipath strategy not yet supported for tcp"
        )),
    }
}

/// We only allow multiple targets to be specified for the Tui and for `Icmp` tracing.
fn validate_multi(
    mode: Mode,
    protocol: Protocol,
    targets: &[String],
    dns_resolve_all: bool,
) -> anyhow::Result<()> {
    match (mode, protocol) {
        (Mode::Stream | Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json, _)
            if targets.len() > 1 || dns_resolve_all =>
        {
            Err(anyhow!(
                "only a single target may be specified for this mode"
            ))
        }
        (_, Protocol::Tcp | Protocol::Udp) if targets.len() > 1 || dns_resolve_all => Err(anyhow!(
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use test_case::test_case;
    use trippy::tracing::Port;

    #[test]
    fn test_config_default() {
        let args = args(&["trip", "example.com"]).unwrap();
        let cfg_file = ConfigFile::default();
        let platform = Platform::dummy_for_test();
        let config = TrippyConfig::build_config(args, cfg_file, &platform).unwrap();
        let expected = TrippyConfig {
            targets: vec![String::from("example.com")],
            ..TrippyConfig::default()
        };
        pretty_assertions::assert_eq!(expected, config);
    }

    #[test]
    fn test_config_sample() {
        let args = args(&["trip", "example.com"]).unwrap();
        let cfg_file: ConfigFile =
            toml::from_str(include_str!("../trippy-config-sample.toml")).unwrap();
        let platform = Platform::dummy_for_test();
        let config = TrippyConfig::build_config(args, cfg_file, &platform).unwrap();
        let expected = TrippyConfig {
            targets: vec![String::from("example.com")],
            ..TrippyConfig::default()
        };
        pretty_assertions::assert_eq!(expected, config);
    }

    #[test_case("trip", Err(anyhow!(include_str!("../test_resources/usage_short.txt"))); "show default help")]
    #[test_case("trip -h", Err(anyhow!(include_str!("../test_resources/usage_short.txt"))); "show short help")]
    #[test_case("trip --help", Err(anyhow!(include_str!("../test_resources/usage_long.txt"))); "show long help")]
    #[test_case("trip -V", Err(anyhow!(format!("trip {}", clap::crate_version!()))); "show version")]
    #[test_case("trip example.com --config-file trippy.toml", Ok(cfg().build()); "custom config file")]
    #[test_case("trip example.com -c trippy.toml", Ok(cfg().build()); "custom config file short")]
    #[test_case("trip example.com", Ok(cfg().build()); "single target")]
    #[test_case("trip example.com foo.com bar.com", Ok(cfg_multi().build()); "multiple targets")]
    #[test_case("trip example.com -U 20", Ok(cfg().max_inflight(20).build()); "single target before args")]
    #[test_case("trip -U 20 example.com", Ok(cfg().max_inflight(20).build()); "single target after args")]
    #[test_case("trip example.com foo.com bar.com -U 20", Ok(cfg_multi().max_inflight(20).build()); "multiple targets before args")]
    #[test_case("trip -U 20 example.com foo.com bar.com", Ok(cfg_multi().max_inflight(20).build()); "multiple targets after args")]
    #[test_case("trip example.com -U 20 foo.com -Q 255 bar.com", Ok(cfg_multi().max_inflight(20).tos(255).build()); "multiple targets between args")]
    #[test_case("trip example.com --dummy", Err(anyhow!("error: unexpected argument found")); "invalid argument")]
    #[test_case("trip example.com", Ok(cfg().multipath_strategy(MultipathStrategy::Classic).build()); "default strategy")]
    #[test_case("trip example.com --multipath-strategy classic", Ok(cfg().multipath_strategy(MultipathStrategy::Classic).build()); "classic strategy")]
    #[test_case("trip example.com --multipath-strategy paris --udp", Ok(cfg().multipath_strategy(MultipathStrategy::Paris).protocol(Protocol::Udp).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "paris strategy")]
    #[test_case("trip example.com --multipath-strategy dublin --udp", Ok(cfg().multipath_strategy(MultipathStrategy::Dublin).protocol(Protocol::Udp).addr_family(IpAddrFamily::Ipv4Only).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "dublin strategy")]
    #[test_case("trip example.com --multipath-strategy tokyo", Err(anyhow!("error: one of the values isn't valid for an argument")); "invalid strategy")]
    #[test_case("trip example.com", Ok(cfg().protocol(Protocol::Icmp).port_direction(PortDirection::None).build()); "default protocol")]
    #[test_case("trip example.com --protocol icmp", Ok(cfg().protocol(Protocol::Icmp).port_direction(PortDirection::None).build()); "icmp protocol")]
    #[test_case("trip example.com --protocol udp", Ok(cfg().protocol(Protocol::Udp).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "udp protocol")]
    #[test_case("trip example.com --protocol tcp", Ok(cfg().protocol(Protocol::Tcp).port_direction(PortDirection::FixedDest(Port(80))).build()); "tcp protocol")]
    #[test_case("trip example.com --protocol foo", Err(anyhow!("error: one of the values isn't valid for an argument")); "invalid protocol")]
    #[test_case("trip example.com -p icmp", Ok(cfg().protocol(Protocol::Icmp).port_direction(PortDirection::None).build()); "icmp protocol short")]
    #[test_case("trip example.com -p udp", Ok(cfg().protocol(Protocol::Udp).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "udp protocol short")]
    #[test_case("trip example.com -p tcp", Ok(cfg().protocol(Protocol::Tcp).port_direction(PortDirection::FixedDest(Port(80))).build()); "tcp protocol short")]
    #[test_case("trip example.com -p foo", Err(anyhow!("error: one of the values isn't valid for an argument")); "invalid protocol short")]
    #[test_case("trip example.com --icmp", Ok(cfg().protocol(Protocol::Icmp).port_direction(PortDirection::None).build()); "icmp protocol shortcut")]
    #[test_case("trip example.com --udp", Ok(cfg().protocol(Protocol::Udp).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "udp protocol shortcut")]
    #[test_case("trip example.com --tcp", Ok(cfg().protocol(Protocol::Tcp).port_direction(PortDirection::FixedDest(Port(80))).build()); "tcp protocol shortcut")]
    #[test_case("trip example.com --udp --source-port 2222", Ok(cfg().protocol(Protocol::Udp).port_direction(PortDirection::FixedSrc(Port(2222))).build()); "udp protocol custom src port")]
    #[test_case("trip example.com --udp --target-port 8888", Ok(cfg().protocol(Protocol::Udp).port_direction(PortDirection::FixedDest(Port(8888))).build()); "udp protocol custom target port")]
    #[test_case("trip example.com --udp --source-port 123", Err(anyhow!("source-port (123) must be >= 1024")); "udp protocol invalid src port")]
    #[test_case("trip example.com --tcp --source-port 3333", Ok(cfg().protocol(Protocol::Tcp).port_direction(PortDirection::FixedSrc(Port(3333))).build()); "tcp protocol custom src port")]
    #[test_case("trip example.com --tcp --target-port 7777", Ok(cfg().protocol(Protocol::Tcp).port_direction(PortDirection::FixedDest(Port(7777))).build()); "tcp protocol custom target port")]
    #[test_case("trip example.com --udp --multipath-strategy paris", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Paris).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "udp protocol paris strategy default ports")]
    #[test_case("trip example.com --udp --multipath-strategy paris --source-port 33000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Paris).port_direction(PortDirection::FixedSrc(Port(33000))).build()); "udp protocol paris strategy custom src port")]
    #[test_case("trip example.com --udp --multipath-strategy paris --target-port 5000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Paris).port_direction(PortDirection::FixedDest(Port(5000))).build()); "udp protocol paris strategy custom target port")]
    #[test_case("trip example.com --udp --multipath-strategy paris --source-port 33000 --target-port 5000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Paris).port_direction(PortDirection::FixedBoth(Port(33000), Port(5000))).build()); "udp protocol paris strategy custom both ports")]
    #[test_case("trip example.com --udp --multipath-strategy dublin", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Dublin).addr_family(IpAddrFamily::Ipv4Only).port_direction(PortDirection::FixedSrc(Port(1024))).build()); "udp protocol dublin strategy default ports")]
    #[test_case("trip example.com --udp --multipath-strategy dublin --source-port 33000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Dublin).addr_family(IpAddrFamily::Ipv4Only).port_direction(PortDirection::FixedSrc(Port(33000))).build()); "udp protocol dublin strategy custom src port")]
    #[test_case("trip example.com --udp --multipath-strategy dublin --target-port 5000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Dublin).addr_family(IpAddrFamily::Ipv4Only).port_direction(PortDirection::FixedDest(Port(5000))).build()); "udp protocol dublin strategy custom target port")]
    #[test_case("trip example.com --udp --multipath-strategy dublin --source-port 33000 --target-port 5000", Ok(cfg().protocol(Protocol::Udp).multipath_strategy(MultipathStrategy::Dublin).addr_family(IpAddrFamily::Ipv4Only).port_direction(PortDirection::FixedBoth(Port(33000), Port(5000))).build()); "udp protocol dublin strategy custom both ports")]
    #[test_case("trip example.com --icmp --multipath-strategy paris", Err(anyhow!("Paris multipath strategy not support for icmp")); "paris with invalid protocol icmp")]
    #[test_case("trip example.com --icmp --multipath-strategy dublin", Err(anyhow!("Dublin multipath strategy not support for icmp")); "dublin with invalid protocol icmp")]
    #[test_case("trip example.com --tcp --multipath-strategy paris", Err(anyhow!("Paris multipath strategy not yet supported for tcp")); "paris with invalid protocol tcp")]
    #[test_case("trip example.com --tcp --multipath-strategy dublin", Err(anyhow!("Dublin multipath strategy not yet supported for tcp")); "dublin with invalid protocol tcp")]
    #[test_case("trip example.com --udp --source-port 33000 --target-port 5000", Err(anyhow!("only one of source-port and target-port may be fixed (except IPv4/udp protocol with dublin or paris strategy)")); "udp protocol custom both ports with invalid strategy")]
    #[test_case("trip example.com", Ok(cfg().addr_family(IpAddrFamily::Ipv4thenIpv6).build()); "default address family")]
    #[test_case("trip example.com --addr-family ipv4", Ok(cfg().addr_family(IpAddrFamily::Ipv4Only).build()); "ipv4 address family")]
    #[test_case("trip example.com --addr-family ipv6", Ok(cfg().addr_family(IpAddrFamily::Ipv6Only).build()); "ipv6 address family")]
    #[test_case("trip example.com --addr-family ipv4-then-ipv6", Ok(cfg().addr_family(IpAddrFamily::Ipv4thenIpv6).build()); "ipv4 then ipv6 address family")]
    #[test_case("trip example.com --addr-family ipv6-then-ipv4", Ok(cfg().addr_family(IpAddrFamily::Ipv6thenIpv4).build()); "ipv6 then ipv4 address family")]
    #[test_case("trip example.com -F ipv4", Ok(cfg().addr_family(IpAddrFamily::Ipv4Only).build()); "custom address family short")]
    #[test_case("trip example.com --addr-family foo", Err(anyhow!("error: one of the values isn't valid for an argument")); "invalid address family")]
    #[test_case("trip example.com -4", Ok(cfg().addr_family(IpAddrFamily::Ipv4Only).build()); "ipv4 address family shortcut")]
    #[test_case("trip example.com -6", Ok(cfg().addr_family(IpAddrFamily::Ipv6Only).build()); "ipv6 address family shortcut")]
    #[test_case("trip example.com -5", Err(anyhow!("error: unexpected argument found")); "invalid address family shortcut")]
    #[test_case("trip example.com", Ok(cfg().first_ttl(1).build()); "default first ttl")]
    #[test_case("trip example.com --first-ttl 5", Ok(cfg().first_ttl(5).build()); "custom first ttl")]
    #[test_case("trip example.com -f 5", Ok(cfg().first_ttl(5).build()); "custom first ttl short")]
    #[test_case("trip example.com --first-ttl 0", Err(anyhow!("first-ttl (0) must be in the range 1..255")); "invalid low first ttl")]
    #[test_case("trip example.com --first-ttl 500", Err(anyhow!("error: invalid value for one of the arguments")); "invalid high first ttl")]
    #[test_case("trip example.com", Ok(cfg().first_ttl(1).build()); "default max ttl")]
    #[test_case("trip example.com --max-ttl 5", Ok(cfg().max_ttl(5).build()); "custom max ttl")]
    #[test_case("trip example.com -t 5", Ok(cfg().max_ttl(5).build()); "custom max ttl short")]
    #[test_case("trip example.com --max-ttl 0", Err(anyhow!("max-ttl (0) must be in the range 1..255")); "invalid low max ttl")]
    #[test_case("trip example.com --max-ttl 500", Err(anyhow!("error: invalid value for one of the arguments")); "invalid high max ttl")]
    #[test_case("trip example.com --first-ttl 3 --max-ttl 2", Err(anyhow!("first-ttl (3) must be less than or equal to max-ttl (2)")); "first ttl higher than max ttl")]
    #[test_case("trip example.com --first-ttl 5 --max-ttl 5", Ok(cfg().first_ttl(5).max_ttl(5).build()); "custom first and max ttl")]
    #[test_case("trip example.com", Ok(cfg().min_round_duration(Duration::from_millis(1000)).build()); "default min round duration")]
    #[test_case("trip example.com --min-round-duration 250ms", Ok(cfg().min_round_duration(Duration::from_millis(250)).build()); "custom min round duration")]
    #[test_case("trip example.com -i 250ms", Ok(cfg().min_round_duration(Duration::from_millis(250)).build()); "custom min round duration short")]
    #[test_case("trip example.com --min-round-duration 0", Err(anyhow!("time unit needed, for example 0sec or 0ms")); "invalid format min round duration")]
    #[test_case("trip example.com", Ok(cfg().min_round_duration(Duration::from_millis(1000)).build()); "default max round duration")]
    #[test_case("trip example.com --max-round-duration 1250ms", Ok(cfg().max_round_duration(Duration::from_millis(1250)).build()); "custom max round duration")]
    #[test_case("trip example.com -T 2s", Ok(cfg().max_round_duration(Duration::from_millis(2000)).build()); "custom max round duration short")]
    #[test_case("trip example.com --min-round-duration 0", Err(anyhow!("time unit needed, for example 0sec or 0ms")); "invalid format max round duration")]
    #[test_case("trip example.com -i 250ms -T 250ms", Ok(cfg().min_round_duration(Duration::from_millis(250)).max_round_duration(Duration::from_millis(250)).build()); "custom min and max round duration")]
    #[test_case("trip example.com -i 300ms -T 250ms", Err(anyhow!("max-round-duration (250ms) must not be less than min-round-duration (300ms)")); "min round duration greater than max")]
    #[test_case("trip example.com", Ok(cfg().grace_duration(Duration::from_millis(100)).build()); "default grace duration")]
    #[test_case("trip example.com --grace-duration 10ms", Ok(cfg().grace_duration(Duration::from_millis(10)).build()); "custom grace duration")]
    #[test_case("trip example.com -g 50ms", Ok(cfg().grace_duration(Duration::from_millis(50)).build()); "custom grace duration short")]
    #[test_case("trip example.com --grace-duration 0", Err(anyhow!("time unit needed, for example 0sec or 0ms")); "invalid format grace duration")]
    #[test_case("trip example.com --grace-duration 9ms", Err(anyhow!("grace-duration (9ms) must be between 10ms and 1s inclusive")); "invalid low grace duration")]
    #[test_case("trip example.com --grace-duration 1001ms", Err(anyhow!("grace-duration (1.001s) must be between 10ms and 1s inclusive")); "invalid high grace duration")]
    #[test_case("trip example.com", Ok(cfg().max_inflight(24).build()); "default max inflight")]
    #[test_case("trip example.com --max-inflight 12", Ok(cfg().max_inflight(12).build()); "custom max inflight")]
    #[test_case("trip example.com -U 20", Ok(cfg().max_inflight(20).build()); "custom max inflight short")]
    #[test_case("trip example.com --max-inflight foo", Err(anyhow!("error: invalid value for one of the arguments")); "invalid format max inflight")]
    #[test_case("trip example.com --max-inflight 0", Err(anyhow!("max-inflight (0) must be greater than zero")); "invalid low max inflight")]
    #[test_case("trip example.com --max-inflight 300", Err(anyhow!("error: invalid value for one of the arguments")); "invalid high max inflight")]
    #[test_case("trip example.com", Ok(cfg().initial_sequence(33000).build()); "default initial sequence")]
    #[test_case("trip example.com --initial-sequence 5000", Ok(cfg().initial_sequence(5000).build()); "custom initial sequence")]
    #[test_case("trip example.com --initial-sequence foo", Err(anyhow!("error: invalid value for one of the arguments")); "invalid format initial sequence")]
    #[test_case("trip example.com --initial-sequence 100000", Err(anyhow!("error: invalid value for one of the arguments")); "invalid high initial sequence")]
    #[test_case("trip example.com", Ok(cfg().tos(0).build()); "default tos")]
    #[test_case("trip example.com --tos 255", Ok(cfg().tos(0xFF).build()); "custom tos")]
    #[test_case("trip example.com -Q 255", Ok(cfg().tos(0xFF).build()); "custom tos short")]
    #[test_case("trip example.com --tos foo", Err(anyhow!("error: invalid value for one of the arguments")); "invalid format tos")]
    #[test_case("trip example.com --tos 300", Err(anyhow!("error: invalid value for one of the arguments")); "invalid high tos")]
    #[test_case("trip example.com", Ok(cfg().icmp_extension_parse_mode(IcmpExtensionParseMode::Disabled).build()); "default icmp extensions")]
    #[test_case("trip example.com --icmp-extensions", Ok(cfg().icmp_extension_parse_mode(IcmpExtensionParseMode::Enabled).build()); "enabled icmp extensions")]
    #[test_case("trip example.com -e", Ok(cfg().icmp_extension_parse_mode(IcmpExtensionParseMode::Enabled).build()); "enabled icmp extensions short")]
    #[test_case("trip example.com", Ok(cfg().read_timeout(Duration::from_millis(10)).build()); "default read timeout")]
    #[test_case("trip example.com --read-timeout 20ms", Ok(cfg().read_timeout(Duration::from_millis(20)).build()); "custom read timeout")]
    #[test_case("trip example.com --read-timeout 20", Err(anyhow!("time unit needed, for example 20sec or 20ms")); "invalid custom read timeout")]
    #[test_case("trip example.com --read-timeout 9ms", Err(anyhow!("read-timeout (9ms) must be between 10ms and 100ms inclusive")); "invalid low custom read timeout")]
    #[test_case("trip example.com --read-timeout 101ms", Err(anyhow!("read-timeout (101ms) must be between 10ms and 100ms inclusive")); "invalid high custom read timeout")]
    #[test_case("trip example.com", Ok(cfg().packet_size(84).build()); "default packet size")]
    #[test_case("trip example.com --packet-size 120", Ok(cfg().packet_size(120).build()); "custom packet size")]
    #[test_case("trip example.com --packet-size foo", Err(anyhow!("error: invalid value for one of the arguments")); "invalid format packet size")]
    #[test_case("trip example.com --packet-size 27", Err(anyhow!("packet-size (27) must be between 28 and 1024 inclusive")); "invalid low packet size")]
    #[test_case("trip example.com --packet-size 1025", Err(anyhow!("packet-size (1025) must be between 28 and 1024 inclusive")); "invalid high packet size")]
    #[test_case("trip example.com --packet-size 100000", Err(anyhow!("error: invalid value for one of the arguments")); "invalid out of range packet size")]
    #[test_case("trip example.com", Ok(cfg().payload_pattern(0).build()); "default payload pattern size")]
    #[test_case("trip example.com --payload-pattern 255", Ok(cfg().payload_pattern(0xFF).build()); "custom payload pattern")]
    #[test_case("trip example.com --payload-pattern foo", Err(anyhow!("error: invalid value for one of the arguments")); "invalid format payload pattern")]
    #[test_case("trip example.com --payload-pattern 256", Err(anyhow!("error: invalid value for one of the arguments")); "invalid out of range payload pattern")]
    #[test_case("trip example.com", Ok(cfg().source_addr(None).build()); "default source address")]
    #[test_case("trip example.com --source-address 10.0.0.1", Ok(cfg().source_addr(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).build()); "custom ipv4 source address")]
    #[test_case("trip example.com --source-address 2404:6800:4005:81a::200e", Ok(cfg().source_addr(Some(IpAddr::V6(Ipv6Addr::from_str("2404:6800:4005:81a::200e").unwrap()))).build()); "custom ipv6 source address")]
    #[test_case("trip example.com -A 10.0.0.1", Ok(cfg().source_addr(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).build()); "custom ipv4 source address short")]
    #[test_case("trip example.com --source-address foobar", Err(anyhow!("invalid source IP address format: foobar")); "invalid source address")]
    #[test_case("trip example.com", Ok(cfg().interface(None).build()); "default interface")]
    #[test_case("trip example.com --interface en0", Ok(cfg().interface(Some(String::from("en0"))).build()); "custom interface")]
    #[test_case("trip example.com -I tun0", Ok(cfg().interface(Some(String::from("tun0"))).build()); "custom interface short")]
    #[test_case("trip example.com", Ok(cfg().dns_timeout(Duration::from_millis(5000)).build()); "default dns timeout")]
    #[test_case("trip example.com --dns-timeout 20ms", Ok(cfg().dns_timeout(Duration::from_millis(20)).build()); "custom dns timeout")]
    #[test_case("trip example.com --dns-timeout 20", Err(anyhow!("time unit needed, for example 20sec or 20ms")); "invalid custom dns timeout")]
    #[test_case("trip example.com", Ok(cfg().dns_resolve_method(ResolveMethod::System).build()); "default resolve method")]
    #[test_case("trip example.com --dns-resolve-method system", Ok(cfg().dns_resolve_method(ResolveMethod::System).build()); "custom resolve method system")]
    #[test_case("trip example.com -r system", Ok(cfg().dns_resolve_method(ResolveMethod::System).build()); "custom resolve method system short")]
    #[test_case("trip example.com --dns-resolve-method google", Ok(cfg().dns_resolve_method(ResolveMethod::Google).build()); "custom resolve method google")]
    #[test_case("trip example.com --dns-resolve-method cloudflare", Ok(cfg().dns_resolve_method(ResolveMethod::Cloudflare).build()); "custom resolve method cloudflare")]
    #[test_case("trip example.com --dns-resolve-method resolv", Ok(cfg().dns_resolve_method(ResolveMethod::Resolv).build()); "custom resolve method resolv")]
    #[test_case("trip example.com --dns-resolve-method foobar", Err(anyhow!("error: one of the values isn't valid for an argument")); "invalid resolve method")]
    #[test_case("trip example.com", Ok(cfg().dns_lookup_as_info(false).build()); "default dns lookup as info")]
    #[test_case("trip example.com --dns-lookup-as-info -r resolv", Ok(cfg().dns_lookup_as_info(true).dns_resolve_method(ResolveMethod::Resolv).build()); "custom dns lookup as info")]
    #[test_case("trip example.com -z -r resolv", Ok(cfg().dns_lookup_as_info(true).dns_resolve_method(ResolveMethod::Resolv).build()); "custom dns lookup as info short")]
    #[test_case("trip example.com --dns-lookup-as-info", Err(anyhow!("AS lookup not supported by resolver `system` (use '-r' to choose another resolver)")); "invalid resolve method for as info")]
    fn test_commands(cmd: &str, expected: anyhow::Result<TrippyConfig>) {
        compare(parse_config(cmd), expected);
    }

    #[test_case("trip --print-config-template", Ok(TrippyAction::PrintConfigTemplate); "print config template")]
    #[test_case("trip --print-tui-binding-commands", Ok(TrippyAction::PrintTuiBindingCommands); "print the tui binding commands")]
    #[test_case("trip --print-tui-theme-items", Ok(TrippyAction::PrintTuiThemeItems); "print the tui theme items")]
    #[test_case("trip --generate elvish", Ok(TrippyAction::PrintShellCompletions(Shell::Elvish)); "generate elvish shell completions")]
    #[test_case("trip --generate fish", Ok(TrippyAction::PrintShellCompletions(Shell::Fish)); "generate fish shell completions")]
    #[test_case("trip --generate powershell", Ok(TrippyAction::PrintShellCompletions(Shell::PowerShell)); "generate powershell shell completions")]
    #[test_case("trip --generate zsh", Ok(TrippyAction::PrintShellCompletions(Shell::Zsh)); "generate zsh shell completions")]
    #[test_case("trip --generate bash", Ok(TrippyAction::PrintShellCompletions(Shell::Bash)); "generate bash shell completions")]
    #[test_case("trip --generate foo", Err(anyhow!("error: one of the values isn't valid for an argument")); "generate invalid shell completions")]
    fn test_action(cmd: &str, expected: anyhow::Result<TrippyAction>) {
        compare(parse_action(cmd), expected);
    }

    fn parse_action(cmd: &str) -> anyhow::Result<TrippyAction> {
        TrippyAction::from(parse(cmd)?, &Platform::dummy_for_test())
    }

    fn parse_config(cmd: &str) -> anyhow::Result<TrippyConfig> {
        let args = parse(cmd)?;
        let cfg_file = ConfigFile::default();
        let platform = Platform::dummy_for_test();
        TrippyConfig::build_config(args, cfg_file, &platform)
    }

    fn parse(cmd: &str) -> anyhow::Result<Args> {
        use clap::Parser;
        Ok(Args::try_parse_from(
            cmd.split(' ').map(std::ffi::OsString::from),
        )?)
    }

    fn compare<T: PartialEq + Eq + std::fmt::Debug>(
        actual: anyhow::Result<T>,
        expected: anyhow::Result<T>,
    ) {
        match (actual, expected) {
            (Ok(cfg), Ok(exp)) => {
                pretty_assertions::assert_eq!(cfg, exp);
            }
            (Err(err), Err(exp_err)) => {
                if remove_whitespace(err.to_string()) != remove_whitespace(exp_err.to_string()) {
                    pretty_assertions::assert_eq!(err.to_string(), exp_err.to_string());
                }
            }
            (Ok(_), Err(exp_err)) => {
                panic!("expected err {}", exp_err.to_string().trim());
            }
            (Err(err), Ok(_)) => {
                panic!("unexpected err {}", err.to_string().trim());
            }
        }
    }

    fn cfg() -> TrippyConfigBuilder {
        TrippyConfigBuilder::new(vec![String::from("example.com")])
    }

    fn cfg_multi() -> TrippyConfigBuilder {
        TrippyConfigBuilder::new(vec![
            String::from("example.com"),
            String::from("foo.com"),
            String::from("bar.com"),
        ])
    }

    fn args(args: &[&str]) -> anyhow::Result<Args> {
        use clap::Parser;
        Ok(Args::try_parse_from(
            args.iter().map(std::ffi::OsString::from),
        )?)
    }

    fn remove_whitespace(mut s: String) -> String {
        s.retain(|c| !c.is_whitespace());
        s
    }

    pub struct TrippyConfigBuilder {
        config: TrippyConfig,
    }

    impl TrippyConfigBuilder {
        pub fn new(targets: Vec<String>) -> Self {
            Self {
                config: TrippyConfig {
                    targets,
                    ..TrippyConfig::default()
                },
            }
        }

        pub fn protocol(self, protocol: Protocol) -> Self {
            Self {
                config: TrippyConfig {
                    protocol,
                    ..self.config
                },
            }
        }

        pub fn addr_family(self, addr_family: IpAddrFamily) -> Self {
            Self {
                config: TrippyConfig {
                    addr_family,
                    ..self.config
                },
            }
        }

        pub fn first_ttl(self, first_ttl: u8) -> Self {
            Self {
                config: TrippyConfig {
                    first_ttl,
                    ..self.config
                },
            }
        }

        pub fn max_ttl(self, max_ttl: u8) -> Self {
            Self {
                config: TrippyConfig {
                    max_ttl,
                    ..self.config
                },
            }
        }

        pub fn min_round_duration(self, min_round_duration: Duration) -> Self {
            Self {
                config: TrippyConfig {
                    min_round_duration,
                    ..self.config
                },
            }
        }

        pub fn max_round_duration(self, max_round_duration: Duration) -> Self {
            Self {
                config: TrippyConfig {
                    max_round_duration,
                    ..self.config
                },
            }
        }

        pub fn grace_duration(self, grace_duration: Duration) -> Self {
            Self {
                config: TrippyConfig {
                    grace_duration,
                    ..self.config
                },
            }
        }

        pub fn max_inflight(self, max_inflight: u8) -> Self {
            Self {
                config: TrippyConfig {
                    max_inflight,
                    ..self.config
                },
            }
        }

        pub fn initial_sequence(self, initial_sequence: u16) -> Self {
            Self {
                config: TrippyConfig {
                    initial_sequence,
                    ..self.config
                },
            }
        }

        pub fn tos(self, tos: u8) -> Self {
            Self {
                config: TrippyConfig { tos, ..self.config },
            }
        }

        pub fn icmp_extension_parse_mode(
            self,
            icmp_extension_parse_mode: IcmpExtensionParseMode,
        ) -> Self {
            Self {
                config: TrippyConfig {
                    icmp_extension_parse_mode,
                    ..self.config
                },
            }
        }

        pub fn read_timeout(self, read_timeout: Duration) -> Self {
            Self {
                config: TrippyConfig {
                    read_timeout,
                    ..self.config
                },
            }
        }

        pub fn packet_size(self, packet_size: u16) -> Self {
            Self {
                config: TrippyConfig {
                    packet_size,
                    ..self.config
                },
            }
        }

        pub fn payload_pattern(self, payload_pattern: u8) -> Self {
            Self {
                config: TrippyConfig {
                    payload_pattern,
                    ..self.config
                },
            }
        }

        pub fn source_addr(self, source_addr: Option<IpAddr>) -> Self {
            Self {
                config: TrippyConfig {
                    source_addr,
                    ..self.config
                },
            }
        }

        pub fn interface(self, interface: Option<String>) -> Self {
            Self {
                config: TrippyConfig {
                    interface,
                    ..self.config
                },
            }
        }

        pub fn port_direction(self, port_direction: PortDirection) -> Self {
            Self {
                config: TrippyConfig {
                    port_direction,
                    ..self.config
                },
            }
        }

        pub fn multipath_strategy(self, multipath_strategy: MultipathStrategy) -> Self {
            Self {
                config: TrippyConfig {
                    multipath_strategy,
                    ..self.config
                },
            }
        }

        pub fn dns_timeout(self, dns_timeout: Duration) -> Self {
            Self {
                config: TrippyConfig {
                    dns_timeout,
                    ..self.config
                },
            }
        }

        pub fn dns_resolve_method(self, dns_resolve_method: ResolveMethod) -> Self {
            Self {
                config: TrippyConfig {
                    dns_resolve_method,
                    ..self.config
                },
            }
        }

        pub fn dns_lookup_as_info(self, dns_lookup_as_info: bool) -> Self {
            Self {
                config: TrippyConfig {
                    dns_lookup_as_info,
                    ..self.config
                },
            }
        }

        pub fn build(self) -> TrippyConfig {
            self.config
        }
    }
}
