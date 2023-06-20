use anyhow::anyhow;
use binding::TuiCommandItem;
use clap::{Command, CommandFactory, Parser, ValueEnum};
use clap_complete::{generate, Generator, Shell};
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
use trippy::tracing::{MultipathStrategy, PortDirection, TracerAddrFamily, TracerProtocol};

mod binding;
mod file;
mod theme;

pub use binding::{TuiBindings, TuiKeyBinding};
pub use theme::{TuiColor, TuiTheme};

/// The maximum number of hops we allow.
///
/// The IP `ttl` is a u8 (0..255) but since a `ttl` of zero isn't useful we only allow 255 distinct hops.
pub const MAX_HOPS: usize = u8::MAX as usize;

/// The minimum TUI refresh rate.
const TUI_MIN_REFRESH_RATE_MS: Duration = Duration::from_millis(50);

/// The maximum TUI refresh rate.
const TUI_MAX_REFRESH_RATE_MS: Duration = Duration::from_millis(1000);

/// The minimum socket read timeout.
const MIN_READ_TIMEOUT_MS: Duration = Duration::from_millis(10);

/// The maximum socket read timeout.
const MAX_READ_TIMEOUT_MS: Duration = Duration::from_millis(100);

/// The minimum grace duration.
const MIN_GRACE_DURATION_MS: Duration = Duration::from_millis(10);

/// The maximum grace duration.
const MAX_GRACE_DURATION_MS: Duration = Duration::from_millis(1000);

/// The default value for `mode`.
const DEFAULT_MODE: Mode = Mode::Tui;

/// The default value for `log-format`.
const DEFAULT_LOG_FORMAT: LogFormat = LogFormat::Pretty;

/// The default value for `log-span-events`.
const DEFAULT_LOG_SPAN_EVENTS: LogSpanEvents = LogSpanEvents::Off;

/// The default value for `log-filter`.
const DEFAULT_LOG_FILTER: &str = "trippy=debug";

/// The default value for `protocol`.
const DEFAULT_STRATEGY_PROTOCOL: Protocol = Protocol::Icmp;

/// The default value for `min-round-duration`.
const DEFAULT_STRATEGY_MIN_ROUND_DURATION: &str = "1s";

/// The default value for `max-round-duration`.
const DEFAULT_STRATEGY_MAX_ROUND_DURATION: &str = "1s";

/// The default value for `initial-sequence`.
const DEFAULT_STRATEGY_INITIAL_SEQUENCE: u16 = 33000;

/// The default value for `multipath-strategy`.
const DEFAULT_STRATEGY_MULTIPATH: MultipathStrategyConfig = MultipathStrategyConfig::Classic;

/// The default value for `grace-duration`.
const DEFAULT_STRATEGY_GRACE_DURATION: &str = "100ms";

/// The default value for `max-inflight`.
const DEFAULT_STRATEGY_MAX_INFLIGHT: u8 = 24;

/// The default value for `first-ttl`.
const DEFAULT_STRATEGY_FIRST_TTL: u8 = 1;

/// The default value for `max-ttl`.
const DEFAULT_STRATEGY_MAX_TTL: u8 = 64;

/// The default value for `packet-size`.
const DEFAULT_STRATEGY_PACKET_SIZE: u16 = 84;

/// The default value for `payload-pattern`.
const DEFAULT_STRATEGY_PAYLOAD_PATTERN: u8 = 0;

/// The default value for `tos`.
const DEFAULT_STRATEGY_TOS: u8 = 0;

/// The default value for `read-timeout`.
const DEFAULT_STRATEGY_READ_TIMEOUT: &str = "10ms";

/// The default value for `tui-max-samples`.
const DEFAULT_TUI_MAX_SAMPLES: usize = 256;

/// The default value for `tui-preserve-screen`.
const DEFAULT_TUI_PRESERVE_SCREEN: bool = false;

/// The default value for `tui-as-mode`.
const DEFAULT_TUI_AS_MODE: AsMode = AsMode::Asn;

/// The default value for `tui-geoip-mode`.
const DEFAULT_TUI_GEOIP_MODE: GeoIpMode = GeoIpMode::Off;

/// The default value for `tui-address-mode`.
const DEFAULT_TUI_ADDRESS_MODE: AddressMode = AddressMode::Host;

/// The default value for `tui-refresh-rate`.
const DEFAULT_TUI_REFRESH_RATE: &str = "100ms";

/// The default value for `dns-resolve-method`.
const DEFAULT_DNS_RESOLVE_METHOD: DnsResolveMethod = DnsResolveMethod::System;

/// The default value for `dns-lookup-as-info`.
const DEFAULT_DNS_LOOKUP_AS_INFO: bool = false;

/// The default value for `dns-timeout`.
const DEFAULT_DNS_TIMEOUT: &str = "5s";

/// The default value for `report-cycles`.
const DEFAULT_REPORT_CYCLES: usize = 10;

/// The minimum packet size we allow.
const MIN_PACKET_SIZE: u16 = 28;

/// The maximum packet size we allow.
const MAX_PACKET_SIZE: u16 = 1024;

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
    /// The `city` name is shown, `subdivision` and `country` codes are shown, `continent` is not displayed.
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

/// Trace a route to a host and record statistics
#[derive(Parser, Debug)]
#[command(name = "trip", author, version, about, long_about = None)]
pub struct Args {
    /// A space delimited list of hostnames and IPs to trace
    #[arg(required_unless_present_any(["print_tui_theme_items", "print_tui_binding_commands", "generate"]))]
    pub targets: Vec<String>,

    /// Config file
    #[arg(value_enum, short = 'c', long, display_order = 0, value_hint = clap::ValueHint::FilePath)]
    pub config_file: Option<String>,

    /// Output mode [default: tui]
    #[arg(value_enum, short = 'm', long, display_order = 1)]
    pub mode: Option<Mode>,

    /// Tracing protocol [default: icmp]
    #[arg(value_enum, short = 'p', long, display_order = 2)]
    pub protocol: Option<Protocol>,

    /// Trace using the UDP protocol
    #[arg(
        long,
        display_order = 3,
        conflicts_with = "protocol",
        conflicts_with = "tcp"
    )]
    pub udp: bool,

    /// Trace using the TCP protocol
    #[arg(
        long,
        display_order = 4,
        conflicts_with = "protocol",
        conflicts_with = "udp"
    )]
    pub tcp: bool,

    /// use IPv4 only
    #[arg(short = '4', long, display_order = 5, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Use IPv6 only
    #[arg(short = '6', long, display_order = 6, conflicts_with = "ipv4")]
    pub ipv6: bool,

    /// The target port (TCP & UDP only) [default: 80]
    #[arg(long, short = 'P', display_order = 7)]
    pub target_port: Option<u16>,

    /// The source port (TCP & UDP only) [default: auto]
    #[arg(long, short = 'S', display_order = 8)]
    pub source_port: Option<u16>,

    /// The source IP address [default: auto]
    #[arg(short = 'A', long, display_order = 9, conflicts_with = "interface")]
    pub source_address: Option<String>,

    /// The network interface [default: auto]
    #[arg(short = 'I', long, display_order = 10)]
    pub interface: Option<String>,

    /// The minimum duration of every round [default: 1s]
    #[arg(short = 'i', long, display_order = 11)]
    pub min_round_duration: Option<String>,

    /// The maximum duration of every round [default: 1s]
    #[arg(short = 'T', long, display_order = 12)]
    pub max_round_duration: Option<String>,

    /// The period of time to wait for additional ICMP responses after the target has responded [default: 100ms]
    #[arg(short = 'g', long, display_order = 13)]
    pub grace_duration: Option<String>,

    /// The initial sequence number [default: 33000]
    #[arg(long, display_order = 14)]
    pub initial_sequence: Option<u16>,

    /// The Equal-cost Multi-Path routing strategy (IPv4/UDP only) [default: classic]
    #[arg(value_enum, short = 'R', long, display_order = 15)]
    pub multipath_strategy: Option<MultipathStrategyConfig>,

    /// The maximum number of in-flight ICMP echo requests [default: 24]
    #[arg(short = 'U', long, display_order = 16)]
    pub max_inflight: Option<u8>,

    /// The TTL to start from [default: 1]
    #[arg(short = 'f', long, display_order = 17)]
    pub first_ttl: Option<u8>,

    /// The maximum number of TTL hops [default: 64]
    #[arg(short = 't', long, display_order = 18)]
    pub max_ttl: Option<u8>,

    /// The size of IP packet to send (IP header + ICMP header + payload) [default: 84]
    #[arg(long, display_order = 19)]
    pub packet_size: Option<u16>,

    /// The repeating pattern in the payload of the ICMP packet [default: 0]
    #[arg(long, display_order = 20)]
    pub payload_pattern: Option<u8>,

    /// The TOS (i.e. DSCP+ECN) IP header value (TCP and UDP only) [default: 0]
    #[arg(short = 'Q', long, display_order = 21)]
    pub tos: Option<u8>,

    /// The socket read timeout [default: 10ms]
    #[arg(long, display_order = 22)]
    pub read_timeout: Option<String>,

    /// How to perform DNS queries [default: system]
    #[arg(value_enum, short = 'r', long, display_order = 23)]
    pub dns_resolve_method: Option<DnsResolveMethod>,

    /// The maximum time to wait to perform DNS queries [default: 5s]
    #[arg(long, display_order = 24)]
    pub dns_timeout: Option<String>,

    /// Lookup autonomous system (AS) information during DNS queries [default: false]
    #[arg(long, short = 'z', display_order = 25)]
    pub dns_lookup_as_info: Option<bool>,

    /// How to render addresses [default: host]
    #[arg(value_enum, short = 'a', long, display_order = 26)]
    pub tui_address_mode: Option<AddressMode>,

    /// How to render AS information [default: asn]
    #[arg(value_enum, long, display_order = 27)]
    pub tui_as_mode: Option<AsMode>,

    /// How to render GeoIp information [default: short]
    #[arg(value_enum, long, display_order = 28)]
    pub tui_geoip_mode: Option<GeoIpMode>,

    /// The maximum number of addresses to show per hop [default: auto]
    #[arg(short = 'M', long, display_order = 29)]
    pub tui_max_addrs: Option<u8>,

    /// The maximum number of samples to record per hop [default: 256]
    #[arg(long, short = 's', display_order = 30)]
    pub tui_max_samples: Option<usize>,

    /// Preserve the screen on exit [default: false]
    #[arg(long, display_order = 31)]
    pub tui_preserve_screen: Option<bool>,

    /// The Tui refresh rate [default: 100ms]
    #[arg(long, display_order = 32)]
    pub tui_refresh_rate: Option<String>,

    /// The TUI theme colors [item=color,item=color,..]
    #[arg(long, value_delimiter(','), value_parser = parse_tui_theme_color_value, display_order = 33)]
    pub tui_theme_colors: Vec<(TuiThemeItem, TuiColor)>,

    /// Print all TUI theme items and exit
    #[arg(long, display_order = 34)]
    pub print_tui_theme_items: bool,

    /// The TUI key bindings [command=key,command=key,..]
    #[arg(long, value_delimiter(','), value_parser = parse_tui_binding_value, display_order = 35)]
    pub tui_key_bindings: Vec<(TuiCommandItem, TuiKeyBinding)>,

    /// Print all TUI commands that can be bound and exit
    #[arg(long, display_order = 36)]
    pub print_tui_binding_commands: bool,

    /// The number of report cycles to run [default: 10]
    #[arg(short = 'C', long, display_order = 37)]
    pub report_cycles: Option<usize>,

    /// The MaxMind City GeoLite2 mmdb file
    #[arg(short = 'G', long, display_order = 38, value_hint = clap::ValueHint::FilePath)]
    pub geoip_mmdb_file: Option<String>,

    /// Generate shell completion
    #[arg(long, display_order = 39)]
    pub generate: Option<Shell>,

    /// The debug log format [default: pretty]
    #[arg(long, display_order = 40)]
    pub log_format: Option<LogFormat>,

    /// The debug log filter [default: trippy=debug]
    #[arg(long, display_order = 41)]
    pub log_filter: Option<String>,

    /// The debug log format [default: off]
    #[arg(long, display_order = 42)]
    pub log_span_events: Option<LogSpanEvents>,

    /// Enable verbose debug logging
    #[arg(short = 'v', long, default_value_t = false, display_order = 43)]
    pub verbose: bool,
}

fn parse_tui_theme_color_value(value: &str) -> anyhow::Result<(TuiThemeItem, TuiColor)> {
    let pos = value
        .find('=')
        .ok_or_else(|| anyhow!("invalid theme value: expected format `item=value`"))?;
    let item = TuiThemeItem::try_from(&value[..pos])?;
    let color = TuiColor::try_from(&value[pos + 1..])?;
    Ok((item, color))
}

fn parse_tui_binding_value(value: &str) -> anyhow::Result<(TuiCommandItem, TuiKeyBinding)> {
    let pos = value
        .find('=')
        .ok_or_else(|| anyhow!("invalid binding value: expected format `item=value`"))?;
    let item = TuiCommandItem::try_from(&value[..pos])?;
    let binding = TuiKeyBinding::try_from(&value[pos + 1..])?;
    Ok((item, binding))
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
    pub report_cycles: usize,
    pub geoip_mmdb_file: Option<String>,
    pub max_rounds: Option<usize>,
    pub verbose: bool,
    pub log_format: LogFormat,
    pub log_filter: String,
    pub log_span_events: LogSpanEvents,
}

impl TryFrom<(Args, u16)> for TrippyConfig {
    type Error = anyhow::Error;

    #[allow(clippy::too_many_lines)]
    fn try_from(data: (Args, u16)) -> Result<Self, Self::Error> {
        let (args, pid) = data;
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
        let mode = cfg_layer(args.mode, cfg_file_trace.mode, DEFAULT_MODE);
        let verbose = args.verbose;
        let log_format = cfg_layer(
            args.log_format,
            cfg_file_trace.log_format,
            DEFAULT_LOG_FORMAT,
        );
        let log_filter = cfg_layer(
            args.log_filter,
            cfg_file_trace.log_filter,
            String::from(DEFAULT_LOG_FILTER),
        );
        let log_span_events = cfg_layer(
            args.log_span_events,
            cfg_file_trace.log_span_events,
            DEFAULT_LOG_SPAN_EVENTS,
        );
        let protocol = cfg_layer(
            args.protocol,
            cfg_file_strategy.protocol,
            DEFAULT_STRATEGY_PROTOCOL,
        );
        let target_port = cfg_layer_opt(args.target_port, cfg_file_strategy.target_port);
        let source_port = cfg_layer_opt(args.source_port, cfg_file_strategy.source_port);
        let source_address = cfg_layer_opt(args.source_address, cfg_file_strategy.source_address);
        let interface = cfg_layer_opt(args.interface, cfg_file_strategy.interface);
        let min_round_duration = cfg_layer(
            args.min_round_duration,
            cfg_file_strategy.min_round_duration,
            String::from(DEFAULT_STRATEGY_MIN_ROUND_DURATION),
        );
        let max_round_duration = cfg_layer(
            args.max_round_duration,
            cfg_file_strategy.max_round_duration,
            String::from(DEFAULT_STRATEGY_MAX_ROUND_DURATION),
        );
        let initial_sequence = cfg_layer(
            args.initial_sequence,
            cfg_file_strategy.initial_sequence,
            DEFAULT_STRATEGY_INITIAL_SEQUENCE,
        );
        let multipath_strategy_cfg = cfg_layer(
            args.multipath_strategy,
            cfg_file_strategy.multipath_strategy,
            DEFAULT_STRATEGY_MULTIPATH,
        );
        let grace_duration = cfg_layer(
            args.grace_duration,
            cfg_file_strategy.grace_duration,
            String::from(DEFAULT_STRATEGY_GRACE_DURATION),
        );
        let max_inflight = cfg_layer(
            args.max_inflight,
            cfg_file_strategy.max_inflight,
            DEFAULT_STRATEGY_MAX_INFLIGHT,
        );
        let first_ttl = cfg_layer(
            args.first_ttl,
            cfg_file_strategy.first_ttl,
            DEFAULT_STRATEGY_FIRST_TTL,
        );
        let max_ttl = cfg_layer(
            args.max_ttl,
            cfg_file_strategy.max_ttl,
            DEFAULT_STRATEGY_MAX_TTL,
        );
        let packet_size = cfg_layer(
            args.packet_size,
            cfg_file_strategy.packet_size,
            DEFAULT_STRATEGY_PACKET_SIZE,
        );
        let payload_pattern = cfg_layer(
            args.payload_pattern,
            cfg_file_strategy.payload_pattern,
            DEFAULT_STRATEGY_PAYLOAD_PATTERN,
        );
        let tos = cfg_layer(args.tos, cfg_file_strategy.tos, DEFAULT_STRATEGY_TOS);
        let read_timeout = cfg_layer(
            args.read_timeout,
            cfg_file_strategy.read_timeout,
            String::from(DEFAULT_STRATEGY_READ_TIMEOUT),
        );
        let tui_max_samples = cfg_layer(
            args.tui_max_samples,
            cfg_file_tui.tui_max_samples,
            DEFAULT_TUI_MAX_SAMPLES,
        );
        let tui_preserve_screen = cfg_layer(
            args.tui_preserve_screen,
            cfg_file_tui.tui_preserve_screen,
            DEFAULT_TUI_PRESERVE_SCREEN,
        );
        let tui_refresh_rate = cfg_layer(
            args.tui_refresh_rate,
            cfg_file_tui.tui_refresh_rate,
            String::from(DEFAULT_TUI_REFRESH_RATE),
        );
        let tui_address_mode = cfg_layer(
            args.tui_address_mode,
            cfg_file_tui.tui_address_mode,
            DEFAULT_TUI_ADDRESS_MODE,
        );
        let tui_as_mode = cfg_layer(
            args.tui_as_mode,
            cfg_file_tui.tui_as_mode,
            DEFAULT_TUI_AS_MODE,
        );
        let tui_geoip_mode = cfg_layer(
            args.tui_geoip_mode,
            cfg_file_tui.tui_geoip_mode,
            DEFAULT_TUI_GEOIP_MODE,
        );
        let tui_max_addrs = cfg_layer_opt(args.tui_max_addrs, cfg_file_tui.tui_max_addrs);
        let dns_resolve_method = cfg_layer(
            args.dns_resolve_method,
            cfg_file_dns.dns_resolve_method,
            DEFAULT_DNS_RESOLVE_METHOD,
        );
        let dns_lookup_as_info = cfg_layer(
            args.dns_lookup_as_info,
            cfg_file_dns.dns_lookup_as_info,
            DEFAULT_DNS_LOOKUP_AS_INFO,
        );
        let dns_timeout = cfg_layer(
            args.dns_timeout,
            cfg_file_dns.dns_timeout,
            String::from(DEFAULT_DNS_TIMEOUT),
        );
        let report_cycles = cfg_layer(
            args.report_cycles,
            cfg_file_report.report_cycles,
            DEFAULT_REPORT_CYCLES,
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
        validate_logging(mode, verbose)?;
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

fn validate_logging(mode: Mode, verbose: bool) -> anyhow::Result<()> {
    if matches!(mode, Mode::Tui) && verbose {
        Err(anyhow!("cannot enable verbose logging in tui mode"))
    } else {
        Ok(())
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
    if read_timeout < MIN_READ_TIMEOUT_MS || read_timeout > MAX_READ_TIMEOUT_MS {
        Err(anyhow!(
            "read-timeout ({:?}) must be between {:?} and {:?} inclusive",
            read_timeout,
            MIN_READ_TIMEOUT_MS,
            MAX_READ_TIMEOUT_MS
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
    if grace_duration < MIN_GRACE_DURATION_MS || grace_duration > MAX_GRACE_DURATION_MS {
        Err(anyhow!(
            "grace-duration ({:?}) must be between {:?} and {:?} inclusive",
            grace_duration,
            MIN_GRACE_DURATION_MS,
            MAX_GRACE_DURATION_MS
        ))
    } else {
        Ok(())
    }
}

/// Validate `packet_size`.
fn validate_packet_size(packet_size: u16) -> anyhow::Result<()> {
    if (MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&packet_size) {
        Ok(())
    } else {
        Err(anyhow!(
            "packet-size ({}) must be between {} and {} inclusive",
            packet_size,
            MIN_PACKET_SIZE,
            MAX_PACKET_SIZE
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
    if tui_refresh_rate < TUI_MIN_REFRESH_RATE_MS || tui_refresh_rate > TUI_MAX_REFRESH_RATE_MS {
        Err(anyhow!(
            "tui-refresh-rate ({:?}) must be between {:?} and {:?} inclusive",
            tui_refresh_rate,
            TUI_MIN_REFRESH_RATE_MS,
            TUI_MAX_REFRESH_RATE_MS
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
