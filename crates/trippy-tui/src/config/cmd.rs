use crate::config::binding::TuiCommandItem;
use crate::config::theme::TuiThemeItem;
use crate::config::{
    AddressFamilyConfig, AddressMode, AsMode, DnsResolveMethodConfig, GeoIpMode, IcmpExtensionMode,
    LogFormat, LogSpanEvents, Mode, MultipathStrategyConfig, ProtocolConfig, TuiColor,
    TuiKeyBinding,
};
use anyhow::anyhow;
use clap::Parser;
use clap_complete::Shell;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

/// Trace a route to a host and record statistics
#[expect(clippy::doc_markdown)]
#[derive(Parser, Debug)]
#[command(name = "trip", author, version, about, long_about = None, arg_required_else_help(true), styles=clap_cargo::style::CLAP_STYLING)]
pub struct Args {
    /// A space delimited list of hostnames and IPs to trace
    #[arg(required_unless_present_any(["print_tui_theme_items", "print_tui_binding_commands", "print_config_template", "generate", "generate_man", "print_locales"]), env = "TRIP_TARGETS")]
    pub targets: Vec<String>,

    /// Config file
    #[arg(value_enum, short = 'c', long, value_hint = clap::ValueHint::FilePath, env = "TRIP_CONFIG_FILE")]
    pub config_file: Option<String>,

    /// Output mode [default: tui]
    #[arg(value_enum, short = 'm', long, env = "TRIP_MODE")]
    pub mode: Option<Mode>,

    /// Trace without requiring elevated privileges on supported platforms [default: false]
    #[arg(short = 'u', long, env = "TRIP_UNPRIVILEGED")]
    pub unprivileged: bool,

    /// Tracing protocol [default: icmp]
    #[arg(value_enum, short = 'p', long, env = "TRIP_PROTOCOL")]
    pub protocol: Option<ProtocolConfig>,

    /// Trace using the UDP protocol
    #[arg(
        long,
        conflicts_with = "protocol",
        conflicts_with = "tcp",
        conflicts_with = "icmp",
        env = "TRIP_UDP"
    )]
    pub udp: bool,

    /// Trace using the TCP protocol
    #[arg(
        long,
        conflicts_with = "protocol",
        conflicts_with = "udp",
        conflicts_with = "icmp",
        env = "TRIP_TCP"
    )]
    pub tcp: bool,

    /// Trace using the ICMP protocol
    #[arg(
        long,
        conflicts_with = "protocol",
        conflicts_with = "udp",
        conflicts_with = "tcp",
        env = "TRIP_ICMP"
    )]
    pub icmp: bool,

    /// The address family [default: system]
    #[arg(value_enum, short = 'F', long, env = "TRIP_ADDR_FAMILY")]
    pub addr_family: Option<AddressFamilyConfig>,

    /// Use IPv4 only
    #[arg(
        short = '4',
        long,
        conflicts_with = "ipv6",
        conflicts_with = "addr_family",
        env = "TRIP_IPV4"
    )]
    pub ipv4: bool,

    /// Use IPv6 only
    #[arg(
        short = '6',
        long,
        conflicts_with = "ipv4",
        conflicts_with = "addr_family",
        env = "TRIP_IPV6"
    )]
    pub ipv6: bool,

    /// The target port (TCP & UDP only) [default: 80]
    #[arg(long, short = 'P', env = "TRIP_TARGET_PORT")]
    pub target_port: Option<u16>,

    /// The source port (TCP & UDP only) [default: auto]
    #[arg(long, short = 'S', env = "TRIP_SOURCE_PORT")]
    pub source_port: Option<u16>,

    /// The source IP address [default: auto]
    #[arg(short = 'A', long, value_parser = parse_addr, conflicts_with = "interface", env = "TRIP_SOURCE_ADDRESS")]
    pub source_address: Option<IpAddr>,

    /// The network interface [default: auto]
    #[arg(short = 'I', long, env = "TRIP_INTERFACE")]
    pub interface: Option<String>,

    /// The minimum duration of every round [default: 1s]
    #[arg(short = 'i', long, value_parser = parse_duration, env = "TRIP_MIN_ROUND_DURATION")]
    pub min_round_duration: Option<Duration>,

    /// The maximum duration of every round [default: 1s]
    #[arg(short = 'T', long, value_parser = parse_duration, env = "TRIP_MAX_ROUND_DURATION")]
    pub max_round_duration: Option<Duration>,

    /// The period of time to wait for additional ICMP responses after the target has responded
    /// [default: 100ms]
    #[arg(short = 'g', long, value_parser = parse_duration, env = "TRIP_GRACE_DURATION")]
    pub grace_duration: Option<Duration>,

    /// The initial sequence number [default: 33434]
    #[arg(long, env = "TRIP_INITIAL_SEQUENCE")]
    pub initial_sequence: Option<u16>,

    /// The Equal-cost Multi-Path routing strategy (UDP only) [default: classic]
    #[arg(value_enum, short = 'R', long, env = "TRIP_MULTIPATH_STRATEGY")]
    pub multipath_strategy: Option<MultipathStrategyConfig>,

    /// The maximum number of in-flight ICMP echo requests [default: 24]
    #[arg(short = 'U', long, env = "TRIP_MAX_INFLIGHT")]
    pub max_inflight: Option<u8>,

    /// The TTL to start from [default: 1]
    #[arg(short = 'f', long, env = "TRIP_FIRST_TTL")]
    pub first_ttl: Option<u8>,

    /// The maximum number of TTL hops [default: 64]
    #[arg(short = 't', long, env = "TRIP_MAX_TTL")]
    pub max_ttl: Option<u8>,

    /// The size of IP packet to send (IP header + ICMP header + payload) [default: 84]
    #[arg(long, env = "TRIP_PACKET_SIZE")]
    pub packet_size: Option<u16>,

    /// The repeating pattern in the payload of the ICMP packet [default: 0]
    #[arg(long, env = "TRIP_PAYLOAD_PATTERN")]
    pub payload_pattern: Option<u8>,

    /// The TOS (i.e. DSCP+ECN) IP header value (IPv4 only) [default: 0]
    #[arg(short = 'Q', long, env = "TRIP_TOS")]
    pub tos: Option<u8>,

    /// Parse ICMP extensions
    #[arg(short = 'e', long, env = "TRIP_ICMP_EXTENSIONS")]
    pub icmp_extensions: bool,

    /// The socket read timeout [default: 10ms]
    #[arg(long, value_parser = parse_duration, env = "TRIP_READ_TIMEOUT")]
    pub read_timeout: Option<Duration>,

    /// How to perform DNS queries [default: system]
    #[arg(value_enum, short = 'r', long, env = "TRIP_DNS_RESOLVE_METHOD")]
    pub dns_resolve_method: Option<DnsResolveMethodConfig>,

    /// Trace to all IPs resolved from DNS lookup [default: false]
    #[arg(short = 'y', long, env = "TRIP_DNS_RESOLVE_ALL")]
    pub dns_resolve_all: bool,

    /// The maximum time to wait to perform DNS queries [default: 5s]
    #[arg(long, value_parser = parse_duration, env = "TRIP_DNS_TIMEOUT")]
    pub dns_timeout: Option<Duration>,

    /// The time-to-live (TTL) of DNS entries [default: 300s]
    #[arg(long, value_parser = parse_duration, env = "TRIP_DNS_TTL")]
    pub dns_ttl: Option<Duration>,

    /// Lookup autonomous system (AS) information during DNS queries [default: false]
    #[arg(long, short = 'z', env = "TRIP_DNS_LOOKUP_AS_INFO")]
    pub dns_lookup_as_info: bool,

    /// The maximum number of samples to record per hop [default: 256]
    #[arg(long, short = 's', env = "TRIP_MAX_SAMPLES")]
    pub max_samples: Option<usize>,

    /// The maximum number of flows to record [default: 64]
    #[arg(long, env = "TRIP_MAX_FLOWS")]
    pub max_flows: Option<usize>,

    /// How to render addresses [default: host]
    #[arg(value_enum, short = 'a', long, env = "TRIP_TUI_ADDRESS_MODE")]
    pub tui_address_mode: Option<AddressMode>,

    /// How to render autonomous system (AS) information [default: asn]
    #[arg(value_enum, long, env = "TRIP_TUI_AS_MODE")]
    pub tui_as_mode: Option<AsMode>,

    /// Custom columns to be displayed in the TUI hops table [default: holsravbwdt]
    #[arg(long, env = "TRIP_TUI_CUSTOM_COLUMNS")]
    pub tui_custom_columns: Option<String>,

    /// How to render ICMP extensions [default: off]
    #[arg(value_enum, long, env = "TRIP_TUI_ICMP_EXTENSION_MODE")]
    pub tui_icmp_extension_mode: Option<IcmpExtensionMode>,

    /// How to render GeoIp information [default: short]
    #[arg(value_enum, long, env = "TRIP_TUI_GEOIP_MODE")]
    pub tui_geoip_mode: Option<GeoIpMode>,

    /// The maximum number of addresses to show per hop [default: auto]
    #[arg(short = 'M', long, env = "TRIP_TUI_MAX_ADDRS")]
    pub tui_max_addrs: Option<u8>,

    /// Preserve the screen on exit [default: false]
    #[arg(long, env = "TRIP_TUI_PRESERVE_SCREEN")]
    pub tui_preserve_screen: bool,

    /// The TUI refresh rate [default: 100ms]
    #[arg(long, value_parser = parse_duration, env = "TRIP_TUI_REFRESH_RATE")]
    pub tui_refresh_rate: Option<Duration>,

    /// The maximum ttl of hops which will be masked for privacy [default: none]
    ///
    /// If set, the source IP address and hostname will also be hidden.
    #[arg(long, env = "TRIP_TUI_PRIVACY_MAX_TTL")]
    pub tui_privacy_max_ttl: Option<u8>,

    /// The locale to use for the TUI [default: auto]
    #[arg(long, env = "TRIP_TUI_LOCALE")]
    pub tui_locale: Option<String>,

    /// The timezone to use for the TUI [default: auto]
    ///
    /// The timezone must be a valid IANA timezone identifier.
    #[arg(long, env = "TRIP_TUI_TIMEZONE")]
    pub tui_timezone: Option<String>,

    /// The TUI theme colors [item=color,item=color,..]
    #[arg(long, value_delimiter(','), value_parser = parse_tui_theme_color_value, env = "TRIP_TUI_THEME_COLORS")]
    pub tui_theme_colors: Vec<(TuiThemeItem, TuiColor)>,

    /// Print all TUI theme items and exit
    #[arg(long, env = "TRIP_PRINT_TUI_THEME_ITEMS")]
    pub print_tui_theme_items: bool,

    /// The TUI key bindings [command=key,command=key,..]
    #[arg(long, value_delimiter(','), value_parser = parse_tui_binding_value, env = "TRIP_TUI_KEY_BINDINGS")]
    pub tui_key_bindings: Vec<(TuiCommandItem, TuiKeyBinding)>,

    /// Print all TUI commands that can be bound and exit
    #[arg(long, env = "TRIP_PRINT_TUI_BINDING_COMMANDS")]
    pub print_tui_binding_commands: bool,

    /// The number of report cycles to run [default: 10]
    #[arg(short = 'C', long, env = "TRIP_REPORT_CYCLES")]
    pub report_cycles: Option<usize>,

    /// The supported MaxMind or IPinfo GeoIp mmdb file
    #[arg(short = 'G', long, value_hint = clap::ValueHint::FilePath, env = "TRIP_GEOIP_MMDB_FILE")]
    pub geoip_mmdb_file: Option<String>,

    /// Generate shell completion
    #[arg(long, env = "TRIP_GENERATE")]
    pub generate: Option<Shell>,

    /// Generate ROFF man page
    #[arg(long, env = "TRIP_GENERATE_MAN")]
    pub generate_man: bool,

    /// Print a template toml config file and exit
    #[arg(long, env = "TRIP_PRINT_CONFIG_TEMPLATE")]
    pub print_config_template: bool,

    /// Print all available TUI locales and exit
    #[arg(long, env = "TRIP_PRINT_LOCALES")]
    pub print_locales: bool,

    /// The debug log format [default: pretty]
    #[arg(long, env = "TRIP_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// The debug log filter [default: trippy=debug]
    #[arg(long, env = "TRIP_LOG_FILTER")]
    pub log_filter: Option<String>,

    /// The debug log format [default: off]
    #[arg(long, env = "TRIP_LOG_SPAN_EVENTS")]
    pub log_span_events: Option<LogSpanEvents>,

    /// Enable verbose debug logging
    #[arg(short = 'v', long, default_value_t = false, env = "TRIP_VERBOSE")]
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
    if item == TuiCommandItem::DeprecatedTogglePrivacy {
        return Err(anyhow!(
            "toggle-privacy is deprecated, use expand-privacy and contract-privacy instead"
        ));
    }
    Ok((item, binding))
}

fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    Ok(humantime::parse_duration(value)?)
}

fn parse_addr(value: &str) -> anyhow::Result<IpAddr> {
    Ok(IpAddr::from_str(value)?)
}
