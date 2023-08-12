use crate::config::binding::TuiCommandItem;
use crate::config::theme::TuiThemeItem;
use crate::config::{
    AddressMode, AsMode, DnsResolveMethod, GeoIpMode, LogFormat, LogSpanEvents, Mode,
    MultipathStrategyConfig, Protocol, TuiColor, TuiKeyBinding,
};
use anyhow::anyhow;
use clap::Parser;
use clap_complete::Shell;

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
