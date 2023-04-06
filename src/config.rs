use crate::config::config_file::{ConfigBindings, ConfigFile, ConfigThemeColors};
use crate::config::TuiCommandItem::{
    AddressModeBoth, AddressModeHost, AddressModeIp, ChartZoomIn, ChartZoomOut, ClearDnsCache,
    ClearSelection, ClearTraceData, ContractHosts, ContractHostsMin, ExpandHosts, ExpandHostsMax,
    NextHop, NextTrace, PreviousHop, PreviousTrace, Quit, ToggleASInfo, ToggleChart, ToggleFreeze,
    ToggleHelp,
};
use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use crossterm::event::{KeyCode, KeyModifiers};
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use strum::{AsRefStr, EnumString, EnumVariantNames, VariantNames};
use trippy::tracing::{MultipathStrategy, PortDirection, TracerAddrFamily, TracerProtocol};

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
    /// Generate a SCV report for N cycles.
    Csv,
    /// Generate a JSON report for N cycles.
    Json,
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

/// Trace a route to a host and record statistics
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// A space delimited list of hostnames and IPs to trace
    #[clap(required = true)]
    pub targets: Vec<String>,

    /// Config file
    #[clap(value_enum, short = 'c', long, display_order = 0)]
    pub config_file: Option<String>,

    /// Output mode
    #[clap(value_enum, short = 'm', long, display_order = 1)]
    pub mode: Option<Mode>,

    /// Tracing protocol [default: icmp]
    #[clap(value_enum, short = 'p', long, display_order = 2)]
    pub protocol: Option<Protocol>,

    /// Trace using the UDP protocol
    #[clap(
        long,
        display_order = 3,
        conflicts_with = "protocol",
        conflicts_with = "tcp"
    )]
    pub udp: bool,

    /// Trace using the TCP protocol
    #[clap(
        long,
        display_order = 4,
        conflicts_with = "protocol",
        conflicts_with = "udp"
    )]
    pub tcp: bool,

    /// use IPv4 only
    #[clap(short = '4', long, display_order = 5, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Use IPv6 only
    #[clap(short = '6', long, display_order = 6, conflicts_with = "ipv4")]
    pub ipv6: bool,

    /// The target port (TCP & UDP only) [default: 80]
    #[clap(long, short = 'P', display_order = 7)]
    pub target_port: Option<u16>,

    /// The source port (TCP & UDP only) [default: auto]
    #[clap(long, short = 'S', display_order = 8)]
    pub source_port: Option<u16>,

    /// The source IP address [default: auto]
    #[clap(short = 'A', long, display_order = 9, conflicts_with = "interface")]
    pub source_address: Option<String>,

    /// The network interface [default: auto]
    #[clap(short = 'I', long, display_order = 10)]
    pub interface: Option<String>,

    /// The minimum duration of every round [default: 1s]
    #[clap(short = 'i', long, display_order = 11)]
    pub min_round_duration: Option<String>,

    /// The maximum duration of every round [default: 1s]
    #[clap(short = 'T', long, display_order = 12)]
    pub max_round_duration: Option<String>,

    /// The period of time to wait for additional ICMP responses after the target has responded [default: 100ms]
    #[clap(short = 'g', long, display_order = 13)]
    pub grace_duration: Option<String>,

    /// The initial sequence number [default: 33000]
    #[clap(long, display_order = 14)]
    pub initial_sequence: Option<u16>,

    /// The Equal-cost Multi-Path routing strategy (IPv4/UDP only) [default: classic]
    #[clap(value_enum, short = 'R', long, display_order = 15)]
    pub multipath_strategy: Option<MultipathStrategyConfig>,

    /// The maximum number of in-flight ICMP echo requests [default: 24]
    #[clap(short = 'U', long, display_order = 16)]
    pub max_inflight: Option<u8>,

    /// The TTL to start from [default: 1]
    #[clap(short = 'f', long, display_order = 17)]
    pub first_ttl: Option<u8>,

    /// The maximum number of TTL hops [default: 64]
    #[clap(short = 't', long, display_order = 18)]
    pub max_ttl: Option<u8>,

    /// The size of IP packet to send (IP header + ICMP header + payload) [default: 84]
    #[clap(long, display_order = 19)]
    pub packet_size: Option<u16>,

    /// The repeating pattern in the payload of the ICMP packet [default: 0]
    #[clap(long, display_order = 20)]
    pub payload_pattern: Option<u8>,

    /// The TOS (i.e. DSCP+ECN) IP header value (TCP and UDP only) [default: 0]
    #[clap(short = 'Q', long, display_order = 21)]
    pub tos: Option<u8>,

    /// The socket read timeout [default: 10ms]
    #[clap(long, display_order = 22)]
    pub read_timeout: Option<String>,

    /// How to perform DNS queries.
    #[clap(value_enum, short = 'r', long, display_order = 23)]
    pub dns_resolve_method: Option<DnsResolveMethod>,

    /// The maximum time to wait to perform DNS queries.
    #[clap(long, display_order = 24)]
    pub dns_timeout: Option<String>,

    /// Lookup autonomous system (AS) information during DNS queries.
    #[clap(long, short = 'z', display_order = 25)]
    pub dns_lookup_as_info: Option<bool>,

    /// How to render addresses.
    #[clap(value_enum, short = 'a', long, display_order = 26)]
    pub tui_address_mode: Option<AddressMode>,

    /// How to render AS information.
    #[clap(value_enum, long, display_order = 27)]
    pub tui_as_mode: Option<AsMode>,

    /// The maximum number of addresses to show per hop
    #[clap(short = 'M', long, display_order = 28)]
    pub tui_max_addrs: Option<u8>,

    /// The maximum number of samples to record per hop
    #[clap(long, short = 's', display_order = 29)]
    pub tui_max_samples: Option<usize>,

    /// Preserve the screen on exit
    #[clap(long, display_order = 30)]
    pub tui_preserve_screen: Option<bool>,

    /// The TUI refresh rate
    #[clap(long, display_order = 31)]
    pub tui_refresh_rate: Option<String>,

    /// The TUI theme colors [item=color,item=color,..]
    #[clap(long, value_delimiter(','), value_parser = parse_tui_theme_color_value, display_order = 32)]
    pub tui_theme_colors: Vec<(TuiThemeItem, TuiColor)>,

    /// Print all TUI theme items and exit
    #[clap(long, display_order = 33)]
    pub print_tui_theme_items: bool,

    /// The TUI key bindings [command=key,command=key,..]
    #[clap(long, value_delimiter(','), value_parser = parse_tui_binding_value, display_order = 34)]
    pub tui_key_bindings: Vec<(TuiCommandItem, TuiKeyBinding)>,

    /// Print all TUI commands that can be bound and exit
    #[clap(long, display_order = 35)]
    pub print_tui_binding_commands: bool,

    /// The number of report cycles to run
    #[clap(short = 'C', long, display_order = 36)]
    pub report_cycles: Option<usize>,
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
    pub tui_max_addrs: Option<u8>,
    pub tui_theme: TuiTheme,
    pub tui_bindings: TuiBindings,
    pub mode: Mode,
    pub report_cycles: usize,
    pub max_rounds: Option<usize>,
}

/// Tui color theme.
#[derive(Debug, Clone, Copy)]
pub struct TuiTheme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    pub bg_color: TuiColor,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    pub border_color: TuiColor,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    pub text_color: TuiColor,
    /// The color of the text in traces tabs.
    pub tab_text_color: TuiColor,
    /// The background color of the hops table header.
    pub hops_table_header_bg_color: TuiColor,
    /// The color of text in the hops table header.
    pub hops_table_header_text_color: TuiColor,
    /// The color of text of active rows in the hops table.
    pub hops_table_row_active_text_color: TuiColor,
    /// The color of text of inactive rows in the hops table.
    pub hops_table_row_inactive_text_color: TuiColor,
    /// The color of the selected series in the hops chart.
    pub hops_chart_selected_color: TuiColor,
    /// The color of the unselected series in the hops chart.
    pub hops_chart_unselected_color: TuiColor,
    /// The color of the axis in the hops chart.
    pub hops_chart_axis_color: TuiColor,
    /// The color of bars in the frequency chart.
    pub frequency_chart_bar_color: TuiColor,
    /// The color of text in the bars of the frequency chart.
    pub frequency_chart_text_color: TuiColor,
    /// The color of the samples chart.
    pub samples_chart_color: TuiColor,
    /// The background color of the help dialog.
    pub help_dialog_bg_color: TuiColor,
    /// The color of the text in the help dialog.
    pub help_dialog_text_color: TuiColor,
}

impl From<(HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)> for TuiTheme {
    fn from(value: (HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)) -> Self {
        let (color_map, cfg) = value;
        Self {
            bg_color: *color_map
                .get(&TuiThemeItem::BgColor)
                .or(cfg.bg_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            border_color: *color_map
                .get(&TuiThemeItem::BorderColor)
                .or(cfg.border_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            text_color: *color_map
                .get(&TuiThemeItem::TextColor)
                .or(cfg.text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            tab_text_color: *color_map
                .get(&TuiThemeItem::TabTextColor)
                .or(cfg.tab_text_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            hops_table_header_bg_color: *color_map
                .get(&TuiThemeItem::HopsTableHeaderBgColor)
                .or(cfg.hops_table_header_bg_color.as_ref())
                .unwrap_or(&TuiColor::White),
            hops_table_header_text_color: *color_map
                .get(&TuiThemeItem::HopsTableHeaderTextColor)
                .or(cfg.hops_table_header_text_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            hops_table_row_active_text_color: *color_map
                .get(&TuiThemeItem::HopsTableRowActiveTextColor)
                .or(cfg.hops_table_row_active_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            hops_table_row_inactive_text_color: *color_map
                .get(&TuiThemeItem::HopsTableRowInactiveTextColor)
                .or(cfg.hops_table_row_inactive_text_color.as_ref())
                .unwrap_or(&TuiColor::DarkGray),
            hops_chart_selected_color: *color_map
                .get(&TuiThemeItem::HopsChartSelectedColor)
                .or(cfg.hops_chart_selected_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            hops_chart_unselected_color: *color_map
                .get(&TuiThemeItem::HopsChartUnselectedColor)
                .or(cfg.hops_chart_unselected_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            hops_chart_axis_color: *color_map
                .get(&TuiThemeItem::HopsChartAxisColor)
                .or(cfg.hops_chart_axis_color.as_ref())
                .unwrap_or(&TuiColor::DarkGray),
            frequency_chart_bar_color: *color_map
                .get(&TuiThemeItem::FrequencyChartBarColor)
                .or(cfg.frequency_chart_bar_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            frequency_chart_text_color: *color_map
                .get(&TuiThemeItem::FrequencyChartTextColor)
                .or(cfg.frequency_chart_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            samples_chart_color: *color_map
                .get(&TuiThemeItem::SamplesChartColor)
                .or(cfg.samples_chart_color.as_ref())
                .unwrap_or(&TuiColor::Yellow),
            help_dialog_bg_color: *color_map
                .get(&TuiThemeItem::HelpDialogBgColor)
                .or(cfg.help_dialog_bg_color.as_ref())
                .unwrap_or(&TuiColor::Blue),
            help_dialog_text_color: *color_map
                .get(&TuiThemeItem::HelpDialogTextColor)
                .or(cfg.help_dialog_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
        }
    }
}

/// A TUI theme item.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
pub enum TuiThemeItem {
    /// The default background color.
    BgColor,
    /// The default color of borders.
    BorderColor,
    /// The default color of text.
    TextColor,
    /// The color of the text in traces tabs.
    TabTextColor,
    /// The background color of the hops table header.
    HopsTableHeaderBgColor,
    /// The color of text in the hops table header.
    HopsTableHeaderTextColor,
    /// The color of text of active rows in the hops table.
    HopsTableRowActiveTextColor,
    /// The color of text of inactive rows in the hops table.
    HopsTableRowInactiveTextColor,
    /// The color of the selected series in the hops chart.
    HopsChartSelectedColor,
    /// The color of the unselected series in the hops chart.
    HopsChartUnselectedColor,
    /// The color of the axis in the hops chart.
    HopsChartAxisColor,
    /// The color of bars in the frequency chart.
    FrequencyChartBarColor,
    /// The color of text in the bars of the frequency chart.
    FrequencyChartTextColor,
    /// The color of the samples chart.
    SamplesChartColor,
    /// The background color of the help dialog.
    HelpDialogBgColor,
    /// The color of the text in the help dialog.
    HelpDialogTextColor,
}

/// A TUI color.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
pub enum TuiColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Gray,
    DarkGray,
    LightRed,
    LightGreen,
    LightYellow,
    LightBlue,
    LightMagenta,
    LightCyan,
    White,
    Rgb(u8, u8, u8),
}

impl TryFrom<String> for TuiColor {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for TuiColor {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().replace('-', "").as_ref() {
            "black" => Ok(Self::Black),
            "red" => Ok(Self::Red),
            "green" => Ok(Self::Green),
            "yellow" => Ok(Self::Yellow),
            "blue" => Ok(Self::Blue),
            "magenta" => Ok(Self::Magenta),
            "cyan" => Ok(Self::Cyan),
            "gray" => Ok(Self::Gray),
            "darkgray" => Ok(Self::DarkGray),
            "lightred" => Ok(Self::LightRed),
            "lightgreen" => Ok(Self::LightGreen),
            "lightyellow" => Ok(Self::LightYellow),
            "lightblue" => Ok(Self::LightBlue),
            "lightmagenta" => Ok(Self::LightMagenta),
            "lightcyan" => Ok(Self::LightCyan),
            "white" => Ok(Self::White),
            rgb_hex if value.len() == 6 && value.chars().all(|c| c.is_ascii_hexdigit()) => {
                let red = u8::from_str_radix(&rgb_hex[0..2], 16)?;
                let green = u8::from_str_radix(&rgb_hex[2..4], 16)?;
                let blue = u8::from_str_radix(&rgb_hex[4..6], 16)?;
                Ok(Self::Rgb(red, green, blue))
            }
            _ => Err(anyhow!("unknown color: {value}")),
        }
    }
}

/// Tui keyboard bindings.
#[derive(Debug, Clone, Copy)]
pub struct TuiBindings {
    pub toggle_help: TuiKeyBinding,
    pub previous_hop: TuiKeyBinding,
    pub next_hop: TuiKeyBinding,
    pub previous_trace: TuiKeyBinding,
    pub next_trace: TuiKeyBinding,
    pub address_mode_ip: TuiKeyBinding,
    pub address_mode_host: TuiKeyBinding,
    pub address_mode_both: TuiKeyBinding,
    pub toggle_freeze: TuiKeyBinding,
    pub toggle_chart: TuiKeyBinding,
    pub expand_hosts: TuiKeyBinding,
    pub contract_hosts: TuiKeyBinding,
    pub expand_hosts_max: TuiKeyBinding,
    pub contract_hosts_min: TuiKeyBinding,
    pub chart_zoom_in: TuiKeyBinding,
    pub chart_zoom_out: TuiKeyBinding,
    pub clear_trace_data: TuiKeyBinding,
    pub clear_dns_cache: TuiKeyBinding,
    pub clear_selection: TuiKeyBinding,
    pub toggle_as_info: TuiKeyBinding,
    pub quit: TuiKeyBinding,
}

impl TuiBindings {
    /// Validate the bindings.
    ///
    /// Returns any duplicate bindings.
    pub fn find_duplicates(&self) -> Vec<String> {
        let (_, duplicates) = [
            (self.toggle_help, ToggleHelp),
            (self.previous_hop, PreviousHop),
            (self.next_hop, NextHop),
            (self.previous_trace, PreviousTrace),
            (self.next_trace, NextTrace),
            (self.address_mode_ip, AddressModeIp),
            (self.address_mode_host, AddressModeHost),
            (self.address_mode_both, AddressModeBoth),
            (self.toggle_freeze, ToggleFreeze),
            (self.toggle_chart, ToggleChart),
            (self.expand_hosts, ExpandHosts),
            (self.expand_hosts_max, ExpandHostsMax),
            (self.contract_hosts, ContractHosts),
            (self.contract_hosts_min, ContractHostsMin),
            (self.chart_zoom_in, ChartZoomIn),
            (self.chart_zoom_out, ChartZoomOut),
            (self.clear_trace_data, ClearTraceData),
            (self.clear_dns_cache, ClearDnsCache),
            (self.clear_selection, ClearSelection),
            (self.toggle_as_info, ToggleASInfo),
            (self.quit, Quit),
        ]
        .iter()
        .fold(
            (HashMap::<TuiKeyBinding, TuiCommandItem>::new(), Vec::new()),
            |(mut all, mut dups), (binding, item)| {
                if let Some(existing) = all.get(binding) {
                    dups.push(format!(
                        "{}: [{} and {}]",
                        binding,
                        item.as_ref(),
                        existing.as_ref()
                    ));
                } else {
                    all.insert(*binding, *item);
                }
                (all, dups)
            },
        );
        duplicates
    }
}

impl From<(HashMap<TuiCommandItem, TuiKeyBinding>, ConfigBindings)> for TuiBindings {
    fn from(value: (HashMap<TuiCommandItem, TuiKeyBinding>, ConfigBindings)) -> Self {
        let (cmd_items, cfg) = value;
        Self {
            toggle_help: *cmd_items
                .get(&ToggleHelp)
                .or(cfg.toggle_help.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('h'))),
            previous_hop: *cmd_items
                .get(&PreviousHop)
                .or(cfg.previous_hop.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Up)),
            next_hop: *cmd_items
                .get(&NextHop)
                .or(cfg.next_hop.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Down)),
            previous_trace: *cmd_items
                .get(&PreviousTrace)
                .or(cfg.previous_trace.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Left)),
            next_trace: *cmd_items
                .get(&NextTrace)
                .or(cfg.next_trace.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Right)),
            address_mode_ip: *cmd_items
                .get(&AddressModeIp)
                .or(cfg.address_mode_ip.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('i'))),
            address_mode_host: *cmd_items
                .get(&AddressModeHost)
                .or(cfg.address_mode_host.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('n'))),
            address_mode_both: *cmd_items
                .get(&AddressModeBoth)
                .or(cfg.address_mode_both.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('b'))),
            toggle_freeze: *cmd_items
                .get(&ToggleFreeze)
                .or(cfg.toggle_freeze.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('f'))),
            toggle_chart: *cmd_items
                .get(&ToggleChart)
                .or(cfg.toggle_chart.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('c'))),
            expand_hosts: *cmd_items
                .get(&ExpandHosts)
                .or(cfg.expand_hosts.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char(']'))),
            contract_hosts: *cmd_items
                .get(&ContractHosts)
                .or(cfg.contract_hosts.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('['))),
            expand_hosts_max: *cmd_items
                .get(&ExpandHostsMax)
                .or(cfg.expand_hosts_max.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('}'))),
            contract_hosts_min: *cmd_items
                .get(&ContractHostsMin)
                .or(cfg.contract_hosts_min.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('{'))),
            chart_zoom_in: *cmd_items
                .get(&ChartZoomIn)
                .or(cfg.chart_zoom_in.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('='))),
            chart_zoom_out: *cmd_items
                .get(&ChartZoomOut)
                .or(cfg.chart_zoom_out.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('-'))),
            clear_trace_data: *cmd_items
                .get(&ClearTraceData)
                .or(cfg.clear_trace_data.as_ref())
                .unwrap_or(&TuiKeyBinding::new_with_modifier(
                    KeyCode::Char('r'),
                    KeyModifiers::CONTROL,
                )),
            clear_dns_cache: *cmd_items
                .get(&ClearDnsCache)
                .or(cfg.clear_dns_cache.as_ref())
                .unwrap_or(&TuiKeyBinding::new_with_modifier(
                    KeyCode::Char('k'),
                    KeyModifiers::CONTROL,
                )),
            clear_selection: *cmd_items
                .get(&ClearSelection)
                .or(cfg.clear_selection.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Esc)),
            toggle_as_info: *cmd_items
                .get(&ToggleASInfo)
                .or(cfg.toggle_as_info.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('z'))),
            quit: *cmd_items
                .get(&Quit)
                .or(cfg.quit.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('q'))),
        }
    }
}

/// Tui key binding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct TuiKeyBinding {
    pub code: KeyCode,
    pub modifier: KeyModifiers,
}

impl TuiKeyBinding {
    pub fn new(code: KeyCode) -> Self {
        Self {
            code,
            modifier: KeyModifiers::NONE,
        }
    }

    pub fn new_with_modifier(code: KeyCode, modifier: KeyModifiers) -> Self {
        Self { code, modifier }
    }
}

impl TryFrom<String> for TuiKeyBinding {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for TuiKeyBinding {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const ALL_MODIFIERS: [(&str, KeyModifiers); 6] = [
            ("shift", KeyModifiers::SHIFT),
            ("ctrl", KeyModifiers::CONTROL),
            ("alt", KeyModifiers::ALT),
            ("super", KeyModifiers::SUPER),
            ("hyper", KeyModifiers::HYPER),
            ("meta", KeyModifiers::META),
        ];
        const ALL_SPECIAL_KEYS: [(&str, KeyCode); 16] = [
            ("backspace", KeyCode::Backspace),
            ("enter", KeyCode::Enter),
            ("left", KeyCode::Left),
            ("right", KeyCode::Right),
            ("up", KeyCode::Up),
            ("down", KeyCode::Down),
            ("home", KeyCode::Home),
            ("end", KeyCode::End),
            ("pageup", KeyCode::PageUp),
            ("pagedown", KeyCode::PageDown),
            ("tab", KeyCode::Tab),
            ("backtab", KeyCode::BackTab),
            ("delete", KeyCode::Delete),
            ("insert", KeyCode::Insert),
            ("null", KeyCode::Null),
            ("esc", KeyCode::Esc),
        ];
        fn parse_keycode(value: &str) -> anyhow::Result<KeyCode> {
            Ok(if value.len() == 1 {
                KeyCode::Char(char::from_str(value)?.to_ascii_lowercase())
            } else {
                ALL_SPECIAL_KEYS
                    .iter()
                    .find_map(|(keycode_str, keycode)| {
                        if keycode_str.eq_ignore_ascii_case(value) {
                            Some(*keycode)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| anyhow!("unknown key binding '{}'", value))?
            })
        }
        fn parse_modifiers(modifiers: &str) -> anyhow::Result<KeyModifiers> {
            modifiers
                .split('+')
                .fold(Ok(KeyModifiers::NONE), |key_modifiers, token| {
                    key_modifiers.and_then(|modifiers| {
                        ALL_MODIFIERS
                            .iter()
                            .find_map(|(modifier_token, modifier)| {
                                if modifier_token.eq_ignore_ascii_case(token) {
                                    Some(modifiers | *modifier)
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| anyhow!("unknown modifier '{}'", token,))
                    })
                })
        }
        match value.rsplit_once('+') {
            Some((modifiers, value)) => Ok(Self {
                code: parse_keycode(value)?,
                modifier: parse_modifiers(modifiers)?,
            }),
            None => Ok(Self {
                code: parse_keycode(value)?,
                modifier: KeyModifiers::NONE,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("c", KeyCode::Char('c'), KeyModifiers::NONE; "char without any modifier")]
    #[test_case("1", KeyCode::Char('1'), KeyModifiers::NONE; "number without any modifier")]
    #[test_case(",", KeyCode::Char(','), KeyModifiers::NONE; "punctuation without any modifier")]
    #[test_case("backspace", KeyCode::Backspace, KeyModifiers::NONE; "backspace without any modifier")]
    #[test_case("enter", KeyCode::Enter, KeyModifiers::NONE; "enter without any modifier")]
    #[test_case("left", KeyCode::Left, KeyModifiers::NONE; "left without any modifier")]
    #[test_case("right", KeyCode::Right, KeyModifiers::NONE; "right without any modifier")]
    #[test_case("up", KeyCode::Up, KeyModifiers::NONE; "up without any modifier")]
    #[test_case("down", KeyCode::Down, KeyModifiers::NONE; "down without any modifier")]
    #[test_case("home", KeyCode::Home, KeyModifiers::NONE; "home without any modifier")]
    #[test_case("end", KeyCode::End, KeyModifiers::NONE; "end without any modifier")]
    #[test_case("pageup", KeyCode::PageUp, KeyModifiers::NONE; "pageup without any modifier")]
    #[test_case("pagedown", KeyCode::PageDown, KeyModifiers::NONE; "pagedown without any modifier")]
    #[test_case("tab", KeyCode::Tab, KeyModifiers::NONE; "tab without any modifier")]
    #[test_case("backtab", KeyCode::BackTab, KeyModifiers::NONE; "backtab without any modifier")]
    #[test_case("delete", KeyCode::Delete, KeyModifiers::NONE; "delete without any modifier")]
    #[test_case("insert", KeyCode::Insert, KeyModifiers::NONE; "insert without any modifier")]
    #[test_case("null", KeyCode::Null, KeyModifiers::NONE; "null without any modifier")]
    #[test_case("esc", KeyCode::Esc, KeyModifiers::NONE; "escape without any modifier")]
    #[test_case("shift+c", KeyCode::Char('c'), KeyModifiers::SHIFT; "with shift modifier")]
    #[test_case("ctrl+i", KeyCode::Char('i'), KeyModifiers::CONTROL; "i with ctrl modifier")]
    #[test_case("shift+I", KeyCode::Char('i'), KeyModifiers::SHIFT; "I with shift modifier")]
    #[test_case("alt+c", KeyCode::Char('c'), KeyModifiers::ALT; "with alt modifier")]
    #[test_case("super+c", KeyCode::Char('c'), KeyModifiers::SUPER; "with super modifier")]
    #[test_case("hyper+c", KeyCode::Char('c'), KeyModifiers::HYPER; "with hyper modifier")]
    #[test_case("meta+c", KeyCode::Char('c'), KeyModifiers::META; "with meta modifier")]
    #[test_case("alt+shift+k", KeyCode::Char('k'), KeyModifiers::ALT | KeyModifiers::SHIFT; "with alt shift modifier")]
    #[test_case("ctrl+up", KeyCode::Up, KeyModifiers::CONTROL; "up with ctrl modifier")]
    #[test_case("shift+ctrl+alt+super+hyper+meta+k", KeyCode::Char('k'), KeyModifiers::all(); "with all modifiers")]
    fn test_key_binding(input: &str, code: KeyCode, modifiers: KeyModifiers) -> anyhow::Result<()> {
        let binding = TuiKeyBinding::try_from(input)?;
        assert_eq!(binding.code, code);
        assert_eq!(binding.modifier, modifiers);
        Ok(())
    }

    #[test]
    fn test_unknown_modifier() {
        let binding = TuiKeyBinding::try_from("foo+c");
        assert!(binding.is_err());
        assert_eq!(&binding.unwrap_err().to_string(), "unknown modifier 'foo'");
    }

    #[test]
    fn test_unknown_second_modifier() {
        let binding = TuiKeyBinding::try_from("alt+foo+c");
        assert!(binding.is_err());
        assert_eq!(&binding.unwrap_err().to_string(), "unknown modifier 'foo'");
    }

    #[test]
    fn test_unknown_key() {
        let binding = TuiKeyBinding::try_from("foo");
        assert!(binding.is_err());
        assert_eq!(
            &binding.unwrap_err().to_string(),
            "unknown key binding 'foo'"
        );
    }
}

impl Display for TuiKeyBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.modifier.contains(KeyModifiers::SHIFT) {
            write!(f, "shift+")?;
        }
        if self.modifier.contains(KeyModifiers::CONTROL) {
            write!(f, "ctrl+")?;
        }
        if self.modifier.contains(KeyModifiers::ALT) {
            write!(f, "alt+")?;
        }
        if self.modifier.contains(KeyModifiers::SUPER) {
            write!(f, "super+")?;
        }
        if self.modifier.contains(KeyModifiers::HYPER) {
            write!(f, "hyper+")?;
        }
        if self.modifier.contains(KeyModifiers::META) {
            write!(f, "meta+")?;
        }
        match self.code {
            KeyCode::Backspace => write!(f, "backspace"),
            KeyCode::Enter => write!(f, "enter"),
            KeyCode::Left => write!(f, "left"),
            KeyCode::Right => write!(f, "right"),
            KeyCode::Up => write!(f, "up"),
            KeyCode::Down => write!(f, "down"),
            KeyCode::Home => write!(f, "home"),
            KeyCode::End => write!(f, "end"),
            KeyCode::PageUp => write!(f, "pageup"),
            KeyCode::PageDown => write!(f, "pagedown"),
            KeyCode::Tab => write!(f, "tab"),
            KeyCode::BackTab => write!(f, "backtab"),
            KeyCode::Delete => write!(f, "delete"),
            KeyCode::Insert => write!(f, "insert"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::Null => write!(f, "null"),
            KeyCode::Esc => write!(f, "esc"),
            _ => write!(f, "unknown"),
        }
    }
}

/// A Tui command that can be bound to a key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
#[derive(AsRefStr)]
#[allow(clippy::enum_variant_names)]
pub enum TuiCommandItem {
    /// Toggle the help dialog.
    ToggleHelp,
    /// Move down to the next hop.
    NextHop,
    /// Move up to the previous hop.
    PreviousHop,
    /// Move right to the next trace.
    NextTrace,
    /// Move left to the previous trace.
    PreviousTrace,
    /// Show IP address mode.
    AddressModeIp,
    /// Show hostname mode.
    AddressModeHost,
    /// Show hostname and IP address mode.
    AddressModeBoth,
    /// Toggle freezing the display.
    ToggleFreeze,
    /// Toggle the chart.
    ToggleChart,
    /// Expand hosts.
    ExpandHosts,
    /// Expand hosts to max.
    ExpandHostsMax,
    /// Contract hosts.
    ContractHosts,
    /// Contract hosts to min.
    ContractHostsMin,
    /// Zoom chart in.
    ChartZoomIn,
    /// Zoom chart out.
    ChartZoomOut,
    /// Clear all tracing data.
    ClearTraceData,
    /// Clear DNS cache.
    ClearDnsCache,
    /// Clear hop selection.
    ClearSelection,
    /// Toggle AS info.
    ToggleASInfo,
    /// Quit the application.
    Quit,
}

pub mod config_file {
    use crate::config::{
        AddressFamily, AddressMode, AsMode, DnsResolveMethod, Mode, MultipathStrategyConfig,
        Protocol, TuiColor, TuiKeyBinding,
    };
    use anyhow::Context;
    use serde::Deserialize;
    use std::fs::File;
    use std::io::read_to_string;
    use std::path::{Path, PathBuf};

    const DEFAULT_CONFIG_FILE: &str = "trippy.toml";
    const DEFAULT_HIDDEN_CONFIG_FILE: &str = ".trippy.toml";

    /// Read the config from the default location of user config for the platform.
    ///
    /// Returns the parsed `Some(ConfigFile)` if the config file exists, `None` otherwise.
    ///
    /// Trippy will attempt to locate a `trippy.toml` or `.trippy.toml`
    /// config file in one of the following platform specific locations:
    ///     - the current directory
    ///     - the user home directory
    ///     - the user config direction
    ///
    /// For example, on Linux the Trippy will attempt to locate the following
    /// files (in order):
    ///     - `./trippy.toml`
    ///     - `./.trippy.toml`
    ///     - `$HOME/trippy.toml`
    ///     - `$HOME/.trippy.toml`
    ///     - `$HOME/.config/trippy.toml`
    ///     - `$HOME/.config/.trippy.toml`
    ///
    /// See [here](https://github.com/dirs-dev/dirs-rs) for platform specific directory
    /// information.
    ///
    /// Note that only the first config file found is used, no attempt is
    /// made to merge the values from multiple files.
    pub fn read_default_config_file() -> anyhow::Result<Option<ConfigFile>> {
        if let Some(file) = read_file(|| Some(PathBuf::new()), DEFAULT_CONFIG_FILE)? {
            Ok(Some(file))
        } else if let Some(file) = read_file(|| Some(PathBuf::new()), DEFAULT_HIDDEN_CONFIG_FILE)? {
            Ok(Some(file))
        } else if let Some(file) = read_file(dirs::home_dir, DEFAULT_CONFIG_FILE)? {
            Ok(Some(file))
        } else if let Some(file) = read_file(dirs::home_dir, DEFAULT_HIDDEN_CONFIG_FILE)? {
            Ok(Some(file))
        } else if let Some(file) = read_file(dirs::config_dir, DEFAULT_CONFIG_FILE)? {
            Ok(Some(file))
        } else if let Some(file) = read_file(dirs::config_dir, DEFAULT_HIDDEN_CONFIG_FILE)? {
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }

    /// Read the config from the given path.
    pub fn read_config_file<P: AsRef<Path>>(path: P) -> anyhow::Result<ConfigFile> {
        println!("{:?}", path.as_ref());
        let file = File::open(path.as_ref())
            .with_context(|| format!("config file not found: {:?}", path.as_ref()))?;
        Ok(toml::from_str(&read_to_string(file)?)?)
    }

    fn read_file<F: FnOnce() -> Option<PathBuf>>(
        dir: F,
        file: &str,
    ) -> anyhow::Result<Option<ConfigFile>> {
        if let Some(mut path) = dir() {
            path.push(file);
            if path.exists() {
                Ok(Some(read_config_file(path)?))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigFile {
        pub trippy: Option<ConfigTrippy>,
        pub strategy: Option<ConfigStrategy>,
        pub theme_colors: Option<ConfigThemeColors>,
        pub bindings: Option<ConfigBindings>,
        pub tui: Option<ConfigTui>,
        pub dns: Option<ConfigDns>,
        pub report: Option<ConfigReport>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigTrippy {
        pub mode: Option<Mode>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigStrategy {
        pub protocol: Option<Protocol>,
        pub addr_family: Option<AddressFamily>,
        pub target_port: Option<u16>,
        pub source_port: Option<u16>,
        pub source_address: Option<String>,
        pub interface: Option<String>,
        pub min_round_duration: Option<String>,
        pub max_round_duration: Option<String>,
        pub initial_sequence: Option<u16>,
        pub multipath_strategy: Option<MultipathStrategyConfig>,
        pub grace_duration: Option<String>,
        pub max_inflight: Option<u8>,
        pub first_ttl: Option<u8>,
        pub max_ttl: Option<u8>,
        pub packet_size: Option<u16>,
        pub payload_pattern: Option<u8>,
        pub tos: Option<u8>,
        pub read_timeout: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigDns {
        pub dns_resolve_method: Option<DnsResolveMethod>,
        pub dns_lookup_as_info: Option<bool>,
        pub dns_timeout: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigReport {
        pub report_cycles: Option<usize>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigTui {
        pub tui_max_samples: Option<usize>,
        pub tui_preserve_screen: Option<bool>,
        pub tui_refresh_rate: Option<String>,
        pub tui_address_mode: Option<AddressMode>,
        pub tui_as_mode: Option<AsMode>,
        pub tui_max_addrs: Option<u8>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigThemeColors {
        pub bg_color: Option<TuiColor>,
        pub border_color: Option<TuiColor>,
        pub text_color: Option<TuiColor>,
        pub tab_text_color: Option<TuiColor>,
        pub hops_table_header_bg_color: Option<TuiColor>,
        pub hops_table_header_text_color: Option<TuiColor>,
        pub hops_table_row_active_text_color: Option<TuiColor>,
        pub hops_table_row_inactive_text_color: Option<TuiColor>,
        pub hops_chart_selected_color: Option<TuiColor>,
        pub hops_chart_unselected_color: Option<TuiColor>,
        pub hops_chart_axis_color: Option<TuiColor>,
        pub frequency_chart_bar_color: Option<TuiColor>,
        pub frequency_chart_text_color: Option<TuiColor>,
        pub samples_chart_color: Option<TuiColor>,
        pub help_dialog_bg_color: Option<TuiColor>,
        pub help_dialog_text_color: Option<TuiColor>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct ConfigBindings {
        pub toggle_help: Option<TuiKeyBinding>,
        pub previous_hop: Option<TuiKeyBinding>,
        pub next_hop: Option<TuiKeyBinding>,
        pub previous_trace: Option<TuiKeyBinding>,
        pub next_trace: Option<TuiKeyBinding>,
        pub address_mode_ip: Option<TuiKeyBinding>,
        pub address_mode_host: Option<TuiKeyBinding>,
        pub address_mode_both: Option<TuiKeyBinding>,
        pub toggle_freeze: Option<TuiKeyBinding>,
        pub toggle_chart: Option<TuiKeyBinding>,
        pub expand_hosts: Option<TuiKeyBinding>,
        pub contract_hosts: Option<TuiKeyBinding>,
        pub expand_hosts_max: Option<TuiKeyBinding>,
        pub contract_hosts_min: Option<TuiKeyBinding>,
        pub chart_zoom_in: Option<TuiKeyBinding>,
        pub chart_zoom_out: Option<TuiKeyBinding>,
        pub clear_trace_data: Option<TuiKeyBinding>,
        pub clear_dns_cache: Option<TuiKeyBinding>,
        pub clear_selection: Option<TuiKeyBinding>,
        pub toggle_as_info: Option<TuiKeyBinding>,
        pub quit: Option<TuiKeyBinding>,
    }
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
        let cfg_file = if let Some(cfg) = args.config_file {
            config_file::read_config_file(cfg)?
        } else if let Some(cfg) = config_file::read_default_config_file()? {
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
            (MultipathStrategyConfig::Paris, _) => {
                Err(anyhow!("Paris multipath strategy not implemented yet!"))
            }
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
            (TracerProtocol::Udp, Some(src), Some(dest), MultipathStrategyConfig::Dublin) => {
                validate_source_port(src)?;
                PortDirection::new_fixed_both(src, dest)
            }
            (_, Some(_), Some(_), _) => {
                return Err(anyhow!(
                    "only one of source-port and target-port may be fixed (except IPv4/udp protocol with dublin strategy)"
                ));
            }
        };
        let tui_refresh_rate = humantime::parse_duration(&tui_refresh_rate)?;
        let dns_timeout = humantime::parse_duration(&dns_timeout)?;
        let max_rounds = match mode {
            Mode::Stream | Mode::Tui => None,
            Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json => Some(report_cycles),
        };
        let tui_max_addrs = match tui_max_addrs {
            Some(n) if n > 0 => Some(n),
            _ => None,
        };
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
            tui_max_addrs,
            tui_theme,
            tui_bindings,
            mode,
            report_cycles,
            max_rounds,
        })
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
            "first_ttl ({first_ttl}) must be in the range 1..{MAX_HOPS}"
        ))
    } else if (max_ttl as usize) < 1 || (max_ttl as usize) > MAX_HOPS {
        Err(anyhow!(
            "max_ttl ({max_ttl}) must be in the range 1..{MAX_HOPS}"
        ))
    } else if first_ttl > max_ttl {
        Err(anyhow!(
            "first_ttl ({first_ttl}) must be less than or equal to max_ttl ({max_ttl})"
        ))
    } else {
        Ok(())
    }
}

/// Validate `max_inflight`.
fn validate_max_inflight(max_inflight: u8) -> anyhow::Result<()> {
    if max_inflight == 0 {
        Err(anyhow!(
            "max_inflight ({}) must be greater than zero",
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
            "read_timeout ({:?}) must be between {:?} and {:?} inclusive",
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
            "max_round_duration ({:?}) must not be less than min_round_duration ({:?})",
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
            "grace_duration ({:?}) must be between {:?} and {:?} inclusive",
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
            "packet_size ({}) must be between {} and {} inclusive",
            packet_size,
            MIN_PACKET_SIZE,
            MAX_PACKET_SIZE
        ))
    }
}

/// Validate `source_port`.
fn validate_source_port(source_port: u16) -> anyhow::Result<()> {
    if source_port < 1024 {
        Err(anyhow!("source_port ({}) must be >= 1024", source_port))
    } else {
        Ok(())
    }
}

/// Validate `tui_refresh_rate`.
fn validate_tui_refresh_rate(tui_refresh_rate: Duration) -> anyhow::Result<()> {
    if tui_refresh_rate < TUI_MIN_REFRESH_RATE_MS || tui_refresh_rate > TUI_MAX_REFRESH_RATE_MS {
        Err(anyhow!(
            "tui_refresh_rate ({:?}) must be between {:?} and {:?} inclusive",
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
            "report_cycles ({}) must be greater than zero",
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
