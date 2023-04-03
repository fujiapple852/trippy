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

/// The minimum packet size we allow.
pub const MIN_PACKET_SIZE: u16 = 28;

/// The maximum packet size we allow.
pub const MAX_PACKET_SIZE: u16 = 1024;

/// The tool mode.
#[derive(Debug, Copy, Clone, ValueEnum)]
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
#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum Protocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

/// The strategy Equal-cost Multi-Path routing strategy.
#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum MultipathStrategyConfig {
    /// The src or dest port is used to store the sequence number.
    Classic,
    /// The UDP `checksum` field is used to store the sequence number.
    Paris,
    /// The IP `identifier` field is used to store the sequence number.
    Dublin,
}

/// How to render the addresses.
#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum AddressMode {
    /// Show IP address only.
    IP,
    /// Show reverse-lookup DNS hostname only.
    Host,
    /// Show both IP address and reverse-lookup DNS hostname.
    Both,
}

/// How to render AS information.
#[derive(Debug, Copy, Clone, ValueEnum)]
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
#[derive(Debug, Copy, Clone, ValueEnum)]
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

    /// Output mode
    #[clap(
        value_enum,
        short = 'm',
        long,
        default_value = "tui",
        display_order = 1
    )]
    pub mode: Mode,

    /// Tracing protocol
    #[clap(
        value_enum,
        short = 'p',
        long,
        default_value = "icmp",
        display_order = 2
    )]
    pub protocol: Protocol,

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

    /// The minimum duration of every round
    #[clap(short = 'i', long, default_value = "1s", display_order = 11)]
    pub min_round_duration: String,

    /// The maximum duration of every round
    #[clap(short = 'T', long, default_value = "1s", display_order = 12)]
    pub max_round_duration: String,

    /// The initial sequence number
    #[clap(long, default_value_t = 33000, display_order = 13)]
    pub initial_sequence: u16,

    /// The Equal-cost Multi-Path routing strategy (IPv4/UDP only).
    #[clap(
        value_enum,
        short = 'R',
        long,
        default_value = "classic",
        display_order = 14
    )]
    pub multipath_strategy: MultipathStrategyConfig,

    /// The period of time to wait for additional ICMP responses after the target has responded
    #[clap(short = 'g', long, default_value = "100ms", display_order = 15)]
    pub grace_duration: String,

    /// The maximum number of in-flight ICMP echo requests
    #[clap(short = 'U', long, default_value_t = 24, display_order = 16)]
    pub max_inflight: u8,

    /// The TTL to start from
    #[clap(short = 'f', long, default_value_t = 1, display_order = 17)]
    pub first_ttl: u8,

    /// The maximum number of TTL hops
    #[clap(short = 't', long, default_value_t = 64, display_order = 18)]
    pub max_ttl: u8,

    /// The size of IP packet to send (IP header + ICMP header + payload)
    #[clap(long, default_value_t = 84, display_order = 19)]
    pub packet_size: u16,

    /// The repeating pattern in the payload of the ICMP packet
    #[clap(long, default_value_t = 0, display_order = 20)]
    pub payload_pattern: u8,

    /// The TOS (i.e. DSCP+ECN) IP header value (TCP and UDP only)
    #[clap(short = 'Q', long, default_value_t = 0, display_order = 21)]
    pub tos: u8,

    /// The socket read timeout
    #[clap(long, default_value = "10ms", display_order = 22)]
    pub read_timeout: String,

    /// How to perform DNS queries.
    #[clap(
        value_enum,
        short = 'r',
        long,
        default_value = "system",
        display_order = 23
    )]
    pub dns_resolve_method: DnsResolveMethod,

    /// The maximum time to wait to perform DNS queries.
    #[clap(long, default_value = "5s", display_order = 24)]
    pub dns_timeout: String,

    /// Lookup autonomous system (AS) information during DNS queries.
    #[clap(long, short = 'z', display_order = 25)]
    pub dns_lookup_as_info: bool,

    /// How to render addresses.
    #[clap(
        value_enum,
        short = 'a',
        long,
        default_value = "host",
        display_order = 26
    )]
    pub tui_address_mode: AddressMode,

    /// How to render AS information.
    #[clap(value_enum, long, default_value = "asn", display_order = 27)]
    pub tui_as_mode: AsMode,

    /// The maximum number of addresses to show per hop
    #[clap(short = 'M', long, display_order = 28)]
    pub tui_max_addrs: Option<u8>,

    /// The maximum number of samples to record per hop
    #[clap(long, short = 's', default_value_t = 256, display_order = 29)]
    pub tui_max_samples: usize,

    /// Preserve the screen on exit
    #[clap(long, display_order = 30)]
    pub tui_preserve_screen: bool,

    /// The TUI refresh rate
    #[clap(long, default_value = "100ms", display_order = 31)]
    pub tui_refresh_rate: String,

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
    #[clap(short = 'c', long, default_value_t = 10, display_order = 36)]
    pub report_cycles: usize,
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

impl From<HashMap<TuiThemeItem, TuiColor>> for TuiTheme {
    fn from(value: HashMap<TuiThemeItem, TuiColor>) -> Self {
        Self {
            bg_color: *value
                .get(&TuiThemeItem::BgColor)
                .unwrap_or(&TuiColor::Black),
            border_color: *value
                .get(&TuiThemeItem::BorderColor)
                .unwrap_or(&TuiColor::Gray),
            text_color: *value
                .get(&TuiThemeItem::TextColor)
                .unwrap_or(&TuiColor::Gray),
            tab_text_color: *value
                .get(&TuiThemeItem::TabTextColor)
                .unwrap_or(&TuiColor::Green),
            hops_table_header_bg_color: *value
                .get(&TuiThemeItem::HopsTableHeaderBgColor)
                .unwrap_or(&TuiColor::White),
            hops_table_header_text_color: *value
                .get(&TuiThemeItem::HopsTableHeaderTextColor)
                .unwrap_or(&TuiColor::Black),
            hops_table_row_active_text_color: *value
                .get(&TuiThemeItem::HopsTableRowActiveTextColor)
                .unwrap_or(&TuiColor::Gray),
            hops_table_row_inactive_text_color: *value
                .get(&TuiThemeItem::HopsTableRowInactiveTextColor)
                .unwrap_or(&TuiColor::DarkGray),
            hops_chart_selected_color: *value
                .get(&TuiThemeItem::HopsChartSelectedColor)
                .unwrap_or(&TuiColor::Green),
            hops_chart_unselected_color: *value
                .get(&TuiThemeItem::HopsChartUnselectedColor)
                .unwrap_or(&TuiColor::Gray),
            hops_chart_axis_color: *value
                .get(&TuiThemeItem::HopsChartAxisColor)
                .unwrap_or(&TuiColor::DarkGray),
            frequency_chart_bar_color: *value
                .get(&TuiThemeItem::FrequencyChartBarColor)
                .unwrap_or(&TuiColor::Green),
            frequency_chart_text_color: *value
                .get(&TuiThemeItem::FrequencyChartTextColor)
                .unwrap_or(&TuiColor::Gray),
            samples_chart_color: *value
                .get(&TuiThemeItem::SamplesChartColor)
                .unwrap_or(&TuiColor::Yellow),
            help_dialog_bg_color: *value
                .get(&TuiThemeItem::HelpDialogBgColor)
                .unwrap_or(&TuiColor::Blue),
            help_dialog_text_color: *value
                .get(&TuiThemeItem::HelpDialogTextColor)
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
#[derive(Debug, Clone, Copy)]
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
    pub up: TuiKeyBinding,
    pub down: TuiKeyBinding,
    pub left: TuiKeyBinding,
    pub right: TuiKeyBinding,
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
            (self.up, PreviousHop),
            (self.down, NextHop),
            (self.left, PreviousTrace),
            (self.right, NextTrace),
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

impl From<HashMap<TuiCommandItem, TuiKeyBinding>> for TuiBindings {
    fn from(value: HashMap<TuiCommandItem, TuiKeyBinding>) -> Self {
        Self {
            toggle_help: *value
                .get(&ToggleHelp)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('h'))),
            up: *value
                .get(&PreviousHop)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Up)),
            down: *value
                .get(&NextHop)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Down)),
            left: *value
                .get(&PreviousTrace)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Left)),
            right: *value
                .get(&NextTrace)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Right)),
            address_mode_ip: *value
                .get(&AddressModeIp)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('i'))),
            address_mode_host: *value
                .get(&AddressModeHost)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('n'))),
            address_mode_both: *value
                .get(&AddressModeBoth)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('b'))),
            toggle_freeze: *value
                .get(&ToggleFreeze)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('f'))),
            toggle_chart: *value
                .get(&ToggleChart)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('c'))),
            expand_hosts: *value
                .get(&ExpandHosts)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char(']'))),
            contract_hosts: *value
                .get(&ContractHosts)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('['))),
            expand_hosts_max: *value
                .get(&ExpandHostsMax)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('}'))),
            contract_hosts_min: *value
                .get(&ContractHostsMin)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('{'))),
            chart_zoom_in: *value
                .get(&ChartZoomIn)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('='))),
            chart_zoom_out: *value
                .get(&ChartZoomOut)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('-'))),
            clear_trace_data: *value.get(&ClearTraceData).unwrap_or(
                &TuiKeyBinding::new_with_modifier(KeyCode::Char('r'), KeyModifiers::CONTROL),
            ),
            clear_dns_cache: *value.get(&ClearDnsCache).unwrap_or(
                &TuiKeyBinding::new_with_modifier(KeyCode::Char('k'), KeyModifiers::CONTROL),
            ),
            clear_selection: *value
                .get(&ClearSelection)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Esc)),
            toggle_as_info: *value
                .get(&ToggleASInfo)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('z'))),
            quit: *value
                .get(&Quit)
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('q'))),
        }
    }
}

/// Tui key binding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
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
        let protocol = match (args.udp, args.tcp, args.protocol) {
            (false, false, Protocol::Icmp) => TracerProtocol::Icmp,
            (false, false, Protocol::Udp) | (true, _, _) => TracerProtocol::Udp,
            (false, false, Protocol::Tcp) | (_, true, _) => TracerProtocol::Tcp,
        };
        let read_timeout = humantime::parse_duration(&args.read_timeout)?;
        let min_round_duration = humantime::parse_duration(&args.min_round_duration)?;
        let max_round_duration = humantime::parse_duration(&args.max_round_duration)?;
        let grace_duration = humantime::parse_duration(&args.grace_duration)?;
        let source_address = args
            .source_address
            .as_ref()
            .map(|addr| {
                IpAddr::from_str(addr)
                    .map_err(|_| anyhow!("invalid source IP address format: {}", addr))
            })
            .transpose()?;
        let addr_family = if args.ipv6 {
            TracerAddrFamily::Ipv6
        } else {
            TracerAddrFamily::Ipv4
        };
        let multipath_strategy = match (args.multipath_strategy, addr_family) {
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
        let port_direction = match (
            protocol,
            args.source_port,
            args.target_port,
            args.multipath_strategy,
        ) {
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
        let tui_refresh_rate = humantime::parse_duration(&args.tui_refresh_rate)?;
        let dns_timeout = humantime::parse_duration(&args.dns_timeout)?;
        let max_rounds = match args.mode {
            Mode::Stream | Mode::Tui => None,
            Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json => Some(args.report_cycles),
        };
        validate_multi(args.mode, protocol, &args.targets)?;
        validate_ttl(args.first_ttl, args.max_ttl)?;
        validate_max_inflight(args.max_inflight)?;
        validate_read_timeout(read_timeout)?;
        validate_round_duration(min_round_duration, max_round_duration)?;
        validate_grace_duration(grace_duration)?;
        validate_packet_size(args.packet_size)?;
        validate_tui_refresh_rate(tui_refresh_rate)?;
        validate_report_cycles(args.report_cycles)?;
        validate_dns(args.dns_resolve_method, args.dns_lookup_as_info)?;
        let tui_theme = TuiTheme::from(
            args.tui_theme_colors
                .into_iter()
                .collect::<HashMap<TuiThemeItem, TuiColor>>(),
        );
        let tui_bindings = TuiBindings::from(
            args.tui_key_bindings
                .into_iter()
                .collect::<HashMap<TuiCommandItem, TuiKeyBinding>>(),
        );
        validate_bindings(&tui_bindings)?;
        Ok(Self {
            targets: args.targets,
            protocol,
            addr_family,
            first_ttl: args.first_ttl,
            max_ttl: args.max_ttl,
            min_round_duration,
            max_round_duration,
            grace_duration,
            max_inflight: args.max_inflight,
            initial_sequence: args.initial_sequence,
            multipath_strategy,
            read_timeout,
            packet_size: args.packet_size,
            payload_pattern: args.payload_pattern,
            tos: args.tos,
            source_addr: source_address,
            interface: args.interface,
            port_direction,
            dns_timeout,
            dns_resolve_method: args.dns_resolve_method,
            dns_lookup_as_info: args.dns_lookup_as_info,
            tui_max_samples: args.tui_max_samples,
            tui_preserve_screen: args.tui_preserve_screen,
            tui_refresh_rate,
            tui_address_mode: args.tui_address_mode,
            tui_as_mode: args.tui_as_mode,
            tui_max_addrs: args.tui_max_addrs,
            tui_theme,
            tui_bindings,
            mode: args.mode,
            report_cycles: args.report_cycles,
            max_rounds,
        })
    }
}

/// We only allow multiple targets to be specified for the Tui and for `Icmp` tracing.
pub fn validate_multi(
    mode: Mode,
    protocol: TracerProtocol,
    targets: &[String],
) -> anyhow::Result<()> {
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
pub fn validate_ttl(first_ttl: u8, max_ttl: u8) -> anyhow::Result<()> {
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
pub fn validate_max_inflight(max_inflight: u8) -> anyhow::Result<()> {
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
pub fn validate_read_timeout(read_timeout: Duration) -> anyhow::Result<()> {
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
pub fn validate_round_duration(
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
pub fn validate_grace_duration(grace_duration: Duration) -> anyhow::Result<()> {
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
pub fn validate_packet_size(packet_size: u16) -> anyhow::Result<()> {
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
pub fn validate_source_port(source_port: u16) -> anyhow::Result<()> {
    if source_port < 1024 {
        Err(anyhow!("source_port ({}) must be >= 1024", source_port))
    } else {
        Ok(())
    }
}

/// Validate `tui_refresh_rate`.
pub fn validate_tui_refresh_rate(tui_refresh_rate: Duration) -> anyhow::Result<()> {
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
pub fn validate_report_cycles(report_cycles: usize) -> anyhow::Result<()> {
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
pub fn validate_dns(
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
pub fn validate_bindings(bindings: &TuiBindings) -> anyhow::Result<()> {
    let duplicates = bindings.find_duplicates();
    if duplicates.is_empty() {
        Ok(())
    } else {
        let dup_str = duplicates.iter().join(", ");
        Err(anyhow!("Duplicate key bindings: {dup_str}"))
    }
}
