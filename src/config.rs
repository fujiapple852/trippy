use anyhow::anyhow;
use clap::{ArgEnum, Parser};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use trippy::tracing::TracerProtocol;

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
#[derive(Debug, Copy, Clone, ArgEnum)]
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
#[derive(Debug, Copy, Clone, ArgEnum)]
pub enum TraceProtocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

/// How to render the addresses.
#[derive(Debug, Copy, Clone, ArgEnum)]
pub enum AddressMode {
    /// Show IP address only.
    IP,
    /// Show reverse-lookup DNS hostname only.
    Host,
    /// Show both IP address and reverse-lookup DNS hostname.
    Both,
}

/// How DNS queries wil be resolved.
#[derive(Debug, Copy, Clone, ArgEnum)]
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
    #[clap(arg_enum, short = 'm', long, default_value = "tui", display_order = 1)]
    pub mode: Mode,

    /// Tracing protocol.
    #[clap(arg_enum, short = 'p', long, default_value = "icmp", display_order = 2)]
    pub protocol: TraceProtocol,

    /// The destination port (TCP only)
    #[clap(long, short = 'P', default_value_t = 80, display_order = 3)]
    pub port: u16,

    /// The source port (UDP only)
    #[clap(long, display_order = 4)]
    pub source_port: Option<u16>,

    /// The source IP address
    #[clap(short = 'A', long, display_order = 5)]
    pub source_address: Option<String>,

    /// The minimum duration of every round
    #[clap(short = 'i', long, default_value = "1s", display_order = 6)]
    pub min_round_duration: String,

    /// The maximum duration of every round
    #[clap(short = 'I', long, default_value = "1s", display_order = 7)]
    pub max_round_duration: String,

    /// The initial sequence number
    #[clap(long, default_value_t = 33000, display_order = 8)]
    pub initial_sequence: u16,

    /// The period of time to wait for additional ICMP responses after the target has responded
    #[clap(short = 'g', long, default_value = "100ms", display_order = 9)]
    pub grace_duration: String,

    /// The maximum number of in-flight ICMP echo requests
    #[clap(short = 'U', long, default_value_t = 24, display_order = 10)]
    pub max_inflight: u8,

    /// The TTL to start from
    #[clap(long, default_value_t = 1, display_order = 11)]
    pub first_ttl: u8,

    /// The maximum number of TTL hops
    #[clap(short = 't', long, default_value_t = 64, display_order = 12)]
    pub max_ttl: u8,

    /// The size of IP packet to send (IP header + ICMP header + payload)
    #[clap(long, default_value_t = 84, display_order = 13)]
    pub packet_size: u16,

    /// The repeating pattern in the payload of the ICMP packet
    #[clap(long, default_value_t = 0, display_order = 14)]
    pub payload_pattern: u8,

    /// The socket read timeout
    #[clap(long, default_value = "10ms", display_order = 15)]
    pub read_timeout: String,

    /// How to perform DNS queries.
    #[clap(
        arg_enum,
        short = 'r',
        long,
        default_value = "system",
        display_order = 16
    )]
    pub dns_resolve_method: DnsResolveMethod,

    /// The maximum time to wait to perform DNS queries.
    #[clap(long, default_value = "5s", display_order = 17)]
    pub dns_timeout: String,

    /// Lookup autonomous system (AS) information during DNS queries.
    #[clap(long, short = 'z', display_order = 18)]
    pub dns_lookup_as_info: bool,

    /// How to render addresses.
    #[clap(
        arg_enum,
        short = 'a',
        long,
        default_value = "host",
        display_order = 19
    )]
    pub tui_address_mode: AddressMode,

    /// The maximum number of addresses to show per hop
    #[clap(long, display_order = 20)]
    pub tui_max_addrs: Option<u8>,

    /// The maximum number of samples to record per hop
    #[clap(long, short = 's', default_value_t = 256, display_order = 21)]
    pub tui_max_samples: usize,

    /// Preserve the screen on exit
    #[clap(long, display_order = 22)]
    pub tui_preserve_screen: bool,

    /// The TUI refresh rate
    #[clap(long, default_value = "100ms", display_order = 23)]
    pub tui_refresh_rate: String,

    /// The number of report cycles to run
    #[clap(short = 'c', long, default_value_t = 10, display_order = 24)]
    pub report_cycles: usize,
}

/// Fully parsed and validate configuration.
pub struct TrippyConfig {
    pub targets: Vec<String>,
    pub protocol: TracerProtocol,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub grace_duration: Duration,
    pub max_inflight: u8,
    pub initial_sequence: u16,
    pub read_timeout: Duration,
    pub packet_size: u16,
    pub payload_pattern: u8,
    pub source_addr: Option<IpAddr>,
    pub source_port: u16,
    pub destination_port: u16,
    pub dns_timeout: Duration,
    pub dns_resolve_method: DnsResolveMethod,
    pub dns_lookup_as_info: bool,
    pub tui_max_samples: usize,
    pub tui_preserve_screen: bool,
    pub tui_refresh_rate: Duration,
    pub tui_address_mode: AddressMode,
    pub tui_max_addrs: Option<u8>,
    pub mode: Mode,
    pub report_cycles: usize,
    pub max_rounds: Option<usize>,
}

impl TryFrom<(Args, u16)> for TrippyConfig {
    type Error = anyhow::Error;

    fn try_from(data: (Args, u16)) -> Result<Self, Self::Error> {
        let (args, pid) = data;
        let protocol = match args.protocol {
            TraceProtocol::Icmp => TracerProtocol::Icmp,
            TraceProtocol::Udp => TracerProtocol::Udp,
            TraceProtocol::Tcp => TracerProtocol::Tcp,
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
        let source_port = args.source_port.unwrap_or_else(|| pid.max(1024));
        let tui_refresh_rate = humantime::parse_duration(&args.tui_refresh_rate)?;
        let dns_timeout = humantime::parse_duration(&args.dns_timeout)?;
        let max_rounds = match args.mode {
            Mode::Stream | Mode::Tui => None,
            Mode::Pretty | Mode::Markdown | Mode::Csv | Mode::Json => Some(args.report_cycles),
        };
        validate_multi(args.mode, args.protocol, &args.targets)?;
        validate_ttl(args.first_ttl, args.max_ttl)?;
        validate_max_inflight(args.max_inflight)?;
        validate_read_timeout(read_timeout)?;
        validate_round_duration(min_round_duration, max_round_duration)?;
        validate_grace_duration(grace_duration)?;
        validate_packet_size(args.packet_size)?;
        validate_source_port(source_port)?;
        validate_tui_refresh_rate(tui_refresh_rate)?;
        validate_report_cycles(args.report_cycles)?;
        validate_dns(args.dns_resolve_method, args.dns_lookup_as_info)?;
        Ok(Self {
            targets: args.targets,
            protocol,
            first_ttl: args.first_ttl,
            max_ttl: args.max_ttl,
            min_round_duration,
            max_round_duration,
            grace_duration,
            max_inflight: args.max_inflight,
            initial_sequence: args.initial_sequence,
            read_timeout,
            packet_size: args.packet_size,
            payload_pattern: args.payload_pattern,
            source_addr: source_address,
            source_port,
            destination_port: args.port,
            dns_timeout,
            dns_resolve_method: args.dns_resolve_method,
            dns_lookup_as_info: args.dns_lookup_as_info,
            tui_max_samples: args.tui_max_samples,
            tui_preserve_screen: args.tui_preserve_screen,
            tui_refresh_rate,
            tui_address_mode: args.tui_address_mode,
            tui_max_addrs: args.tui_max_addrs,
            mode: args.mode,
            report_cycles: args.report_cycles,
            max_rounds,
        })
    }
}

/// We only allow multiple targets to be specified for the Tui and for `Icmp` tracing.
pub fn validate_multi(
    mode: Mode,
    protocol: TraceProtocol,
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
        (_, TraceProtocol::Tcp | TraceProtocol::Udp) if targets.len() > 1 => Err(anyhow!(
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
