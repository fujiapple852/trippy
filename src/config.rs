use clap::{ArgEnum, Parser};
use std::process::exit;
use std::time::Duration;

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

/// Trace a route to a host and record statistics
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The hostname or IP to scan
    pub hostname: String,

    /// Tracing protocol.
    #[clap(arg_enum, short = 'p', long, default_value = "icmp")]
    pub protocol: TraceProtocol,

    /// The TTL to start from
    #[clap(long, default_value_t = 1)]
    pub first_ttl: u8,

    /// The maximum number of hops
    #[clap(short = 't', long, default_value_t = 64)]
    pub max_ttl: u8,

    /// The minimum duration of every round
    #[clap(short = 'i', long, default_value = "1s")]
    pub min_round_duration: String,

    /// The maximum duration of every round
    #[clap(short = 'I', long, default_value = "1s")]
    pub max_round_duration: String,

    /// The period of time to wait for additional ICMP responses after the target has responded
    #[clap(short = 'g', long, default_value = "100ms")]
    pub grace_duration: String,

    /// The maximum number of in-flight ICMP echo requests
    #[clap(short = 'U', long, default_value_t = 24)]
    pub max_inflight: u8,

    /// The initial sequence number
    #[clap(long, default_value_t = 33000)]
    pub initial_sequence: u16,

    /// The socket read timeout
    #[clap(long, default_value = "10ms")]
    pub read_timeout: String,

    /// The size of IP packet to send (IP header + ICMP header + payload)
    #[clap(long, default_value_t = 84)]
    pub packet_size: u16,

    /// The repeating pattern in the payload of the ICMP packet
    #[clap(long, default_value_t = 0)]
    pub payload_pattern: u8,

    /// The source port (TCP & UDP only)
    #[clap(long)]
    pub source_port: Option<u16>,

    /// Preserve the screen on exit
    #[clap(long)]
    pub tui_preserve_screen: bool,

    /// The TUI refresh rate
    #[clap(long, default_value = "100ms")]
    pub tui_refresh_rate: String,

    /// How to render addresses.
    #[clap(arg_enum, short = 'a', long, default_value = "host")]
    pub tui_address_mode: AddressMode,

    /// The maximum number of addresses to show per hop
    #[clap(long)]
    pub tui_max_addresses_per_hop: Option<u8>,

    /// Output mode
    #[clap(arg_enum, short = 'm', long, default_value = "tui")]
    pub mode: Mode,

    /// The number of report cycles to run
    #[clap(short = 'c', long, default_value_t = 10)]
    pub report_cycles: usize,
}

/// Validate `report_cycles`
pub fn validate_report_cycles(report_cycles: usize) {
    if report_cycles == 0 {
        eprintln!(
            "report_cycles ({}) must be greater than zero",
            report_cycles
        );
        exit(-1);
    }
}

/// Validate `tui_refresh_rate`
pub fn validate_tui_refresh_rate(tui_refresh_rate: Duration) {
    if tui_refresh_rate < TUI_MIN_REFRESH_RATE_MS || tui_refresh_rate > TUI_MAX_REFRESH_RATE_MS {
        eprintln!(
            "tui_refresh_rate ({:?}) must be between {:?} and {:?} inclusive",
            tui_refresh_rate, TUI_MIN_REFRESH_RATE_MS, TUI_MAX_REFRESH_RATE_MS
        );
        exit(-1);
    }
}

/// Validate `grace_duration`
pub fn validate_grace_duration(grace_duration: Duration) {
    if grace_duration < MIN_GRACE_DURATION_MS || grace_duration > MAX_GRACE_DURATION_MS {
        eprintln!(
            "grace_duration ({:?}) must be between {:?} and {:?} inclusive",
            grace_duration, MIN_GRACE_DURATION_MS, MAX_GRACE_DURATION_MS
        );
        exit(-1);
    }
}

/// Validate `packet_size`
pub fn validate_packet_size(packet_size: u16) {
    if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&packet_size) {
        eprintln!(
            "packet_size ({}) must be between {} and {} inclusive",
            packet_size, MIN_PACKET_SIZE, MAX_PACKET_SIZE
        );
        exit(-1);
    }
}

/// Validate `source_port`
pub fn validate_source_port(source_port: u16) {
    if source_port < 1024 {
        eprintln!("source_port ({}) must be >= 1024", source_port);
        exit(-1);
    }
}

/// Validate `min_round_duration` and `max_round_duration`
pub fn validate_round_duration(min_round_duration: Duration, max_round_duration: Duration) {
    if min_round_duration > max_round_duration {
        eprintln!(
            "max_round_duration ({:?}) must not be less than min_round_duration ({:?})",
            max_round_duration, min_round_duration
        );
        exit(-1);
    }
}

/// Validate `read_timeout`
pub fn validate_read_timeout(read_timeout: Duration) {
    if read_timeout < MIN_READ_TIMEOUT_MS || read_timeout > MAX_READ_TIMEOUT_MS {
        eprintln!(
            "read_timeout ({:?}) must be between {:?} and {:?} inclusive",
            read_timeout, MIN_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS
        );
        exit(-1);
    }
}

/// Validate `max_inflight`
pub fn validate_max_inflight(max_inflight: u8) {
    if max_inflight == 0 {
        eprintln!("max_inflight ({}) must be greater than zero", max_inflight);
        exit(-1);
    }
}

/// Validate `first_ttl` and `max_ttl`
pub fn validate_ttl(first_ttl: u8, max_ttl: u8) {
    if (first_ttl as usize) < 1 || (first_ttl as usize) > MAX_HOPS {
        eprintln!("first_ttl ({first_ttl}) must be in the range 1..{MAX_HOPS}");
        exit(-1);
    }
    if (max_ttl as usize) < 1 || (max_ttl as usize) > MAX_HOPS {
        eprintln!("max_ttl ({max_ttl}) must be in the range 1..{MAX_HOPS}");
        exit(-1);
    }
    if first_ttl > max_ttl {
        eprintln!("first_ttl ({first_ttl}) must be less than or equal to max_ttl ({max_ttl})");
        exit(-1);
    }
}
