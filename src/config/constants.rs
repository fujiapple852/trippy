use crate::config::{
    AddressFamily, AddressMode, AsMode, DnsResolveMethodConfig, GeoIpMode, LogFormat,
    LogSpanEvents, Mode, MultipathStrategyConfig, Protocol,
};
use std::time::Duration;

/// The maximum number of hops we allow.
///
/// The IP `ttl` is a u8 (0..255) but since a `ttl` of zero isn't useful we only allow 255 distinct
/// hops.
pub const MAX_HOPS: usize = u8::MAX as usize;

/// The default value for `mode`.
pub const DEFAULT_MODE: Mode = Mode::Tui;

/// The default value for `unprivileged`.
pub const DEFAULT_UNPRIVILEGED: bool = false;

/// The default value for `all_resolved_ips`.
pub const DEFAULT_DNS_RESOLVE_ALL: bool = false;

/// The default value for `log-format`.
pub const DEFAULT_LOG_FORMAT: LogFormat = LogFormat::Pretty;

/// The default value for `log-span-events`.
pub const DEFAULT_LOG_SPAN_EVENTS: LogSpanEvents = LogSpanEvents::Off;

/// The default value for `log-filter`.
pub const DEFAULT_LOG_FILTER: &str = "trippy=debug";

/// The default value for `protocol`.
pub const DEFAULT_STRATEGY_PROTOCOL: Protocol = Protocol::Icmp;

/// The default value for `addr-family`.
pub const DEFAULT_ADDRESS_FAMILY: AddressFamily = AddressFamily::Ipv4;

/// The default value for `min-round-duration`.
pub const DEFAULT_STRATEGY_MIN_ROUND_DURATION: &str = "1s";

/// The default value for `max-round-duration`.
pub const DEFAULT_STRATEGY_MAX_ROUND_DURATION: &str = "1s";

/// The default value for `initial-sequence`.
pub const DEFAULT_STRATEGY_INITIAL_SEQUENCE: u16 = 33000;

/// The default value for `multipath-strategy`.
pub const DEFAULT_STRATEGY_MULTIPATH: MultipathStrategyConfig = MultipathStrategyConfig::Classic;

/// The default value for `grace-duration`.
pub const DEFAULT_STRATEGY_GRACE_DURATION: &str = "100ms";

/// The default value for `max-inflight`.
pub const DEFAULT_STRATEGY_MAX_INFLIGHT: u8 = 24;

/// The default value for `first-ttl`.
pub const DEFAULT_STRATEGY_FIRST_TTL: u8 = 1;

/// The default value for `max-ttl`.
pub const DEFAULT_STRATEGY_MAX_TTL: u8 = 64;

/// The default value for `packet-size`.
pub const DEFAULT_STRATEGY_PACKET_SIZE: u16 = 84;

/// The default value for `payload-pattern`.
pub const DEFAULT_STRATEGY_PAYLOAD_PATTERN: u8 = 0;

/// The default value for `tos`.
pub const DEFAULT_STRATEGY_TOS: u8 = 0;

/// The default value for `icmp-extensions`.
pub const DEFAULT_ICMP_EXTENSIONS: bool = false;

/// The default value for `read-timeout`.
pub const DEFAULT_STRATEGY_READ_TIMEOUT: &str = "10ms";

/// The default value for `tui-max-samples`.
pub const DEFAULT_TUI_MAX_SAMPLES: usize = 256;

/// The default value for `tui-preserve-screen`.
pub const DEFAULT_TUI_PRESERVE_SCREEN: bool = false;

/// The default value for `tui-as-mode`.
pub const DEFAULT_TUI_AS_MODE: AsMode = AsMode::Asn;

/// The default value for `tui-geoip-mode`.
pub const DEFAULT_TUI_GEOIP_MODE: GeoIpMode = GeoIpMode::Off;

/// The default value for `tui-address-mode`.
pub const DEFAULT_TUI_ADDRESS_MODE: AddressMode = AddressMode::Host;

/// The default value for `tui-refresh-rate`.
pub const DEFAULT_TUI_REFRESH_RATE: &str = "100ms";

/// The default value for `tui_privacy_max_ttl`.
pub const DEFAULT_TUI_PRIVACY_MAX_TTL: u8 = 0;

/// The default value for `dns-resolve-method`.
pub const DEFAULT_DNS_RESOLVE_METHOD: DnsResolveMethodConfig = DnsResolveMethodConfig::System;

/// The default value for `dns-lookup-as-info`.
pub const DEFAULT_DNS_LOOKUP_AS_INFO: bool = false;

/// The default value for `dns-timeout`.
pub const DEFAULT_DNS_TIMEOUT: &str = "5s";

/// The default value for `report-cycles`.
pub const DEFAULT_REPORT_CYCLES: usize = 10;

/// The minimum TUI refresh rate.
pub const TUI_MIN_REFRESH_RATE_MS: Duration = Duration::from_millis(50);

/// The maximum TUI refresh rate.
pub const TUI_MAX_REFRESH_RATE_MS: Duration = Duration::from_millis(1000);

/// The minimum socket read timeout.
pub const MIN_READ_TIMEOUT_MS: Duration = Duration::from_millis(10);

/// The maximum socket read timeout.
pub const MAX_READ_TIMEOUT_MS: Duration = Duration::from_millis(100);

/// The minimum grace duration.
pub const MIN_GRACE_DURATION_MS: Duration = Duration::from_millis(10);

/// The maximum grace duration.
pub const MAX_GRACE_DURATION_MS: Duration = Duration::from_millis(1000);

/// The minimum packet size we allow.
pub const MIN_PACKET_SIZE: u16 = 28;

/// The maximum packet size we allow.
pub const MAX_PACKET_SIZE: u16 = 1024;
