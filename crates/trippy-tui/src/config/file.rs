use crate::config::binding::TuiKeyBinding;
use crate::config::theme::TuiColor;
use crate::config::{
    AddressFamilyConfig, AddressMode, AsMode, DnsResolveMethodConfig, GeoIpMode, IcmpExtensionMode,
    LogFormat, LogSpanEvents, Mode, MultipathStrategyConfig, ProtocolConfig,
};
use anyhow::Context;
use encoding_rs_io::DecodeReaderBytes;
use etcetera::BaseStrategy;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use trippy_core::defaults;

const DEFAULT_CONFIG_FILE: &str = "trippy.toml";
const DEFAULT_HIDDEN_CONFIG_FILE: &str = ".trippy.toml";

/// Read the config from the default location of user config for the platform.
///
/// Returns the parsed `Some(ConfigFile)` if the config file exists, `None` otherwise.
///
/// Trippy will attempt to locate a `trippy.toml` or `.trippy.toml`
/// config file in one of the following locations:
///     - the current directory
///     - the user home directory
///     - the XDG config directory (Unix only): `$XDG_CONFIG_HOME` or `~/.config`
///     - the XDG app config directory (Unix only): `$XDG_CONFIG_HOME/trippy` or `~/.config/trippy`
///     - the Windows data directory (Windows only): `%APPDATA%`
///
/// Note that only the first config file found is used, no attempt is
/// made to merge the values from multiple files.
pub fn read_default_config_file() -> anyhow::Result<Option<ConfigFile>> {
    use etcetera::base_strategy as base;
    if let Some(file) = read_files("")? {
        Ok(Some(file))
    } else {
        let basedirs = base::choose_base_strategy()?;
        if let Some(file) = read_files(basedirs.home_dir())? {
            Ok(Some(file))
        } else if let Some(file) = read_files(basedirs.config_dir())? {
            Ok(Some(file))
        } else if let Some(file) = read_files(basedirs.config_dir().join("trippy"))? {
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }
}

/// Read the config from the given path.
pub fn read_config_file<P: AsRef<Path>>(path: P) -> anyhow::Result<ConfigFile> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("config file not found: {}", path.as_ref().display()))?;
    let mut decoder = DecodeReaderBytes::new(BufReader::new(file));
    let mut dest = String::new();
    decoder.read_to_string(&mut dest)?;
    Ok(toml::from_str(&dest)?)
}

fn read_files<P: AsRef<Path>>(dir: P) -> anyhow::Result<Option<ConfigFile>> {
    if let Some(file) = read_file(dir.as_ref(), DEFAULT_CONFIG_FILE)? {
        Ok(Some(file))
    } else if let Some(file) = read_file(dir.as_ref(), DEFAULT_HIDDEN_CONFIG_FILE)? {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

fn read_file<P: AsRef<Path>>(dir: P, file: &str) -> anyhow::Result<Option<ConfigFile>> {
    let path = dir.as_ref().join(file);
    if path.exists() {
        Ok(Some(read_config_file(path)?))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
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

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            trippy: Some(ConfigTrippy::default()),
            strategy: Some(ConfigStrategy::default()),
            theme_colors: Some(ConfigThemeColors::default()),
            bindings: Some(ConfigBindings::default()),
            tui: Some(ConfigTui::default()),
            dns: Some(ConfigDns::default()),
            report: Some(ConfigReport::default()),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigTrippy {
    pub mode: Option<Mode>,
    pub unprivileged: Option<bool>,
    pub log_format: Option<LogFormat>,
    pub log_filter: Option<String>,
    pub log_span_events: Option<LogSpanEvents>,
}

impl Default for ConfigTrippy {
    fn default() -> Self {
        Self {
            mode: Some(super::constants::DEFAULT_MODE),
            unprivileged: Some(defaults::DEFAULT_PRIVILEGE_MODE.is_unprivileged()),
            log_format: Some(super::constants::DEFAULT_LOG_FORMAT),
            log_filter: Some(String::from(super::constants::DEFAULT_LOG_FILTER)),
            log_span_events: Some(super::constants::DEFAULT_LOG_SPAN_EVENTS),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigStrategy {
    pub protocol: Option<ProtocolConfig>,
    pub addr_family: Option<AddressFamilyConfig>,
    pub target_port: Option<u16>,
    pub source_port: Option<u16>,
    #[serde(default)]
    #[serde(deserialize_with = "addr_deser")]
    pub source_address: Option<IpAddr>,
    pub interface: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub min_round_duration: Option<Duration>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub max_round_duration: Option<Duration>,
    pub initial_sequence: Option<u16>,
    pub multipath_strategy: Option<MultipathStrategyConfig>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub grace_duration: Option<Duration>,
    pub max_inflight: Option<u8>,
    pub first_ttl: Option<u8>,
    pub max_ttl: Option<u8>,
    pub packet_size: Option<u16>,
    pub payload_pattern: Option<u8>,
    pub tos: Option<u8>,
    pub icmp_extensions: Option<bool>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub read_timeout: Option<Duration>,
    pub max_samples: Option<usize>,
    pub max_flows: Option<usize>,
}

impl Default for ConfigStrategy {
    fn default() -> Self {
        Self {
            protocol: Some(ProtocolConfig::from(defaults::DEFAULT_STRATEGY_PROTOCOL)),
            addr_family: Some(super::constants::DEFAULT_ADDR_FAMILY),
            target_port: None,
            source_port: None,
            source_address: None,
            interface: None,
            min_round_duration: Some(defaults::DEFAULT_STRATEGY_MIN_ROUND_DURATION),
            max_round_duration: Some(defaults::DEFAULT_STRATEGY_MAX_ROUND_DURATION),
            initial_sequence: Some(defaults::DEFAULT_STRATEGY_INITIAL_SEQUENCE),
            multipath_strategy: Some(MultipathStrategyConfig::from(
                defaults::DEFAULT_STRATEGY_MULTIPATH,
            )),
            grace_duration: Some(defaults::DEFAULT_STRATEGY_GRACE_DURATION),
            max_inflight: Some(defaults::DEFAULT_STRATEGY_MAX_INFLIGHT),
            first_ttl: Some(defaults::DEFAULT_STRATEGY_FIRST_TTL),
            max_ttl: Some(defaults::DEFAULT_STRATEGY_MAX_TTL),
            packet_size: Some(defaults::DEFAULT_STRATEGY_PACKET_SIZE),
            payload_pattern: Some(defaults::DEFAULT_STRATEGY_PAYLOAD_PATTERN),
            tos: Some(defaults::DEFAULT_STRATEGY_TOS),
            icmp_extensions: Some(defaults::DEFAULT_ICMP_EXTENSION_PARSE_MODE.is_enabled()),
            read_timeout: Some(defaults::DEFAULT_STRATEGY_READ_TIMEOUT),
            max_samples: Some(defaults::DEFAULT_MAX_SAMPLES),
            max_flows: Some(defaults::DEFAULT_MAX_FLOWS),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[expect(clippy::struct_field_names)]
pub struct ConfigDns {
    pub dns_resolve_method: Option<DnsResolveMethodConfig>,
    pub dns_resolve_all: Option<bool>,
    pub dns_lookup_as_info: Option<bool>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub dns_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub dns_ttl: Option<Duration>,
}

impl Default for ConfigDns {
    fn default() -> Self {
        Self {
            dns_resolve_method: Some(super::constants::DEFAULT_DNS_RESOLVE_METHOD),
            dns_resolve_all: Some(super::constants::DEFAULT_DNS_RESOLVE_ALL),
            dns_lookup_as_info: Some(super::constants::DEFAULT_DNS_LOOKUP_AS_INFO),
            dns_timeout: Some(super::constants::DEFAULT_DNS_TIMEOUT),
            dns_ttl: Some(super::constants::DEFAULT_DNS_TTL),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigReport {
    pub report_cycles: Option<usize>,
}

impl Default for ConfigReport {
    fn default() -> Self {
        Self {
            report_cycles: Some(super::constants::DEFAULT_REPORT_CYCLES),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigTui {
    pub tui_preserve_screen: Option<bool>,
    #[serde(default)]
    #[serde(deserialize_with = "humantime_deser")]
    pub tui_refresh_rate: Option<Duration>,
    pub tui_privacy_max_ttl: Option<u8>,
    pub tui_address_mode: Option<AddressMode>,
    pub tui_as_mode: Option<AsMode>,
    pub tui_icmp_extension_mode: Option<IcmpExtensionMode>,
    pub tui_geoip_mode: Option<GeoIpMode>,
    pub tui_max_addrs: Option<u8>,
    pub geoip_mmdb_file: Option<String>,
    pub tui_custom_columns: Option<String>,
    pub tui_locale: Option<String>,
    pub tui_timezone: Option<String>,
    #[serde(rename = "tui-max-samples")]
    pub deprecated_tui_max_samples: Option<usize>,
    #[serde(rename = "tui-max-flows")]
    pub deprecated_tui_max_flows: Option<usize>,
}

impl Default for ConfigTui {
    fn default() -> Self {
        Self {
            tui_preserve_screen: Some(super::constants::DEFAULT_TUI_PRESERVE_SCREEN),
            tui_refresh_rate: Some(super::constants::DEFAULT_TUI_REFRESH_RATE),
            tui_privacy_max_ttl: None,
            tui_address_mode: Some(super::constants::DEFAULT_TUI_ADDRESS_MODE),
            tui_as_mode: Some(super::constants::DEFAULT_TUI_AS_MODE),
            tui_custom_columns: Some(String::from(super::constants::DEFAULT_CUSTOM_COLUMNS)),
            tui_icmp_extension_mode: Some(super::constants::DEFAULT_TUI_ICMP_EXTENSION_MODE),
            tui_geoip_mode: Some(super::constants::DEFAULT_TUI_GEOIP_MODE),
            tui_max_addrs: Some(super::constants::DEFAULT_TUI_MAX_ADDRS),
            tui_locale: None,
            tui_timezone: None,
            geoip_mmdb_file: None,
            deprecated_tui_max_samples: None,
            deprecated_tui_max_flows: None,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[expect(clippy::struct_field_names)]
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
    pub flows_chart_bar_selected_color: Option<TuiColor>,
    pub flows_chart_bar_unselected_color: Option<TuiColor>,
    pub flows_chart_text_current_color: Option<TuiColor>,
    pub flows_chart_text_non_current_color: Option<TuiColor>,
    pub samples_chart_color: Option<TuiColor>,
    pub samples_chart_lost_color: Option<TuiColor>,
    pub help_dialog_bg_color: Option<TuiColor>,
    pub help_dialog_text_color: Option<TuiColor>,
    pub settings_dialog_bg_color: Option<TuiColor>,
    pub settings_tab_text_color: Option<TuiColor>,
    pub settings_table_header_text_color: Option<TuiColor>,
    pub settings_table_header_bg_color: Option<TuiColor>,
    pub settings_table_row_text_color: Option<TuiColor>,
    pub map_world_color: Option<TuiColor>,
    pub map_radius_color: Option<TuiColor>,
    pub map_selected_color: Option<TuiColor>,
    pub map_info_panel_border_color: Option<TuiColor>,
    pub map_info_panel_bg_color: Option<TuiColor>,
    pub map_info_panel_text_color: Option<TuiColor>,
    pub info_bar_bg_color: Option<TuiColor>,
    pub info_bar_text_color: Option<TuiColor>,
}

impl Default for ConfigThemeColors {
    fn default() -> Self {
        let theme = super::theme::TuiTheme::default();
        Self {
            bg_color: Some(theme.bg),
            border_color: Some(theme.border),
            text_color: Some(theme.text),
            tab_text_color: Some(theme.tab_text),
            hops_table_header_bg_color: Some(theme.hops_table_header_bg),
            hops_table_header_text_color: Some(theme.hops_table_header_text),
            hops_table_row_active_text_color: Some(theme.hops_table_row_active_text),
            hops_table_row_inactive_text_color: Some(theme.hops_table_row_inactive_text),
            hops_chart_selected_color: Some(theme.hops_chart_selected),
            hops_chart_unselected_color: Some(theme.hops_chart_unselected),
            hops_chart_axis_color: Some(theme.hops_chart_axis),
            frequency_chart_bar_color: Some(theme.frequency_chart_bar),
            frequency_chart_text_color: Some(theme.frequency_chart_text),
            flows_chart_bar_selected_color: Some(theme.flows_chart_bar_selected),
            flows_chart_bar_unselected_color: Some(theme.flows_chart_bar_unselected),
            flows_chart_text_current_color: Some(theme.flows_chart_text_current),
            flows_chart_text_non_current_color: Some(theme.flows_chart_text_non_current),
            samples_chart_color: Some(theme.samples_chart),
            samples_chart_lost_color: Some(theme.samples_chart_lost),
            help_dialog_bg_color: Some(theme.help_dialog_bg),
            help_dialog_text_color: Some(theme.help_dialog_text),
            settings_dialog_bg_color: Some(theme.settings_dialog_bg),
            settings_tab_text_color: Some(theme.settings_tab_text),
            settings_table_header_text_color: Some(theme.settings_table_header_text),
            settings_table_header_bg_color: Some(theme.settings_table_header_bg),
            settings_table_row_text_color: Some(theme.settings_table_row_text),
            map_world_color: Some(theme.map_world),
            map_radius_color: Some(theme.map_radius),
            map_selected_color: Some(theme.map_selected),
            map_info_panel_border_color: Some(theme.map_info_panel_border),
            map_info_panel_bg_color: Some(theme.map_info_panel_bg),
            map_info_panel_text_color: Some(theme.map_info_panel_text),
            info_bar_bg_color: Some(theme.info_bar_bg),
            info_bar_text_color: Some(theme.info_bar_text),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigBindings {
    pub toggle_help: Option<TuiKeyBinding>,
    pub toggle_help_alt: Option<TuiKeyBinding>,
    pub toggle_settings: Option<TuiKeyBinding>,
    pub toggle_settings_tui: Option<TuiKeyBinding>,
    pub toggle_settings_trace: Option<TuiKeyBinding>,
    pub toggle_settings_dns: Option<TuiKeyBinding>,
    pub toggle_settings_geoip: Option<TuiKeyBinding>,
    pub toggle_settings_bindings: Option<TuiKeyBinding>,
    pub toggle_settings_theme: Option<TuiKeyBinding>,
    pub toggle_settings_columns: Option<TuiKeyBinding>,
    pub previous_hop: Option<TuiKeyBinding>,
    pub next_hop: Option<TuiKeyBinding>,
    pub previous_trace: Option<TuiKeyBinding>,
    pub next_trace: Option<TuiKeyBinding>,
    pub previous_hop_address: Option<TuiKeyBinding>,
    pub next_hop_address: Option<TuiKeyBinding>,
    pub address_mode_ip: Option<TuiKeyBinding>,
    pub address_mode_host: Option<TuiKeyBinding>,
    pub address_mode_both: Option<TuiKeyBinding>,
    pub toggle_freeze: Option<TuiKeyBinding>,
    pub toggle_chart: Option<TuiKeyBinding>,
    pub toggle_flows: Option<TuiKeyBinding>,
    #[serde(rename = "toggle-privacy")]
    pub deprecated_toggle_privacy: Option<TuiKeyBinding>,
    pub expand_privacy: Option<TuiKeyBinding>,
    pub contract_privacy: Option<TuiKeyBinding>,
    pub toggle_map: Option<TuiKeyBinding>,
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
    pub toggle_hop_details: Option<TuiKeyBinding>,
    pub quit: Option<TuiKeyBinding>,
    pub quit_preserve_screen: Option<TuiKeyBinding>,
}

impl Default for ConfigBindings {
    fn default() -> Self {
        let bindings = super::binding::TuiBindings::default();
        Self {
            toggle_help: Some(bindings.toggle_help),
            toggle_help_alt: Some(bindings.toggle_help_alt),
            toggle_settings: Some(bindings.toggle_settings),
            toggle_settings_tui: Some(bindings.toggle_settings_tui),
            toggle_settings_trace: Some(bindings.toggle_settings_trace),
            toggle_settings_dns: Some(bindings.toggle_settings_dns),
            toggle_settings_geoip: Some(bindings.toggle_settings_geoip),
            toggle_settings_bindings: Some(bindings.toggle_settings_bindings),
            toggle_settings_theme: Some(bindings.toggle_settings_theme),
            toggle_settings_columns: Some(bindings.toggle_settings_columns),
            previous_hop: Some(bindings.previous_hop),
            next_hop: Some(bindings.next_hop),
            previous_trace: Some(bindings.previous_trace),
            next_trace: Some(bindings.next_trace),
            previous_hop_address: Some(bindings.previous_hop_address),
            next_hop_address: Some(bindings.next_hop_address),
            address_mode_ip: Some(bindings.address_mode_ip),
            address_mode_host: Some(bindings.address_mode_host),
            address_mode_both: Some(bindings.address_mode_both),
            toggle_freeze: Some(bindings.toggle_freeze),
            toggle_chart: Some(bindings.toggle_chart),
            toggle_flows: Some(bindings.toggle_flows),
            deprecated_toggle_privacy: None,
            expand_privacy: Some(bindings.expand_privacy),
            contract_privacy: Some(bindings.contract_privacy),
            toggle_map: Some(bindings.toggle_map),
            expand_hosts: Some(bindings.expand_hosts),
            contract_hosts: Some(bindings.contract_hosts),
            expand_hosts_max: Some(bindings.expand_hosts_max),
            contract_hosts_min: Some(bindings.contract_hosts_min),
            chart_zoom_in: Some(bindings.chart_zoom_in),
            chart_zoom_out: Some(bindings.chart_zoom_out),
            clear_trace_data: Some(bindings.clear_trace_data),
            clear_dns_cache: Some(bindings.clear_dns_cache),
            clear_selection: Some(bindings.clear_selection),
            toggle_as_info: Some(bindings.toggle_as_info),
            toggle_hop_details: Some(bindings.toggle_hop_details),
            quit: Some(bindings.quit),
            quit_preserve_screen: Some(bindings.quit_preserve_screen),
        }
    }
}

fn humantime_deser<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    humantime::parse_duration(&String::deserialize(deserializer)?)
        .map_err(serde::de::Error::custom)
        .map(Some)
}

fn addr_deser<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    IpAddr::from_str(&String::deserialize(deserializer)?)
        .map_err(serde::de::Error::custom)
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_sample() {
        let config: ConfigFile =
            toml::from_str(include_str!("../../trippy-config-sample.toml")).unwrap();
        pretty_assertions::assert_eq!(ConfigFile::default(), config);
    }
}
