use crate::config::binding::TuiKeyBinding;
use crate::config::theme::TuiColor;
use crate::config::{
    AddressFamily, AddressMode, AsMode, DnsResolveMethod, GeoIpMode, LogFormat, LogSpanEvents,
    Mode, MultipathStrategyConfig, Protocol,
};
use anyhow::Context;
use etcetera::BaseStrategy;
use serde::Deserialize;
use std::fs::File;
use std::io::read_to_string;
use std::path::Path;

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
        } else {
            Ok(None)
        }
    }
}

/// Read the config from the given path.
pub fn read_config_file<P: AsRef<Path>>(path: P) -> anyhow::Result<ConfigFile> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("config file not found: {:?}", path.as_ref()))?;
    Ok(toml::from_str(&read_to_string(file)?)?)
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
    pub unprivileged: Option<bool>,
    pub log_format: Option<LogFormat>,
    pub log_filter: Option<String>,
    pub log_span_events: Option<LogSpanEvents>,
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
    pub icmp_extensions: Option<bool>,
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
    pub tui_geoip_mode: Option<GeoIpMode>,
    pub tui_max_addrs: Option<u8>,
    pub geoip_mmdb_file: Option<String>,
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
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigBindings {
    pub toggle_help: Option<TuiKeyBinding>,
    pub toggle_help_alt: Option<TuiKeyBinding>,
    pub toggle_settings: Option<TuiKeyBinding>,
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
}
