use crate::config::{AddressMode, AsMode, GeoIpMode, TuiColumns, TuiTheme};
use crate::config::{IcmpExtensionMode, TuiBindings};
use crate::frontend::binding::Bindings;
use crate::frontend::columns::Columns;
use crate::frontend::theme::Theme;
use std::time::Duration;

/// Tui configuration.
#[derive(Debug)]
pub struct TuiConfig {
    /// Refresh rate.
    pub refresh_rate: Duration,
    /// Mask addresses for privacy.
    pub privacy: bool,
    /// The maximum ttl of hops which will be masked for privacy.
    pub privacy_max_ttl: u8,
    /// Preserve screen on exit.
    pub preserve_screen: bool,
    /// How to render addresses.
    pub address_mode: AddressMode,
    /// Lookup autonomous system (AS) information.
    pub lookup_as_info: bool,
    /// How to render autonomous system (AS) data.
    pub as_mode: AsMode,
    /// How to render ICMP extensions.
    pub icmp_extension_mode: IcmpExtensionMode,
    /// How to render `GeoIp` data.
    pub geoip_mode: GeoIpMode,
    /// The maximum number of addresses to show per hop.
    pub max_addrs: Option<u8>,
    /// The Tui color theme.
    pub theme: Theme,
    /// The Tui keyboard bindings.
    pub bindings: Bindings,
    /// The columns to display in the hops table.
    pub tui_columns: Columns,
    pub geoip_mmdb_file: Option<String>,
    pub dns_resolve_all: bool,
}

impl TuiConfig {
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub fn new(
        refresh_rate: Duration,
        privacy: bool,
        privacy_max_ttl: u8,
        preserve_screen: bool,
        address_mode: AddressMode,
        lookup_as_info: bool,
        as_mode: AsMode,
        icmp_extension_mode: IcmpExtensionMode,
        geoip_mode: GeoIpMode,
        max_addrs: Option<u8>,
        tui_theme: TuiTheme,
        tui_bindings: &TuiBindings,
        tui_columns: &TuiColumns,
        geoip_mmdb_file: Option<String>,
        dns_resolve_all: bool,
    ) -> Self {
        Self {
            refresh_rate,
            privacy,
            privacy_max_ttl,
            preserve_screen,
            address_mode,
            lookup_as_info,
            as_mode,
            icmp_extension_mode,
            geoip_mode,
            max_addrs,
            theme: Theme::from(tui_theme),
            bindings: Bindings::from(*tui_bindings),
            tui_columns: Columns::from(tui_columns.clone()),
            geoip_mmdb_file,
            dns_resolve_all,
        }
    }
}
