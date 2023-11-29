use crate::config::{AddressMode, AsMode, GeoIpMode, TuiTheme};
use crate::config::{IcmpExtensionMode, TuiBindings};
use crate::frontend::binding::Bindings;
use crate::frontend::theme::Theme;
use std::time::Duration;

/// Tui configuration.
#[derive(Debug)]
pub struct TuiConfig {
    /// Refresh rate.
    pub refresh_rate: Duration,
    /// The maximum ttl of hops which will be masked for privacy.
    pub privacy_max_ttl: u8,
    /// Preserve screen on exit.
    pub preserve_screen: bool,
    /// How to render addresses.
    pub address_mode: AddressMode,
    /// Lookup `AS` information.
    pub lookup_as_info: bool,
    /// How to render AS data.
    pub as_mode: AsMode,
    /// How to render ICMP extensions.
    pub icmp_extension_mode: IcmpExtensionMode,
    /// How to render GeoIp data.
    pub geoip_mode: GeoIpMode,
    /// The maximum number of addresses to show per hop.
    pub max_addrs: Option<u8>,
    /// The maximum number of samples to record per hop.
    pub max_samples: usize,
    /// The maximum number of flows to display.
    pub max_flows: usize,
    /// The Tui color theme.
    pub theme: Theme,
    /// The Tui keyboard bindings.
    pub bindings: Bindings,
}

impl TuiConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        refresh_rate: Duration,
        privacy_max_ttl: u8,
        preserve_screen: bool,
        address_mode: AddressMode,
        lookup_as_info: bool,
        as_mode: AsMode,
        icmp_extension_mode: IcmpExtensionMode,
        geoip_mode: GeoIpMode,
        max_addrs: Option<u8>,
        max_samples: usize,
        max_flows: usize,
        tui_theme: TuiTheme,
        tui_bindings: &TuiBindings,
    ) -> Self {
        Self {
            refresh_rate,
            privacy_max_ttl,
            preserve_screen,
            address_mode,
            lookup_as_info,
            as_mode,
            icmp_extension_mode,
            geoip_mode,
            max_addrs,
            max_samples,
            max_flows,
            theme: Theme::from(tui_theme),
            bindings: Bindings::from(*tui_bindings),
        }
    }
}
