use crate::backend::{Hop, Trace};
use crate::frontend::config::TuiConfig;
use crate::frontend::render::settings::SETTINGS_TABS;
use crate::geoip::GeoIpLookup;
use crate::TraceInfo;
use ratatui::widgets::TableState;
use std::time::SystemTime;
use trippy::dns::{DnsResolver, ResolveMethod};

pub struct TuiApp {
    pub selected_tracer_data: Trace,
    pub trace_info: Vec<TraceInfo>,
    pub tui_config: TuiConfig,
    /// The state of the hop table.
    pub table_state: TableState,
    /// The state of the settings table.
    pub setting_table_state: TableState,
    /// The selected trace.
    pub trace_selected: usize,
    /// The selected tab in the settings dialog.
    pub settings_tab_selected: usize,
    /// The index of the current address to show for the selected hop.
    ///
    /// Only used in detail mode.
    pub selected_hop_address: usize,
    pub resolver: DnsResolver,
    pub geoip_lookup: GeoIpLookup,
    pub show_help: bool,
    pub show_settings: bool,
    pub show_hop_details: bool,
    pub show_chart: bool,
    pub show_map: bool,
    pub frozen_start: Option<SystemTime>,
    pub zoom_factor: usize,
}

impl TuiApp {
    pub fn new(
        tui_config: TuiConfig,
        resolver: DnsResolver,
        geoip_lookup: GeoIpLookup,
        trace_info: Vec<TraceInfo>,
    ) -> Self {
        Self {
            selected_tracer_data: Trace::new(tui_config.max_samples),
            trace_info,
            tui_config,
            table_state: TableState::default(),
            setting_table_state: TableState::default(),
            trace_selected: 0,
            settings_tab_selected: 0,
            selected_hop_address: 0,
            resolver,
            geoip_lookup,
            show_help: false,
            show_settings: false,
            show_hop_details: false,
            show_chart: false,
            show_map: false,
            frozen_start: None,
            zoom_factor: 1,
        }
    }

    pub fn tracer_data(&self) -> &Trace {
        &self.selected_tracer_data
    }

    pub fn snapshot_trace_data(&mut self) {
        self.selected_tracer_data = self.trace_info[self.trace_selected].data.read().clone();
    }

    pub fn clear_trace_data(&mut self) {
        *self.trace_info[self.trace_selected].data.write() =
            Trace::new(self.tui_config.max_samples);
    }

    pub fn selected_hop_or_target(&self) -> &Hop {
        self.table_state.selected().map_or_else(
            || self.tracer_data().target_hop(),
            |s| &self.tracer_data().hops()[s],
        )
    }

    pub fn selected_hop(&self) -> Option<&Hop> {
        self.table_state
            .selected()
            .map(|s| &self.tracer_data().hops()[s])
    }

    pub fn tracer_config(&self) -> &TraceInfo {
        &self.trace_info[self.trace_selected]
    }

    pub fn clamp_selected_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if let Some(selected) = self.table_state.selected() {
            if selected > hop_count - 1 {
                self.table_state.select(Some(hop_count - 1));
            }
        }
    }

    pub fn next_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if hop_count == 0 {
            return;
        }
        let max_index = 0.max(hop_count.saturating_sub(1));
        let i = match self.table_state.selected() {
            Some(i) => {
                if i < max_index {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_hop_address = 0;
    }

    pub fn previous_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if hop_count == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
            None => 0.max(hop_count.saturating_sub(1)),
        };
        self.table_state.select(Some(i));
        self.selected_hop_address = 0;
    }

    pub fn next_trace(&mut self) {
        if self.trace_selected < self.trace_info.len() - 1 {
            self.trace_selected += 1;
        }
    }

    pub fn previous_trace(&mut self) {
        if self.trace_selected > 0 {
            self.trace_selected -= 1;
        };
    }

    pub fn next_hop_address(&mut self) {
        if let Some(hop) = self.selected_hop() {
            if self.selected_hop_address < hop.addr_count() - 1 {
                self.selected_hop_address += 1;
            }
        }
    }

    pub fn previous_hop_address(&mut self) {
        if self.selected_hop().is_some() && self.selected_hop_address > 0 {
            self.selected_hop_address -= 1;
        }
    }

    pub fn next_settings_tab(&mut self) {
        if self.settings_tab_selected < SETTINGS_TABS.len() - 1 {
            self.settings_tab_selected += 1;
        }
        self.setting_table_state.select(Some(0));
    }

    pub fn previous_settings_tab(&mut self) {
        if self.settings_tab_selected > 0 {
            self.settings_tab_selected -= 1;
        };
        self.setting_table_state.select(Some(0));
    }

    pub fn next_settings_item(&mut self) {
        let count = SETTINGS_TABS[self.settings_tab_selected].1;
        let max_index = 0.max(count.saturating_sub(1));
        let i = match self.setting_table_state.selected() {
            Some(i) => {
                if i < max_index {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };
        self.setting_table_state.select(Some(i));
    }

    pub fn previous_settings_item(&mut self) {
        let count = SETTINGS_TABS[self.settings_tab_selected].1;
        let i = match self.setting_table_state.selected() {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
            None => 0.max(count.saturating_sub(1)),
        };
        self.setting_table_state.select(Some(i));
    }

    pub fn clear(&mut self) {
        self.table_state.select(None);
        self.selected_hop_address = 0;
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn toggle_settings(&mut self) {
        self.show_settings = !self.show_settings;
    }

    pub fn toggle_hop_details(&mut self) {
        if self.show_hop_details {
            self.tui_config.max_addrs = None;
        } else {
            self.tui_config.max_addrs = Some(1);
        }
        self.show_hop_details = !self.show_hop_details;
    }

    pub fn toggle_freeze(&mut self) {
        self.frozen_start = match self.frozen_start {
            None => Some(SystemTime::now()),
            Some(_) => None,
        };
    }

    pub fn toggle_chart(&mut self) {
        self.show_chart = !self.show_chart;
        self.show_map = false;
    }

    pub fn toggle_map(&mut self) {
        self.show_map = !self.show_map;
        self.show_chart = false;
    }

    pub fn toggle_asinfo(&mut self) {
        match self.resolver.config().resolve_method {
            ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
                self.tui_config.lookup_as_info = !self.tui_config.lookup_as_info;
                self.resolver.flush();
            }
            ResolveMethod::System => {}
        }
    }

    pub fn expand_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            None => Some(1),
            Some(i) if i < self.max_hosts() => Some(i + 1),
            Some(i) => Some(i),
        }
    }

    pub fn contract_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            Some(i) if i > 1 => Some(i - 1),
            _ => None,
        }
    }

    pub fn zoom_in(&mut self) {
        if self.zoom_factor < MAX_ZOOM_FACTOR {
            self.zoom_factor += 1;
        }
    }

    pub fn zoom_out(&mut self) {
        if self.zoom_factor > 1 {
            self.zoom_factor -= 1;
        }
    }

    pub fn expand_hosts_max(&mut self) {
        self.tui_config.max_addrs = Some(self.max_hosts());
    }

    pub fn contract_hosts_min(&mut self) {
        self.tui_config.max_addrs = Some(1);
    }

    /// The maximum number of hosts per hop for the currently selected trace.
    pub fn max_hosts(&self) -> u8 {
        self.selected_tracer_data
            .hops()
            .iter()
            .map(|h| h.addrs().count())
            .max()
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or_default()
    }
}

const MAX_ZOOM_FACTOR: usize = 16;
