use crate::backend::Hop;
use crate::config::{
    AddressMode, AsMode, DnsResolveMethod, GeoIpMode, TuiBindings, TuiColor, TuiKeyBinding,
    TuiTheme,
};
use crate::dns::{AsInfo, DnsEntry, Resolved, Unresolved};
use crate::geoip::{GeoIpCity, GeoIpLookup};
use crate::{DnsResolver, Trace, TraceInfo};
use chrono::SecondsFormat;
use crossterm::event::{KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use humantime::format_duration;
use itertools::Itertools;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter};
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use trippy::tracing::{PortDirection, TracerProtocol};
use tui::layout::{Alignment, Direction, Margin, Rect};
use tui::symbols::Marker;
use tui::text::{Span, Spans};
use tui::widgets::canvas::{Canvas, Context, Map, MapResolution, Painter, Rectangle, Shape};
use tui::widgets::{
    Axis, BarChart, BorderType, Chart, Clear, Dataset, GraphType, Paragraph, Sparkline, TableState,
    Tabs,
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame, Terminal,
};

const TABLE_HEADER: [&str; 11] = [
    "#", "Host", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StDev", "Sts",
];

/// The name and number of items for each tabs in the setting dialog.
const SETTINGS_TABS: [(&str, usize); 6] = [
    ("Tui", 8),
    ("Trace", 14),
    ("Dns", 3),
    ("GeoIp", 1),
    ("Bindings", 25),
    ("Theme", 21),
];

/// The settings table header.
const SETTINGS_TABLE_HEADER: [&str; 2] = ["Setting", "Value"];

const TABLE_WIDTH: [Constraint; 11] = [
    Constraint::Percentage(3),
    Constraint::Percentage(42),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
];

const SETTINGS_TABLE_WIDTH: [Constraint; 3] = [
    Constraint::Length(3),
    Constraint::Min(1),
    Constraint::Length(4),
];

const LAYOUT_WITHOUT_TABS: [Constraint; 3] = [
    Constraint::Length(5),
    Constraint::Min(10),
    Constraint::Length(6),
];

const LAYOUT_WITH_TABS: [Constraint; 4] = [
    Constraint::Length(5),
    Constraint::Length(3),
    Constraint::Min(10),
    Constraint::Length(6),
];

const MAP_LAYOUT: [Constraint; 3] = [
    Constraint::Min(1),
    Constraint::Length(3),
    Constraint::Length(1),
];

const MAX_ZOOM_FACTOR: usize = 16;

const HELP_LINES: [&str; 20] = [
    "[up] & [down]    - select hop",
    "[left] & [right] - select trace",
    ", & .            - select hop address",
    "[esc]            - clear selection",
    "d                - toggle hop details",
    "c                - toggle chart",
    "m                - toggle map",
    "f                - toggle freeze display",
    "Ctrl+r           - reset statistics",
    "Ctrl+k           - flush DNS cache",
    "i                - show IP only",
    "n                - show hostname only",
    "b                - show both IP and hostname",
    "[ & ]            - expand & collapse hosts",
    "{ & }            - expand & collapse hosts to max and min",
    "+ & -            - zoom chart in and out",
    "z                - toggle AS information (if available)",
    "h                - toggle help",
    "s                - toggle settings",
    "q                - quit",
];

/// Tui key bindings.
#[derive(Debug, Clone, Copy)]
pub struct Bindings {
    toggle_help: KeyBinding,
    toggle_settings: KeyBinding,
    previous_hop: KeyBinding,
    next_hop: KeyBinding,
    previous_trace: KeyBinding,
    next_trace: KeyBinding,
    previous_hop_address: KeyBinding,
    next_hop_address: KeyBinding,
    address_mode_ip: KeyBinding,
    address_mode_host: KeyBinding,
    address_mode_both: KeyBinding,
    toggle_freeze: KeyBinding,
    toggle_chart: KeyBinding,
    toggle_map: KeyBinding,
    expand_hosts: KeyBinding,
    contract_hosts: KeyBinding,
    expand_hosts_max: KeyBinding,
    contract_hosts_min: KeyBinding,
    chart_zoom_in: KeyBinding,
    chart_zoom_out: KeyBinding,
    clear_trace_data: KeyBinding,
    clear_dns_cache: KeyBinding,
    clear_selection: KeyBinding,
    toggle_as_info: KeyBinding,
    toggle_hop_details: KeyBinding,
    quit: KeyBinding,
}

impl From<TuiBindings> for Bindings {
    fn from(value: TuiBindings) -> Self {
        Self {
            toggle_help: KeyBinding::from(value.toggle_help),
            toggle_settings: KeyBinding::from(value.toggle_settings),
            previous_hop: KeyBinding::from(value.previous_hop),
            next_hop: KeyBinding::from(value.next_hop),
            previous_trace: KeyBinding::from(value.previous_trace),
            next_trace: KeyBinding::from(value.next_trace),
            previous_hop_address: KeyBinding::from(value.previous_hop_address),
            next_hop_address: KeyBinding::from(value.next_hop_address),
            address_mode_ip: KeyBinding::from(value.address_mode_ip),
            address_mode_host: KeyBinding::from(value.address_mode_host),
            address_mode_both: KeyBinding::from(value.address_mode_both),
            toggle_freeze: KeyBinding::from(value.toggle_freeze),
            toggle_chart: KeyBinding::from(value.toggle_chart),
            toggle_map: KeyBinding::from(value.toggle_map),
            expand_hosts: KeyBinding::from(value.expand_hosts),
            contract_hosts: KeyBinding::from(value.contract_hosts),
            expand_hosts_max: KeyBinding::from(value.expand_hosts_max),
            contract_hosts_min: KeyBinding::from(value.contract_hosts_min),
            chart_zoom_in: KeyBinding::from(value.chart_zoom_in),
            chart_zoom_out: KeyBinding::from(value.chart_zoom_out),
            clear_trace_data: KeyBinding::from(value.clear_trace_data),
            clear_dns_cache: KeyBinding::from(value.clear_dns_cache),
            clear_selection: KeyBinding::from(value.clear_selection),
            toggle_as_info: KeyBinding::from(value.toggle_as_info),
            toggle_hop_details: KeyBinding::from(value.toggle_hop_details),
            quit: KeyBinding::from(value.quit),
        }
    }
}

const CTRL_C: KeyBinding = KeyBinding {
    code: KeyCode::Char('c'),
    modifiers: KeyModifiers::CONTROL,
};

/// Tui key binding.
#[derive(Debug, Clone, Copy)]
pub struct KeyBinding {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyBinding {
    pub fn check(&self, event: KeyEvent) -> bool {
        let code_match = match (event.code, self.code) {
            (KeyCode::Char(c1), KeyCode::Char(c2)) => {
                c1.to_ascii_lowercase() == c2.to_ascii_lowercase()
            }
            (c1, c2) => c1 == c2,
        };
        code_match && self.modifiers == event.modifiers
    }
}

impl From<TuiKeyBinding> for KeyBinding {
    fn from(value: TuiKeyBinding) -> Self {
        Self {
            code: value.code,
            modifiers: value.modifier,
        }
    }
}

impl Display for KeyBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let modifiers = &[
            self.modifiers
                .contains(KeyModifiers::SHIFT)
                .then_some("shift"),
            self.modifiers
                .contains(KeyModifiers::CONTROL)
                .then_some("ctrl"),
            self.modifiers.contains(KeyModifiers::ALT).then_some("alt"),
            self.modifiers
                .contains(KeyModifiers::SUPER)
                .then_some("super"),
            self.modifiers
                .contains(KeyModifiers::HYPER)
                .then_some("hyper"),
            self.modifiers
                .contains(KeyModifiers::META)
                .then_some("meta"),
        ]
        .into_iter()
        .flatten()
        .join("+");
        if !modifiers.is_empty() {
            write!(f, "{modifiers}+")?;
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
            KeyCode::Esc => write!(f, "esc"),
            _ => write!(f, "unknown"),
        }
    }
}

/// Tui color theme.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    bg_color: Color,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    border_color: Color,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    text_color: Color,
    /// The color of the text in traces tabs.
    tab_text_color: Color,
    /// The background color of the hops table header.
    hops_table_header_bg_color: Color,
    /// The color of text in the hops table header.
    hops_table_header_text_color: Color,
    /// The color of text of active rows in the hops table.
    hops_table_row_active_text_color: Color,
    /// The color of text of inactive rows in the hops table.
    hops_table_row_inactive_text_color: Color,
    /// The color of the selected series in the hops chart.
    hops_chart_selected_color: Color,
    /// The color of the unselected series in the hops chart.
    hops_chart_unselected_color: Color,
    /// The color of the axis in the hops chart.
    hops_chart_axis_color: Color,
    /// The color of bars in the frequency chart.
    frequency_chart_bar_color: Color,
    /// The color of text in the bars of the frequency chart.
    frequency_chart_text_color: Color,
    /// The color of the samples chart.
    samples_chart_color: Color,
    /// The background color of the help dialog.
    help_dialog_bg_color: Color,
    /// The color of the text in the help dialog.
    help_dialog_text_color: Color,
    /// The background color of the settings dialog.
    settings_dialog_bg_color: Color,
    /// The color of the text in settings dialog tabs.
    settings_tab_text_color: Color,
    /// The color of text in the settings table header.
    settings_table_header_text_color: Color,
    /// The background color of the settings table header.
    settings_table_header_bg_color: Color,
    /// The color of text of rows in the settings table.
    settings_table_row_text_color: Color,
    /// The color of the map world diagram.
    map_world_color: Color,
    /// The color of the map accuracy radius circle.
    map_radius_color: Color,
    /// The color of the map selected item box.
    map_selected_color: Color,
    /// The color of border of the map info panel.
    map_info_panel_border_color: Color,
    /// The background color of the map info panel.
    map_info_panel_bg_color: Color,
    /// The color of text in the map info panel.
    map_info_panel_text_color: Color,
}

impl From<TuiTheme> for Theme {
    fn from(value: TuiTheme) -> Self {
        Self {
            bg_color: Color::from(value.bg_color),
            border_color: Color::from(value.border_color),
            text_color: Color::from(value.text_color),
            tab_text_color: Color::from(value.tab_text_color),
            hops_table_header_bg_color: Color::from(value.hops_table_header_bg_color),
            hops_table_header_text_color: Color::from(value.hops_table_header_text_color),
            hops_table_row_active_text_color: Color::from(value.hops_table_row_active_text_color),
            hops_table_row_inactive_text_color: Color::from(
                value.hops_table_row_inactive_text_color,
            ),
            hops_chart_selected_color: Color::from(value.hops_chart_selected_color),
            hops_chart_unselected_color: Color::from(value.hops_chart_unselected_color),
            hops_chart_axis_color: Color::from(value.hops_chart_axis_color),
            frequency_chart_bar_color: Color::from(value.frequency_chart_bar_color),
            frequency_chart_text_color: Color::from(value.frequency_chart_text_color),
            samples_chart_color: Color::from(value.samples_chart_color),
            help_dialog_bg_color: Color::from(value.help_dialog_bg_color),
            help_dialog_text_color: Color::from(value.help_dialog_text_color),
            settings_dialog_bg_color: Color::from(value.settings_dialog_bg_color),
            settings_tab_text_color: Color::from(value.settings_tab_text_color),
            settings_table_header_text_color: Color::from(value.settings_table_header_text_color),
            settings_table_header_bg_color: Color::from(value.settings_table_header_bg_color),
            settings_table_row_text_color: Color::from(value.settings_table_row_text_color),
            map_world_color: Color::from(value.map_world_color),
            map_radius_color: Color::from(value.map_radius_color),
            map_selected_color: Color::from(value.map_selected_color),
            map_info_panel_border_color: Color::from(value.map_info_panel_border_color),
            map_info_panel_bg_color: Color::from(value.map_info_panel_bg_color),
            map_info_panel_text_color: Color::from(value.map_info_panel_text_color),
        }
    }
}

impl From<TuiColor> for Color {
    fn from(value: TuiColor) -> Self {
        match value {
            TuiColor::Black => Self::Black,
            TuiColor::Red => Self::Red,
            TuiColor::Green => Self::Green,
            TuiColor::Yellow => Self::Yellow,
            TuiColor::Blue => Self::Blue,
            TuiColor::Magenta => Self::Magenta,
            TuiColor::Cyan => Self::Cyan,
            TuiColor::Gray => Self::Gray,
            TuiColor::DarkGray => Self::DarkGray,
            TuiColor::LightRed => Self::LightRed,
            TuiColor::LightGreen => Self::LightGreen,
            TuiColor::LightYellow => Self::LightYellow,
            TuiColor::LightBlue => Self::LightBlue,
            TuiColor::LightMagenta => Self::LightMagenta,
            TuiColor::LightCyan => Self::LightCyan,
            TuiColor::White => Self::White,
            TuiColor::Rgb(r, g, b) => Self::Rgb(r, g, b),
        }
    }
}

fn fmt_color(color: Color) -> String {
    match color {
        Color::Black => "black".to_string(),
        Color::Red => "red".to_string(),
        Color::Green => "green".to_string(),
        Color::Yellow => "yellow".to_string(),
        Color::Blue => "blue".to_string(),
        Color::Magenta => "magenta".to_string(),
        Color::Cyan => "cyan".to_string(),
        Color::Gray => "gray".to_string(),
        Color::DarkGray => "darkgray".to_string(),
        Color::LightRed => "lightred".to_string(),
        Color::LightGreen => "lightgreen".to_string(),
        Color::LightYellow => "lightyellow".to_string(),
        Color::LightBlue => "lightblue".to_string(),
        Color::LightMagenta => "lightmagenta".to_string(),
        Color::LightCyan => "lightcyan".to_string(),
        Color::White => "white".to_string(),
        Color::Rgb(r, g, b) => format!("{r:02x}{g:02x}{b:02x}"),
        _ => "unknown".to_string(),
    }
}

/// Tui configuration.
#[derive(Debug)]
pub struct TuiConfig {
    /// Refresh rate.
    refresh_rate: Duration,
    /// Preserve screen on exit.
    preserve_screen: bool,
    /// How to render addresses.
    address_mode: AddressMode,
    /// Lookup `AS` information.
    lookup_as_info: bool,
    /// How to render AS data.
    as_mode: AsMode,
    /// How to render GeoIp data.
    geoip_mode: GeoIpMode,
    /// The maximum number of addresses to show per hop.
    max_addrs: Option<u8>,
    /// The maximum number of samples to record per hop.
    max_samples: usize,
    /// The Tui color theme.
    theme: Theme,
    /// The Tui keyboard bindings.
    bindings: Bindings,
}

impl TuiConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        refresh_rate: Duration,
        preserve_screen: bool,
        address_mode: AddressMode,
        lookup_as_info: bool,
        as_mode: AsMode,
        geoip_mode: GeoIpMode,
        max_addrs: Option<u8>,
        max_samples: usize,
        tui_theme: TuiTheme,
        tui_bindings: &TuiBindings,
    ) -> Self {
        Self {
            refresh_rate,
            preserve_screen,
            address_mode,
            lookup_as_info,
            as_mode,
            geoip_mode,
            max_addrs,
            max_samples,
            theme: Theme::from(tui_theme),
            bindings: Bindings::from(*tui_bindings),
        }
    }
}

struct TuiApp {
    selected_tracer_data: Trace,
    trace_info: Vec<TraceInfo>,
    tui_config: TuiConfig,
    /// The state of the hop table.
    table_state: TableState,
    /// The state of the settings table.
    setting_table_state: TableState,
    /// The selected trace.
    trace_selected: usize,
    /// The selected tab in the settings dialog.
    settings_tab_selected: usize,
    /// The index of the current address to show for the selected hop.
    ///
    /// Only used in detail mode.
    selected_hop_address: usize,
    resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
    show_help: bool,
    show_settings: bool,
    show_hop_details: bool,
    show_chart: bool,
    show_map: bool,
    frozen_start: Option<SystemTime>,
    zoom_factor: usize,
}

impl TuiApp {
    fn new(
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

    fn tracer_data(&self) -> &Trace {
        &self.selected_tracer_data
    }

    fn snapshot_trace_data(&mut self) {
        self.selected_tracer_data = self.trace_info[self.trace_selected].data.read().clone();
    }

    fn clear_trace_data(&mut self) {
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

    fn tracer_config(&self) -> &TraceInfo {
        &self.trace_info[self.trace_selected]
    }

    fn clamp_selected_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if let Some(selected) = self.table_state.selected() {
            if selected > hop_count - 1 {
                self.table_state.select(Some(hop_count - 1));
            }
        }
    }

    fn next_hop(&mut self) {
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

    fn previous_hop(&mut self) {
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

    fn next_trace(&mut self) {
        if self.trace_selected < self.trace_info.len() - 1 {
            self.trace_selected += 1;
        }
    }

    fn previous_trace(&mut self) {
        if self.trace_selected > 0 {
            self.trace_selected -= 1;
        };
    }

    fn next_hop_address(&mut self) {
        if let Some(hop) = self.selected_hop() {
            if self.selected_hop_address < hop.addr_count() - 1 {
                self.selected_hop_address += 1;
            }
        }
    }

    fn previous_hop_address(&mut self) {
        if self.selected_hop().is_some() && self.selected_hop_address > 0 {
            self.selected_hop_address -= 1;
        }
    }

    fn next_settings_tab(&mut self) {
        if self.settings_tab_selected < SETTINGS_TABS.len() - 1 {
            self.settings_tab_selected += 1;
        }
        self.setting_table_state.select(Some(0));
    }

    fn previous_settings_tab(&mut self) {
        if self.settings_tab_selected > 0 {
            self.settings_tab_selected -= 1;
        };
        self.setting_table_state.select(Some(0));
    }

    fn next_settings_item(&mut self) {
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

    fn previous_settings_item(&mut self) {
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

    fn clear(&mut self) {
        self.table_state.select(None);
        self.selected_hop_address = 0;
    }

    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    fn toggle_settings(&mut self) {
        self.show_settings = !self.show_settings;
    }

    fn toggle_hop_details(&mut self) {
        if self.show_hop_details {
            self.tui_config.max_addrs = None;
        } else {
            self.tui_config.max_addrs = Some(1);
        }
        self.show_hop_details = !self.show_hop_details;
    }

    fn toggle_freeze(&mut self) {
        self.frozen_start = match self.frozen_start {
            None => Some(SystemTime::now()),
            Some(_) => None,
        };
    }

    fn toggle_chart(&mut self) {
        self.show_chart = !self.show_chart;
        self.show_map = false;
    }

    fn toggle_map(&mut self) {
        self.show_map = !self.show_map;
        self.show_chart = false;
    }

    fn toggle_asinfo(&mut self) {
        match self.resolver.config().resolve_method {
            DnsResolveMethod::Resolv | DnsResolveMethod::Google | DnsResolveMethod::Cloudflare => {
                self.tui_config.lookup_as_info = !self.tui_config.lookup_as_info;
                self.resolver.flush();
            }
            DnsResolveMethod::System => {}
        }
    }

    fn expand_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            None => Some(1),
            Some(i) if i < self.max_hosts() => Some(i + 1),
            Some(i) => Some(i),
        }
    }

    fn contract_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            Some(i) if i > 1 => Some(i - 1),
            _ => None,
        }
    }

    fn zoom_in(&mut self) {
        if self.zoom_factor < MAX_ZOOM_FACTOR {
            self.zoom_factor += 1;
        }
    }

    fn zoom_out(&mut self) {
        if self.zoom_factor > 1 {
            self.zoom_factor -= 1;
        }
    }

    fn expand_hosts_max(&mut self) {
        self.tui_config.max_addrs = Some(self.max_hosts());
    }

    fn contract_hosts_min(&mut self) {
        self.tui_config.max_addrs = Some(1);
    }

    /// The maximum number of hosts per hop for the currently selected trace.
    fn max_hosts(&self) -> u8 {
        self.selected_tracer_data
            .hops()
            .iter()
            .map(|h| h.addrs().count())
            .max()
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or_default()
    }
}

/// Run the frontend TUI.
pub fn run_frontend(
    traces: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let preserve_screen = tui_config.preserve_screen;
    let res = run_app(&mut terminal, traces, tui_config, resolver, geoip_lookup);
    disable_raw_mode()?;
    if !preserve_screen {
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    }
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("{err:?}");
    }
    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    trace_info: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
) -> io::Result<()> {
    let mut app = TuiApp::new(tui_config, resolver, geoip_lookup, trace_info);
    loop {
        if app.frozen_start.is_none() {
            app.snapshot_trace_data();
            app.clamp_selected_hop();
        };
        terminal.draw(|f| render_app(f, &mut app))?;
        if event::poll(app.tui_config.refresh_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let bindings = &app.tui_config.bindings;
                    if app.show_help {
                        if bindings.toggle_help.check(key)
                            || bindings.clear_selection.check(key)
                            || bindings.quit.check(key)
                        {
                            app.toggle_help();
                        }
                    } else if app.show_settings {
                        if bindings.toggle_settings.check(key)
                            || bindings.clear_selection.check(key)
                            || bindings.quit.check(key)
                        {
                            app.toggle_settings();
                        } else if bindings.previous_trace.check(key) {
                            app.previous_settings_tab();
                        } else if bindings.next_trace.check(key) {
                            app.next_settings_tab();
                        } else if bindings.next_hop.check(key) {
                            app.next_settings_item();
                        } else if bindings.previous_hop.check(key) {
                            app.previous_settings_item();
                        }
                    } else if bindings.toggle_help.check(key) {
                        app.toggle_help();
                    } else if bindings.toggle_settings.check(key) {
                        app.toggle_settings();
                    } else if bindings.next_hop.check(key) {
                        app.next_hop();
                    } else if bindings.previous_hop.check(key) {
                        app.previous_hop();
                    } else if bindings.previous_trace.check(key) {
                        app.previous_trace();
                        app.clear();
                    } else if bindings.next_trace.check(key) {
                        app.next_trace();
                        app.clear();
                    } else if bindings.next_hop_address.check(key) {
                        app.next_hop_address();
                    } else if bindings.previous_hop_address.check(key) {
                        app.previous_hop_address();
                    } else if bindings.address_mode_ip.check(key) {
                        app.tui_config.address_mode = AddressMode::IP;
                    } else if bindings.address_mode_host.check(key) {
                        app.tui_config.address_mode = AddressMode::Host;
                    } else if bindings.address_mode_both.check(key) {
                        app.tui_config.address_mode = AddressMode::Both;
                    } else if bindings.toggle_freeze.check(key) {
                        app.toggle_freeze();
                    } else if bindings.toggle_chart.check(key) {
                        app.toggle_chart();
                    } else if bindings.toggle_map.check(key) {
                        app.toggle_map();
                    } else if bindings.contract_hosts_min.check(key) {
                        app.contract_hosts_min();
                    } else if bindings.expand_hosts_max.check(key) {
                        app.expand_hosts_max();
                    } else if bindings.contract_hosts.check(key) {
                        app.contract_hosts();
                    } else if bindings.expand_hosts.check(key) {
                        app.expand_hosts();
                    } else if bindings.chart_zoom_in.check(key) {
                        app.zoom_in();
                    } else if bindings.chart_zoom_out.check(key) {
                        app.zoom_out();
                    } else if bindings.clear_trace_data.check(key) {
                        app.clear();
                        app.clear_trace_data();
                    } else if bindings.clear_dns_cache.check(key) {
                        app.resolver.flush();
                    } else if bindings.clear_selection.check(key) {
                        app.clear();
                    } else if bindings.toggle_as_info.check(key) {
                        app.toggle_asinfo();
                    } else if bindings.toggle_hop_details.check(key) {
                        app.toggle_hop_details();
                    } else if bindings.quit.check(key) || CTRL_C.check(key) {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Render the application main screen.
///
/// The layout of the TUI is as follows:
///
///  ____________________________________
/// |               Header               |
///  ------------------------------------
/// |                Tabs                |
///  ------------------------------------
/// |                                    |
/// |                                    |
/// |                                    |
/// |            Hops / Chart            |
/// |                                    |
/// |                                    |
/// |                                    |
///  ------------------------------------
/// |     History     |    Frequency     |
/// |                 |                  |
///  ------------------------------------
///
/// Header - the title, configuration, destination, clock and keyboard controls
/// Tab - a tab for each target being traced (only shown if > 1 target requested)
/// Hops - a table where each row represents a single hop (time-to-live) in the trace
/// History - a graph of historic round-trip ping samples for the target host
/// Frequency - a histogram of sample frequencies by round-trip time for the target host
///
/// On startup a splash screen is shown in place of the hops table, until the completion of the first round.
fn render_app<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp) {
    let constraints = if app.trace_info.len() > 1 {
        LAYOUT_WITH_TABS.as_slice()
    } else {
        LAYOUT_WITHOUT_TABS.as_slice()
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.as_ref())
        .split(f.size());
    render_header(f, app, chunks[0]);
    if app.trace_info.len() > 1 {
        render_tabs(f, app, chunks[1]);
        render_body(f, chunks[2], app);
        render_footer(f, chunks[3], app);
    } else {
        render_body(f, chunks[1], app);
        render_footer(f, chunks[2], app);
    }
    if app.show_settings {
        render_settings(f, app);
    } else if app.show_help {
        render_help(f, app);
    }
}

/// Render the title, config, target, clock and keyboard controls.
fn render_header<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let header_block = Block::default()
        .title(format!(" Trippy v{} ", clap::crate_version!()))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border_color))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        );
    let now = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let clock_span = Spans::from(Span::raw(now));
    let help_span = Spans::from(vec![
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("elp "),
        Span::styled("s", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("ettings "),
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("uit"),
    ]);
    let right_spans = vec![clock_span, help_span];
    let right = Paragraph::new(right_spans)
        .style(Style::default())
        .block(header_block.clone())
        .alignment(Alignment::Right);
    let protocol = match app.tracer_config().protocol {
        TracerProtocol::Icmp => format!("icmp({})", app.tracer_config().addr_family),
        TracerProtocol::Udp => format!(
            "udp({}, {})",
            app.tracer_config().addr_family,
            app.tracer_config().multipath_strategy,
        ),
        TracerProtocol::Tcp => format!("tcp({})", app.tracer_config().addr_family),
    };
    let details = if app.show_hop_details {
        String::from("on")
    } else {
        String::from("off")
    };
    let as_info = match app.resolver.config().resolve_method {
        DnsResolveMethod::System => String::from("n/a"),
        DnsResolveMethod::Resolv | DnsResolveMethod::Google | DnsResolveMethod::Cloudflare => {
            if app.tui_config.lookup_as_info {
                String::from("on")
            } else {
                String::from("off")
            }
        }
    };
    let max_hosts = app
        .tui_config
        .max_addrs
        .map_or_else(|| String::from("auto"), |m| m.to_string());
    let source = render_source(app);
    let dest = render_destination(app);
    let target = format!("{source} -> {dest}");
    let left_spans = vec![
        Spans::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(target),
        ]),
        Spans::from(vec![
            Span::styled("Config: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "protocol={protocol} as-info={as_info} details={details} max-hosts={max_hosts}"
            )),
        ]),
        Spans::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(render_status(app)),
            Span::raw(format!(
                ", discovered {} hops",
                app.tracer_data().hops().len()
            )),
        ]),
    ];

    let left = Paragraph::new(left_spans)
        .style(Style::default())
        .block(header_block)
        .alignment(Alignment::Left);
    f.render_widget(right, rect);
    f.render_widget(left, rect);
}

/// Render the source address of the trace.
fn render_source(app: &mut TuiApp) -> String {
    let src_hostname = app.resolver.reverse_lookup(app.tracer_config().source_addr);
    let src_addr = app.tracer_config().source_addr;
    match app.tracer_config().port_direction {
        PortDirection::None => {
            format!("{src_hostname} ({src_addr})")
        }
        PortDirection::FixedDest(_) => {
            format!("{src_hostname}:* ({src_addr}:*)")
        }
        PortDirection::FixedSrc(src) | PortDirection::FixedBoth(src, _) => {
            format!("{src_hostname}:{} ({src_addr}:{})", src.0, src.0)
        }
    }
}

/// Render the destination address.
fn render_destination(app: &mut TuiApp) -> String {
    let dest_hostname = &app.tracer_config().target_hostname;
    let dest_addr = app.tracer_config().target_addr;
    match app.tracer_config().port_direction {
        PortDirection::None => {
            format!("{dest_hostname} ({dest_addr})")
        }
        PortDirection::FixedSrc(_) => {
            format!("{dest_hostname}:* ({dest_addr}:*)")
        }
        PortDirection::FixedDest(dest) | PortDirection::FixedBoth(_, dest) => {
            format!("{dest_hostname}:{} ({dest_addr}:{})", dest.0, dest.0)
        }
    }
}

/// Render the headline status of the tracing.
fn render_status(app: &TuiApp) -> String {
    if app.selected_tracer_data.error().is_some() {
        String::from("Failed")
    } else if let Some(start) = app.frozen_start {
        format!(
            "Frozen ({})",
            format_duration(Duration::from_secs(
                start.elapsed().unwrap_or_default().as_secs()
            ))
        )
    } else {
        String::from("Running")
    }
}

/// Format the `DnsResolveMethod`.
fn format_dns_method(resolve_method: DnsResolveMethod) -> String {
    match resolve_method {
        DnsResolveMethod::System => String::from("system"),
        DnsResolveMethod::Resolv => String::from("resolv"),
        DnsResolveMethod::Google => String::from("google"),
        DnsResolveMethod::Cloudflare => String::from("cloudflare"),
    }
}

/// Format the `AsMode`.
fn format_as_mode(as_mode: AsMode) -> String {
    match as_mode {
        AsMode::Asn => "asn".to_string(),
        AsMode::Prefix => "prefix".to_string(),
        AsMode::CountryCode => "country-code".to_string(),
        AsMode::Registry => "registry".to_string(),
        AsMode::Allocated => "allocated".to_string(),
        AsMode::Name => "name".to_string(),
    }
}

/// Format the `AddressMode`.
fn format_address_mode(address_mode: AddressMode) -> String {
    match address_mode {
        AddressMode::IP => "ip".to_string(),
        AddressMode::Host => "host".to_string(),
        AddressMode::Both => "both".to_string(),
    }
}

/// Format the `GeoIpMode`.
fn format_geoip_mode(geoip_mode: GeoIpMode) -> String {
    match geoip_mode {
        GeoIpMode::Off => "off".to_string(),
        GeoIpMode::Short => "short".to_string(),
        GeoIpMode::Long => "long".to_string(),
        GeoIpMode::Location => "location".to_string(),
    }
}

/// Render the tabs, one per trace.
fn render_tabs<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let tabs_block = Block::default()
        .title("Traces")
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border_color))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        );
    let titles: Vec<_> = app
        .trace_info
        .iter()
        .map(|trace| {
            Spans::from(Span::styled(
                &trace.target_hostname,
                Style::default().fg(app.tui_config.theme.tab_text_color),
            ))
        })
        .collect();
    let tabs = Tabs::new(titles)
        .block(tabs_block)
        .select(app.trace_selected)
        .style(Style::default())
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(tabs, rect);
}

/// Render the body.
///
/// This is either an BSOD if there wa san error or the table of hop data or, if there is no data, the splash screen.
fn render_body<B: Backend>(f: &mut Frame<'_, B>, rec: Rect, app: &mut TuiApp) {
    if let Some(err) = app.selected_tracer_data.error() {
        render_bsod(f, rec, err);
    } else if app.tracer_data().hops().is_empty() {
        render_splash(f, app, rec);
    } else if app.show_chart {
        render_chart(f, app, rec);
    } else if app.show_map {
        render_map(f, app, rec);
    } else {
        render_table(f, app, rec);
    }
}

#[derive(Debug, Clone)]
pub struct CircleWidget {
    pub x: f64,
    pub y: f64,
    pub radius: f64,
    pub color: Color,
}

impl CircleWidget {
    pub fn new(x: f64, y: f64, radius: f64, color: Color) -> Self {
        Self {
            x,
            y,
            radius,
            color,
        }
    }
}

impl Shape for CircleWidget {
    fn draw(&self, painter: &mut Painter<'_, '_>) {
        for angle in 0..360 {
            let radians = f64::from(angle).to_radians();
            let circle_x = self.radius.mul_add(radians.cos(), self.x);
            let circle_y = self.radius.mul_add(radians.sin(), self.y);
            if let Some((x, y)) = painter.get_point(circle_x, circle_y) {
                painter.paint(x, y, self.color);
            }
        }
    }
}

/// Render the `GeoIp` map.
fn render_map<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let entries = build_map_entries(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(MAP_LAYOUT)
        .split(rect);
    let info_rect = chunks[1].inner(&Margin {
        vertical: 0,
        horizontal: 16,
    });
    render_map_canvas(f, app, rect, &entries);
    render_map_info_panel(f, app, info_rect, &entries);
}

/// Render the map canvas.
fn render_map_canvas<B: Backend>(
    f: &mut Frame<'_, B>,
    app: &TuiApp,
    rect: Rect,
    entries: &[MapEntry],
) {
    let theme = app.tui_config.theme;
    let map = Canvas::default()
        .background_color(app.tui_config.theme.bg_color)
        .block(
            Block::default()
                .title("Map")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.tui_config.theme.border_color))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg_color)
                        .fg(app.tui_config.theme.text_color),
                ),
        )
        .paint(|ctx| {
            render_map_canvas_world(ctx, theme.map_world_color);
            ctx.layer();
            for entry in entries {
                render_map_canvas_pin(ctx, entry);
                render_map_canvas_radius(ctx, entry, theme.map_radius_color);
                render_map_canvas_selected(
                    ctx,
                    entry,
                    app.selected_hop_or_target(),
                    theme.map_selected_color,
                );
            }
        })
        .marker(Marker::Braille)
        .x_bounds([-180.0, 180.0])
        .y_bounds([-90.0, 90.0]);
    f.render_widget(Clear, rect);
    f.render_widget(map, rect);
}

/// Render the map canvas world.
fn render_map_canvas_world(ctx: &mut Context<'_>, color: Color) {
    ctx.draw(&Map {
        color,
        resolution: MapResolution::High,
    });
}

/// Render the map canvas pin.
fn render_map_canvas_pin(ctx: &mut Context<'_>, entry: &MapEntry) {
    let MapEntry {
        latitude,
        longitude,
        ..
    } = entry;
    ctx.print(*longitude, *latitude, Span::styled("📍", Style::default()));
}

/// Render the map canvas accuracy radius circle.
fn render_map_canvas_radius(ctx: &mut Context<'_>, entry: &MapEntry, color: Color) {
    let MapEntry {
        latitude,
        longitude,
        radius,
        ..
    } = entry;
    let radius_degrees = f64::from(*radius) / 110_f64;
    if radius_degrees > 2_f64 {
        let circle_widget = CircleWidget::new(*longitude, *latitude, radius_degrees, color);
        ctx.draw(&circle_widget);
    }
}

/// Render the map canvas selected item box.
fn render_map_canvas_selected(
    ctx: &mut Context<'_>,
    entry: &MapEntry,
    selected_hop: &Hop,
    color: Color,
) {
    let MapEntry {
        latitude,
        longitude,
        hops,
        ..
    } = entry;
    if hops.contains(&selected_hop.ttl()) {
        ctx.draw(&Rectangle {
            x: longitude - 5.0_f64,
            y: latitude - 5.0_f64,
            width: 10.0_f64,
            height: 10.0_f64,
            color,
        });
    }
}

/// Render the map info panel.
fn render_map_info_panel<B: Backend>(
    f: &mut Frame<'_, B>,
    app: &TuiApp,
    rect: Rect,
    entries: &[MapEntry],
) {
    let theme = app.tui_config.theme;
    let selected_hop = app.selected_hop_or_target();
    let locations = entries
        .iter()
        .filter_map(|entry| {
            if entry.hops.contains(&selected_hop.ttl()) {
                Some(format!("{} [{}]", entry.long_name, entry.location))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let info = match locations.as_slice() {
        _ if app.tracer_config().geoip_mmdb_file.is_none() => "GeoIp not enabled".to_string(),
        [] if selected_hop.addr_count() > 0 => format!(
            "No GeoIp data for hop {} ({})",
            selected_hop.ttl(),
            selected_hop.addrs().join(", ")
        ),
        [] => format!("No GeoIp data for hop {}", selected_hop.ttl()),
        [loc] => loc.to_string(),
        _ => format!("Multiple GeoIp locations for hop {}", selected_hop.ttl()),
    };
    let info_panel = Paragraph::new(info)
        .block(
            Block::default()
                .title(format!("Hop {}", selected_hop.ttl()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.map_info_panel_border_color))
                .style(
                    Style::default()
                        .bg(theme.map_info_panel_bg_color)
                        .fg(theme.map_info_panel_text_color),
                ),
        )
        .alignment(Alignment::Left);
    f.render_widget(Clear, rect);
    f.render_widget(info_panel, rect);
}

/// An entry to render on the map.
struct MapEntry {
    long_name: String,
    location: String,
    latitude: f64,
    longitude: f64,
    radius: u16,
    hops: Vec<u8>,
}

/// Build a vec of `MapEntry` for all hops.
///
/// Each entry represent a single `GeoIp` location, which may be associated with multiple hops.
fn build_map_entries(app: &mut TuiApp) -> Vec<MapEntry> {
    let mut geo_map: HashMap<String, MapEntry> = HashMap::new();
    for hop in app.tracer_data().hops() {
        for addr in hop.addrs() {
            if let Some(geo) = app.geoip_lookup.lookup(*addr).unwrap_or_default() {
                if let Some((latitude, longitude, radius)) = geo.coordinates() {
                    let entry = geo_map.entry(geo.long_name()).or_insert(MapEntry {
                        long_name: geo.long_name(),
                        location: format!("{latitude}, {longitude} ~{radius}km"),
                        latitude,
                        longitude,
                        radius,
                        hops: vec![],
                    });
                    entry.hops.push(hop.ttl());
                }
            };
        }
    }
    geo_map.into_values().collect_vec()
}

/// Render the ping history for all hops as a chart.
fn render_chart<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let selected_hop = app.table_state.selected().map_or_else(
        || app.tracer_data().target_hop(),
        |s| &app.tracer_data().hops()[s],
    );
    let samples = app.tui_config.max_samples / app.zoom_factor;
    let series_data = app
        .selected_tracer_data
        .hops()
        .iter()
        .map(|hop| {
            hop.samples()
                .iter()
                .enumerate()
                .take(samples)
                .map(|(i, s)| (i as f64, (s.as_secs_f64() * 1000_f64)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let max_sample = series_data
        .iter()
        .flatten()
        .map(|&(_, s)| s)
        .max_by_key(|&c| c as u64)
        .unwrap_or_default();
    let sets = series_data
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Dataset::default()
                .name(format!("Hop {}", i + 1))
                .data(s)
                .graph_type(GraphType::Line)
                .marker(Marker::Braille)
                .style(Style::default().fg({
                    match i {
                        i if i + 1 == selected_hop.ttl() as usize => {
                            app.tui_config.theme.hops_chart_selected_color
                        }
                        _ => app.tui_config.theme.hops_chart_unselected_color,
                    }
                }))
        })
        .collect::<Vec<_>>();
    let constraints = (Constraint::Ratio(1, 1), Constraint::Ratio(1, 1));
    let chart = Chart::new(sets)
        .x_axis(
            Axis::default()
                .title("Samples")
                .bounds([0_f64, samples as f64])
                .labels_alignment(Alignment::Right)
                .labels(
                    ["0".to_string(), format!("{samples} ({}x)", app.zoom_factor)]
                        .into_iter()
                        .map(Span::from)
                        .collect(),
                )
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis_color)),
        )
        .y_axis(
            Axis::default()
                .title("RTT")
                .bounds([0_f64, max_sample])
                .labels(
                    [
                        String::from("0.0"),
                        format!("{:.1}", max_sample / 2_f64),
                        format!("{max_sample:.1}"),
                    ]
                    .into_iter()
                    .map(Span::from)
                    .collect(),
                )
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis_color)),
        )
        .hidden_legend_constraints(constraints)
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color))
                .title("Chart"),
        );
    f.render_widget(chart, rect);
}

/// Render a blue screen of death.
fn render_bsod<B: Backend>(f: &mut Frame<'_, B>, rect: Rect, error: &str) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title("Hops")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(Color::Blue));
    let spans = vec![
        Spans::from(Span::styled(
            "Trippy Failed :(",
            Style::default().add_modifier(Modifier::REVERSED),
        )),
        Spans::from(""),
        Spans::from(error),
        Spans::from(""),
        Spans::from("Press q to quit "),
    ];
    let paragraph = Paragraph::new(spans).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}

/// Render the splash screen.
///
/// This is shown on startup whilst we await the first round of data to be available.
fn render_splash<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title("Hops")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border_color))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        );
    let splash = vec![
        r#" _____    _                "#,
        r#"|_   _| _(_)_ __ _ __ _  _ "#,
        r#"  | || '_| | '_ \ '_ \ || |"#,
        r#"  |_||_| |_| .__/ .__/\_, |"#,
        r#"           |_|  |_|   |__/ "#,
        "",
        "Awaiting data...",
    ];
    let spans: Vec<_> = splash
        .into_iter()
        .map(|line| Spans::from(Span::styled(line, Style::default())))
        .collect();
    let paragraph = Paragraph::new(spans).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}

/// Render the table of data about the hops.
///
/// For each hop, we show:
///
/// - The time-to-live (indexed from 1) at this hop (`#`)
/// - The host(s) reported at this hop (`Host`)
/// - The packet loss % for all probes at this hop (`Loss%`)
/// - The number of requests sent for all probes at this hop (`Snt`)
/// - The number of replies received for all probes at this hop (`Recv`)
/// - The round-trip time of the most recent probe at this hop (`Last`)
/// - The average round-trip time for all probes at this hop (`Avg`)
/// - The best round-trip time for all probes at this hop (`Best`)
/// - The worst round-trip time for all probes at this hop (`Wrst`)
/// - The standard deviation round-trip time for all probes at this hop (`StDev`)
/// - The status of this hop (`Sts`)
fn render_table<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let header = render_table_header(app.tui_config.theme);
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let rows =
        app.tracer_data().hops().iter().map(|hop| {
            render_table_row(app, hop, &app.resolver, &app.geoip_lookup, &app.tui_config)
        });
    let table = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color))
                .title("Hops"),
        )
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        )
        .highlight_style(selected_style)
        .widths(&TABLE_WIDTH);
    f.render_stateful_widget(table, rect, &mut app.table_state);
}

/// Render the table header.
fn render_table_header(theme: Theme) -> Row<'static> {
    let header_cells = TABLE_HEADER
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(theme.hops_table_header_text_color)));
    Row::new(header_cells)
        .style(Style::default().bg(theme.hops_table_header_bg_color))
        .height(1)
        .bottom_margin(0)
}

/// Render a single row in the table of hops.
fn render_table_row(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> Row<'static> {
    let is_selected_hop = app
        .selected_hop()
        .map(|h| h.ttl() == hop.ttl())
        .unwrap_or_default();
    let is_target = app.tracer_data().is_target(hop);
    let is_in_round = app.tracer_data().is_in_round(hop);
    let ttl_cell = render_ttl_cell(hop);
    let (hostname_cell, row_height) = if is_selected_hop && app.show_hop_details {
        render_hostname_with_details(app, hop, dns, geoip_lookup, config)
    } else {
        render_hostname(hop, dns, geoip_lookup, config)
    };
    let loss_pct_cell = render_loss_pct_cell(hop);
    let total_sent_cell = render_total_sent_cell(hop);
    let total_recv_cell = render_total_recv_cell(hop);
    let last_cell = render_last_cell(hop);
    let avg_cell = render_avg_cell(hop);
    let best_cell = render_best_cell(hop);
    let worst_cell = render_worst_cell(hop);
    let stddev_cell = render_stddev_cell(hop);
    let status_cell = render_status_cell(hop, is_target);
    let cells = [
        ttl_cell,
        hostname_cell,
        loss_pct_cell,
        total_sent_cell,
        total_recv_cell,
        last_cell,
        avg_cell,
        best_cell,
        worst_cell,
        stddev_cell,
        status_cell,
    ];
    let row_color = if is_in_round {
        config.theme.hops_table_row_active_text_color
    } else {
        config.theme.hops_table_row_inactive_text_color
    };
    Row::new(cells)
        .height(row_height)
        .bottom_margin(0)
        .style(Style::default().fg(row_color))
}

fn render_ttl_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.ttl()))
}

fn render_loss_pct_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{:.1}%", hop.loss_pct()))
}

fn render_total_sent_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.total_sent()))
}

fn render_total_recv_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.total_recv()))
}

fn render_avg_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 0 {
        format!("{:.1}", hop.avg_ms())
    } else {
        String::default()
    })
}

fn render_last_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.last_ms()
            .map(|last| format!("{last:.1}"))
            .unwrap_or_default(),
    )
}

fn render_best_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.best_ms()
            .map(|best| format!("{best:.1}"))
            .unwrap_or_default(),
    )
}

fn render_worst_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.worst_ms()
            .map(|worst| format!("{worst:.1}"))
            .unwrap_or_default(),
    )
}

fn render_stddev_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 1 {
        format!("{:.1}", hop.stddev_ms())
    } else {
        String::default()
    })
}

fn render_status_cell(hop: &Hop, is_target: bool) -> Cell<'static> {
    let lost = hop.total_sent() - hop.total_recv();
    Cell::from(match (lost, is_target) {
        (lost, target) if target && lost == hop.total_sent() => "🔴",
        (lost, target) if target && lost > 0 => "🟡",
        (lost, target) if !target && lost == hop.total_sent() => "🟤",
        (lost, target) if !target && lost > 0 => "🔵",
        _ => "🟢",
    })
}

/// Render hostname table cell (normal mode).
fn render_hostname(
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (Cell<'static>, u16) {
    let (hostname, count) = if hop.total_recv() > 0 {
        match config.max_addrs {
            None => {
                let hostnames = hop
                    .addrs_with_counts()
                    .map(|(addr, &freq)| format_address(addr, freq, hop, dns, geoip_lookup, config))
                    .join("\n");
                let count = hop.addr_count().clamp(1, u8::MAX as usize);
                (hostnames, count as u16)
            }
            Some(max_addr) => {
                let hostnames = hop
                    .addrs_with_counts()
                    .sorted_unstable_by_key(|(_, &cnt)| cnt)
                    .rev()
                    .take(max_addr as usize)
                    .map(|(addr, &freq)| format_address(addr, freq, hop, dns, geoip_lookup, config))
                    .join("\n");
                let count = hop.addr_count().clamp(1, max_addr as usize);
                (hostnames, count as u16)
            }
        }
    } else {
        (String::from("No response"), 1)
    };
    (Cell::from(hostname), count)
}

/// Perform a reverse DNS lookup for an address and format the result.
fn format_address(
    addr: &IpAddr,
    freq: usize,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> String {
    let addr_fmt = match config.address_mode {
        AddressMode::IP => addr.to_string(),
        AddressMode::Host => {
            if config.lookup_as_info {
                let entry = dns.reverse_lookup_with_asinfo(*addr);
                format_dns_entry(entry, true, config.as_mode)
            } else {
                let entry = dns.reverse_lookup(*addr);
                format_dns_entry(entry, false, config.as_mode)
            }
        }
        AddressMode::Both => {
            let hostname = if config.lookup_as_info {
                let entry = dns.reverse_lookup_with_asinfo(*addr);
                format_dns_entry(entry, true, config.as_mode)
            } else {
                let entry = dns.reverse_lookup(*addr);
                format_dns_entry(entry, false, config.as_mode)
            };
            format!("{hostname} ({addr})")
        }
    };
    let geo_fmt = match config.geoip_mode {
        GeoIpMode::Off => None,
        GeoIpMode::Short => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.short_name()),
        GeoIpMode::Long => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.long_name()),
        GeoIpMode::Location => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.location()),
    };
    match geo_fmt {
        Some(geo) if hop.addr_count() > 1 => {
            format!(
                "{} [{}] [{:.1}%]",
                addr_fmt,
                geo,
                (freq as f64 / hop.total_recv() as f64) * 100_f64
            )
        }
        Some(geo) => {
            format!("{addr_fmt} [{geo}]")
        }
        None if hop.addr_count() > 1 => {
            format!(
                "{} [{:.1}%]",
                addr_fmt,
                (freq as f64 / hop.total_recv() as f64) * 100_f64
            )
        }
        None => addr_fmt,
    }
}

/// Format a `DnsEntry` with or without `AS` information (if available)
fn format_dns_entry(dns_entry: DnsEntry, lookup_as_info: bool, as_mode: AsMode) -> String {
    match dns_entry {
        DnsEntry::Resolved(Resolved::Normal(_, hosts)) => hosts.join(" "),
        DnsEntry::Resolved(Resolved::WithAsInfo(_, hosts, asinfo)) => {
            if lookup_as_info && !asinfo.asn.is_empty() {
                format!("{} {}", format_asinfo(&asinfo, as_mode), hosts.join(" "))
            } else {
                hosts.join(" ")
            }
        }
        DnsEntry::NotFound(Unresolved::Normal(ip)) | DnsEntry::Pending(ip) => format!("{ip}"),
        DnsEntry::NotFound(Unresolved::WithAsInfo(ip, asinfo)) => {
            if lookup_as_info && !asinfo.asn.is_empty() {
                format!("{} {}", format_asinfo(&asinfo, as_mode), ip)
            } else {
                format!("{ip}")
            }
        }
        DnsEntry::Failed(ip) => format!("Failed: {ip}"),
        DnsEntry::Timeout(ip) => format!("Timeout: {ip}"),
    }
}

/// Format `AsInfo` based on the `ASDisplayMode`.
fn format_asinfo(asinfo: &AsInfo, as_mode: AsMode) -> String {
    match as_mode {
        AsMode::Asn => format!("AS{}", asinfo.asn),
        AsMode::Prefix => format!("AS{} [{}]", asinfo.asn, asinfo.prefix),
        AsMode::CountryCode => format!("AS{} [{}]", asinfo.asn, asinfo.cc),
        AsMode::Registry => format!("AS{} [{}]", asinfo.asn, asinfo.registry),
        AsMode::Allocated => format!("AS{} [{}]", asinfo.asn, asinfo.allocated),
        AsMode::Name => format!("AS{} [{}]", asinfo.asn, asinfo.name),
    }
}

/// Render hostname table cell (detailed mode).
fn render_hostname_with_details(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (Cell<'static>, u16) {
    let (rendered, count) = if hop.total_recv() > 0 {
        let index = app.selected_hop_address;
        format_details(hop, index, dns, geoip_lookup, config)
    } else {
        (String::from("No response"), 1)
    };
    let cell = Cell::from(rendered);
    (cell, count)
}

/// Format hop details.
fn format_details(
    hop: &Hop,
    offset: usize,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (String, u16) {
    let Some(addr) = hop.addrs().nth(offset) else {
        return (format!("Error: no addr for index {offset}"), 1);
    };
    let count = hop.addr_count();
    let index = offset + 1;
    let geoip = geoip_lookup.lookup(*addr).unwrap_or_default();

    if config.lookup_as_info {
        let dns_entry = dns.reverse_lookup_with_asinfo(*addr);
        match dns_entry {
            DnsEntry::Pending(addr) => {
                let details = fmt_details_with_asn(addr, index, count, None, None, geoip);
                (details, 6)
            }
            DnsEntry::Resolved(Resolved::WithAsInfo(addr, hosts, asinfo)) => {
                let details =
                    fmt_details_with_asn(addr, index, count, Some(hosts), Some(asinfo), geoip);
                (details, 6)
            }
            DnsEntry::NotFound(Unresolved::WithAsInfo(addr, asinfo)) => {
                let details =
                    fmt_details_with_asn(addr, index, count, Some(vec![]), Some(asinfo), geoip);
                (details, 6)
            }
            DnsEntry::Failed(ip) => {
                let details = format!("Failed: {ip}");
                (details, 1)
            }
            DnsEntry::Timeout(ip) => {
                let details = format!("Timeout: {ip}");
                (details, 1)
            }
            DnsEntry::Resolved(Resolved::Normal(_, _))
            | DnsEntry::NotFound(Unresolved::Normal(_)) => unreachable!(),
        }
    } else {
        let dns_entry = dns.reverse_lookup(*addr);
        match dns_entry {
            DnsEntry::Pending(addr) => {
                let details = fmt_details_no_asn(addr, index, count, None, geoip);
                (details, 3)
            }
            DnsEntry::Resolved(Resolved::Normal(addr, hosts)) => {
                let details = fmt_details_no_asn(addr, index, count, Some(hosts), geoip);
                (details, 3)
            }
            DnsEntry::NotFound(Unresolved::Normal(addr)) => {
                let details = fmt_details_no_asn(addr, index, count, Some(vec![]), geoip);
                (details, 3)
            }
            DnsEntry::Failed(ip) => {
                let details = format!("Failed: {ip}");
                (details, 1)
            }
            DnsEntry::Timeout(ip) => {
                let details = format!("Timeout: {ip}");
                (details, 1)
            }
            DnsEntry::Resolved(Resolved::WithAsInfo(_, _, _))
            | DnsEntry::NotFound(Unresolved::WithAsInfo(_, _)) => unreachable!(),
        }
    }
}

/// Format hostname details with AS information.
///
/// Format as follows:
///
/// ```
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// AS Name: AS15169 GOOGLE, US
/// AS Info: 142.250.0.0/15 arin 2012-05-24
/// ```
///
/// If `hostnames` or `asinfo` is `None` it is rendered as `<pending>`
/// If `hostnames` or `asinfo` is `Some(vec![])` it is rendered as `<not found>`
fn fmt_details_with_asn(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    asinfo: Option<AsInfo>,
    geoip: Option<Rc<GeoIpCity>>,
) -> String {
    let as_formatted = if let Some(info) = asinfo {
        if info.asn.is_empty() {
            "AS Name: <not found>\nAS Info: <not found>".to_string()
        } else {
            format!(
                "AS Name: AS{} {}\nAS Info: {} {} {}",
                info.asn, info.name, info.prefix, info.registry, info.allocated
            )
        }
    } else {
        "AS Name: <awaited>\nAS Info: <awaited>".to_string()
    };
    let hosts_rendered = if let Some(hosts) = hostnames {
        if hosts.is_empty() {
            "Host: <not found>".to_string()
        } else {
            format!("Host: {}", hosts.join(" "))
        }
    } else {
        "Host: <awaited>".to_string()
    };
    let geoip_formatted = if let Some(geo) = geoip {
        let (lat, long, radius) = geo.coordinates().unwrap_or_default();
        format!(
            "Geo: {}\nPos: {}, {} (~{}km)",
            geo.long_name(),
            lat,
            long,
            radius
        )
    } else {
        "Geo: <not found>\nPos: <not found>".to_string()
    };
    format!("{addr} [{index} of {count}]\n{hosts_rendered}\n{as_formatted}\n{geoip_formatted}")
}

/// Format hostname details without AS information.
///
/// Format as follows:
///
/// ```
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// ```
///
/// If `hostnames` is `None` it is rendered as `<pending>`
/// If `hostnames` is `Some(vec![])` it is rendered as `<not found>`
fn fmt_details_no_asn(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    geoip: Option<Rc<GeoIpCity>>,
) -> String {
    let hosts_rendered = if let Some(hosts) = hostnames {
        if hosts.is_empty() {
            "Host: <not found>".to_string()
        } else {
            format!("Host: {}", hosts.join(" "))
        }
    } else {
        "Host: <awaited>".to_string()
    };
    let geoip_formatted = if let Some(geo) = geoip {
        let (lat, long, radius) = geo.coordinates().unwrap_or_default();
        format!(
            "Geo: {}\nPos: {}, {} (~{}km)",
            geo.long_name(),
            lat,
            long,
            radius
        )
    } else {
        "Geo: <not found>\nPos: <not found>".to_string()
    };
    format!("{addr} [{index} of {count}]\n{hosts_rendered}\n{geoip_formatted}")
}

/// Render the footer.
///
/// This contains the history and frequency charts.
fn render_footer<B: Backend>(f: &mut Frame<'_, B>, rec: Rect, app: &mut TuiApp) {
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
        .split(rec);
    render_history(f, app, bottom_chunks[0]);
    render_ping_frequency(f, app, bottom_chunks[1]);
}

/// Render the ping history for the final hop which is typically the target.
fn render_history<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let data = selected_hop
        .samples()
        .iter()
        .take(rect.width as usize)
        .map(|s| (s.as_secs_f64() * 1000_f64) as u64)
        .collect::<Vec<_>>();
    let history = Sparkline::default()
        .block(
            Block::default()
                .title(format!("Samples #{}", selected_hop.ttl()))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg_color)
                        .fg(app.tui_config.theme.text_color),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color)),
        )
        .data(&data)
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.samples_chart_color),
        );
    f.render_widget(history, rect);
}

/// Render a histogram of ping frequencies.
fn render_ping_frequency<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let target_hop = app.table_state.selected().map_or_else(
        || app.tracer_data().target_hop(),
        |s| &app.tracer_data().hops()[s],
    );
    let freq_data = sample_frequency(target_hop.samples());
    let freq_data_ref: Vec<_> = freq_data.iter().map(|(b, c)| (b.as_str(), *c)).collect();
    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(format!("Frequency #{}", target_hop.ttl()))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg_color)
                        .fg(app.tui_config.theme.text_color),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color)),
        )
        .data(freq_data_ref.as_slice())
        .bar_width(4)
        .bar_gap(1)
        .bar_style(Style::default().fg(app.tui_config.theme.frequency_chart_bar_color))
        .value_style(
            Style::default()
                .bg(app.tui_config.theme.frequency_chart_bar_color)
                .fg(app.tui_config.theme.frequency_chart_text_color)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(barchart, rect);
}

/// Render help dialog.
fn render_help<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp) {
    let block = Block::default()
        .title(" Default Controls ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg_color))
        .border_type(BorderType::Double);
    let control_spans: Vec<_> = HELP_LINES.iter().map(|&line| Spans::from(line)).collect();
    let control = Paragraph::new(control_spans)
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text_color))
        .block(block.clone())
        .alignment(Alignment::Left);
    let area = centered_rect(60, 60, f.size());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}

/// Render settings dialog.
fn render_settings<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp) {
    let all_settings = format_all_settings(app);
    let (name, info, items) = &all_settings[app.settings_tab_selected];
    let area = centered_rect(60, 60, f.size());
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(SETTINGS_TABLE_WIDTH.as_ref())
        .split(area);
    f.render_widget(Clear, area);
    render_settings_tabs(f, app, chunks[0]);
    render_settings_table(f, app, chunks[1], name, items);
    render_settings_info(f, app, chunks[2], info);
}

/// Render settings tabs.
fn render_settings_tabs<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let titles: Vec<_> = SETTINGS_TABS
        .iter()
        .map(|(title, _)| {
            Spans::from(Span::styled(
                *title,
                Style::default().fg(app.tui_config.theme.settings_tab_text_color),
            ))
        })
        .collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(" Settings ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg_color))
                .border_type(BorderType::Double),
        )
        .select(app.settings_tab_selected)
        .style(Style::default())
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(tabs, rect);
}

/// Render settings table.
fn render_settings_table<B: Backend>(
    f: &mut Frame<'_, B>,
    app: &mut TuiApp,
    rect: Rect,
    name: &str,
    items: &[SettingsItem],
) {
    let header_cells = SETTINGS_TABLE_HEADER.iter().map(|h| {
        Cell::from(*h)
            .style(Style::default().fg(app.tui_config.theme.settings_table_header_text_color))
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(app.tui_config.theme.settings_table_header_bg_color))
        .height(1)
        .bottom_margin(0);
    let rows = items.iter().map(|item| {
        Row::new(vec![Cell::from(item.item), Cell::from(item.value.as_str())])
            .style(Style::default().fg(app.tui_config.theme.settings_table_row_text_color))
    });
    let item_width = items
        .iter()
        .map(|item| item.item.len() as u16)
        .max()
        .unwrap_or_default()
        .max(30);
    let table_widths = [Constraint::Min(item_width), Constraint::Length(60)];
    let table = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .title(format!(" {name} "))
                .title_alignment(Alignment::Left)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg_color))
                .border_type(BorderType::Plain),
        )
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .widths(&table_widths);
    f.render_stateful_widget(table, rect, &mut app.setting_table_state);
}

/// Render settings info footer.
fn render_settings_info<B: Backend>(
    f: &mut Frame<'_, B>,
    app: &mut TuiApp,
    rect: Rect,
    info: &str,
) {
    let info = Paragraph::new(info)
        .style(Style::default())
        .block(
            Block::default()
                .title(" Info ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg_color))
                .border_type(BorderType::Plain),
        )
        .alignment(Alignment::Left);
    f.render_widget(info, rect);
}

struct SettingsItem {
    item: &'static str,
    value: String,
}

impl SettingsItem {
    pub fn new(item: &'static str, value: String) -> Self {
        Self { item, value }
    }
}

/// Format all settings.
fn format_all_settings(app: &TuiApp) -> Vec<(&'static str, &'static str, Vec<SettingsItem>)> {
    let tui_settings = format_tui_settings(app);
    let trace_settings = format_trace_settings(app);
    let dns_settings = format_dns_settings(app);
    let geoip_settings = format_geoip_settings(app);
    let bindings_settings = format_binding_settings(app);
    let theme_settings = format_theme_settings(app);
    vec![
        (
            "Tui",
            "Settings which control how data is displayed in this Tui",
            tui_settings,
        ),
        (
            "Trace",
            "Settings which control the tracing strategy",
            trace_settings,
        ),
        (
            "Dns",
            "Settings which control how DNS lookups are performed",
            dns_settings,
        ),
        ("GeoIp", "Settings relating to GeoIp", geoip_settings),
        ("Bindings", "Tui key bindings", bindings_settings),
        ("Theme", "Tui theme colors", theme_settings),
    ]
}

/// Format Tui settings.
fn format_tui_settings(app: &TuiApp) -> Vec<SettingsItem> {
    vec![
        SettingsItem::new("tui-max-samples", format!("{}", app.tui_config.max_samples)),
        SettingsItem::new(
            "tui-preserve-screen",
            format!("{}", app.tui_config.preserve_screen),
        ),
        SettingsItem::new(
            "tui-refresh-rate",
            format!("{}", format_duration(app.tui_config.refresh_rate)),
        ),
        SettingsItem::new(
            "tui-address-mode",
            format_address_mode(app.tui_config.address_mode),
        ),
        SettingsItem::new("tui-as-mode", format_as_mode(app.tui_config.as_mode)),
        SettingsItem::new(
            "tui-geoip-mode",
            format_geoip_mode(app.tui_config.geoip_mode),
        ),
        SettingsItem::new(
            "tui-max-addrs",
            app.tui_config
                .max_addrs
                .map_or_else(|| String::from("auto"), |m| m.to_string()),
        ),
    ]
}

/// Format trace settings.
fn format_trace_settings(app: &TuiApp) -> Vec<SettingsItem> {
    let cfg = app.tracer_config();
    let interface = if let Some(iface) = cfg.interface.as_deref() {
        iface.to_string()
    } else {
        "auto".to_string()
    };
    let (src_port, dst_port) = match cfg.port_direction {
        PortDirection::None => ("n/a".to_string(), "n/a".to_string()),
        PortDirection::FixedDest(dst) => ("auto".to_string(), format!("{}", dst.0)),
        PortDirection::FixedSrc(src) => (format!("{}", src.0), "auto".to_string()),
        PortDirection::FixedBoth(src, dst) => (format!("{}", src.0), format!("{}", dst.0)),
    };
    vec![
        SettingsItem::new("first-ttl", format!("{}", cfg.first_ttl)),
        SettingsItem::new("max-ttl", format!("{}", cfg.max_ttl)),
        SettingsItem::new(
            "min-round-duration",
            format!("{}", format_duration(cfg.min_round_duration)),
        ),
        SettingsItem::new(
            "max-round-duration",
            format!("{}", format_duration(cfg.max_round_duration)),
        ),
        SettingsItem::new(
            "grace-duration",
            format!("{}", format_duration(cfg.grace_duration)),
        ),
        SettingsItem::new("max-inflight", format!("{}", cfg.max_inflight)),
        SettingsItem::new("initial-sequence", format!("{}", cfg.initial_sequence)),
        SettingsItem::new(
            "read-timeout",
            format!("{}", format_duration(cfg.read_timeout)),
        ),
        SettingsItem::new("packet-size", format!("{}", cfg.packet_size)),
        SettingsItem::new("payload-pattern", format!("{}", cfg.payload_pattern)),
        SettingsItem::new("interface", interface),
        SettingsItem::new("multipath-strategy", cfg.multipath_strategy.to_string()),
        SettingsItem::new("target-port", dst_port),
        SettingsItem::new("source-port", src_port),
    ]
}

/// Format DNS settings.
fn format_dns_settings(app: &TuiApp) -> Vec<SettingsItem> {
    vec![
        SettingsItem::new(
            "dns-timeout",
            format!("{}", format_duration(app.resolver.config().timeout)),
        ),
        SettingsItem::new(
            "dns-resolve-method",
            format_dns_method(app.resolver.config().resolve_method),
        ),
        SettingsItem::new(
            "dns-lookup-as-info",
            format!("{}", app.tui_config.lookup_as_info),
        ),
    ]
}

/// Format `GeoIp` settings.
fn format_geoip_settings(app: &TuiApp) -> Vec<SettingsItem> {
    vec![SettingsItem::new(
        "geoip-mmdb-file",
        app.tracer_config()
            .geoip_mmdb_file
            .as_deref()
            .unwrap_or("none")
            .to_string(),
    )]
}

/// Format binding settings.
fn format_binding_settings(app: &TuiApp) -> Vec<SettingsItem> {
    let binds = &app.tui_config.bindings;
    vec![
        SettingsItem::new("toggle-help", format!("{}", binds.toggle_help)),
        SettingsItem::new("toggle-settings", format!("{}", binds.toggle_settings)),
        SettingsItem::new("next-hop", format!("{}", binds.next_hop)),
        SettingsItem::new("previous-hop", format!("{}", binds.previous_hop)),
        SettingsItem::new("next-trace", format!("{}", binds.next_trace)),
        SettingsItem::new("previous-trace", format!("{}", binds.previous_trace)),
        SettingsItem::new("next-hop-address", format!("{}", binds.next_hop_address)),
        SettingsItem::new(
            "previous-hop-address",
            format!("{}", binds.previous_hop_address),
        ),
        SettingsItem::new("address-mode-ip", format!("{}", binds.address_mode_ip)),
        SettingsItem::new("address-mode-host", format!("{}", binds.address_mode_host)),
        SettingsItem::new("address-mode-both", format!("{}", binds.address_mode_both)),
        SettingsItem::new("toggle-freeze", format!("{}", binds.toggle_freeze)),
        SettingsItem::new("toggle-chart", format!("{}", binds.toggle_chart)),
        SettingsItem::new("toggle-map", format!("{}", binds.toggle_map)),
        SettingsItem::new("expand-hosts", format!("{}", binds.expand_hosts)),
        SettingsItem::new("expand-hosts-max", format!("{}", binds.expand_hosts_max)),
        SettingsItem::new("contract-hosts", format!("{}", binds.contract_hosts)),
        SettingsItem::new(
            "contract-hosts-min",
            format!("{}", binds.contract_hosts_min),
        ),
        SettingsItem::new("chart-zoom-in", format!("{}", binds.chart_zoom_in)),
        SettingsItem::new("chart-zoom-out", format!("{}", binds.chart_zoom_out)),
        SettingsItem::new("clear-trace-data", format!("{}", binds.clear_trace_data)),
        SettingsItem::new("clear-dns-cache", format!("{}", binds.clear_dns_cache)),
        SettingsItem::new("clear-selection", format!("{}", binds.clear_selection)),
        SettingsItem::new("toggle-as-info", format!("{}", binds.toggle_as_info)),
        SettingsItem::new(
            "toggle-hop-details",
            format!("{}", binds.toggle_hop_details),
        ),
        SettingsItem::new("quit", format!("{}", binds.quit)),
    ]
}

/// Format theme settings.
fn format_theme_settings(app: &TuiApp) -> Vec<SettingsItem> {
    let theme = &app.tui_config.theme;
    vec![
        SettingsItem::new("bg-color", fmt_color(theme.bg_color)),
        SettingsItem::new("border-color", fmt_color(theme.border_color)),
        SettingsItem::new("text-color", fmt_color(theme.text_color)),
        SettingsItem::new("tab-text-color", fmt_color(theme.tab_text_color)),
        SettingsItem::new(
            "hops-table-header-bg-color",
            fmt_color(theme.hops_table_header_bg_color),
        ),
        SettingsItem::new(
            "hops-table-header-text-color",
            fmt_color(theme.hops_table_header_text_color),
        ),
        SettingsItem::new(
            "hops-table-row-active-text-color",
            fmt_color(theme.hops_table_row_active_text_color),
        ),
        SettingsItem::new(
            "hops-table-row-inactive-text-color",
            fmt_color(theme.hops_table_row_inactive_text_color),
        ),
        SettingsItem::new(
            "hops-chart-selected-color",
            fmt_color(theme.hops_chart_selected_color),
        ),
        SettingsItem::new(
            "hops-chart-unselected-color",
            fmt_color(theme.hops_chart_unselected_color),
        ),
        SettingsItem::new(
            "hops-chart-axis-color",
            fmt_color(theme.hops_chart_axis_color),
        ),
        SettingsItem::new(
            "frequency-chart-bar-color",
            fmt_color(theme.frequency_chart_bar_color),
        ),
        SettingsItem::new(
            "frequency-chart-text-color",
            fmt_color(theme.frequency_chart_text_color),
        ),
        SettingsItem::new("samples-chart-color ", fmt_color(theme.samples_chart_color)),
        SettingsItem::new(
            "help-dialog-bg-color",
            fmt_color(theme.help_dialog_bg_color),
        ),
        SettingsItem::new(
            "help-dialog-text-color",
            fmt_color(theme.help_dialog_text_color),
        ),
        SettingsItem::new(
            "settings-dialog-bg-color",
            fmt_color(theme.settings_dialog_bg_color),
        ),
        SettingsItem::new(
            "settings-tab-text-color",
            fmt_color(theme.settings_tab_text_color),
        ),
        SettingsItem::new(
            "settings-table-header-text-color",
            fmt_color(theme.settings_table_header_text_color),
        ),
        SettingsItem::new(
            "settings-table-header-bg-color",
            fmt_color(theme.settings_table_header_bg_color),
        ),
        SettingsItem::new(
            "settings-table-row-text-color",
            fmt_color(theme.settings_table_row_text_color),
        ),
    ]
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

/// Return the frequency % grouped by sample duration.
fn sample_frequency(samples: &[Duration]) -> Vec<(String, u64)> {
    let sample_count = samples.len();
    let mut count_by_duration: BTreeMap<u128, u64> = BTreeMap::new();
    for sample in samples {
        if sample.as_millis() > 0 {
            *count_by_duration.entry(sample.as_millis()).or_default() += 1;
        }
    }
    count_by_duration
        .iter()
        .map(|(ping, count)| {
            let ping = format!("{ping}");
            let freq_pct = ((*count as f64 / sample_count as f64) * 100_f64) as u64;
            (ping, freq_pct)
        })
        .collect()
}
