use crate::config::{AddressMode, AsMode, GeoIpMode, IcmpExtensionMode};
use crate::frontend::render::util;
use crate::frontend::theme;
use crate::frontend::tui_app::TuiApp;
use humantime::format_duration;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap,
};
use ratatui::Frame;
use trippy_core::PortDirection;
use trippy_dns::ResolveMethod;

/// Render settings dialog.
pub fn render(f: &mut Frame<'_>, app: &mut TuiApp) {
    let all_settings = format_all_settings(app);
    let (name, info, items) = &all_settings[app.settings_tab_selected];
    let area = util::centered_rect(60, 60, f.area());
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
fn render_settings_tabs(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let titles: Vec<_> = SETTINGS_TABS
        .iter()
        .map(|(title, _)| {
            Line::from(Span::styled(
                *title,
                Style::default().fg(app.tui_config.theme.settings_tab_text),
            ))
        })
        .collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(" Settings ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg))
                .border_type(BorderType::Double),
        )
        .select(app.settings_tab_selected)
        .style(Style::default())
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(tabs, rect);
}

/// Render settings table.
fn render_settings_table(
    f: &mut Frame<'_>,
    app: &mut TuiApp,
    rect: Rect,
    name: &str,
    items: &[SettingsItem],
) {
    let header_cells = SETTINGS_TABLE_HEADER.iter().map(|h| {
        Cell::from(*h).style(Style::default().fg(app.tui_config.theme.settings_table_header_text))
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(app.tui_config.theme.settings_table_header_bg))
        .height(1)
        .bottom_margin(0);
    let rows = items.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.item.as_str()),
            Cell::from(item.value.as_str()),
        ])
        .style(Style::default().fg(app.tui_config.theme.settings_table_row_text))
    });
    let item_width = items
        .iter()
        .map(|item| item.item.len() as u16)
        .max()
        .unwrap_or_default()
        .max(30);
    let table_widths = [Constraint::Min(item_width), Constraint::Length(60)];
    let table = Table::new(rows, table_widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" {name} "))
                .title_alignment(Alignment::Left)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg))
                .border_type(BorderType::Plain),
        )
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, rect, &mut app.setting_table_state);
}

/// Render settings info footer.
fn render_settings_info(f: &mut Frame<'_>, app: &TuiApp, rect: Rect, info: &str) {
    let info = Paragraph::new(info)
        .style(Style::default())
        .wrap(Wrap::default())
        .block(
            Block::default()
                .title(" Info ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .style(Style::default().bg(app.tui_config.theme.settings_dialog_bg))
                .border_type(BorderType::Plain),
        )
        .alignment(Alignment::Left);
    f.render_widget(info, rect);
}

/// Format all settings.
fn format_all_settings(app: &TuiApp) -> Vec<(&'static str, String, Vec<SettingsItem>)> {
    let tui_settings = format_tui_settings(app);
    let trace_settings = format_trace_settings(app);
    let dns_settings = format_dns_settings(app);
    let geoip_settings = format_geoip_settings(app);
    let bindings_settings = format_binding_settings(app);
    let theme_settings = format_theme_settings(app);
    let columns_settings = format_columns_settings(app);
    let toggle_column = app.tui_config.bindings.toggle_chart.to_string();
    let move_down = app.tui_config.bindings.next_hop_address.to_string();
    let move_up = app.tui_config.bindings.previous_hop_address.to_string();
    vec![
        (
            "Tui",
            String::from("Settings which control how data is displayed in this Tui"),
            tui_settings,
        ),
        (
            "Trace",
            String::from("Settings which control the tracing strategy"),
            trace_settings,
        ),
        (
            "Dns",
            String::from("Settings which control how DNS lookups are performed"),
            dns_settings,
        ),
        ("GeoIp", String::from("Settings relating to GeoIp"), geoip_settings),
        ("Bindings", String::from("Tui key bindings"), bindings_settings),
        ("Theme", String::from("Tui theme colors"), theme_settings),
        (
            "Columns",
            format!("Tui table columns.  Press [{toggle_column}] to toggle a column on or off and use the [{move_down}] and [{move_up}] keys to change the column order."),
            columns_settings,
        ),
    ]
}

/// Format Tui settings.
fn format_tui_settings(app: &TuiApp) -> Vec<SettingsItem> {
    vec![
        SettingsItem::new(
            "tui-preserve-screen",
            format!("{}", app.tui_config.preserve_screen),
        ),
        SettingsItem::new(
            "tui-refresh-rate",
            format!("{}", format_duration(app.tui_config.refresh_rate)),
        ),
        SettingsItem::new(
            "tui-privacy-max-ttl",
            format!("{}", app.tui_config.privacy_max_ttl),
        ),
        SettingsItem::new(
            "tui-address-mode",
            format_address_mode(app.tui_config.address_mode),
        ),
        SettingsItem::new("tui-as-mode", format_as_mode(app.tui_config.as_mode)),
        SettingsItem::new(
            "tui-icmp-extension-mode",
            format_extension_mode(app.tui_config.icmp_extension_mode),
        ),
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
        SettingsItem::new(
            "tui-custom-columns",
            format!("{}", app.tui_config.tui_columns),
        ),
    ]
}

/// Format trace settings.
fn format_trace_settings(app: &TuiApp) -> Vec<SettingsItem> {
    let cfg = app.tracer_config();
    let interface = if let Some(iface) = cfg.data.interface() {
        iface.to_string()
    } else {
        "auto".to_string()
    };
    let (src_port, dst_port) = match cfg.data.port_direction() {
        PortDirection::None => ("n/a".to_string(), "n/a".to_string()),
        PortDirection::FixedDest(dst) => ("auto".to_string(), format!("{}", dst.0)),
        PortDirection::FixedSrc(src) => (format!("{}", src.0), "auto".to_string()),
        PortDirection::FixedBoth(src, dst) => (format!("{}", src.0), format!("{}", dst.0)),
    };
    vec![
        SettingsItem::new("first-ttl", format!("{}", cfg.data.first_ttl().0)),
        SettingsItem::new("max-ttl", format!("{}", cfg.data.max_ttl().0)),
        SettingsItem::new(
            "min-round-duration",
            format!("{}", format_duration(cfg.data.min_round_duration())),
        ),
        SettingsItem::new(
            "max-round-duration",
            format!("{}", format_duration(cfg.data.max_round_duration())),
        ),
        SettingsItem::new(
            "grace-duration",
            format!("{}", format_duration(cfg.data.grace_duration())),
        ),
        SettingsItem::new("max-inflight", format!("{}", cfg.data.max_inflight().0)),
        SettingsItem::new(
            "initial-sequence",
            format!("{}", cfg.data.initial_sequence().0),
        ),
        SettingsItem::new(
            "read-timeout",
            format!("{}", format_duration(cfg.data.read_timeout())),
        ),
        SettingsItem::new("packet-size", format!("{}", cfg.data.packet_size().0)),
        SettingsItem::new(
            "payload-pattern",
            format!("{}", cfg.data.payload_pattern().0),
        ),
        SettingsItem::new(
            "icmp-extensions",
            format!("{}", cfg.data.icmp_extension_parse_mode()),
        ),
        SettingsItem::new("interface", interface),
        SettingsItem::new(
            "multipath-strategy",
            cfg.data.multipath_strategy().to_string(),
        ),
        SettingsItem::new("target-port", dst_port),
        SettingsItem::new("source-port", src_port),
        SettingsItem::new(
            "max-samples",
            format!("{}", app.selected_tracer_data.max_samples()),
        ),
        SettingsItem::new(
            "max-flows",
            format!("{}", app.selected_tracer_data.max_flows()),
        ),
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
            "dns-ttl",
            format!("{}", format_duration(app.resolver.config().ttl)),
        ),
        SettingsItem::new(
            "dns-resolve-method",
            format_dns_method(app.resolver.config().resolve_method),
        ),
        SettingsItem::new(
            "dns-resolve-all",
            format!("{}", app.tui_config.dns_resolve_all),
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
        app.tui_config
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
        SettingsItem::new("toggle-help-alt", format!("{}", binds.toggle_help_alt)),
        SettingsItem::new("toggle-settings", format!("{}", binds.toggle_settings)),
        SettingsItem::new(
            "toggle-settings-tui",
            format!("{}", binds.toggle_settings_tui),
        ),
        SettingsItem::new(
            "toggle-settings-trace",
            format!("{}", binds.toggle_settings_trace),
        ),
        SettingsItem::new(
            "toggle-settings-dns",
            format!("{}", binds.toggle_settings_dns),
        ),
        SettingsItem::new(
            "toggle-settings-geoip",
            format!("{}", binds.toggle_settings_geoip),
        ),
        SettingsItem::new(
            "toggle-settings-bindings",
            format!("{}", binds.toggle_settings_bindings),
        ),
        SettingsItem::new(
            "toggle-settings-theme",
            format!("{}", binds.toggle_settings_theme),
        ),
        SettingsItem::new(
            "toggle-settings-columns",
            format!("{}", binds.toggle_settings_columns),
        ),
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
        SettingsItem::new("toggle-flows", format!("{}", binds.toggle_flows)),
        SettingsItem::new("toggle-privacy", format!("{}", binds.toggle_privacy)),
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
#[allow(clippy::too_many_lines)]
fn format_theme_settings(app: &TuiApp) -> Vec<SettingsItem> {
    let theme = &app.tui_config.theme;
    vec![
        SettingsItem::new("bg-color", theme::fmt_color(theme.bg)),
        SettingsItem::new("border-color", theme::fmt_color(theme.border)),
        SettingsItem::new("text-color", theme::fmt_color(theme.text)),
        SettingsItem::new("tab-text-color", theme::fmt_color(theme.tab_text)),
        SettingsItem::new(
            "hops-table-header-bg-color",
            theme::fmt_color(theme.hops_table_header_bg),
        ),
        SettingsItem::new(
            "hops-table-header-text-color",
            theme::fmt_color(theme.hops_table_header_text),
        ),
        SettingsItem::new(
            "hops-table-row-active-text-color",
            theme::fmt_color(theme.hops_table_row_active_text),
        ),
        SettingsItem::new(
            "hops-table-row-inactive-text-color",
            theme::fmt_color(theme.hops_table_row_inactive_text),
        ),
        SettingsItem::new(
            "hops-chart-selected-color",
            theme::fmt_color(theme.hops_chart_selected),
        ),
        SettingsItem::new(
            "hops-chart-unselected-color",
            theme::fmt_color(theme.hops_chart_unselected),
        ),
        SettingsItem::new(
            "hops-chart-axis-color",
            theme::fmt_color(theme.hops_chart_axis),
        ),
        SettingsItem::new(
            "frequency-chart-bar-color",
            theme::fmt_color(theme.frequency_chart_bar),
        ),
        SettingsItem::new(
            "frequency-chart-text-color",
            theme::fmt_color(theme.frequency_chart_text),
        ),
        SettingsItem::new(
            "flows-chart-bar-selected-color",
            theme::fmt_color(theme.flows_chart_bar_selected),
        ),
        SettingsItem::new(
            "flows-chart-bar-unselected-color",
            theme::fmt_color(theme.flows_chart_bar_unselected),
        ),
        SettingsItem::new(
            "flows-chart-text-current-color",
            theme::fmt_color(theme.flows_chart_text_current),
        ),
        SettingsItem::new(
            "flows-chart-text-non-current-color",
            theme::fmt_color(theme.flows_chart_text_non_current),
        ),
        SettingsItem::new(
            "samples-chart-color ",
            theme::fmt_color(theme.samples_chart),
        ),
        SettingsItem::new(
            "help-dialog-bg-color",
            theme::fmt_color(theme.help_dialog_bg),
        ),
        SettingsItem::new(
            "help-dialog-text-color",
            theme::fmt_color(theme.help_dialog_text),
        ),
        SettingsItem::new(
            "settings-dialog-bg-color",
            theme::fmt_color(theme.settings_dialog_bg),
        ),
        SettingsItem::new(
            "settings-tab-text-color",
            theme::fmt_color(theme.settings_tab_text),
        ),
        SettingsItem::new(
            "settings-table-header-text-color",
            theme::fmt_color(theme.settings_table_header_text),
        ),
        SettingsItem::new(
            "settings-table-header-bg-color",
            theme::fmt_color(theme.settings_table_header_bg),
        ),
        SettingsItem::new(
            "settings-table-row-text-color",
            theme::fmt_color(theme.settings_table_row_text),
        ),
        SettingsItem::new("map-world-color", theme::fmt_color(theme.map_world)),
        SettingsItem::new("map-radius-color", theme::fmt_color(theme.map_radius)),
        SettingsItem::new("map-selected-color", theme::fmt_color(theme.map_selected)),
        SettingsItem::new(
            "map-info-panel-border-color",
            theme::fmt_color(theme.map_info_panel_border),
        ),
        SettingsItem::new(
            "map-info-panel-bg-color",
            theme::fmt_color(theme.map_info_panel_bg),
        ),
        SettingsItem::new(
            "map-info-panel-text-color",
            theme::fmt_color(theme.map_info_panel_text),
        ),
    ]
}

/// Format columns settings.
fn format_columns_settings(app: &TuiApp) -> Vec<SettingsItem> {
    app.tui_config
        .tui_columns
        .all_columns()
        .map(|c| SettingsItem::new(c.typ.to_string(), c.status.to_string()))
        .collect()
}

pub const SETTINGS_TAB_COLUMNS: usize = 6;

/// The name and number of items for each tabs in the setting dialog.
pub const SETTINGS_TABS: [(&str, usize); 7] = [
    ("Tui", 9),
    ("Trace", 17),
    ("Dns", 5),
    ("GeoIp", 1),
    ("Bindings", 36),
    ("Theme", 31),
    ("Columns", 0),
];

/// The settings table header.
const SETTINGS_TABLE_HEADER: [&str; 2] = ["Setting", "Value"];

const SETTINGS_TABLE_WIDTH: [Constraint; 3] = [
    Constraint::Length(3),
    Constraint::Min(1),
    Constraint::Length(4),
];

struct SettingsItem {
    item: String,
    value: String,
}

impl SettingsItem {
    pub fn new(item: impl Into<String>, value: String) -> Self {
        Self {
            item: item.into(),
            value,
        }
    }
}

/// Format the `DnsResolveMethod`.
fn format_dns_method(resolve_method: ResolveMethod) -> String {
    match resolve_method {
        ResolveMethod::System => String::from("system"),
        ResolveMethod::Resolv => String::from("resolv"),
        ResolveMethod::Google => String::from("google"),
        ResolveMethod::Cloudflare => String::from("cloudflare"),
    }
}

fn format_extension_mode(icmp_extension_mode: IcmpExtensionMode) -> String {
    match icmp_extension_mode {
        IcmpExtensionMode::Off => "off".to_string(),
        IcmpExtensionMode::Mpls => "mpls".to_string(),
        IcmpExtensionMode::Full => "full".to_string(),
        IcmpExtensionMode::All => "all".to_string(),
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
