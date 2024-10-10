use crate::frontend::tui_app::TuiApp;
use crate::t;
use itertools::Itertools;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::prelude::Line;
use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use ratatui::text::Span;
use ratatui::widgets::canvas::{Canvas, Circle, Context, Map, MapResolution, Rectangle};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;
use std::collections::HashMap;
use trippy_core::Hop;

/// Render the `GeoIp` map.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let entries = build_map_entries(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(MAP_LAYOUT)
        .split(rect);
    let info_rect = chunks[1].inner(Margin {
        vertical: 0,
        horizontal: 16,
    });
    render_map_canvas(f, app, rect, &entries);
    render_map_info_panel(f, app, info_rect, &entries);
}

/// Render the map canvas.
fn render_map_canvas(f: &mut Frame<'_>, app: &TuiApp, rect: Rect, entries: &[MapEntry]) {
    let theme = app.tui_config.theme;
    let map = Canvas::default()
        .background_color(app.tui_config.theme.bg)
        .block(
            Block::default()
                .title(Line::raw(t!("title_map")))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.tui_config.theme.border))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg)
                        .fg(app.tui_config.theme.text),
                ),
        )
        .paint(|ctx| {
            render_map_canvas_world(ctx, theme.map_world);
            ctx.layer();
            for entry in entries {
                let any_show = entry
                    .hops
                    .iter()
                    .any(|hop| *hop > app.tui_config.privacy_max_ttl);
                if !app.tui_config.privacy || any_show {
                    render_map_canvas_pin(ctx, entry);
                    render_map_canvas_radius(ctx, entry, theme.map_radius);
                    render_map_canvas_selected(
                        ctx,
                        entry,
                        app.selected_hop_or_target(),
                        theme.map_selected,
                    );
                }
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
        let circle_widget = Circle {
            x: *longitude,
            y: *latitude,
            radius: radius_degrees,
            color,
        };
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
fn render_map_info_panel(f: &mut Frame<'_>, app: &TuiApp, rect: Rect, entries: &[MapEntry]) {
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
    let info = if app.tui_config.privacy && app.tui_config.privacy_max_ttl >= selected_hop.ttl() {
        format!("**{}**", t!("hidden"))
    } else {
        match locations.as_slice() {
            _ if app.tui_config.geoip_mmdb_file.is_none() => t!("geoip_not_enabled").to_string(),
            [] if selected_hop.addr_count() > 0 => format!(
                "{} {} ({})",
                t!("geoip_no_data_for_hop"),
                selected_hop.ttl(),
                selected_hop.addrs().join(", ")
            ),
            [] => format!("{} {}", t!("geoip_no_data_for_hop"), selected_hop.ttl()),
            [loc] => loc.to_string(),
            _ => format!(
                "{} {}",
                t!("geoip_multiple_data_for_hop"),
                selected_hop.ttl()
            ),
        }
    };
    let info_panel = Paragraph::new(info)
        .block(
            Block::default()
                .title(format!("{} {}", t!("hop"), selected_hop.ttl()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.map_info_panel_border))
                .style(
                    Style::default()
                        .bg(theme.map_info_panel_bg)
                        .fg(theme.map_info_panel_text),
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
fn build_map_entries(app: &TuiApp) -> Vec<MapEntry> {
    let mut geo_map: HashMap<String, MapEntry> = HashMap::new();
    for hop in app.tracer_data().hops_for_flow(app.selected_flow) {
        for addr in hop.addrs() {
            if let Some(geo) = app.geoip_lookup.lookup(*addr).unwrap_or_default() {
                if let Some((latitude, longitude, radius)) = geo.coordinates() {
                    let entry = geo_map.entry(geo.long_name()).or_insert(MapEntry {
                        long_name: geo.long_name(),
                        location: format!("{latitude}, {longitude} ~{radius}{}", t!("kilometer")),
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

const MAP_LAYOUT: [Constraint; 3] = [
    Constraint::Min(1),
    Constraint::Length(3),
    Constraint::Length(1),
];
