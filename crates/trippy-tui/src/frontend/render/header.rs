use crate::frontend::tui_app::TuiApp;
use crate::t;
use chrono::SecondsFormat;
use humantime::format_duration;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use trippy_core::{Hop, PortDirection};
use trippy_dns::Resolver;

/// Render the title, target, clock and basic keyboard controls.
#[expect(clippy::too_many_lines)]
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let header_block = Block::default()
        .title(format!(" {} v{} ", t!("trippy"), clap::crate_version!()))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        );
    let now = if let Some(tz) = &app.tui_config.timezone {
        chrono::Utc::now()
            .with_timezone(tz)
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    } else {
        chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    };
    let clock_span = Line::from(Span::raw(now));
    let bold = Style::default().add_modifier(Modifier::BOLD);

    let help_binding = app.tui_config.bindings.toggle_help.to_string();
    let header_help = t!("header_help");
    let help_line_help = if header_help.starts_with(&help_binding) {
        vec![
            Span::styled(&help_binding, bold),
            Span::raw(&header_help[help_binding.len()..]),
        ]
    } else {
        vec![
            Span::raw("["),
            Span::styled(help_binding, bold),
            Span::raw("]"),
            Span::raw(header_help),
        ]
    };

    let settings_binding = app.tui_config.bindings.toggle_settings.to_string();
    let header_settings = t!("header_settings");
    let help_line_settings = if header_settings.starts_with(&settings_binding) {
        vec![
            Span::styled(&settings_binding, bold),
            Span::raw(&header_settings[settings_binding.len()..]),
        ]
    } else {
        vec![
            Span::raw("["),
            Span::styled(settings_binding, bold),
            Span::raw("]"),
            Span::raw(header_settings),
        ]
    };

    let quit_binding = app.tui_config.bindings.quit.to_string();
    let header_quit = t!("header_quit");
    let help_line_quit = if header_quit.starts_with(&quit_binding) {
        vec![
            Span::styled(&quit_binding, bold),
            Span::raw(&header_quit[quit_binding.len()..]),
        ]
    } else {
        vec![
            Span::raw("["),
            Span::styled(quit_binding, bold),
            Span::raw("]"),
            Span::raw(header_quit),
        ]
    };

    let help_span = Line::from(
        [
            help_line_help,
            vec![Span::raw(" ")],
            help_line_settings,
            vec![Span::raw(" ")],
            help_line_quit,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>(),
    );
    let right_line = vec![clock_span, help_span];
    let right = Paragraph::new(right_line)
        .style(Style::default())
        .block(header_block.clone())
        .alignment(Alignment::Right);

    let source = render_source(app);
    let dest = render_destination(app);
    let target = format!("{source} -> {dest}");
    let hop_count = app.tracer_data().hops_for_flow(app.selected_flow).len();
    let discovered = if app.selected_tracer_data.max_flows() > 1 {
        let plural_flows = if app.tracer_data().flows().len() > 1 {
            t!("flows")
        } else {
            t!("flow")
        };
        let flow_count = app.tracer_data().flows().len();
        format!(
            ", {}",
            t!("discovered_flows",
                "hop_count" => hop_count,
                "flow_count" => flow_count,
                "plural_flows" => plural_flows
            )
        )
    } else {
        format!(", {}", t!("discovered", "hop_count" => hop_count))
    };
    let left_line = vec![
        Line::from(vec![
            Span::styled(
                format!("{}: ", t!("target")),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(target),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{}: ", t!("status")),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(render_status(app)),
            Span::raw(discovered),
        ]),
    ];

    let left = Paragraph::new(left_line)
        .style(Style::default())
        .block(header_block)
        .alignment(Alignment::Left);
    f.render_widget(right, rect);
    f.render_widget(left, rect);
}

/// Render the source address of the trace.
fn render_source(app: &TuiApp) -> String {
    fn format_ip(app: &TuiApp, src_addr: IpAddr) -> String {
        match app.tracer_config().data.port_direction() {
            PortDirection::None => {
                format!("{src_addr}")
            }
            PortDirection::FixedDest(_) => {
                format!("{src_addr}:*")
            }
            PortDirection::FixedSrc(src) | PortDirection::FixedBoth(src, _) => {
                format!("{src_addr}:{}", src.0)
            }
        }
    }
    fn format_both(app: &TuiApp, src_hostname: &str, src_addr: IpAddr) -> String {
        match app.tracer_config().data.port_direction() {
            PortDirection::None => {
                format!("{src_addr} ({src_hostname})")
            }
            PortDirection::FixedDest(_) => {
                format!("{src_addr}:* ({src_hostname})")
            }
            PortDirection::FixedSrc(src) | PortDirection::FixedBoth(src, _) => {
                format!("{src_addr}:{} ({src_hostname})", src.0)
            }
        }
    }
    if app.tui_config.privacy_max_ttl.is_some() {
        format!("**{}**", t!("hidden"))
    } else if let Some(addr) = app.tracer_config().data.source_addr() {
        let entry = app.resolver.lazy_reverse_lookup_with_asinfo(addr);
        if let Some(hostname) = entry.hostnames().next() {
            format_both(app, hostname, addr)
        } else {
            format_ip(app, addr)
        }
    } else {
        String::from(t!("unknown"))
    }
}

/// Render the destination address.
fn render_destination(app: &TuiApp) -> String {
    fn format_ip(app: &TuiApp, dest_addr: IpAddr) -> String {
        match app.tracer_config().data.port_direction() {
            PortDirection::None => {
                format!("{dest_addr}")
            }
            PortDirection::FixedSrc(_) => {
                format!("{dest_addr}:*")
            }
            PortDirection::FixedDest(dest) | PortDirection::FixedBoth(_, dest) => {
                format!("{dest_addr}:{}", dest.0)
            }
        }
    }
    fn format_both(app: &TuiApp, dest_hostname: &str, dest_addr: IpAddr) -> String {
        match app.tracer_config().data.port_direction() {
            PortDirection::None => {
                format!("{dest_addr} ({dest_hostname})")
            }
            PortDirection::FixedSrc(_) => {
                format!("{dest_addr}:* ({dest_hostname})")
            }
            PortDirection::FixedDest(dest) | PortDirection::FixedBoth(_, dest) => {
                format!("{dest_addr}:{} ({dest_hostname})", dest.0)
            }
        }
    }
    let dest_addr = app.tracer_config().data.target_addr();
    let target_hostname = &app.tracer_config().target_hostname;
    if let Ok(addr) = IpAddr::from_str(target_hostname) {
        let entry = app.resolver.lazy_reverse_lookup_with_asinfo(addr);
        let hostname = entry.hostnames().next().unwrap_or_else(|| target_hostname);
        if hostname == target_hostname {
            format_ip(app, addr)
        } else {
            format_both(app, hostname, addr)
        }
    } else {
        format_both(app, target_hostname, dest_addr)
    }
}

/// Render the headline status of the tracing.
fn render_status(app: &TuiApp) -> String {
    let failure_count: usize = app
        .tracer_data()
        .hops_for_flow(app.selected_flow)
        .iter()
        .map(Hop::total_failed)
        .sum();
    let failures = if failure_count > 0 {
        let total_probes: usize = app
            .tracer_data()
            .hops_for_flow(app.selected_flow)
            .iter()
            .map(Hop::total_sent)
            .sum();
        let failure_rate = if total_probes > 0 {
            (failure_count as f64 / total_probes as f64) * 100.0
        } else {
            0_f64
        };
        let failure_rate = format!("{failure_rate:.1}");
        format!(
            " [{}❗]",
            t!("status_failures",
                    "failure_count" => failure_count,
                    "total_probes" => total_probes,
                    "failure_rate" => failure_rate)
        )
    } else {
        String::new()
    };
    if app.selected_tracer_data.error().is_some() {
        String::from(t!("status_failed"))
    } else if let Some(start) = app.frozen_start {
        let frozen = format_duration(Duration::from_secs(
            start.elapsed().unwrap_or_default().as_secs(),
        ));
        format!("{} ({frozen}){failures}", t!("status_frozen"))
    } else {
        format!("{}{failures}", t!("status_running"))
    }
}
