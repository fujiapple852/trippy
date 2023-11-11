use crate::frontend::tui_app::TuiApp;
use chrono::SecondsFormat;
use humantime::format_duration;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::time::Duration;
use trippy::dns::{ResolveMethod, Resolver};
use trippy::tracing::{PortDirection, TracerProtocol};

/// Render the title, config, target, clock and keyboard controls.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
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
    let clock_span = Line::from(Span::raw(now));
    let help_span = Line::from(vec![
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("elp "),
        Span::styled("s", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("ettings "),
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("uit"),
    ]);
    let right_line = vec![clock_span, help_span];
    let right = Paragraph::new(right_line)
        .style(Style::default())
        .block(header_block.clone())
        .alignment(Alignment::Right);
    let protocol = match app.tracer_config().protocol {
        TracerProtocol::Icmp => format!(
            "icmp({}, {})",
            app.tracer_config().addr_family,
            app.tracer_config().privilege_mode
        ),
        TracerProtocol::Udp => format!(
            "udp({}, {}, {})",
            app.tracer_config().addr_family,
            app.tracer_config().multipath_strategy,
            app.tracer_config().privilege_mode
        ),
        TracerProtocol::Tcp => format!(
            "tcp({}, {})",
            app.tracer_config().addr_family,
            app.tracer_config().privilege_mode
        ),
    };
    let details = if app.show_hop_details {
        String::from("on")
    } else {
        String::from("off")
    };
    let as_info = match app.resolver.config().resolve_method {
        ResolveMethod::System => String::from("n/a"),
        ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
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
    let left_line = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(target),
        ]),
        Line::from(vec![
            Span::styled("Config: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "protocol={protocol} as-info={as_info} details={details} max-hosts={max_hosts}"
            )),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(render_status(app)),
            Span::raw(format!(
                ", discovered {} hops",
                app.tracer_data().hops(app.selected_flow).len()
            )),
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
    let src_hostname = app
        .resolver
        .lazy_reverse_lookup(app.tracer_config().source_addr);
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
fn render_destination(app: &TuiApp) -> String {
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
