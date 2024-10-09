use crate::frontend::tui_app::TuiApp;
use crate::t;
use chrono::SecondsFormat;
use humantime::format_duration;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;
use trippy_core::{Hop, PortDirection, PrivilegeMode, Protocol};
use trippy_dns::{ResolveMethod, Resolver};

/// Render the title, config, target, clock and keyboard controls.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
    let now = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let clock_span = Line::from(Span::raw(now));
    let help_span = Line::from(vec![
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(t!("header_help")),
        Span::styled(" s", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(t!("header_settings")),
        Span::styled(" q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(t!("header_quit")),
    ]);
    let right_line = vec![clock_span, help_span];
    let right = Paragraph::new(right_line)
        .style(Style::default())
        .block(header_block.clone())
        .alignment(Alignment::Right);
    let protocol = match app.tracer_config().data.protocol() {
        Protocol::Icmp => format!(
            "{}({}, {})",
            t!("icmp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
        Protocol::Udp => format!(
            "{}({}, {}, {})",
            t!("udp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            app.tracer_config().data.multipath_strategy(),
            fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
        Protocol::Tcp => format!(
            "{}({}, {})",
            t!("tcp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
    };
    let details = if app.show_hop_details {
        String::from(t!("on"))
    } else {
        String::from(t!("off"))
    };
    let as_info = match app.resolver.config().resolve_method {
        ResolveMethod::System => String::from(t!("na")),
        ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
            if app.tui_config.lookup_as_info {
                String::from(t!("on"))
            } else {
                String::from(t!("off"))
            }
        }
    };
    let max_hosts = app
        .tui_config
        .max_addrs
        .map_or_else(|| String::from(t!("auto")), |m| m.to_string());
    let privacy = if app.tui_config.privacy {
        t!("on")
    } else {
        t!("off")
    };
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
                format!("{}: ", t!("config")),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{}={protocol} {}={as_info} {}={details} {}={max_hosts}, {}={privacy}",
                t!("protocol"),
                t!("as-info"),
                t!("details"),
                t!("max-hosts"),
                t!("privacy")
            )),
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

fn fmt_privilege_mode(privilege_mode: PrivilegeMode) -> Cow<'static, str> {
    match privilege_mode {
        PrivilegeMode::Privileged => t!("privileged"),
        PrivilegeMode::Unprivileged => t!("unprivileged"),
    }
}

const fn fmt_target_family(target: IpAddr) -> &'static str {
    match target {
        IpAddr::V4(_) => "v4",
        IpAddr::V6(_) => "v6",
    }
}

/// Render the source address of the trace.
fn render_source(app: &TuiApp) -> String {
    if let Some(src_addr) = app.tracer_config().data.source_addr() {
        let src_hostname = app.resolver.lazy_reverse_lookup(src_addr);
        match app.tracer_config().data.port_direction() {
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
    } else {
        String::from(t!("unknown"))
    }
}

/// Render the destination address.
fn render_destination(app: &TuiApp) -> String {
    let dest_hostname = &app.tracer_config().target_hostname;
    let dest_addr = app.tracer_config().data.target_addr();
    match app.tracer_config().data.port_direction() {
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
