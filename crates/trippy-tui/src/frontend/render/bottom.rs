use crate::config::AddressMode;
use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::{Alignment, Rect};
use ratatui::prelude::{Color, Line, Modifier, Span, Style};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::borrow::Cow;
use std::net::IpAddr;
use trippy_core::{PrivilegeMode, Protocol};
use trippy_dns::ResolveMethod;

pub fn render(f: &mut Frame<'_>, rect: Rect, app: &TuiApp) {
    let footer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        );

    let protocol = match app.tracer_config().data.protocol() {
        Protocol::Icmp => format!(
            " {}/{} ",
            t!("icmp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            // fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
        Protocol::Udp => format!(
            " {}/{}/{} ",
            t!("udp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            app.tracer_config().data.multipath_strategy(),
            // fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
        Protocol::Tcp => format!(
            " {}/{} ",
            t!("tcp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            // fmt_privilege_mode(app.tracer_config().data.privilege_mode())
        ),
    };

    let privilige_mode = fmt_privilege_mode(app.tracer_config().data.privilege_mode());

    let as_mode = match app.resolver.config().resolve_method {
        ResolveMethod::System => Span::styled("asn", Style::default()),
        ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
            if app.tui_config.lookup_as_info {
                Span::styled(
                    "asn",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("asn", Style::default())
            }
        }
    };

    let details = if app.show_hop_details {
        Span::styled(
            "detail",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("detail", Style::default())
    };

    // needs to be padded to length of translation of "auto".
    let max_hosts = app
        .tui_config
        .max_addrs
        .map_or_else(|| Span::raw(t!("auto")), |m| Span::raw(format!("{m:4}")));

    let privacy = if app.hide_private_hops && app.tui_config.privacy_max_ttl > 0 {
        Span::styled(
            "private",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("private", Style::default())
    };

    let address_mode = match app.tui_config.address_mode {
        AddressMode::Ip => Span::styled(" ip ", Style::default()),
        AddressMode::Host => Span::styled("host", Style::default()),
        AddressMode::Both => Span::styled("both", Style::default()),
    };

    let left_line = Line::from(vec![
        Span::raw(protocol),
        Span::raw("│ "),
        Span::raw(privilige_mode),
        Span::raw(" │ ["),
        as_mode,
        Span::raw("] │ ["),
        details,
        Span::raw("] │ ["),
        privacy,
        Span::raw("] │"),
    ]);

    let right_line = Line::from(vec![
        Span::raw("│ "),
        address_mode,
        Span::raw(" │ "),
        max_hosts,
        Span::raw(" "),
    ]);

    let left = Paragraph::new(left_line)
        .style(Style::default())
        .block(footer_block.clone())
        .alignment(Alignment::Left);
    let right = Paragraph::new(right_line)
        .style(Style::default())
        .block(footer_block.clone())
        .alignment(Alignment::Right);

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
