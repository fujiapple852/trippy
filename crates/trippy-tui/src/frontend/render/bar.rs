use crate::config::AddressMode;
use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::{Alignment, Rect};
use ratatui::prelude::{Line, Span, Style};
use ratatui::style::Stylize;
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::borrow::Cow;
use std::net::IpAddr;
use trippy_core::{PrivilegeMode, Protocol};
use trippy_dns::ResolveMethod;

pub fn render(f: &mut Frame<'_>, rect: Rect, app: &TuiApp) {
    let protocol = match app.tracer_config().data.protocol() {
        Protocol::Icmp => format!(
            "{}/{}",
            t!("icmp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
        ),
        Protocol::Udp => format!(
            "{}/{}/{}",
            t!("udp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
            app.tracer_config().data.multipath_strategy(),
        ),
        Protocol::Tcp => format!(
            "{}/{}",
            t!("tcp"),
            fmt_target_family(app.tracer_config().data.target_addr()),
        ),
    };

    let privilege_mode = fmt_privilege_mode(app.tracer_config().data.privilege_mode());

    let as_mode = match app.resolver.config().resolve_method {
        ResolveMethod::System => Span::styled("✖asn", Style::default().dim()),
        ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
            if app.tui_config.lookup_as_info {
                Span::styled("✓asn", Style::default())
            } else {
                Span::styled("✖asn", Style::default().dim())
            }
        }
    };

    let details = if app.show_hop_details {
        Span::styled(format!("✓{}", t!("details")), Style::default())
    } else {
        Span::styled(format!("✖{}", t!("details")), Style::default().dim())
    };

    let auto = t!("auto");
    let width = auto.len();
    let max_hosts = app
        .tui_config
        .max_addrs
        .map_or_else(|| Span::raw(auto), |m| Span::raw(format!("{m:width$}")));

    let privacy = if app.tui_config.privacy_max_ttl > 0 {
        Span::styled(format!("✓{}", t!("privacy")), Style::default())
    } else {
        Span::styled(format!("✖{}", t!("privacy")), Style::default().dim())
    };

    let address_mode = match app.tui_config.address_mode {
        AddressMode::Ip => Span::styled(" ip ", Style::default()),
        AddressMode::Host => Span::styled("host", Style::default()),
        AddressMode::Both => Span::styled("both", Style::default()),
    };

    let left_line = Line::from(vec![
        Span::raw(" ["),
        Span::raw(protocol),
        Span::raw("] ["),
        Span::raw(privilege_mode),
        Span::raw("] ["),
        as_mode,
        Span::raw("] ["),
        details,
        Span::raw("] ["),
        privacy,
        Span::raw("]"),
    ]);

    let right_line = Line::from(vec![
        Span::raw(" ["),
        address_mode,
        Span::raw("] ["),
        max_hosts,
        Span::raw("] "),
    ]);

    let bar_style = Style::default()
        .bg(app.tui_config.theme.dynamic_bar_bg)
        .fg(app.tui_config.theme.dynamic_bar_text);
    let left = Paragraph::new(left_line)
        .style(bar_style)
        .alignment(Alignment::Left);
    let right = Paragraph::new(right_line)
        .style(bar_style)
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
