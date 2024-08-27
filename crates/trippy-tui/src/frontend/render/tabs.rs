use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Tabs};
use ratatui::Frame;

/// Render the tabs, one per trace.
pub fn render(f: &mut Frame<'_>, rect: Rect, app: &TuiApp) {
    let tabs_block = Block::default()
        .title(Line::raw(t!("title_traces")))
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        );
    let titles: Vec<_> = app
        .trace_info
        .iter()
        .map(|trace| {
            Line::from(Span::styled(
                &trace.target_hostname,
                Style::default().fg(app.tui_config.theme.tab_text),
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
