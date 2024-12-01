use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, BorderType, Borders, Sparkline};
use ratatui::Frame;

/// Render the ping history for the final hop which is typically the target.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let data = selected_hop
        .samples()
        .iter()
        .take(rect.width as usize)
        .map(|s| {
            if s.is_zero() {
                None
            } else {
                Some(s.as_micros() as u64)
            }
        })
        .collect::<Vec<_>>();
    let history = Sparkline::default()
        .block(
            Block::default()
                .title(format!("{} #{}", t!("title_samples"), selected_hop.ttl()))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg)
                        .fg(app.tui_config.theme.text),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border)),
        )
        .data(data.as_slice())
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.samples_chart),
        )
        .absent_value_style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.samples_chart_lost),
        )
        .absent_value_symbol(ratatui::symbols::bar::FULL);
    f.render_widget(history, rect);
}
