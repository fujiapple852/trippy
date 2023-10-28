use crate::frontend::tui_app::TuiApp;
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
