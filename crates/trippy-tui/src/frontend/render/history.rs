use crate::frontend::render::widgets::sparkline::{EmptyBarSymbol, Sparkline};
use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, BorderType, Borders};
use ratatui::Frame;

/// Render the ping history for the final hop which is typically the target.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let data = selected_hop
        .samples()
        .iter()
        .take(rect.width as usize)
        .map(|s| {
            if s.as_secs_f64() > 0_f64 {
                Some((s.as_secs_f64() * 1000_f64) as u64)
            } else {
                None
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
        .empty_bar_style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.samples_chart_lost),
        )
        .empty_bar_symbol(EmptyBarSymbol::Full);
    f.render_widget(history, rect);
}
