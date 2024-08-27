use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, BorderType, Borders};
use ratatui::Frame;

/// Render the flows.
pub fn render(f: &mut Frame<'_>, rect: Rect, app: &TuiApp) {
    let round_flow_id = app.tracer_data().round_flow_id();
    let data: Vec<_> = app
        .flow_counts
        .iter()
        .map(|(flow_id, count)| {
            let bar_color = if flow_id == &app.selected_flow {
                app.tui_config.theme.flows_chart_bar_selected
            } else {
                app.tui_config.theme.flows_chart_bar_unselected
            };
            let label_color = if flow_id == &round_flow_id {
                app.tui_config.theme.flows_chart_text_current
            } else {
                app.tui_config.theme.flows_chart_text_non_current
            };
            Bar::default()
                .label(Line::from(format!("{flow_id}")))
                .value(*count as u64)
                .style(Style::default().fg(bar_color))
                .value_style(
                    Style::default()
                        .bg(bar_color)
                        .fg(label_color)
                        .add_modifier(Modifier::BOLD),
                )
        })
        .collect();
    let block = Block::default()
        .title(Line::raw(t!("title_flows")))
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        );
    let group = BarGroup::default().bars(&data);
    let flow_counts = BarChart::default()
        .block(block)
        .data(group)
        .bar_width(4)
        .bar_gap(1);
    f.render_widget(flow_counts, rect);
}
