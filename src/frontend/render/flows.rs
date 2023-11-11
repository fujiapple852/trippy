use crate::frontend::tui_app::TuiApp;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

/// Render the flows tabs.
pub fn render(f: &mut Frame<'_>, rect: Rect, app: &TuiApp) {
    let block = Block::default()
        .title("Flows")
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border_color))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        );
    // let titles: Vec<_> = (1..app.flow_count())
    //     .map(|flow_id| {
    //         let count = app.tracer_data().probe_count(FlowId(flow_id as u64));
    //         (flow_id, count)
    //     })
    //     .sorted_by_key(|(_, count)| count).rev()
    //     .take(10)
    //     .map(|(flow_id, count)| {
    //         Line::from(Span::styled(
    //             format!("{flow_id}"),
    //             Style::default().fg(app.tui_config.theme.tab_text_color),
    //         ))
    //     })
    //     .collect();

    let line = Line::raw(format!(
        "Flow {} of {}",
        app.selected_flow.0,
        app.flow_count()
    ));

    let para = Paragraph::new(line)
        .style(Style::default())
        .block(block)
        .alignment(Alignment::Left);
    f.render_widget(para, rect);

    // let tabs = Tabs::new(titles)
    //     .block(tabs_block)
    //     .select(app.selected_flow.0 as usize)
    //     .style(Style::default())
    //     .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    // f.render_widget(tabs, rect);
}
