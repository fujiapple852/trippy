use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, BorderType, Borders, Paragraph};

const FLOW_BAR_WIDTH: u16 = 4;
const FLOW_BAR_GAP: u16 = 1;

/// Render the flows.
pub fn render(f: &mut Frame<'_>, rect: Rect, app: &mut TuiApp) {
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

    let inner = block.inner(rect);
    let visible_bars = ((inner.width as usize + FLOW_BAR_GAP as usize)
        / ((FLOW_BAR_WIDTH + FLOW_BAR_GAP) as usize))
        .max(1);
    let total_flows = app.flow_counts.len();
    let selected_index = app
        .flow_counts
        .iter()
        .position(|(flow_id, _)| *flow_id == app.selected_flow)
        .unwrap_or(0);
    let mut start_index = app
        .flows_start_index
        .min(total_flows.saturating_sub(visible_bars));
    if selected_index < start_index {
        start_index = selected_index;
    } else if selected_index >= start_index + visible_bars {
        start_index = selected_index + 1 - visible_bars;
    }
    app.flows_start_index = start_index;

    let round_flow_id = app.tracer_data().round_flow_id();
    let show_left_indicator = start_index > 0;
    let show_right_indicator = start_index + visible_bars < total_flows;
    let data: Vec<_> = app
        .flow_counts
        .iter()
        .skip(start_index)
        .take(visible_bars)
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
    let group = BarGroup::default().bars(&data);
    let flow_counts = BarChart::default()
        .block(block)
        .data(group)
        .bar_width(FLOW_BAR_WIDTH)
        .bar_gap(FLOW_BAR_GAP);
    f.render_widget(flow_counts, rect);
    render_scroll_indicators(f, inner, show_left_indicator, show_right_indicator, app);
}

fn render_scroll_indicators(
    f: &mut Frame<'_>,
    inner_rect: Rect,
    show_left_indicator: bool,
    show_right_indicator: bool,
    app: &TuiApp,
) {
    if inner_rect.width == 0 || inner_rect.height == 0 {
        return;
    }

    let indicator_style = Style::default()
        .fg(app.tui_config.theme.border)
        .add_modifier(Modifier::BOLD);
    let indicator_y = inner_rect.y + inner_rect.height / 2;
    if show_left_indicator {
        let left_rect = Rect {
            x: inner_rect.x,
            y: indicator_y,
            width: 1,
            height: 1,
        };
        let indicator = Paragraph::new(Line::raw("◀")).style(indicator_style);
        f.render_widget(indicator, left_rect);
    }
    if show_right_indicator {
        let right_rect = Rect {
            x: inner_rect.x + inner_rect.width.saturating_sub(1),
            y: indicator_y,
            width: 1,
            height: 1,
        };
        let indicator = Paragraph::new(Line::raw("▶")).style(indicator_style);
        f.render_widget(indicator, right_rect);
    }
}
