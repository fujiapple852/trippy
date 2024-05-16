use crate::frontend::tui_app::TuiApp;
use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::Style;
use ratatui::symbols::Marker;
use ratatui::text::Span;
use ratatui::widgets::{Axis, Block, BorderType, Borders, Chart, Dataset, GraphType};
use ratatui::Frame;

/// Render the ping history for all hops as a chart.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let samples = app.tui_config.max_samples / app.zoom_factor;
    let series_data = app
        .selected_tracer_data
        .hops(app.selected_flow)
        .iter()
        .map(|hop| {
            hop.samples()
                .iter()
                .enumerate()
                .take(samples)
                .map(|(i, s)| (i as f64, (s.as_secs_f64() * 1000_f64)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let max_sample = series_data
        .iter()
        .flatten()
        .map(|&(_, s)| s)
        .max_by_key(|&c| c as u64)
        .unwrap_or_default();
    let sets = series_data
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Dataset::default()
                .name(format!("Hop {}", i + 1))
                .data(s)
                .graph_type(GraphType::Line)
                .marker(Marker::Braille)
                .style(Style::default().fg({
                    match i {
                        i if i + 1 == selected_hop.ttl() as usize => {
                            app.tui_config.theme.hops_chart_selected_color
                        }
                        _ => app.tui_config.theme.hops_chart_unselected_color,
                    }
                }))
        })
        .collect::<Vec<_>>();
    let constraints = (Constraint::Ratio(1, 1), Constraint::Ratio(1, 1));
    let chart = Chart::new(sets)
        .x_axis(
            Axis::default()
                .title("Samples")
                .bounds([0_f64, samples as f64])
                .labels_alignment(Alignment::Right)
                .labels(
                    ["0".to_string(), format!("{samples} ({}x)", app.zoom_factor)]
                        .into_iter()
                        .map(Span::from)
                        .collect(),
                )
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis_color)),
        )
        .y_axis(
            Axis::default()
                .title("RTT")
                .bounds([0_f64, max_sample])
                .labels(
                    [
                        String::from("0.0"),
                        format!("{:.1}", max_sample / 2_f64),
                        format!("{max_sample:.1}"),
                    ]
                    .into_iter()
                    .map(Span::from)
                    .collect(),
                )
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis_color)),
        )
        .hidden_legend_constraints(constraints)
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color))
                .title("Chart"),
        );
    f.render_widget(chart, rect);
}
