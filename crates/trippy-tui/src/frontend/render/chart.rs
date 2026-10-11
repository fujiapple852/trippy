use crate::frontend::tui_app::TuiApp;
use crate::tr;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::Style;
use ratatui::symbols::Marker;
use ratatui::text::Line;
use ratatui::widgets::{Axis, Block, BorderType, Borders, Chart, Dataset, GraphType};

/// Render the ping history for all hops as a chart.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let samples = app.selected_tracer_data.max_samples() / app.zoom_factor;
    let series_data = app
        .selected_tracer_data
        .hops_for_flow(app.selected_flow)
        .iter()
        .map(|hop| {
            hop.samples()
                .iter()
                .enumerate()
                .take(samples)
                .map(|(i, s)| (i as f64, s.as_secs_f64() * 1000_f64))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let max_sample = series_data
        .iter()
        .flatten()
        .map(|&(_, s)| s)
        .max_by_key(|&c| (c * 1000.0) as u64)
        .unwrap_or_default();
    let sets = series_data
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Dataset::default()
                .name(tr!("hop", ttl = i + 1))
                .data(s)
                .graph_type(GraphType::Line)
                .marker(Marker::Braille)
                .style(Style::default().fg({
                    match i {
                        i if i + 1 == selected_hop.ttl() as usize => {
                            app.tui_config.theme.hops_chart_selected
                        }
                        _ => app.tui_config.theme.hops_chart_unselected,
                    }
                }))
        })
        .collect::<Vec<_>>();
    let constraints = (Constraint::Ratio(1, 1), Constraint::Ratio(1, 1));
    let chart = Chart::new(sets)
        .x_axis(
            Axis::default()
                .title(Line::from(tr!("samples")))
                .bounds([0_f64, samples as f64])
                .labels_alignment(Alignment::Right)
                .labels([
                    Line::from("0"),
                    Line::from(tr!(
                        "chart_samples",
                        samples = samples,
                        zoom = app.zoom_factor
                    )),
                ])
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis)),
        )
        .y_axis(
            Axis::default()
                .title(Line::from(tr!("rtt")))
                .bounds([0_f64, max_sample])
                .labels([
                    Line::from(tr!("ms_value", value = 0_f64)),
                    Line::from(tr!("ms_value", value = max_sample / 2_f64)),
                    Line::from(tr!("ms_value", value = max_sample)),
                ])
                .style(Style::default().fg(app.tui_config.theme.hops_chart_axis)),
        )
        .hidden_legend_constraints(constraints)
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border))
                .title(Line::from(tr!("title_chart"))),
        );
    f.render_widget(chart, rect);
}
