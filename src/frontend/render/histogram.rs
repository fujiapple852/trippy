use crate::frontend::tui_app::TuiApp;
use ratatui::backend::Backend;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{BarChart, Block, BorderType, Borders};
use ratatui::Frame;
use std::collections::BTreeMap;
use std::time::Duration;

/// Render a histogram of ping frequencies.
pub fn render<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let target_hop = app.table_state.selected().map_or_else(
        || app.tracer_data().target_hop(),
        |s| &app.tracer_data().hops()[s],
    );
    let freq_data = sample_frequency(target_hop.samples());
    let freq_data_ref: Vec<_> = freq_data.iter().map(|(b, c)| (b.as_str(), *c)).collect();
    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(format!("Frequency #{}", target_hop.ttl()))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg_color)
                        .fg(app.tui_config.theme.text_color),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color)),
        )
        .data(freq_data_ref.as_slice())
        .bar_width(4)
        .bar_gap(1)
        .bar_style(Style::default().fg(app.tui_config.theme.frequency_chart_bar_color))
        .value_style(
            Style::default()
                .bg(app.tui_config.theme.frequency_chart_bar_color)
                .fg(app.tui_config.theme.frequency_chart_text_color)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(barchart, rect);
}

/// Return the frequency % grouped by sample duration.
fn sample_frequency(samples: &[Duration]) -> Vec<(String, u64)> {
    let sample_count = samples.len();
    let mut count_by_duration: BTreeMap<u128, u64> = BTreeMap::new();
    for sample in samples {
        if sample.as_millis() > 0 {
            *count_by_duration.entry(sample.as_millis()).or_default() += 1;
        }
    }
    count_by_duration
        .iter()
        .map(|(ping, count)| {
            let ping = format!("{ping}");
            let freq_pct = ((*count as f64 / sample_count as f64) * 100_f64) as u64;
            (ping, freq_pct)
        })
        .collect()
}
