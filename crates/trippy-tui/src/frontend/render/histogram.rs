use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{BarChart, Block, BorderType, Borders};
use std::collections::BTreeMap;
use std::time::Duration;

/// The width, in columns, occupied by a single bar (including its trailing gap).
const BAR_WIDTH: u16 = 4;
const BAR_GAP: u16 = 1;

/// Render a histogram of ping frequencies.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let freq_data = sample_frequency(selected_hop.samples());
    let visible = windowed_around_peak(&freq_data, rect.width);
    let freq_data_ref: Vec<_> = visible.iter().map(|(b, c)| (b.as_str(), *c)).collect();
    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(format!("{} #{}", t!("title_frequency"), selected_hop.ttl()))
                .style(
                    Style::default()
                        .bg(app.tui_config.theme.bg)
                        .fg(app.tui_config.theme.text),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border)),
        )
        .data(freq_data_ref.as_slice())
        .bar_width(BAR_WIDTH)
        .bar_gap(BAR_GAP)
        .bar_style(Style::default().fg(app.tui_config.theme.frequency_chart_bar))
        .value_style(
            Style::default()
                .bg(app.tui_config.theme.frequency_chart_bar)
                .fg(app.tui_config.theme.frequency_chart_text)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(barchart, rect);
}

/// Return the slice of `freq_data` that fits within `width` columns, centred on the bucket
/// with the highest frequency.
///
/// `BarChart` renders bars left-to-right and simply clips whatever doesn't fit, so without this
/// the highest-frequency bucket can be pushed off-screen if it doesn't happen to be amongst the
/// first buckets shown.
fn windowed_around_peak(freq_data: &[(String, u64)], width: u16) -> &[(String, u64)] {
    let bar_and_gap = BAR_WIDTH + BAR_GAP;
    let max_bars = usize::from(width / bar_and_gap).max(1);
    if freq_data.len() <= max_bars {
        return freq_data;
    }
    let peak_index = freq_data
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, count))| *count)
        .map_or(0, |(i, _)| i);
    let start = peak_index
        .saturating_sub(max_bars / 2)
        .min(freq_data.len() - max_bars);
    &freq_data[start..start + max_bars]
}

/// Return the frequency % grouped by sample duration.
fn sample_frequency(samples: &[Duration]) -> Vec<(String, u64)> {
    let sample_count = samples.len();
    let mut count_by_duration: BTreeMap<u128, u64> = BTreeMap::new();
    for sample in samples {
        if !sample.is_zero() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn data(counts: &[u64]) -> Vec<(String, u64)> {
        counts
            .iter()
            .enumerate()
            .map(|(i, c)| (i.to_string(), *c))
            .collect()
    }

    #[test]
    fn returns_all_data_when_it_fits() {
        let freq_data = data(&[1, 2, 3]);
        let visible = windowed_around_peak(&freq_data, 100);
        assert_eq!(visible, freq_data.as_slice());
    }

    #[test]
    fn centres_on_the_peak_when_it_does_not_fit() {
        // width 20 / (bar_width 4 + bar_gap 1) == 4 bars visible.
        let freq_data = data(&[1, 1, 1, 1, 1, 9, 1, 1, 1, 1, 1]);
        let visible = windowed_around_peak(&freq_data, 20);
        assert_eq!(visible.len(), 4);
        assert!(visible.iter().any(|(_, c)| *c == 9));
    }

    #[test]
    fn clamps_the_window_to_the_start_of_the_data() {
        let freq_data = data(&[9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        let visible = windowed_around_peak(&freq_data, 20);
        assert_eq!(visible.len(), 4);
        assert_eq!(visible[0].1, 9);
    }

    #[test]
    fn clamps_the_window_to_the_end_of_the_data() {
        let freq_data = data(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9]);
        let visible = windowed_around_peak(&freq_data, 20);
        assert_eq!(visible.len(), 4);
        assert_eq!(visible.last().unwrap().1, 9);
    }

    #[test]
    fn handles_a_width_too_small_for_a_single_bar() {
        let freq_data = data(&[1, 2, 3]);
        let visible = windowed_around_peak(&freq_data, 1);
        assert_eq!(visible.len(), 1);
    }
}
