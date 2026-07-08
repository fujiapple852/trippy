use crate::frontend::tui_app::TuiApp;
use crate::t;
use itertools::Itertools;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, BorderType, Borders};
use std::time::Duration;

/// The width of a bar in terminal columns, excluding the gap.
const BAR_WIDTH: u16 = 4;
const BAR_GAP: u16 = 1;

/// Render a histogram of ping frequencies.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let selected_hop = app.selected_hop_or_target();
    let freq_data = sample_frequency(selected_hop.samples(), rect.width);
    let bars: Vec<_> = freq_data
        .iter()
        .map(|bucket| {
            Bar::default()
                .label(bucket.rtt.as_millis().to_string())
                .value(bucket.freq_pct)
        })
        .collect();
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
        .data(BarGroup::new(bars))
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

/// A single bucket of the frequency histogram.
struct Bucket {
    /// Round-trip time.
    rtt: Duration,
    /// Raw sample count.
    count: usize,
    /// The frequency as a percentage of all samples.
    freq_pct: u64,
}

/// Group samples by millisecond and return a window centred on the most frequent bucket.
///
/// `width` includes both borders. Match `BarChart` sizing: the last bar needs no trailing gap.
fn sample_frequency(samples: &[Duration], width: u16) -> Vec<Bucket> {
    let sample_count = samples.len();
    let freq_data: Vec<_> = samples
        .iter()
        .filter(|sample| !sample.is_zero())
        .map(|sample| Duration::new(sample.as_secs(), sample.subsec_millis() * 1_000_000))
        .counts()
        .into_iter()
        .sorted_unstable_by_key(|(rtt, _)| *rtt)
        .map(|(rtt, count)| Bucket {
            rtt,
            count,
            freq_pct: (count as u128 * 100 / sample_count as u128) as u64,
        })
        .collect();

    let bar_and_gap = BAR_WIDTH + BAR_GAP;
    let inner_width = width.saturating_sub(2);
    let max_bars = usize::from((inner_width + BAR_GAP) / bar_and_gap).max(1);
    if freq_data.len() <= max_bars {
        return freq_data;
    }
    let peak_index = freq_data
        .iter()
        .enumerate()
        .max_by_key(|(_, bucket)| bucket.count)
        .map_or(0, |(i, _)| i);
    let start = peak_index
        .saturating_sub(max_bars / 2)
        .min(freq_data.len() - max_bars);
    freq_data.into_iter().skip(start).take(max_bars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(&[], 0, &[]; "no samples")]
    #[test_case(&[0, 0], 100, &[]; "only zero samples")]
    #[test_case(&[1, 2, 3], 100, &[1, 2, 3]; "all data fits")]
    #[test_case(&[1, 2, 3, 3, 4, 5], 16, &[2, 3, 4]; "centres on peak")]
    #[test_case(&[1, 1, 2, 3, 4, 5], 16, &[1, 2, 3]; "clamps to start")]
    #[test_case(&[1, 2, 3, 4, 5, 5], 16, &[3, 4, 5]; "clamps to end")]
    #[test_case(&[1, 2, 3, 3], 1, &[3]; "width smaller than one bar")]
    #[test_case(&[1, 2, 3, 4, 5, 5], 21, &[2, 3, 4, 5]; "last bar needs no trailing gap")]
    #[test_case(&[1, 2, 3, 4, 5, 5], 20, &[3, 4, 5]; "reserves both borders")]
    fn selects_window_around_peak(millis: &[u64], width: u16, expected: &[u64]) {
        let samples: Vec<_> = millis.iter().copied().map(Duration::from_millis).collect();
        let freq_data = sample_frequency(&samples, width);
        let rtts: Vec<_> = freq_data.iter().map(|bucket| bucket.rtt).collect();
        let expected: Vec<_> = expected
            .iter()
            .copied()
            .map(Duration::from_millis)
            .collect();
        assert_eq!(rtts, expected);
    }
}
