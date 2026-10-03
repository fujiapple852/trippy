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
    let freq_data_ref: Vec<_> = visible
        .iter()
        .map(|bucket| (bucket.label.as_str(), bucket.freq_pct))
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

/// A single bucket of the frequency histogram.
#[derive(Debug, PartialEq, Eq)]
struct Bucket {
    /// The bucket's label (the round-trip time, in ms, as a string).
    label: String,
    /// The number of samples that fell into this bucket.
    ///
    /// This is the raw sample count, not `freq_pct` -- it must be used (rather than the
    /// truncated integer percentage) to find the bucket with the highest frequency, as two
    /// buckets with different counts can round down to the same displayed percentage.
    count: u64,
    /// The displayed frequency, as a percentage of all samples, truncated to an integer.
    freq_pct: u64,
}

/// Return the slice of `freq_data` that fits within `width` columns, centred on the bucket
/// with the highest frequency.
///
/// `BarChart` renders bars left-to-right and simply clips whatever doesn't fit, so without this
/// the highest-frequency bucket can be pushed off-screen if it doesn't happen to be amongst the
/// first buckets shown.
///
/// `width` is the full `rect` width passed to `render`, i.e. before the surrounding
/// `Borders::ALL` block is applied, so two columns (one per side) are reserved for it here.
/// The bar count itself mirrors `BarChart`'s own sizing rule (`(space + bar_gap) /
/// (bar_width + bar_gap)`): the last visible bar doesn't need a trailing gap after it, so a
/// plain `inner_width / bar_and_gap` would undercount by one bar whenever `inner_width mod
/// bar_and_gap == bar_width`.
fn windowed_around_peak(freq_data: &[Bucket], width: u16) -> &[Bucket] {
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
    &freq_data[start..start + max_bars]
}

/// Return the frequency % grouped by sample duration.
fn sample_frequency(samples: &[Duration]) -> Vec<Bucket> {
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
            let freq_pct = ((*count as f64 / sample_count as f64) * 100_f64) as u64;
            Bucket {
                label: format!("{ping}"),
                count: *count,
                freq_pct,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(counts: &[u64]) -> Vec<Bucket> {
        counts
            .iter()
            .enumerate()
            .map(|(i, c)| Bucket {
                label: i.to_string(),
                count: *c,
                freq_pct: *c,
            })
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
        // rect width 22 -> inner width 20 -> (20 + 1) / (4 + 1) == 4 bars visible.
        let freq_data = data(&[1, 1, 1, 1, 1, 9, 1, 1, 1, 1, 1]);
        let visible = windowed_around_peak(&freq_data, 22);
        assert_eq!(visible.len(), 4);
        assert!(visible.iter().any(|bucket| bucket.count == 9));
    }

    #[test]
    fn clamps_the_window_to_the_start_of_the_data() {
        let freq_data = data(&[9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        let visible = windowed_around_peak(&freq_data, 22);
        assert_eq!(visible.len(), 4);
        assert_eq!(visible[0].count, 9);
    }

    #[test]
    fn clamps_the_window_to_the_end_of_the_data() {
        let freq_data = data(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9]);
        let visible = windowed_around_peak(&freq_data, 22);
        assert_eq!(visible.len(), 4);
        assert_eq!(visible.last().unwrap().count, 9);
    }

    #[test]
    fn handles_a_width_too_small_for_a_single_bar() {
        let freq_data = data(&[1, 2, 3]);
        let visible = windowed_around_peak(&freq_data, 1);
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn accounts_for_the_last_bar_not_needing_a_trailing_gap() {
        // rect width 21 -> inner width 19 -> the widget's own sizing rule
        // ((space + gap) / (bar_width + gap) == (19 + 1) / 5 == 4) fits one more
        // bar than a naive `inner_width / (bar_width + gap)` (19 / 5 == 3) would,
        // because the last visible bar doesn't need a trailing gap after it.
        let freq_data = data(&[1, 2, 3, 4, 5, 6]);
        let visible = windowed_around_peak(&freq_data, 21);
        assert_eq!(visible.len(), 4);
    }

    #[test]
    fn accounts_for_the_two_columns_taken_by_the_border() {
        // A rounded `Borders::ALL` block consumes one column on each side, so the
        // bar area only has `rect.width - 2` columns to work with, not the full
        // `rect.width` passed in here. rect width 20 -> inner width 18 -> (18 + 1)
        // / 5 == 3 bars. Treating the full rect width as usable would give 4.
        let freq_data = data(&[1, 2, 3, 4, 5, 6]);
        let visible = windowed_around_peak(&freq_data, 20);
        assert_eq!(visible.len(), 3);
    }

    #[test]
    fn picks_the_peak_by_raw_count_not_truncated_percentage() {
        // Two buckets whose *truncated* percentages tie at 33%, but whose raw counts
        // differ: 100 samples in bucket 0 (33.0%) and 133 samples in bucket 5 (33.25%
        // of 400, i.e. it is the true peak). Selecting on `freq_pct` alone would pick
        // whichever tied bucket comes first (index 0); selecting on `count` must pick
        // index 5.
        let freq_data: Vec<Bucket> = [
            (0, 100_u64),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 133),
            (6, 1),
            (7, 1),
            (8, 1),
            (9, 1),
            (10, 1),
        ]
        .into_iter()
        .map(|(i, count)| Bucket {
            label: i.to_string(),
            count,
            freq_pct: 33, // both tie once truncated to an integer percentage
        })
        .collect();
        let visible = windowed_around_peak(&freq_data, 22);
        assert_eq!(visible.len(), 4);
        assert!(visible.iter().any(|bucket| bucket.count == 133));
    }

    #[test]
    fn sample_frequency_reports_raw_counts_alongside_truncated_percentages() {
        // 3 samples: durations 1ms, 1ms, 2ms -> bucket "1" has count 2 (66%),
        // bucket "2" has count 1 (33%). The raw counts must reflect the actual
        // sample distribution, not just the truncated percentages.
        let samples = [
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(2),
        ];
        let buckets = sample_frequency(&samples);
        let bucket_1 = buckets.iter().find(|b| b.label == "1").unwrap();
        let bucket_2 = buckets.iter().find(|b| b.label == "2").unwrap();
        assert_eq!(bucket_1.count, 2);
        assert_eq!(bucket_1.freq_pct, 66);
        assert_eq!(bucket_2.count, 1);
        assert_eq!(bucket_2.freq_pct, 33);
    }
}
