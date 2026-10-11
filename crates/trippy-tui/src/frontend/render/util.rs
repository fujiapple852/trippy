use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

/// A block title with one space either side; the message's markup is kept.
pub fn padded_title<'a>(title: impl Into<Line<'a>>) -> Line<'a> {
    let mut line = Line::from(" ");
    line.extend(title.into().spans);
    line.push_span(" ");
    line
}
