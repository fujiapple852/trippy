use crate::frontend::render::{histogram, history};
use crate::frontend::tui_app::TuiApp;
use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

/// Render the footer.
///
/// This contains the history and frequency charts.
pub fn render<B: Backend>(f: &mut Frame<'_, B>, rec: Rect, app: &mut TuiApp) {
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
        .split(rec);
    history::render(f, app, bottom_chunks[0]);
    histogram::render(f, app, bottom_chunks[1]);
}
