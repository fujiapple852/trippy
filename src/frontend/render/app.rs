use crate::frontend::render::{body, footer, header, help, settings, tabs};
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use super::table_dialog;

/// Render the application main screen.
///
/// The layout of the TUI is as follows:
///
///  ____________________________________
/// |               Header               |
///  ------------------------------------
/// |                Tabs                |
///  ------------------------------------
/// |                                    |
/// |                                    |
/// |                                    |
/// |         Hops / Chart / Map         |
/// |                                    |
/// |                                    |
/// |                                    |
///  ------------------------------------
/// |     History     |    Frequency     |
/// |                 |                  |
///  ------------------------------------
///
/// Header - the title, configuration, destination, clock and keyboard controls
/// Tab - a tab for each target being traced (only shown if > 1 target requested)
/// Hops - a table where each row represents a single hop (time-to-live) in the trace
/// History - a graph of historic round-trip ping samples for the target host
/// Frequency - a histogram of sample frequencies by round-trip time for the target host
///
/// On startup a splash screen is shown in place of the hops table, until the completion of the
/// first round.
pub fn render(f: &mut Frame<'_>, app: &mut TuiApp) {
    let constraints = if app.trace_info.len() > 1 {
        LAYOUT_WITH_TABS.as_slice()
    } else {
        LAYOUT_WITHOUT_TABS.as_slice()
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.as_ref())
        .split(f.size());
    header::render(f, app, chunks[0]);
    if app.trace_info.len() > 1 {
        tabs::render(f, chunks[1], app);
        body::render(f, chunks[2], app);
        footer::render(f, chunks[3], app);
    } else {
        body::render(f, chunks[1], app);
        footer::render(f, chunks[2], app);
    }
    if app.show_settings {
        settings::render(f, app);
    } else if app.show_table_dialog {
        table_dialog::render(f, app);
    } else if app.show_help {
        help::render(f, app);
    }
}

const LAYOUT_WITHOUT_TABS: [Constraint; 3] = [
    Constraint::Length(5),
    Constraint::Min(10),
    Constraint::Length(6),
];

const LAYOUT_WITH_TABS: [Constraint; 4] = [
    Constraint::Length(5),
    Constraint::Length(3),
    Constraint::Min(10),
    Constraint::Length(6),
];
