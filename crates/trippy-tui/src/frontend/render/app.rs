use crate::frontend::render::{bar, body, flows, footer, header, help, settings, tabs};
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

/// Render the application main screen.
///
/// The layout of the TUI is as follows:
///
///  ____________________________________
/// |               Header               |
///  ------------------------------------
/// |               Tabs                 |
///  ------------------------------------
/// |               Flows                |
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
/// ===== dynamic configuration bar ======
///
/// - Header: the title, target, clock and basic keyboard controls
/// - Tab: a tab for each target (shown if > 1 target requested, can't be used with flows)
/// - Flows: a navigable chart of individual trace flows (toggled on/off, can't be used with tabs)
/// - Hops: a table where each row represents a single hop (time-to-live) in the trace
/// - History: a graph of historic round-trip ping samples for the target host
/// - Frequency: a histogram of sample frequencies by round-trip time for the target host
/// - Configuration bar: a bar showing the current value for dynamically configurable items
///
/// On startup a splash screen is shown in place of the hops table, until the completion of the
/// first round.
pub fn render(f: &mut Frame<'_>, app: &mut TuiApp) {
    let constraints = if app.trace_info.len() > 1 {
        LAYOUT_WITH_TABS.as_slice()
    } else if app.show_flows {
        LAYOUT_WITH_FLOWS.as_slice()
    } else {
        LAYOUT_WITHOUT_TABS.as_slice()
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.as_ref())
        .split(f.area());
    header::render(f, app, chunks[0]);
    if app.trace_info.len() > 1 {
        tabs::render(f, chunks[1], app);
        body::render(f, chunks[2], app);
        footer::render(f, chunks[3], app);
        bar::render(f, chunks[4], app);
    } else if app.show_flows {
        flows::render(f, chunks[1], app);
        body::render(f, chunks[2], app);
        footer::render(f, chunks[3], app);
        bar::render(f, chunks[4], app);
    } else {
        body::render(f, chunks[1], app);
        footer::render(f, chunks[2], app);
        bar::render(f, chunks[3], app);
    }
    if app.show_settings {
        settings::render(f, app);
    } else if app.show_help {
        help::render(f, app);
    }
}

const LAYOUT_WITHOUT_TABS: [Constraint; 4] = [
    Constraint::Length(4),
    Constraint::Min(10),
    Constraint::Length(6),
    Constraint::Length(1),
];

const LAYOUT_WITH_TABS: [Constraint; 5] = [
    Constraint::Length(4),
    Constraint::Length(3),
    Constraint::Min(10),
    Constraint::Length(6),
    Constraint::Length(1),
];

const LAYOUT_WITH_FLOWS: [Constraint; 5] = [
    Constraint::Length(4),
    Constraint::Length(6),
    Constraint::Min(10),
    Constraint::Length(6),
    Constraint::Length(1),
];
