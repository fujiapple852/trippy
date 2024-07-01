use crate::frontend::render::{bsod, chart, splash, table, world};
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::Rect;
use ratatui::Frame;

/// Render the body.
///
/// This is either an BSOD if there wa san error or the table of hop data or, if there is no data,
/// the splash screen.
pub fn render(f: &mut Frame<'_>, rec: Rect, app: &mut TuiApp) {
    if let Some(err) = app.selected_tracer_data.error() {
        bsod::render(f, rec, err);
    } else if app.tracer_data().hops().is_empty() {
        splash::render(f, app, rec);
    } else if app.show_chart {
        chart::render(f, app, rec);
    } else if app.show_map {
        world::render(f, app, rec);
    } else {
        table::render(f, app, rec);
    }
}
