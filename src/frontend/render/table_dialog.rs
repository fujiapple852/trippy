use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::Alignment;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

/// Render Table dialog.
pub fn render(f: &mut Frame<'_>, app: &TuiApp) {
    let block = Block::default()
        .title(" Table Columns ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg_color))
        .border_type(BorderType::Double);
    let control_line: Vec<_> = GRID_COLUMN_LINES
        .iter()
        .map(|&line| Line::from(line))
        .collect();
    let control = Paragraph::new(control_line)
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text_color))
        .block(block.clone())
        .alignment(Alignment::Left);
    let area = util::centered_rect(40, 40, f.size());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}

const GRID_COLUMN_LINES: [&str; 12] = [
    "Short Description",
    "[H] - # of Hop",
    "[O] - Hostname or IP",
    "[L] - Loss%",
    "[S] - Sent",
    "[R] - Received",
    "[A] - Last",
    "[V] - Average",
    "[B] - Best",
    "[W] - Worst",
    "[D] - Standard Deviation",
    "[T] - Status",
];
