use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::Alignment;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

/// Render help dialog.
pub fn render(f: &mut Frame<'_>, app: &TuiApp) {
    let block = Block::default()
        .title(" Default Controls ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg_color))
        .border_type(BorderType::Double);
    let control_line: Vec<_> = HELP_LINES.iter().map(|&line| Line::from(line)).collect();
    let control = Paragraph::new(control_line)
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text_color))
        .block(block.clone())
        .alignment(Alignment::Left);
    let area = util::centered_rect(60, 60, f.size());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}

const HELP_LINES: [&str; 21] = [
    "[up] & [down]    - select hop",
    "[left] & [right] - select trace or flow",
    ", & .            - select hop address",
    "[esc]            - clear selection",
    "d                - toggle hop details",
    "f                - toggle flows",
    "c                - toggle chart",
    "m                - toggle map",
    "Ctrl-f           - toggle freeze display",
    "Ctrl+r           - reset statistics",
    "Ctrl+k           - flush DNS cache",
    "i                - show IP only",
    "n                - show hostname only",
    "b                - show both IP and hostname",
    "[ & ]            - expand & collapse hosts",
    "{ & }            - expand & collapse hosts to max and min",
    "+ & -            - zoom chart in and out",
    "z                - toggle AS information (if available)",
    "h or ?           - toggle help",
    "s                - toggle settings",
    "q                - quit",
];
