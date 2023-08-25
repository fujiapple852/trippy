use crate::frontend::tui_app::TuiApp;
use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

/// Render the splash screen.
///
/// This is shown on startup whilst we await the first round of data to be available.
pub fn render<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title("Hops")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border_color))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        );
    #[allow(clippy::needless_raw_string_hashes)]
    let splash = vec![
        r#" _____    _                "#,
        r#"|_   _| _(_)_ __ _ __ _  _ "#,
        r#"  | || '_| | '_ \ '_ \ || |"#,
        r#"  |_||_| |_| .__/ .__/\_, |"#,
        r#"           |_|  |_|   |__/ "#,
        "",
        "Awaiting data...",
    ];
    let line: Vec<_> = splash
        .into_iter()
        .map(|line| Line::from(Span::styled(line, Style::default())))
        .collect();
    let paragraph = Paragraph::new(line).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}
