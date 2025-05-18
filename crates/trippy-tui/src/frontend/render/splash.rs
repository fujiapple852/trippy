use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::borrow::Cow;

/// Render the splash screen.
///
/// This is shown on startup whilst we await the first round of data to be available.
pub fn render(f: &mut Frame<'_>, app: &TuiApp, rect: Rect) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title(Line::raw(t!("title_hops")))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.tui_config.theme.border))
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        );
    #[expect(clippy::needless_raw_string_hashes)]
    let splash: Vec<Cow<'static, str>> = vec![
        r#" _____    _                "#.into(),
        r#"|_   _| _(_)_ __ _ __ _  _ "#.into(),
        r#"  | || '_| | '_ \ '_ \ || |"#.into(),
        r#"  |_||_| |_| .__/ .__/\_, |"#.into(),
        r#"           |_|  |_|   |__/ "#.into(),
        "".into(),
        t!("awaiting_data"),
    ];
    let line: Vec<_> = splash
        .into_iter()
        .map(|line| Line::from(Span::styled(line, Style::default())))
        .collect();
    let paragraph = Paragraph::new(line).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}
