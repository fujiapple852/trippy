use crate::frontend::binding::KeyBinding;
use crate::tr;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

/// Render a blue screen of death.
pub fn render(f: &mut Frame<'_>, rect: Rect, error: &str, quit: KeyBinding) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title(Line::from(tr!("title_hops")))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(Color::Blue));
    let line = vec![
        Line::from(Span::styled(
            tr!("bsod_failed").to_cow(),
            Style::default().add_modifier(Modifier::REVERSED),
        )),
        Line::from(""),
        Line::from(error),
        Line::from(""),
        Line::from(tr!("bsod_quit", key = quit)),
    ];
    let paragraph = Paragraph::new(line).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}
