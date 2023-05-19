use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Span, Spans};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

/// Render a blue screen of death.
pub fn render<B: Backend>(f: &mut Frame<'_, B>, rect: Rect, error: &str) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title("Hops")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(Color::Blue));
    let spans = vec![
        Spans::from(Span::styled(
            "Trippy Failed :(",
            Style::default().add_modifier(Modifier::REVERSED),
        )),
        Spans::from(""),
        Spans::from(error),
        Spans::from(""),
        Spans::from("Press q to quit "),
    ];
    let paragraph = Paragraph::new(spans).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}
