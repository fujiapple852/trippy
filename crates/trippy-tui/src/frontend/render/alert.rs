use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::prelude::{Line, Style};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui_dialog::{Dialog, DialogLayout, DialogPlacement};

pub fn render(f: &mut Frame<'_>, app: &mut TuiApp) {
    let help_lines = vec![
        Line::raw(r"                           "),
        Line::raw(t!("alert_flows")),
        Line::raw(r"                           "),
    ];
    let block = Block::default()
        .title(format!(" {} ", t!("title_alert")))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg))
        .border_type(BorderType::Double);
    let control = Paragraph::new(help_lines)
        .wrap(Wrap::default())
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text))
        .block(block.clone())
        .alignment(Alignment::Center);
    let dialog = Dialog::new(control).layout(
        DialogLayout::default()
            .with_width_percentage(0.2)
            .with_height_percentage(0.2)
            .with_placement(DialogPlacement::Centered),
    );
    f.render_stateful_widget(dialog, f.area(), &mut app.alert_state);
}
