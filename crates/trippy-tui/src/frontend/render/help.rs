use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
use crate::t;
use ratatui::layout::Alignment;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

/// Render help dialog.
pub fn render(f: &mut Frame<'_>, app: &TuiApp) {
    let s = app.tui_config.bindings.toggle_settings;
    let b = app.tui_config.bindings.toggle_settings_bindings;
    let c = app.tui_config.bindings.toggle_settings_columns;
    #[expect(clippy::needless_raw_string_hashes)]
    let help_lines = vec![
        Line::raw(r#"                           "#),
        Line::raw(r#" _____    _                "#),
        Line::raw(r#"|_   _| _(_)_ __ _ __ _  _ "#),
        Line::raw(r#"  | || '_| | '_ \ '_ \ || |"#),
        Line::raw(r#"  |_||_| |_| .__/ .__/\_, |"#),
        Line::raw(r#"           |_|  |_|   |__/ "#),
        Line::raw(r#"                           "#),
        Line::raw(t!("help_tagline")),
        Line::raw(r#"                           "#),
        Line::raw(t!("help_show_settings", key = s)),
        Line::raw(t!("help_show_bindings", key = b)),
        Line::raw(t!("help_show_columns", key = c)),
        Line::raw(r#"                           "#),
        Line::raw(r#" https://github.com/fujiapple852/trippy "#),
        Line::raw(r#"                           "#),
        Line::raw(t!("help_license")),
        Line::raw(r#"                           "#),
        Line::raw(t!("help_copyright")),
    ];
    let block = Block::default()
        .title(format!(" {} ", t!("title_help")))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg))
        .border_type(BorderType::Double);
    let control = Paragraph::new(help_lines)
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text))
        .block(block.clone())
        .alignment(Alignment::Center);
    let area = util::centered_rect(60, 60, f.area());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}
