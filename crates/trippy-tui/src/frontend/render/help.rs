use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
use ratatui::layout::Alignment;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;
use rust_i18n::t;

/// Render help dialog.
pub fn render(f: &mut Frame<'_>, app: &TuiApp) {
    let s = app.tui_config.bindings.toggle_settings;
    let b = app.tui_config.bindings.toggle_settings_bindings;
    let c = app.tui_config.bindings.toggle_settings_columns;
    #[allow(clippy::needless_raw_string_hashes)]
    let help_lines = vec![
        r#"                           "#.to_string(),
        r#" _____    _                "#.to_string(),
        r#"|_   _| _(_)_ __ _ __ _  _ "#.to_string(),
        r#"  | || '_| | '_ \ '_ \ || |"#.to_string(),
        r#"  |_||_| |_| .__/ .__/\_, |"#.to_string(),
        r#"           |_|  |_|   |__/ "#.to_string(),
        r#"                           "#.to_string(),
        t!("help_tagline").to_string(),
        r#"                           "#.to_string(),
        t!("help_show_settings", key = s).to_string(),
        t!("help_show_bindings", key = b).to_string(),
        t!("help_show_columns", key = c).to_string(),
        r#"                           "#.to_string(),
        r#" https://github.com/fujiapple852/trippy "#.to_string(),
        r#"                           "#.to_string(),
        t!("help_license").to_string(),
        r#"                           "#.to_string(),
        t!("help_copyright").to_string(),
    ];
    let block = Block::default()
        .title(format!(" {} ", t!("title_help")))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(app.tui_config.theme.help_dialog_bg))
        .border_type(BorderType::Double);
    let control_line: Vec<_> = help_lines
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect();
    let control = Paragraph::new(control_line)
        .style(Style::default().fg(app.tui_config.theme.help_dialog_text))
        .block(block.clone())
        .alignment(Alignment::Center);
    let area = util::centered_rect(60, 60, f.area());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}
