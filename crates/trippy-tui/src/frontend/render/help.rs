use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
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
    #[allow(clippy::needless_raw_string_hashes)]
    let help_lines = vec![
        r#"                           "#.to_string(),
        r#" _____    _                "#.to_string(),
        r#"|_   _| _(_)_ __ _ __ _  _ "#.to_string(),
        r#"  | || '_| | '_ \ '_ \ || |"#.to_string(),
        r#"  |_||_| |_| .__/ .__/\_, |"#.to_string(),
        r#"           |_|  |_|   |__/ "#.to_string(),
        r#"                           "#.to_string(),
        r#" A network diagnostic tool "#.to_string(),
        r#"                           "#.to_string(),
        format!(" Press [{s}] to show all settings "),
        format!(" Press [{b}] to show key bindings "),
        format!(" Press [{c}] to choose columns "),
        r#"                           "#.to_string(),
        r#" https://github.com/fujiapple852/trippy "#.to_string(),
        r#"                           "#.to_string(),
        r#" Distributed under the Apache License 2.0 "#.to_string(),
        r#"                           "#.to_string(),
        r#" Copyright 2022 Trippy Contributors "#.to_string(),
    ];
    let block = Block::default()
        .title(" Help ")
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
