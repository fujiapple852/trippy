use crate::config::{TuiColor, TuiTheme};
use ratatui::style::Color;

/// Tui color theme.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    pub bg_color: Color,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    pub border_color: Color,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    pub text_color: Color,
    /// The color of the text in traces tabs.
    pub tab_text_color: Color,
    /// The background color of the hops table header.
    pub hops_table_header_bg_color: Color,
    /// The color of text in the hops table header.
    pub hops_table_header_text_color: Color,
    /// The color of text of active rows in the hops table.
    pub hops_table_row_active_text_color: Color,
    /// The color of text of inactive rows in the hops table.
    pub hops_table_row_inactive_text_color: Color,
    /// The color of the selected series in the hops chart.
    pub hops_chart_selected_color: Color,
    /// The color of the unselected series in the hops chart.
    pub hops_chart_unselected_color: Color,
    /// The color of the axis in the hops chart.
    pub hops_chart_axis_color: Color,
    /// The color of bars in the frequency chart.
    pub frequency_chart_bar_color: Color,
    /// The color of text in the bars of the frequency chart.
    pub frequency_chart_text_color: Color,
    /// The color of the samples chart.
    pub samples_chart_color: Color,
    /// The background color of the help dialog.
    pub help_dialog_bg_color: Color,
    /// The color of the text in the help dialog.
    pub help_dialog_text_color: Color,
    /// The background color of the settings dialog.
    pub settings_dialog_bg_color: Color,
    /// The color of the text in settings dialog tabs.
    pub settings_tab_text_color: Color,
    /// The color of text in the settings table header.
    pub settings_table_header_text_color: Color,
    /// The background color of the settings table header.
    pub settings_table_header_bg_color: Color,
    /// The color of text of rows in the settings table.
    pub settings_table_row_text_color: Color,
    /// The color of the map world diagram.
    pub map_world_color: Color,
    /// The color of the map accuracy radius circle.
    pub map_radius_color: Color,
    /// The color of the map selected item box.
    pub map_selected_color: Color,
    /// The color of border of the map info panel.
    pub map_info_panel_border_color: Color,
    /// The background color of the map info panel.
    pub map_info_panel_bg_color: Color,
    /// The color of text in the map info panel.
    pub map_info_panel_text_color: Color,
}

impl From<TuiTheme> for Theme {
    fn from(value: TuiTheme) -> Self {
        Self {
            bg_color: Color::from(value.bg_color),
            border_color: Color::from(value.border_color),
            text_color: Color::from(value.text_color),
            tab_text_color: Color::from(value.tab_text_color),
            hops_table_header_bg_color: Color::from(value.hops_table_header_bg_color),
            hops_table_header_text_color: Color::from(value.hops_table_header_text_color),
            hops_table_row_active_text_color: Color::from(value.hops_table_row_active_text_color),
            hops_table_row_inactive_text_color: Color::from(
                value.hops_table_row_inactive_text_color,
            ),
            hops_chart_selected_color: Color::from(value.hops_chart_selected_color),
            hops_chart_unselected_color: Color::from(value.hops_chart_unselected_color),
            hops_chart_axis_color: Color::from(value.hops_chart_axis_color),
            frequency_chart_bar_color: Color::from(value.frequency_chart_bar_color),
            frequency_chart_text_color: Color::from(value.frequency_chart_text_color),
            samples_chart_color: Color::from(value.samples_chart_color),
            help_dialog_bg_color: Color::from(value.help_dialog_bg_color),
            help_dialog_text_color: Color::from(value.help_dialog_text_color),
            settings_dialog_bg_color: Color::from(value.settings_dialog_bg_color),
            settings_tab_text_color: Color::from(value.settings_tab_text_color),
            settings_table_header_text_color: Color::from(value.settings_table_header_text_color),
            settings_table_header_bg_color: Color::from(value.settings_table_header_bg_color),
            settings_table_row_text_color: Color::from(value.settings_table_row_text_color),
            map_world_color: Color::from(value.map_world_color),
            map_radius_color: Color::from(value.map_radius_color),
            map_selected_color: Color::from(value.map_selected_color),
            map_info_panel_border_color: Color::from(value.map_info_panel_border_color),
            map_info_panel_bg_color: Color::from(value.map_info_panel_bg_color),
            map_info_panel_text_color: Color::from(value.map_info_panel_text_color),
        }
    }
}

impl From<TuiColor> for Color {
    fn from(value: TuiColor) -> Self {
        match value {
            TuiColor::Black => Self::Black,
            TuiColor::Red => Self::Red,
            TuiColor::Green => Self::Green,
            TuiColor::Yellow => Self::Yellow,
            TuiColor::Blue => Self::Blue,
            TuiColor::Magenta => Self::Magenta,
            TuiColor::Cyan => Self::Cyan,
            TuiColor::Gray => Self::Gray,
            TuiColor::DarkGray => Self::DarkGray,
            TuiColor::LightRed => Self::LightRed,
            TuiColor::LightGreen => Self::LightGreen,
            TuiColor::LightYellow => Self::LightYellow,
            TuiColor::LightBlue => Self::LightBlue,
            TuiColor::LightMagenta => Self::LightMagenta,
            TuiColor::LightCyan => Self::LightCyan,
            TuiColor::White => Self::White,
            TuiColor::Rgb(r, g, b) => Self::Rgb(r, g, b),
        }
    }
}

pub fn fmt_color(color: Color) -> String {
    match color {
        Color::Black => "black".to_string(),
        Color::Red => "red".to_string(),
        Color::Green => "green".to_string(),
        Color::Yellow => "yellow".to_string(),
        Color::Blue => "blue".to_string(),
        Color::Magenta => "magenta".to_string(),
        Color::Cyan => "cyan".to_string(),
        Color::Gray => "gray".to_string(),
        Color::DarkGray => "darkgray".to_string(),
        Color::LightRed => "lightred".to_string(),
        Color::LightGreen => "lightgreen".to_string(),
        Color::LightYellow => "lightyellow".to_string(),
        Color::LightBlue => "lightblue".to_string(),
        Color::LightMagenta => "lightmagenta".to_string(),
        Color::LightCyan => "lightcyan".to_string(),
        Color::White => "white".to_string(),
        Color::Rgb(r, g, b) => format!("{r:02x}{g:02x}{b:02x}"),
        _ => "unknown".to_string(),
    }
}
