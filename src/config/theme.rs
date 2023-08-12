use crate::config::file::ConfigThemeColors;
use anyhow::anyhow;
use serde::Deserialize;
use std::collections::HashMap;
use strum::{EnumString, EnumVariantNames};

/// Tui color theme.
#[derive(Debug, Clone, Copy)]
pub struct TuiTheme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    pub bg_color: TuiColor,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    pub border_color: TuiColor,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    pub text_color: TuiColor,
    /// The color of the text in traces tabs.
    pub tab_text_color: TuiColor,
    /// The background color of the hops table header.
    pub hops_table_header_bg_color: TuiColor,
    /// The color of text in the hops table header.
    pub hops_table_header_text_color: TuiColor,
    /// The color of text of active rows in the hops table.
    pub hops_table_row_active_text_color: TuiColor,
    /// The color of text of inactive rows in the hops table.
    pub hops_table_row_inactive_text_color: TuiColor,
    /// The color of the selected series in the hops chart.
    pub hops_chart_selected_color: TuiColor,
    /// The color of the unselected series in the hops chart.
    pub hops_chart_unselected_color: TuiColor,
    /// The color of the axis in the hops chart.
    pub hops_chart_axis_color: TuiColor,
    /// The color of bars in the frequency chart.
    pub frequency_chart_bar_color: TuiColor,
    /// The color of text in the bars of the frequency chart.
    pub frequency_chart_text_color: TuiColor,
    /// The color of the samples chart.
    pub samples_chart_color: TuiColor,
    /// The background color of the help dialog.
    pub help_dialog_bg_color: TuiColor,
    /// The color of the text in the help dialog.
    pub help_dialog_text_color: TuiColor,
    /// The background color of the settings dialog.
    pub settings_dialog_bg_color: TuiColor,
    /// The color of the text in settings dialog tabs.
    pub settings_tab_text_color: TuiColor,
    /// The color of text in the settings table header.
    pub settings_table_header_text_color: TuiColor,
    /// The background color of the settings table header.
    pub settings_table_header_bg_color: TuiColor,
    /// The color of text of rows in the settings table.
    pub settings_table_row_text_color: TuiColor,
    /// The color of the map world diagram.
    pub map_world_color: TuiColor,
    /// The color of the map accuracy radius circle.
    pub map_radius_color: TuiColor,
    /// The color of the map selected item box.
    pub map_selected_color: TuiColor,
    /// The color of border of the map info panel.
    pub map_info_panel_border_color: TuiColor,
    /// The background color of the map info panel.
    pub map_info_panel_bg_color: TuiColor,
    /// The color of text in the map info panel.
    pub map_info_panel_text_color: TuiColor,
}

impl From<(HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)> for TuiTheme {
    #[allow(clippy::too_many_lines)]
    fn from(value: (HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)) -> Self {
        let (color_map, cfg) = value;
        Self {
            bg_color: *color_map
                .get(&TuiThemeItem::BgColor)
                .or(cfg.bg_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            border_color: *color_map
                .get(&TuiThemeItem::BorderColor)
                .or(cfg.border_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            text_color: *color_map
                .get(&TuiThemeItem::TextColor)
                .or(cfg.text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            tab_text_color: *color_map
                .get(&TuiThemeItem::TabTextColor)
                .or(cfg.tab_text_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            hops_table_header_bg_color: *color_map
                .get(&TuiThemeItem::HopsTableHeaderBgColor)
                .or(cfg.hops_table_header_bg_color.as_ref())
                .unwrap_or(&TuiColor::White),
            hops_table_header_text_color: *color_map
                .get(&TuiThemeItem::HopsTableHeaderTextColor)
                .or(cfg.hops_table_header_text_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            hops_table_row_active_text_color: *color_map
                .get(&TuiThemeItem::HopsTableRowActiveTextColor)
                .or(cfg.hops_table_row_active_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            hops_table_row_inactive_text_color: *color_map
                .get(&TuiThemeItem::HopsTableRowInactiveTextColor)
                .or(cfg.hops_table_row_inactive_text_color.as_ref())
                .unwrap_or(&TuiColor::DarkGray),
            hops_chart_selected_color: *color_map
                .get(&TuiThemeItem::HopsChartSelectedColor)
                .or(cfg.hops_chart_selected_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            hops_chart_unselected_color: *color_map
                .get(&TuiThemeItem::HopsChartUnselectedColor)
                .or(cfg.hops_chart_unselected_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            hops_chart_axis_color: *color_map
                .get(&TuiThemeItem::HopsChartAxisColor)
                .or(cfg.hops_chart_axis_color.as_ref())
                .unwrap_or(&TuiColor::DarkGray),
            frequency_chart_bar_color: *color_map
                .get(&TuiThemeItem::FrequencyChartBarColor)
                .or(cfg.frequency_chart_bar_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            frequency_chart_text_color: *color_map
                .get(&TuiThemeItem::FrequencyChartTextColor)
                .or(cfg.frequency_chart_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            samples_chart_color: *color_map
                .get(&TuiThemeItem::SamplesChartColor)
                .or(cfg.samples_chart_color.as_ref())
                .unwrap_or(&TuiColor::Yellow),
            help_dialog_bg_color: *color_map
                .get(&TuiThemeItem::HelpDialogBgColor)
                .or(cfg.help_dialog_bg_color.as_ref())
                .unwrap_or(&TuiColor::Blue),
            help_dialog_text_color: *color_map
                .get(&TuiThemeItem::HelpDialogTextColor)
                .or(cfg.help_dialog_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            settings_dialog_bg_color: *color_map
                .get(&TuiThemeItem::SettingsDialogBgColor)
                .or(cfg.settings_dialog_bg_color.as_ref())
                .unwrap_or(&TuiColor::Blue),
            settings_tab_text_color: *color_map
                .get(&TuiThemeItem::SettingsTabTextColor)
                .or(cfg.settings_tab_text_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            settings_table_header_text_color: *color_map
                .get(&TuiThemeItem::SettingsTableHeaderTextColor)
                .or(cfg.settings_table_header_text_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            settings_table_header_bg_color: *color_map
                .get(&TuiThemeItem::SettingsTableHeaderBgColor)
                .or(cfg.settings_table_header_bg_color.as_ref())
                .unwrap_or(&TuiColor::White),
            settings_table_row_text_color: *color_map
                .get(&TuiThemeItem::SettingsTableRowTextColor)
                .or(cfg.settings_table_row_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            map_world_color: *color_map
                .get(&TuiThemeItem::MapWorldColor)
                .or(cfg.map_world_color.as_ref())
                .unwrap_or(&TuiColor::White),
            map_radius_color: *color_map
                .get(&TuiThemeItem::MapRadiusColor)
                .or(cfg.map_radius_color.as_ref())
                .unwrap_or(&TuiColor::Yellow),
            map_selected_color: *color_map
                .get(&TuiThemeItem::MapSelectedColor)
                .or(cfg.map_selected_color.as_ref())
                .unwrap_or(&TuiColor::Green),
            map_info_panel_border_color: *color_map
                .get(&TuiThemeItem::MapInfoPanelBorderColor)
                .or(cfg.map_info_panel_border_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
            map_info_panel_bg_color: *color_map
                .get(&TuiThemeItem::MapInfoPanelBgColor)
                .or(cfg.map_info_panel_bg_color.as_ref())
                .unwrap_or(&TuiColor::Black),
            map_info_panel_text_color: *color_map
                .get(&TuiThemeItem::MapInfoPanelTextColor)
                .or(cfg.map_info_panel_text_color.as_ref())
                .unwrap_or(&TuiColor::Gray),
        }
    }
}

/// A TUI theme item.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
pub enum TuiThemeItem {
    /// The default background color.
    BgColor,
    /// The default color of borders.
    BorderColor,
    /// The default color of text.
    TextColor,
    /// The color of the text in traces tabs.
    TabTextColor,
    /// The background color of the hops table header.
    HopsTableHeaderBgColor,
    /// The color of text in the hops table header.
    HopsTableHeaderTextColor,
    /// The color of text of active rows in the hops table.
    HopsTableRowActiveTextColor,
    /// The color of text of inactive rows in the hops table.
    HopsTableRowInactiveTextColor,
    /// The color of the selected series in the hops chart.
    HopsChartSelectedColor,
    /// The color of the unselected series in the hops chart.
    HopsChartUnselectedColor,
    /// The color of the axis in the hops chart.
    HopsChartAxisColor,
    /// The color of bars in the frequency chart.
    FrequencyChartBarColor,
    /// The color of text in the bars of the frequency chart.
    FrequencyChartTextColor,
    /// The color of the samples chart.
    SamplesChartColor,
    /// The background color of the help dialog.
    HelpDialogBgColor,
    /// The color of the text in the help dialog.
    HelpDialogTextColor,
    /// The color of the text in settings tabs.
    SettingsTabTextColor,
    /// The background color of the settings dialog.
    SettingsDialogBgColor,
    /// The color of text in the settings table header.
    SettingsTableHeaderTextColor,
    /// The background color of the settings table header.
    SettingsTableHeaderBgColor,
    /// The color of text of rows in the settings table.
    SettingsTableRowTextColor,
    /// The color of the map world diagram.
    MapWorldColor,
    /// The color of the map accuracy radius circle.
    MapRadiusColor,
    /// The color of the map selected item box.
    MapSelectedColor,
    /// The color of border of the map info panel.
    MapInfoPanelBorderColor,
    /// The background color of the map info panel.
    MapInfoPanelBgColor,
    /// The color of text in the map info panel.
    MapInfoPanelTextColor,
}

/// A TUI color.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
pub enum TuiColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Gray,
    DarkGray,
    LightRed,
    LightGreen,
    LightYellow,
    LightBlue,
    LightMagenta,
    LightCyan,
    White,
    Rgb(u8, u8, u8),
}

impl TryFrom<String> for TuiColor {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for TuiColor {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().replace('-', "").as_ref() {
            "black" => Ok(Self::Black),
            "red" => Ok(Self::Red),
            "green" => Ok(Self::Green),
            "yellow" => Ok(Self::Yellow),
            "blue" => Ok(Self::Blue),
            "magenta" => Ok(Self::Magenta),
            "cyan" => Ok(Self::Cyan),
            "gray" => Ok(Self::Gray),
            "darkgray" => Ok(Self::DarkGray),
            "lightred" => Ok(Self::LightRed),
            "lightgreen" => Ok(Self::LightGreen),
            "lightyellow" => Ok(Self::LightYellow),
            "lightblue" => Ok(Self::LightBlue),
            "lightmagenta" => Ok(Self::LightMagenta),
            "lightcyan" => Ok(Self::LightCyan),
            "white" => Ok(Self::White),
            rgb_hex if value.len() == 6 && value.chars().all(|c| c.is_ascii_hexdigit()) => {
                let red = u8::from_str_radix(&rgb_hex[0..2], 16)?;
                let green = u8::from_str_radix(&rgb_hex[2..4], 16)?;
                let blue = u8::from_str_radix(&rgb_hex[4..6], 16)?;
                Ok(Self::Rgb(red, green, blue))
            }
            _ => Err(anyhow!("unknown color: {value}")),
        }
    }
}
