use crate::config::file::ConfigThemeColors;
use anyhow::anyhow;
use serde::Deserialize;
use std::collections::HashMap;
use strum::{EnumString, VariantNames};

/// Tui color theme.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TuiTheme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    pub bg: TuiColor,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    pub border: TuiColor,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    pub text: TuiColor,
    /// The color of the text in traces tabs.
    pub tab_text: TuiColor,
    /// The background color of the hops table header.
    pub hops_table_header_bg: TuiColor,
    /// The color of text in the hops table header.
    pub hops_table_header_text: TuiColor,
    /// The color of text of active rows in the hops table.
    pub hops_table_row_active_text: TuiColor,
    /// The color of text of inactive rows in the hops table.
    pub hops_table_row_inactive_text: TuiColor,
    /// The color of the selected series in the hops chart.
    pub hops_chart_selected: TuiColor,
    /// The color of the unselected series in the hops chart.
    pub hops_chart_unselected: TuiColor,
    /// The color of the axis in the hops chart.
    pub hops_chart_axis: TuiColor,
    /// The color of bars in the frequency chart.
    pub frequency_chart_bar: TuiColor,
    /// The color of text in the bars of the frequency chart.
    pub frequency_chart_text: TuiColor,
    /// The color of the selected flow bar in the flows chart.
    pub flows_chart_bar_selected: TuiColor,
    /// The color of the unselected flow bar in the flows chart.
    pub flows_chart_bar_unselected: TuiColor,
    /// The color of the current flow text in the flows chart.
    pub flows_chart_text_current: TuiColor,
    /// The color of the non-current flow text in the flows chart.
    pub flows_chart_text_non_current: TuiColor,
    /// The color of the samples chart.
    pub samples_chart: TuiColor,
    /// The color of the samples chart for lost probes.
    pub samples_chart_lost: TuiColor,
    /// The background color of the help dialog.
    pub help_dialog_bg: TuiColor,
    /// The color of the text in the help dialog.
    pub help_dialog_text: TuiColor,
    /// The background color of the settings dialog.
    pub settings_dialog_bg: TuiColor,
    /// The color of the text in settings dialog tabs.
    pub settings_tab_text: TuiColor,
    /// The color of text in the settings table header.
    pub settings_table_header_text: TuiColor,
    /// The background color of the settings table header.
    pub settings_table_header_bg: TuiColor,
    /// The color of text of rows in the settings table.
    pub settings_table_row_text: TuiColor,
    /// The color of the map world diagram.
    pub map_world: TuiColor,
    /// The color of the map accuracy radius circle.
    pub map_radius: TuiColor,
    /// The color of the map selected item box.
    pub map_selected: TuiColor,
    /// The color of border of the map info panel.
    pub map_info_panel_border: TuiColor,
    /// The background color of the map info panel.
    pub map_info_panel_bg: TuiColor,
    /// The color of text in the map info panel.
    pub map_info_panel_text: TuiColor,
    /// The color of the dynamic bar background.
    pub dynamic_bar_bg: TuiColor,
    /// The color of the dynamic bar text.
    pub dynamic_bar_text: TuiColor,
}

impl Default for TuiTheme {
    fn default() -> Self {
        Self {
            bg: TuiColor::Black,
            border: TuiColor::Gray,
            text: TuiColor::Gray,
            tab_text: TuiColor::Green,
            hops_table_header_bg: TuiColor::White,
            hops_table_header_text: TuiColor::Black,
            hops_table_row_active_text: TuiColor::Gray,
            hops_table_row_inactive_text: TuiColor::DarkGray,
            hops_chart_selected: TuiColor::Green,
            hops_chart_unselected: TuiColor::Gray,
            hops_chart_axis: TuiColor::DarkGray,
            frequency_chart_bar: TuiColor::Green,
            frequency_chart_text: TuiColor::Gray,
            flows_chart_bar_selected: TuiColor::Green,
            flows_chart_bar_unselected: TuiColor::DarkGray,
            flows_chart_text_current: TuiColor::LightGreen,
            flows_chart_text_non_current: TuiColor::White,
            samples_chart: TuiColor::Yellow,
            samples_chart_lost: TuiColor::Red,
            help_dialog_bg: TuiColor::Blue,
            help_dialog_text: TuiColor::Gray,
            settings_dialog_bg: TuiColor::Blue,
            settings_tab_text: TuiColor::Green,
            settings_table_header_text: TuiColor::Black,
            settings_table_header_bg: TuiColor::White,
            settings_table_row_text: TuiColor::Gray,
            map_world: TuiColor::White,
            map_radius: TuiColor::Yellow,
            map_selected: TuiColor::Green,
            map_info_panel_border: TuiColor::Gray,
            map_info_panel_bg: TuiColor::Black,
            map_info_panel_text: TuiColor::Gray,
            dynamic_bar_bg: TuiColor::White,
            dynamic_bar_text: TuiColor::Black,
        }
    }
}

impl From<(HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)> for TuiTheme {
    #[allow(clippy::too_many_lines)]
    fn from(value: (HashMap<TuiThemeItem, TuiColor>, ConfigThemeColors)) -> Self {
        let (color_map, cfg) = value;
        Self {
            bg: *color_map
                .get(&TuiThemeItem::BgColor)
                .or(cfg.bg_color.as_ref())
                .unwrap_or(&Self::default().bg),
            border: *color_map
                .get(&TuiThemeItem::BorderColor)
                .or(cfg.border_color.as_ref())
                .unwrap_or(&Self::default().border),
            text: *color_map
                .get(&TuiThemeItem::TextColor)
                .or(cfg.text_color.as_ref())
                .unwrap_or(&Self::default().text),
            tab_text: *color_map
                .get(&TuiThemeItem::TabTextColor)
                .or(cfg.tab_text_color.as_ref())
                .unwrap_or(&Self::default().tab_text),
            hops_table_header_bg: *color_map
                .get(&TuiThemeItem::HopsTableHeaderBgColor)
                .or(cfg.hops_table_header_bg_color.as_ref())
                .unwrap_or(&Self::default().hops_table_header_bg),
            hops_table_header_text: *color_map
                .get(&TuiThemeItem::HopsTableHeaderTextColor)
                .or(cfg.hops_table_header_text_color.as_ref())
                .unwrap_or(&Self::default().hops_table_header_text),
            hops_table_row_active_text: *color_map
                .get(&TuiThemeItem::HopsTableRowActiveTextColor)
                .or(cfg.hops_table_row_active_text_color.as_ref())
                .unwrap_or(&Self::default().hops_table_row_active_text),
            hops_table_row_inactive_text: *color_map
                .get(&TuiThemeItem::HopsTableRowInactiveTextColor)
                .or(cfg.hops_table_row_inactive_text_color.as_ref())
                .unwrap_or(&Self::default().hops_table_row_inactive_text),
            hops_chart_selected: *color_map
                .get(&TuiThemeItem::HopsChartSelectedColor)
                .or(cfg.hops_chart_selected_color.as_ref())
                .unwrap_or(&Self::default().hops_chart_selected),
            hops_chart_unselected: *color_map
                .get(&TuiThemeItem::HopsChartUnselectedColor)
                .or(cfg.hops_chart_unselected_color.as_ref())
                .unwrap_or(&Self::default().hops_chart_unselected),
            hops_chart_axis: *color_map
                .get(&TuiThemeItem::HopsChartAxisColor)
                .or(cfg.hops_chart_axis_color.as_ref())
                .unwrap_or(&Self::default().hops_chart_axis),
            frequency_chart_bar: *color_map
                .get(&TuiThemeItem::FrequencyChartBarColor)
                .or(cfg.frequency_chart_bar_color.as_ref())
                .unwrap_or(&Self::default().frequency_chart_bar),
            frequency_chart_text: *color_map
                .get(&TuiThemeItem::FrequencyChartTextColor)
                .or(cfg.frequency_chart_text_color.as_ref())
                .unwrap_or(&Self::default().frequency_chart_text),
            flows_chart_bar_selected: *color_map
                .get(&TuiThemeItem::FlowsChartBarSelectedColor)
                .or(cfg.flows_chart_bar_selected_color.as_ref())
                .unwrap_or(&Self::default().flows_chart_bar_selected),
            flows_chart_bar_unselected: *color_map
                .get(&TuiThemeItem::FlowsChartBarUnselectedColor)
                .or(cfg.flows_chart_bar_unselected_color.as_ref())
                .unwrap_or(&Self::default().flows_chart_bar_unselected),
            flows_chart_text_current: *color_map
                .get(&TuiThemeItem::FlowsChartTextCurrentColor)
                .or(cfg.flows_chart_text_current_color.as_ref())
                .unwrap_or(&Self::default().flows_chart_text_current),
            flows_chart_text_non_current: *color_map
                .get(&TuiThemeItem::FlowsChartTextNonCurrentColor)
                .or(cfg.flows_chart_text_non_current_color.as_ref())
                .unwrap_or(&Self::default().flows_chart_text_non_current),
            samples_chart: *color_map
                .get(&TuiThemeItem::SamplesChartColor)
                .or(cfg.samples_chart_color.as_ref())
                .unwrap_or(&Self::default().samples_chart),
            samples_chart_lost: *color_map
                .get(&TuiThemeItem::SamplesChartLostColor)
                .or(cfg.samples_chart_lost_color.as_ref())
                .unwrap_or(&Self::default().samples_chart_lost),
            help_dialog_bg: *color_map
                .get(&TuiThemeItem::HelpDialogBgColor)
                .or(cfg.help_dialog_bg_color.as_ref())
                .unwrap_or(&Self::default().help_dialog_bg),
            help_dialog_text: *color_map
                .get(&TuiThemeItem::HelpDialogTextColor)
                .or(cfg.help_dialog_text_color.as_ref())
                .unwrap_or(&Self::default().help_dialog_text),
            settings_dialog_bg: *color_map
                .get(&TuiThemeItem::SettingsDialogBgColor)
                .or(cfg.settings_dialog_bg_color.as_ref())
                .unwrap_or(&Self::default().settings_dialog_bg),
            settings_tab_text: *color_map
                .get(&TuiThemeItem::SettingsTabTextColor)
                .or(cfg.settings_tab_text_color.as_ref())
                .unwrap_or(&Self::default().settings_tab_text),
            settings_table_header_text: *color_map
                .get(&TuiThemeItem::SettingsTableHeaderTextColor)
                .or(cfg.settings_table_header_text_color.as_ref())
                .unwrap_or(&Self::default().settings_table_header_text),
            settings_table_header_bg: *color_map
                .get(&TuiThemeItem::SettingsTableHeaderBgColor)
                .or(cfg.settings_table_header_bg_color.as_ref())
                .unwrap_or(&Self::default().settings_table_header_bg),
            settings_table_row_text: *color_map
                .get(&TuiThemeItem::SettingsTableRowTextColor)
                .or(cfg.settings_table_row_text_color.as_ref())
                .unwrap_or(&Self::default().settings_table_row_text),
            map_world: *color_map
                .get(&TuiThemeItem::MapWorldColor)
                .or(cfg.map_world_color.as_ref())
                .unwrap_or(&Self::default().map_world),
            map_radius: *color_map
                .get(&TuiThemeItem::MapRadiusColor)
                .or(cfg.map_radius_color.as_ref())
                .unwrap_or(&Self::default().map_radius),
            map_selected: *color_map
                .get(&TuiThemeItem::MapSelectedColor)
                .or(cfg.map_selected_color.as_ref())
                .unwrap_or(&Self::default().map_selected),
            map_info_panel_border: *color_map
                .get(&TuiThemeItem::MapInfoPanelBorderColor)
                .or(cfg.map_info_panel_border_color.as_ref())
                .unwrap_or(&Self::default().map_info_panel_border),
            map_info_panel_bg: *color_map
                .get(&TuiThemeItem::MapInfoPanelBgColor)
                .or(cfg.map_info_panel_bg_color.as_ref())
                .unwrap_or(&Self::default().map_info_panel_bg),
            map_info_panel_text: *color_map
                .get(&TuiThemeItem::MapInfoPanelTextColor)
                .or(cfg.map_info_panel_text_color.as_ref())
                .unwrap_or(&Self::default().map_info_panel_text),
            dynamic_bar_bg: *color_map
                .get(&TuiThemeItem::DynamicBarBgColor)
                .or(cfg.dynamic_bar_bg_color.as_ref())
                .unwrap_or(&Self::default().dynamic_bar_bg),
            dynamic_bar_text: *color_map
                .get(&TuiThemeItem::DynamicBarTextColor)
                .or(cfg.dynamic_bar_text_color.as_ref())
                .unwrap_or(&Self::default().dynamic_bar_text),
        }
    }
}

/// A TUI theme item.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, VariantNames)]
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
    /// The color of the selected flow bar in the flows chart.
    FlowsChartBarSelectedColor,
    /// The color of the unselected flow bar in the flows chart.
    FlowsChartBarUnselectedColor,
    /// The color of the current flow text in the flows chart.
    FlowsChartTextCurrentColor,
    /// The color of the non-current flow text in the flows chart.
    FlowsChartTextNonCurrentColor,
    /// The color of the samples chart.
    SamplesChartColor,
    /// The color of the samples chart for lost probes.
    SamplesChartLostColor,
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
    /// The color of the dynamic bar background.
    DynamicBarBgColor,
    /// The color of the dynamic bar text.
    DynamicBarTextColor,
}

/// A TUI color.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub enum TuiColor {
    // ANSI colors
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
    // Other colors
    AliceBlue,
    AntiqueWhite,
    Aqua,
    Aquamarine,
    Azure,
    Beige,
    Bisque,
    BlanchedAlmond,
    BlueViolet,
    Brown,
    BurlyWood,
    CadetBlue,
    Chartreuse,
    Chocolate,
    Coral,
    CornflowerBlue,
    CornSilk,
    Crimson,
    DarkBlue,
    DarkCyan,
    DarkGoldenrod,
    DarkGreen,
    DarkKhaki,
    DarkMagenta,
    DarkOliveGreen,
    DarkOrange,
    DarkOrchid,
    DarkRed,
    DarkSalmon,
    DarkSeaGreen,
    DarkSlateBlue,
    DarkSlateGray,
    DarkTurquoise,
    DarkViolet,
    DeepPink,
    DeepSkyBlue,
    DimGray,
    DodgerBlue,
    Firebrick,
    FloralWhite,
    ForestGreen,
    Fuchsia,
    Gainsboro,
    GhostWhite,
    Gold,
    Goldenrod,
    GreenYellow,
    Honeydew,
    HotPink,
    IndianRed,
    Indigo,
    Ivory,
    Khaki,
    Lavender,
    LavenderBlush,
    LawnGreen,
    LemonChiffon,
    LightCoral,
    LightGoldenrodYellow,
    LightGray,
    LightPink,
    LightSalmon,
    LightSeaGreen,
    LightSkyBlue,
    LightSlateGray,
    LightSteelBlue,
    Lime,
    LimeGreen,
    Linen,
    Maroon,
    MediumAquamarine,
    MediumBlue,
    MediumOrchid,
    MediumPurple,
    MediumSeaGreen,
    MediumSlateBlue,
    MediumSpringGreen,
    MediumTurquoise,
    MediumVioletRed,
    MidnightBlue,
    MintCream,
    MistyRose,
    Moccasin,
    NavajoWhite,
    Navy,
    OldLace,
    Olive,
    OliveDrab,
    Orange,
    OrangeRed,
    Orchid,
    PaleGoldenrod,
    PaleGreen,
    PaleTurquoise,
    PaleVioletRed,
    PapayaWhip,
    PeachPuff,
    Peru,
    Pink,
    Plum,
    PowderBlue,
    Purple,
    RebeccaPurple,
    RosyBrown,
    RoyalBlue,
    SaddleBrown,
    Salmon,
    SandyBrown,
    SeaGreen,
    SeaShell,
    Sienna,
    Silver,
    SkyBlue,
    SlateBlue,
    SlateGray,
    Snow,
    SpringGreen,
    SteelBlue,
    Tan,
    Teal,
    Thistle,
    Tomato,
    Turquoise,
    Violet,
    Wheat,
    WhiteSmoke,
    YellowGreen,
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

    #[allow(clippy::too_many_lines)]
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
            "aliceblue" => Ok(Self::AliceBlue),
            "antiquewhite" => Ok(Self::AntiqueWhite),
            "aqua" => Ok(Self::Aqua),
            "aquamarine" => Ok(Self::Aquamarine),
            "azure" => Ok(Self::Azure),
            "beige" => Ok(Self::Beige),
            "bisque" => Ok(Self::Bisque),
            "blanchedalmond" => Ok(Self::BlanchedAlmond),
            "blueviolet" => Ok(Self::BlueViolet),
            "brown" => Ok(Self::Brown),
            "burlywood" => Ok(Self::BurlyWood),
            "cadetblue" => Ok(Self::CadetBlue),
            "chartreuse" => Ok(Self::Chartreuse),
            "chocolate" => Ok(Self::Chocolate),
            "coral" => Ok(Self::Coral),
            "cornflowerblue" => Ok(Self::CornflowerBlue),
            "cornsilk" => Ok(Self::CornSilk),
            "crimson" => Ok(Self::Crimson),
            "darkblue" => Ok(Self::DarkBlue),
            "darkcyan" => Ok(Self::DarkCyan),
            "darkgoldenrod" => Ok(Self::DarkGoldenrod),
            "darkgreen" => Ok(Self::DarkGreen),
            "darkkhaki" => Ok(Self::DarkKhaki),
            "darkmagenta" => Ok(Self::DarkMagenta),
            "darkolivegreen" => Ok(Self::DarkOliveGreen),
            "darkorange" => Ok(Self::DarkOrange),
            "darkorchid" => Ok(Self::DarkOrchid),
            "darkred" => Ok(Self::DarkRed),
            "darksalmon" => Ok(Self::DarkSalmon),
            "darkseagreen" => Ok(Self::DarkSeaGreen),
            "darkslateblue" => Ok(Self::DarkSlateBlue),
            "darkslategray" | "darkslategrey" => Ok(Self::DarkSlateGray),
            "darkturquoise" => Ok(Self::DarkTurquoise),
            "darkviolet" => Ok(Self::DarkViolet),
            "deeppink" => Ok(Self::DeepPink),
            "deepskyblue" => Ok(Self::DeepSkyBlue),
            "dimgray" | "dimgrey" => Ok(Self::DimGray),
            "dodgerblue" => Ok(Self::DodgerBlue),
            "firebrick" => Ok(Self::Firebrick),
            "floralwhite" => Ok(Self::FloralWhite),
            "forestgreen" => Ok(Self::ForestGreen),
            "fuchsia" => Ok(Self::Fuchsia),
            "gainsboro" => Ok(Self::Gainsboro),
            "ghostwhite" => Ok(Self::GhostWhite),
            "gold" => Ok(Self::Gold),
            "goldenrod" => Ok(Self::Goldenrod),
            "greenyellow" => Ok(Self::GreenYellow),
            "honeydew" => Ok(Self::Honeydew),
            "hotpink" => Ok(Self::HotPink),
            "indianred" => Ok(Self::IndianRed),
            "indigo" => Ok(Self::Indigo),
            "ivory" => Ok(Self::Ivory),
            "khaki" => Ok(Self::Khaki),
            "lavender" => Ok(Self::Lavender),
            "lavenderblush" => Ok(Self::LavenderBlush),
            "lawngreen" => Ok(Self::LawnGreen),
            "lemonchiffon" => Ok(Self::LemonChiffon),
            "lightcoral" => Ok(Self::LightCoral),
            "lightgoldenrodyellow" => Ok(Self::LightGoldenrodYellow),
            "lightgray" | "lightgrey" => Ok(Self::LightGray),
            "lightpink" => Ok(Self::LightPink),
            "lightsalmon" => Ok(Self::LightSalmon),
            "lightseagreen" => Ok(Self::LightSeaGreen),
            "lightskyblue" => Ok(Self::LightSkyBlue),
            "lightslategray" | "lightslategrey" => Ok(Self::LightSlateGray),
            "lightsteelblue" => Ok(Self::LightSteelBlue),
            "lime" => Ok(Self::Lime),
            "limegreen" => Ok(Self::LimeGreen),
            "linen" => Ok(Self::Linen),
            "maroon" => Ok(Self::Maroon),
            "mediumaquamarine" => Ok(Self::MediumAquamarine),
            "mediumblue" => Ok(Self::MediumBlue),
            "mediumorchid" => Ok(Self::MediumOrchid),
            "mediumpurple" => Ok(Self::MediumPurple),
            "mediumseagreen" => Ok(Self::MediumSeaGreen),
            "mediumslateblue" => Ok(Self::MediumSlateBlue),
            "mediumspringgreen" => Ok(Self::MediumSpringGreen),
            "mediumturquoise" => Ok(Self::MediumTurquoise),
            "mediumvioletred" => Ok(Self::MediumVioletRed),
            "midnightblue" => Ok(Self::MidnightBlue),
            "mintcream" => Ok(Self::MintCream),
            "mistyrose" => Ok(Self::MistyRose),
            "moccasin" => Ok(Self::Moccasin),
            "navajowhite" => Ok(Self::NavajoWhite),
            "navy" => Ok(Self::Navy),
            "oldlace" => Ok(Self::OldLace),
            "olive" => Ok(Self::Olive),
            "olivedrab" => Ok(Self::OliveDrab),
            "orange" => Ok(Self::Orange),
            "orangered" => Ok(Self::OrangeRed),
            "orchid" => Ok(Self::Orchid),
            "palegoldenrod" => Ok(Self::PaleGoldenrod),
            "palegreen" => Ok(Self::PaleGreen),
            "paleturquoise" => Ok(Self::PaleTurquoise),
            "palevioletred" => Ok(Self::PaleVioletRed),
            "papayawhip" => Ok(Self::PapayaWhip),
            "peachpuff" => Ok(Self::PeachPuff),
            "peru" => Ok(Self::Peru),
            "pink" => Ok(Self::Pink),
            "plum" => Ok(Self::Plum),
            "powderblue" => Ok(Self::PowderBlue),
            "purple" => Ok(Self::Purple),
            "rebeccapurple" => Ok(Self::RebeccaPurple),
            "rosybrown" => Ok(Self::RosyBrown),
            "royalblue" => Ok(Self::RoyalBlue),
            "saddlebrown" => Ok(Self::SaddleBrown),
            "salmon" => Ok(Self::Salmon),
            "sandybrown" => Ok(Self::SandyBrown),
            "seagreen" => Ok(Self::SeaGreen),
            "seashell" => Ok(Self::SeaShell),
            "sienna" => Ok(Self::Sienna),
            "silver" => Ok(Self::Silver),
            "skyblue" => Ok(Self::SkyBlue),
            "slateblue" => Ok(Self::SlateBlue),
            "slategray" | "slategrey" => Ok(Self::SlateGray),
            "snow" => Ok(Self::Snow),
            "springgreen" => Ok(Self::SpringGreen),
            "steelblue" => Ok(Self::SteelBlue),
            "tan" => Ok(Self::Tan),
            "teal" => Ok(Self::Teal),
            "thistle" => Ok(Self::Thistle),
            "tomato" => Ok(Self::Tomato),
            "turquoise" => Ok(Self::Turquoise),
            "violet" => Ok(Self::Violet),
            "wheat" => Ok(Self::Wheat),
            "whitesmoke" => Ok(Self::WhiteSmoke),
            "yellowgreen" => Ok(Self::YellowGreen),
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
