use crate::config::constants::DEFAULT_TUI_THEME;
use crate::config::file::ConfigThemeColors;
use crate::config::theme::named::NamedThemes;
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
    /// The background color of selected active rows in the hops table.
    pub hops_table_row_active_selected_bg: TuiColor,
    /// The color of text of selected active rows in the hops table.
    pub hops_table_row_active_selected_text: TuiColor,
    /// The background color of selected inactive rows in the hops table.
    pub hops_table_row_inactive_selected_bg: TuiColor,
    /// The color of text of selected inactive rows in the hops table.
    pub hops_table_row_inactive_selected_text: TuiColor,
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
    /// The color of the info bar background.
    pub info_bar_bg: TuiColor,
    /// The color of the info bar text.
    pub info_bar_text: TuiColor,
}

impl Default for TuiTheme {
    // TODO: expect here
    fn default() -> Self {
        Self::from(
            NamedThemes::data()
                .get(DEFAULT_TUI_THEME)
                .expect("default theme"),
        )
    }
}

impl TuiTheme {
    pub fn for_name(name: &str) -> anyhow::Result<Self> {
        let base_theme = NamedThemes::data()
            .get(name)
            .ok_or_else(|| anyhow!("unknown theme '{name}'"))?;
        Ok(Self::from(base_theme))
    }

    pub fn available() -> Vec<&'static str> {
        NamedThemes::data().keys()
    }

    #[expect(clippy::too_many_lines)]
    pub fn overlay(mut self, colors: &ConfigThemeColors) -> Self {
        if let Some(color) = colors.bg_color {
            self.bg = color;
        }
        if let Some(color) = colors.border_color {
            self.border = color;
        }
        if let Some(color) = colors.text_color {
            self.text = color;
        }
        if let Some(color) = colors.tab_text_color {
            self.tab_text = color;
        }
        if let Some(color) = colors.hops_table_header_bg_color {
            self.hops_table_header_bg = color;
        }
        if let Some(color) = colors.hops_table_header_text_color {
            self.hops_table_header_text = color;
        }
        if let Some(color) = colors.hops_table_row_active_text_color {
            self.hops_table_row_active_text = color;
        }
        if let Some(color) = colors.hops_table_row_inactive_text_color {
            self.hops_table_row_inactive_text = color;
        }
        if let Some(color) = colors.hops_table_row_active_selected_bg_color {
            self.hops_table_row_active_selected_bg = color;
        }
        if let Some(color) = colors.hops_table_row_active_selected_text_color {
            self.hops_table_row_active_selected_text = color;
        }
        if let Some(color) = colors.hops_table_row_inactive_selected_bg_color {
            self.hops_table_row_inactive_selected_bg = color;
        }
        if let Some(color) = colors.hops_table_row_inactive_selected_text_color {
            self.hops_table_row_inactive_selected_text = color;
        }
        if let Some(color) = colors.hops_chart_selected_color {
            self.hops_chart_selected = color;
        }
        if let Some(color) = colors.hops_chart_unselected_color {
            self.hops_chart_unselected = color;
        }
        if let Some(color) = colors.hops_chart_axis_color {
            self.hops_chart_axis = color;
        }
        if let Some(color) = colors.frequency_chart_bar_color {
            self.frequency_chart_bar = color;
        }
        if let Some(color) = colors.frequency_chart_text_color {
            self.frequency_chart_text = color;
        }
        if let Some(color) = colors.flows_chart_bar_selected_color {
            self.flows_chart_bar_selected = color;
        }
        if let Some(color) = colors.flows_chart_bar_unselected_color {
            self.flows_chart_bar_unselected = color;
        }
        if let Some(color) = colors.flows_chart_text_current_color {
            self.flows_chart_text_current = color;
        }
        if let Some(color) = colors.flows_chart_text_non_current_color {
            self.flows_chart_text_non_current = color;
        }
        if let Some(color) = colors.samples_chart_color {
            self.samples_chart = color;
        }
        if let Some(color) = colors.samples_chart_lost_color {
            self.samples_chart_lost = color;
        }
        if let Some(color) = colors.help_dialog_bg_color {
            self.help_dialog_bg = color;
        }
        if let Some(color) = colors.help_dialog_text_color {
            self.help_dialog_text = color;
        }
        if let Some(color) = colors.settings_dialog_bg_color {
            self.settings_dialog_bg = color;
        }
        if let Some(color) = colors.settings_tab_text_color {
            self.settings_tab_text = color;
        }
        if let Some(color) = colors.settings_table_header_text_color {
            self.settings_table_header_text = color;
        }
        if let Some(color) = colors.settings_table_header_bg_color {
            self.settings_table_header_bg = color;
        }
        if let Some(color) = colors.settings_table_row_text_color {
            self.settings_table_row_text = color;
        }
        if let Some(color) = colors.map_world_color {
            self.map_world = color;
        }
        if let Some(color) = colors.map_radius_color {
            self.map_radius = color;
        }
        if let Some(color) = colors.map_selected_color {
            self.map_selected = color;
        }
        if let Some(color) = colors.map_info_panel_border_color {
            self.map_info_panel_border = color;
        }
        if let Some(color) = colors.map_info_panel_bg_color {
            self.map_info_panel_bg = color;
        }
        if let Some(color) = colors.map_info_panel_text_color {
            self.map_info_panel_text = color;
        }
        if let Some(color) = colors.info_bar_bg_color {
            self.info_bar_bg = color;
        }
        if let Some(color) = colors.info_bar_text_color {
            self.info_bar_text = color;
        }
        self
    }
}

impl From<HashMap<TuiThemeItem, TuiColor>> for ConfigThemeColors {
    fn from(value: HashMap<TuiThemeItem, TuiColor>) -> Self {
        Self {
            bg_color: value.get(&TuiThemeItem::BgColor).copied(),
            border_color: value.get(&TuiThemeItem::BorderColor).copied(),
            text_color: value.get(&TuiThemeItem::TextColor).copied(),
            tab_text_color: value.get(&TuiThemeItem::TabTextColor).copied(),
            hops_table_header_bg_color: value.get(&TuiThemeItem::HopsTableHeaderBgColor).copied(),
            hops_table_header_text_color: value
                .get(&TuiThemeItem::HopsTableHeaderTextColor)
                .copied(),
            hops_table_row_active_text_color: value
                .get(&TuiThemeItem::HopsTableRowActiveTextColor)
                .copied(),
            hops_table_row_inactive_text_color: value
                .get(&TuiThemeItem::HopsTableRowInactiveTextColor)
                .copied(),
            hops_table_row_active_selected_bg_color: value
                .get(&TuiThemeItem::HopsTableRowActiveSelectedBgColor)
                .copied(),
            hops_table_row_active_selected_text_color: value
                .get(&TuiThemeItem::HopsTableRowActiveSelectedTextColor)
                .copied(),
            hops_table_row_inactive_selected_bg_color: value
                .get(&TuiThemeItem::HopsTableRowInactiveSelectedBgColor)
                .copied(),
            hops_table_row_inactive_selected_text_color: value
                .get(&TuiThemeItem::HopsTableRowInactiveSelectedTextColor)
                .copied(),
            hops_chart_selected_color: value.get(&TuiThemeItem::HopsChartSelectedColor).copied(),
            hops_chart_unselected_color: value
                .get(&TuiThemeItem::HopsChartUnselectedColor)
                .copied(),
            hops_chart_axis_color: value.get(&TuiThemeItem::HopsChartAxisColor).copied(),
            frequency_chart_bar_color: value.get(&TuiThemeItem::FrequencyChartBarColor).copied(),
            frequency_chart_text_color: value.get(&TuiThemeItem::FrequencyChartTextColor).copied(),
            flows_chart_bar_selected_color: value
                .get(&TuiThemeItem::FlowsChartBarSelectedColor)
                .copied(),
            flows_chart_bar_unselected_color: value
                .get(&TuiThemeItem::FlowsChartBarUnselectedColor)
                .copied(),
            flows_chart_text_current_color: value
                .get(&TuiThemeItem::FlowsChartTextCurrentColor)
                .copied(),
            flows_chart_text_non_current_color: value
                .get(&TuiThemeItem::FlowsChartTextNonCurrentColor)
                .copied(),
            samples_chart_color: value.get(&TuiThemeItem::SamplesChartColor).copied(),
            samples_chart_lost_color: value.get(&TuiThemeItem::SamplesChartLostColor).copied(),
            help_dialog_bg_color: value.get(&TuiThemeItem::HelpDialogBgColor).copied(),
            help_dialog_text_color: value.get(&TuiThemeItem::HelpDialogTextColor).copied(),
            settings_dialog_bg_color: value.get(&TuiThemeItem::SettingsDialogBgColor).copied(),
            settings_tab_text_color: value.get(&TuiThemeItem::SettingsTabTextColor).copied(),
            settings_table_header_text_color: value
                .get(&TuiThemeItem::SettingsTableHeaderTextColor)
                .copied(),
            settings_table_header_bg_color: value
                .get(&TuiThemeItem::SettingsTableHeaderBgColor)
                .copied(),
            settings_table_row_text_color: value
                .get(&TuiThemeItem::SettingsTableRowTextColor)
                .copied(),
            map_world_color: value.get(&TuiThemeItem::MapWorldColor).copied(),
            map_radius_color: value.get(&TuiThemeItem::MapRadiusColor).copied(),
            map_selected_color: value.get(&TuiThemeItem::MapSelectedColor).copied(),
            map_info_panel_border_color: value.get(&TuiThemeItem::MapInfoPanelBorderColor).copied(),
            map_info_panel_bg_color: value.get(&TuiThemeItem::MapInfoPanelBgColor).copied(),
            map_info_panel_text_color: value.get(&TuiThemeItem::MapInfoPanelTextColor).copied(),
            info_bar_bg_color: value.get(&TuiThemeItem::InfoBarBgColor).copied(),
            info_bar_text_color: value.get(&TuiThemeItem::InfoBarTextColor).copied(),
        }
    }
}

mod named {
    use crate::config::TuiColor;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    macro_rules! named_themes {
        ($($name:literal),+ $(,)?) => {
            &[$(
                ($name, include_str!(concat!("../../themes/", $name, ".toml"))),
            )+]
        };
    }

    #[derive(Debug)]
    pub struct NamedThemes(BTreeMap<&'static str, TuiTheme>);

    impl NamedThemes {
        const NAMED_THEMES: &[(&str, &str)] = named_themes!(
            "trippy",
            "catppuccin-frappe",
            "catppuccin-latte",
            "catppuccin-macchiato",
            "catppuccin-mocha"
        );

        pub fn data() -> &'static Self {
            static DATA: OnceLock<NamedThemes> = OnceLock::new();
            DATA.get_or_init(Self::load)
        }

        pub fn keys(&self) -> Vec<&str> {
            self.0.keys().copied().collect()
        }

        pub fn get(&self, name: &str) -> Option<&TuiTheme> {
            self.0.get(name)
        }

        fn load() -> Self {
            let themes = Self::NAMED_THEMES
                .iter()
                .map(|(name, source)| {
                    let theme: TuiTheme = toml::from_str(source).unwrap_or_else(|err| {
                        // TODO panic here
                        panic!("Failed to parse embedded theme `{name}`: {err}")
                    });
                    (*name, theme)
                })
                .collect::<BTreeMap<_, _>>();
            Self(themes)
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    #[expect(clippy::struct_field_names)]
    pub struct TuiTheme {
        pub bg_color: TuiColor,
        pub border_color: TuiColor,
        pub text_color: TuiColor,
        pub tab_text_color: TuiColor,
        pub hops_table_header_bg_color: TuiColor,
        pub hops_table_header_text_color: TuiColor,
        pub hops_table_row_active_text_color: TuiColor,
        pub hops_table_row_inactive_text_color: TuiColor,
        pub hops_table_row_active_selected_bg_color: TuiColor,
        pub hops_table_row_active_selected_text_color: TuiColor,
        pub hops_table_row_inactive_selected_bg_color: TuiColor,
        pub hops_table_row_inactive_selected_text_color: TuiColor,
        pub hops_chart_selected_color: TuiColor,
        pub hops_chart_unselected_color: TuiColor,
        pub hops_chart_axis_color: TuiColor,
        pub frequency_chart_bar_color: TuiColor,
        pub frequency_chart_text_color: TuiColor,
        pub flows_chart_bar_selected_color: TuiColor,
        pub flows_chart_bar_unselected_color: TuiColor,
        pub flows_chart_text_current_color: TuiColor,
        pub flows_chart_text_non_current_color: TuiColor,
        pub samples_chart_color: TuiColor,
        pub samples_chart_lost_color: TuiColor,
        pub help_dialog_bg_color: TuiColor,
        pub help_dialog_text_color: TuiColor,
        pub settings_dialog_bg_color: TuiColor,
        pub settings_tab_text_color: TuiColor,
        pub settings_table_header_text_color: TuiColor,
        pub settings_table_header_bg_color: TuiColor,
        pub settings_table_row_text_color: TuiColor,
        pub map_world_color: TuiColor,
        pub map_radius_color: TuiColor,
        pub map_selected_color: TuiColor,
        pub map_info_panel_border_color: TuiColor,
        pub map_info_panel_bg_color: TuiColor,
        pub map_info_panel_text_color: TuiColor,
        pub info_bar_bg_color: TuiColor,
        pub info_bar_text_color: TuiColor,
    }

    impl From<&TuiTheme> for super::TuiTheme {
        fn from(value: &TuiTheme) -> Self {
            Self {
                bg: value.bg_color,
                border: value.border_color,
                text: value.text_color,
                tab_text: value.tab_text_color,
                hops_table_header_bg: value.hops_table_header_bg_color,
                hops_table_header_text: value.hops_table_header_text_color,
                hops_table_row_active_text: value.hops_table_row_active_text_color,
                hops_table_row_inactive_text: value.hops_table_row_inactive_text_color,
                hops_table_row_active_selected_bg: value.hops_table_row_active_selected_bg_color,
                hops_table_row_active_selected_text: value
                    .hops_table_row_active_selected_text_color,
                hops_table_row_inactive_selected_bg: value
                    .hops_table_row_inactive_selected_bg_color,
                hops_table_row_inactive_selected_text: value
                    .hops_table_row_inactive_selected_text_color,
                hops_chart_selected: value.hops_chart_selected_color,
                hops_chart_unselected: value.hops_chart_unselected_color,
                hops_chart_axis: value.hops_chart_axis_color,
                frequency_chart_bar: value.frequency_chart_bar_color,
                frequency_chart_text: value.frequency_chart_text_color,
                flows_chart_bar_selected: value.flows_chart_bar_selected_color,
                flows_chart_bar_unselected: value.flows_chart_bar_unselected_color,
                flows_chart_text_current: value.flows_chart_text_current_color,
                flows_chart_text_non_current: value.flows_chart_text_non_current_color,
                samples_chart: value.samples_chart_color,
                samples_chart_lost: value.samples_chart_lost_color,
                help_dialog_bg: value.help_dialog_bg_color,
                help_dialog_text: value.help_dialog_text_color,
                settings_dialog_bg: value.settings_dialog_bg_color,
                settings_tab_text: value.settings_tab_text_color,
                settings_table_header_text: value.settings_table_header_text_color,
                settings_table_header_bg: value.settings_table_header_bg_color,
                settings_table_row_text: value.settings_table_row_text_color,
                map_world: value.map_world_color,
                map_radius: value.map_radius_color,
                map_selected: value.map_selected_color,
                map_info_panel_border: value.map_info_panel_border_color,
                map_info_panel_bg: value.map_info_panel_bg_color,
                map_info_panel_text: value.map_info_panel_text_color,
                info_bar_bg: value.info_bar_bg_color,
                info_bar_text: value.info_bar_text_color,
            }
        }
    }
}

/// A TUI theme item.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, VariantNames)]
#[strum(serialize_all = "kebab-case")]
#[expect(clippy::enum_variant_names)]
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
    /// The background color of selected active rows in the hops table.
    HopsTableRowActiveSelectedBgColor,
    /// The color of text of selected active rows in the hops table.
    HopsTableRowActiveSelectedTextColor,
    /// The background color of selected inactive rows in the hops table.
    HopsTableRowInactiveSelectedBgColor,
    /// The color of text of selected inactive rows in the hops table.
    HopsTableRowInactiveSelectedTextColor,
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
    /// The color of the info bar background.
    InfoBarBgColor,
    /// The color of the info bar text.
    InfoBarTextColor,
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

    #[expect(clippy::too_many_lines)]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let normalized = value.to_ascii_lowercase().replace('-', "");
        let rgb_hex = normalized.strip_prefix('#').unwrap_or(&normalized);
        match normalized.as_ref() {
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
            _ if rgb_hex.len() == 6 && rgb_hex.chars().all(|c| c.is_ascii_hexdigit()) => {
                let red = u8::from_str_radix(&rgb_hex[0..2], 16)?;
                let green = u8::from_str_radix(&rgb_hex[2..4], 16)?;
                let blue = u8::from_str_radix(&rgb_hex[4..6], 16)?;
                Ok(Self::Rgb(red, green, blue))
            }
            _ => Err(anyhow!("unknown color: {value}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TuiTheme;
    use super::named::NamedThemes;

    #[test]
    fn named_themes_load() {
        for name in NamedThemes::data().keys() {
            TuiTheme::for_name(name).expect("theme");
        }
    }
}
