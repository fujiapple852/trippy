use crate::config::{TuiColor, TuiTheme};
use ratatui::style::Color;

/// Tui color theme.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// The default background color.
    ///
    /// This may be overridden for specific components.
    pub bg: Color,
    /// The default color of borders.
    ///
    /// This may be overridden for specific components.
    pub border: Color,
    /// The default color of text.
    ///
    /// This may be overridden for specific components.
    pub text: Color,
    /// The color of the text in traces tabs.
    pub tab_text: Color,
    /// The background color of the hops table header.
    pub hops_table_header_bg: Color,
    /// The color of text in the hops table header.
    pub hops_table_header_text: Color,
    /// The color of text of active rows in the hops table.
    pub hops_table_row_active_text: Color,
    /// The color of text of inactive rows in the hops table.
    pub hops_table_row_inactive_text: Color,
    /// The color of the selected series in the hops chart.
    pub hops_chart_selected: Color,
    /// The color of the unselected series in the hops chart.
    pub hops_chart_unselected: Color,
    /// The color of the axis in the hops chart.
    pub hops_chart_axis: Color,
    /// The color of bars in the frequency chart.
    pub frequency_chart_bar: Color,
    /// The color of text in the bars of the frequency chart.
    pub frequency_chart_text: Color,
    /// The color of the selected flow bar in the flows chart.
    pub flows_chart_bar_selected: Color,
    /// The color of the unselected flow bar in the flows chart.
    pub flows_chart_bar_unselected: Color,
    /// The color of the current flow text in the flows chart.
    pub flows_chart_text_current: Color,
    /// The color of the non-current flow text in the flows chart.
    pub flows_chart_text_non_current: Color,
    /// The color of the samples chart.
    pub samples_chart: Color,
    /// The color of the samples chart for lost probes.
    pub samples_chart_lost: Color,
    /// The background color of the help dialog.
    pub help_dialog_bg: Color,
    /// The color of the text in the help dialog.
    pub help_dialog_text: Color,
    /// The background color of the settings dialog.
    pub settings_dialog_bg: Color,
    /// The color of the text in settings dialog tabs.
    pub settings_tab_text: Color,
    /// The color of text in the settings table header.
    pub settings_table_header_text: Color,
    /// The background color of the settings table header.
    pub settings_table_header_bg: Color,
    /// The color of text of rows in the settings table.
    pub settings_table_row_text: Color,
    /// The color of the map world diagram.
    pub map_world: Color,
    /// The color of the map accuracy radius circle.
    pub map_radius: Color,
    /// The color of the map selected item box.
    pub map_selected: Color,
    /// The color of border of the map info panel.
    pub map_info_panel_border: Color,
    /// The background color of the map info panel.
    pub map_info_panel_bg: Color,
    /// The color of text in the map info panel.
    pub map_info_panel_text: Color,
    /// The color of the info bar background.
    pub info_bar_bg: Color,
    /// The color of the info bar text.
    pub info_bar_text: Color,
}

impl From<TuiTheme> for Theme {
    fn from(value: TuiTheme) -> Self {
        Self {
            bg: Color::from(value.bg),
            border: Color::from(value.border),
            text: Color::from(value.text),
            tab_text: Color::from(value.tab_text),
            hops_table_header_bg: Color::from(value.hops_table_header_bg),
            hops_table_header_text: Color::from(value.hops_table_header_text),
            hops_table_row_active_text: Color::from(value.hops_table_row_active_text),
            hops_table_row_inactive_text: Color::from(value.hops_table_row_inactive_text),
            hops_chart_selected: Color::from(value.hops_chart_selected),
            hops_chart_unselected: Color::from(value.hops_chart_unselected),
            hops_chart_axis: Color::from(value.hops_chart_axis),
            frequency_chart_bar: Color::from(value.frequency_chart_bar),
            frequency_chart_text: Color::from(value.frequency_chart_text),
            flows_chart_bar_selected: Color::from(value.flows_chart_bar_selected),
            flows_chart_bar_unselected: Color::from(value.flows_chart_bar_unselected),
            flows_chart_text_current: Color::from(value.flows_chart_text_current),
            flows_chart_text_non_current: Color::from(value.flows_chart_text_non_current),
            samples_chart: Color::from(value.samples_chart),
            samples_chart_lost: Color::from(value.samples_chart_lost),
            help_dialog_bg: Color::from(value.help_dialog_bg),
            help_dialog_text: Color::from(value.help_dialog_text),
            settings_dialog_bg: Color::from(value.settings_dialog_bg),
            settings_tab_text: Color::from(value.settings_tab_text),
            settings_table_header_text: Color::from(value.settings_table_header_text),
            settings_table_header_bg: Color::from(value.settings_table_header_bg),
            settings_table_row_text: Color::from(value.settings_table_row_text),
            map_world: Color::from(value.map_world),
            map_radius: Color::from(value.map_radius),
            map_selected: Color::from(value.map_selected),
            map_info_panel_border: Color::from(value.map_info_panel_border),
            map_info_panel_bg: Color::from(value.map_info_panel_bg),
            map_info_panel_text: Color::from(value.map_info_panel_text),
            info_bar_bg: Color::from(value.info_bar_bg),
            info_bar_text: Color::from(value.info_bar_text),
        }
    }
}

impl From<TuiColor> for Color {
    #[expect(clippy::too_many_lines)]
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
            TuiColor::AliceBlue => Self::from_u32(0x00f0_f8ff),
            TuiColor::AntiqueWhite => Self::from_u32(0x00fa_ebd7),
            TuiColor::Aqua => Self::from_u32(0x0000_ffff),
            TuiColor::Aquamarine => Self::from_u32(0x007f_ffd4),
            TuiColor::Azure => Self::from_u32(0x00f0_ffff),
            TuiColor::Beige => Self::from_u32(0x00f5_f5dc),
            TuiColor::Bisque => Self::from_u32(0x00ff_e4c4),
            TuiColor::BlanchedAlmond => Self::from_u32(0x00ff_ebcd),
            TuiColor::BlueViolet => Self::from_u32(0x008a_2be2),
            TuiColor::Brown => Self::from_u32(0x00a5_2a2a),
            TuiColor::BurlyWood => Self::from_u32(0x00de_b887),
            TuiColor::CadetBlue => Self::from_u32(0x005f_9ea0),
            TuiColor::Chartreuse => Self::from_u32(0x007f_ff00),
            TuiColor::Chocolate => Self::from_u32(0x00d2_691e),
            TuiColor::Coral => Self::from_u32(0x00ff_7f50),
            TuiColor::CornflowerBlue => Self::from_u32(0x0064_95ed),
            TuiColor::CornSilk => Self::from_u32(0x00ff_f8dc),
            TuiColor::Crimson => Self::from_u32(0x00dc_143c),
            TuiColor::DarkBlue => Self::from_u32(0x0000_008b),
            TuiColor::DarkCyan => Self::from_u32(0x0000_8b8b),
            TuiColor::DarkGoldenrod => Self::from_u32(0x00b8_860b),
            TuiColor::DarkGreen => Self::from_u32(0x0000_6400),
            TuiColor::DarkKhaki => Self::from_u32(0x00bd_b76b),
            TuiColor::DarkMagenta => Self::from_u32(0x008b_008b),
            TuiColor::DarkOliveGreen => Self::from_u32(0x0055_6b2f),
            TuiColor::DarkOrange => Self::from_u32(0x00ff_8c00),
            TuiColor::DarkOrchid => Self::from_u32(0x0099_32cc),
            TuiColor::DarkRed => Self::from_u32(0x008b_0000),
            TuiColor::DarkSalmon => Self::from_u32(0x00e9_967a),
            TuiColor::DarkSeaGreen => Self::from_u32(0x008f_bc8f),
            TuiColor::DarkSlateBlue => Self::from_u32(0x0048_3d8b),
            TuiColor::DarkSlateGray => Self::from_u32(0x002f_4f4f),
            TuiColor::DarkTurquoise => Self::from_u32(0x0000_ced1),
            TuiColor::DarkViolet => Self::from_u32(0x0094_00d3),
            TuiColor::DeepPink => Self::from_u32(0x00ff_1493),
            TuiColor::DeepSkyBlue => Self::from_u32(0x0000_bfff),
            TuiColor::DimGray => Self::from_u32(0x0069_6969),
            TuiColor::DodgerBlue => Self::from_u32(0x001e_90ff),
            TuiColor::Firebrick => Self::from_u32(0x00b2_2222),
            TuiColor::FloralWhite => Self::from_u32(0x00ff_faf0),
            TuiColor::ForestGreen => Self::from_u32(0x0022_8b22),
            TuiColor::Fuchsia => Self::from_u32(0x00ff_00ff),
            TuiColor::Gainsboro => Self::from_u32(0x00dc_dcdc),
            TuiColor::GhostWhite => Self::from_u32(0x00f8_f8ff),
            TuiColor::Gold => Self::from_u32(0x00ff_d700),
            TuiColor::Goldenrod => Self::from_u32(0x00da_a520),
            TuiColor::GreenYellow => Self::from_u32(0x00ad_ff2f),
            TuiColor::Honeydew => Self::from_u32(0x00f0_fff0),
            TuiColor::HotPink => Self::from_u32(0x00ff_69b4),
            TuiColor::IndianRed => Self::from_u32(0x00cd_5c5c),
            TuiColor::Indigo => Self::from_u32(0x004b_0082),
            TuiColor::Ivory => Self::from_u32(0x00ff_fff0),
            TuiColor::Khaki => Self::from_u32(0x00f0_e68c),
            TuiColor::Lavender => Self::from_u32(0x00e6_e6fa),
            TuiColor::LavenderBlush => Self::from_u32(0x00ff_f0f5),
            TuiColor::LawnGreen => Self::from_u32(0x007c_fc00),
            TuiColor::LemonChiffon => Self::from_u32(0x00ff_facd),
            TuiColor::LightCoral => Self::from_u32(0x00f0_8080),
            TuiColor::LightGoldenrodYellow => Self::from_u32(0x00fa_fad2),
            TuiColor::LightGray => Self::from_u32(0x00d3_d3d3),
            TuiColor::LightPink => Self::from_u32(0x00ff_b6c1),
            TuiColor::LightSalmon => Self::from_u32(0x00ff_a07a),
            TuiColor::LightSeaGreen => Self::from_u32(0x0020_b2aa),
            TuiColor::LightSkyBlue => Self::from_u32(0x0087_cefa),
            TuiColor::LightSlateGray => Self::from_u32(0x0077_8899),
            TuiColor::LightSteelBlue => Self::from_u32(0x00b0_c4de),
            TuiColor::Lime => Self::from_u32(0x0000_ff00),
            TuiColor::LimeGreen => Self::from_u32(0x0032_cd32),
            TuiColor::Linen => Self::from_u32(0x00fa_f0e6),
            TuiColor::Maroon => Self::from_u32(0x0080_0000),
            TuiColor::MediumAquamarine => Self::from_u32(0x0066_cdaa),
            TuiColor::MediumBlue => Self::from_u32(0x0000_00cd),
            TuiColor::MediumOrchid => Self::from_u32(0x00ba_55d3),
            TuiColor::MediumPurple => Self::from_u32(0x0093_70db),
            TuiColor::MediumSeaGreen => Self::from_u32(0x003c_b371),
            TuiColor::MediumSlateBlue => Self::from_u32(0x007b_68ee),
            TuiColor::MediumSpringGreen => Self::from_u32(0x0000_fa9a),
            TuiColor::MediumTurquoise => Self::from_u32(0x0048_d1cc),
            TuiColor::MediumVioletRed => Self::from_u32(0x00c7_1585),
            TuiColor::MidnightBlue => Self::from_u32(0x0019_1970),
            TuiColor::MintCream => Self::from_u32(0x00f5_fffa),
            TuiColor::MistyRose => Self::from_u32(0x00ff_e4e1),
            TuiColor::Moccasin => Self::from_u32(0x00ff_e4b5),
            TuiColor::NavajoWhite => Self::from_u32(0x00ff_dead),
            TuiColor::Navy => Self::from_u32(0x0000_0080),
            TuiColor::OldLace => Self::from_u32(0x00fd_f5e6),
            TuiColor::Olive => Self::from_u32(0x0080_8000),
            TuiColor::OliveDrab => Self::from_u32(0x006b_8e23),
            TuiColor::Orange => Self::from_u32(0x00ff_a500),
            TuiColor::OrangeRed => Self::from_u32(0x00ff_4500),
            TuiColor::Orchid => Self::from_u32(0x00da_70d6),
            TuiColor::PaleGoldenrod => Self::from_u32(0x00ee_e8aa),
            TuiColor::PaleGreen => Self::from_u32(0x0098_fb98),
            TuiColor::PaleTurquoise => Self::from_u32(0x00af_eeee),
            TuiColor::PaleVioletRed => Self::from_u32(0x00db_7093),
            TuiColor::PapayaWhip => Self::from_u32(0x00ff_efd5),
            TuiColor::PeachPuff => Self::from_u32(0x00ff_dab9),
            TuiColor::Peru => Self::from_u32(0x00cd_853f),
            TuiColor::Pink => Self::from_u32(0x00ff_c0cb),
            TuiColor::Plum => Self::from_u32(0x00dd_a0dd),
            TuiColor::PowderBlue => Self::from_u32(0x00b0_e0e6),
            TuiColor::Purple => Self::from_u32(0x0080_0080),
            TuiColor::RebeccaPurple => Self::from_u32(0x0066_3399),
            TuiColor::RosyBrown => Self::from_u32(0x00bc_8f8f),
            TuiColor::RoyalBlue => Self::from_u32(0x0041_69e1),
            TuiColor::SaddleBrown => Self::from_u32(0x008b_4513),
            TuiColor::Salmon => Self::from_u32(0x00fa_8072),
            TuiColor::SandyBrown => Self::from_u32(0x00f4_a460),
            TuiColor::SeaGreen => Self::from_u32(0x002e_8b57),
            TuiColor::SeaShell => Self::from_u32(0x00ff_f5ee),
            TuiColor::Sienna => Self::from_u32(0x00a0_522d),
            TuiColor::Silver => Self::from_u32(0x00c0_c0c0),
            TuiColor::SkyBlue => Self::from_u32(0x0087_ceeb),
            TuiColor::SlateBlue => Self::from_u32(0x006a_5acd),
            TuiColor::SlateGray => Self::from_u32(0x0070_8090),
            TuiColor::Snow => Self::from_u32(0x00ff_fafa),
            TuiColor::SpringGreen => Self::from_u32(0x0000_ff7f),
            TuiColor::SteelBlue => Self::from_u32(0x0046_82b4),
            TuiColor::Tan => Self::from_u32(0x00d2_b48c),
            TuiColor::Teal => Self::from_u32(0x0000_8080),
            TuiColor::Thistle => Self::from_u32(0x00d8_bfd8),
            TuiColor::Tomato => Self::from_u32(0x00ff_6347),
            TuiColor::Turquoise => Self::from_u32(0x0040_e0d0),
            TuiColor::Violet => Self::from_u32(0x00ee_82ee),
            TuiColor::Wheat => Self::from_u32(0x00f5_deb3),
            TuiColor::WhiteSmoke => Self::from_u32(0x00f5_f5f5),
            TuiColor::YellowGreen => Self::from_u32(0x009a_cd32),
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
