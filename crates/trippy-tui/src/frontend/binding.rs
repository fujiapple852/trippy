use crate::config::{TuiBindings, TuiKeyBinding};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use itertools::Itertools;
use std::fmt::{Display, Formatter};

/// Tui key bindings.
#[derive(Debug, Clone, Copy)]
pub struct Bindings {
    pub toggle_help: KeyBinding,
    pub toggle_help_alt: KeyBinding,
    pub toggle_settings: KeyBinding,
    pub toggle_settings_tui: KeyBinding,
    pub toggle_settings_trace: KeyBinding,
    pub toggle_settings_dns: KeyBinding,
    pub toggle_settings_geoip: KeyBinding,
    pub toggle_settings_bindings: KeyBinding,
    pub toggle_settings_theme: KeyBinding,
    pub toggle_settings_columns: KeyBinding,
    pub previous_hop: KeyBinding,
    pub next_hop: KeyBinding,
    pub previous_trace: KeyBinding,
    pub next_trace: KeyBinding,
    pub previous_hop_address: KeyBinding,
    pub next_hop_address: KeyBinding,
    pub address_mode_ip: KeyBinding,
    pub address_mode_host: KeyBinding,
    pub address_mode_both: KeyBinding,
    pub toggle_freeze: KeyBinding,
    pub toggle_chart: KeyBinding,
    pub toggle_map: KeyBinding,
    pub toggle_flows: KeyBinding,
    pub expand_privacy: KeyBinding,
    pub contract_privacy: KeyBinding,
    pub expand_hosts: KeyBinding,
    pub contract_hosts: KeyBinding,
    pub expand_hosts_max: KeyBinding,
    pub contract_hosts_min: KeyBinding,
    pub chart_zoom_in: KeyBinding,
    pub chart_zoom_out: KeyBinding,
    pub clear_trace_data: KeyBinding,
    pub clear_dns_cache: KeyBinding,
    pub clear_selection: KeyBinding,
    pub toggle_as_info: KeyBinding,
    pub toggle_hop_details: KeyBinding,
    pub quit: KeyBinding,
    pub quit_preserve_screen: KeyBinding,
}

impl From<TuiBindings> for Bindings {
    fn from(value: TuiBindings) -> Self {
        Self {
            toggle_help: KeyBinding::from(value.toggle_help),
            toggle_help_alt: KeyBinding::from(value.toggle_help_alt),
            toggle_settings: KeyBinding::from(value.toggle_settings),
            toggle_settings_tui: KeyBinding::from(value.toggle_settings_tui),
            toggle_settings_trace: KeyBinding::from(value.toggle_settings_trace),
            toggle_settings_dns: KeyBinding::from(value.toggle_settings_dns),
            toggle_settings_geoip: KeyBinding::from(value.toggle_settings_geoip),
            toggle_settings_bindings: KeyBinding::from(value.toggle_settings_bindings),
            toggle_settings_theme: KeyBinding::from(value.toggle_settings_theme),
            toggle_settings_columns: KeyBinding::from(value.toggle_settings_columns),
            previous_hop: KeyBinding::from(value.previous_hop),
            next_hop: KeyBinding::from(value.next_hop),
            previous_trace: KeyBinding::from(value.previous_trace),
            next_trace: KeyBinding::from(value.next_trace),
            previous_hop_address: KeyBinding::from(value.previous_hop_address),
            next_hop_address: KeyBinding::from(value.next_hop_address),
            address_mode_ip: KeyBinding::from(value.address_mode_ip),
            address_mode_host: KeyBinding::from(value.address_mode_host),
            address_mode_both: KeyBinding::from(value.address_mode_both),
            toggle_freeze: KeyBinding::from(value.toggle_freeze),
            toggle_chart: KeyBinding::from(value.toggle_chart),
            toggle_map: KeyBinding::from(value.toggle_map),
            toggle_flows: KeyBinding::from(value.toggle_flows),
            expand_privacy: KeyBinding::from(value.expand_privacy),
            contract_privacy: KeyBinding::from(value.contract_privacy),
            expand_hosts: KeyBinding::from(value.expand_hosts),
            contract_hosts: KeyBinding::from(value.contract_hosts),
            expand_hosts_max: KeyBinding::from(value.expand_hosts_max),
            contract_hosts_min: KeyBinding::from(value.contract_hosts_min),
            chart_zoom_in: KeyBinding::from(value.chart_zoom_in),
            chart_zoom_out: KeyBinding::from(value.chart_zoom_out),
            clear_trace_data: KeyBinding::from(value.clear_trace_data),
            clear_dns_cache: KeyBinding::from(value.clear_dns_cache),
            clear_selection: KeyBinding::from(value.clear_selection),
            toggle_as_info: KeyBinding::from(value.toggle_as_info),
            toggle_hop_details: KeyBinding::from(value.toggle_hop_details),
            quit: KeyBinding::from(value.quit),
            quit_preserve_screen: KeyBinding::from(value.quit_preserve_screen),
        }
    }
}

/// Tui key binding.
#[derive(Debug, Clone, Copy)]
pub struct KeyBinding {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyBinding {
    pub fn check(&self, event: KeyEvent) -> bool {
        let code_match = match (event.code, self.code) {
            (KeyCode::Char(c1), KeyCode::Char(c2)) => c1.eq_ignore_ascii_case(&c2),
            (c1, c2) => c1 == c2,
        };
        code_match && self.modifiers == event.modifiers
    }
}

impl From<TuiKeyBinding> for KeyBinding {
    fn from(value: TuiKeyBinding) -> Self {
        Self {
            code: value.code,
            modifiers: value.modifier,
        }
    }
}

impl Display for KeyBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let modifiers = &[
            self.modifiers
                .contains(KeyModifiers::SHIFT)
                .then_some("shift"),
            self.modifiers
                .contains(KeyModifiers::CONTROL)
                .then_some("ctrl"),
            self.modifiers.contains(KeyModifiers::ALT).then_some("alt"),
            self.modifiers
                .contains(KeyModifiers::SUPER)
                .then_some("super"),
            self.modifiers
                .contains(KeyModifiers::HYPER)
                .then_some("hyper"),
            self.modifiers
                .contains(KeyModifiers::META)
                .then_some("meta"),
        ]
        .into_iter()
        .flatten()
        .join("+");
        if !modifiers.is_empty() {
            write!(f, "{modifiers}+")?;
        }
        match self.code {
            KeyCode::Backspace => write!(f, "backspace"),
            KeyCode::Enter => write!(f, "enter"),
            KeyCode::Left => write!(f, "left"),
            KeyCode::Right => write!(f, "right"),
            KeyCode::Up => write!(f, "up"),
            KeyCode::Down => write!(f, "down"),
            KeyCode::Home => write!(f, "home"),
            KeyCode::End => write!(f, "end"),
            KeyCode::PageUp => write!(f, "pageup"),
            KeyCode::PageDown => write!(f, "pagedown"),
            KeyCode::Tab => write!(f, "tab"),
            KeyCode::BackTab => write!(f, "backtab"),
            KeyCode::Delete => write!(f, "delete"),
            KeyCode::Insert => write!(f, "insert"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::Esc => write!(f, "esc"),
            _ => write!(f, "unknown"),
        }
    }
}

pub const CTRL_C: KeyBinding = KeyBinding {
    code: KeyCode::Char('c'),
    modifiers: KeyModifiers::CONTROL,
};
