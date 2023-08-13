use crate::config::file::ConfigBindings;
use anyhow::anyhow;
use crossterm::event::{KeyCode, KeyModifiers};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use strum::{AsRefStr, EnumString, EnumVariantNames};

/// Tui keyboard bindings.
#[derive(Debug, Clone, Copy)]
pub struct TuiBindings {
    pub toggle_help: TuiKeyBinding,
    pub toggle_settings: TuiKeyBinding,
    pub previous_hop: TuiKeyBinding,
    pub next_hop: TuiKeyBinding,
    pub previous_trace: TuiKeyBinding,
    pub next_trace: TuiKeyBinding,
    pub previous_hop_address: TuiKeyBinding,
    pub next_hop_address: TuiKeyBinding,
    pub address_mode_ip: TuiKeyBinding,
    pub address_mode_host: TuiKeyBinding,
    pub address_mode_both: TuiKeyBinding,
    pub toggle_freeze: TuiKeyBinding,
    pub toggle_chart: TuiKeyBinding,
    pub toggle_map: TuiKeyBinding,
    pub expand_hosts: TuiKeyBinding,
    pub contract_hosts: TuiKeyBinding,
    pub expand_hosts_max: TuiKeyBinding,
    pub contract_hosts_min: TuiKeyBinding,
    pub chart_zoom_in: TuiKeyBinding,
    pub chart_zoom_out: TuiKeyBinding,
    pub clear_trace_data: TuiKeyBinding,
    pub clear_dns_cache: TuiKeyBinding,
    pub clear_selection: TuiKeyBinding,
    pub toggle_as_info: TuiKeyBinding,
    pub toggle_hop_details: TuiKeyBinding,
    pub quit: TuiKeyBinding,
}

impl TuiBindings {
    /// Validate the bindings.
    ///
    /// Returns any duplicate bindings.
    pub fn find_duplicates(&self) -> Vec<String> {
        let (_, duplicates) = [
            (self.toggle_help, TuiCommandItem::ToggleHelp),
            (self.toggle_settings, TuiCommandItem::ToggleSettings),
            (self.previous_hop, TuiCommandItem::PreviousHop),
            (self.next_hop, TuiCommandItem::NextHop),
            (self.previous_trace, TuiCommandItem::PreviousTrace),
            (self.next_trace, TuiCommandItem::NextTrace),
            (
                self.previous_hop_address,
                TuiCommandItem::PreviousHopAddress,
            ),
            (self.next_hop_address, TuiCommandItem::NextHopAddress),
            (self.address_mode_ip, TuiCommandItem::AddressModeIp),
            (self.address_mode_host, TuiCommandItem::AddressModeHost),
            (self.address_mode_both, TuiCommandItem::AddressModeBoth),
            (self.toggle_freeze, TuiCommandItem::ToggleFreeze),
            (self.toggle_chart, TuiCommandItem::ToggleChart),
            (self.toggle_map, TuiCommandItem::ToggleMap),
            (self.expand_hosts, TuiCommandItem::ExpandHosts),
            (self.expand_hosts_max, TuiCommandItem::ExpandHostsMax),
            (self.contract_hosts, TuiCommandItem::ContractHosts),
            (self.contract_hosts_min, TuiCommandItem::ContractHostsMin),
            (self.chart_zoom_in, TuiCommandItem::ChartZoomIn),
            (self.chart_zoom_out, TuiCommandItem::ChartZoomOut),
            (self.clear_trace_data, TuiCommandItem::ClearTraceData),
            (self.clear_dns_cache, TuiCommandItem::ClearDnsCache),
            (self.clear_selection, TuiCommandItem::ClearSelection),
            (self.toggle_as_info, TuiCommandItem::ToggleASInfo),
            (self.toggle_hop_details, TuiCommandItem::ToggleHopDetails),
            (self.quit, TuiCommandItem::Quit),
        ]
        .iter()
        .fold(
            (HashMap::<TuiKeyBinding, TuiCommandItem>::new(), Vec::new()),
            |(mut all, mut dups), (binding, item)| {
                if let Some(existing) = all.get(binding) {
                    dups.push(format!(
                        "{}: [{} and {}]",
                        binding,
                        item.as_ref(),
                        existing.as_ref()
                    ));
                } else {
                    all.insert(*binding, *item);
                }
                (all, dups)
            },
        );
        duplicates
    }
}

impl From<(HashMap<TuiCommandItem, TuiKeyBinding>, ConfigBindings)> for TuiBindings {
    #[allow(clippy::too_many_lines)]
    fn from(value: (HashMap<TuiCommandItem, TuiKeyBinding>, ConfigBindings)) -> Self {
        let (cmd_items, cfg) = value;
        Self {
            toggle_help: *cmd_items
                .get(&TuiCommandItem::ToggleHelp)
                .or(cfg.toggle_help.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('h'))),
            toggle_settings: *cmd_items
                .get(&TuiCommandItem::ToggleSettings)
                .or(cfg.toggle_settings.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('s'))),
            previous_hop: *cmd_items
                .get(&TuiCommandItem::PreviousHop)
                .or(cfg.previous_hop.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Up)),
            next_hop: *cmd_items
                .get(&TuiCommandItem::NextHop)
                .or(cfg.next_hop.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Down)),
            previous_trace: *cmd_items
                .get(&TuiCommandItem::PreviousTrace)
                .or(cfg.previous_trace.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Left)),
            next_trace: *cmd_items
                .get(&TuiCommandItem::NextTrace)
                .or(cfg.next_trace.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Right)),
            previous_hop_address: *cmd_items
                .get(&TuiCommandItem::PreviousHopAddress)
                .or(cfg.previous_hop_address.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char(','))),
            next_hop_address: *cmd_items
                .get(&TuiCommandItem::NextHopAddress)
                .or(cfg.next_hop_address.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('.'))),
            address_mode_ip: *cmd_items
                .get(&TuiCommandItem::AddressModeIp)
                .or(cfg.address_mode_ip.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('i'))),
            address_mode_host: *cmd_items
                .get(&TuiCommandItem::AddressModeHost)
                .or(cfg.address_mode_host.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('n'))),
            address_mode_both: *cmd_items
                .get(&TuiCommandItem::AddressModeBoth)
                .or(cfg.address_mode_both.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('b'))),
            toggle_freeze: *cmd_items
                .get(&TuiCommandItem::ToggleFreeze)
                .or(cfg.toggle_freeze.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('f'))),
            toggle_chart: *cmd_items
                .get(&TuiCommandItem::ToggleChart)
                .or(cfg.toggle_chart.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('c'))),
            toggle_map: *cmd_items
                .get(&TuiCommandItem::ToggleMap)
                .or(cfg.toggle_map.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('m'))),
            expand_hosts: *cmd_items
                .get(&TuiCommandItem::ExpandHosts)
                .or(cfg.expand_hosts.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char(']'))),
            contract_hosts: *cmd_items
                .get(&TuiCommandItem::ContractHosts)
                .or(cfg.contract_hosts.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('['))),
            expand_hosts_max: *cmd_items
                .get(&TuiCommandItem::ExpandHostsMax)
                .or(cfg.expand_hosts_max.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('}'))),
            contract_hosts_min: *cmd_items
                .get(&TuiCommandItem::ContractHostsMin)
                .or(cfg.contract_hosts_min.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('{'))),
            chart_zoom_in: *cmd_items
                .get(&TuiCommandItem::ChartZoomIn)
                .or(cfg.chart_zoom_in.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('='))),
            chart_zoom_out: *cmd_items
                .get(&TuiCommandItem::ChartZoomOut)
                .or(cfg.chart_zoom_out.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('-'))),
            clear_trace_data: *cmd_items
                .get(&TuiCommandItem::ClearTraceData)
                .or(cfg.clear_trace_data.as_ref())
                .unwrap_or(&TuiKeyBinding::new_with_modifier(
                    KeyCode::Char('r'),
                    KeyModifiers::CONTROL,
                )),
            clear_dns_cache: *cmd_items
                .get(&TuiCommandItem::ClearDnsCache)
                .or(cfg.clear_dns_cache.as_ref())
                .unwrap_or(&TuiKeyBinding::new_with_modifier(
                    KeyCode::Char('k'),
                    KeyModifiers::CONTROL,
                )),
            clear_selection: *cmd_items
                .get(&TuiCommandItem::ClearSelection)
                .or(cfg.clear_selection.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Esc)),
            toggle_as_info: *cmd_items
                .get(&TuiCommandItem::ToggleASInfo)
                .or(cfg.toggle_as_info.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('z'))),
            toggle_hop_details: *cmd_items
                .get(&TuiCommandItem::ToggleHopDetails)
                .or(cfg.toggle_hop_details.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('d'))),
            quit: *cmd_items
                .get(&TuiCommandItem::Quit)
                .or(cfg.quit.as_ref())
                .unwrap_or(&TuiKeyBinding::new(KeyCode::Char('q'))),
        }
    }
}

/// Tui key binding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct TuiKeyBinding {
    pub code: KeyCode,
    pub modifier: KeyModifiers,
}

impl TuiKeyBinding {
    pub fn new(code: KeyCode) -> Self {
        Self {
            code,
            modifier: KeyModifiers::NONE,
        }
    }

    pub fn new_with_modifier(code: KeyCode, modifier: KeyModifiers) -> Self {
        Self { code, modifier }
    }
}

impl TryFrom<String> for TuiKeyBinding {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for TuiKeyBinding {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const ALL_MODIFIERS: [(&str, KeyModifiers); 6] = [
            ("shift", KeyModifiers::SHIFT),
            ("ctrl", KeyModifiers::CONTROL),
            ("alt", KeyModifiers::ALT),
            ("super", KeyModifiers::SUPER),
            ("hyper", KeyModifiers::HYPER),
            ("meta", KeyModifiers::META),
        ];
        const ALL_SPECIAL_KEYS: [(&str, KeyCode); 16] = [
            ("backspace", KeyCode::Backspace),
            ("enter", KeyCode::Enter),
            ("left", KeyCode::Left),
            ("right", KeyCode::Right),
            ("up", KeyCode::Up),
            ("down", KeyCode::Down),
            ("home", KeyCode::Home),
            ("end", KeyCode::End),
            ("pageup", KeyCode::PageUp),
            ("pagedown", KeyCode::PageDown),
            ("tab", KeyCode::Tab),
            ("backtab", KeyCode::BackTab),
            ("delete", KeyCode::Delete),
            ("insert", KeyCode::Insert),
            ("null", KeyCode::Null),
            ("esc", KeyCode::Esc),
        ];
        fn parse_keycode(value: &str) -> anyhow::Result<KeyCode> {
            Ok(if value.len() == 1 {
                KeyCode::Char(char::from_str(value)?.to_ascii_lowercase())
            } else {
                ALL_SPECIAL_KEYS
                    .iter()
                    .find_map(|(keycode_str, keycode)| {
                        if keycode_str.eq_ignore_ascii_case(value) {
                            Some(*keycode)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| anyhow!("unknown key binding '{}'", value))?
            })
        }
        fn parse_modifiers(modifiers: &str) -> anyhow::Result<KeyModifiers> {
            modifiers
                .split('+')
                .try_fold(KeyModifiers::NONE, |modifiers, token| {
                    ALL_MODIFIERS
                        .iter()
                        .find_map(|(modifier_token, modifier)| {
                            if modifier_token.eq_ignore_ascii_case(token) {
                                Some(modifiers | *modifier)
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| anyhow!("unknown modifier '{}'", token,))
                })
        }
        match value.rsplit_once('+') {
            Some((modifiers, value)) => Ok(Self {
                code: parse_keycode(value)?,
                modifier: parse_modifiers(modifiers)?,
            }),
            None => Ok(Self {
                code: parse_keycode(value)?,
                modifier: KeyModifiers::NONE,
            }),
        }
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use test_case::test_case;

    #[test_case("c", KeyCode::Char('c'), KeyModifiers::NONE; "char without any modifier")]
    #[test_case("1", KeyCode::Char('1'), KeyModifiers::NONE; "number without any modifier")]
    #[test_case(",", KeyCode::Char(','), KeyModifiers::NONE; "punctuation without any modifier")]
    #[test_case("backspace", KeyCode::Backspace, KeyModifiers::NONE; "backspace without any modifier")]
    #[test_case("enter", KeyCode::Enter, KeyModifiers::NONE; "enter without any modifier")]
    #[test_case("left", KeyCode::Left, KeyModifiers::NONE; "left without any modifier")]
    #[test_case("right", KeyCode::Right, KeyModifiers::NONE; "right without any modifier")]
    #[test_case("up", KeyCode::Up, KeyModifiers::NONE; "up without any modifier")]
    #[test_case("down", KeyCode::Down, KeyModifiers::NONE; "down without any modifier")]
    #[test_case("home", KeyCode::Home, KeyModifiers::NONE; "home without any modifier")]
    #[test_case("end", KeyCode::End, KeyModifiers::NONE; "end without any modifier")]
    #[test_case("pageup", KeyCode::PageUp, KeyModifiers::NONE; "pageup without any modifier")]
    #[test_case("pagedown", KeyCode::PageDown, KeyModifiers::NONE; "pagedown without any modifier")]
    #[test_case("tab", KeyCode::Tab, KeyModifiers::NONE; "tab without any modifier")]
    #[test_case("backtab", KeyCode::BackTab, KeyModifiers::NONE; "backtab without any modifier")]
    #[test_case("delete", KeyCode::Delete, KeyModifiers::NONE; "delete without any modifier")]
    #[test_case("insert", KeyCode::Insert, KeyModifiers::NONE; "insert without any modifier")]
    #[test_case("null", KeyCode::Null, KeyModifiers::NONE; "null without any modifier")]
    #[test_case("esc", KeyCode::Esc, KeyModifiers::NONE; "escape without any modifier")]
    #[test_case("shift+c", KeyCode::Char('c'), KeyModifiers::SHIFT; "with shift modifier")]
    #[test_case("ctrl+i", KeyCode::Char('i'), KeyModifiers::CONTROL; "i with ctrl modifier")]
    #[test_case("shift+I", KeyCode::Char('i'), KeyModifiers::SHIFT; "I with shift modifier")]
    #[test_case("alt+c", KeyCode::Char('c'), KeyModifiers::ALT; "with alt modifier")]
    #[test_case("super+c", KeyCode::Char('c'), KeyModifiers::SUPER; "with super modifier")]
    #[test_case("hyper+c", KeyCode::Char('c'), KeyModifiers::HYPER; "with hyper modifier")]
    #[test_case("meta+c", KeyCode::Char('c'), KeyModifiers::META; "with meta modifier")]
    #[test_case("alt+shift+k", KeyCode::Char('k'), KeyModifiers::ALT | KeyModifiers::SHIFT; "with alt shift modifier")]
    #[test_case("ctrl+up", KeyCode::Up, KeyModifiers::CONTROL; "up with ctrl modifier")]
    #[test_case("shift+ctrl+alt+super+hyper+meta+k", KeyCode::Char('k'), KeyModifiers::all(); "with all modifiers")]
    fn test_key_binding(input: &str, code: KeyCode, modifiers: KeyModifiers) -> anyhow::Result<()> {
        let binding = TuiKeyBinding::try_from(input)?;
        assert_eq!(binding.code, code);
        assert_eq!(binding.modifier, modifiers);
        Ok(())
    }

    #[test]
    fn test_unknown_modifier() {
        let binding = TuiKeyBinding::try_from("foo+c");
        assert!(binding.is_err());
        assert_eq!(&binding.unwrap_err().to_string(), "unknown modifier 'foo'");
    }

    #[test]
    fn test_unknown_second_modifier() {
        let binding = TuiKeyBinding::try_from("alt+foo+c");
        assert!(binding.is_err());
        assert_eq!(&binding.unwrap_err().to_string(), "unknown modifier 'foo'");
    }

    #[test]
    fn test_unknown_key() {
        let binding = TuiKeyBinding::try_from("foo");
        assert!(binding.is_err());
        assert_eq!(
            &binding.unwrap_err().to_string(),
            "unknown key binding 'foo'"
        );
    }
}

impl Display for TuiKeyBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.modifier.contains(KeyModifiers::SHIFT) {
            write!(f, "shift+")?;
        }
        if self.modifier.contains(KeyModifiers::CONTROL) {
            write!(f, "ctrl+")?;
        }
        if self.modifier.contains(KeyModifiers::ALT) {
            write!(f, "alt+")?;
        }
        if self.modifier.contains(KeyModifiers::SUPER) {
            write!(f, "super+")?;
        }
        if self.modifier.contains(KeyModifiers::HYPER) {
            write!(f, "hyper+")?;
        }
        if self.modifier.contains(KeyModifiers::META) {
            write!(f, "meta+")?;
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
            KeyCode::Null => write!(f, "null"),
            KeyCode::Esc => write!(f, "esc"),
            _ => write!(f, "unknown"),
        }
    }
}

/// A Tui command that can be bound to a key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
#[derive(AsRefStr)]
#[allow(clippy::enum_variant_names)]
pub enum TuiCommandItem {
    /// Toggle the help dialog.
    ToggleHelp,
    /// Toggle the settings dialog.
    ToggleSettings,
    /// Move down to the next hop.
    NextHop,
    /// Move up to the previous hop.
    PreviousHop,
    /// Move right to the next trace.
    NextTrace,
    /// Move left to the previous trace.
    PreviousTrace,
    /// Move to the next hop address.
    NextHopAddress,
    /// Move to the previous hop address.
    PreviousHopAddress,
    /// Show IP address mode.
    AddressModeIp,
    /// Show hostname mode.
    AddressModeHost,
    /// Show hostname and IP address mode.
    AddressModeBoth,
    /// Toggle freezing the display.
    ToggleFreeze,
    /// Toggle the chart.
    ToggleChart,
    /// Toggle the map.
    ToggleMap,
    /// Expand hosts.
    ExpandHosts,
    /// Expand hosts to max.
    ExpandHostsMax,
    /// Contract hosts.
    ContractHosts,
    /// Contract hosts to min.
    ContractHostsMin,
    /// Zoom chart in.
    ChartZoomIn,
    /// Zoom chart out.
    ChartZoomOut,
    /// Clear all tracing data.
    ClearTraceData,
    /// Clear DNS cache.
    ClearDnsCache,
    /// Clear hop selection.
    ClearSelection,
    /// Toggle AS info.
    ToggleASInfo,
    /// Toggle hop details.
    ToggleHopDetails,
    /// Quit the application.
    Quit,
}
