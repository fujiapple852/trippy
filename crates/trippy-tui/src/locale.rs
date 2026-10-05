use crate::Locale;
use mf2::ratatui::{Theme, set_theme};
use ratatui::style::Style;

/// Set the locale for the application.
///
/// The embedded catalogs are installed first, in the language that best serves the system's
/// preferred languages (else English). If a locale is given, it replaces that choice.
///
/// Returns the chosen locale's tag.
pub fn set_locale(locale: Option<&str>) -> &'static str {
    crate::install();
    // How the messages' markup is drawn: a key hint (`{#key}h{/key}`) in bold.
    set_theme(Theme::default().style(crate::markup::KEY, Style::new().bold()));
    if locale.is_some() {
        crate::set_locale(choose(locale, None));
    }
    crate::current_locale().tag()
}

/// Get the available locales.
pub fn available_locales() -> Vec<&'static str> {
    Locale::ALL.iter().map(|locale| locale.tag()).collect()
}

/// Choose the locale to use: the configured one, else the system's, else English.
///
/// A tag is matched to the catalogs with CLDR's language matching, so a region or a script the
/// catalogs lack falls back to the closest language they have.
fn choose(cfg_locale: Option<&str>, sys_locale: Option<&str>) -> Locale {
    cfg_locale
        .or(sys_locale)
        .and_then(|tag| tag.parse().ok())
        .unwrap_or(Locale::SOURCE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tr;
    use test_case::test_case;

    #[test_case(None, None, "en"; "no_locale")]
    #[test_case(Some("en"), None, "en"; "cfg_locale")]
    #[test_case(None, Some("en"), "en"; "sys_locale")]
    #[test_case(Some("en"), Some("en"), "en"; "both_locales")]
    #[test_case(Some("en"), Some("zh"), "en"; "both_locales_mismatch")]
    #[test_case(Some("zh"), Some("en"), "zh"; "both_locales_mismatch_reverse")]
    #[test_case(Some("en-US"), None, "en"; "cfg_locale_dash")]
    #[test_case(None, Some("en-US"), "en"; "sys_locale_dash")]
    #[test_case(Some("en-US"), Some("en-US"), "en"; "both_locales_dash")]
    #[test_case(Some("en-US"), Some("zh-CN"), "en"; "both_locales_mismatch_dash")]
    #[test_case(Some("zh-CN"), Some("en-US"), "zh"; "both_locales_mismatch_reverse_dash")]
    #[test_case(Some("en_US"), None, "en"; "cfg_locale_underscore")]
    #[test_case(None, Some("en_US"), "en"; "sys_locale_underscore")]
    #[test_case(Some("xx"), None, "en"; "cfg_locale_unknown")]
    #[test_case(None, Some("xx"), "en"; "sys_locale_unknown")]
    #[test_case(Some("xx"), Some("xx"), "en"; "both_locales_unknown")]
    #[test_case(Some("en-"), None, "en"; "cfg_locale_invalid_dash")]
    #[test_case(Some("en_"), None, "en"; "cfg_locale_invalid_underscore")]
    #[test_case(Some("en?"), None, "en"; "cfg_locale_invalid_accepted")]
    #[test_case(Some("zh-Hant-TW"), None, "zh-TW"; "cfg_locale_ignore_script")]
    #[test_case(None, Some("zh-Hant-TW"), "zh-TW"; "sys_locale_ignore_script")]
    #[test_case(Some("zh-Hant-TW"), Some("zh-Hant-TW"), "zh-TW"; "both_locales_ignore_script")]
    fn test_set_locale(cfg_locale: Option<&str>, sys_locale: Option<&str>, expected: &str) {
        assert_eq!(choose(cfg_locale, sys_locale).tag(), expected);
    }

    #[test]
    fn test_available_languages() {
        assert_eq!(
            available_locales(),
            vec![
                "de", "en", "es", "fr", "it", "ja", "pt", "ru", "sv", "tr", "zh", "zh-TW"
            ]
        );
    }

    #[test]
    fn test_translate() {
        crate::install();
        assert_eq!(Locale::En.format(&tr!("title_hops")), "Hops");
        assert_eq!(Locale::Zh.format(&tr!("title_hops")), "跳");
        assert_eq!(Locale::ZhTw.format(&tr!("title_hops")), "跳");
    }

    #[test]
    fn test_zh_tw_translations() {
        crate::install();
        let zh_tw = |message| Locale::ZhTw.format(&message);
        assert_eq!(zh_tw(tr!("auto")), "自動");
        assert_eq!(zh_tw(tr!("status_failed")), "失敗");
        assert_eq!(zh_tw(tr!("status_running")), "執行中");
        assert_eq!(zh_tw(tr!("title_settings")), "設定");
        assert_eq!(zh_tw(tr!("help_tagline")), "網路診斷工具");
        assert_eq!(zh_tw(tr!("column_loss_pct")), "封包遺失率");
        assert_eq!(zh_tw(tr!("rtt")), "往返時間");
    }

    #[test]
    fn test_messages() {
        crate::install();
        let flows = |locale: Locale, flow_count: usize| {
            locale.format(&tr!(
                "discovered_flows",
                hop_count = 7,
                flow_count = flow_count
            ))
        };
        assert_eq!(flows(Locale::En, 1), "discovered 7 hops and 1 unique flow");
        assert_eq!(flows(Locale::En, 2), "discovered 7 hops and 2 unique flows");
        assert_eq!(flows(Locale::Fr, 1), "7 sauts et 1 flux unique découverts");
        assert_eq!(
            flows(Locale::Ru, 5),
            "обнаружено: 7 хопов и 5 уникальных потоков"
        );
        let failures = |locale: Locale| {
            locale.format(&tr!(
                "status_failures",
                status = "Running",
                failure_count = 2411,
                total_probes = 14448,
                failure_rate = 2411.0 / 14448.0
            ))
        };
        assert_eq!(
            failures(Locale::En),
            "Running [2,411 of 14,448 (16.7%) probes failed❗]"
        );
        assert_eq!(Locale::En.format(&tr!("header_help", key = "h")), "help");
        assert_eq!(
            Locale::Fr.format(&tr!("header_help", key = "h")),
            "[h] aide"
        );
        assert_eq!(
            Locale::Fr.format(&tr!("target", source = "a", dest = "b")),
            "Cible : a -> b"
        );
    }
}
