use itertools::Itertools;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

const FALLBACK_LOCALE: &str = "en";

/// Set the locale for the application.
///
/// If the given locale is `None` the system locale is tried. If the system locale cannot be
/// determined then the fallback locale is used.
///
/// In all cases, the language part of the locale is used if the full locale is not supported.
pub fn set_locale(locale: Option<&str>) -> String {
    let new_locale = calculate_locale(locale, sys_locale::get_locale().as_deref());
    store_locale(&new_locale);
    new_locale
}

/// Get the available locales.
pub fn available_locales() -> Vec<&'static str> {
    data()
        .0
        .iter()
        .flat_map(|(_, v)| v.0.keys().map(AsRef::as_ref))
        .unique()
        .sorted_unstable()
        .collect::<Vec<_>>()
}

/// A macro to translate an item to the current locale.
#[macro_export]
macro_rules! t {
    ($key:expr) => {
        std::borrow::Cow::Borrowed($crate::locale::__translate($key))
    };
    ($key:expr, $($kt:ident = $kv:expr),+) => {
        {
            let string = t!($key);
            $(
                let string = string.replace(concat!("%{", stringify!($kt), "}"), &$kv.to_string());
            )+
            string
        }
    };
    ($key:expr, $($kt:literal => $kv:expr),+) => {
        {
            let string = t!($key);
            $(
                let string = string.replace(concat!("%{", $kt, "}"), &$kv.to_string());
            )+
            string
        }
    };
}

/// Translate an item to the current locale.
///
/// This function is public as it is used by the `t!` macro, however is not considered part of the
/// public interface.
#[doc(hidden)]
pub fn __translate(item: &str) -> &str {
    let locale = CURRENT_LOCALE.with(Clone::clone);
    let binding = locale.borrow();
    translate_locale(item, binding.as_str())
}

/// Translate an item to a specific locale.
///
/// If the item does not exists, the key is returned. Otherwise, if item does not contain the
/// locale, the fallback locale is used. If the fallback locale does not exist, the key is
/// returned.
fn translate_locale<'a>(item: &'a str, locale: &str) -> &'a str {
    if let Some(key) = data().0.get(item) {
        if let Some(value) = key.0.get(locale) {
            value
        } else if let Some(value) = key.0.get(&split_locale(locale)) {
            value
        } else if let Some(value) = key.0.get(FALLBACK_LOCALE) {
            value
        } else {
            item
        }
    } else {
        item
    }
}

/// Get the locale data.
fn data() -> &'static Data {
    static DATA: OnceLock<Data> = OnceLock::new();
    DATA.get_or_init(|| {
        toml::from_str(include_str!("../locales.toml")).expect("Failed to parse locales.toml")
    })
}

/// This is a map of a item name (i.e. `title_hops`, `awaiting_data`, etc.) to the locale `Item`.
#[derive(Debug, Deserialize)]
struct Data(HashMap<String, Item>);

/// This is a map of locale keys (i.e. `en`, `zh`, etc.) to the translated value.
#[derive(Debug, Deserialize)]
struct Item(HashMap<String, String>);

/// calculate the locale to use.
fn calculate_locale(cfg_locale: Option<&str>, sys_locale: Option<&str>) -> String {
    let target_locale = if let Some(locale) = cfg_locale {
        locale
    } else if let Some(locale) = sys_locale {
        locale
    } else {
        FALLBACK_LOCALE
    };
    let all_locales = available_locales();
    if all_locales.contains(&target_locale) {
        String::from(target_locale)
    } else {
        let language = split_locale(target_locale);
        if all_locales.contains(&language.as_str()) {
            language
        } else {
            String::from(FALLBACK_LOCALE)
        }
    }
}

/// Split a locale into language and region parts and return the language part.
fn split_locale(locale: &str) -> String {
    let mut parts = locale.split(['-', '_']);
    parts
        .next()
        .map_or_else(|| FALLBACK_LOCALE, |lang| lang)
        .to_string()
}

thread_local! {
    static CURRENT_LOCALE: RefCell<String> = RefCell::new(String::from(FALLBACK_LOCALE));
}

fn store_locale(new_locale: &str) {
    CURRENT_LOCALE.with(|locale| *locale.borrow_mut() = String::from(new_locale));
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("en-US", "en"; "dash")]
    #[test_case("en_US", "en"; "underscore")]
    #[test_case("en", "en"; "no_region")]
    #[test_case("zh-", "zh"; "invalid_dash")]
    #[test_case("zh_", "zh"; "invalid_underscore")]
    #[test_case("en?", "en?"; "invalid_accepted")]
    fn test_split_locale(locale: &str, expected: &str) {
        assert_eq!(split_locale(locale), expected);
    }

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
    fn test_set_locale(cfg_locale: Option<&str>, sys_locale: Option<&str>, expected: &str) {
        assert_eq!(calculate_locale(cfg_locale, sys_locale), expected);
    }

    #[test]
    fn test_available_languages() {
        assert_eq!(
            available_locales(),
            vec!["de", "en", "es", "fr", "it", "pt", "ru", "sv", "tr", "zh"]
        );
    }

    #[test]
    fn test_data_deserialize() {
        assert!(!data().0.is_empty());
    }

    #[test]
    fn test_translate() {
        assert_eq!(translate_locale("title_hops", "en"), "Hops");
        assert_eq!(translate_locale("title_hops", "zh"), "跳");
        assert_eq!(translate_locale("unknown_item", "en"), "unknown_item");
        assert_eq!(translate_locale("unknown_locale", "xx"), "unknown_locale");
    }

    #[test]
    fn test_translate_macro() {
        assert_eq!(t!("title_hops"), "Hops");
        assert_eq!(t!("awaiting_data"), "Awaiting data...");
        assert_eq!(t!("unknown_item"), "unknown_item");
    }
}
