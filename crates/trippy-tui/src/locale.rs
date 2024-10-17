const FALLBACK_LOCALE: &str = "en";

/// Set the locale for the application.
///
/// If the given locale is `None` or unsupported, the system locale is tried. If the system locale
/// is not supported, the fallback locale is used.
///
/// In both cases, the language part of the locale is used if the full locale is not supported.
pub fn set_locale(locale: Option<&str>) {
    if let Some(locale) = locale {
        set_locale_inner(locale);
    } else if let Some(locale) = sys_locale::get_locale().as_ref() {
        set_locale_inner(locale);
    } else {
        set_locale_inner(FALLBACK_LOCALE);
    }
}

/// Get the current locale.
pub fn locale() -> String {
    rust_i18n::locale().to_string()
}

fn set_locale_inner(locale: &str) {
    let all_locales = rust_i18n::available_locales!();
    if all_locales.contains(&locale) {
        rust_i18n::set_locale(locale);
    } else {
        let language = split_locale(locale);
        if all_locales.contains(&language.as_str()) {
            rust_i18n::set_locale(&language);
        } else {
            rust_i18n::set_locale(FALLBACK_LOCALE);
        }
    }
}

fn split_locale(locale: &str) -> String {
    let mut parts = locale.split(['-', '_']);
    parts
        .next()
        .map_or_else(|| FALLBACK_LOCALE, |lang| lang)
        .to_string()
}

// A macro for translating a text string.
#[macro_export]
macro_rules! t {
    ($($all:tt)*) => {
        rust_i18n::t!($($all)*)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_locale_dash() {
        let language = split_locale("en-US");
        assert_eq!(language, "en");
    }

    #[test]
    fn test_split_locale_underscore() {
        let language = split_locale("en_US");
        assert_eq!(language, "en");
    }

    #[test]
    fn test_split_locale_no_region() {
        let language = split_locale("en");
        assert_eq!(language, "en");
    }
}
