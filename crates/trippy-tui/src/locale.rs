use anyhow::Context;
use i18n_embed::unic_langid::LanguageIdentifier;
use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester, LanguageLoader, LanguageRequester,
};
use std::str::FromStr;
use std::sync::OnceLock;

/// Get all available locales.
pub fn available_languages() -> anyhow::Result<Vec<String>> {
    Ok(__language_loader()
        .available_languages(&Localizations)?
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Initialize the locale.
pub fn init(cfg_locale: Option<&str>) -> anyhow::Result<String> {
    let cfg_locale = cfg_locale
        .map(LanguageIdentifier::from_str)
        .transpose()
        .context("failed to parse locale")?;
    let requested = cfg_locale
        .into_iter()
        .chain(DesktopLanguageRequester::new().requested_languages())
        .collect::<Vec<_>>();
    let selected = i18n_embed::select(__language_loader(), &Localizations, &requested)?;
    Ok(selected
        .first()
        .map_or_else(|| String::from(FALLBACK_LOCALE), ToString::to_string))
}

const FALLBACK_LOCALE: &str = "en";

static LANGUAGE_LOADER: OnceLock<FluentLanguageLoader> = OnceLock::new();

#[derive(rust_embed::RustEmbed)]
#[folder = "i18n"]
struct Localizations;

// this needs to be public for the macro to work, however it should be considered private and not
// used directly.
#[doc(hidden)]
pub fn __language_loader() -> &'static FluentLanguageLoader {
    LANGUAGE_LOADER.get_or_init(|| fluent_language_loader!())
}

// A wrapper macro for translating a text string.
#[macro_export]
macro_rules! t {
    ($($all:tt)*) => {
        i18n_embed_fl::fl!($crate::locale::__language_loader(), $($all)*)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_languages() {
        assert_eq!(
            available_languages().unwrap(),
            vec!["de", "en", "es", "fr", "it", "pt", "ru", "sv", "tr", "zh"]
        );
    }

    #[test]
    fn test_init() {
        assert!(init(None).is_ok());
        assert_eq!(init(Some("en")).unwrap(), "en");
        assert_eq!(init(Some("zh")).unwrap(), "zh");
        assert_eq!(init(Some("en-US")).unwrap(), "en");
        assert_eq!(init(Some("en-xx")).unwrap(), "en");
        assert_eq!(init(Some("zh_hk")).unwrap(), "zh");
        assert_eq!(init(Some("zh_xx")).unwrap(), "zh");
        assert!(init(Some("en-x")).is_err());
        assert!(init(Some("en-")).is_err());
    }
}
