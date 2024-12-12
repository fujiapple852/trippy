use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester, LanguageRequester,
};
use rust_embed::RustEmbed;
use std::sync::LazyLock;

#[derive(RustEmbed)]
#[folder = "i18n"]
pub struct Localizations;

pub static LANGUAGE_LOADER: LazyLock<FluentLanguageLoader> =
    LazyLock::new(|| fluent_language_loader!());

#[macro_export]
macro_rules! t {
    ($($all:tt)*) => {
        i18n_embed_fl::fl!($crate::locale::LANGUAGE_LOADER, $($all)*)
    }
}

pub fn init(cfg_locale: Option<&str>) -> anyhow::Result<String> {
    let language_requester = DesktopLanguageRequester::new();
    let mut requested_languages = language_requester.requested_languages();
    //language_requester.set_language_override(cfg.tui_locale.map(|l| l.parse().unwrap());`
    // above doesn't work due to https://github.com/kellpossible/cargo-i18n/issues/94
    if let Some(cfg_locale) = cfg_locale {
        requested_languages.insert(0, cfg_locale.parse().expect("unsupported locale in config"));
    };
    let selected_languages =
        i18n_embed::select(&*LANGUAGE_LOADER, &Localizations, &requested_languages)
            .expect("failed to load locales");
    let Some(locale) = selected_languages.first().map(ToString::to_string) else {
        anyhow::bail!("failed to select a locale")
    };
    Ok(locale)
}


