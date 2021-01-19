use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    unic_langid::LanguageIdentifier,
    DefaultLocalizer, LanguageLoader, Localizer,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Translations;

const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    pub(crate) static ref LANGUAGE_LOADER: FluentLanguageLoader = {
        let language_loader = fluent_language_loader!();
        // Ensure that the fallback language is always loaded, even if the library user
        // doesn't call `localizer().select(languages)`.
        let fallback: LanguageIdentifier = "en-US".parse().unwrap();
        language_loader.load_languages(&TRANSLATIONS, &[&fallback]).unwrap();
        language_loader
    };
}

/// Loads a localized age string.
#[doc(hidden)]
#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id)
    }};
}

/// age-localized version of the write! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };
}

/// age-localized version of the writeln! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };
}

/// Returns the [`Localizer`] to be used for localizing this library.
pub fn localizer() -> Box<dyn Localizer> {
    Box::from(DefaultLocalizer::new(&*LANGUAGE_LOADER, &TRANSLATIONS))
}
