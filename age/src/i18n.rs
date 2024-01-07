use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    unic_langid::LanguageIdentifier,
    DefaultLocalizer, LanguageLoader, Localizer,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

lazy_static! {
    pub(crate) static ref LANGUAGE_LOADER: FluentLanguageLoader = {
        let language_loader = fluent_language_loader!();
        // Ensure that the fallback language is always loaded, even if the library user
        // doesn't call `localizer().select(languages)`.
        let fallback: LanguageIdentifier = "en-US".parse().unwrap();
        language_loader.load_languages(&Localizations, &[&fallback]).unwrap();
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

    ($message_id:literal, $($args:expr),* $(,)?) => {{
        i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

/// age-localized version of the write! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        write!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

/// age-localized version of the writeln! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

/// Returns the [`Localizer`] to be used for localizing this library.
///
/// # Examples
///
/// ```
/// // Fetch the set of languages that the user's desktop environment requests.
/// let requested_languages = i18n_embed::DesktopLanguageRequester::requested_languages();
///
/// // Localize the age crate based on the requested languages.
/// //
/// // If none of the requested languages are available, or if this function
/// // is not called, age defaults to en-US.
/// age::localizer().select(&requested_languages).unwrap();
/// ```
pub fn localizer() -> Box<dyn Localizer> {
    Box::from(DefaultLocalizer::new(&*LANGUAGE_LOADER, &Localizations))
}
