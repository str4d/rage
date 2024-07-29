use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    unic_langid::LanguageIdentifier,
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

lazy_static! {
    pub(crate) static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

/// Selects the most suitable available language in order of preference by
/// `requested_languages`, and loads it using the `rage` [`static@LANGUAGE_LOADER`] from the
/// languages available in `rage/i18n/`.
///
/// Returns the available languages that were negotiated as being the most suitable to be
/// selected, and were loaded by [`i18n_embed::select`].
pub(crate) fn load_languages(
    requested_languages: &[LanguageIdentifier],
) -> Vec<LanguageIdentifier> {
    let supported_languages =
        i18n_embed::select(&*LANGUAGE_LOADER, &Localizations, requested_languages).unwrap();
    // Unfortunately the common Windows terminals don't support Unicode Directionality
    // Isolation Marks, so we disable them for now.
    LANGUAGE_LOADER.set_use_isolating(false);
    supported_languages
}
