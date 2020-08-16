//! This is a helper crate for implementing age plugins.

#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
const PLUGIN_IDENTITY_PREFIX: &str = "age-plugin-";

/// Prints the newly-created identity and corresponding recipient to standard out.
///
/// A "created" time is included in the output, set to the current local time.
pub fn print_new_identity(plugin_name: &str, identity: &[u8], recipient: &[u8]) {
    use bech32::ToBase32;

    println!(
        "# created: {}",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    println!(
        "# recipient: {}",
        bech32::encode(
            &format!("{}{}", PLUGIN_RECIPIENT_PREFIX, plugin_name),
            recipient.to_base32(),
        )
        .expect("HRP is valid")
    );
    println!(
        "{}",
        bech32::encode(
            &format!("{}{}-", PLUGIN_IDENTITY_PREFIX, plugin_name),
            identity.to_base32(),
        )
        .expect("HRP is valid")
        .to_uppercase()
    );
}
