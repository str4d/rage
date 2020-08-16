//! This is a helper crate for implementing age plugins.

#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

use std::io;

pub mod recipient;

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

/// Runs the plugin state machine defined by `state_machine`.
///
/// This should be triggered if the `--age-plugin=state_machine` flag is provided as an
/// argument when starting the plugin.
pub fn run_state_machine<R: recipient::RecipientPluginV1>(
    state_machine: &str,
    recipient_v1: impl FnOnce() -> R,
) -> io::Result<()> {
    use age_core::plugin::RECIPIENT_V1;

    match state_machine {
        RECIPIENT_V1 => recipient::run_v1(recipient_v1()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown plugin state machine",
        )),
    }
}
