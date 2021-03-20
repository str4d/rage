//! This crate provides an API for building age plugins.
//!
//! # Introduction
//!
//! The [age file encryption format] follows the "one well-oiled joint" design philosophy.
//! The mechanism for extensibility (within a particular format version) is the recipient
//! stanzas within the age header: file keys can be wrapped in any number of ways, and age
//! clients are required to ignore stanzas that they do not understand.
//!
//! The core APIs that exercise this mechanism are:
//! - A recipient that wraps a file key and returns a stanza.
//! - An identity that unwraps a stanza and returns a file key.
//!
//! The age plugin system provides a mechanism for exposing these core APIs across process
//! boundaries. It has two main components:
//!
//! - A map from recipients and identities to plugin binaries.
//! - State machines for wrapping and unwrapping file keys.
//!
//! With this composable design, you can implement a recipient or identity that you might
//! use directly with the [`age`] library crate, and also deploy it as a plugin binary for
//! use with clients like [`rage`].
//!
//! [age file encryption format]: https://age-encryption.org/v1
//! [`age`]: https://crates.io/crates/age
//! [`rage`]: https://crates.io/crates/rage
//!
//! # Mapping recipients and identities to plugin binaries
//!
//! age plugins are identified by an arbitrary case-insensitive string `NAME`. This string
//! is used in three places:
//!
//! - Plugin-compatible recipients are encoded using Bech32 with the HRP `age1name`
//!   (lowercase).
//! - Plugin-compatible identities are encoded using Bech32 with the HRP
//!   `AGE-PLUGIN-NAME-` (uppercase).
//! - Plugin binaries (to be started by age clients) are named `age-plugin-name`.
//!
//! Users interact with age clients by providing either recipients for file encryption, or
//! identities for file decryption. When a plugin recipient or identity is provided, the
//! age client searches the `PATH` for a binary with the corresponding plugin name.
//!
//! Recipient stanza types are not required to be correlated to specific plugin names.
//! When decrypting, age clients will pass all recipient stanzas to every connected
//! plugin. Plugins MUST ignore stanzas that they do not know about.
//!
//! A plugin binary may handle multiple recipient or identity types by being present in
//! the `PATH` under multiple names. This can be implemented with symlinks or aliases to
//! the canonical binary.
//!
//! Multiple plugin binaries can support the same recipient and identity types; the first
//! binary found in the `PATH` will be used by age clients. Some Unix OSs support
//! "alternatives", which plugin binaries should leverage if they provide support for a
//! common recipient or identity type.
//!
//! Note that the identity specified by a user doesn't need to point to a specific
//! decryption key, or indeed contain any key material at all. It only needs to contain
//! sufficient information for the plugin to locate the necessary key material.
//!
//! ## Standard age keys
//!
//! A plugin MAY support decrypting files encrypted to native age recipients, by including
//! support for the `x25519` recipient stanza. Such plugins will pick their own name, and
//! users will use identity files containing identities that specify that plugin name.
//!
//! # Example plugin binary
//!
//! The following example uses `gumdrop` to parse CLI arguments, but any argument parsing
//! logic will work as long as it can detect the `--age-plugin=STATE_MACHINE` flag.
//!
//! ```
//! use age_core::format::{FileKey, Stanza};
//! use age_plugin::{
//!     identity::{self, IdentityPluginV1},
//!     print_new_identity,
//!     recipient::{self, RecipientPluginV1},
//!     Callbacks, run_state_machine,
//! };
//! use gumdrop::Options;
//! use std::collections::HashMap;
//! use std::io;
//!
//! struct RecipientPlugin;
//!
//! impl RecipientPluginV1 for RecipientPlugin {
//!     fn add_recipients<'a, I: Iterator<Item = &'a str>>(
//!         &mut self,
//!         recipients: I,
//!     ) -> Result<(), Vec<recipient::Error>> {
//!         todo!()
//!     }
//!
//!     fn add_identities<'a, I: Iterator<Item = &'a str>>(
//!         &mut self,
//!         identities: I,
//!     ) -> Result<(), Vec<recipient::Error>> {
//!         todo!()
//!     }
//!
//!     fn wrap_file_keys(
//!         &mut self,
//!         file_keys: Vec<FileKey>,
//!         mut callbacks: impl Callbacks<recipient::Error>,
//!     ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
//!         todo!()
//!     }
//! }
//!
//! struct IdentityPlugin;
//!
//! impl IdentityPluginV1 for IdentityPlugin {
//!     fn add_identities<'a, I: Iterator<Item = &'a str>>(
//!         &mut self,
//!         identities: I,
//!     ) -> Result<(), Vec<identity::Error>> {
//!         todo!()
//!     }
//!
//!     fn unwrap_file_keys(
//!         &mut self,
//!         files: Vec<Vec<Stanza>>,
//!         mut callbacks: impl Callbacks<identity::Error>,
//!     ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
//!         todo!()
//!     }
//! }
//!
//! #[derive(Debug, Options)]
//! struct PluginOptions {
//!     #[options(help = "print help message")]
//!     help: bool,
//!
//!     #[options(help = "run the given age plugin state machine", no_short)]
//!     age_plugin: Option<String>,
//! }
//!
//! fn main() -> io::Result<()> {
//!     let opts = PluginOptions::parse_args_default_or_exit();
//!
//!     if let Some(state_machine) = opts.age_plugin {
//!         // The plugin was started by an age client; run the state machine.
//!         run_state_machine(
//!             &state_machine,
//!             || RecipientPlugin,
//!             || IdentityPlugin,
//!         )?;
//!         return Ok(());
//!     }
//!
//!     // Here you can assume the binary is being run directly by a user,
//!     // and perform administrative tasks like generating keys.
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

use bech32::Variant;
use secrecy::SecretString;
use std::io;

pub mod identity;
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
            Variant::Bech32
        )
        .expect("HRP is valid")
    );
    println!(
        "{}",
        bech32::encode(
            &format!("{}{}-", PLUGIN_IDENTITY_PREFIX, plugin_name),
            identity.to_base32(),
            Variant::Bech32,
        )
        .expect("HRP is valid")
        .to_uppercase()
    );
}

/// Runs the plugin state machine defined by `state_machine`.
///
/// This should be triggered if the `--age-plugin=state_machine` flag is provided as an
/// argument when starting the plugin.
pub fn run_state_machine<R: recipient::RecipientPluginV1, I: identity::IdentityPluginV1>(
    state_machine: &str,
    recipient_v1: impl FnOnce() -> R,
    identity_v1: impl FnOnce() -> I,
) -> io::Result<()> {
    use age_core::plugin::{IDENTITY_V1, RECIPIENT_V1};

    match state_machine {
        RECIPIENT_V1 => recipient::run_v1(recipient_v1()),
        IDENTITY_V1 => identity::run_v1(identity_v1()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown plugin state machine",
        )),
    }
}

/// The interface that age plugins can use to interact with an age implementation.
pub trait Callbacks<E> {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn message(&mut self, message: &str) -> age_core::plugin::Result<(), ()>;

    /// Requests a non-secret value from the user.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    ///
    /// To request secrets, use [`Callbacks::request_secret`].
    fn request_public(&mut self, message: &str) -> age_core::plugin::Result<String, ()>;

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> age_core::plugin::Result<SecretString, ()>;

    /// Sends an error.
    ///
    /// Note: This API may be removed in a subsequent API refactor, after we've figured
    /// out how errors should be handled overall, and how to distinguish between hard and
    /// soft errors.
    fn error(&mut self, error: E) -> age_core::plugin::Result<(), ()>;
}
