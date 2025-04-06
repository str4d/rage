//! *Library for encrypting and decrypting age files*
//!
//! This crate implements file encryption according to the [age-encryption.org/v1]
//! specification. It generates and consumes encrypted files that are compatible with the
//! [rage] CLI tool, as well as the reference [Go] implementation.
//!
//! The encryption and decryption APIs are provided by [`Encryptor`] and [`Decryptor`].
//! There are several ways to use these:
//! - For most cases (including programmatic usage), use [`Encryptor::with_recipients`]
//!   with [`x25519::Recipient`], and [`Decryptor`] with [`x25519::Identity`].
//! - For passphrase-based encryption and decryption, use [`scrypt::Recipient`] and
//!   [`scrypt::Identity`], or the helper method [`Encryptor::with_user_passphrase`].
//!   These should only be used with passphrases that were provided by (or generated for)
//!   a human.
//! - For compatibility with existing SSH keys, enable the `ssh` feature flag, and use
//!   [`ssh::Recipient`] and [`ssh::Identity`].
//!
//! Age-encrypted files are binary and non-malleable. To encode them as text, use the
//! wrapping readers and writers in the [`armor`] module, behind the `armor` feature flag.
//!
//! *Caution*: all crate versions prior to 1.0 are beta releases for **testing purposes
//! only**.
//!
//! [age-encryption.org/v1]: https://age-encryption.org/v1
//! [rage]: https://crates.io/crates/rage
//! [Go]: https://filippo.io/age
//!
//! # Examples
//!
//! ## Streamlined APIs
//!
//! These are useful when you only need to encrypt to a single recipient, and the data is
//! small enough to fit in memory.
//!
//! ### Recipient-based encryption
//!
//! ```
//! # fn run_main() -> Result<(), ()> {
//! let key = age::x25519::Identity::generate();
//! let pubkey = key.to_public();
//!
//! let plaintext = b"Hello world!";
//!
//! # fn encrypt(pubkey: age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
//! let encrypted = age::encrypt(&pubkey, plaintext)?;
//! # Ok(encrypted)
//! # }
//! # fn decrypt(key: age::x25519::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
//! let decrypted = age::decrypt(&key, &encrypted)?;
//! # Ok(decrypted)
//! # }
//! # let decrypted = decrypt(
//! #     key,
//! #     encrypt(pubkey, &plaintext[..]).map_err(|_| ())?
//! # ).map_err(|_| ())?;
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # run_main().unwrap();
//! ```
//!
//! ## Passphrase-based encryption
//!
//! ```
//! use age::secrecy::SecretString;
//!
//! # fn run_main() -> Result<(), ()> {
//! let passphrase = SecretString::from("this is not a good passphrase".to_owned());
//! let recipient = age::scrypt::Recipient::new(passphrase.clone());
//! let identity = age::scrypt::Identity::new(passphrase);
//!
//! let plaintext = b"Hello world!";
//!
//! # fn encrypt(recipient: age::scrypt::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
//! let encrypted = age::encrypt(&recipient, plaintext)?;
//! # Ok(encrypted)
//! # }
//! # fn decrypt(identity: age::scrypt::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
//! let decrypted = age::decrypt(&identity, &encrypted)?;
//! # Ok(decrypted)
//! # }
//! # let decrypted = decrypt(
//! #     identity,
//! #     encrypt(recipient, &plaintext[..]).map_err(|_| ())?
//! # ).map_err(|_| ())?;
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # run_main().unwrap();
//! ```
//!
//! ## Full APIs
//!
//! The full APIs support encrypting to multiple recipients, streaming the data, and have
//! async I/O options.
//!
//! ### Recipient-based encryption
//!
//! ```
//! use std::io::{Read, Write};
//! use std::iter;
//!
//! # fn run_main() -> Result<(), ()> {
//! let key = age::x25519::Identity::generate();
//! let pubkey = key.to_public();
//!
//! let plaintext = b"Hello world!";
//!
//! // Encrypt the plaintext to a ciphertext...
//! # fn encrypt(pubkey: age::x25519::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
//! let encrypted = {
//!     let encryptor = age::Encryptor::with_recipients(iter::once(&pubkey as _))
//!         .expect("we provided a recipient");
//!
//!     let mut encrypted = vec![];
//!     let mut writer = encryptor.wrap_output(&mut encrypted)?;
//!     writer.write_all(plaintext)?;
//!     writer.finish()?;
//!
//!     encrypted
//! };
//! # Ok(encrypted)
//! # }
//!
//! // ... and decrypt the obtained ciphertext to the plaintext again.
//! # fn decrypt(key: age::x25519::Identity, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
//! let decrypted = {
//!     let decryptor = age::Decryptor::new(&encrypted[..])?;
//!
//!     let mut decrypted = vec![];
//!     let mut reader = decryptor.decrypt(iter::once(&key as &dyn age::Identity))?;
//!     reader.read_to_end(&mut decrypted);
//!
//!     decrypted
//! };
//! # Ok(decrypted)
//! # }
//! # let decrypted = decrypt(
//! #     key,
//! #     encrypt(pubkey, &plaintext[..]).map_err(|_| ())?
//! # ).map_err(|_| ())?;
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//!
//! # run_main().unwrap();
//! ```
//!
//! ## Passphrase-based encryption
//!
//! ```
//! use age::secrecy::SecretString;
//! use std::io::{Read, Write};
//! use std::iter;
//!
//! # fn run_main() -> Result<(), ()> {
//! let plaintext = b"Hello world!";
//! let passphrase = SecretString::from("this is not a good passphrase".to_owned());
//!
//! // Encrypt the plaintext to a ciphertext using the passphrase...
//! # fn encrypt(passphrase: SecretString, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
//! let encrypted = {
//!     let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
//!
//!     let mut encrypted = vec![];
//!     let mut writer = encryptor.wrap_output(&mut encrypted)?;
//!     writer.write_all(plaintext)?;
//!     writer.finish()?;
//!
//!     encrypted
//! };
//! # Ok(encrypted)
//! # }
//!
//! // ... and decrypt the ciphertext to the plaintext again using the same passphrase.
//! # fn decrypt(passphrase: SecretString, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
//! let decrypted = {
//!     let decryptor = age::Decryptor::new(&encrypted[..])?;
//!
//!     let mut decrypted = vec![];
//!     let mut reader = decryptor.decrypt(iter::once(&age::scrypt::Identity::new(passphrase) as _))?;
//!     reader.read_to_end(&mut decrypted);
//!
//!     decrypted
//! };
//! # Ok(decrypted)
//! # }
//! # let decrypted = decrypt(
//! #     passphrase.clone(),
//! #     encrypt(passphrase, &plaintext[..]).map_err(|_| ())?
//! # ).map_err(|_| ())?;
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # run_main().unwrap();
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

use std::collections::HashSet;

// Re-export crates that are used in our public API.
pub use age_core::secrecy;

mod error;
mod format;
mod identity;
mod keys;
mod primitives;
mod protocol;
mod util;

pub use error::{DecryptError, EncryptError, IdentityFileConvertError};
pub use identity::IdentityFile;
pub use primitives::stream;
pub use protocol::{Decryptor, Encryptor};

#[cfg(feature = "armor")]
#[cfg_attr(docsrs, doc(cfg(feature = "armor")))]
pub use primitives::armor;

#[cfg(feature = "cli-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "cli-common")))]
pub mod cli_common;

mod i18n;
pub use i18n::localizer;

//
// Simple interface
//

mod simple;
pub use simple::{decrypt, encrypt};

#[cfg(feature = "armor")]
#[cfg_attr(docsrs, doc(cfg(feature = "armor")))]
pub use simple::encrypt_and_armor;

//
// Identity types
//

pub mod encrypted;
pub mod scrypt;
pub mod x25519;

#[cfg(feature = "plugin")]
#[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
pub mod plugin;

#[cfg(feature = "ssh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
pub mod ssh;

//
// Core traits
//

use age_core::{
    format::{FileKey, Stanza},
    secrecy::SecretString,
};

/// A private key or other value that can unwrap an opaque file key from a recipient
/// stanza.
///
/// # Implementation notes
///
/// The canonical entry point for this trait is [`Identity::unwrap_stanzas`]. The default
/// implementation of that method is:
/// ```ignore
/// stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
/// ```
///
/// The `age` crate otherwise does not call [`Identity::unwrap_stanza`] directly. As such,
/// if you want to add file-level stanza checks, override [`Identity::unwrap_stanzas`].
pub trait Identity {
    /// Attempts to unwrap the given stanza with this identity.
    ///
    /// This method is part of the `Identity` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// identities to [`Decryptor::decrypt`].
    ///
    /// The `age` crate only calls this method via [`Identity::unwrap_stanzas`].
    ///
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the recipient stanza does not match this key.
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>>;

    /// Attempts to unwrap any of the given stanzas, which are assumed to come from the
    /// same age file header, and therefore contain the same file key.
    ///
    /// This method is part of the `Identity` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// identities to [`Decryptor::decrypt`].
    ///
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if none of the recipient stanzas match this identity.
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}

/// A public key or other value that can wrap an opaque file key to a recipient stanza.
///
/// Implementations of this trait might represent more than one recipient.
pub trait Recipient {
    /// Wraps the given file key, returning stanzas to be placed in an age file header,
    /// and labels that constrain how the stanzas may be combined with those from other
    /// recipients.
    ///
    /// Implementations may return more than one stanza per "actual recipient", e.g. to
    /// support multiple formats, to build group aliases, or to act as a proxy.
    ///
    /// This method is part of the `Recipient` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// recipients to [`Encryptor::with_recipients`].
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    ///
    /// # Labels
    ///
    /// [`Encryptor`] will succeed at encrypting only if every recipient returns the same
    /// set of labels. Subsets or partial overlapping sets are not allowed; all sets must
    /// be identical. Labels are compared exactly, and are case-sensitive.
    ///
    /// Label sets can be used to ensure a recipient is only encrypted to alongside other
    /// recipients with equivalent properties, or to ensure a recipient is always used
    /// alone. A recipient with no particular properties to enforce should return an empty
    /// label set.
    ///
    /// Labels can have any value that is a valid arbitrary string (`1*VCHAR` in ABNF),
    /// but usually take one of several forms:
    ///   - *Common public label* - used by multiple recipients to permit their stanzas to
    ///     be used only together. Examples include:
    ///     - `postquantum` - indicates that the recipient stanzas being generated are
    ///       postquantum-secure, and that they can only be combined with other stanzas
    ///       that are also postquantum-secure.
    ///   - *Common private label* - used by recipients created by the same private entity
    ///     to permit their recipient stanzas to be used only together. For example,
    ///     private recipients used in a corporate environment could all send the same
    ///     private label in order to prevent compliant age clients from simultaneously
    ///     wrapping file keys with other recipients.
    ///   - *Random label* - used by recipients that want to ensure their stanzas are not
    ///     used with any other recipient stanzas. This can be used to produce a file key
    ///     that is only encrypted to a single recipient stanza, for example to preserve
    ///     its authentication properties.
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError>;
}

/// Callbacks that might be triggered during encryption or decryption.
///
/// Structs that implement this trait should be given directly to the individual
/// `Recipient` or `Identity` implementations that require them.
pub trait Callbacks: Clone + Send + Sync + 'static {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    ///
    /// No guarantee is provided that the user sees this message (for example, if there is
    /// no UI for displaying messages).
    fn display_message(&self, message: &str);

    /// Requests that the user provides confirmation for some action.
    ///
    /// This can be used to, for example, request that a hardware key the plugin wants to
    /// try either be plugged in, or skipped.
    ///
    /// - `message` is the request or call-to-action to be displayed to the user.
    /// - `yes_string` and (optionally) `no_string` will be displayed on buttons or next
    ///   to selection options in the user's UI.
    ///
    /// Returns:
    /// - `Some(true)` if the user selected the option marked with `yes_string`.
    /// - `Some(false)` if the user selected the option marked with `no_string` (or the
    ///   default negative confirmation label).
    /// - `None` if the confirmation request could not be given to the user (for example,
    ///   if there is no UI for displaying messages).
    fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool>;

    /// Requests non-private input from the user.
    ///
    /// To request private inputs, use [`Callbacks::request_passphrase`].
    ///
    /// Returns:
    /// - `Some(input)` with the user-provided input.
    /// - `None` if no input could be requested from the user (for example, if there is no
    ///   UI for displaying messages or typing inputs).
    fn request_public_string(&self, description: &str) -> Option<String>;

    /// Requests a passphrase to decrypt a key.
    ///
    /// Returns:
    /// - `Some(passphrase)` with the user-provided passphrase.
    /// - `None` if no passphrase could be requested from the user (for example, if there
    ///   is no UI for displaying messages or typing inputs).
    fn request_passphrase(&self, description: &str) -> Option<SecretString>;
}

/// An implementation of [`Callbacks`] that does not allow callbacks.
///
/// No user interaction will occur; [`Recipient`] or [`Identity`] implementations will
/// receive `None` from the callbacks that return responses, and will act accordingly.
#[derive(Clone, Copy, Debug)]
pub struct NoCallbacks;

impl Callbacks for NoCallbacks {
    fn display_message(&self, _: &str) {}

    fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _: &str) -> Option<SecretString> {
        None
    }
}

//
// Fuzzing APIs
//

/// Helper for fuzzing the Header parser and serializer.
#[cfg(fuzzing)]
pub fn fuzz_header(data: &[u8]) {
    if let Ok(header) = format::Header::read(data) {
        let mut buf = Vec::with_capacity(data.len());
        header.write(&mut buf).expect("can write header");
        assert_eq!(&buf[..], &data[..buf.len()]);
    }
}
