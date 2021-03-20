//! *Library for encrypting and decryping age files*
//!
//! This crate implements file encryption according to the [age-encryption.org/v1]
//! specification. It generates and consumes encrypted files that are compatible with the
//! [rage] CLI tool, as well as the reference [Golang] implementation.
//!
//! The encryption and decryption APIs are provided by [`Encryptor`] and [`Decryptor`].
//! There are several ways to use these:
//! - For most cases (including programmatic usage), use [`Encryptor::with_recipients`]
//!   with [`x25519::Recipient`], and [`Decryptor`] with [`x25519::Identity`].
//! - APIs are available for passphrase-based encryption and decryption. These should
//!   only be used with passphrases that were provided by (or generated for) a human.
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
//! [Golang]: https://filippo.io/age
//!
//! # Examples
//!
//! ## Recipient-based encryption
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
//!     let encryptor = age::Encryptor::with_recipients(vec![Box::new(pubkey)]);
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
//!     let decryptor = match age::Decryptor::new(&encrypted[..])? {
//!         age::Decryptor::Recipients(d) => d,
//!         _ => unreachable!(),
//!     };
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
//! use secrecy::Secret;
//! use std::io::{Read, Write};
//!
//! # fn run_main() -> Result<(), ()> {
//! let plaintext = b"Hello world!";
//! let passphrase = "this is not a good passphrase";
//!
//! // Encrypt the plaintext to a ciphertext using the passphrase...
//! # fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
//! let encrypted = {
//!     let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
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
//! # fn decrypt(passphrase: &str, encrypted: Vec<u8>) -> Result<Vec<u8>, age::DecryptError> {
//! let decrypted = {
//!     let decryptor = match age::Decryptor::new(&encrypted[..])? {
//!         age::Decryptor::Passphrase(d) => d,
//!         _ => unreachable!(),
//!     };
//!
//!     let mut decrypted = vec![];
//!     let mut reader = decryptor.decrypt(&Secret::new(passphrase.to_owned()), None)?;
//!     reader.read_to_end(&mut decrypted);
//!
//!     decrypted
//! };
//! # Ok(decrypted)
//! # }
//! # let decrypted = decrypt(
//! #     passphrase,
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
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod error;
mod format;
mod identity;
mod keys;
mod primitives;
mod protocol;
mod scrypt;
mod util;
pub mod x25519;

pub use error::{DecryptError, EncryptError};
pub use identity::IdentityFile;
pub use primitives::stream;
pub use protocol::{decryptor, Decryptor, Encryptor};

#[cfg(feature = "armor")]
pub use primitives::armor;

#[cfg(feature = "cli-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "cli-common")))]
pub mod cli_common;

mod i18n;
pub use i18n::localizer;

#[cfg(feature = "plugin")]
#[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
pub mod plugin;

#[cfg(feature = "ssh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ssh")))]
pub mod ssh;

use age_core::format::{FileKey, Stanza};
use secrecy::SecretString;

/// A private key or other value that can unwrap an opaque file key from a recipient
/// stanza.
pub trait Identity {
    /// Attempts to unwrap the given stanza with this identity.
    ///
    /// This method is part of the `Identity` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// identities to [`RecipientsDecryptor::decrypt`].
    ///
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the recipient stanza does not match this key.
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    /// [`RecipientsDecryptor::decrypt`]: protocol::decryptor::RecipientsDecryptor::decrypt
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>>;

    /// Attempts to unwrap any of the given stanzas, which are assumed to come from the
    /// same age file header, and therefore contain the same file key.
    ///
    /// This method is part of the `Identity` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// identities to [`RecipientsDecryptor::decrypt`].
    ///
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if none of the recipient stanzas match this identity.
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    /// [`RecipientsDecryptor::decrypt`]: protocol::decryptor::RecipientsDecryptor::decrypt
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}

/// A public key or other value that can wrap an opaque file key to a recipient stanza.
///
/// Implementations of this trait might represent more than one recipient.
pub trait Recipient {
    /// Wraps the given file key, returning stanzas to be placed in an age file header.
    ///
    /// Implementations MUST NOT return more than one stanza per "actual recipient".
    ///
    /// This method is part of the `Recipient` trait to expose age's [one joint] for
    /// external implementations. You should not need to call this directly; instead, pass
    /// recipients to [`Encryptor::with_recipients`].
    ///
    /// [one joint]: https://www.imperialviolet.org/2016/05/16/agility.html
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError>;
}

/// Callbacks that might be triggered during encryption or decryption.
///
/// Structs that implement this trait should be given directly to the individual
/// `Recipient` or `Identity` implementations that require them.
pub trait Callbacks {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn prompt(&self, message: &str);

    /// Requests non-private input from the user.
    ///
    /// To request private inputs, use [`Callbacks::request_passphrase`].
    fn request_public_string(&self, description: &str) -> Option<String>;

    /// Requests a passphrase to decrypt a key.
    fn request_passphrase(&self, description: &str) -> Option<SecretString>;
}

/// Helper for fuzzing the Header parser and serializer.
#[cfg(fuzzing)]
pub fn fuzz_header(data: &[u8]) {
    if let Ok(header) = format::Header::read(data) {
        let mut buf = Vec::with_capacity(data.len());
        header.write(&mut buf).expect("can write header");
        assert_eq!(&buf[..], &data[..buf.len()]);
    }
}
