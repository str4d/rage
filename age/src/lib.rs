//! *Library for encrypting and decryping age files*
//!
//! age is a simple, secure, and modern encryption tool with small explicit keys, no
//! config options, and UNIX-style composability.
//!
//! The age specification is available in a Google Doc here: [A simple file encryption tool & format](https://age-encryption.org/v1).
//!
//! *Caution*: all crate versions prior to 1.0 are beta releases for **testing purposes only**.
//!
//! # Examples
//!
//! ## Key-based encryption
//!
//! ```
//! use std::io::{Read, Write};
//! use std::iter;
//!
//! # fn run_main() -> Result<(), age::Error> {
//! let key = age::SecretKey::generate();
//! let pubkey = key.to_public();
//!
//! let plaintext = b"Hello world!";
//!
//! // Encrypt the plaintext to a ciphertext...
//! let encrypted = {
//!     let encryptor = age::Encryptor::with_recipients(vec![pubkey]);
//!
//!     let mut encrypted = vec![];
//!     let mut writer = encryptor.wrap_output(&mut encrypted)?;
//!     writer.write_all(plaintext)?;
//!     writer.finish()?;
//!
//!     encrypted
//! };
//!
//! // ... and decrypt the obtained ciphertext to the plaintext again.
//! let decrypted = {
//!     let decryptor = match age::Decryptor::new(&encrypted[..])? {
//!         age::Decryptor::Recipients(d) => d,
//!         _ => unreachable!(),
//!     };
//!
//!     let mut decrypted = vec![];
//!     let mut reader = decryptor.decrypt(
//!         iter::once(Box::new(key) as Box<dyn age::Identity>))?;
//!     reader.read_to_end(&mut decrypted);
//!
//!     decrypted
//! };
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
//! # fn run_main() -> Result<(), age::Error> {
//! let plaintext = b"Hello world!";
//! let passphrase = "this is not a good passphrase";
//!
//! // Encrypt the plaintext to a ciphertext using the passphrase...
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
//!
//! // ... and decrypt the ciphertext to the plaintext again using the same passphrase.
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
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # run_main().unwrap();
//! ```

#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod error;
mod format;
mod identity;
pub mod keys;
mod primitives;
mod protocol;
pub mod ssh;
mod util;

pub use error::Error;
pub use identity::IdentityFile;
pub use keys::SecretKey;
pub use primitives::{armor, stream};
pub use protocol::{decryptor, Callbacks, Decryptor, Encryptor};

#[cfg(feature = "cli-common")]
pub mod cli_common;

/// An Identity is a private key or other value that can decrypt an opaque [`FileKey`]
/// from a recipient stanza.
///
/// [`FileKey`]: keys::FileKey
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
    fn unwrap_file_key(
        &self,
        stanza: &format::RecipientStanza,
    ) -> Option<Result<keys::FileKey, Error>>;
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
