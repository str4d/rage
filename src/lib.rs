//! *Library for encrypting and decryping age messages*
//!
//! age is a simple, secure, and modern encryption tool with small explicit keys, no
//! config options, and UNIX-style composability.
//!
//! This is an **alpha release** for experimentation only. The age specification is still
//! in flux, and should not currently be relied on for any usage. The in-progress
//! specification is available [here](https://age-tool.com).
//!
//! # Examples
//!
//! ## Key-based encryption
//!
//! ```
//! use std::io::{Read, Write};
//!
//! let key = age::SecretKey::new();
//! let pubkey = key.to_public();
//!
//! let plaintext = b"Hello world!";
//!
//! let encryptor = age::Encryptor::Keys(vec![pubkey]);
//! let mut encrypted = vec![];
//! {
//!     let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
//!     writer.write_all(plaintext).unwrap();
//!     writer.flush().unwrap();
//! };
//!
//! let decryptor = age::Decryptor::Keys(vec![key]);
//! let mut reader = decryptor.trial_decrypt(&encrypted[..]).unwrap();
//! let mut decrypted = vec![];
//! reader.read_to_end(&mut decrypted);
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Passphrase-based encryption
//!
//! ```
//! use std::io::{Read, Write};
//!
//! let plaintext = b"Hello world!";
//! let passphrase = "this is not a good passphrase";
//!
//! let encryptor = age::Encryptor::Passphrase(passphrase.to_owned());
//! let mut encrypted = vec![];
//! {
//!     let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
//!     writer.write_all(plaintext).unwrap();
//!     writer.flush().unwrap();
//! };
//!
//! let decryptor = age::Decryptor::Passphrase(passphrase.to_owned());
//! let mut reader = decryptor.trial_decrypt(&encrypted[..]).unwrap();
//! let mut decrypted = vec![];
//! reader.read_to_end(&mut decrypted);
//!
//! assert_eq!(decrypted, plaintext);
//! ```

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod format;
mod keys;
mod primitives;
mod protocol;

pub use keys::{RecipientKey, SecretKey};
pub use protocol::{Decryptor, Encryptor};
