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
//! # fn run_main() -> std::io::Result<()> {
//! let key = age::SecretKey::generate();
//! let pubkey = key.to_public();
//!
//! let plaintext = b"Hello world!";
//!
//! let encryptor = age::Encryptor::Keys(vec![pubkey]);
//! let mut encrypted = vec![];
//! {
//!     let mut writer = encryptor.wrap_output(&mut encrypted, false)?;
//!     writer.write_all(plaintext)?;
//!     writer.flush()?;
//! };
//!
//! let decryptor = age::Decryptor::Keys(vec![key]);
//! let mut reader = decryptor.trial_decrypt(&encrypted[..])?;
//! let mut decrypted = vec![];
//! reader.read_to_end(&mut decrypted);
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # fn main() { run_main().unwrap(); }
//! ```
//!
//! ## Passphrase-based encryption
//!
//! ```
//! use std::io::{Read, Write};
//!
//! # fn run_main() -> std::io::Result<()> {
//! let plaintext = b"Hello world!";
//! let passphrase = "this is not a good passphrase";
//!
//! let encryptor = age::Encryptor::Passphrase(passphrase.to_owned());
//! let mut encrypted = vec![];
//! {
//!     let mut writer = encryptor.wrap_output(&mut encrypted, false)?;
//!     writer.write_all(plaintext)?;
//!     writer.flush()?;
//! };
//!
//! let decryptor = age::Decryptor::Passphrase(passphrase.to_owned());
//! let mut reader = decryptor.trial_decrypt(&encrypted[..])?;
//! let mut decrypted = vec![];
//! reader.read_to_end(&mut decrypted);
//!
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! # fn main() { run_main().unwrap(); }
//! ```

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod format;
mod keys;
mod openssh;
mod primitives;
mod protocol;
mod util;

pub use keys::{RecipientKey, SecretKey};
pub use primitives::stream::StreamReader;
pub use protocol::{Decryptor, Encryptor};

#[cfg(feature = "cli-common")]
pub mod cli_common;
