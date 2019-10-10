//! *Library for encrypting and decryping age messages*
//!
//! age is a simple, secure, and modern encryption tool with small explicit keys, no
//! config options, and UNIX-style composability.
//!
//! This is an **alpha release** for experimentation only. The age specification is still
//! in flux, and should not currently be relied on for any usage. The in-progress
//! specification is available [here](https://age-tool.com).

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_docs)]

mod format;
mod keys;
mod primitives;
mod protocol;

pub use keys::{RecipientKey, SecretKey};
pub use protocol::{Decryptor, Encryptor};
