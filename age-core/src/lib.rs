//! This crate contains common structs and functions used across the `age` crates.
//!
//! You are probably looking for the [`age`](https://crates.io/crates/age) crate
//! itself. You should only need to directly depend on this crate if you are
//! implementing a custom recipient type.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

// Re-export crates that are used in our public API.
pub use secrecy;

pub mod format;
pub mod io;
pub mod primitives;

#[cfg(feature = "plugin")]
#[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
pub mod plugin;
