// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]

// Re-export crates that are used in our public API.
pub use secrecy;

pub mod format;
pub mod primitives;

#[cfg(feature = "plugin")]
pub mod plugin;
